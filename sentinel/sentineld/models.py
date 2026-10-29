"""Claude API sessions: one long-lived conversation for Sentinel, one short one per investigator.

Requests go through the Anthropic SDK (Messages API). Thinking is left at the model's default (adaptive); thinking
blocks are passed back unchanged and the history is append-only. The system prompt and the growing conversation
are cached. Refusals are retried server-side on the API's default fallback chain when the beta is available.
"""
import json
import logging
import threading
import time

import anthropic

log = logging.getLogger("models")

BETA_FALLBACK = "server-side-fallback-2026-07-01"


class ModelError(Exception):
    pass


class TurnResult:
    def __init__(self, status, text="", tool_calls=0, finished=False):
        self.status = status        # ok | refusal | max_tokens | rounds | deadline | error
        self.text = text
        self.tool_calls = tool_calls
        self.finished = finished    # a tool asked to stop the turn (finish)


class Transcript:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, kind, **fields):
        rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind}
        rec.update(fields)
        try:
            with self._lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass


class ModelSession:
    def __init__(self, client, model, system_text, tools, effort, label, use_fallback=True, transcript=None,
                 max_tokens=16000, context_limit=100000):
        self.client = client
        self.model = model
        self.system_text = system_text
        self.tools = tools
        self.effort = effort
        self.label = label
        self.use_fallback = use_fallback
        self.transcript = transcript
        self.max_tokens = max_tokens
        self.context_limit = context_limit
        self.messages = []
        self.turns = 0
        self.tool_calls = 0
        self.last_input_tokens = 0
        self.total_input = 0
        self.total_output = 0
        self.total_cache_read = 0
        self.total_cache_write = 0

    # ------------------------------------------------------------------ one API call with retries
    def _create(self):
        kwargs = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=[{"type": "text", "text": self.system_text, "cache_control": {"type": "ephemeral"}}],
            tools=self.tools,
            messages=self.messages,
            output_config={"effort": self.effort},
            cache_control={"type": "ephemeral"},
        )
        attempt = 0
        while True:
            try:
                if self.use_fallback:
                    return self.client.beta.messages.create(betas=[BETA_FALLBACK], fallbacks="default", **kwargs)
                return self.client.messages.create(**kwargs)
            except anthropic.AuthenticationError as e:
                raise ModelError(f"authentication failed: {e.message}")
            except anthropic.PermissionDeniedError as e:
                raise ModelError(f"permission denied: {e.message}")
            except anthropic.BadRequestError as e:
                msg = str(e.message)
                if self.use_fallback and ("fallback" in msg.lower() or "beta" in msg.lower()):
                    log.warning("[%s] server-side fallback not accepted (%s); continuing without it", self.label, msg[:200])
                    self.use_fallback = False
                    continue
                raise ModelError(f"bad request: {msg[:500]}")
            except anthropic.RateLimitError as e:
                wait = 30.0
                try:
                    wait = float(e.response.headers.get("retry-after", "30"))
                except (TypeError, ValueError, AttributeError):
                    pass
                wait = min(max(wait, 5.0), 120.0)
                log.warning("[%s] rate limited; waiting %.0f s", self.label, wait)
            except anthropic.APIStatusError as e:
                if e.status_code < 500:
                    raise ModelError(f"API error {e.status_code}: {e.message}")
                wait = min(5.0 * (2 ** attempt), 60.0)
                log.warning("[%s] server error %s; retry in %.0f s", self.label, e.status_code, wait)
            except anthropic.APIConnectionError as e:
                wait = min(5.0 * (2 ** attempt), 60.0)
                log.warning("[%s] connection error (%s); retry in %.0f s", self.label, e, wait)
            attempt += 1
            if attempt > 6:
                raise ModelError("gave up after repeated API errors")
            time.sleep(wait)

    def _note_usage(self, resp):
        u = getattr(resp, "usage", None)
        if not u:
            return
        inp = getattr(u, "input_tokens", 0) or 0
        cr = getattr(u, "cache_read_input_tokens", 0) or 0
        cw = getattr(u, "cache_creation_input_tokens", 0) or 0
        out = getattr(u, "output_tokens", 0) or 0
        self.last_input_tokens = inp + cr + cw
        self.total_input += inp
        self.total_cache_read += cr
        self.total_cache_write += cw
        self.total_output += out

    def usage_line(self):
        return (f"{self.turns} turns, {self.tool_calls} tool calls, context {self.last_input_tokens} tok, "
                f"in {self.total_input} + cache r{self.total_cache_read}/w{self.total_cache_write}, out {self.total_output}")

    # ------------------------------------------------------------------ a turn: user text -> tool loop -> text
    def run_turn(self, user_text, execute_tool, max_tool_rounds=40, deadline=None, stop_event=None):
        """execute_tool(name, input) -> (content_str, is_error) or (content_str, is_error, stop_turn)."""
        self.messages.append({"role": "user", "content": [{"type": "text", "text": user_text}]})
        if self.transcript:
            self.transcript.write("user", label=self.label, text=user_text[:20000])
        self.turns += 1
        rounds = 0
        calls = 0
        text_out = []
        while True:
            if stop_event is not None and stop_event.is_set():
                return TurnResult("deadline", "\n".join(text_out), calls)
            resp = self._create()
            self._note_usage(resp)
            if resp.stop_reason == "refusal":
                cat = None
                sd = getattr(resp, "stop_details", None)
                if sd is not None:
                    cat = getattr(sd, "category", None)
                log.warning("[%s] model declined (category %s)", self.label, cat)
                if self.transcript:
                    self.transcript.write("refusal", label=self.label, category=cat)
                if not resp.content:
                    self.messages.pop()     # nothing was produced for it; keep the history valid
                else:
                    self.messages.append({"role": "assistant", "content": resp.content})
                return TurnResult("refusal", f"(model declined: {cat})", calls)
            texts = [b.text for b in resp.content if b.type == "text" and b.text]
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            text_out.extend(texts)
            self.messages.append({"role": "assistant", "content": resp.content})
            if self.transcript:
                for t in texts:
                    self.transcript.write("assistant", label=self.label, text=t[:20000])
            if resp.stop_reason == "max_tokens":
                log.warning("[%s] reply hit max_tokens", self.label)
                return TurnResult("max_tokens", "\n".join(text_out), calls)
            if not tool_uses:
                return TurnResult("ok", "\n".join(text_out), calls)
            results = []
            stop_turn = False
            for tu in tool_uses:
                calls += 1
                self.tool_calls += 1
                inp = tu.input if isinstance(tu.input, dict) else {}
                try:
                    r = execute_tool(tu.name, inp)
                except Exception as e:       # a tool bug must not kill the session
                    log.exception("[%s] tool %s failed", self.label, tu.name)
                    r = (f"tool error: {e}", True)
                content, is_error = r[0], r[1]
                if len(r) > 2 and r[2]:
                    stop_turn = True
                if self.transcript:
                    self.transcript.write("tool", label=self.label, name=tu.name, input=inp, result=str(content)[:4000],
                                          error=bool(is_error))
                block = {"type": "tool_result", "tool_use_id": tu.id, "content": str(content)}
                if is_error:
                    block["is_error"] = True
                results.append(block)
            self.messages.append({"role": "user", "content": results})
            rounds += 1
            if stop_turn:
                return TurnResult("ok", "\n".join(text_out), calls, finished=True)
            if rounds >= max_tool_rounds:
                log.warning("[%s] tool-round budget (%d) used up", self.label, max_tool_rounds)
                return TurnResult("rounds", "\n".join(text_out), calls)
            if deadline is not None and time.time() >= deadline:
                log.warning("[%s] deadline reached mid-turn", self.label)
                return TurnResult("deadline", "\n".join(text_out), calls)

    def needs_rollover(self):
        return self.last_input_tokens >= self.context_limit

    def rollover(self):
        """Start a fresh conversation (the ledger holds durable state). Called between turns only."""
        log.info("[%s] context %d tokens; starting a new conversation", self.label, self.last_input_tokens)
        if self.transcript:
            self.transcript.write("rollover", label=self.label, context_tokens=self.last_input_tokens)
        self.messages = []
        self.last_input_tokens = 0
