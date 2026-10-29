import socket, sys, time, select
# Minimal Hodometer client: connect, print every line for N seconds; send the given commands once allowed.
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 20
cmds = sys.argv[2:]
s = socket.create_connection(("127.0.0.1", 48201), timeout=5)
s.setblocking(False)
buf = b""; end = time.time() + secs; sent = False
while time.time() < end:
    r, _, _ = select.select([s], [], [], 0.5)
    if not r:
        continue
    try:
        data = s.recv(65536)
    except BlockingIOError:
        continue
    if not data:
        print("[closed by server]", flush=True); break
    buf += data
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        text = line.decode("utf-8", "replace")
        print(text[:300], flush=True)
        if '"status":"allowed"' in text and not sent:
            for c in cmds:
                s.sendall((c + "\n").encode())
            sent = True
s.close()
