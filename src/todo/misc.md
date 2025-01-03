{{#include ../banners/hacktricks-training.md}}

У відповіді ping TTL:\
127 = Windows\
254 = Cisco\
Інше, якийсь linux

$1$- md5\
$2$or $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Якщо ви не знаєте, що стоїть за сервісом, спробуйте зробити HTTP GET запит.

**UDP Сканування**\
nc -nv -u -z -w 1 \<IP> 160-16

Порожній UDP пакет надсилається на конкретний порт. Якщо UDP порт відкритий, відповідь не надсилається з цільової машини. Якщо UDP порт закритий, з цільової машини має бути надіслано пакет ICMP "порт недоступний".\

Сканування UDP портів часто ненадійне, оскільки брандмауери та маршрутизатори можуть відкидати пакети ICMP.\
Це може призвести до хибнопозитивних результатів у вашому скануванні, і ви регулярно будете бачити,\
що сканування UDP портів показує всі UDP порти відкритими на сканованій машині.\
Більшість сканерів портів не сканують всі доступні порти і зазвичай мають попередньо встановлений список\
"цікавих портів", які скануються.

# CTF - Трюки

У **Windows** використовуйте **Winzip** для пошуку файлів.\
**Альтернативні потоки даних**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Крипто

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Починається з "_begin \<mode> \<filename>_" і дивних символів\
**Xxencoding** --> Починається з "_begin \<mode> \<filename>_" і B64\
\
**Vigenere** (аналіз частот) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (зсув символів) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Сховати повідомлення, використовуючи пробіли та табуляції

# Символи

%E2%80%AE => RTL символ (пише payloads у зворотному порядку)

{{#include ../banners/hacktricks-training.md}}
