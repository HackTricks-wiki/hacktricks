{{#include ../banners/hacktricks-training.md}}

W odpowiedzi ping TTL:\
127 = Windows\
254 = Cisco\
Reszta, jakiś linux

$1$- md5\
$2$lub $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Jeśli nie wiesz, co kryje się za usługą, spróbuj wykonać żądanie HTTP GET.

**Skanowanie UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Pusty pakiet UDP jest wysyłany do konkretnego portu. Jeśli port UDP jest otwarty, nie zostaje wysłana odpowiedź z maszyny docelowej. Jeśli port UDP jest zamknięty, z maszyny docelowej powinien zostać wysłany pakiet ICMP informujący o niedostępności portu.\

Skanowanie portów UDP jest często niewiarygodne, ponieważ zapory sieciowe i routery mogą odrzucać pakiety ICMP.\
Może to prowadzić do fałszywych pozytywów w twoim skanowaniu, a ty regularnie zobaczysz,\
że skanowanie portów UDP pokazuje wszystkie porty UDP jako otwarte na skanowanej maszynie.\
Większość skanerów portów nie skanuje wszystkich dostępnych portów i zazwyczaj ma wstępnie ustawioną listę\
„interesujących portów”, które są skanowane.

# CTF - Sztuczki

W **Windows** użyj **Winzip**, aby wyszukać pliki.\
**Alternatywne strumienie danych**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Zacznij od "_begin \<mode> \<filename>_" i dziwnych znaków\
**Xxencoding** --> Zacznij od "_begin \<mode> \<filename>_" i B64\
\
**Vigenere** (analiza częstotliwości) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (przesunięcie znaków) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ukryj wiadomości używając spacji i tabulatorów

# Characters

%E2%80%AE => Znak RTL (pisze ładunki odwrotnie)

{{#include ../banners/hacktricks-training.md}}
