{{#include ../banners/hacktricks-training.md}}

In 'n ping antwoord TTL:\
127 = Windows\
254 = Cisco\
Die res, 'n paar linux

$1$- md5\
$2$of $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

As jy nie weet wat agter 'n diens is nie, probeer om 'n HTTP GET versoek te maak.

**UDP Skande**\
nc -nv -u -z -w 1 \<IP> 160-16

'n Leë UDP-pakket word na 'n spesifieke poort gestuur. As die UDP-poort oop is, word daar geen antwoord van die teikenmasjien teruggestuur nie. As die UDP-poort gesluit is, moet 'n ICMP-poort onbereikbaar pakket van die teikenmasjien teruggestuur word.\

UDP-poort skandering is dikwels onbetroubaar, aangesien vuurmure en routers ICMP\
pakkette kan laat val. Dit kan lei tot vals positiewe in jou skandering, en jy sal gereeld\
UDP-poort skanderings sien wat alle UDP-poorte oop op 'n gescande masjien toon.\
o Meeste poort skandeerders skandeer nie alle beskikbare poorte nie, en het gewoonlik 'n vooraf ingestelde lys\
van “interessante poorte” wat geskandeer word.

# CTF - Tricks

In **Windows** gebruik **Winzip** om na lêers te soek.\
**Alternatiewe data Strome**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Begin met "_begin \<mode> \<filename>_" en vreemde karakters\
**Xxencoding** --> Begin met "_begin \<mode> \<filename>_" en B64\
\
**Vigenere** (frekwensie analise) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset van karakters) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Versteek boodskappe met spaties en tabulatoren

# Characters

%E2%80%AE => RTL Karakter (skryf payloads agterstewe)

{{#include ../banners/hacktricks-training.md}}
