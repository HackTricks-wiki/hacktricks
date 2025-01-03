{{#include ../banners/hacktricks-training.md}}

Katika jibu la ping TTL:\
127 = Windows\
254 = Cisco\
Mengine, baadhi ya linux

$1$- md5\
$2$au $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Ikiwa hujui kilicho nyuma ya huduma, jaribu kufanya ombi la HTTP GET.

**UDP Scans**\
nc -nv -u -z -w 1 \<IP> 160-16

Pakiti tupu ya UDP inatumwa kwa bandari maalum. Ikiwa bandari ya UDP iko wazi, hakuna jibu litatumwa kutoka kwa mashine lengwa. Ikiwa bandari ya UDP imefungwa, pakiti ya ICMP port unreachable inapaswa kutumwa kutoka kwa mashine lengwa.\

Kuchunguza bandari za UDP mara nyingi hakutegemeki, kwani firewalls na routers zinaweza kuondoa pakiti za ICMP\
hii inaweza kusababisha matokeo ya uwongo katika uchunguzi wako, na utaona mara kwa mara\
uchunguzi wa bandari za UDP ukionyesha bandari zote za UDP zikiwa wazi kwenye mashine iliyochunguzwa.\
au Skana nyingi za bandari hazichunguze bandari zote zinazopatikana, na kwa kawaida zina orodha iliyowekwa ya “bandari za kuvutia” zinazochunguzwa.

# CTF - Tricks

Katika **Windows** tumia **Winzip** kutafuta faili.\
**Alternate data Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Anza na "_begin \<mode> \<filename>_" na herufi za ajabu\
**Xxencoding** --> Anza na "_begin \<mode> \<filename>_" na B64\
\
**Vigenere** (uchambuzi wa masafa) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (mabadiliko ya wahusika) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ficha ujumbe kwa kutumia nafasi na tab

# Characters

%E2%80%AE => Mwandiko wa RTL (andika payloads kwa nyuma)

{{#include ../banners/hacktricks-training.md}}
