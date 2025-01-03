{{#include ../banners/hacktricks-training.md}}

U ping odgovoru TTL:\
127 = Windows\
254 = Cisco\
Ostalo, neki linux

$1$- md5\
$2$ili $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Ako ne znate šta se nalazi iza usluge, pokušajte da napravite HTTP GET zahtev.

**UDP skeniranja**\
nc -nv -u -z -w 1 \<IP> 160-16

Prazan UDP paket se šalje na određeni port. Ako je UDP port otvoren, nema odgovora sa ciljne mašine. Ako je UDP port zatvoren, ICMP paket o nedostupnom portu treba da se vrati sa ciljne mašine.\

UDP skeniranje portova često nije pouzdano, jer vatrozidi i ruteri mogu odbaciti ICMP\
pakete. To može dovesti do lažno pozitivnih rezultata u vašem skeniranju, i redovno ćete videti\
UDP skeniranja portova koja prikazuju sve UDP portove otvorene na skeniranoj mašini.\
Većina skenera portova ne skenira sve dostupne portove, i obično imaju unapred postavljenu listu\
“zanimljivih portova” koji se skeniraju.

# CTF - Trikovi

U **Windows** koristite **Winzip** za pretragu datoteka.\
**Alternativni podaci Strimovi**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Počnite sa "_begin \<mode> \<filename>_" i čudnim karakterima\
**Xxencoding** --> Počnite sa "_begin \<mode> \<filename>_" i B64\
\
**Vigenere** (analiza frekvencije) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (pomak karaktera) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Sakrijte poruke koristeći razmake i tabove

# Characters

%E2%80%AE => RTL karakter (piše payload-ove unazad)

{{#include ../banners/hacktricks-training.md}}
