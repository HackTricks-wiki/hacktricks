{{#include ../banners/hacktricks-training.md}}

Bir ping yanıtında TTL:\
127 = Windows\
254 = Cisco\
Diğerleri, bazılinux

$1$- md5\
$2$veya $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Bir hizmetin arkasında ne olduğunu bilmiyorsanız, bir HTTP GET isteği yapmayı deneyin.

**UDP Tarama**\
nc -nv -u -z -w 1 \<IP> 160-16

Boş bir UDP paketi belirli bir porta gönderilir. Eğer UDP portu açıksa, hedef makineden geri bir yanıt gönderilmez. Eğer UDP portu kapalıysa, hedef makineden bir ICMP port ulaşılamaz paketi gönderilmelidir.\

UDP port taraması genellikle güvenilir değildir, çünkü güvenlik duvarları ve yönlendiriciler ICMP\
paketlerini düşürebilir. Bu, taramanızda yanlış pozitiflere yol açabilir ve taranan bir makinede tüm UDP portlarının açık olduğunu gösteren UDP port taramaları görebilirsiniz.\
Çoğu port tarayıcı tüm mevcut portları taramaz ve genellikle taranan "ilginç portlar" için önceden ayarlanmış bir listeye sahiptir.

# CTF - Hileler

**Windows**'ta dosyaları aramak için **Winzip** kullanın.\
**Alternatif veri Akışları**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Kripto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" ile başla ve garip karakterler\
**Xxencoding** --> "_begin \<mode> \<filename>_" ile başla ve B64\
\
**Vigenere** (frekans analizi) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (karakterlerin kaydırılması) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Mesajları boşluklar ve sekmeler kullanarak gizle

# Karakterler

%E2%80%AE => RTL Karakteri (yükleme verilerini ters yazar)

{{#include ../banners/hacktricks-training.md}}
