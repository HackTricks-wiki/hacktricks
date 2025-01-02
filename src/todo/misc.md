{{#include ../banners/hacktricks-training.md}}

Em uma resposta de ping TTL:\
127 = Windows\
254 = Cisco\
O restante, algum linux

$1$- md5\
$2$ou $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Se você não souber o que está por trás de um serviço, tente fazer uma solicitação HTTP GET.

**Escaneamentos UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Um pacote UDP vazio é enviado para uma porta específica. Se a porta UDP estiver aberta, nenhuma resposta é enviada de volta da máquina alvo. Se a porta UDP estiver fechada, um pacote ICMP de porta inatingível deve ser enviado de volta da máquina alvo.\

A varredura de portas UDP é frequentemente não confiável, pois firewalls e roteadores podem descartar pacotes ICMP.\
Isso pode levar a falsos positivos em sua varredura, e você verá regularmente\
varreduras de portas UDP mostrando todas as portas UDP abertas em uma máquina escaneada.\
A maioria dos scanners de porta não escaneia todas as portas disponíveis e geralmente tem uma lista predefinida de “portas interessantes” que são escaneadas.

# CTF - Truques

Em **Windows** use **Winzip** para procurar arquivos.\
**Streams de dados alternativos**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Cripto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Comece com "_begin \<mode> \<filename>_" e caracteres estranhos\
**Xxencoding** --> Comece com "_begin \<mode> \<filename>_" e B64\
\
**Vigenere** (análise de frequência) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (deslocamento de caracteres) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Oculte mensagens usando espaços e tabulações

# Caracteres

%E2%80%AE => Caractere RTL (escreve payloads ao contrário)

{{#include ../banners/hacktricks-training.md}}
