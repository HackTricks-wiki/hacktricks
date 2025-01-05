{{#include ../banners/hacktricks-training.md}}

En una respuesta de ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás, algún linux

$1$- md5\
$2$o $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Si no sabes qué hay detrás de un servicio, intenta hacer una solicitud HTTP GET.

**Escaneos UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Se envía un paquete UDP vacío a un puerto específico. Si el puerto UDP está abierto, no se envía respuesta desde la máquina objetivo. Si el puerto UDP está cerrado, se debería enviar un paquete ICMP de puerto inalcanzable desde la máquina objetivo.\

El escaneo de puertos UDP a menudo es poco confiable, ya que los firewalls y routers pueden descartar paquetes ICMP.\
Esto puede llevar a falsos positivos en tu escaneo, y regularmente verás\
escaneos de puertos UDP mostrando todos los puertos UDP abiertos en una máquina escaneada.\
o La mayoría de los escáneres de puertos no escanean todos los puertos disponibles, y generalmente tienen una lista preestablecida de “puertos interesantes” que se escanean.

# CTF - Tricks

En **Windows** usa **Winzip** para buscar archivos.\
**Flujos de datos alternativos**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Cripto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Comienza con "_begin \<mode> \<filename>_" y caracteres extraños\
**Xxencoding** --> Comienza con "_begin \<mode> \<filename>_" y B64\
\
**Vigenere** (análisis de frecuencia) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (desplazamiento de caracteres) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ocultar mensajes usando espacios y tabulaciones

# Caracteres

%E2%80%AE => Carácter RTL (escribe cargas útiles al revés)

{{#include ../banners/hacktricks-training.md}}
