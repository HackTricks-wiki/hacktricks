<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


En una respuesta de ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás, algún Linux

$1$- md5\
$2$ o $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Si no sabes qué hay detrás de un servicio, intenta hacer una solicitud HTTP GET.

**Escaneos UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Se envía un paquete UDP vacío a un puerto específico. Si el puerto UDP está abierto, la máquina objetivo no enviará ninguna respuesta. Si el puerto UDP está cerrado, la máquina objetivo debería enviar un paquete ICMP de puerto inalcanzable.\

El escaneo de puertos UDP a menudo es poco confiable, ya que los firewalls y routers pueden descartar paquetes ICMP. Esto puede llevar a falsos positivos en tu escaneo, y verás regularmente escaneos de puertos UDP mostrando todos los puertos UDP abiertos en una máquina escaneada.\
o La mayoría de los escáneres de puertos no escanean todos los puertos disponibles, y generalmente tienen una lista predefinida de "puertos interesantes" que se escanean.

# CTF - Trucos

En **Windows** usa **Winzip** para buscar archivos.\
**Flujos de datos alternativos**: _dir /r | find ":$DATA"_
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Comienza con "_begin \<modo> \<nombre de archivo>_" y caracteres extraños\
**Xxencoding** --> Comienza con "_begin \<modo> \<nombre de archivo>_" y B64\
\
**Vigenere** (análisis de frecuencia) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (desplazamiento de caracteres) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Ocultar mensajes usando espacios y tabulaciones

# Characters

%E2%80%AE => Carácter RTL (escribe payloads al revés)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
