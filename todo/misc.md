<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


En una respuesta de ping TTL:\
127 = Windows\
254 = Cisco\
Lo demás, algún linux

$1$- md5\
$2$ o $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Si no sabes qué hay detrás de un servicio, intenta hacer una petición HTTP GET.

**Escaneos UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Se envía un paquete UDP vacío a un puerto específico. Si el puerto UDP está abierto, no se envía respuesta desde la máquina objetivo. Si el puerto UDP está cerrado, se debería enviar un paquete ICMP de puerto inalcanzable desde la máquina objetivo.\


El escaneo de puertos UDP a menudo es poco fiable, ya que los firewalls y routers pueden descartar paquetes ICMP\
Esto puede llevar a falsos positivos en tu escaneo, y verás regularmente\
escaneos de puertos UDP mostrando todos los puertos UDP abiertos en una máquina escaneada.\
o La mayoría de los escáneres de puertos no escanean todos los puertos disponibles, y generalmente tienen una lista preestablecida\
de "puertos interesantes" que son escaneados.

# CTF - Trucos

En **Windows** usa **Winzip** para buscar archivos.\
**Flujos de datos alternativos**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Criptografía

**featherduster**


**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
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

Snow --> Oculta mensajes utilizando espacios y tabs

# Caracteres

%E2%80%AE => Carácter RTL (escribe cargas útiles al revés)


<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
