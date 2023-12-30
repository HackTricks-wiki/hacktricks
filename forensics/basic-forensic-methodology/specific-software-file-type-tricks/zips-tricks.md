# Trucos con ZIPs

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Existen varias herramientas de línea de comandos para archivos zip que son útiles conocer.

* `unzip` a menudo proporciona información útil sobre por qué un zip no se descomprime.
* `zipdetails -v` ofrece información detallada sobre los valores presentes en los distintos campos del formato.
* `zipinfo` lista información sobre el contenido del archivo zip, sin extraerlo.
* `zip -F input.zip --out output.zip` y `zip -FF input.zip --out output.zip` intentan reparar un archivo zip dañado.
* [fcrackzip](https://github.com/hyc/fcrackzip) realiza intentos de fuerza bruta para adivinar la contraseña de un zip (para contraseñas de <7 caracteres aproximadamente).

[Especificación del formato de archivo zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Una nota importante relacionada con la seguridad sobre los archivos zip protegidos con contraseña es que no cifran los nombres de archivo ni los tamaños originales de los archivos comprimidos que contienen, a diferencia de los archivos RAR o 7z protegidos con contraseña.

Otra nota sobre la ruptura de zips es que si tienes una copia sin cifrar/descomprimir de cualquiera de los archivos que están comprimidos en el zip encriptado, puedes realizar un "ataque de texto plano" y romper el zip, como se [detalla aquí](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), y se explica en [este documento](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). El esquema más nuevo para proteger archivos zip con contraseña (con AES-256, en lugar de "ZipCrypto") no tiene esta debilidad.

De: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
