# Trucos de archivos ZIP

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Existen varias herramientas de línea de comandos para archivos zip que serán útiles de conocer.

* `unzip` a menudo proporcionará información útil sobre por qué un zip no se puede descomprimir.
* `zipdetails -v` proporcionará información detallada sobre los valores presentes en los diversos campos del formato.
* `zipinfo` lista información sobre el contenido del archivo zip, sin extraerlo.
* `zip -F input.zip --out output.zip` y `zip -FF input.zip --out output.zip` intentan reparar un archivo zip corrupto.
* [fcrackzip](https://github.com/hyc/fcrackzip) realiza suposiciones de fuerza bruta sobre una contraseña zip (para contraseñas <7 caracteres aproximadamente).

[Especificación del formato de archivo ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Una nota importante relacionada con la seguridad sobre archivos zip protegidos con contraseña es que no cifran los nombres de archivo y los tamaños de archivo originales de los archivos comprimidos que contienen, a diferencia de los archivos RAR o 7z protegidos con contraseña.

Otra nota sobre la craqueo de zip es que si tienes una copia sin cifrar/descomprimida de cualquiera de los archivos que están comprimidos en el zip cifrado, puedes realizar un "ataque de texto plano" y craquear el zip, como se detalla [aquí](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), y se explica en [este documento](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). El nuevo esquema para proteger con contraseña archivos zip (con AES-256, en lugar de "ZipCrypto") no tiene esta debilidad.

Desde: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)
