# Trucos de archivos ZIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR a los repositorios** [**hacktricks**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Hay varias herramientas de línea de comandos para archivos zip que serán útiles conocer.

* `unzip` a menudo proporciona información útil sobre por qué un archivo zip no se puede descomprimir.
* `zipdetails -v` proporcionará información detallada sobre los valores presentes en los diversos campos del formato.
* `zipinfo` lista información sobre el contenido del archivo zip, sin extraerlo.
* `zip -F input.zip --out output.zip` y `zip -FF input.zip --out output.zip` intentan reparar un archivo zip corrupto.
* [fcrackzip](https://github.com/hyc/fcrackzip) adivina por fuerza bruta una contraseña de zip (para contraseñas de <7 caracteres aproximadamente).

[Especificación del formato de archivo zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Una nota importante relacionada con la seguridad sobre los archivos zip protegidos con contraseña es que no cifran los nombres de archivo y los tamaños de archivo originales de los archivos comprimidos que contienen, a diferencia de los archivos RAR o 7z protegidos con contraseña.

Otra nota sobre la descarga de archivos zip es que si tiene una copia sin cifrar / sin comprimir de cualquiera de los archivos que se comprimen en el archivo zip cifrado, puede realizar un "ataque de texto sin formato" y descifrar el archivo zip, como se detalla aquí, y se explica en este documento. El nuevo esquema para proteger con contraseña los archivos zip (con AES-256, en lugar de "ZipCrypto") no tiene esta debilidad.

De: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](http://localhost:5000/s/-L\_2uGJGU7AVNRcqRvEi/)
