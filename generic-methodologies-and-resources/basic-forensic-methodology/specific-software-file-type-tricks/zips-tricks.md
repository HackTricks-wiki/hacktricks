# Trucos de archivos ZIP

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Las **herramientas de línea de comandos** para gestionar **archivos ZIP** son esenciales para diagnosticar, reparar y crackear archivos ZIP. Aquí tienes algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo ZIP puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato de archivo ZIP.
- **`zipinfo`**: Lista el contenido de un archivo ZIP sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intenta reparar archivos ZIP corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para crackear por fuerza bruta contraseñas de archivos ZIP, efectiva para contraseñas de hasta alrededor de 7 caracteres.

La [especificación del formato de archivo ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles completos sobre la estructura y los estándares de los archivos ZIP.

Es crucial tener en cuenta que los archivos ZIP protegidos con contraseña **no cifran los nombres de archivo ni los tamaños de archivo** en su interior, una falla de seguridad que no comparten los archivos RAR o 7z, que cifran esta información. Además, los archivos ZIP cifrados con el antiguo método ZipCrypto son vulnerables a un **ataque de texto plano** si hay una copia sin cifrar de un archivo comprimido disponible. Este ataque aprovecha el contenido conocido para crackear la contraseña del ZIP, una vulnerabilidad detallada en el [artículo de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada más detalladamente en [este documento académico](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Sin embargo, los archivos ZIP asegurados con cifrado **AES-256** son inmunes a este ataque de texto plano, lo que destaca la importancia de elegir métodos de cifrado seguros para datos sensibles.

# Referencias
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
