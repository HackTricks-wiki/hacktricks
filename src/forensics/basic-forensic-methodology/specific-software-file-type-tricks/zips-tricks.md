# Trucos de ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Herramientas de línea de comandos** para gestionar **archivos zip** son esenciales para diagnosticar, reparar y descifrar archivos zip. Aquí hay algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo zip puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato de archivo zip.
- **`zipinfo`**: Lista el contenido de un archivo zip sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intenta reparar archivos zip corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para el descifrado por fuerza bruta de contraseñas zip, efectiva para contraseñas de hasta aproximadamente 7 caracteres.

La [especificación del formato de archivo Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles completos sobre la estructura y los estándares de los archivos zip.

Es crucial notar que los archivos zip protegidos por contraseña **no encriptan los nombres de archivo ni los tamaños de archivo** dentro, un defecto de seguridad que no comparten los archivos RAR o 7z, que encriptan esta información. Además, los archivos zip encriptados con el método más antiguo ZipCrypto son vulnerables a un **ataque de texto plano** si hay una copia no encriptada de un archivo comprimido disponible. Este ataque aprovecha el contenido conocido para descifrar la contraseña del zip, una vulnerabilidad detallada en [el artículo de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada más a fondo en [este artículo académico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Sin embargo, los archivos zip asegurados con encriptación **AES-256** son inmunes a este ataque de texto plano, lo que demuestra la importancia de elegir métodos de encriptación seguros para datos sensibles.

## Referencias

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
