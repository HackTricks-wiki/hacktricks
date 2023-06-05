# DDexec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Contexto

En Linux, para ejecutar un programa, este debe existir como archivo y debe ser accesible de alguna manera a través de la jerarquía del sistema de archivos (esto es simplemente cómo funciona `execve()`). Este archivo puede residir en el disco o en la memoria RAM (tmpfs, memfd), pero necesitas una ruta de archivo. Esto ha hecho muy fácil controlar lo que se ejecuta en un sistema Linux, lo que facilita la detección de amenazas y herramientas de atacantes o evitar que intenten ejecutar cualquier cosa de ellos en absoluto (_por ejemplo_, no permitir que los usuarios sin privilegios coloquen archivos ejecutables en cualquier lugar).

Pero esta técnica está aquí para cambiar todo esto. Si no puedes iniciar el proceso que deseas... **entonces secuestras uno que ya existe**.

Esta técnica te permite **burlar técnicas de protección comunes como solo lectura, noexec, lista blanca de nombres de archivo, lista blanca de hash...**

## Dependencias

El script final depende de las siguientes herramientas para funcionar, deben ser accesibles en el sistema que estás atacando (por defecto las encontrarás en todas partes):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## La técnica

Si eres capaz de modificar arbitrariamente la memoria de un proceso, entonces puedes tomar el control de él. Esto se puede utilizar para secuestrar un proceso ya existente y reemplazarlo con otro programa. Podemos lograr esto utilizando la llamada al sistema `ptrace()` (que requiere que tengas la capacidad de ejecutar llamadas al sistema o tener gdb disponible en el sistema) o, de manera más interesante, escribiendo en `/proc/$pid/mem`.

El archivo `/proc/$pid/mem` es un mapeo uno a uno de todo el espacio de direcciones de un proceso (por ejemplo, desde `0x0000000000000000` hasta `0x7ffffffffffff000` en x86-64). Esto significa que leer o escribir en este archivo en un desplazamiento `x` es lo mismo que leer o modificar el contenido en la dirección virtual `x`.

Ahora, tenemos cuatro problemas básicos a enfrentar:

* En general, solo el root y el propietario del programa del archivo pueden modificarlo.
* ASLR.
* Si intentamos leer o escribir en una dirección que no está mapeada en el espacio de direcciones del programa, obtendremos un error de E/S.

Estos problemas tienen soluciones que, aunque no son perfectas, son buenas:

* La mayoría de los intérpretes de shell permiten la creación de descriptores de archivos que luego serán heredados por los procesos secundarios. Podemos crear un descriptor de archivo que apunte al archivo `mem` de la shell con permisos de escritura... de esta manera, los procesos secundarios que usen ese descriptor de archivo podrán modificar la memoria de la shell.
* ASLR ni siquiera es un problema, podemos verificar el archivo `maps` de la shell o cualquier otro del procfs para obtener información sobre el espacio de direcciones del proceso.
* Entonces necesitamos hacer `lseek()` sobre el archivo. Desde la shell esto no se puede hacer a menos que se use el infame `dd`.

### Con más detalle

Los pasos son relativamente fáciles y no requieren ningún tipo de experiencia para entenderlos:

* Analiza el binario que queremos ejecutar y el cargador para averiguar qué mapeos necesitan. Luego crea un "código de shell" que realizará, en términos generales, los mismos pasos que el kernel hace en cada llamada a `execve()`:
  * Crea dichos mapeos.
  * Lee los binarios en ellos.
  * Configura los permisos.
  * Finalmente inicializa la pila con los argumentos para el programa y coloca el vector auxiliar (necesario para el cargador).
  * Salta al cargador y deja que haga el resto (cargar bibliotecas necesarias para el programa).
* Obtén del archivo `syscall` la dirección a la que el proceso volverá después de la llamada al sistema que está ejecutando.
* Sobrescribe ese lugar, que será ejecutable, con nuestro código de shell (a través de `mem` podemos modificar páginas no escribibles).
* Pasa el programa que queremos ejecutar a la entrada estándar del proceso (será `leído()` por dicho "código de shell").
* En este punto, depende del cargador cargar las bibliotecas necesarias para nuestro programa y saltar a él.

**Echa un vistazo a la herramienta en** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿o quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
