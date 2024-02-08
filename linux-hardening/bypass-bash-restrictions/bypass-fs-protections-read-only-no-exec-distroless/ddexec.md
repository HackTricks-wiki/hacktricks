# DDexec / EverythingExec

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Contexto

En Linux, para ejecutar un programa, este debe existir como un archivo, debe ser accesible de alguna manera a través de la jerarquía del sistema de archivos (así es como funciona `execve()`). Este archivo puede residir en disco o en la memoria RAM (tmpfs, memfd), pero necesitas una ruta de archivo. Esto ha hecho muy fácil controlar lo que se ejecuta en un sistema Linux, facilita detectar amenazas y herramientas de atacantes o evitar que intenten ejecutar algo propio en absoluto (_por ejemplo, no permitir que usuarios no privilegiados coloquen archivos ejecutables en cualquier lugar).

Pero esta técnica está aquí para cambiar todo esto. Si no puedes iniciar el proceso que deseas... **entonces secuestras uno que ya existe**.

Esta técnica te permite **burlar técnicas de protección comunes como solo lectura, noexec, lista blanca de nombres de archivo, lista blanca de hash...**

## Dependencias

El script final depende de las siguientes herramientas para funcionar, estas deben ser accesibles en el sistema que estás atacando (por defecto las encontrarás en todas partes):
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

Si puedes modificar arbitrariamente la memoria de un proceso, entonces puedes tomar el control de él. Esto se puede utilizar para secuestrar un proceso existente y reemplazarlo con otro programa. Podemos lograr esto ya sea usando la llamada al sistema `ptrace()` (lo cual requiere tener la capacidad de ejecutar llamadas al sistema o tener gdb disponible en el sistema) o, de manera más interesante, escribiendo en `/proc/$pid/mem`.

El archivo `/proc/$pid/mem` es un mapeo uno a uno de todo el espacio de direcciones de un proceso (por ejemplo, desde `0x0000000000000000` hasta `0x7ffffffffffff000` en x86-64). Esto significa que leer o escribir en este archivo en un desplazamiento `x` es lo mismo que leer o modificar el contenido en la dirección virtual `x`.

Ahora, tenemos cuatro problemas básicos a enfrentar:

- En general, solo root y el propietario del programa del archivo pueden modificarlo.
- ASLR.
- Si intentamos leer o escribir en una dirección no mapeada en el espacio de direcciones del programa, obtendremos un error de E/S.

Estos problemas tienen soluciones que, aunque no son perfectas, son buenas:

- La mayoría de los intérpretes de shell permiten la creación de descriptores de archivo que luego serán heredados por los procesos secundarios. Podemos crear un descriptor de archivo que apunte al archivo `mem` de la shell con permisos de escritura... por lo tanto, los procesos secundarios que utilicen ese descriptor de archivo podrán modificar la memoria de la shell.
- ASLR ni siquiera es un problema, podemos verificar el archivo `maps` de la shell o cualquier otro del procfs para obtener información sobre el espacio de direcciones del proceso.
- Entonces necesitamos hacer `lseek()` sobre el archivo. Desde la shell esto no se puede hacer a menos que se use el infame `dd`.

### Con más detalle

Los pasos son relativamente fáciles y no requieren ningún tipo de experiencia para entenderlos:

- Analizar el binario que queremos ejecutar y el cargador para averiguar qué mapeos necesitan. Luego crear un "código" de "shell" que realizará, en términos generales, los mismos pasos que el kernel hace en cada llamada a `execve()`:
- Crear dichos mapeos.
- Leer los binarios en ellos.
- Configurar los permisos.
- Finalmente, inicializar la pila con los argumentos del programa y colocar el vector auxiliar (necesario por el cargador).
- Saltar al cargador y dejar que haga el resto (cargar las bibliotecas necesarias para el programa).
- Obtener del archivo `syscall` la dirección a la que el proceso regresará después de la llamada al sistema que está ejecutando.
- Sobrescribir ese lugar, que será ejecutable, con nuestro código de "shell" (a través de `mem` podemos modificar páginas no escribibles).
- Pasar el programa que queremos ejecutar a la entrada estándar del proceso (será `leído()` por dicho código de "shell").
- En este punto, depende del cargador cargar las bibliotecas necesarias para nuestro programa y saltar a él.

**Echa un vistazo a la herramienta en** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Existen varias alternativas a `dd`, una de las cuales, `tail`, es actualmente el programa predeterminado utilizado para `lseek()` a través del archivo `mem` (que era el único propósito de usar `dd`). Dichas alternativas son:
```bash
tail
hexdump
cmp
xxd
```
Al establecer la variable `SEEKER` puedes cambiar el buscador utilizado, _por ejemplo_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si encuentras otro buscador válido que no esté implementado en el script, aún puedes usarlo configurando la variable `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquea esto, EDRs.

## Referencias
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
