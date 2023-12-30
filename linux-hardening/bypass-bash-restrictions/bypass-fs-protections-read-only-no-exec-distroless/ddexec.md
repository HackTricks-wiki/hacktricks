# DDexec / EverythingExec

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexto

En Linux, para ejecutar un programa, debe existir como archivo y debe ser accesible de alguna manera a través de la jerarquía del sistema de archivos (esto es simplemente cómo funciona `execve()`). Este archivo puede residir en disco o en ram (tmpfs, memfd), pero necesitas una ruta de archivo. Esto ha facilitado mucho el control de lo que se ejecuta en un sistema Linux, facilita la detección de amenazas y herramientas de atacantes o prevenir que intenten ejecutar algo propio en absoluto (_por ejemplo_, no permitir a usuarios sin privilegios colocar archivos ejecutables en cualquier lugar).

Pero esta técnica está aquí para cambiar todo eso. Si no puedes iniciar el proceso que deseas... **entonces secuestra uno ya existente**.

Esta técnica te permite **burlar técnicas de protección comunes como solo lectura, noexec, listas blancas de nombres de archivos, listas blancas de hashes...**

## Dependencias

El script final depende de las siguientes herramientas para funcionar, necesitan ser accesibles en el sistema que estás atacando (por defecto las encontrarás en todas partes):
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

Si puedes modificar arbitrariamente la memoria de un proceso, entonces puedes tomar el control de él. Esto se puede utilizar para secuestrar un proceso ya existente y reemplazarlo con otro programa. Podemos lograr esto ya sea utilizando la llamada al sistema `ptrace()` (que requiere que tengas la capacidad de ejecutar llamadas al sistema o que tengas gdb disponible en el sistema) o, más interesantemente, escribiendo en `/proc/$pid/mem`.

El archivo `/proc/$pid/mem` es un mapeo uno a uno de todo el espacio de direcciones de un proceso (_por ejemplo_, de `0x0000000000000000` a `0x7ffffffffffff000` en x86-64). Esto significa que leer o escribir en este archivo en un desplazamiento `x` es lo mismo que leer o modificar el contenido en la dirección virtual `x`.

Ahora, tenemos cuatro problemas básicos que enfrentar:

* En general, solo root y el propietario del programa del archivo pueden modificarlo.
* ASLR.
* Si intentamos leer o escribir en una dirección no mapeada en el espacio de direcciones del programa, obtendremos un error de E/S.

Estos problemas tienen soluciones que, aunque no son perfectas, son buenas:

* La mayoría de los intérpretes de comandos permiten la creación de descriptores de archivos que luego serán heredados por procesos hijos. Podemos crear un fd apuntando al archivo `mem` de la shell con permisos de escritura... así los procesos hijos que usen ese fd podrán modificar la memoria de la shell.
* ASLR ni siquiera es un problema, podemos verificar el archivo `maps` de la shell o cualquier otro del procfs para obtener información sobre el espacio de direcciones del proceso.
* Así que necesitamos hacer `lseek()` sobre el archivo. Desde la shell esto no se puede hacer a menos que se use el infame `dd`.

### Más en detalle

Los pasos son relativamente fáciles y no requieren ningún tipo de experiencia para entenderlos:

* Analizar el binario que queremos ejecutar y el cargador para averiguar qué mapeos necesitan. Luego, elaborar un "shell"code que realizará, en términos generales, los mismos pasos que el kernel hace en cada llamada a `execve()`:
* Crear dichos mapeos.
* Leer los binarios en ellos.
* Establecer permisos.
* Finalmente, inicializar la pila con los argumentos para el programa y colocar el vector auxiliar (necesario por el cargador).
* Saltar al cargador y dejar que haga el resto (cargar las bibliotecas necesarias para el programa).
* Obtener del archivo `syscall` la dirección a la que el proceso regresará después de la llamada al sistema que está ejecutando.
* Sobrescribir ese lugar, que será ejecutable, con nuestro shellcode (a través de `mem` podemos modificar páginas no escribibles).
* Pasar el programa que queremos ejecutar al stdin del proceso (será `read()` por dicho "shell"code).
* En este punto depende del cargador cargar las bibliotecas necesarias para nuestro programa y saltar a él.

**Consulta la herramienta en** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

A partir del 12/12/2022 he encontrado una serie de alternativas a `dd`, una de las cuales, `tail`, es actualmente el programa predeterminado utilizado para hacer `lseek()` a través del archivo `mem` (que era el único propósito de usar `dd`). Las alternativas mencionadas son:
```bash
tail
hexdump
cmp
xxd
```
Estableciendo la variable `SEEKER` puedes cambiar el buscador utilizado, _p. ej._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si encuentra otro seeker válido que no esté implementado en el script, aún puede usarlo configurando la variable `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquea esto, EDRs.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
