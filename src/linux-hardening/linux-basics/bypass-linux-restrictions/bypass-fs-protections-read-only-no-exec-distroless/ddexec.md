# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contexto

En Linux, para ejecutar un programa este debe existir como archivo y debe ser accesible de alguna forma a través de la jerarquía del sistema de archivos (así es como funciona `execve()`). Este archivo puede residir en el disco o en la RAM (tmpfs, memfd), pero necesitas una ruta de archivo. Esto ha facilitado mucho controlar qué se ejecuta en un sistema Linux, detectar threats y las herramientas del atacante, o impedir por completo que intenten ejecutar algo propio (_p. ej._, no permitir que usuarios sin privilegios coloquen archivos ejecutables en ningún lugar).

Pero esta técnica está aquí para cambiar todo esto. Si no puedes iniciar el proceso que quieres... **entonces secuestras uno que ya exista**.

Esta técnica permite **evadir técnicas de protección comunes, como read-only, noexec, file-name whitelisting, hash whitelisting...**

## Dependencias

El script final depende de las siguientes herramientas para funcionar; deben ser accesibles en el sistema que estás atacando (por defecto, las encontrarás en todas partes):
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

Si puedes modificar arbitrariamente la memoria de un proceso, puedes tomar el control de este. Esto puede utilizarse para secuestrar un proceso ya existente y reemplazarlo por otro programa. Podemos lograrlo utilizando la syscall `ptrace()` (lo que requiere tener la capacidad de ejecutar syscalls o disponer de gdb en el sistema) o, de forma más interesante, escribiendo en `/proc/$pid/mem`.

El archivo `/proc/$pid/mem` es un mapeo uno a uno de todo el espacio de direcciones de un proceso (_p. ej._, desde `0x0000000000000000` hasta `0x7ffffffffffff000` en x86-64). Esto significa que leer o escribir en este archivo en un offset `x` equivale a leer o modificar el contenido de la dirección virtual `x`.

Ahora tenemos cuatro problemas básicos que afrontar:

- En general, solo root y el propietario del programa pueden modificarlo.
- ASLR.
- Si intentamos leer o escribir en una dirección que no está mapeada en el espacio de direcciones del programa, obtendremos un error de E/S.

Estos problemas tienen soluciones que, aunque no son perfectas, son buenas:

- La mayoría de los intérpretes de shell permiten crear file descriptors que luego serán heredados por los procesos hijos. Podemos crear un fd que apunte al archivo `mem` del shell con permisos de escritura... así, los procesos hijos que utilicen ese fd podrán modificar la memoria del shell.
- ASLR ni siquiera es un problema: podemos consultar el archivo `maps` del shell o cualquier otro archivo de procfs para obtener información sobre el espacio de direcciones del proceso.
- Por tanto, necesitamos hacer `lseek()` sobre el archivo. Desde el shell esto no se puede hacer salvo utilizando el infame `dd`.

### En más detalle

Los pasos son relativamente fáciles y no requieren ningún tipo de experiencia para entenderlos:

- Analizar el binario que queremos ejecutar y el loader para averiguar qué mapeos necesitan. Luego crear un "shell"code que realice, a grandes rasgos, los mismos pasos que hace el kernel en cada llamada a `execve()`:
- Crear dichos mapeos.
- Leer los binarios en ellos.
- Configurar los permisos.
- Finalmente, inicializar el stack con los argumentos del programa y colocar el vector auxiliar (necesario para el loader).
- Saltar al loader y dejar que haga el resto (cargar las libraries necesarias para el programa).
- Obtener del archivo `syscall` la dirección a la que regresará el proceso después de la syscall que está ejecutando.
- Sobrescribir ese lugar, que será executable, con nuestro shellcode (a través de `mem` podemos modificar páginas no escribibles).
- Pasar el programa que queremos ejecutar a la stdin del proceso (será `read()` por dicho "shell"code).
- En este punto, el loader debe cargar las libraries necesarias para nuestro programa y saltar a él.

**Consulta la herramienta en** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Existen varias alternativas a `dd`, una de las cuales, `tail`, es actualmente el programa predeterminado utilizado para hacer `lseek()` a través del archivo `mem` (que era el único propósito de utilizar `dd`). Dichas alternativas son:
```bash
tail
hexdump
cmp
xxd
```
Al configurar la variable `SEEKER`, puedes cambiar el seeker utilizado, _p. ej._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si encuentras otro seeker válido que no esté implementado en el script, aún puedes usarlo configurando la variable `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueen esto, EDRs.

## Referencias

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
