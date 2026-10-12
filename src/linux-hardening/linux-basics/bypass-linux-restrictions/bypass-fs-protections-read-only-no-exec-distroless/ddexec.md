# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contexto

Linux normalmente ejecuta programas desde archivos ejecutables almacenados en disco o en memoria. Puede identificar un ejecutable mediante su nombre de ruta o descriptor de archivo, por lo que no siempre se necesita un nombre de ruta normal del sistema de archivos.<sup>[[2]](#references)</sup>

DDexec / EverythingExec usa la memoria de un **proceso que ya está en ejecución**. La página [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) trata la ejecución de archivos anónimos y la detección y recopilación forense relacionadas; la [descripción general de Memory Bypasses](index.html#memory-bypasses) también enlaza a MemExec y Memdlopen.<sup>[[1]](#references)</sup>

Esta técnica te permite **eludir técnicas de protección comunes, como solo lectura, noexec, listas de permitidos de nombres de archivo y listas de permitidos de hashes**.<sup>[[1]](#references)</sup>

## Dependencias

El script final depende de las siguientes herramientas para funcionar; deben estar disponibles en el sistema al que estás atacando (de forma predeterminada, las encontrarás en todas partes):

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

Si puedes modificar arbitrariamente la memoria de un proceso, puedes tomar el control de este. Esto puede usarse para secuestrar un proceso existente y reemplazarlo por otro programa. Podemos lograrlo usando la syscall `ptrace()` (que requiere que puedas ejecutar syscalls o que `gdb` esté disponible en el sistema) o, más interesante aún, escribiendo en `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

El archivo `/proc/$pid/mem` es una asignación uno a uno de todo el espacio de direcciones de un proceso (_p. ej._, desde `0x0000000000000000` hasta `0x7ffffffffffff000` en x86-64). Esto significa que leer o escribir en este archivo en un desplazamiento `x` equivale a leer o modificar el contenido de la dirección virtual `x`.

Ahora tenemos cuatro problemas básicos que afrontar:

- En general, solo root y el propietario del archivo pueden modificarlo.
- ASLR.
- Si intentamos leer o escribir en una dirección que no está asignada en el espacio de direcciones del programa, obtendremos un error de E/S.

Estos problemas tienen soluciones que, aunque no son perfectas, son buenas:

- La mayoría de los intérpretes de shell permiten crear descriptores de archivo que luego heredarán los procesos secundarios. Podemos crear un fd que apunte al archivo `mem` de la shell con permisos de escritura... así, los procesos secundarios que usen ese fd podrán modificar la memoria de la shell.
- ASLR ni siquiera es un problema; podemos consultar el archivo `maps` de la shell o cualquier otro archivo de procfs para obtener información sobre el espacio de direcciones del proceso.
- Por tanto, necesitamos hacer `lseek()` en el archivo. Desde la shell esto no se puede hacer salvo usando el infame `dd`.

### En más detalle

Los pasos son relativamente sencillos y no requieren ningún tipo de experiencia para entenderlos:<sup>[[1]](#references)</sup>

- Analiza el binario que queremos ejecutar y el loader para averiguar qué asignaciones necesitan. Después, crea un "shell"code que realice, en términos generales, los mismos pasos que lleva a cabo el kernel en cada llamada a `execve()`:
  - Crea dichas asignaciones.
  - Lee los binarios en ellas.
  - Configura los permisos.
  - Finalmente, inicializa la pila con los argumentos del programa y coloca el vector auxiliar (que necesita el loader).
  - Salta al loader y deja que haga el resto (cargar las bibliotecas que necesita el programa).
- Obtén del archivo `syscall` la dirección a la que regresará el proceso después de la syscall que está ejecutando.
- Sobrescribe esa ubicación, que será ejecutable, con nuestro shellcode (a través de `mem` podemos modificar páginas no escribibles).
- Pasa el programa que queremos ejecutar a la entrada estándar del proceso (el "shell"code lo leerá con `read()`).
- En este punto, el loader se encarga de cargar las bibliotecas necesarias para nuestro programa y saltar a él.

**Echa un vistazo a la herramienta en** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Hay varias alternativas a `dd`; una de ellas, `tail`, es actualmente el programa predeterminado para hacer `lseek()` en el archivo `mem` (que era el único propósito de usar `dd`). Estas alternativas son:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

Al establecer la variable `SEEKER`, puedes cambiar el seeker utilizado, _p. ej._:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Si encuentras otro seeker válido que no esté implementado en el script, puedes usarlo igualmente configurando la variable `SEEKER_ARGS`:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Bloqueen esto, EDRs.

## References

- [1] [DDexec: Una técnica para ejecutar binarios sin archivos y de forma sigilosa en Linux](https://github.com/arget13/DDexec)
- [2] [execveat(2) — página del manual de Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
