# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variables de identificación de usuario

- **`ruid`**: El **ID de usuario real** indica el usuario que inició el proceso.<sup>[[1]](#references)</sup>
- **`euid`**: Conocido como **ID de usuario efectivo**, representa la identidad de usuario que utiliza el sistema para determinar los privilegios del proceso. Generalmente, `euid` refleja `ruid`, salvo en casos como la ejecución de un binario SetUID (cuando se respeta la transición set-user-ID), donde `euid` adopta la identidad del propietario del archivo, otorgando así permisos operativos específicos.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Este **ID de usuario guardado** es fundamental cuando un proceso con privilegios elevados (normalmente ejecutándose como root) necesita renunciar temporalmente a sus privilegios para realizar ciertas tareas y, posteriormente, recuperar su estado elevado inicial.<sup>[[1]](#references)</sup>

#### Nota importante

Un proceso sin privilegios solo puede modificar su `euid` para que coincida con el `ruid`, `euid` o `suid` actual.<sup>[[3]](#references)</sup>

### Comprensión de las funciones set\*uid

- **`setuid`**: Contrariamente a lo que podría suponerse inicialmente, `setuid` establece el `euid` del proceso que realiza la llamada. Para un proceso con privilegios, también establece `ruid` y `suid` en el usuario especificado; una vez que todos los ID se establecen en root, el proceso no puede recuperar una identidad anterior mediante `setuid`. Se pueden consultar detalles en la [página man de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** y **`setresuid`**: `setreuid` cambia `ruid` y `euid`, mientras que `setresuid` cambia los tres ID. Para un proceso sin privilegios, `setresuid` restringe cada destino al `ruid`, `euid` o `suid` actual; `setreuid` restringe `euid` a esos valores y `ruid` al `ruid` o `euid` actual. Un proceso con `CAP_SETUID` puede asignar valores arbitrarios a los ID compatibles con cada llamada. Se puede obtener más información en la [página man de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) y la [página man de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Estas funcionalidades no están diseñadas como un mecanismo de seguridad, sino para facilitar el flujo operativo previsto, como cuando un programa adopta la identidad de otro usuario modificando su ID de usuario efectivo.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Cabe destacar que una llamada privilegiada a `setuid` puede asignar los tres ID, mientras que `setreuid` y `setresuid` ofrecen controles diferentes; distinguir estas funciones es fundamental para comprender las transiciones de los ID de usuario.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mecanismos de ejecución de programas en Linux

#### Llamada de sistema **`execve`**

- **Funcionalidad**: `execve` inicia un programa determinado por el primer argumento. Recibe dos argumentos de tipo array: `argv` para los argumentos y `envp` para el entorno.<sup>[[5]](#references)</sup>
- **Comportamiento**: Conserva el espacio de memoria del llamador, pero actualiza los segmentos de stack, heap y datos. El código del programa se reemplaza por el del nuevo programa.<sup>[[5]](#references)</sup>
- **Conservación de los ID de usuario**:
- `ruid` y los ID de grupo suplementarios permanecen sin cambios.<sup>[[5]](#references)</sup>
- `euid` normalmente no cambia, pero puede cambiar si el nuevo programa tiene activado el bit SetUID.<sup>[[5]](#references)</sup>
- `suid` se actualiza a partir de `euid` después de la ejecución.<sup>[[5]](#references)</sup>
- **Documentación**: Se puede encontrar información detallada en la [página man de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### Función **`system`**

- **Funcionalidad**: A diferencia de `execve`, `system` se comporta como si creara un proceso hijo mediante `fork` y ejecutara el comando dentro de ese proceso hijo usando `execl`.<sup>[[6]](#references)</sup>
- **Ejecución del comando**: Ejecuta el comando mediante `sh` con `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Comportamiento**: Como `execl` es una llamada de la familia `exec`, funciona de forma similar a `execve`, pero en el contexto de un nuevo proceso hijo.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentación**: Se puede obtener más información en la [página man de `system`](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Comportamiento de `bash` y `sh` con SUID**

- **`bash`**:
- Tiene una opción `-p` que influye en cómo se tratan `euid` y `ruid`.<sup>[[7]](#references)</sup>
- Sin `-p`, `bash` establece `euid` en `ruid` si inicialmente son diferentes.<sup>[[7]](#references)</sup>
- Con `-p`, se conserva el `euid` inicial.<sup>[[7]](#references)</sup>
- Se pueden consultar más detalles en la [página man de `bash`](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` no define una opción de preservación de privilegios al estilo de `bash` como `-p`.<sup>[[8]](#references)</sup>
- Su lista de opciones POSIX incluye `-i`, que selecciona el modo interactivo y puede rechazarse cuando los ID real y efectivo son diferentes.<sup>[[8]](#references)</sup>
- Hay información adicional disponible en la [página man de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Estos mecanismos, diferentes en su funcionamiento, ofrecen un conjunto versátil de opciones para ejecutar y realizar transiciones entre programas, con matices específicos respecto a cómo se gestionan y conservan los ID de usuario.

### Pruebas del comportamiento de los ID de usuario durante las ejecuciones

Ejemplos tomados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; consúltalo para obtener más información.<sup>[[1]](#references)</sup>

#### Caso 1: Uso de `setuid` con `system`

**Objetivo**: Comprender el efecto de `setuid` en combinación con `system` y `bash` como `sh`.

**Código C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilación y permisos:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- `ruid` y `euid` comienzan como 99 (nobody) y 1000 (frank), respectivamente.
- En este contexto sin privilegios, `setuid(1000)` deja `ruid` en 99 y `euid` en 1000.<sup>[[1]](#references)</sup>
- `system` ejecuta `/bin/bash -c id` debido al enlace simbólico de sh a bash.
- `bash`, sin `-p`, ajusta `euid` para que coincida con `ruid`, lo que da como resultado que ambos sean 99 (nobody).<sup>[[1]](#references)</sup>

#### Caso 2: Uso de setreuid con system

**Código C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilación y permisos:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Ejecución y resultado:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- `setreuid` establece tanto ruid como euid en 1000.
- `system` invoca bash, que mantiene los ID de usuario debido a su igualdad, operando efectivamente como frank.<sup>[[1]](#references)</sup>

#### Caso 3: Uso de setuid con execve

Objetivo: Explorar la interacción entre setuid y execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Ejecución y resultado:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- `ruid` sigue siendo 99, pero `euid` se establece en 1000, de acuerdo con el efecto de `setuid`.<sup>[[1]](#references)</sup>

**Ejemplo de código C 2 (Llamada a Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Ejecución y resultado:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- Aunque `euid` se establece en 1000 mediante `setuid`, `bash` restablece `euid` a `ruid` (99) debido a la ausencia de `-p`.<sup>[[1]](#references)</sup>

**Ejemplo de código C 3 (Uso de bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Ejecución y resultado:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - página del manual de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - página del manual de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - página del manual de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - página del manual de execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - página del manual de system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - página del manual de bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - página del manual de POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
