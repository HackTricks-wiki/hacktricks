# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variables de identificación de usuario

- **`ruid`**: El **ID de usuario real** indica el usuario que inició el proceso.
- **`euid`**: Conocido como el **ID de usuario efectivo**, representa la identidad de usuario utilizada por el sistema para determinar los privilegios del proceso. Generalmente, `euid` refleja `ruid`, salvo en casos como la ejecución de un binario SetUID, donde `euid` adopta la identidad del propietario del archivo, otorgando así permisos operativos específicos.
- **`suid`**: Este **ID de usuario guardado** es fundamental cuando un proceso con altos privilegios (normalmente ejecutándose como root) necesita renunciar temporalmente a sus privilegios para realizar determinadas tareas y posteriormente recuperar su estado elevado inicial.

#### Nota importante

Un proceso que no se ejecuta como root solo puede modificar su `euid` para que coincida con el `ruid`, `euid` o `suid` actuales.

### Comprensión de las funciones set\*uid

- **`setuid`**: Contrariamente a lo que se podría suponer inicialmente, `setuid` modifica principalmente `euid` en lugar de `ruid`. En concreto, para los procesos con privilegios, establece `ruid`, `euid` y `suid` con el usuario especificado, normalmente root, consolidando de hecho estos IDs debido a la sobrescritura de `suid`. Se pueden encontrar explicaciones detalladas en la [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** y **`setresuid`**: Estas funciones permiten ajustar de forma detallada `ruid`, `euid` y `suid`. Sin embargo, sus capacidades dependen del nivel de privilegios del proceso. En los procesos que no son root, las modificaciones están restringidas a los valores actuales de `ruid`, `euid` y `suid`. En cambio, los procesos root o aquellos con la capacidad `CAP_SETUID` pueden asignar valores arbitrarios a estos IDs. Se puede obtener más información en la [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) y la [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Estas funcionalidades no están diseñadas como un mecanismo de seguridad, sino para facilitar el flujo operativo previsto, como cuando un programa adopta la identidad de otro usuario modificando su ID de usuario efectivo.

Cabe destacar que, aunque `setuid` puede ser una opción habitual para elevar privilegios a root (ya que alinea todos los IDs con root), diferenciar entre estas funciones es crucial para comprender y manipular el comportamiento de los IDs de usuario en distintos escenarios.

### Mecanismos de ejecución de programas en Linux

#### **Llamada al sistema `execve`**

- **Funcionalidad**: `execve` inicia un programa determinado por el primer argumento. Recibe dos argumentos de tipo array, `argv` para los argumentos y `envp` para el entorno.
- **Comportamiento**: Conserva el espacio de memoria del llamador, pero actualiza los segmentos de stack, heap y datos. El código del programa se sustituye por el del nuevo programa.
- **Conservación de los IDs de usuario**:
- `ruid`, `euid` y los IDs de grupo suplementarios no se modifican.
- `euid` puede sufrir cambios específicos si el nuevo programa tiene establecido el bit SetUID.
- `suid` se actualiza a partir de `euid` después de la ejecución.
- **Documentación**: Se puede encontrar información detallada en la [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Función `system`**

- **Funcionalidad**: A diferencia de `execve`, `system` crea un proceso hijo utilizando `fork` y ejecuta un comando dentro de ese proceso hijo mediante `execl`.
- **Ejecución de comandos**: Ejecuta el comando mediante `sh` con `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamiento**: Como `execl` es una forma de `execve`, funciona de manera similar, pero en el contexto de un nuevo proceso hijo.
- **Documentación**: Se puede obtener más información en la [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamiento de `bash` y `sh` con SUID**

- **`bash`**:
- Tiene una opción `-p` que influye en cómo se tratan `euid` y `ruid`.
- Sin `-p`, `bash` establece `euid` con el valor de `ruid` si inicialmente son diferentes.
- Con `-p`, se conserva el `euid` inicial.
- Se pueden encontrar más detalles en la [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- No posee un mecanismo similar a `-p` en `bash`.
- El comportamiento relativo a los IDs de usuario no se menciona explícitamente, salvo con la opción `-i`, que hace hincapié en conservar la igualdad entre `euid` y `ruid`.
- Hay información adicional disponible en la [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Estos mecanismos, diferentes en su funcionamiento, ofrecen un conjunto flexible de opciones para ejecutar y pasar de un programa a otro, con matices específicos sobre cómo se gestionan y conservan los IDs de usuario.

### Prueba del comportamiento de los IDs de usuario durante las ejecuciones

Ejemplos tomados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consulta esta referencia para obtener más información<sup>[[1]](#references)</sup>

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

- `ruid` y `euid` comienzan siendo 99 (nobody) y 1000 (frank), respectivamente.
- `setuid` alinea ambos con 1000.
- `system` ejecuta `/bin/bash -c id` debido al symlink de sh a bash.
- `bash`, sin `-p`, ajusta `euid` para que coincida con `ruid`, lo que da como resultado que ambos sean 99 (nobody).

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
- `system` invoca bash, que mantiene los ID de usuario debido a su igualdad, operando efectivamente como frank.

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

- `ruid` permanece en 99, pero euid se establece en 1000, de acuerdo con el efecto de setuid.

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

- Aunque `euid` se establece en 1000 mediante `setuid`, `bash` restablece euid a `ruid` (99) debido a la ausencia de `-p`.

**Ejemplo de código C 3 (Usando bash -p):**
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
uid=99(nobody) gid=99(nobody) euid=100
```
## Referencias

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - página man de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - página man de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - página man de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - página man de execve](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
