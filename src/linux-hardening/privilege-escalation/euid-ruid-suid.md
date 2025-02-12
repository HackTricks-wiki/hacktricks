# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Variables de Identificación de Usuario

- **`ruid`**: El **ID de usuario real** denota al usuario que inició el proceso.
- **`euid`**: Conocido como el **ID de usuario efectivo**, representa la identidad del usuario utilizada por el sistema para determinar los privilegios del proceso. Generalmente, `euid` refleja `ruid`, salvo en instancias como la ejecución de un binario SetUID, donde `euid` asume la identidad del propietario del archivo, otorgando así permisos operativos específicos.
- **`suid`**: Este **ID de usuario guardado** es fundamental cuando un proceso de alto privilegio (normalmente ejecutándose como root) necesita renunciar temporalmente a sus privilegios para realizar ciertas tareas, solo para luego recuperar su estado elevado inicial.

#### Nota Importante

Un proceso que no opera bajo root solo puede modificar su `euid` para que coincida con el `ruid`, `euid` o `suid` actuales.

### Entendiendo las Funciones set\*uid

- **`setuid`**: Contrario a las suposiciones iniciales, `setuid` modifica principalmente `euid` en lugar de `ruid`. Específicamente, para procesos privilegiados, alinea `ruid`, `euid` y `suid` con el usuario especificado, a menudo root, solidificando efectivamente estos IDs debido al `suid` que prevalece. Se pueden encontrar detalles en la [página del manual de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** y **`setresuid`**: Estas funciones permiten el ajuste matizado de `ruid`, `euid` y `suid`. Sin embargo, sus capacidades dependen del nivel de privilegio del proceso. Para procesos que no son root, las modificaciones están restringidas a los valores actuales de `ruid`, `euid` y `suid`. En contraste, los procesos root o aquellos con la capacidad `CAP_SETUID` pueden asignar valores arbitrarios a estos IDs. Se puede obtener más información de la [página del manual de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) y de la [página del manual de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Estas funcionalidades no están diseñadas como un mecanismo de seguridad, sino para facilitar el flujo operativo previsto, como cuando un programa adopta la identidad de otro usuario al alterar su ID de usuario efectivo.

Notablemente, aunque `setuid` puede ser un recurso común para la elevación de privilegios a root (ya que alinea todos los IDs a root), diferenciar entre estas funciones es crucial para entender y manipular los comportamientos del ID de usuario en diferentes escenarios.

### Mecanismos de Ejecución de Programas en Linux

#### **Llamada al Sistema `execve`**

- **Funcionalidad**: `execve` inicia un programa, determinado por el primer argumento. Toma dos argumentos de matriz, `argv` para argumentos y `envp` para el entorno.
- **Comportamiento**: Retiene el espacio de memoria del llamador pero actualiza la pila, el montón y los segmentos de datos. El código del programa es reemplazado por el nuevo programa.
- **Preservación del ID de Usuario**:
- `ruid`, `euid` y los IDs de grupo suplementarios permanecen inalterados.
- `euid` puede tener cambios matizados si el nuevo programa tiene el bit SetUID establecido.
- `suid` se actualiza desde `euid` después de la ejecución.
- **Documentación**: Se puede encontrar información detallada en la [página del manual de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Función `system`**

- **Funcionalidad**: A diferencia de `execve`, `system` crea un proceso hijo utilizando `fork` y ejecuta un comando dentro de ese proceso hijo utilizando `execl`.
- **Ejecución de Comandos**: Ejecuta el comando a través de `sh` con `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamiento**: Como `execl` es una forma de `execve`, opera de manera similar pero en el contexto de un nuevo proceso hijo.
- **Documentación**: Se pueden obtener más detalles de la [página del manual de `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamiento de `bash` y `sh` con SUID**

- **`bash`**:
- Tiene una opción `-p` que influye en cómo se tratan `euid` y `ruid`.
- Sin `-p`, `bash` establece `euid` a `ruid` si inicialmente difieren.
- Con `-p`, se preserva el `euid` inicial.
- Se pueden encontrar más detalles en la [página del manual de `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- No posee un mecanismo similar a `-p` en `bash`.
- El comportamiento respecto a los IDs de usuario no se menciona explícitamente, excepto bajo la opción `-i`, enfatizando la preservación de la igualdad entre `euid` y `ruid`.
- Información adicional está disponible en la [página del manual de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Estos mecanismos, distintos en su operación, ofrecen una gama versátil de opciones para ejecutar y transitar entre programas, con matices específicos en cómo se gestionan y preservan los IDs de usuario.

### Pruebas de Comportamientos de ID de Usuario en Ejecuciones

Ejemplos tomados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consúltalo para más información

#### Caso 1: Usando `setuid` con `system`

**Objetivo**: Entender el efecto de `setuid` en combinación con `system` y `bash` como `sh`.

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
**Compilación y Permisos:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- `ruid` y `euid` comienzan como 99 (nadie) y 1000 (frank) respectivamente.
- `setuid` alinea ambos a 1000.
- `system` ejecuta `/bin/bash -c id` debido al symlink de sh a bash.
- `bash`, sin `-p`, ajusta `euid` para que coincida con `ruid`, resultando en que ambos sean 99 (nadie).

#### Caso 2: Usando setreuid con system

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
**Compilación y Permisos:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Ejecución y Resultado:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- `setreuid` establece tanto ruid como euid a 1000.
- `system` invoca bash, que mantiene los IDs de usuario debido a su igualdad, operando efectivamente como frank.

#### Caso 3: Usando setuid con execve

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
**Ejecución y Resultado:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- `ruid` permanece en 99, pero euid se establece en 1000, en línea con el efecto de setuid.

**Ejemplo de Código C 2 (Llamando a Bash):**
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
**Ejecución y Resultado:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

- Aunque `euid` se establece en 1000 por `setuid`, `bash` restablece `euid` a `ruid` (99) debido a la ausencia de `-p`.

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
**Ejecución y Resultado:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referencias

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
