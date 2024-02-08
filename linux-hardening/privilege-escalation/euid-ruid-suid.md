# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Variables de Identificación de Usuario

- **`ruid`**: El **ID de usuario real** denota al usuario que inició el proceso.
- **`euid`**: Conocido como el **ID de usuario efectivo**, representa la identidad de usuario utilizada por el sistema para determinar los privilegios del proceso. Generalmente, `euid` refleja `ruid`, salvo en casos como la ejecución de un binario SetUID, donde `euid` asume la identidad del propietario del archivo, otorgando permisos operativos específicos.
- **`suid`**: Este **ID de usuario guardado** es crucial cuando un proceso de alto privilegio (normalmente en ejecución como root) necesita renunciar temporalmente a sus privilegios para realizar ciertas tareas, solo para luego recuperar su estado elevado inicial.

#### Nota Importante
Un proceso que no opera bajo root solo puede modificar su `euid` para que coincida con el `ruid`, `euid` o `suid` actual.

### Comprensión de las Funciones set*uid

- **`setuid`**: Contrariamente a las suposiciones iniciales, `setuid` modifica principalmente `euid` en lugar de `ruid`. Específicamente, para procesos privilegiados, alinea `ruid`, `euid` y `suid` con el usuario especificado, a menudo root, solidificando efectivamente estos IDs debido al `suid` que los anula. Se pueden encontrar información detallada en la [página del manual de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** y **`setresuid`**: Estas funciones permiten el ajuste sutil de `ruid`, `euid` y `suid`. Sin embargo, sus capacidades dependen del nivel de privilegio del proceso. Para procesos no root, las modificaciones están restringidas a los valores actuales de `ruid`, `euid` y `suid`. En contraste, los procesos root o aquellos con la capacidad `CAP_SETUID` pueden asignar valores arbitrarios a estos IDs. Se puede obtener más información en la página del manual de [setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) y en la página del manual de [setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Estas funcionalidades no están diseñadas como un mecanismo de seguridad, sino para facilitar el flujo operativo previsto, como cuando un programa adopta la identidad de otro usuario al alterar su ID de usuario efectivo.

Es importante destacar que si bien `setuid` puede ser común para la elevación de privilegios a root (ya que alinea todos los IDs a root), diferenciar entre estas funciones es crucial para comprender y manipular los comportamientos de los ID de usuario en diferentes escenarios.

### Mecanismos de Ejecución de Programas en Linux

#### Llamada al Sistema **`execve`**
- **Funcionalidad**: `execve` inicia un programa, determinado por el primer argumento. Toma dos argumentos de matriz, `argv` para los argumentos y `envp` para el entorno.
- **Comportamiento**: Conserva el espacio de memoria del llamante pero actualiza la pila, el montón y los segmentos de datos. El código del programa es reemplazado por el del nuevo programa.
- **Preservación del ID de Usuario**:
- Los IDs de grupo `ruid`, `euid` y suplementarios permanecen sin cambios.
- `euid` puede tener cambios sutiles si el nuevo programa tiene el bit SetUID establecido.
- `suid` se actualiza desde `euid` después de la ejecución.
- **Documentación**: Se puede encontrar información detallada en la [página del manual de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### Función **`system`**
- **Funcionalidad**: A diferencia de `execve`, `system` crea un proceso hijo usando `fork` y ejecuta un comando dentro de ese proceso hijo usando `execl`.
- **Ejecución de Comandos**: Ejecuta el comando a través de `sh` con `execl("/bin/sh", "sh", "-c", comando, (char *) NULL);`.
- **Comportamiento**: Como `execl` es una forma de `execve`, opera de manera similar pero en el contexto de un nuevo proceso hijo.
- **Documentación**: Se pueden obtener más información en la [página del manual de `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### Comportamiento de `bash` y `sh` con SUID
- **`bash`**:
- Tiene una opción `-p` que influye en cómo se tratan `euid` y `ruid`.
- Sin `-p`, `bash` establece `euid` en `ruid` si difieren inicialmente.
- Con `-p`, se conserva el `euid` inicial.
- Se pueden encontrar más detalles en la [página del manual de `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- No posee un mecanismo similar a `-p` en `bash`.
- El comportamiento con respecto a los IDs de usuario no se menciona explícitamente, excepto bajo la opción `-i`, que enfatiza la preservación de la igualdad de `euid` y `ruid`.
- Se dispone de información adicional en la [página del manual de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Estos mecanismos, distintos en su funcionamiento, ofrecen una amplia gama de opciones para ejecutar y transicionar entre programas, con matices específicos en cómo se gestionan y preservan los IDs de usuario.

### Pruebas de Comportamientos de ID de Usuario en Ejecuciones

Ejemplos tomados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, compruébalo para obtener más información

#### Caso 1: Uso de `setuid` con `system`

**Objetivo**: Comprender el efecto de `setuid` en combinación con `system` y `bash` como `sh`.

**Código en C**:
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

* `ruid` y `euid` comienzan como 99 (nobody) y 1000 (frank) respectivamente.
* `setuid` alinea ambos a 1000.
* `system` ejecuta `/bin/bash -c id` debido al enlace simbólico de sh a bash.
* `bash`, sin `-p`, ajusta `euid` para que coincida con `ruid`, lo que resulta en ambos siendo 99 (nobody).

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

* `setreuid` establece tanto el ruid como el euid en 1000.
* `system` invoca a bash, que mantiene los IDs de usuario debido a su igualdad, operando efectivamente como frank.

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
**Ejecución y Resultado:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análisis:**

* `ruid` sigue siendo 99, pero `euid` se establece en 1000, en línea con el efecto de `setuid`.

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

* Aunque `euid` se establece en 1000 por `setuid`, `bash` restablece euid a `ruid` (99) debido a la ausencia de `-p`.

**Ejemplo de Código C 3 (Usando bash -p):**
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
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
