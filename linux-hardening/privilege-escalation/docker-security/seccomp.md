# Seccomp

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

**Seccomp** o modo de Computación Segura, en resumen, es una característica del kernel de Linux que puede actuar como **filtro de syscalls**.\
Seccomp tiene 2 modos.

**seccomp** (abreviatura de **modo de computación segura**) es una facilidad de seguridad informática en el **kernel de Linux**. seccomp permite que un proceso haga una transición unidireccional hacia un estado "seguro" donde **no puede realizar ninguna llamada al sistema excepto** `exit()`, `sigreturn()`, `read()` y `write()` a descriptores de archivo **ya abiertos**. Si intenta realizar cualquier otra llamada al sistema, el **kernel** **terminará** el **proceso** con SIGKILL o SIGSYS. En este sentido, no virtualiza los recursos del sistema, sino que aísla completamente al proceso de ellos.

El modo seccomp se **habilita mediante la llamada al sistema `prctl(2)`** usando el argumento `PR_SET_SECCOMP`, o (desde el kernel de Linux 3.17) mediante la llamada al sistema `seccomp(2)`. Anteriormente se habilitaba escribiendo en un archivo, `/proc/self/seccomp`, pero este método se eliminó a favor de `prctl()`. En algunas versiones del kernel, seccomp deshabilita la instrucción x86 `RDTSC`, que devuelve el número de ciclos de procesador transcurridos desde el encendido, utilizada para temporización de alta precisión.

**seccomp-bpf** es una extensión de seccomp que permite **filtrar llamadas al sistema utilizando una política configurable** implementada mediante reglas del Filtro de Paquetes de Berkeley. Es utilizado por OpenSSH y vsftpd, así como por los navegadores web Google Chrome/Chromium en Chrome OS y Linux. (En este sentido, seccomp-bpf logra una funcionalidad similar, pero con más flexibilidad y mayor rendimiento, al antiguo systrace—que parece ya no estar soportado para Linux.)

### **Modo Original/Estricto**

En este modo Seccomp **solo permite las syscalls** `exit()`, `sigreturn()`, `read()` y `write()` a descriptores de archivo ya abiertos. Si se realiza cualquier otra syscall, el proceso se mata usando SIGKILL

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

Este modo permite el **filtrado de llamadas al sistema utilizando una política configurable** implementada mediante reglas de Berkeley Packet Filter.

{% code title="seccomp_bpf.c" %}
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Seccomp en Docker

**Seccomp-bpf** es soportado por **Docker** para restringir los **syscalls** de los contenedores, disminuyendo efectivamente el área de exposición. Puedes encontrar los **syscalls bloqueados** por **defecto** en [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) y el **perfil de seccomp por defecto** se puede encontrar aquí [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puedes ejecutar un contenedor de docker con una política de **seccomp diferente** con:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Si, por ejemplo, quieres **prohibir** que un contenedor ejecute algún **syscall** como `uname`, podrías descargar el perfil predeterminado de [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) y simplemente **eliminar la cadena `uname` de la lista**.\
Si quieres asegurarte de que **cierto binario no funcione dentro de un contenedor de docker**, podrías usar strace para listar los syscalls que el binario está utilizando y luego prohibirlos.\
En el siguiente ejemplo se descubren los **syscalls** de `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Si estás utilizando **Docker solo para lanzar una aplicación**, puedes **perfilarla** con **`strace`** y **permitir solo las llamadas al sistema** que necesita.
{% endhint %}

### Ejemplo de política Seccomp

Para ilustrar la característica Seccomp, vamos a crear un perfil Seccomp que deshabilite la llamada al sistema "chmod" como se muestra a continuación.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
En el perfil anterior, hemos establecido la acción predeterminada en "permitir" y creado una lista negra para deshabilitar "chmod". Para mayor seguridad, podemos establecer la acción predeterminada en rechazar y crear una lista blanca para habilitar selectivamente las llamadas al sistema.
La siguiente salida muestra la llamada a "chmod" devolviendo un error porque está deshabilitada en el perfil de seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
La salida siguiente muestra el "docker inspect" mostrando el perfil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Desactivarlo en Docker

Inicia un contenedor con la bandera: **`--security-opt seccomp=unconfined`**

A partir de Kubernetes 1.19, **seccomp está habilitado por defecto para todos los Pods**. Sin embargo, el perfil de seccomp predeterminado aplicado a los Pods es el perfil "**RuntimeDefault**", que es **proporcionado por el entorno de ejecución de contenedores** (por ejemplo, Docker, containerd). El perfil "RuntimeDefault" permite la mayoría de las llamadas al sistema mientras bloquea algunas que se consideran peligrosas o generalmente no necesarias para los contenedores.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
