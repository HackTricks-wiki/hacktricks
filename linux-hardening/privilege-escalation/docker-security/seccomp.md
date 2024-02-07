# Seccomp

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

**Seccomp**, que significa Modo de Computación Segura, es una característica de seguridad del **kernel de Linux diseñada para filtrar llamadas al sistema**. Restringe los procesos a un conjunto limitado de llamadas al sistema (`exit()`, `sigreturn()`, `read()` y `write()` para descriptores de archivos ya abiertos). Si un proceso intenta llamar a cualquier otra cosa, es terminado por el kernel usando SIGKILL o SIGSYS. Este mecanismo no virtualiza recursos, sino que aísla el proceso de ellos.

Hay dos formas de activar seccomp: a través de la llamada al sistema `prctl(2)` con `PR_SET_SECCOMP`, o para los kernels de Linux 3.17 en adelante, la llamada al sistema `seccomp(2)`. El método más antiguo de habilitar seccomp escribiendo en `/proc/self/seccomp` ha sido desaprobado a favor de `prctl()`.

Una mejora, **seccomp-bpf**, agrega la capacidad de filtrar llamadas al sistema con una política personalizable, utilizando reglas de Berkeley Packet Filter (BPF). Esta extensión es aprovechada por software como OpenSSH, vsftpd y los navegadores Chrome/Chromium en Chrome OS y Linux para un filtrado eficiente y flexible de llamadas al sistema, ofreciendo una alternativa al ya no compatible systrace para Linux.

### **Modo Original/Estricto**

En este modo Seccomp **solo permite las llamadas al sistema** `exit()`, `sigreturn()`, `read()` y `write()` a descriptores de archivos ya abiertos. Si se realiza cualquier otra llamada al sistema, el proceso es terminado usando SIGKILL

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

Este modo permite **filtrar las llamadas al sistema utilizando una política configurable** implementada utilizando reglas de Berkeley Packet Filter.
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

**Seccomp-bpf** es compatible con **Docker** para restringir las **syscalls** desde los contenedores, disminuyendo efectivamente la superficie de ataque. Puedes encontrar las **syscalls bloqueadas** por **defecto** en [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) y el **perfil seccomp por defecto** se puede encontrar aquí [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puedes ejecutar un contenedor de docker con una política de **seccomp diferente** con:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Si deseas, por ejemplo, **prohibir** que un contenedor ejecute alguna **llamada al sistema** como `uname`, puedes descargar el perfil predeterminado desde [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) y simplemente **eliminar la cadena `uname` de la lista**.\
Si deseas asegurarte de que **cierto binario no funcione dentro de un contenedor de Docker**, puedes usar strace para listar las llamadas al sistema que el binario está utilizando y luego prohibirlas.\
En el siguiente ejemplo se descubren las **llamadas al sistema** de `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Si estás utilizando **Docker solo para lanzar una aplicación**, puedes **perfil**arla con **`strace`** y **solo permitir las llamadas al sistema** que necesita.
{% endhint %}

### Ejemplo de política Seccomp

[Ejemplo de aquí](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Para ilustrar la característica de Seccomp, creemos un perfil de Seccomp deshabilitando la llamada al sistema "chmod" como se muestra a continuación.
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
En el perfil anterior, hemos establecido la acción predeterminada en "permitir" y creado una lista negra para deshabilitar "chmod". Para ser más seguro, podemos establecer la acción predeterminada en "bloquear" y crear una lista blanca para habilitar selectivamente las llamadas al sistema.\
El siguiente resultado muestra la llamada "chmod" devolviendo un error porque está deshabilitada en el perfil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
El siguiente resultado muestra el "docker inspect" que muestra el perfil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Desactivarlo en Docker

Inicia un contenedor con la bandera: **`--security-opt seccomp=unconfined`**

A partir de Kubernetes 1.19, **seccomp está habilitado de forma predeterminada para todos los Pods**. Sin embargo, el perfil seccomp predeterminado aplicado a los Pods es el perfil "**RuntimeDefault**", que es **proporcionado por el tiempo de ejecución del contenedor** (por ejemplo, Docker, containerd). El perfil "RuntimeDefault" permite la mayoría de las llamadas al sistema mientras bloquea algunas que se consideran peligrosas o generalmente no requeridas por los contenedores.
