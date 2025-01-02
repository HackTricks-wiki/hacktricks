# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

**Seccomp**, que significa modo de Computación Segura, es una característica de seguridad del **núcleo de Linux diseñada para filtrar llamadas al sistema**. Restringe los procesos a un conjunto limitado de llamadas al sistema (`exit()`, `sigreturn()`, `read()`, y `write()` para descriptores de archivo ya abiertos). Si un proceso intenta llamar a cualquier otra cosa, es terminado por el núcleo usando SIGKILL o SIGSYS. Este mecanismo no virtualiza recursos, sino que aísla el proceso de ellos.

Hay dos formas de activar seccomp: a través de la llamada al sistema `prctl(2)` con `PR_SET_SECCOMP`, o para núcleos de Linux 3.17 y superiores, la llamada al sistema `seccomp(2)`. El método más antiguo de habilitar seccomp escribiendo en `/proc/self/seccomp` ha sido desaprobado a favor de `prctl()`.

Una mejora, **seccomp-bpf**, añade la capacidad de filtrar llamadas al sistema con una política personalizable, utilizando reglas de Berkeley Packet Filter (BPF). Esta extensión es aprovechada por software como OpenSSH, vsftpd, y los navegadores Chrome/Chromium en Chrome OS y Linux para un filtrado de syscall flexible y eficiente, ofreciendo una alternativa a la ahora no soportada systrace para Linux.

### **Modo Original/Estricto**

En este modo, Seccomp **solo permite las syscalls** `exit()`, `sigreturn()`, `read()` y `write()` a descriptores de archivo ya abiertos. Si se realiza cualquier otra syscall, el proceso es terminado usando SIGKILL.
```c:seccomp_strict.c
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

Este modo permite **filtrar llamadas al sistema utilizando una política configurable** implementada mediante reglas de Berkeley Packet Filter.
```c:seccomp_bpf.c
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

**Seccomp-bpf** es compatible con **Docker** para restringir las **syscalls** de los contenedores, disminuyendo efectivamente el área de superficie. Puedes encontrar las **syscalls bloqueadas** por **defecto** en [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) y el **perfil seccomp por defecto** se puede encontrar aquí [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puedes ejecutar un contenedor de docker con una política de **seccomp** **diferente** con:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Si quieres, por ejemplo, **prohibir** que un contenedor ejecute alguna **syscall** como `uname`, podrías descargar el perfil predeterminado de [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) y simplemente **eliminar la cadena `uname` de la lista**.\
Si quieres asegurarte de que **algún binario no funcione dentro de un contenedor docker**, podrías usar strace para listar las syscalls que el binario está utilizando y luego prohibirlas.\
En el siguiente ejemplo se descubren las **syscalls** de `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Si estás usando **Docker solo para lanzar una aplicación**, puedes **perfilarla** con **`strace`** y **solo permitir las syscalls** que necesita

### Ejemplo de política Seccomp

[Ejemplo de aquí](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Para ilustrar la función Seccomp, creemos un perfil Seccomp deshabilitando la llamada al sistema “chmod” como se muestra a continuación.
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
En el perfil anterior, hemos establecido la acción predeterminada en "permitir" y creado una lista negra para deshabilitar "chmod". Para ser más seguros, podemos establecer la acción predeterminada en "rechazar" y crear una lista blanca para habilitar selectivamente las llamadas al sistema.\
La siguiente salida muestra la llamada "chmod" devolviendo un error porque está deshabilitada en el perfil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
La siguiente salida muestra el “docker inspect” mostrando el perfil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
