## Seccomp

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

**Seccomp** o modo de computación segura, en resumen, es una característica del kernel de Linux que puede actuar como **filtro de llamadas al sistema**.\
Seccomp tiene 2 modos.

**seccomp** (abreviatura de **modo de computación segura**) es una instalación de seguridad informática en el **kernel de Linux**. seccomp permite que un proceso haga una transición unidireccional a un estado "seguro" donde **no puede hacer ninguna llamada al sistema excepto** `exit()`, `sigreturn()`, `read()` y `write()` a los descriptores de archivo **ya abiertos**. Si intenta hacer cualquier otra llamada al sistema, el **kernel** terminará el **proceso** con SIGKILL o SIGSYS. En este sentido, no virtualiza los recursos del sistema, sino que aísla completamente el proceso de ellos.

El modo seccomp se habilita mediante la llamada al sistema `prctl(2)` utilizando el argumento `PR_SET_SECCOMP`, o (desde el kernel de Linux 3.17) mediante la llamada al sistema `seccomp(2)`. El modo seccomp solía habilitarse escribiendo en un archivo, `/proc/self/seccomp`, pero este método se eliminó a favor de `prctl()`. En algunas versiones del kernel, seccomp deshabilita la instrucción x86 `RDTSC`, que devuelve el número de ciclos del procesador transcurridos desde el encendido, utilizado para la temporización de alta precisión.

**seccomp-bpf** es una extensión de seccomp que permite **filtrar las llamadas al sistema utilizando una política configurable** implementada mediante reglas de filtro de Berkeley Packet. Es utilizado por OpenSSH y vsftpd, así como por los navegadores web Google Chrome/Chromium en Chrome OS y Linux. (En este sentido, seccomp-bpf logra una funcionalidad similar, pero con más flexibilidad y mayor rendimiento, al antiguo systrace, que parece que ya no es compatible con Linux).

### **Modo original/estricto**

En este modo, Seccomp **solo permite las llamadas al sistema** `exit()`, `sigreturn()`, `read()` y `write()` a los descriptores de archivo ya abiertos. Si se realiza cualquier otra llamada al sistema, el proceso se mata usando SIGKILL. 

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
{% endcode %}

### Seccomp-bpf

Este modo permite **filtrar las llamadas al sistema utilizando una política configurable** implementada mediante reglas de Berkeley Packet Filter. 

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
{% endcode %}

## Seccomp en Docker

**Seccomp-bpf** es compatible con **Docker** para restringir las **syscalls** de los contenedores, disminuyendo efectivamente la superficie de ataque. Puedes encontrar las **syscalls bloqueadas** por **defecto** en [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) y el **perfil de seccomp por defecto** se puede encontrar aquí [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puedes ejecutar un contenedor de docker con una **política de seccomp diferente** con:
```bash
docker run --rm \
             -it \
             --security-opt seccomp=/path/to/seccomp/profile.json \
             hello-world
```
Si desea, por ejemplo, **prohibir** que un contenedor ejecute alguna **llamada al sistema** como `uname`, puede descargar el perfil predeterminado desde [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) y simplemente **eliminar la cadena `uname` de la lista**.\
Si desea asegurarse de que **algún binario no funcione dentro de un contenedor de Docker**, puede usar strace para listar las llamadas al sistema que está utilizando el binario y luego prohibirlas.\
En el siguiente ejemplo se descubren las **llamadas al sistema** de `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Si estás utilizando **Docker solo para lanzar una aplicación**, puedes **perfilizarla** con **`strace`** y **solo permitir las llamadas al sistema** que necesita.
{% endhint %}

### Ejemplo de política Seccomp

Para ilustrar la función de Seccomp, creemos un perfil de Seccomp que deshabilite la llamada al sistema "chmod" como se muestra a continuación.
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
El siguiente resultado muestra la llamada "chmod" devolviendo un error porque está deshabilitada en el perfil de seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
El siguiente resultado muestra el comando "docker inspect" mostrando el perfil:
```json
           "SecurityOpt": [
                "seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
            ],
```
### Desactivarlo en Docker

Lanza un contenedor con la bandera: **`--security-opt seccomp=unconfined`**

A partir de Kubernetes 1.19, **seccomp está habilitado por defecto para todos los Pods**. Sin embargo, el perfil de seccomp por defecto aplicado a los Pods es el perfil "**RuntimeDefault**", el cual es **proporcionado por el tiempo de ejecución del contenedor** (por ejemplo, Docker, containerd). El perfil "RuntimeDefault" permite la mayoría de las llamadas al sistema mientras bloquea algunas que se consideran peligrosas o que no son generalmente requeridas por los contenedores.
