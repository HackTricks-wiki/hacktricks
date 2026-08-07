# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

**seccomp** es el mecanismo que permite al kernel aplicar un filtro a los syscalls que un proceso puede invocar. En entornos containerizados, seccomp normalmente se utiliza en filter mode, de modo que el proceso no queda simplemente marcado como "restringido" en un sentido vago, sino que está sujeto a una política concreta de syscalls. Esto es importante porque muchos container breakouts requieren alcanzar interfaces muy específicas del kernel. Si el proceso no puede invocar correctamente los syscalls relevantes, una gran clase de ataques desaparece antes de que cualquier matiz sobre namespaces o capabilities llegue siquiera a ser relevante.

El modelo mental clave es sencillo: los namespaces determinan **qué puede ver el proceso**, las capabilities determinan **qué acciones privilegiadas puede intentar realizar nominalmente el proceso**, y seccomp determina **si el kernel aceptará siquiera el punto de entrada del syscall para la acción intentada**. Por eso seccomp suele prevenir ataques que, de otro modo, parecerían posibles basándose únicamente en las capabilities.

## Impacto en la seguridad

Una gran parte de la superficie peligrosa del kernel solo es accesible mediante un conjunto relativamente pequeño de syscalls. Entre los ejemplos que importan repetidamente en el hardening de containers se incluyen `mount`, `unshare`, `clone` o `clone3` con flags específicos, `bpf`, `ptrace`, `keyctl` y `perf_event_open`. Un atacante que pueda acceder a esos syscalls podría crear nuevos namespaces, manipular subsistemas del kernel o interactuar con una superficie de ataque que un application container normal no necesita en absoluto.

Por eso los perfiles predeterminados de seccomp del runtime son tan importantes. No son simplemente una "defensa adicional". En muchos entornos, representan la diferencia entre un container que puede utilizar una parte amplia de la funcionalidad del kernel y otro que está limitado a una superficie de syscalls más cercana a lo que la aplicación realmente necesita.

## Modos y construcción de filters

Históricamente, seccomp tenía un modo estricto en el que solo permanecía disponible un conjunto mínimo de syscalls, pero el modo relevante para los container runtimes modernos es el filter mode de seccomp, a menudo denominado **seccomp-bpf**. En este modelo, el kernel evalúa un programa de filter que decide si un syscall debe permitirse, denegarse con un errno, interceptarse, registrarse o provocar la terminación del proceso.<sup>[[1]](#references)</sup> Los container runtimes utilizan este mecanismo porque es lo bastante expresivo como para bloquear clases amplias de syscalls peligrosos y, al mismo tiempo, permitir el comportamiento normal de las aplicaciones.

Dos ejemplos de bajo nivel son útiles porque hacen que el mecanismo sea concreto en lugar de parecer mágico. El strict mode demuestra el antiguo modelo de "solo sobrevive un conjunto mínimo de syscalls":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
El `open` final provoca que el proceso sea eliminado porque no forma parte del conjunto mínimo de strict mode.

Un ejemplo de filtro de libseccomp muestra más claramente el modelo de políticas moderno:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Este es el tipo de política que la mayoría de los lectores debería imaginar cuando piensa en runtime seccomp profiles.

## Laboratorio

Una forma sencilla de confirmar que seccomp está activo en un contenedor es:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
También puedes intentar una operación que los perfiles predeterminados suelen restringir:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si el contenedor se está ejecutando con un perfil seccomp predeterminado normal, las operaciones de estilo `unshare` suelen estar bloqueadas. Esta es una demostración útil porque muestra que, aunque la herramienta de espacio de usuario exista dentro de la imagen, la ruta del kernel que necesita puede seguir sin estar disponible.
Si el contenedor se está ejecutando con un perfil seccomp predeterminado normal, las operaciones de estilo `unshare` suelen estar bloqueadas incluso cuando la herramienta de espacio de usuario existe dentro de la imagen.

Para inspeccionar el estado del proceso de forma más general, ejecuta:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso en tiempo de ejecución

Docker admite perfiles seccomp predeterminados y personalizados, y permite a los administradores desactivarlos con `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman ofrece una compatibilidad similar y a menudo combina seccomp con la ejecución rootless, lo que proporciona una configuración predeterminada muy sensata. Kubernetes expone seccomp mediante la configuración de las cargas de trabajo, donde `RuntimeDefault` suele ser la base adecuada y `Unconfined` debería tratarse como una excepción que requiere justificación, no como una opción de conveniencia.<sup>[[3]](#references)</sup>

En entornos basados en containerd y CRI-O, la ruta exacta tiene más capas, pero el principio es el mismo: el engine o el orquestador de nivel superior decide qué debe ocurrir, y el runtime finalmente instala la policy seccomp resultante para el proceso del contenedor. El resultado sigue dependiendo de la configuración final del runtime que llega al kernel.

### Ejemplo de una policy personalizada

Docker y engines similares pueden cargar un perfil seccomp personalizado desde JSON. Un ejemplo mínimo que deniega `chmod` mientras permite todo lo demás es el siguiente:
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
Aplicado con:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
El comando falla con `Operation not permitted`, lo que demuestra que la restricción proviene de la política de syscalls y no únicamente de los permisos de archivo normales. En un hardening real, las allowlists suelen ser más sólidas que los valores predeterminados permisivos con una pequeña blacklist.

## Misconfigurations

El error más grave consiste en establecer seccomp como **unconfined** porque una aplicación falló con la política predeterminada. Esto es común durante la resolución de problemas y muy peligroso como solución permanente. Una vez eliminado el filtro, muchas primitivas de breakout basadas en syscalls vuelven a estar disponibles, especialmente cuando también hay capabilities potentes o namespaces del host compartidos.

Otro problema frecuente es el uso de un **custom permissive profile** copiado de algún blog o workaround interno sin haberlo revisado cuidadosamente. A veces los equipos conservan casi todas las syscalls peligrosas simplemente porque el perfil se creó con el objetivo de "evitar que la aplicación falle" en lugar de "conceder solo lo que la aplicación realmente necesita". Otra idea equivocada es asumir que seccomp es menos importante para los contenedores non-root. En realidad, una gran parte de la attack surface del kernel sigue siendo relevante incluso cuando el proceso no tiene UID 0.

## Abuse

Si seccomp está ausente o muy debilitado, un atacante podría invocar syscalls de creación de namespaces, ampliar la attack surface accesible del kernel mediante `bpf` o `perf_event_open`, abusar de `keyctl` o combinar esas rutas de syscalls con capabilities peligrosas como `CAP_SYS_ADMIN`. En muchos ataques reales, seccomp no es el único control ausente, pero su ausencia acorta drásticamente la ruta de exploit porque elimina una de las pocas defensas capaces de detener una syscall de riesgo antes de que entre en juego el resto del modelo de privilegios.

La prueba práctica más útil consiste en intentar las familias exactas de syscalls que normalmente bloquean los perfiles predeterminados. Si de repente funcionan, la postura de seguridad del contenedor ha cambiado considerablemente:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` u otra capability potente está presente, comprueba si seccomp es la única barrera que falta antes de un abuso basado en montajes:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
En algunos objetivos, el valor inmediato no es el escape completo, sino la recopilación de información y la ampliación de la superficie de ataque del kernel. Estos comandos ayudan a determinar si se puede acceder a rutas de syscall especialmente sensibles:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp está ausente y el container también es privilegiado de otras formas, es entonces cuando tiene sentido hacer pivot hacia las técnicas más específicas de breakout ya documentadas en las páginas legacy de container-escape.

### Ejemplo completo: seccomp era lo único que bloqueaba `unshare`

En muchos targets, el efecto práctico de eliminar seccomp es que las syscalls de creación de namespaces o de montaje empiezan a funcionar de repente. Si el container también tiene `CAP_SYS_ADMIN`, la siguiente secuencia puede ser posible:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Por sí solo, esto todavía no constituye un escape del host, pero demuestra que seccomp era la barrera que impedía la explotación relacionada con montajes.

### Ejemplo completo: seccomp deshabilitado + `release_agent` de cgroup v1

Si seccomp está deshabilitado y el contenedor puede montar jerarquías de cgroup v1, la técnica `release_agent` de la sección de cgroups se vuelve accesible:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Esto no es un exploit exclusivo de seccomp. El punto es que, una vez que seccomp está sin restricciones, las cadenas de escape con un uso intensivo de syscalls que antes estaban bloqueadas pueden empezar a funcionar exactamente como están escritas.

## Comprobaciones

El propósito de estas comprobaciones es determinar si seccomp está activo, si `no_new_privs` lo acompaña y si la configuración del runtime muestra que seccomp está deshabilitado explícitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Qué es interesante aquí:

- Un valor `Seccomp` distinto de cero significa que el filtrado está activo; `0` normalmente significa que no hay protección seccomp.
- Si las opciones de seguridad del Runtime incluyen `seccomp=unconfined`, la workload ha perdido una de sus defensas más útiles a nivel de syscall.
- `NoNewPrivs` no es seccomp en sí, pero ver ambos juntos normalmente indica una postura de hardening más cuidadosa que no ver ninguno.

Si un container ya tiene mounts sospechosos, capabilities amplias o namespaces del host compartidos, y seccomp también está configurado como unconfined, esa combinación debe tratarse como una señal importante de escalada. El container todavía podría no ser trivial de romper, pero el número de entry points del kernel disponibles para el atacante ha aumentado considerablemente.

## Valores predeterminados del Runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Normalmente habilitado de forma predeterminada | Usa el perfil seccomp predeterminado integrado de Docker, salvo que se sobrescriba | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Normalmente habilitado de forma predeterminada | Aplica el perfil seccomp predeterminado del Runtime, salvo que se sobrescriba | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **No está garantizado de forma predeterminada** | Si `securityContext.seccompProfile` no está definido, el valor predeterminado es `Unconfined`, salvo que el kubelet habilite `--seccomp-default`; en caso contrario, se debe establecer explícitamente `RuntimeDefault` o `Localhost` | `securityContext.seccompProfile.type: Unconfined`, dejar seccomp sin definir en clusters sin `seccompDefault`, `privileged: true` |
| containerd / CRI-O bajo Kubernetes | Sigue la configuración del nodo y del Pod de Kubernetes | El perfil del Runtime se utiliza cuando Kubernetes solicita `RuntimeDefault` o cuando está habilitada la configuración predeterminada de seccomp del kubelet | Igual que en la fila de Kubernetes; la configuración directa de CRI/OCI también puede omitir seccomp por completo |

El comportamiento de Kubernetes es el que más suele sorprender a los operadores. En muchos clusters, seccomp sigue estando ausente a menos que el Pod lo solicite o que el kubelet esté configurado para usar `RuntimeDefault` de forma predeterminada.<sup>[[3]](#references)</sup>

## Referencias

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
