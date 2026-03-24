# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** es el mecanismo que permite al kernel aplicar un filtro a los syscalls que un proceso puede invocar. En entornos containerizados, seccomp se usa normalmente en filter mode para que el proceso no sea simplemente marcado "restricted" en un sentido vago, sino que esté sujeto a una política concreta de syscalls. Esto importa porque muchas container breakouts requieren alcanzar interfaces del kernel muy específicas. Si el proceso no puede invocar con éxito los syscalls relevantes, una gran clase de ataques desaparece antes incluso de que cualquier matiz de namespaces o capabilities llegue a ser relevante.

El modelo mental clave es simple: namespaces deciden **qué puede ver el proceso**, capabilities deciden **qué acciones privilegiadas el proceso está nominalmente autorizado a intentar**, y seccomp decide **si el kernel siquiera aceptará el punto de entrada del syscall para la acción intentada**. Por eso seccomp con frecuencia previene ataques que de otro modo parecerían posibles basándose únicamente en capabilities.

## Security Impact

Mucha superficie peligrosa del kernel es accesible solo a través de un conjunto relativamente pequeño de syscalls. Ejemplos que importan repetidamente en container hardening incluyen `mount`, `unshare`, `clone` o `clone3` con flags particulares, `bpf`, `ptrace`, `keyctl` y `perf_event_open`. Un atacante que pueda alcanzar esos syscalls podría crear nuevos namespaces, manipular subsistemas del kernel o interactuar con superficie de ataque que un contenedor de aplicación normal no necesita en absoluto.

Por eso los perfiles seccomp por defecto del runtime son tan importantes. No son meramente una "extra defense". En muchos entornos suponen la diferencia entre un container que puede ejercer una amplia porción de la funcionalidad del kernel y otro que está restringido a una superficie de syscalls más cercana a lo que la aplicación realmente necesita.

## Modes And Filter Construction

seccomp históricamente tenía un strict mode en el que solo un conjunto mínimo de syscalls permanecía disponible, pero el modo relevante para los modernos container runtimes es seccomp filter mode, a menudo llamado **seccomp-bpf**. En este modelo, el kernel evalúa un programa de filtro que decide si un syscall debe permitirse, denegarse con un errno, atraparse, registrarse, o matar el proceso. Los container runtimes usan este mecanismo porque es lo bastante expresivo para bloquear amplias clases de syscalls peligrosos sin impedir el comportamiento normal de la aplicación.

Dos ejemplos a bajo nivel son útiles porque hacen el mecanismo concreto en lugar de mágico. Strict mode demuestra el viejo modelo de "only a minimal syscall set survives":
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
El `open` final hace que el proceso sea terminado porque no forma parte del conjunto mínimo de strict mode.

Un ejemplo de filtro libseccomp muestra el modelo de políticas moderno con más claridad:
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
Este estilo de política es lo que la mayoría de los lectores debería imaginar cuando piensan en perfiles seccomp en tiempo de ejecución.

## Lab

Una forma sencilla de confirmar que seccomp está activo en un contenedor es:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
También puedes intentar una operación que los perfiles predeterminados suelen restringir:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si el container se está ejecutando con un perfil seccomp predeterminado normal, las operaciones de tipo `unshare` suelen estar bloqueadas. Esto es una demostración útil porque muestra que, incluso si la userspace tool existe dentro de la imagen, la ruta del kernel que necesita puede seguir siendo inaccesible.
Si el container se está ejecutando con un perfil seccomp predeterminado normal, las operaciones de tipo `unshare` suelen estar bloqueadas incluso cuando la userspace tool existe dentro de la imagen.

Para inspeccionar el estado del proceso de forma más general, ejecute:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso en tiempo de ejecución

Docker es compatible con perfiles seccomp predeterminados y personalizados y permite a los administradores deshabilitarlos con `--security-opt seccomp=unconfined`. Podman tiene soporte similar y a menudo combina seccomp con la ejecución sin privilegios de root en una postura predeterminada muy sensata. Kubernetes expone seccomp a través de la configuración de las cargas de trabajo, donde `RuntimeDefault` suele ser la línea base sensata y `Unconfined` debe tratarse como una excepción que requiere justificación en lugar de un interruptor de conveniencia.

En entornos basados en containerd y CRI-O, la ruta exacta es más por capas, pero el principio es el mismo: el motor u orquestador de más alto nivel decide qué debe ocurrir, y el runtime finalmente instala la política seccomp resultante para el proceso del contenedor. El resultado aún depende de la configuración final del runtime que llegue al kernel.

### Ejemplo de política personalizada

Docker y motores similares pueden cargar un perfil seccomp personalizado desde JSON. Un ejemplo mínimo que deniega `chmod` mientras permite todo lo demás se ve así:
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
El comando falla con `Operation not permitted`, demostrando que la restricción proviene de la política de syscalls en lugar de los permisos ordinarios del archivo. En el endurecimiento real, las allowlists suelen ser más estrictas que los valores predeterminados permisivos con una pequeña blacklist.

## Misconfiguraciones

El error más grave es establecer seccomp a **unconfined** porque una aplicación falló bajo la política predeterminada. Esto es común durante la resolución de problemas y muy peligroso como solución permanente. Una vez que el filtro desaparece, muchos primitivos de escape basados en syscalls vuelven a ser alcanzables, especialmente cuando también están presentes capacidades potentes o el compartido del namespace del host.

Otro problema frecuente es el uso de un **custom permissive profile** que fue copiado de algún blog o workaround interno sin ser revisado cuidadosamente. Los equipos a veces retienen casi todos los syscalls peligrosos simplemente porque el profile se construyó alrededor de "evitar que la app falle" en lugar de "conceder solo lo que la app realmente necesita". Una tercera idea equivocada es asumir que seccomp es menos importante para contenedores no-root. En realidad, mucha superficie de ataque del kernel sigue siendo relevante incluso cuando el proceso no es UID 0.

## Abuse

Si seccomp está ausente o gravemente debilitado, un atacante puede ser capaz de invocar syscalls de creación de namespaces, expandir la superficie de ataque del kernel alcanzable a través de `bpf` o `perf_event_open`, abusar de `keyctl`, o combinar esas rutas de syscalls con capacidades peligrosas como `CAP_SYS_ADMIN`. En muchos ataques reales, seccomp no es el único control ausente, pero su ausencia acorta dramáticamente el camino del exploit porque elimina una de las pocas defensas que pueden detener un syscall riesgoso antes de que el resto del modelo de privilegios entre en juego.

La prueba práctica más útil es intentar las familias exactas de syscalls que los perfiles por defecto suelen bloquear. Si de repente funcionan, la postura del contenedor ha cambiado mucho:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` u otra capacidad fuerte está presente, comprueba si seccomp es la única barrera que falta antes del abuso basado en mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
En algunos objetivos, el valor inmediato no es un full escape sino information gathering y kernel attack-surface expansion. Estos comandos ayudan a determinar si rutas de syscall especialmente sensibles son alcanzables:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
If seccomp is absent and the container is also privileged in other ways, that is when it makes sense to pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### Ejemplo completo: seccomp fue lo único que bloqueaba `unshare`

En muchos objetivos, el efecto práctico de eliminar seccomp es que namespace-creation o mount syscalls de repente empiezan a funcionar. Si el container también tiene `CAP_SYS_ADMIN`, la siguiente secuencia puede volverse posible:
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
Por sí solo esto aún no es un escape al host, pero demuestra que seccomp era la barrera que prevenía la explotación relacionada con mount.

### Ejemplo completo: seccomp deshabilitado + cgroup v1 `release_agent`

Si seccomp está deshabilitado y el contenedor puede montar jerarquías cgroup v1, la técnica `release_agent` de la sección cgroups se vuelve alcanzable:
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
Este no es un exploit exclusivo de seccomp. La idea es que, una vez que seccomp no está confinado, las syscall-heavy breakout chains que antes estaban bloqueadas pueden empezar a funcionar exactamente como están escritas.

## Comprobaciones

El propósito de estas comprobaciones es determinar si seccomp está activo en absoluto, si `no_new_privs` lo acompaña, y si la configuración en tiempo de ejecución muestra que seccomp está explícitamente deshabilitado.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Lo interesante aquí:

- Un valor de `Seccomp` distinto de cero significa que el filtrado está activo; `0` suele significar que no hay protección seccomp.
- Si las opciones de seguridad del runtime incluyen `seccomp=unconfined`, la carga de trabajo ha perdido una de sus defensas a nivel de syscall más útiles.
- `NoNewPrivs` no es seccomp en sí, pero ver ambos juntos normalmente indica una postura de hardening más cuidadosa que no ver ninguno.

Si un contenedor ya tiene montajes sospechosos, capacidades amplias o espacios de nombres del host compartidos, y seccomp también está unconfined, esa combinación debe tratarse como una señal de escalada importante. El contenedor aún puede no ser trivialmente explotable, pero el número de puntos de entrada al kernel disponibles para el atacante ha aumentado drásticamente.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **No garantizado por defecto** | Si `securityContext.seccompProfile` no está establecido, el valor por defecto es `Unconfined` a menos que el kubelet habilite `--seccomp-default`; `RuntimeDefault` o `Localhost` deben establecerse explícitamente en caso contrario | `securityContext.seccompProfile.type: Unconfined`, dejar seccomp sin establecer en clusters sin `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Sigue la configuración de nodo y Pod de Kubernetes | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

El comportamiento de Kubernetes es el que más suele sorprender a los operadores. En muchos clusters, seccomp todavía está ausente a menos que el Pod lo solicite o el kubelet esté configurado para usar `RuntimeDefault` por defecto.
{{#include ../../../../banners/hacktricks-training.md}}
