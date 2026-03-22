# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Visión general

**seccomp** es el mecanismo que permite al kernel aplicar un filtro a las syscalls que un proceso puede invocar. En entornos con contenedores, seccomp se usa normalmente en modo filtro para que el proceso no sea simplemente marcado como "restricted" de forma vaga, sino que esté sujeto a una política concreta de syscalls. Esto importa porque muchos escapes de contenedor requieren alcanzar interfaces del kernel muy específicas. Si el proceso no puede invocar con éxito las syscalls relevantes, una gran clase de ataques desaparece antes de que cualquier matiz de namespace o capability siquiera se vuelva relevante.

El modelo mental clave es simple: los namespaces deciden **qué puede ver el proceso**, las capabilities deciden **qué acciones privilegiadas el proceso está nominalmente autorizado a intentar**, y seccomp decide **si el kernel siquiera aceptará el punto de entrada syscall para la acción intentada**. Por eso seccomp frecuentemente evita ataques que, de otra manera, parecerían posibles basándose solo en las capabilities.

## Impacto en la seguridad

Mucha superficie peligrosa del kernel solo es accesible a través de un conjunto relativamente pequeño de syscalls. Ejemplos que importan repetidamente para el endurecimiento de contenedores incluyen `mount`, `unshare`, `clone` o `clone3` con flags particulares, `bpf`, `ptrace`, `keyctl` y `perf_event_open`. Un atacante que pueda alcanzar esas syscalls puede ser capaz de crear nuevos namespaces, manipular subsistemas del kernel o interactuar con superficie de ataque que un contenedor de aplicación normal no necesita en absoluto.

Por eso los perfiles seccomp por defecto del runtime son tan importantes. No son simplemente una "defensa extra". En muchos entornos son la diferencia entre un contenedor que puede ejercer una amplia porción de la funcionalidad del kernel y otro que está limitado a una superficie de syscalls más cercana a lo que la aplicación realmente necesita.

## Modos y construcción del filtro

seccomp históricamente tenía un modo estricto en el que solo un conjunto mínimo de syscalls seguía estando disponible, pero el modo relevante para los runtimes modernos de contenedores es el modo filtro de seccomp, a menudo llamado **seccomp-bpf**. En este modelo, el kernel evalúa un programa de filtro que decide si una syscall debe permitirse, denegarse con un errno, atraparse, registrarse o matar el proceso. Los runtimes de contenedores usan este mecanismo porque es lo bastante expresivo para bloquear amplias clases de syscalls peligrosas mientras permite el comportamiento normal de la aplicación.

Dos ejemplos a bajo nivel son útiles porque hacen el mecanismo concreto en lugar de mágico. El modo estricto demuestra el antiguo modelo de "solo sobrevive un conjunto mínimo de syscalls":
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
La llamada final `open` provoca que el proceso sea terminado porque no forma parte del conjunto mínimo de strict mode.

Un ejemplo de filtro libseccomp muestra el modelo de política moderno con más claridad:
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
Si el contenedor se está ejecutando bajo un perfil seccomp predeterminado normal, las operaciones estilo `unshare` suelen estar bloqueadas. Esto es una demostración útil porque muestra que incluso si la herramienta de espacio de usuario existe dentro de la imagen, la ruta del kernel que necesita aún puede estar indisponible.
Si el contenedor se está ejecutando bajo un perfil seccomp predeterminado normal, las operaciones estilo `unshare` suelen estar bloqueadas incluso cuando la herramienta de espacio de usuario existe dentro de la imagen.

Para inspeccionar el estado del proceso de forma más general, ejecuta:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso en tiempo de ejecución

Docker admite tanto perfiles seccomp predeterminados como personalizados y permite a los administradores deshabilitarlos con `--security-opt seccomp=unconfined`. Podman tiene soporte similar y a menudo combina seccomp con ejecución rootless en una postura predeterminada muy sensata. Kubernetes expone seccomp a través de la configuración de workload, donde `RuntimeDefault` suele ser la línea base sensata y `Unconfined` debe tratarse como una excepción que requiere justificación en lugar de un interruptor de conveniencia.

En entornos basados en containerd y CRI-O, la ruta exacta es más en capas, pero el principio es el mismo: el motor o orquestador de nivel superior decide qué debe ocurrir, y el runtime finalmente instala la política seccomp resultante para el proceso del contenedor. El resultado todavía depende de la configuración de runtime final que llega al kernel.

### Ejemplo de política personalizada

Docker y motores similares pueden cargar un perfil seccomp personalizado desde JSON. Un ejemplo mínimo que niega `chmod` mientras permite todo lo demás se ve así:
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
El comando falla con `Operation not permitted`, lo que demuestra que la restricción proviene de la política de syscalls en lugar de los permisos ordinarios de archivos. En un hardening real, las allowlists son generalmente más fuertes que los valores predeterminados permisivos con una pequeña blacklist.

## Misconfiguraciones

El error más torpe es establecer seccomp a **unconfined** porque una aplicación falló bajo la política predeterminada. Esto es común durante la resolución de problemas y muy peligroso como solución permanente. Una vez que el filtro desaparece, muchos primitivos de escape basados en syscalls vuelven a ser alcanzables nuevamente, especialmente cuando capacidades poderosas o el compartido de namespaces del host también están presentes.

Otro problema frecuente es el uso de un **custom permissive profile** que se copió de algún blog o solución interna sin revisarlo cuidadosamente. Los equipos a veces mantienen casi todos los syscalls peligrosos simplemente porque el perfil se construyó alrededor de "evitar que la app falle" en lugar de "otorgar solo lo que la app realmente necesita". Una tercera idea errónea es asumir que seccomp es menos importante para contenedores non-root. En realidad, mucha superficie de ataque del kernel sigue siendo relevante incluso cuando el proceso no es UID 0.

## Abuso

Si seccomp está ausente o muy debilitado, un atacante puede ser capaz de invocar syscalls de creación de namespaces, ampliar la superficie de ataque del kernel accesible a través de `bpf` o `perf_event_open`, abusar de `keyctl`, o combinar esas rutas de syscall con capacidades peligrosas como `CAP_SYS_ADMIN`. En muchos ataques reales, seccomp no es el único control ausente, pero su ausencia acorta dramáticamente el camino del exploit porque elimina una de las pocas defensas que puede detener un syscall riesgoso antes de que el resto del modelo de privilegios siquiera entre en juego.

La prueba práctica más útil es intentar las familias exactas de syscalls que los perfiles por defecto suelen bloquear. Si de repente funcionan, la postura del contenedor ha cambiado mucho:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` u otra capability fuerte está presente, comprueba si seccomp es la única barrera que falta antes de mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
En algunos objetivos, el valor inmediato no es un full escape sino la recopilación de información y la expansión de la superficie de ataque del kernel. Estos comandos ayudan a determinar si rutas de syscall especialmente sensibles son accesibles:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp está ausente y el contenedor también tiene privilegios de otras formas, entonces es cuando tiene sentido pivotar hacia las breakout techniques más específicas ya documentadas en las legacy container-escape pages.

### Ejemplo completo: seccomp fue lo único que bloqueaba `unshare`

En muchos targets, el efecto práctico de eliminar seccomp es que namespace-creation o mount syscalls de repente comienzan a funcionar. Si el contenedor también tiene `CAP_SYS_ADMIN`, la siguiente secuencia puede volverse posible:
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
Por sí solo esto todavía no constituye un host escape, pero demuestra que seccomp era la barrera que impedía la explotación relacionada con mount.

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
Esto no es un exploit exclusivo de seccomp. La cuestión es que, una vez que seccomp queda sin restricciones, syscall-heavy breakout chains que antes estaban bloqueadas pueden empezar a funcionar exactamente como están escritas.

## Comprobaciones

El objetivo de estas comprobaciones es establecer si seccomp está activo, si `no_new_privs` lo acompaña, y si la configuración en tiempo de ejecución muestra que seccomp está deshabilitado explícitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Lo interesante aquí:

- Un valor distinto de cero `Seccomp` significa que el filtrado está activo; `0` normalmente significa que no hay protección seccomp.
- Si las opciones de seguridad en tiempo de ejecución incluyen `seccomp=unconfined`, la workload ha perdido una de sus defensas más útiles a nivel de syscall.
- `NoNewPrivs` no es seccomp en sí, pero ver ambos juntos suele indicar una postura de hardening más cuidadosa que ver ninguno.

Si un contenedor ya tiene mounts sospechosos, capacidades amplias, o namespaces del host compartidos, y seccomp también está unconfined, esa combinación debe tratarse como una señal importante de escalada. El contenedor puede que aún no sea trivialmente explotable, pero el número de puntos de entrada del kernel disponibles para el atacante ha aumentado drásticamente.

## Valores predeterminados en tiempo de ejecución

| Runtime / platform | Estado por defecto | Comportamiento por defecto | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **No garantizado por defecto** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

El comportamiento de Kubernetes es el que más a menudo sorprende a los operadores. En muchos clusters, seccomp todavía está ausente a menos que el Pod lo solicite o el kubelet esté configurado para usar `RuntimeDefault` por defecto.
{{#include ../../../../banners/hacktricks-training.md}}
