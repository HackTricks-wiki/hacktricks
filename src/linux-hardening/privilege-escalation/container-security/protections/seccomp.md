# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Visión general

**seccomp** es el mecanismo que permite al kernel aplicar un filtro a los syscalls que un proceso puede invocar. En entornos containerizados, seccomp normalmente se usa en modo filtro de forma que el proceso no queda simplemente marcado como "restringido" en un sentido vago, sino que está sujeto a una política concreta de syscalls. Esto importa porque muchas fugas de contenedores requieren alcanzar interfaces específicas del kernel. Si el proceso no puede invocar con éxito los syscalls relevantes, una gran clase de ataques desaparece antes de que cualquier matiz de namespaces o capabilities siquiera se vuelva relevante.

El modelo mental clave es simple: namespaces deciden **qué puede ver el proceso**, capabilities deciden **qué acciones privilegiadas puede intentar nominalmente el proceso**, y seccomp decide **si el kernel siquiera aceptará el punto de entrada syscall para la acción intentada**. Por eso seccomp frecuentemente previene ataques que de otra forma parecerían posibles basándose únicamente en las capabilities.

## Impacto en la seguridad

Una gran parte de la superficie peligrosa del kernel es accesible solo a través de un conjunto relativamente pequeño de syscalls. Ejemplos que importan repetidamente en el hardening de contenedores incluyen `mount`, `unshare`, `clone` o `clone3` con flags particulares, `bpf`, `ptrace`, `keyctl`, y `perf_event_open`. Un atacante que pueda alcanzar esos syscalls puede ser capaz de crear nuevos namespaces, manipular subsistemas del kernel, o interactuar con superficie de ataque que un contenedor de aplicación normal no necesita en absoluto.

Por eso los perfiles seccomp por defecto del runtime son tan importantes. No son meramente una "defensa extra". En muchos entornos son la diferencia entre un contenedor que puede ejercer una amplia porción de la funcionalidad del kernel y uno que está restringido a una superficie de syscalls más cercana a lo que la aplicación necesita genuinamente.

## Modos y construcción de filtros

seccomp históricamente tenía un modo estricto en el que solo un conjunto mínimo de syscalls permanecía disponible, pero el modo relevante para los runtimes de contenedores modernos es seccomp filter mode, a menudo llamado **seccomp-bpf**. En este modelo, el kernel evalúa un programa de filtro que decide si un syscall debe ser permitido, denegado con un errno, atrapado, registrado, o terminar el proceso. Los container runtimes usan este mecanismo porque es lo bastante expresivo para bloquear amplias clases de syscalls peligrosos mientras aún permite el comportamiento normal de la aplicación.

Dos ejemplos a bajo nivel son útiles porque hacen el mecanismo concreto en lugar de mágico. El modo estricto demuestra el viejo modelo de "solo sobrevive un conjunto mínimo de syscalls":
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
La última llamada `open` provoca que el proceso sea terminado porque no forma parte del conjunto mínimo del modo estricto.

Un ejemplo de filtro de libseccomp muestra el modelo de políticas moderno con más claridad:
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
Este estilo de política es lo que la mayoría de los lectores debería imaginar cuando piensan en los seccomp profiles en tiempo de ejecución.

## Lab

Una forma simple de confirmar que seccomp está activo en un contenedor es:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
También puedes intentar una operación que los perfiles predeterminados suelen restringir:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si el contenedor se está ejecutando bajo un seccomp profile normal por defecto, las operaciones de tipo `unshare` suelen estar bloqueadas. Esto es una demostración útil porque muestra que, incluso si la userspace tool existe dentro de la imagen, la ruta del kernel que necesita puede seguir siendo inaccesible.

Si el contenedor se está ejecutando bajo un seccomp profile normal por defecto, las operaciones de tipo `unshare` suelen estar bloqueadas incluso cuando la userspace tool existe dentro de la imagen.

Para inspeccionar el estado del proceso de forma más general, ejecute:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso en tiempo de ejecución

Docker admite perfiles seccomp predeterminados y personalizados y permite a los administradores desactivarlos con `--security-opt seccomp=unconfined`. Podman ofrece soporte similar y a menudo empareja seccomp con ejecución sin root en una postura predeterminada muy sensata. Kubernetes expone seccomp a través de la configuración de cargas de trabajo, donde `RuntimeDefault` suele ser la línea base sensata y `Unconfined` debe tratarse como una excepción que requiere justificación en lugar de como un interruptor de conveniencia.

En entornos basados en containerd y CRI-O, la ruta exacta es más estratificada, pero el principio es el mismo: el motor u orquestador de mayor nivel decide qué debe ocurrir, y el runtime finalmente instala la política seccomp resultante para el proceso del contenedor. El resultado sigue dependiendo de la configuración final del runtime que llega al kernel.

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
El comando falla con `Operation not permitted`, lo que demuestra que la restricción proviene de la política de syscalls en lugar de las simples permisos de archivos. En el hardening real, las allowlists suelen ser más fuertes que los valores predeterminados permisivos con una pequeña blacklist.

## Misconfigurations

El error más burdo es establecer seccomp en **unconfined** porque una aplicación falló bajo la política por defecto. Esto es común durante el troubleshooting y muy peligroso como solución permanente. Una vez que el filtro desaparece, muchas primitivas de escape basadas en syscalls vuelven a ser alcanzables, especialmente cuando también están presentes capacidades potentes o compartición del host namespace.

Otro problema frecuente es el uso de un **custom permissive profile** que fue copiado de algún blog o workaround interno sin revisarlo detenidamente. Los equipos a veces mantienen casi todos los syscalls peligrosos simplemente porque el profile se construyó alrededor de "evitar que la app falle" en lugar de "conceder solo lo que la app realmente necesita". Una tercera idea equivocada es asumir que seccomp es menos importante para contenedores non-root. En realidad, gran parte de la superficie de ataque del kernel sigue siendo relevante incluso cuando el proceso no es UID 0.

## Abuse

Si seccomp está ausente o muy debilitado, un atacante puede ser capaz de invocar syscalls de creación de namespaces, expandir la superficie de ataque del kernel alcanzable a través de `bpf` o `perf_event_open`, abusar de `keyctl`, o combinar esas rutas de syscall con capacidades peligrosas como `CAP_SYS_ADMIN`. En muchos ataques reales, seccomp no es el único control faltante, pero su ausencia acorta dramáticamente la ruta del exploit porque elimina una de las pocas defensas que pueden detener un syscall riesgoso antes de que el resto del modelo de privilegios entre siquiera en juego.

La prueba práctica más útil es intentar las familias de syscalls exactas que los perfiles por defecto suelen bloquear. Si de repente funcionan, la postura del contenedor ha cambiado mucho:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` u otra capability fuerte está presente, comprueba si seccomp es la única barrera que falta antes del abuso basado en mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
En algunos objetivos, el valor inmediato no es un escape completo sino la recopilación de información y la expansión del attack-surface del kernel. Estos comandos ayudan a determinar si rutas de syscall especialmente sensibles son alcanzables:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp está ausente y el container también tiene otros privilegios, entonces tiene sentido pivotar hacia las breakout techniques más específicas ya documentadas en las legacy container-escape pages.

### Ejemplo completo: seccomp era lo único que bloqueaba `unshare`

En muchos objetivos, el efecto práctico de eliminar seccomp es que las syscalls de namespace-creation o de mount de repente comienzan a funcionar. Si el container también tiene `CAP_SYS_ADMIN`, la siguiente secuencia puede volverse posible:
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
Por sí solo, esto aún no constituye un host escape, pero demuestra que seccomp era la barrera que impedía mount-related exploitation.

### Ejemplo completo: seccomp Disabled + cgroup v1 `release_agent`

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
Esto no es un exploit exclusivo de seccomp. La idea es que, una vez que seccomp queda sin restricciones, syscall-heavy breakout chains que antes estaban bloqueadas pueden empezar a funcionar exactamente como están escritas.

## Comprobaciones

El propósito de estas comprobaciones es establecer si seccomp está activo en absoluto, si `no_new_privs` lo acompaña y si la configuración en tiempo de ejecución muestra que seccomp está deshabilitado explícitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Lo interesante aquí:

- Un valor `Seccomp` distinto de cero significa que el filtrado está activo; `0` normalmente indica ausencia de protección seccomp.
- Si las opciones de seguridad del runtime incluyen `seccomp=unconfined`, la carga de trabajo ha perdido una de sus defensas a nivel de syscall más útiles.
- `NoNewPrivs` no es seccomp en sí, pero ver ambos juntos suele indicar una postura de hardening más cuidadosa que no ver ninguno.

Si un contenedor ya tiene montajes sospechosos, capacidades amplias o espacios de nombres del host compartidos, y seccomp también está unconfined, esa combinación debe tratarse como una señal importante de escalada. El contenedor aún puede no ser trivialmente explotable, pero el número de puntos de entrada al kernel disponibles para el atacante ha aumentado drásticamente.

## Valores predeterminados en tiempo de ejecución

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **No garantizado por defecto** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

El comportamiento de Kubernetes es el que más sorprende a los operadores. En muchos clústeres, seccomp sigue ausente a menos que el Pod lo solicite o el kubelet esté configurado para usar `RuntimeDefault` por defecto.
