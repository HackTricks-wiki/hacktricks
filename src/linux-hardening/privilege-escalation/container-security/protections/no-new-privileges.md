# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` es una función de hardening del kernel que impide que un proceso obtenga más privilegios a través de `execve()`. En términos prácticos, una vez que se establece la bandera, ejecutar un binario setuid, un binario setgid o un archivo con Linux file capabilities no concede privilegios extra más allá de los que el proceso ya tenía. En entornos containerized, esto es importante porque muchas cadenas de privilege-escalation dependen de encontrar un ejecutable dentro de la imagen que cambie de privilegios al lanzarse.

Desde un punto de vista defensivo, `no_new_privs` no sustituye a namespaces, seccomp o capability dropping. Es una capa de refuerzo. Bloquea una clase concreta de escalada posterior después de que ya se ha obtenido code execution. Eso lo hace especialmente valioso en entornos donde las imágenes contienen helper binaries, artefactos de package-manager o herramientas heredadas que, de otro modo, serían peligrosas cuando se combinan con una compromise parcial.

## Operation

La bandera del kernel detrás de este comportamiento es `PR_SET_NO_NEW_PRIVS`. Una vez que se establece para un proceso, las llamadas posteriores a `execve()` no pueden aumentar privilegios. El detalle importante es que el proceso puede seguir ejecutando binaries; simplemente no puede usar esos binaries para cruzar una frontera de privilegios que el kernel de otro modo respetaría.

El comportamiento del kernel también es **heredado e irreversible**: una vez que una task establece `no_new_privs`, el bit se hereda a través de `fork()`, `clone()` y `execve()`, y no puede desactivarse después. Esto es útil en assessments porque un solo `NoNewPrivs: 1` en el proceso del container normalmente significa que los descendientes también deberían permanecer en ese modo, a menos que estés mirando un árbol de procesos completamente distinto.

En entornos orientados a Kubernetes, `allowPrivilegeEscalation: false` se mapea a este comportamiento para el proceso del container. En runtimes estilo Docker y Podman, el equivalente suele habilitarse explícitamente mediante una security option. En la capa OCI, el mismo concepto aparece como `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` bloquea la ganancia de privilegios en tiempo de `exec`, no cualquier cambio de privilegios. En particular:

- las transiciones setuid y setgid dejan de funcionar a través de `execve()`
- las file capabilities no se añaden al conjunto permitido en `execve()`
- los LSMs como AppArmor o SELinux no relajan restricciones después de `execve()`
- el privilege ya obtenido sigue siendo privilege ya obtenido

Ese último punto importa operativamente. Si el proceso ya se ejecuta como root, ya tiene una capability peligrosa o ya tiene acceso a una potente API de runtime o a un host mount writable, establecer `no_new_privs` no neutraliza esas exposiciones. Solo elimina un paso común **siguiente** en una cadena de privilege-escalation.

También hay que tener en cuenta que la bandera no bloquea cambios de privilegios que no dependen de `execve()`. Por ejemplo, una task que ya es lo suficientemente privilegiada aún puede llamar a `setuid(2)` directamente o recibir un privileged file descriptor a través de un Unix socket. Por eso `no_new_privs` debe leerse junto con [seccomp](seccomp.md), capability sets y la exposición de namespace, en lugar de como una solución aislada.

## Lab

Inspecciona el estado actual del proceso:
```bash
grep NoNewPrivs /proc/self/status
```
Compáralo con un container donde el runtime habilita la flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
En un workload hardened, el resultado debería mostrar `NoNewPrivs: 1`.

También puedes demostrar el efecto real contra un binary setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
El punto de la comparación no es que `su` sea universalmente explotable. Es que la misma imagen puede comportarse de forma muy diferente dependiendo de si `execve()` todavía puede cruzar un límite de privilegio.

## Security Impact

Si `no_new_privs` no está presente, un foothold dentro del container aún puede ser elevado mediante setuid helpers o binaries con file capabilities. Si está presente, esos cambios de privilegio después de `exec` quedan bloqueados. El efecto es especialmente relevante en imágenes base amplias que incluyen muchas utilidades que la aplicación nunca necesitó en primer lugar.

También hay una interacción importante con seccomp. Las tareas sin privilegios generalmente necesitan que `no_new_privs` esté configurado antes de poder instalar un seccomp filter en filter mode. Esta es una de las razones por las que los containers endurecidos a menudo muestran tanto `Seccomp` como `NoNewPrivs` habilitados juntos. Desde la perspectiva de un atacante, ver ambos normalmente significa que el entorno fue configurado deliberadamente y no por accidente.

## Misconfigurations

El problema más común es simplemente no habilitar el control en entornos donde sería compatible. En Kubernetes, dejar `allowPrivilegeEscalation` habilitado suele ser el error operativo por defecto. En Docker y Podman, omitir la security option relevante tiene el mismo efecto. Otro modo de fallo recurrente es asumir que, porque un container no es "privileged", las transiciones de privilegio en tiempo de `exec` son automáticamente irrelevantes.

Un problema más sutil en Kubernetes es que `allowPrivilegeEscalation: false` **no** se respeta como la gente espera cuando el container es `privileged` o cuando tiene `CAP_SYS_ADMIN`. La API de Kubernetes documenta que `allowPrivilegeEscalation` es efectivamente siempre true en esos casos. En la práctica, esto significa que el campo debe tratarse como una señal más en la postura final, no como una garantía de que el runtime terminó con `NoNewPrivs: 1`.

## Abuse

Si `no_new_privs` no está configurado, la primera pregunta es si la imagen contiene binaries que aún pueden elevar privilegio:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interesantes incluyen:

- `NoNewPrivs: 0`
- helpers setuid como `su`, `mount`, `passwd`, o herramientas de administración específicas de la distribución
- binaries con file capabilities que conceden privilegios de red o de filesystem

En una evaluación real, estos hallazgos no prueban por sí solos una escalada funcional, pero identifican exactamente los binaries que merece la pena probar a continuación.

En Kubernetes, también verifica que la intención del YAML coincida con la realidad del kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinaciones interesantes incluyen:

- `allowPrivilegeEscalation: false` en el Pod spec pero `NoNewPrivs: 0` en el container
- `cap_sys_admin` presente, lo que hace que el campo de Kubernetes sea mucho menos confiable
- `Seccomp: 0` y `NoNewPrivs: 0`, lo que normalmente indica una postura de runtime ampliamente debilitada en lugar de un único error aislado

### Full Example: In-Container Privilege Escalation Through setuid

Este control suele prevenir la **in-container privilege escalation** en lugar de un escape del host directamente. Si `NoNewPrivs` es `0` y existe un helper setuid, pruébalo explícitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binario setuid conocido está presente y funciona, intenta lanzarlo de una forma que preserve la transición de privilegios:
```bash
/bin/su -c id 2>/dev/null
```
Esto por sí solo no escapa del container, pero puede convertir un foothold de bajo privilegio dentro del container en container-root, lo que a menudo se convierte en el requisito previo para un posterior host escape mediante mounts, runtime sockets o interfaces orientadas al kernel.

## Checks

El objetivo de estos checks es establecer si el aumento de privilegios en tiempo de ejecución está bloqueado y si la imagen todavía contiene helpers que importarían si no lo está.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Lo interesante aquí:

- `NoNewPrivs: 1` suele ser el resultado más seguro.
- `NoNewPrivs: 0` significa que las rutas de escalada basadas en setuid y file-cap siguen siendo relevantes.
- `NoNewPrivs: 1` junto con `Seccomp: 2` es una señal común de una postura de hardening más intencional.
- Un manifest de Kubernetes que diga `allowPrivilegeEscalation: false` es útil, pero el estado del kernel es la verdad absoluta.
- Una imagen minimalista con pocos o ningún binario setuid/file-cap le da a un atacante menos opciones de post-exploitation incluso cuando `no_new_privs` falta.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | No habilitado por defecto | Habilitado explícitamente con `--security-opt no-new-privileges=true`; también existe un valor por defecto a nivel daemon vía `dockerd --no-new-privileges` | omitir el flag, `--privileged` |
| Podman | No habilitado por defecto | Habilitado explícitamente con `--security-opt no-new-privileges` o una configuración de seguridad equivalente | omitir la opción, `--privileged` |
| Kubernetes | Controlado por la policy del workload | `allowPrivilegeEscalation: false` solicita el efecto, pero `privileged: true` y `CAP_SYS_ADMIN` lo mantienen efectivamente true | `allowPrivilegeEscalation: true`, `privileged: true`, añadir `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Sigue la configuración del workload de Kubernetes / OCI `process.noNewPrivileges` | Normalmente se hereda del security context del Pod y se traduce a la OCI runtime config | igual que la fila de Kubernetes |

Esta protección a menudo está ausente simplemente porque nadie la activó, no porque el runtime no la soporte.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
