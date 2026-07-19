# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` es una feature de hardening del kernel que impide que un proceso obtenga más privilegios mediante `execve()`. En términos prácticos, una vez establecido el flag, ejecutar un binario setuid, un binario setgid o un archivo con Linux file capabilities no otorga privilegios adicionales más allá de los que el proceso ya tenía. En entornos containerizados, esto es importante porque muchas cadenas de privilege-escalation dependen de encontrar un ejecutable dentro de la image que cambie los privilegios al iniciarse.

Desde un punto de vista defensivo, `no_new_privs` no sustituye a namespaces, seccomp ni al dropping de capabilities. Es una capa de refuerzo. Bloquea una clase específica de escalada posterior después de que ya se haya obtenido code execution. Esto lo hace especialmente valioso en entornos donde las images contienen helper binaries, artefactos de package-managers o herramientas legacy que, de otro modo, serían peligrosas al combinarse con un compromiso parcial.

## Funcionamiento

El flag del kernel detrás de este comportamiento es `PR_SET_NO_NEW_PRIVS`. Una vez establecido para un proceso, las llamadas posteriores a `execve()` no pueden aumentar los privilegios. El detalle importante es que el proceso todavía puede ejecutar binarios; simplemente no puede utilizar esos binarios para cruzar un límite de privilegios que el kernel normalmente respetaría.

El comportamiento del kernel también es **heredado e irreversible**: una vez que una task establece `no_new_privs`, el bit se hereda mediante `fork()`, `clone()` y `execve()`, y no se puede desactivar posteriormente. Esto resulta útil en assessments porque un `NoNewPrivs: 1` en el proceso del container normalmente significa que los descendientes también deberían permanecer en ese modo, a menos que estés observando un process tree completamente diferente.

En entornos orientados a Kubernetes, `allowPrivilegeEscalation: false` se corresponde con este comportamiento para el proceso del container. En runtimes al estilo de Docker y Podman, el equivalente normalmente se habilita explícitamente mediante una security option. En la capa OCI, el mismo concepto aparece como `process.noNewPrivileges`.

## Matices importantes

`no_new_privs` bloquea la obtención de privilegios **durante la ejecución**, no todos los cambios de privilegios. En particular:

- las transiciones setuid y setgid dejan de funcionar mediante `execve()`
- las file capabilities no se añaden al permitted set mediante `execve()`
- los LSMs como AppArmor o SELinux no relajan sus restricciones después de `execve()`
- los privilegios que ya se tienen siguen siendo privilegios que ya se tienen

Este último punto es importante desde el punto de vista operativo. Si el proceso ya se ejecuta como root, ya tiene una capability peligrosa o ya tiene acceso a una runtime API potente o a un host mount escribible, establecer `no_new_privs` no neutraliza esas exposiciones. Solo elimina un **siguiente paso** común en una cadena de privilege-escalation.

Ten en cuenta también que el flag no bloquea los cambios de privilegios que no dependen de `execve()`. Por ejemplo, una task que ya tenga suficientes privilegios puede seguir llamando directamente a `setuid(2)` o recibir un file descriptor privilegiado a través de un Unix socket. Por eso, `no_new_privs` debe analizarse junto con [seccomp](seccomp.md), los capability sets y la exposición de namespaces, en lugar de considerarse una solución independiente.

## Laboratorio

Inspecciona el estado del proceso actual:
```bash
grep NoNewPrivs /proc/self/status
```
Compáralo con un contenedor en el que el runtime habilita el flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
En un workload reforzado, el resultado debería mostrar `NoNewPrivs: 1`.

También puedes demostrar el efecto real contra un binario setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
El objetivo de la comparación no es afirmar que `su` sea explotable universalmente. Es que la misma imagen puede comportarse de forma muy diferente dependiendo de si `execve()` todavía puede cruzar un límite de privilegios.

## Impacto en la seguridad

Si `no_new_privs` está ausente, un foothold dentro del contenedor todavía puede elevarse mediante helpers setuid o binaries con file capabilities. Si está presente, esos cambios de privilegios posteriores a `exec` quedan bloqueados. El efecto es especialmente relevante en imágenes base amplias que incluyen muchas utilidades que la aplicación nunca necesitó.

También existe una interacción importante con seccomp. Por lo general, las tareas sin privilegios necesitan que `no_new_privs` esté configurado antes de poder instalar un filtro seccomp en filter mode. Esta es una de las razones por las que los contenedores hardened suelen mostrar `Seccomp` y `NoNewPrivs` habilitados al mismo tiempo. Desde la perspectiva de un atacante, ver ambos normalmente significa que el entorno se configuró deliberadamente y no por accidente.

## Configuraciones incorrectas

El problema más común es simplemente no habilitar este control en entornos donde sería compatible. En Kubernetes, dejar `allowPrivilegeEscalation` habilitado suele ser el error operativo predeterminado. En Docker y Podman, omitir la security option correspondiente tiene el mismo efecto. Otro fallo recurrente es asumir que, como un contenedor "no es privileged", las transiciones de privilegios en tiempo de `exec` dejan de ser relevantes automáticamente.

Un problema más sutil de Kubernetes es que `allowPrivilegeEscalation: false` **no** se respeta como la gente espera cuando el contenedor es `privileged` o cuando tiene `CAP_SYS_ADMIN`. La API de Kubernetes documenta que `allowPrivilegeEscalation` es efectivamente siempre true en esos casos. En la práctica, esto significa que el campo debe tratarse como una señal más de la postura final, no como una garantía de que el runtime terminó con `NoNewPrivs: 1`.

## Abuso

Si `no_new_privs` no está configurado, la primera pregunta es si la imagen contiene binaries que todavía puedan elevar privilegios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Los resultados interesantes incluyen:

- `NoNewPrivs: 0`
- helpers setuid como `su`, `mount`, `passwd` o herramientas de administración específicas de la distribución
- binarios con file capabilities que otorgan privilegios de red o del filesystem

En una evaluación real, estos hallazgos no demuestran por sí mismos que exista una escalada funcional, pero identifican exactamente los binarios que conviene probar a continuación.

En Kubernetes, verifica también que la intención del YAML coincida con la realidad del kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinaciones interesantes incluyen:

- `allowPrivilegeEscalation: false` en la especificación del Pod, pero `NoNewPrivs: 0` en el contenedor
- `cap_sys_admin` presente, lo que hace que el campo de Kubernetes sea mucho menos confiable
- `Seccomp: 0` y `NoNewPrivs: 0`, lo que normalmente indica una postura del runtime ampliamente debilitada, en lugar de un único error aislado

### Ejemplo completo: In-Container Privilege Escalation mediante setuid

Este control normalmente evita la **in-container privilege escalation** en lugar de impedir directamente el **host escape**. Si `NoNewPrivs` es `0` y existe un helper setuid, pruébalo explícitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si hay un binario setuid conocido presente y funcional, intenta ejecutarlo de forma que preserve la transición de privilegios:
```bash
/bin/su -c id 2>/dev/null
```
Esto no permite por sí mismo escapar del container, pero puede convertir un foothold de bajos privilegios dentro del container en container-root, lo que a menudo se convierte en el requisito previo para un escape posterior del host mediante mounts, runtime sockets o interfaces orientadas al kernel.

## Checks

El objetivo de estos checks es determinar si la obtención de privilegios durante la ejecución está bloqueada y si la imagen aún contiene helpers relevantes en caso de que no lo esté.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Qué es interesante aquí:

- `NoNewPrivs: 1` suele ser el resultado más seguro.
- `NoNewPrivs: 0` significa que las rutas de escalada basadas en setuid y file-cap siguen siendo relevantes.
- `NoNewPrivs: 1` junto con `Seccomp: 2` suele indicar una postura de hardening más intencional.
- Un manifest de Kubernetes que indica `allowPrivilegeEscalation: false` es útil, pero el estado del kernel es la fuente de verdad.
- Una imagen minimalista con pocos binarios setuid/file-cap, o sin ellos, ofrece a un atacante menos opciones de post-explotación incluso cuando falta `no_new_privs`.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | No habilitado de forma predeterminada | Se habilita explícitamente con `--security-opt no-new-privileges=true`; también existe un valor predeterminado para todo el daemon mediante `dockerd --no-new-privileges` | omitir el flag, `--privileged` |
| Podman | No habilitado de forma predeterminada | Se habilita explícitamente con `--security-opt no-new-privileges` o una configuración de seguridad equivalente | omitir la opción, `--privileged` |
| Kubernetes | Controlado por la política de la carga de trabajo | `allowPrivilegeEscalation: false` solicita este efecto, pero `privileged: true` y `CAP_SYS_ADMIN` hacen que, en la práctica, siga habilitado | `allowPrivilegeEscalation: true`, `privileged: true`, añadir `CAP_SYS_ADMIN` |
| containerd / CRI-O bajo Kubernetes | Sigue la configuración de la carga de trabajo de Kubernetes / `OCI process.noNewPrivileges` | Normalmente se hereda del contexto de seguridad del Pod y se traduce a la configuración del runtime OCI | igual que en la fila de Kubernetes |

Esta protección suele estar ausente simplemente porque nadie la habilitó, no porque el runtime no la admita.

## Referencias

- [Documentación del kernel de Linux: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
