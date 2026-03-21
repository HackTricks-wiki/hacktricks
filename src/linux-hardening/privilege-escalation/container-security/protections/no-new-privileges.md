# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` es una característica de hardening del kernel que evita que un proceso obtenga más privilegios a través de `execve()`. En términos prácticos, una vez que se establece la bandera, ejecutar un binario setuid, un binario setgid, o un archivo con Linux file capabilities no concede privilegios adicionales más allá de los que el proceso ya tenía. En entornos containerizados, esto es importante porque muchas cadenas de privilege-escalation dependen de encontrar un ejecutable dentro de la imagen que cambie privilegios al lanzarse.

Desde un punto de vista defensivo, `no_new_privs` no sustituye a namespaces, seccomp o a capability dropping. Es una capa de refuerzo. Bloquea una clase específica de escalada posterior después de que ya se ha obtenido ejecución de código. Eso lo hace especialmente valioso en entornos donde las imágenes contienen helper binaries, package-manager artifacts o legacy tools que de otro modo serían peligrosos cuando se combinan con un compromiso parcial.

## Operación

La flag del kernel detrás de este comportamiento es `PR_SET_NO_NEW_PRIVS`. Una vez que se establece para un proceso, las llamadas posteriores a `execve()` no pueden aumentar privilegios. El detalle importante es que el proceso aún puede ejecutar binarios; simplemente no puede usar esos binarios para cruzar una frontera de privilegios que el kernel de otro modo respetaría.

En entornos orientados a Kubernetes, `allowPrivilegeEscalation: false` mapea este comportamiento para el proceso del contenedor. En runtimes estilo Docker y Podman, el equivalente usualmente se habilita explícitamente mediante una opción de seguridad.

## Laboratorio

Inspecciona el estado del proceso actual:
```bash
grep NoNewPrivs /proc/self/status
```
Compáralo con un contenedor donde el runtime habilita la flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
En una carga de trabajo endurecida, el resultado debe mostrar `NoNewPrivs: 1`.

## Impacto en la seguridad

Si `no_new_privs` está ausente, un punto de apoyo dentro del contenedor aún puede elevarse mediante setuid helpers o binarios con file capabilities. Si está presente, esos cambios de privilegios post-ejecución se cortan. El efecto es especialmente relevante en imágenes base amplias que incluyen muchas utilidades que la aplicación nunca necesitó en primer lugar.

## Misconfiguraciones

El problema más común es simplemente no habilitar el control en entornos donde sería compatible. En Kubernetes, dejar `allowPrivilegeEscalation` habilitado suele ser el error operativo por defecto. En Docker y Podman, omitir la opción de seguridad relevante produce el mismo efecto. Otro modo recurrente de fallo es asumir que, porque un contenedor está "not privileged", las transiciones de privilegios en tiempo de ejecución son automáticamente irrelevantes.

## Abuso

Si `no_new_privs` no está establecido, la primera pregunta es si la imagen contiene binarios que aún pueden elevar privilegios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interesantes incluyen:

- `NoNewPrivs: 0`
- programas setuid como `su`, `mount`, `passwd`, o herramientas de administración específicas de la distribución
- binarios con file capabilities que otorgan privilegios de red o del sistema de archivos

En una evaluación real, estos hallazgos no prueban por sí mismos una escalada funcional, pero identifican exactamente los binarios que vale la pena probar a continuación.

### Ejemplo completo: In-Container Privilege Escalation Through setuid

Este control normalmente evita la **in-container privilege escalation** en lugar de permitir un host escape directo. Si `NoNewPrivs` es `0` y existe un helper setuid, pruébalo explícitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binario setuid conocido está presente y funcional, intenta ejecutarlo de forma que se preserve la transición de privilegios:
```bash
/bin/su -c id 2>/dev/null
```
Esto por sí solo no escapa del contenedor, pero puede convertir un punto de apoyo de baja privilegio dentro del contenedor en root del contenedor, lo que a menudo se vuelve el requisito previo para un posterior escape al host a través de montajes, sockets en tiempo de ejecución o interfaces con el kernel.

## Comprobaciones

El objetivo de estas comprobaciones es establecer si la ganancia de privilegios en tiempo de ejecución está bloqueada y si la imagen aún contiene herramientas auxiliares que serían relevantes si no lo está.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Lo que es interesante aquí:

- `NoNewPrivs: 1` suele ser el resultado más seguro.
- `NoNewPrivs: 0` significa que las rutas de escalada basadas en setuid y file-cap siguen siendo relevantes.
- Una imagen mínima con pocos o ningún binario setuid/file-cap ofrece al atacante menos opciones de post-explotación incluso cuando `no_new_privs` falta.

## Valores predeterminados en tiempo de ejecución

| Runtime / platform | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | No habilitado por defecto | Se habilita explícitamente con `--security-opt no-new-privileges=true` | omitir la bandera, `--privileged` |
| Podman | No habilitado por defecto | Se habilita explícitamente con `--security-opt no-new-privileges` o configuración de seguridad equivalente | omitir la opción, `--privileged` |
| Kubernetes | Controlado por la política de la carga de trabajo | `allowPrivilegeEscalation: false` habilita el efecto; muchas cargas de trabajo aún lo dejan habilitado | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Sigue la configuración de la carga de trabajo de Kubernetes | Usualmente heredado del contexto de seguridad del Pod | igual que la fila de Kubernetes |

Esta protección suele estar ausente simplemente porque nadie la activó, no porque el entorno de ejecución carezca de soporte para ella.
