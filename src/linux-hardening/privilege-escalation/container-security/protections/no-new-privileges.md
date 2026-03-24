# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` es una característica del kernel para hardening que evita que un proceso obtenga más privilegios a través de `execve()`. En términos prácticos, una vez que se establece la bandera, ejecutar un binario `setuid`, un binario `setgid` o un archivo con Linux file capabilities no concede privilegios adicionales más allá de los que el proceso ya tenía. En entornos containerizados, esto es importante porque muchas cadenas de privilege-escalation dependen de encontrar un ejecutable dentro de la imagen que cambie el privilegio al lanzarse.

Desde un punto de vista defensivo, `no_new_privs` no es un sustituto de namespaces, seccomp, o capability dropping. Es una capa de refuerzo. Bloquea una clase específica de escalada posterior después de que ya se ha obtenido ejecución de código. Eso lo hace particularmente valioso en entornos donde las imágenes contienen binarios auxiliares, artefactos del package manager o herramientas legacy que de otro modo serían peligrosas cuando se combinan con una compromisión parcial.

## Operation

La bandera del kernel detrás de este comportamiento es `PR_SET_NO_NEW_PRIVS`. Una vez que se establece para un proceso, llamadas posteriores a `execve()` no pueden aumentar los privilegios. El detalle importante es que el proceso todavía puede ejecutar binarios; simplemente no puede usar esos binarios para cruzar una frontera de privilegios que el kernel de otro modo honraría.

En entornos orientados a Kubernetes, `allowPrivilegeEscalation: false` mapea a este comportamiento para el proceso del contenedor. En runtimes estilo Docker y Podman, el equivalente normalmente se habilita explícitamente mediante una opción de seguridad.

## Lab

Inspecciona el estado actual del proceso:
```bash
grep NoNewPrivs /proc/self/status
```
Compáralo con un contenedor donde el runtime habilita la flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
En una carga de trabajo reforzada, el resultado debería mostrar `NoNewPrivs: 1`.

## Security Impact

Si `no_new_privs` está ausente, un foothold dentro del contenedor aún puede escalar privilegios mediante setuid helpers o binarios con file capabilities. Si está presente, esos cambios de privilegios post-exec quedan interrumpidos. El efecto es especialmente relevante en imágenes base amplias que incluyen muchas utilidades que la aplicación nunca necesitó en primer lugar.

## Misconfigurations

El problema más común es simplemente no habilitar el control en entornos donde sería compatible. En Kubernetes, dejar `allowPrivilegeEscalation` habilitado suele ser el error operacional por defecto. En Docker y Podman, omitir la opción de seguridad correspondiente tiene el mismo efecto. Otro modo de fallo recurrente es asumir que, porque un contenedor es "not privileged", las transiciones de privilegios en exec-time son automáticamente irrelevantes.

## Abuse

Si `no_new_privs` no está establecido, la primera pregunta es si la imagen contiene binarios que aún puedan elevar privilegios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesting results include:

- `NoNewPrivs: 0`
- ayudantes setuid como `su`, `mount`, `passwd`, u herramientas administrativas específicas de la distribución
- binarios con file capabilities que otorgan privilegios de red o del sistema de archivos

En una evaluación real, estos hallazgos por sí solos no prueban una escalada funcional, pero identifican exactamente los binarios que vale la pena probar a continuación.

### Ejemplo completo: In-Container Privilege Escalation Through setuid

Esta configuración normalmente evita **in-container privilege escalation** más que un escape al host directamente. Si `NoNewPrivs` es `0` y existe un ayudante setuid, pruébalo explícitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Si un binario setuid conocido está presente y funcional, intenta ejecutarlo de una manera que preserve la transición de privilegios:
```bash
/bin/su -c id 2>/dev/null
```
Esto por sí solo no escapa del contenedor, pero puede convertir un foothold de bajo privilegio dentro del contenedor en container-root, lo que a menudo se convierte en el requisito previo para un posterior escape al host a través de mounts, runtime sockets o kernel-facing interfaces.

## Checks

El objetivo de estas comprobaciones es determinar si exec-time privilege gain está bloqueado y si la image aún contiene helpers que serían relevantes si no lo está.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Lo interesante aquí:

- `NoNewPrivs: 1` suele ser el resultado más seguro.
- `NoNewPrivs: 0` significa que las rutas de escalada basadas en setuid y file-cap siguen siendo relevantes.
- Una imagen mínima con pocos o ningún binario setuid/file-cap le da a un atacante menos opciones de post-exploitation incluso cuando `no_new_privs` no está presente.

## Valores predeterminados en tiempo de ejecución

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | No habilitado por defecto | Habilitado explícitamente con `--security-opt no-new-privileges=true` | omitiendo la opción, `--privileged` |
| Podman | No habilitado por defecto | Habilitado explícitamente con `--security-opt no-new-privileges` o una configuración de seguridad equivalente | omitiendo la opción, `--privileged` |
| Kubernetes | Controlado por la política de la carga de trabajo | `allowPrivilegeEscalation: false` habilita el efecto; muchas cargas de trabajo todavía lo dejan habilitado | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Sigue la configuración de la carga de trabajo de Kubernetes | Normalmente heredado del contexto de seguridad del Pod | igual que en la fila de Kubernetes |

Esta protección a menudo está ausente simplemente porque nadie la activó, no porque el entorno de ejecución carezca de soporte para ella.
{{#include ../../../../banners/hacktricks-training.md}}
