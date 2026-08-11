# Abuso de Kernel Modules y modprobe

{{#include ../../banners/hacktricks-training.md}}

## Misconfiguraciones de Kernel Modules y carga de módulos

El soporte para Kernel Modules es un área de alto impacto durante una revisión de privilege escalation en Linux. No consideres explotable por sí mismo cada mensaje sobre módulos sin firma, sino que úsalo para responder preguntas prácticas.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- ¿Puede el usuario actual cargar módulos mediante `sudo`, capabilities o una ruta de helper con permisos de escritura?
- ¿La carga de módulos sigue habilitada?
- ¿Está deshabilitada la verificación de firmas de módulos?
- ¿Los directorios de módulos o los archivos de módulos tienen permisos de escritura?
- ¿Se pueden leer los logs del kernel para confirmar lo ocurrido?

El triage rápido comienza con las siguientes comprobaciones del estado de los módulos, las firmas, el logging y el árbol de módulos.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretación:

- `modules_disabled=1` significa que los módulos no se pueden cargar ni descargar, y el valor no se puede restablecer a `0` hasta reiniciar.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` en la línea de comandos del kernel o `CONFIG_MODULE_SIG_FORCE=y` requiere módulos firmados válidamente; de lo contrario, los módulos sin firma pueden cargarse y taint el kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` no impone ninguna restricción sobre `dmesg`; cuando es `1`, el acceso requiere `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Las rutas con permisos de escritura bajo `/lib/modules/$(uname -r)/` son peligrosas porque `modprobe` busca en ese árbol y en sus datos de dependencias al cargar módulos.<sup>[[8]](#references)</sup>

### Cargar un módulo y leer la salida del kernel

Si tienes permiso legítimo para cargar un módulo local, `insmod` inserta el archivo `.ko` exacto que proporciones. La función init del módulo se ejecuta como parte de la carga, y los mensajes escritos con `printk()` se envían al búfer de logs del kernel, que normalmente se lee con `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un flujo de revisión mínimo utiliza `modinfo` para inspeccionar los metadatos, `insmod` y `rmmod` para cargar y eliminar un módulo, `lsmod` para confirmar su estado de carga y `dmesg` para inspeccionar los logs del kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Si `sudo -l` permite ejecutar `insmod`, `modprobe` o un wrapper que los utilice, trátalo como crítico: `sudo -l` muestra los privilegios del usuario que lo invoca, y cargar un kernel module requiere `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` permitido mediante Sudo

Una regla de sudo que permite a un usuario ejecutar `insmod` no es comparable con permitir un helper administrativo normal. El código de inicialización del módulo se ejecuta como parte de la inserción, por lo que la pregunta práctica de la revisión es si este usuario puede elegir o modificar el módulo que se carga.<sup>[[3]](#references)</sup>

El siguiente flujo de revisión genérico repite esas comprobaciones de inspección, carga, estado, registros y eliminación para un módulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Si el usuario puede proporcionar un archivo `.ko` arbitrario, la regla debe tratarse como un compromiso total del sistema en una evaluación autorizada. Un patrón operativo más seguro consiste en evitar delegar la carga de módulos mediante sudo; si es inevitable, restrinja la ruta exacta, la propiedad, los permisos, la política de firma y el flujo de trabajo de eliminación.<sup>[[3]](#references)[[10]](#references)</sup>

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
Construye y carga únicamente en un laboratorio autorizado; kbuild compila el módulo externo y los comandos de carga/eliminación invocan las interfaces de módulos del kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Comprobaciones de abuso de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` indica el helper de espacio de usuario que ejecuta el kernel para las solicitudes de carga automática de módulos; este sysctl afecta a la carga automática, no a la inserción explícita de módulos. Si un atacante puede cambiarlo a una ruta de ejecutable escribible y activar una solicitud de módulo, ese helper se convierte en una ruta de ejecución de código privilegiada.<sup>[[1]](#references)</sup>

Comprueba la ruta actual del helper mediante la interfaz sysctl del kernel e inspecciona la propiedad y los permisos del objetivo.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Comprueba si se pueden influir los sysctl, las reglas sudo delegadas o las capacidades de archivo.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
El siguiente patrón, exclusivo para laboratorios, cambia la ruta del helper y activa una solicitud documentada de carga automática de módulos; úsalo únicamente en un sistema aislado y autorizado.<sup>[[1]](#references)</sup>

En los kernels actuales de Linux, no uses un ejecutable desconocido como activador genérico: la carga automática de módulos para formatos binarios personalizados heredados se eliminó en Linux 6.14, mientras que la documentación del kernel identifica un tipo de filesystem desconocido como una ruta de solicitud de carga automática de módulos.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
En sistemas reforzados, esto debería fallar cuando los permisos impidan las escrituras sin privilegios en `kernel.modprobe`, la ruta del helper no sea escribible o la carga automática de módulos esté deshabilitada.<sup>[[1]](#references)</sup>

### Revisión de `/lib/modules` escribible

Los directorios de módulos escribibles pueden permitir el reemplazo de módulos, la implantación de módulos maliciosos o el abuso de la carga automática, dependiendo de cómo se invoque posteriormente `modprobe`; `modprobe` busca en `/lib/modules/$(uname -r)` y utiliza sus datos de dependencias al resolver módulos.<sup>[[8]](#references)</sup>

Revisa los archivos de módulos escribibles y los metadatos de dependencias/alias bajo el árbol de módulos de la versión activa del kernel.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Si encuentras contenido de módulos escribible, inspecciona cómo `modprobe` resuelve las dependencias y cómo `modinfo` informa sobre los metadatos de los módulos.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notas defensivas:

- Mantén `/lib/modules` propiedad de `root:root` y no escribible por los usuarios.<sup>[[8]](#references)</sup>
- Establece `kernel.modules_disabled=1` después del arranque cuando sea operacionalmente posible.<sup>[[1]](#references)</sup>
- Aplica la firma de módulos en los sistemas que requieran módulos cargables.<sup>[[2]](#references)</sup>
- Monitoriza las escrituras en `/proc/sys/kernel/modprobe`, `/lib/modules` y la ejecución inesperada de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

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
{{#include ../../banners/hacktricks-training.md}}
