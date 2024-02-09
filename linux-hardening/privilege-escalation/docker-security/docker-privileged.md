# Docker --privileged

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks AWS)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Qué afecta

Cuando ejecutas un contenedor como privilegiado, deshabilitas las siguientes protecciones:

### Montar /dev

En un contenedor privilegiado, todos los **dispositivos pueden ser accedidos en `/dev/`**. Por lo tanto, puedes **escapar** montando el disco del host.

{% tabs %}
{% tab title="Dentro del contenedor predeterminado" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Dentro del Contenedor con Privilegios" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
### Sistemas de archivos de kernel de solo lectura

Los sistemas de archivos de kernel proporcionan un mecanismo para que un proceso modifique el comportamiento del kernel. Sin embargo, cuando se trata de procesos de contenedores, queremos evitar que realicen cambios en el kernel. Por lo tanto, montamos los sistemas de archivos de kernel como **solo lectura** dentro del contenedor, asegurando que los procesos del contenedor no puedan modificar el kernel.
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Dentro del contenedor privilegiado" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
### Enmascaramiento de sistemas de archivos del kernel

El sistema de archivos **/proc** es selectivamente escribible pero, por motivos de seguridad, ciertas partes están protegidas del acceso de escritura y lectura al superponerlas con **tmpfs**, asegurando que los procesos del contenedor no puedan acceder a áreas sensibles.

{% hint style="info" %}
**tmpfs** es un sistema de archivos que almacena todos los archivos en la memoria virtual. tmpfs no crea archivos en tu disco duro. Por lo tanto, si desmontas un sistema de archivos tmpfs, todos los archivos que residen en él se pierden para siempre.
{% endhint %}

{% tabs %}
{% tab title="Dentro del contenedor predeterminado" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Dentro del Contenedor con Privilegios" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
### Capacidades de Linux

Los motores de contenedores lanzan los contenedores con un **número limitado de capacidades** para controlar lo que sucede dentro del contenedor de forma predeterminada. Los contenedores **privilegiados** tienen **todas** las **capacidades** accesibles. Para aprender sobre las capacidades, lee:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Dentro del contenedor predeterminado" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Dentro del Contenedor con Privilegios" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

Puedes manipular las capacidades disponibles para un contenedor sin ejecutarlo en modo `--privileged` usando las banderas `--cap-add` y `--cap-drop`.

### Seccomp

**Seccomp** es útil para **limitar** las **llamadas al sistema (syscalls)** que un contenedor puede realizar. Un perfil de Seccomp predeterminado está habilitado de forma predeterminada al ejecutar contenedores de Docker, pero en modo privilegiado está deshabilitado. Obtén más información sobre Seccomp aquí:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Dentro del Contenedor con Privilegios" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
También, ten en cuenta que cuando Docker (u otros CRIs) se utilizan en un clúster de **Kubernetes**, el **filtro seccomp está deshabilitado de forma predeterminada**

### AppArmor

**AppArmor** es una mejora del kernel para confinar los **contenedores** a un **conjunto limitado** de **recursos** con **perfiles por programa**. Cuando se ejecuta con la bandera `--privileged`, esta protección se deshabilita.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Ejecutar un contenedor con la bandera `--privileged` deshabilita las **etiquetas SELinux**, lo que hace que herede la etiqueta del motor de contenedores, típicamente `unconfined`, otorgando acceso completo similar al del motor de contenedores. En modo sin raíz, se utiliza `container_runtime_t`, mientras que en modo raíz, se aplica `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Lo que no afecta

### Espacios de nombres

Los espacios de nombres **NO se ven afectados** por la bandera `--privileged`. Aunque no tengan habilitadas las restricciones de seguridad, **no ven todos los procesos en el sistema o la red del host, por ejemplo**. Los usuarios pueden deshabilitar espacios de nombres individuales utilizando las banderas de motores de contenedores **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Dentro del contenedor privilegiado predeterminado" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Dentro del contenedor --pid=host" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### Espacio de nombres de usuario

**De forma predeterminada, los motores de contenedores no utilizan espacios de nombres de usuario, excepto para contenedores sin raíz**, que los requieren para el montaje del sistema de archivos y el uso de múltiples UID. Los espacios de nombres de usuario, esenciales para los contenedores sin raíz, no se pueden desactivar y mejoran significativamente la seguridad al restringir los privilegios.

## Referencias

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
