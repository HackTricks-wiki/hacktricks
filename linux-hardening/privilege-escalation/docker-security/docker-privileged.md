## Docker --privileged

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Qué afecta

Cuando ejecutas un contenedor como privilegiado, estas deshabilitando las siguientes protecciones:

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

{% tab title="Dentro del contenedor privilegiado" %}
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

Los sistemas de archivos de kernel proporcionan un mecanismo para que un proceso altere la forma en que se ejecuta el kernel. Por defecto, no queremos que los procesos del contenedor modifiquen el kernel, por lo que montamos los sistemas de archivos de kernel como de solo lectura dentro del contenedor.

{% tabs %}
{% tab title="Dentro del contenedor por defecto" %}
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
{% endtab %}
{% tab title="Enmascaramiento de sistemas de archivos del kernel" %}

El sistema de archivos **/proc** es consciente del espacio de nombres y se pueden permitir ciertas escrituras, por lo que no lo montamos en solo lectura. Sin embargo, se deben **proteger de la escritura** directorios específicos en el sistema de archivos /proc y, en algunos casos, **de la lectura**. En estos casos, los motores de contenedores montan sistemas de archivos **tmpfs** sobre directorios potencialmente peligrosos, evitando que los procesos dentro del contenedor los utilicen.

{% hint style="info" %}
**tmpfs** es un sistema de archivos que almacena todos los archivos en memoria virtual. tmpfs no crea ningún archivo en su disco duro. Por lo tanto, si desmonta un sistema de archivos tmpfs, todos los archivos que residen en él se pierden para siempre.
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

{% tab title="Dentro del contenedor privilegiado" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% tab title="Dentro del contenedor por defecto" %}

Los motores de contenedores lanzan los contenedores con un **número limitado de capacidades** para controlar lo que sucede dentro del contenedor de forma predeterminada. Los privilegiados tienen **todas** las **capacidades** accesibles. Para aprender sobre las capacidades, lee:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% endtab %}
{% endtabs %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Dentro del contenedor privilegiado" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% tab title="Manipulación de capacidades" %}
Puedes manipular las capacidades disponibles para un contenedor sin ejecutarlo en modo `--privileged` usando las banderas `--cap-add` y `--cap-drop`.

### Seccomp

**Seccomp** es útil para **limitar** las **syscalls** que un contenedor puede llamar. Un perfil de seccomp predeterminado está habilitado por defecto al ejecutar contenedores de Docker, pero en modo privilegiado está deshabilitado. Aprende más sobre Seccomp aquí:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}
{% endtab %}
{% endtabs %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Dentro del contenedor privilegiado" %}
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
También, tenga en cuenta que cuando Docker (u otros CRIs) se utilizan en un clúster de **Kubernetes**, el filtro **seccomp** está desactivado por defecto.

### AppArmor

**AppArmor** es una mejora del kernel para confinar los **contenedores** a un **conjunto limitado de recursos** con **perfiles por programa**. Cuando se ejecuta con la bandera `--privileged`, esta protección se desactiva.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Cuando se ejecuta con la bandera `--privileged`, **las etiquetas SELinux se desactivan**, y el contenedor se ejecuta con la **etiqueta con la que se ejecutó el motor del contenedor**. Esta etiqueta suele ser `unconfined` y tiene **acceso completo a las etiquetas que tiene el motor del contenedor**. En el modo sin raíz, el contenedor se ejecuta con `container_runtime_t`. En el modo raíz, se ejecuta con `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Lo que no afecta

### Espacios de nombres

Los espacios de nombres **NO se ven afectados** por la bandera `--privileged`. Aunque no tienen las restricciones de seguridad habilitadas, **no ven todos los procesos en el sistema o la red del host, por ejemplo**. Los usuarios pueden deshabilitar espacios de nombres individuales usando las banderas del motor de contenedores **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

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
### Namespace de usuario

Los motores de contenedores **NO usan el namespace de usuario por defecto**. Sin embargo, los contenedores sin root siempre lo usan para montar sistemas de archivos y usar más de un UID. En el caso sin root, el namespace de usuario no se puede desactivar; es necesario para ejecutar contenedores sin root. Los namespaces de usuario previenen ciertos privilegios y añaden una considerable seguridad.

## Referencias

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
