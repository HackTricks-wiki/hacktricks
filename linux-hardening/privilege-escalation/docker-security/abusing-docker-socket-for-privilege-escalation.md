# Abusando del Socket de Docker para Escalada de Privilegios

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Hay ocasiones en las que solo tienes **acceso al socket de docker** y quieres usarlo para **escalar privilegios**. Algunas acciones pueden ser muy sospechosas y es posible que quieras evitarlas, así que aquí puedes encontrar diferentes flags que pueden ser útiles para escalar privilegios:

### Vía montaje

Puedes **montar** diferentes partes del **sistema de archivos** en un contenedor que se ejecuta como root y **acceder** a ellos.\
También podrías **abusar de un montaje para escalar privilegios** dentro del contenedor.

* **`-v /:/host`** -> Monta el sistema de archivos del host en el contenedor para que puedas **leer el sistema de archivos del host.**
* Si quieres **sentirte como si estuvieras en el host** pero estando en el contenedor, podrías desactivar otros mecanismos de defensa usando flags como:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Esto es similar al método anterior, pero aquí estamos **montando el disco del dispositivo**. Luego, dentro del contenedor ejecuta `mount /dev/sda1 /mnt` y puedes **acceder** al **sistema de archivos del host** en `/mnt`
* Ejecuta `fdisk -l` en el host para encontrar el dispositivo `</dev/sda1>` a montar
* **`-v /tmp:/host`** -> Si por alguna razón solo puedes **montar algún directorio** del host y tienes acceso dentro del host. Monta y crea un **`/bin/bash`** con **suid** en el directorio montado para que puedas **ejecutarlo desde el host y escalar a root**.

{% hint style="info" %}
Ten en cuenta que quizás no puedas montar la carpeta `/tmp` pero puedes montar un **directorio escribible diferente**. Puedes encontrar directorios escribibles usando: `find / -writable -type d 2>/dev/null`

**¡Ten en cuenta que no todos los directorios en una máquina linux admitirán el bit suid!** Para comprobar qué directorios admiten el bit suid ejecuta `mount | grep -v "nosuid"` Por ejemplo, usualmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no admiten el bit suid.

Ten en cuenta también que si puedes **montar `/etc`** o cualquier otro directorio **que contenga archivos de configuración**, puedes cambiarlos desde el contenedor docker como root para **abusar de ellos en el host** y escalar privilegios (quizás modificando `/etc/shadow`)
{% endhint %}

### Escapando del contenedor

* **`--privileged`** -> Con esta flag [eliminas toda la aislación del contenedor](docker-privileged.md#what-affects). Revisa técnicas para [escapar de contenedores privilegiados como root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Para [escalar abusando de capacidades](../linux-capabilities.md), **otorga esa capacidad al contenedor** y desactiva otros métodos de protección que puedan prevenir que el exploit funcione.

### Curl

En esta página hemos discutido formas de escalar privilegios usando flags de docker, puedes encontrar **formas de abusar de estos métodos usando el comando curl** en la página:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
