# Abusando del Socket de Docker para Escalada de Privilegios

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

En algunas ocasiones, solo tienes **acceso al socket de Docker** y quieres usarlo para **escalar privilegios**. Algunas acciones pueden ser muy sospechosas y es posible que desees evitarlas, por lo que aquí puedes encontrar diferentes banderas que pueden ser útiles para escalar privilegios:

### A través de montaje

Puedes **montar** diferentes partes del **sistema de archivos** en un contenedor que se ejecuta como root y **acceder** a ellas.\
También puedes **abusar de un montaje para escalar privilegios** dentro del contenedor.

* **`-v /:/host`** -> Monta el sistema de archivos del host en el contenedor para que puedas **leer el sistema de archivos del host.**
  * Si quieres **sentirte como si estuvieras en el host** pero estando en el contenedor, puedes deshabilitar otros mecanismos de defensa usando banderas como:
    * `--privileged`
    * `--cap-add=ALL`
    * `--security-opt apparmor=unconfined`
    * `--security-opt seccomp=unconfined`
    * `-security-opt label:disable`
    * `--pid=host`
    * `--userns=host`
    * `--uts=host`
    * `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Esto es similar al método anterior, pero aquí estamos **montando el disco del dispositivo**. Luego, dentro del contenedor, ejecuta `mount /dev/sda1 /mnt` y puedes **acceder** al **sistema de archivos del host** en `/mnt`
  * Ejecuta `fdisk -l` en el host para encontrar el dispositivo `</dev/sda1>` para montar
* **`-v /tmp:/host`** -> Si por alguna razón solo puedes **montar algún directorio** del host y tienes acceso dentro del host. Monta y crea un **`/bin/bash`** con **suid** en el directorio montado para que puedas **ejecutarlo desde el host y escalar a root**.

{% hint style="info" %}
Ten en cuenta que tal vez no puedas montar la carpeta `/tmp` pero puedes montar una **carpeta diferente que sea escribible**. Puedes encontrar directorios escribibles usando: `find / -writable -type d 2>/dev/null`

**Ten en cuenta que no todos los directorios en una máquina Linux admitirán el bit suid!** Para verificar qué directorios admiten el bit suid, ejecuta `mount | grep -v "nosuid"`. Por ejemplo, por lo general, `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no admiten el bit suid.

También ten en cuenta que si puedes **montar `/etc`** o cualquier otra carpeta **que contenga archivos de configuración**, puedes cambiarlos desde el contenedor de Docker como root para **abusar de ellos en el host** y escalar privilegios (tal vez modificando `/etc/shadow`).
{% endhint %}

### Escapando del contenedor

* **`--privileged`** -> Con esta bandera, [eliminas todo el aislamiento del contenedor](docker-privileged.md#what-affects). Consulta técnicas para [escapar de contenedores privilegiados como root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Para [escalar abusando de las capacidades](../linux-capabilities.md), **concede esa capacidad al contenedor** y deshabilita otros métodos de protección que puedan evitar que funcione el exploit.

### Curl

En esta página hemos discutido formas de escalar privilegios usando banderas de Docker, puedes encontrar **formas de abusar de estos métodos usando el comando curl** en la página:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
