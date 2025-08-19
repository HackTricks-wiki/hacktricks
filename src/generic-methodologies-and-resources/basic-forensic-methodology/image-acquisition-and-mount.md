# Απόκτηση Εικόνας & Τοποθέτηση

{{#include ../../banners/hacktricks-training.md}}


## Απόκτηση

> Πάντα να αποκτάτε **μόνο για ανάγνωση** και **να υπολογίζετε το hash ενώ αντιγράφετε**. Διατηρήστε τη συσκευή πρωτοτύπου **κλειδωμένη για εγγραφή** και εργάζεστε μόνο σε επαληθευμένα αντίγραφα.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` είναι το ενεργά συντηρούμενο παρακλάδι του dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Γραφικό, πολυνηματικό εργαλείο εικόνας που υποστηρίζει **raw (dd)**, **EWF (E01/EWFX)** και **AFF4** εξόδους με παράλληλη επαλήθευση. Διαθέσιμο σε πολλές αποθήκες Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 είναι η σύγχρονη μορφή εικόνας της Google που έχει σχεδιαστεί για *πολύ* μεγάλα αποδεικτικά στοιχεία (σπάνια, επαναλαμβανόμενα, cloud-native).
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Μπορείτε να [κατεβάσετε το FTK Imager](https://accessdata.com/product-download) και να δημιουργήσετε **raw, E01 ή AFF4** εικόνες:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF εργαλεία (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – δημιουργήστε ένα **forensic snapshot** χωρίς να κλείσετε την παρουσίαση:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – use `az snapshot create` and export to a SAS URL.


## Mount

### Επιλογή της σωστής προσέγγισης

1. Mount the **whole disk** when you want the original partition table (MBR/GPT).
2. Mount a **single partition file** when you only need one volume.
3. Always mount **read-only** (`-o ro,norecovery`) and work on **copies**.

### Raw images (dd, AFF4-extracted)
```bash
# Identify partitions
fdisk -l disk.img

# Attach the image to a network block device (does not modify the file)
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only disk.img

# Inspect partitions
lsblk /dev/nbd0 -o NAME,SIZE,TYPE,FSTYPE,LABEL,UUID

# Mount a partition (e.g. /dev/nbd0p2)
sudo mount -o ro,uid=$(id -u) /dev/nbd0p2 /mnt
```
Αποσυνδέστε όταν τελειώσετε:
```bash
sudo umount /mnt && sudo qemu-nbd --disconnect /dev/nbd0
```
### EWF (E01/EWFX)
```bash
# 1. Mount the EWF container
mkdir /mnt/ewf
ewfmount evidence.E01 /mnt/ewf

# 2. Attach the exposed raw file via qemu-nbd (safer than loop)
sudo qemu-nbd --connect=/dev/nbd1 --read-only /mnt/ewf/ewf1

# 3. Mount the desired partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
Εναλλακτικά, μετατρέψτε δυναμικά με **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

Μετά την προσάρτηση της συσκευής μπλοκ (loop ή nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` χαρτογραφεί τις κατατμήσεις από μια εικόνα στο `/dev/mapper/` αυτόματα:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Κοινά σφάλματα προσάρτησης & διορθώσεις

| Σφάλμα | Τυπική Αιτία | Διόρθωση |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Το Journaled FS (ext4) δεν έχει αποσυνδεθεί καθαρά | χρησιμοποιήστε `-o ro,norecovery` |
| `bad superblock …` | Λάθος offset ή κατεστραμμένο FS | υπολογίστε το offset (`sector*size`) ή εκτελέστε `fsck -n` σε ένα αντίγραφο |
| `mount: unknown filesystem type 'LVM2_member'` | Δοχείο LVM | ενεργοποιήστε την ομάδα όγκων με `vgchange -ay` |

### Καθαρισμός

Θυμηθείτε να **umount** και **αποσυνδέσετε** τις συσκευές loop/nbd για να αποφύγετε την αφήγηση χαλαρών χαρτογραφήσεων που μπορεί να διαφθείρουν περαιτέρω εργασία:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Αναφορές

- AFF4 imaging tool announcement & specification: https://github.com/aff4/aff4
- qemu-nbd manual page (mounting disk images safely): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
