# Απόκτηση και προσάρτηση εικόνας

{{#include ../../banners/hacktricks-training.md}}

## Απόκτηση

> Να πραγματοποιείτε πάντα την απόκτηση σε **read-only** λειτουργία και να υπολογίζετε το **hash κατά την αντιγραφή**. Διατηρείτε την αρχική συσκευή **write-blocked** και εργάζεστε μόνο με επαληθευμένα αντίγραφα.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

Το `dc3dd` είναι το ενεργά συντηρούμενο fork του dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Γραφικό εργαλείο δημιουργίας image με υποστήριξη πολλαπλών threads, που υποστηρίζει έξοδο **raw (dd)**, **EWF (E01/EWFX)** και **AFF4**, με παράλληλη επαλήθευση. Διαθέσιμο στα περισσότερα Linux repos (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Η προδιαγραφή AFF4 v1.0, που συντάχθηκε από τους Bradley L. Schatz και Michael I. Cohen, ορίζει ένα forensic container με virtualization storage, arbitrary metadata, extensible compression και hashing, καθώς και λειτουργία υψηλής απόδοσης.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Μπορείτε να [κατεβάσετε το FTK Imager](https://accessdata.com/product-download) και να δημιουργήσετε **raw, E01 ή AFF4** images:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Εργαλεία EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Λήψη Εικόνων από Cloud Disks

*AWS* – δημιουργήστε ένα **forensic snapshot** χωρίς να τερματίσετε το instance:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – χρησιμοποιήστε `az snapshot create` και κάντε export σε ένα SAS URL.


## Προσάρτηση

### Επιλογή της σωστής προσέγγισης

1. Προσαρτήστε **ολόκληρο τον δίσκο** όταν θέλετε τον αρχικό πίνακα κατατμήσεων (MBR/GPT).
2. Προσαρτήστε ένα **αρχείο μεμονωμένης κατάτμησης** όταν χρειάζεστε μόνο έναν τόμο.
3. Διατηρήστε τα image attachments μόνο για ανάγνωση (για παράδειγμα, το `--read-only` του qemu-nbd).<sup>[[2]](#references)</sup> Προσαρτήστε τα filesystems μόνο για ανάγνωση (`-o ro`).<sup>[[3]](#references)</sup> Εργαστείτε σε **αντίγραφα**.

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
Δεν παρασχέθηκε κείμενο για μετάφραση.
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

# 3. Mount the desired partition (XFS example; use the filesystem-specific option)
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
Για mounts χωρίς επανάληψη που είναι ειδικά για το filesystem, τα ext3/ext4 χρησιμοποιούν `noload`, ενώ το XFS χρησιμοποιεί `norecovery` και απαιτεί λειτουργία μόνο για ανάγνωση.<sup>[[3]](#references)[[4]](#references)</sup>

Εναλλακτικά, μετατρέψτε τα on the fly με το **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

Μετά τη σύνδεση της block device (loop ή nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### Βοηθητικά εργαλεία kpartx

Το `kpartx` αντιστοιχίζει αυτόματα τα partitions από ένα image στο `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Συνήθη σφάλματα προσάρτησης & διορθώσεις

Για ένα dirty ext3/ext4 filesystem, χρησιμοποιήστε `ro,noload` όταν πρέπει να αποτραπεί η αναπαραγωγή του journal.<sup>[[3]](#references)</sup>

| Σφάλμα | Συνήθης αιτία | Διόρθωση |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) που δεν αποπροσαρτήθηκε καθαρά | χρησιμοποιήστε `-o ro,noload` |
| `bad superblock …` | Λανθασμένο offset ή κατεστραμμένο FS | υπολογίστε το offset (`sector*size`) ή εκτελέστε `fsck -n` σε αντίγραφο |
| `mount: unknown filesystem type 'LVM2_member'` | Container LVM | ενεργοποιήστε το volume group με `vgchange -ay` |

### Εκκαθάριση

Θυμηθείτε να κάνετε **umount** και **disconnect** στις συσκευές loop/nbd, ώστε να μην αφήσετε dangling mappings που μπορούν να καταστρέψουν περαιτέρω την εργασία:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Προδιαγραφή προτύπου AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Τεκμηρίωση του QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Σελίδα εγχειριδίου Linux για το mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Το σύστημα αρχείων SGI XFS (τεκμηρίωση πυρήνα Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
