# Απόκτηση εικόνας & προσάρτηση

{{#include ../../banners/hacktricks-training.md}}

## Απόκτηση

> Να αποκτάς πάντα δεδομένα **μόνο για ανάγνωση** και να υπολογίζεις **hash** κατά την αντιγραφή. Διατήρησε την αρχική συσκευή **προστατευμένη από εγγραφή** και εργάσου μόνο με επαληθευμένα αντίγραφα.

Κατέγραψε τον κατασκευαστή, το μοντέλο, τον σειριακό αριθμό και το μέγεθος της πηγής, το εργαλείο και την έκδοσή του, τις χρονικές σημάνσεις, τον χειριστή, τον προορισμό, τα σφάλματα και τα hash απόκτησης/επαλήθευσης. Διατήρησε ένα αρχειακό image και εξέτασε ένα ξεχωριστό αντίγραφο εργασίας.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

Το `dc3dd` προσθέτει κατακερματισμό κατά τη λειτουργία, επαλήθευση εξόδου, καταγραφή σφαλμάτων και διαχωρισμό εξόδου στη ροή εργασίας του `dd`. Το `hof=` επιλέγει μια έξοδο επαληθευμένη με hash· τα `hash=`, `hlog=`, `log=` και `bufsz=` είναι ξεχωριστά ορίσματα.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Το Guymager είναι ένα γραφικό, πολυνηματικό εργαλείο απεικόνισης δίσκων για Linux, με υποστήριξη εξόδου raw/dd, EWF και παλαιού τύπου AFF. **Τα AFF και AFF4 είναι διαφορετικές μορφές**· το Guymager δεν διαφημίζει υποστήριξη εξόδου AFF4. Ενεργοποιήστε το SHA-256 και την επαλήθευση προορισμού στο παράθυρο διαλόγου απόκτησης και, στη συνέχεια, εκκινήστε το με `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Η προδιαγραφή AFF4 v1.0 ορίζει ένα εγκληματολογικό container με εικονικοποιημένη αποθήκευση, αυθαίρετα metadata, επεκτάσιμη συμπίεση και κατακερματισμό, καθώς και λειτουργία υψηλής απόδοσης.<sup>[[1]](#references)</sup>

Η κανονική υλοποίηση C/C++ χρησιμοποιεί το `-i` για την πηγή και το `-o` για τον τόμο AFF4. Δημιουργήστε και διατηρήστε ένα εξωτερικό hash του container ως βάση αναφοράς για την απόκτηση.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Η τρέχουσα τεκμηρίωση του FTK Imager αναφέρει έξοδο raw/DD, E01 και AFF με επαλήθευση hash. Μην χαρακτηρίζετε την έξοδο AFF ως AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Εργαλεία EWF (libewf)

Για μη επιβλεπόμενη απόκτηση, ο στόχος ορίζεται με `-t`, τα μεταδεδομένα της υπόθεσης με `-C/-D/-E/-e`, το `-d sha256` προσθέτει SHA-256 και το `-l` καταγράφει σφάλματα απόκτησης και digest. Επαληθεύστε το ολοκληρωμένο σύνολο τμημάτων πριν από την ανάλυση.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Απεικόνιση cloud δίσκων

Ένα snapshot παρόχου είναι μια συλλογή δεδομένων σε συγκεκριμένη χρονική στιγμή και δεν αποτελεί αυτομάτως forensic image με συνέπεια εφαρμογής. Ένα snapshot EBS δεν περιλαμβάνει δεδομένα που παραμένουν αποθηκευμένα στην cache του guest· διακόψτε τις εγγραφές, θέστε την εφαρμογή σε quiescent κατάσταση, κάντε unmount τον τόμο δεδομένων ή σταματήστε ένα instance του οποίου καταγράφεται ο root τόμος, εφόσον το επιτρέπει το σχέδιο απόκρισης.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Μην περιγράφετε τα EBS snapshots ως αρχεία που μπορούν απλώς να αντιγραφούν στο S3. Για να ανακατασκευάσετε την εικόνα block χωρίς να δημιουργήσετε volume, απαριθμήστε τα εκχωρημένα blocks με το `ListSnapshotBlocks`, ανακτήστε κάθε block των 512 KiB με το `GetSnapshotBlock`, επαληθεύστε το checksum που επιστρέφεται και συμπληρώστε με μηδενικά τα indexes των blocks που απουσιάζουν από το sparse snapshot.<sup>[[14]](#references)</sup>

Για το Azure, δημιουργήστε το snapshot, εκδώστε ένα βραχύβιο SAS **μόνο για ανάγνωση**, κατεβάστε το VHD, ανακαλέστε την πρόσβαση και υπολογίστε το hash του αποτελέσματος. Δημιουργήστε snapshot για κάθε δίσκο ξεχωριστά, εκτός αν ο μηχανισμός συλλογής διασφαλίζει συντονισμένη συνέπεια.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Προσάρτηση

### Αντιμετωπίζετε τα images ως μη έμπιστη είσοδο

Ένα κακόβουλο filesystem μπορεί να στοχεύσει τους parsers διαμερισμάτων και filesystem του host kernel. Το QEMU προειδοποιεί ρητά να μη συνδέετε μη έμπιστο guest image στο host NBD για προσάρτηση, ενώ το libguestfs συνιστά να μην προσαρτάτε ποτέ απευθείας ένα μη έμπιστο guest filesystem με `loop` ή `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

Για ένα άγνωστο ή ελεγχόμενο από επιτιθέμενο image, προτιμήστε το `guestmount`. Αναλύει και προσαρτά το guest μέσα σε ένα μικρό appliance και στη συνέχεια εκθέτει τα αρχεία μέσω FUSE. Καθορίστε ρητά τη γνωστή μορφή αντί να βασιστείτε στην αυτόματη ανίχνευση και διατηρήστε το appliance σε λειτουργία μόνο για ανάγνωση.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Αν η επιθεώρηση δεν μπορεί να προσδιορίσει το OS, αντικαταστήστε το `-i` με μια ρητά καθορισμένη συσκευή guest, όπως `-m /dev/sda2`. Μπορείτε να δώσετε κρυπτογραφημένους τόμους LUKS με selectors `--key`· αποφύγετε να βάλετε κλειδί απευθείας στο ιστορικό του shell.<sup>[[17]](#references)</sup>

### Επιλογή απευθείας προσάρτησης στον host

Χρησιμοποιήστε απευθείας προσάρτηση στον host μόνο για έμπιστες εικόνες ή σε VM ανάλυσης που προορίζεται για απόρριψη:

1. Προσαρτήστε **ολόκληρο τον δίσκο** όταν χρειάζεστε τον αρχικό πίνακα κατατμήσεων.
2. Προσαρτήστε **εικόνα μίας κατάτμησης** όταν χρειάζεστε μόνο έναν τόμο.
3. Ορίστε τη σύνδεση ως μόνο για ανάγνωση και καθορίστε ρητά τη μορφή της εικόνας. Προσαρτήστε και το filesystem ως μόνο για ανάγνωση. Το `ro` από μόνο του δεν αποτρέπει την επανάληψη του journal σε ext3/ext4, γι' αυτό χρησιμοποιήστε `ro,noload` για μη καθαρά ext filesystems.<sup>[[2]](#references)[[3]](#references)</sup>

Το `mmls` είναι χρήσιμο όταν το μέγεθος τομέα δεν είναι 512 bytes ή όταν τα μεταδεδομένα των κατατμήσεων έχουν υποστεί ζημιά· το `-b` ορίζει το πραγματικό μέγεθος τομέα της συσκευής. Συνεχίστε την ανάλυση κατατμήσεων και filesystems εδώ:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Ακατέργαστες εικόνες (dd, εξαγωγή από AFF4)

```bash
# Identify partitions without attaching the image
mmls -b 512 disk.img

# Attach a known raw image read-only and force its format
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only --format=raw disk.img
lsblk /dev/nbd0 -o NAME,SIZE,RO,TYPE,FSTYPE,LABEL,UUID

# Example ext4 partition: prevent journal replay
sudo mount -o ro,noload /dev/nbd0p2 /mnt/evidence
```

Αποπροσαρτήστε όταν τελειώσετε:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Για qcow2, VMDK ή VHD/VHDX, εξακριβώστε τη μορφή από αξιόπιστη προέλευση ή επιθεωρήστε το αρχείο μέσα στην προσωρινή VM ανάλυσης και, στη συνέχεια, αντικαταστήστε το `--format=raw` με την καθορισμένη μορφή. Μην βασίζεστε ποτέ στην αυτόματη ανίχνευση μορφής από το host για μη έμπιστη είσοδο.<sup>[[2]](#references)</sup>

### EWF (E01/EWFX)

```bash
# Verify, then expose the embedded raw media stream
mkdir -p /mnt/ewf /mnt/evidence
ewfverify evidence.E01
ewfmount evidence.E01 /mnt/ewf

# ewf1 is raw media data; attach it explicitly as raw and read-only
sudo qemu-nbd --connect=/dev/nbd1 --read-only --format=raw /mnt/ewf/ewf1
# Example XFS partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```

Για mounts χωρίς replay ειδικά για κάθε filesystem, τα ext3/ext4 χρησιμοποιούν `noload`, ενώ το XFS χρησιμοποιεί `norecovery` και απαιτεί λειτουργία μόνο για ανάγνωση.<sup>[[3]](#references)[[4]](#references)</sup>

Το `xmount` μπορεί να εκθέσει μια εικονική raw προβολή, αλλά αυτή εξακολουθεί να περιέχει τον αρχικό πίνακα κατατμήσεων. Τροφοδοτήστε την στην ίδια ροή εργασίας με `mmls`, απομονωμένο `guestmount` ή NBD μόνο για ανάγνωση, αντί να προσαρτήσετε το αρχείο ολόκληρου δίσκου ως filesystem.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Τόμοι BitLocker

Χρησιμοποιήστε λειτουργία μόνο για ανάγνωση και στα δύο επίπεδα. Η επιλογή `-u` χωρίς τιμή ζητά τον κωδικό πρόσβασης, αποφεύγοντας έτσι την καταχώρισή του στα ορίσματα διεργασιών ή στο ιστορικό του shell.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Για LUKS ή LVM, προτίμησε το `guestmount -i --ro`· το appliance του μπορεί να επιθεωρήσει συνήθεις διατάξεις με κρυπτογράφηση και logical volumes, χωρίς να ενεργοποιήσει foreign volume group στον host.<sup>[[17]](#references)</sup>

### Βοηθητικά εργαλεία kpartx

Το `kpartx` δημιουργεί κόμβους device-mapper στον host και, επομένως, δεν είναι κατάλληλο για μη έμπιστες εικόνες δίσκων. Όταν δικαιολογείται η άμεση αντιστοίχιση, πρόσθεσε το `-r` ώστε οι αντιστοιχίσεις των partitions να είναι μόνο για ανάγνωση και αφαίρεσε τις αντιστοιχίσεις περνώντας την ίδια διαδρομή εικόνας που χρησιμοποιήθηκε για τη δημιουργία τους.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Συνηθισμένα σφάλματα προσάρτησης και διορθώσεις

| Σφάλμα | Συνήθης αιτία | Ασφαλές επόμενο βήμα |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Μη καθαρό journaled filesystem | χρησιμοποιήστε την ειδική για το filesystem επιλογή no-replay, όπως `ro,noload` για ext4 |
| `bad superblock ...` | Λανθασμένο partition/offset τομέα ή κατεστραμμένο filesystem | επιβεβαιώστε το μέγεθος τομέα και το offset με `mmls`· εκτελέστε `fsck -n` μόνο σε επαληθευμένο αντίγραφο |
| `unknown filesystem type 'LVM2_member'` | Το επιλεγμένο partition είναι φυσικός τόμος LVM | αφήστε το libguestfs να το επιθεωρήσει ή περιορίστε τη χειροκίνητη ενεργοποίηση LVM σε μια προσωρινή VM |

### Εκκαθάριση

Αποπροσαρτήστε τα filesystems πριν αποσυνδέσετε τις συσκευές υποστήριξής τους. Αφαιρέστε επίσης το επίπεδο FUSE για EWF/xmount και τυχόν αντιστοιχίσεις crypt ή device-mapper που δημιουργήθηκαν:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Προδιαγραφή προτύπου AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Τεκμηρίωση QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Σελίδα εγχειριδίου Linux για το mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Το σύστημα αρχείων SGI XFS (τεκμηρίωση πυρήνα Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Βέλτιστες πρακτικές SWGDE για τη συλλογή ψηφιακών αποδεικτικών στοιχείων](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Βέλτιστες πρακτικές SWGDE για την απόκτηση δεδομένων από υπολογιστές στο πλαίσιο ψηφιακής εγκληματολογίας](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Σελίδα εγχειριδίου dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Αρχική σελίδα του Guymager και τεκμηρίωση διαμόρφωσης](https://guymager.sourceforge.io/)
- [9] [Τεκμηρίωση c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Μορφές και επαλήθευση του Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Εγχειρίδιο libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Εγχειρίδιο libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Δημιουργία Amazon EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Ανάγνωση Amazon EBS snapshots με τα EBS direct APIs](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Αναφορά snapshot του Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Ασφάλεια του libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
