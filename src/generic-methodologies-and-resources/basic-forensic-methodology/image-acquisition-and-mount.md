# इमेज अधिग्रहण और माउंट

{{#include ../../banners/hacktricks-training.md}}


## अधिग्रहण

> हमेशा **read-only** तरीके से अधिग्रहण करें और **hash while you copy** करें। मूल डिवाइस को **write-blocked** रखें और केवल सत्यापित कॉपियों पर काम करें।

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`, dcfldd (DoD Computer Forensics Lab dd) का सक्रिय रूप से maintained fork है।
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Graphical, multithreaded imager जो **raw (dd)**, **EWF (E01/EWFX)** और **AFF4** output को parallel verification के साथ support करता है। अधिकांश Linux repos में उपलब्ध है (`apt install guymager`)।
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 Google का आधुनिक इमेजिंग फ़ॉर्मेट है, जिसे *बहुत बड़े* साक्ष्यों (sparse, resumable, cloud-native) के लिए डिज़ाइन किया गया है।<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows और Linux)

आप [FTK Imager डाउनलोड](https://accessdata.com/product-download) कर सकते हैं और **raw, E01 या AFF4** images बना सकते हैं:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF tools (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Cloud Disks की Imaging

*AWS* – instance को shut down किए बिना **forensic snapshot** बनाएं:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create` का उपयोग करें और SAS URL पर export करें।


## माउंट

### सही तरीका चुनना

1. **पूरी disk** को माउंट करें जब आपको मूल partition table (MBR/GPT) चाहिए।
2. **एकल partition file** को माउंट करें जब आपको केवल एक volume चाहिए।
3. हमेशा **read-only** (`-o ro,norecovery`) माउंट करें और **copies** पर काम करें।<sup>[[2]](#references)</sup>

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
पूरा होने पर अलग करें:
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
वैकल्पिक रूप से **xmount** के साथ चलते-चलते रूपांतरित करें:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

ब्लॉक डिवाइस (loop या nbd) अटैच करने के बाद:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx सहायक

`kpartx` किसी image से partitions को स्वचालित रूप से `/dev/mapper/` पर map करता है:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### सामान्य mount errors और fixes

| Error | सामान्य कारण | Fix |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) को सही तरीके से unmount नहीं किया गया | `-o ro,norecovery` का उपयोग करें |
| `bad superblock …` | गलत offset या क्षतिग्रस्त FS | offset की गणना करें (`sector*size`) या किसी कॉपी पर `fsck -n` चलाएँ |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | `vgchange -ay` से volume group को activate करें |

### सफाई

Dangling mappings छोड़ने से बचने के लिए **umount** करें और loop/nbd devices को disconnect करें, क्योंकि वे आगे के काम को corrupt कर सकते हैं:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## संदर्भ

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [qemu-nbd manual page (mounting disk images safely)](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}
