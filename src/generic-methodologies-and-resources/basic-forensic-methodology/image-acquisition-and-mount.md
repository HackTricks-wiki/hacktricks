# Image Acquisition & Mount

{{#include ../../banners/hacktricks-training.md}}

## Acquisition

> हमेशा **read-only** तरीके से acquire करें और **copy करते समय hash करें**। मूल device को **write-blocked** रखें और केवल verified copies पर काम करें।

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`, dcfldd (DoD Computer Forensics Lab dd) का actively maintained fork है।
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
ग्राफिकल, multithreaded imager जो **raw (dd)**, **EWF (E01/EWFX)** और **AFF4** output को parallel verification के साथ support करता है। अधिकांश Linux repos में उपलब्ध है (`apt install guymager`)।
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Bradley L. Schatz और Michael I. Cohen द्वारा लिखित AFF4 v1.0 specification, virtualized storage, arbitrary metadata, extensible compression और hashing, तथा high-throughput operation वाले forensic container को परिभाषित करती है।<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

आप [FTK Imager डाउनलोड](https://accessdata.com/product-download) कर सकते हैं और **raw, E01 या AFF4** इमेज बना सकते हैं:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF उपकरण (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Cloud Disks की Imaging

*AWS* – instance को shut down किए बिना एक **forensic snapshot** बनाएँ:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create` का उपयोग करें और SAS URL पर export करें।


## माउंट

### सही approach चुनना

1. **पूरी disk** को माउंट करें, जब आपको original partition table (MBR/GPT) चाहिए।
2. **एकल partition file** को माउंट करें, जब आपको केवल एक volume चाहिए।
3. Image attachments को read-only रखें (उदाहरण के लिए, qemu-nbd का `--read-only`)।<sup>[[2]](#references)</sup> Filesystems को read-only (`-o ro`) माउंट करें।<sup>[[3]](#references)</sup> **Copies** पर काम करें।

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
अनुवाद करने के लिए कोई मूल पाठ प्रदान नहीं किया गया है।
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
filesystem-specific no-replay mounts के लिए, ext3/ext4 `noload` का उपयोग करते हैं, जबकि XFS `norecovery` का उपयोग करता है और read-only mode आवश्यक होता है।<sup>[[3]](#references)[[4]](#references)</sup>

वैकल्पिक रूप से **xmount** के साथ on the fly convert करें:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

Block device (loop या nbd) attach करने के बाद:
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

एक dirty ext3/ext4 filesystem के लिए, जब journal replay को रोकना आवश्यक हो, तब `ro,noload` का उपयोग करें।<sup>[[3]](#references)</sup>

| Error | सामान्य कारण | Fix |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) को cleanly unmount नहीं किया गया | `-o ro,noload` का उपयोग करें |
| `bad superblock …` | गलत offset या damaged FS | offset (`sector*size`) calculate करें या किसी copy पर `fsck -n` चलाएँ |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | `vgchange -ay` से volume group activate करें |

### Clean-up

आगे के work को corrupt करने वाली dangling mappings छोड़ने से बचने के लिए **umount** करें और loop/nbd devices को **disconnect** करें:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd documentation](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [The SGI XFS filesystem (Linux kernel documentation)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
