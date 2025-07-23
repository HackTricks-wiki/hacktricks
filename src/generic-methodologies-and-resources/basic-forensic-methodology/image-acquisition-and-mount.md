# इमेज अधिग्रहण और माउंट

{{#include ../../banners/hacktricks-training.md}}


## अधिग्रहण

> हमेशा **पढ़ने के लिए केवल** और **कॉपी करते समय हैश** प्राप्त करें। मूल डिवाइस को **लेखन-रोक** रखें और केवल सत्यापित प्रतियों पर काम करें।

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` dcfldd (DoD Computer Forensics Lab dd) का सक्रिय रूप से बनाए रखा गया फोर्क है।
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
ग्राफिकल, मल्टीथ्रेडेड इमेजर जो **raw (dd)**, **EWF (E01/EWFX)** और **AFF4** आउटपुट को समानांतर सत्यापन के साथ समर्थन करता है। अधिकांश Linux रिपोजिटरी में उपलब्ध है (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 गूगल का आधुनिक इमेजिंग फॉर्मेट है जो *बहुत* बड़े सबूतों (स्पार्स, रिस्यूमेबल, क्लाउड-नेटिव) के लिए डिज़ाइन किया गया है।
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

आप [FTK Imager डाउनलोड कर सकते हैं](https://accessdata.com/product-download) और **कच्चे, E01 या AFF4** इमेज बना सकते हैं:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF उपकरण (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – बिना इंस्टेंस को बंद किए **forensic snapshot** बनाएं:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – use `az snapshot create` and export to a SAS URL.  See the HackTricks page {{#ref}}
../../cloud/azure/azure-forensics.md
{{#endref}}


## माउंट

### सही दृष्टिकोण चुनना

1. **पूरे डिस्क** को माउंट करें जब आपको मूल विभाजन तालिका (MBR/GPT) की आवश्यकता हो।
2. **एकल विभाजन फ़ाइल** को माउंट करें जब आपको केवल एक वॉल्यूम की आवश्यकता हो।
3. हमेशा **पढ़ने के लिए केवल** (`-o ro,norecovery`) माउंट करें और **कॉपीज़** पर काम करें।

### कच्ची छवियाँ (dd, AFF4-extracted)
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
जब समाप्त हो जाए तो अलग करें:
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
इसके बजाय **xmount** के साथ तुरंत परिवर्तित करें:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt वॉल्यूम

ब्लॉक डिवाइस (लूप या nbd) को अटैच करने के बाद:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx हेल्पर्स

`kpartx` एक इमेज से विभाजनों को स्वचालित रूप से `/dev/mapper/` पर मैप करता है:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### सामान्य माउंट त्रुटियाँ और समाधान

| त्रुटि | सामान्य कारण | समाधान |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | जर्नल्ड FS (ext4) सही तरीके से अनमाउंट नहीं हुआ | `-o ro,norecovery` का उपयोग करें |
| `bad superblock …` | गलत ऑफसेट या क्षतिग्रस्त FS | ऑफसेट की गणना करें (`sector*size`) या एक कॉपी पर `fsck -n` चलाएँ |
| `mount: unknown filesystem type 'LVM2_member'` | LVM कंटेनर | `vgchange -ay` के साथ वॉल्यूम समूह को सक्रिय करें |

### सफाई

याद रखें कि **umount** और **disconnect** लूप/nbd उपकरणों को करें ताकि लटकते मैपिंग्स न छोड़ें जो आगे के काम को भ्रष्ट कर सकते हैं:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## संदर्भ

- AFF4 इमेजिंग टूल की घोषणा और विनिर्देशन: https://github.com/aff4/aff4
- qemu-nbd मैनुअल पृष्ठ (डिस्क इमेज को सुरक्षित रूप से माउंट करना): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
