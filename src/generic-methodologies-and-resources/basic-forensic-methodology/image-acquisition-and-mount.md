# Upatikanaji wa Picha na Mount

{{#include ../../banners/hacktricks-training.md}}


## Upatikanaji

> Daima fanya upatikanaji kwa **kusoma-tu** na **kokotoa hash wakati wa kunakili**. Weka kifaa asili kikiwa **kimezuiwa kuandikwa** na fanyia kazi nakala zilizothibitishwa pekee.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` ni fork inayodumishwa kikamilifu ya dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Image tool ya kielelezo yenye multithreading inayotumia matokeo ya **raw (dd)**, **EWF (E01/EWFX)** na **AFF4**, pamoja na uthibitishaji sambamba. Inapatikana katika repos nyingi za Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 ni muundo wa kisasa wa imaging wa Google ulioundwa kwa ajili ya ushahidi mkubwa *sana* (sparse, unaoweza kuendelea, cloud-native).<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Unaweza [kupakua FTK Imager](https://accessdata.com/product-download) na kuunda picha za **raw, E01 au AFF4**:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Zana za EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Kutengeneza Picha za Diski za Cloud

*AWS* – tengeneza **forensic snapshot** bila kuzima instance:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – tumia `az snapshot create` na export kwa URL ya SAS.


## Mount

### Kuchagua mbinu inayofaa

1. Mount **diski nzima** unapotaka partition table asili (MBR/GPT).
2. Mount **faili la partition moja** unapohitaji volume moja pekee.
3. Daima mount **ya kusoma pekee** (`-o ro,norecovery`) na ufanyie kazi kwenye nakala.<sup>[[2]](#references)</sup>

### Picha ghafi (zilizotolewa kwa AFF4)
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
Ondoa muunganisho ukimaliza:
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
Vinginevyo, badilisha papo hapo kwa kutumia **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### Volumes za LVM / BitLocker / VeraCrypt

Baada ya kuambatisha kifaa cha block (loop au nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` huweka ramani ya partitions kutoka kwenye image hadi `/dev/mapper/` automatically:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Makosa ya kawaida ya mount na marekebisho

| Kosa | Sababu ya kawaida | Marekebisho |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) haiku-unmount kwa usafi | tumia `-o ro,norecovery` |
| `bad superblock …` | Offset si sahihi au FS imeharibika | hesabu offset (`sector*size`) au endesha `fsck -n` kwenye nakala |
| `mount: unknown filesystem type 'LVM2_member'` | Kontena la LVM | activate volume group kwa `vgchange -ay` |

### Usafishaji

Kumbuka kufanya **umount** na **disconnect** vifaa vya loop/nbd ili kuepuka kuacha mappings zinazoning'inia ambazo zinaweza kuharibu kazi zaidi:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Marejeo

- [1] [Maelezo ya Kawaida ya AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Ukurasa wa mwongozo wa qemu-nbd (ku-mount disk images kwa usalama)](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}
