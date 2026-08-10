# Upatikanaji na Mount wa Image

## Upatikanaji

> Daima fanya upatikanaji wa **read-only** na **hash while you copy**. Weka kifaa asili kikiwa **write-blocked** na fanyia kazi nakala zilizothibitishwa pekee.

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
Imageer ya kielelezo yenye multithread inayotumia matokeo ya **raw (dd)**, **EWF (E01/EWFX)** na **AFF4**, pamoja na uthibitishaji sambamba. Inapatikana katika repos nyingi za Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Specification ya AFF4 v1.0, iliyoandikwa na Bradley L. Schatz na Michael I. Cohen, inafafanua forensic container yenye storage iliyovirtualize, metadata yoyote, compression na hashing zinazoweza kupanuliwa, pamoja na operation yenye throughput ya juu.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Unaweza [kupakua FTK Imager](https://accessdata.com/product-download) na kuunda images za **raw, E01 au AFF4**:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Zana za EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Kutengeneza Image za Cloud Disks

*AWS* – tengeneza **forensic snapshot** bila kuzima instance:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – tumia `az snapshot create` na u-export kwenda kwenye SAS URL.


## Kupachika

### Kuchagua mbinu sahihi

1. Pachika **diski nzima** unapotaka jedwali la awali la partitions (MBR/GPT).
2. Pachika **faili la partition moja** unapohitaji volume moja pekee.
3. Weka viambatisho vya image katika hali ya kusomeka tu (kwa mfano, `--read-only` ya qemu-nbd).<sup>[[2]](#references)</sup> Pachika filesystems katika hali ya kusomeka tu (`-o ro`).<sup>[[3]](#references)</sup> Fanyia kazi **nakala**.

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
Tenganisha ukimaliza:
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
Kwa mount za mfumo maalum wa faili zisizotekeleza tena, ext3/ext4 hutumia `noload`, huku XFS ikitumia `norecovery` na kuhitaji hali ya kusoma pekee.<sup>[[3]](#references)[[4]](#references)</sup>

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
### Wasaidizi wa kpartx

`kpartx` hupanga partitions kutoka kwenye image hadi `/dev/mapper/` kiotomatiki:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Makosa ya kawaida ya mount na marekebisho

Kwa filesystem ya ext3/ext4 iliyo dirty, tumia `ro,noload` wakati journal replay lazima izuiwe.<sup>[[3]](#references)</sup>

| Kosa | Sababu ya Kawaida | Marekebisho |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) haiku-unmount kwa usahihi | tumia `-o ro,noload` |
| `bad superblock …` | Offset isiyo sahihi au FS iliyoharibika | kokotoa offset (`sector*size`) au endesha `fsck -n` kwenye copy |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | activate volume group kwa `vgchange -ay` |

### Usafishaji

Kumbuka kufanya **umount** na **disconnect** vifaa vya loop/nbd ili kuepuka kuacha mappings zinazoning'inia ambazo zinaweza kuharibu kazi zaidi:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Maelezo ya Kiwango cha AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Nyaraka za QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Ukurasa wa mwongozo wa Linux wa mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Mfumo wa faili wa SGI XFS (Nyaraka za kernel ya Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
