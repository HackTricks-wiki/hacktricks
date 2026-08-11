# Beeldverkryging en Montering

{{#include ../../banners/hacktricks-training.md}}

## Verkryging

> Verkry altyd **slegs-lees** en **bereken die hash terwyl jy kopieer**. Hou die oorspronklike toestel **skryfgeblokkeer** en werk slegs met geverifieerde kopieë.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` is die aktief onderhoude fork van dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Grafiese, multithreaded imager wat **raw (dd)**-, **EWF (E01/EWFX)**- en **AFF4**-uitvoer met parallelle verifikasie ondersteun. Beskikbaar in die meeste Linux-repositories (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Die AFF4 v1.0-spesifikasie, geskryf deur Bradley L. Schatz en Michael I. Cohen, definieer ’n forensiese houer met gevirtualiseerde berging, arbitrêre metadata, uitbreidbare kompressie en hashing, en hoë-deurset-werking.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Jy kan [FTK Imager aflaai](https://accessdata.com/product-download) en **raw, E01 of AFF4**-beelde skep:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF-gereedskap (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Beeldvorming van Cloud-skywe

*AWS* – skep ’n **forensic snapshot** sonder om die instance af te skakel:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – gebruik `az snapshot create` en voer dit na ’n SAS URL uit.


## Montering

### Die keuse van die regte benadering

1. Monteer die **hele skyf** wanneer jy die oorspronklike partisietabel (MBR/GPT) benodig.
2. Monteer ’n **enkele partisie-lêer** wanneer jy slegs een volume benodig.
3. Hou beeldaanhegsels leesalleen (byvoorbeeld qemu-nbd se `--read-only`).<sup>[[2]](#references)</sup> Monteer lêerstelsels leesalleen (`-o ro`).<sup>[[3]](#references)</sup> Werk op **kopieë**.

### Rou beelde (dd, AFF4-extracted)
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
Ontkoppel wanneer jy klaar is:
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
Vir lêerstelselspesifieke mounts sonder replay gebruik ext3/ext4 `noload`, terwyl XFS `norecovery` gebruik en leesalleenmodus vereis.<sup>[[3]](#references)[[4]](#references)</sup>

Alternatiewelik, convert on the fly met **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt-volumes

Nadat die bloktoestel (loop of nbd) aangeheg is:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` karteer partisies vanaf ’n image outomaties na `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Algemene mount-foute en oplossings

Vir ’n vuil ext3/ext4-lêerstelsel, gebruik `ro,noload` wanneer joernaalherspeel voorkom moet word.<sup>[[3]](#references)</sup>

| Fout | Tipiese oorsaak | Oplossing |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Gejoernaalde FS (ext4) is nie korrek ontkoppel nie | gebruik `-o ro,noload` |
| `bad superblock …` | Verkeerde offset of beskadigde FS | bereken offset (`sector*size`) of voer `fsck -n` op ’n kopie uit |
| `mount: unknown filesystem type 'LVM2_member'` | LVM-container | aktiveer volume group met `vgchange -ay` |

### Opruiming

Onthou om **umount** uit te voer en loop/nbd-toestelle te **disconnect** om te voorkom dat hangende mappings agtergelaat word wat verdere werk kan korrupteer:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [AFF4 Standaardspesifikasie (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd-dokumentasie](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Die SGI XFS-lêerstelsel (Linux-kerneldokumentasie)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
