# Nabavka i montiranje image-a

{{#include ../../banners/hacktricks-training.md}}

## Nabavka

> Uvek vršite nabavku **samo za čitanje** i **hashujte tokom kopiranja**. Originalni uređaj držite **write-blocked** i radite samo sa verifikovanim kopijama.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` je aktivno održavani fork alata dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Grafički alat za kreiranje image-a sa podrškom za izlazne formate **raw (dd)**, **EWF (E01/EWFX)** i **AFF4**, uz paralelnu verifikaciju. Dostupan je u većini Linux repozitorijuma (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Specifikacija AFF4 v1.0, čiji su autori Bradley L. Schatz i Michael I. Cohen, definiše forenzički kontejner sa virtuelizovanim skladištem, proizvoljnim metapodacima, proširivom kompresijom i heširanjem, kao i operacijama velikog protoka podataka.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Možete [preuzeti FTK Imager](https://accessdata.com/product-download) i kreirati **raw, E01 ili AFF4** imidže:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF alati (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Izrada imidža Cloud diskova

*AWS* – kreirajte **forenzički snapshot** bez gašenja instance:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – koristite `az snapshot create` i izvezite u SAS URL.


## Montiranje

### Izbor odgovarajućeg pristupa

1. Montirajte **ceo disk** kada želite originalnu particionu tabelu (MBR/GPT).
2. Montirajte **datoteku pojedinačne particije** kada vam je potreban samo jedan volumen.
3. Priloge image-a držite u režimu samo za čitanje (na primer, `--read-only` za qemu-nbd).<sup>[[2]](#references)</sup> Filesystem-e montirajte samo za čitanje (`-o ro`).<sup>[[3]](#references)</sup> Radite na **kopijama**.

### Raw image-i (dd, AFF4-extracted)
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
Za filesystem-specifične no-replay mount-ove, ext3/ext4 koriste `noload`, dok XFS koristi `norecovery` i zahteva read-only režim.<sup>[[3]](#references)[[4]](#references)</sup>

Alternativno, konvertujte u hodu pomoću **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumeni

Nakon priključivanja blok uređaja (loop ili nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx pomoćni alati

`kpartx` automatski mapira particije iz image-a u `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Uobičajene greške pri montiranju i rešenja

Za nečist ext3/ext4 filesystem, koristite `ro,noload` kada se mora sprečiti ponovna reprodukcija journala.<sup>[[3]](#references)</sup>

| Greška | Tipičan uzrok | Rešenje |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) nije pravilno demontiran | koristite `-o ro,noload` |
| `bad superblock …` | Pogrešan offset ili oštećen FS | izračunajte offset (`sector*size`) ili pokrenite `fsck -n` nad kopijom |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | aktivirajte volume group pomoću `vgchange -ay` |

### Čišćenje

Ne zaboravite da **umount** i **disconnect** loop/nbd devices kako ne biste ostavili viseća mapiranja koja mogu oštetiti dalji rad:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd документација](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Linux приручник за mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS систем датотека (документација Linux kernel-а)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
