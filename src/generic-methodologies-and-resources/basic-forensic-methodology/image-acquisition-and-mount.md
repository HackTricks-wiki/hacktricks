# Akvizicija i montiranje image-a

## Akvizicija

> Uvek vršite akviziciju u režimu **samo za čitanje** i **izračunavajte hash tokom kopiranja**. Originalni uređaj mora ostati **zaštićen od upisivanja**, a radite isključivo sa verifikovanim kopijama.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` je aktivno održavana fork verzija alata dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Grafički alat za kreiranje image-a sa podrškom za **raw (dd)**, **EWF (E01/EWFX)** i **AFF4** izlaz, uz paralelnu verifikaciju. Dostupan je u većini Linux repozitorijuma (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 v1.0 specifikacija, čiji su autori Bradley L. Schatz i Michael I. Cohen, definiše forenzički kontejner sa virtuelizovanim skladištem, proizvoljnim metapodacima, proširivom kompresijom i heširanjem, kao i operacijama velikog protoka.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Možete [preuzeti FTK Imager](https://accessdata.com/product-download) i kreirati **raw, E01 ili AFF4** image datoteke:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF alati (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Kreiranje image-a Cloud diskova

*AWS* – kreirajte **forensic snapshot** bez gašenja instance:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – koristite `az snapshot create` i izvezite na SAS URL.


## Montiranje

### Izbor odgovarajućeg pristupa

1. Montirajte **ceo disk** kada vam je potrebna originalna particiona tabela (MBR/GPT).
2. Montirajte **datoteku jedne particije** kada vam je potreban samo jedan volumen.
3. Održavajte prikačene image datoteke u režimu samo za čitanje (na primer, `qemu-nbd` opcijom `--read-only`).<sup>[[2]](#references)</sup> Montirajte filesysteme samo za čitanje (`-o ro`).<sup>[[3]](#references)</sup> Radite na **kopijama**.

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
Nije dostavljen tekst za prevođenje. Molimo vas da pošaljete sadržaj datoteke.
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
Za filesystem-specific montiranja bez ponovne reprodukcije, ext3/ext4 koriste `noload`, dok XFS koristi `norecovery` i zahteva režim samo za čitanje.<sup>[[3]](#references)[[4]](#references)</sup>

Druga mogućnost je konvertovanje u hodu pomoću **xmount**:
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
### Uobičajene greške pri mountovanju i rešenja

Za nečist ext3/ext4 filesystem, koristite `ro,noload` kada se mora sprečiti ponovna reprodukcija journala.<sup>[[3]](#references)</sup>

| Greška | Tipičan uzrok | Rešenje |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) nije pravilno unmountovan | koristite `-o ro,noload` |
| `bad superblock …` | Pogrešan offset ili oštećen FS | izračunajte offset (`sector*size`) ili pokrenite `fsck -n` nad kopijom |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | aktivirajte volume group pomoću `vgchange -ay` |

### Čišćenje

Ne zaboravite da uradite **umount** i **disconnect** loop/nbd devices kako ne biste ostavili viseća mapiranja koja mogu da oštete dalji rad:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Specifikacija standarda AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd dokumentacija](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Linux priručnik za mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS sistem datoteka (dokumentacija Linux kernela)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
