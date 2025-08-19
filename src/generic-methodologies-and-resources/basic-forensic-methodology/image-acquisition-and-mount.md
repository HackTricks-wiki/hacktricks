# Sticanje slika i montiranje

{{#include ../../banners/hacktricks-training.md}}


## Sticanje

> Uvek stičite **samo za čitanje** i **hash dok kopirate**. Držite originalni uređaj **blokiranim za pisanje** i radite samo na verifikovanim kopijama.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` je aktivno održavana verzija dcfldd (DoD laboratorija za forenziku računara dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Grafički, višedretveni imager koji podržava **raw (dd)**, **EWF (E01/EWFX)** i **AFF4** izlaz sa paralelnom verifikacijom. Dostupan u većini Linux repozitorijuma (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Napredni Forenzički Format 4)

AFF4 je moderni format slika koji je razvio Google, dizajniran za *veoma* velike dokaze (retki, nastavljivi, cloud-native).
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Možete [preuzeti FTK Imager](https://accessdata.com/product-download) i kreirati **raw, E01 ili AFF4** slike:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF alati (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – kreirajte **forenzičku snimku** bez gašenja instance:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – koristite `az snapshot create` i izvezite na SAS URL.

## Montiranje

### Biranje pravog pristupa

1. Montirajte **ceo disk** kada želite originalnu tabelu particija (MBR/GPT).
2. Montirajte **datoteku jedne particije** kada vam je potrebna samo jedna jedinica.
3. Uvek montirajte **samo za čitanje** (`-o ro,norecovery`) i radite na **kopijama**.

### Sirove slike (dd, AFF4-izvučene)
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
Odvojite kada završite:
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
Alternativno konvertujte u realnom vremenu pomoću **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumeni

Nakon povezivanja blok uređaja (loop ili nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx помоћници

`kpartx` аутоматски мапира партиције из слике на `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Uobičajene greške prilikom montiranja i rešenja

| Greška | Tipičan uzrok | Rešenje |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) nije pravilno odmontiran | koristite `-o ro,norecovery` |
| `bad superblock …` | Pogrešan offset ili oštećen FS | izračunajte offset (`sector*size`) ili pokrenite `fsck -n` na kopiji |
| `mount: unknown filesystem type 'LVM2_member'` | LVM kontejner | aktivirajte grupu volumena sa `vgchange -ay` |

### Čišćenje

Zapamtite da **umount** i **isključite** loop/nbd uređaje kako biste izbegli ostavljanje visećih mapiranja koja mogu oštetiti dalji rad:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Reference

- AFF4 alat za slikanje najava i specifikacija: https://github.com/aff4/aff4
- qemu-nbd priručnik (sigurno montiranje slika diska): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
