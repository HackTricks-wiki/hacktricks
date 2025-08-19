# Beeldverkryging & Monteer

{{#include ../../banners/hacktricks-training.md}}


## Verkryging

> Verkry altyd **slegs lees** en **hash terwyl jy kopieer**. Hou die oorspronklike toestel **skryf-geblooke** en werk slegs op geverifieerde kopieë.

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
Grafiese, multithreaded beeldverwerker wat **raw (dd)**, **EWF (E01/EWFX)** en **AFF4** uitvoer met parallelle verifikasie ondersteun. Beskikbaar in die meeste Linux repos (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Geavanceerde Forensiese Formaat 4)

AFF4 is Google se moderne beeldformaat ontwerp vir *baie* groot bewys (spaar, hervatbaar, wolk-inheems).
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Jy kan [FTK Imager aflaai](https://accessdata.com/product-download) en **raw, E01 of AFF4** beelde skep:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF tools (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Beeldvorming van Wolk Skyfies

*AWS* – skep 'n **forensiese snapshot** sonder om die instansie af te sluit:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – gebruik `az snapshot create` en voer uit na 'n SAS-URL.

## Mount

### Keuse van die regte benadering

1. Mount die **hele skyf** wanneer jy die oorspronklike partisie tabel (MBR/GPT) wil hê.
2. Mount 'n **enkele partisie lêer** wanneer jy net een volume nodig het.
3. Mount altyd **slegs lees** (`-o ro,norecovery`) en werk op **kopieë**.

### Rau beelde (dd, AFF4-uitgetrek)
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
Ontkoppel wanneer klaar:
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
Alternatiewelik op die vlieg omskakel met **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

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

`kpartx` kaart partities van 'n beeld outomaties na `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Algemene monteerfoute & oplossings

| Fout | Tipiese Oorsaak | Oplossing |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) nie skoon ontkoppel nie | gebruik `-o ro,norecovery` |
| `bad superblock …` | Verkeerde offset of beskadigde FS | bereken offset (`sector*size`) of voer `fsck -n` op 'n kopie uit |
| `mount: unknown filesystem type 'LVM2_member'` | LVM houer | aktiveer volume groep met `vgchange -ay` |

### Skoonmaak

Onthou om **umount** en **ontkoppel** loop/nbd toestelle om te verhoed dat daar losstaande kaarte agterbly wat verdere werk kan beskadig:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Verwysings

- AFF4 beeldvorming hulpmiddel aankondiging & spesifikasie: https://github.com/aff4/aff4
- qemu-nbd handleiding bladsy (veiligheid van skyfbeeldes monteer): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
