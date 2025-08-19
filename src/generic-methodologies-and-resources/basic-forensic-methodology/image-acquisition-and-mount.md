# Acquisizione e Montaggio

{{#include ../../banners/hacktricks-training.md}}


## Acquisizione

> Acquisisci sempre in **sola lettura** e **calcola l'hash mentre copi**. Mantieni il dispositivo originale **bloccato in scrittura** e lavora solo su copie verificate.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` è il fork attivamente mantenuto di dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Immagine grafica multithread che supporta **raw (dd)**, **EWF (E01/EWFX)** e **AFF4** in output con verifica parallela. Disponibile nella maggior parte dei repository Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 è il formato di imaging moderno di Google progettato per prove *molto* grandi (sparse, riprendibili, native al cloud).
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows e Linux)

Puoi [scaricare FTK Imager](https://accessdata.com/product-download) e creare immagini **raw, E01 o AFF4**:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Strumenti EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – crea un **forensic snapshot** senza spegnere l'istanza:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – usa `az snapshot create` ed esporta in un URL SAS.

## Montare

### Scegliere l'approccio giusto

1. Monta il **disco intero** quando desideri la tabella delle partizioni originale (MBR/GPT).
2. Monta un **file di partizione singola** quando hai bisogno solo di un volume.
3. Monta sempre in **sola lettura** (`-o ro,norecovery`) e lavora su **copia**.

### Immagini raw (dd, estratte da AFF4)
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
Scollegare quando finito:
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
In alternativa, converti al volo con **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

Dopo aver collegato il dispositivo a blocchi (loop o nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` mappa automaticamente le partizioni da un'immagine a `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Errori comuni di montaggio e soluzioni

| Errore | Causa tipica | Soluzione |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS journalizzato (ext4) non smontato correttamente | usa `-o ro,norecovery` |
| `bad superblock …` | Offset errato o FS danneggiato | calcola l'offset (`settore*dimensione`) o esegui `fsck -n` su una copia |
| `mount: unknown filesystem type 'LVM2_member'` | Contenitore LVM | attiva il gruppo di volumi con `vgchange -ay` |

### Pulizia

Ricorda di **umount** e **disconnettere** i dispositivi loop/nbd per evitare di lasciare mappature pendenti che possono corrompere ulteriori lavori:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Riferimenti

- Annuncio e specifiche dello strumento di imaging AFF4: https://github.com/aff4/aff4
- Pagina del manuale qemu-nbd (montaggio sicuro delle immagini disco): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
