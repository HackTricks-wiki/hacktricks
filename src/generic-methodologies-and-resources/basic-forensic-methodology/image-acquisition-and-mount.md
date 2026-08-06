# Acquisizione e montaggio

{{#include ../../banners/hacktricks-training.md}}


## Acquisizione

> Acquisisci sempre in modalità **read-only** e calcola l'**hash durante la copia**. Mantieni il dispositivo originale **write-blocked** e lavora solo su copie verificate.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` è il fork mantenuto attivamente di dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Imager grafico e multithread che supporta output **raw (dd)**, **EWF (E01/EWFX)** e **AFF4** con verifica parallela. Disponibile nella maggior parte dei repository Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 è il moderno formato di imaging di Google, progettato per evidenze *molto* grandi (sparse, riprendibile, cloud-native).<sup>[[1]](#references)</sup>
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
### Acquisizione immagini dei dischi cloud

*AWS* – crea uno **snapshot forense** senza arrestare l’istanza:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – usa `az snapshot create` ed esporta a un URL SAS.


## Mount

### Scelta dell'approccio corretto

1. Monta l'**intero disco** quando vuoi la tabella delle partizioni originale (MBR/GPT).
2. Monta il **file di una singola partizione** quando ti serve un solo volume.
3. Monta sempre in **sola lettura** (`-o ro,norecovery`) e lavora su **copie**.<sup>[[2]](#references)</sup>

### Immagini raw (estratte con dd, AFF4)
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
Scollega al termine:
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
### Volumi LVM / BitLocker / VeraCrypt

Dopo aver collegato il dispositivo a blocchi (loop o nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### Strumenti ausiliari di kpartx

`kpartx` mappa automaticamente le partizioni di un'immagine in `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Errori comuni di mount e relative soluzioni

| Errore | Causa tipica | Soluzione |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS journaled (ext4) non smontato correttamente | usare `-o ro,norecovery` |
| `bad superblock …` | Offset errato o FS danneggiato | calcolare l'offset (`settore*dimensione`) oppure eseguire `fsck -n` su una copia |
| `mount: unknown filesystem type 'LVM2_member'` | Container LVM | attivare il volume group con `vgchange -ay` |

### Pulizia

Ricordarsi di eseguire **umount** e di **disconnect** dei dispositivi loop/nbd per evitare di lasciare mapping pendenti che potrebbero danneggiare il lavoro successivo:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Riferimenti

- [1] [Specifiche dello standard AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Pagina del manuale di qemu-nbd (montaggio sicuro delle immagini disco)](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}
