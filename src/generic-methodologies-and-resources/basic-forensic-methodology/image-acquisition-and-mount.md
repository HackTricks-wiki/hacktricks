# Acquisizione e montaggio delle immagini

{{#include ../../banners/hacktricks-training.md}}

## Acquisizione

> Acquisisci sempre in modalità **sola lettura** e **calcola l'hash durante la copia**. Mantieni il dispositivo originale **protetto dalla scrittura** e lavora solo su copie verificate.

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
Strumento grafico e multithread per l'acquisizione di immagini, che supporta output **raw (dd)**, **EWF (E01/EWFX)** e **AFF4**, con verifica parallela. Disponibile nella maggior parte dei repository Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

La specifica AFF4 v1.0, redatta da Bradley L. Schatz e Michael I. Cohen, definisce un contenitore forense con storage virtualizzato, metadati arbitrari, compressione ed hashing estensibili e operazioni ad alta velocità.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Puoi [scaricare FTK Imager](https://accessdata.com/product-download) e creare immagini **raw, E01 o AFF4**:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Strumenti EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Acquisizione di immagini dei dischi Cloud

*AWS* – crea uno **snapshot forense** senza arrestare l'istanza:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – usa `az snapshot create` ed esporta in un SAS URL.


## Montaggio

### Scelta dell'approccio corretto

1. Monta l'**intero disco** quando vuoi la tabella delle partizioni originale (MBR/GPT).
2. Monta un **file di partizione singolo** quando ti serve un solo volume.
3. Mantieni gli allegati delle immagini in sola lettura (ad esempio, `--read-only` di qemu-nbd).<sup>[[2]](#references)</sup> Monta i filesystem in sola lettura (`-o ro`).<sup>[[3]](#references)</sup> Lavora su **copie**.

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

# 3. Mount the desired partition (XFS example; use the filesystem-specific option)
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```
Per i mount no-replay specifici del filesystem, ext3/ext4 usano `noload`, mentre XFS usa `norecovery` e richiede la modalità di sola lettura.<sup>[[3]](#references)[[4]](#references)</sup>

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
### helper di kpartx

`kpartx` mappa automaticamente le partizioni di un'immagine in `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Errori comuni di mount e correzioni

Per un filesystem ext3/ext4 sporco, usa `ro,noload` quando è necessario impedire il replay del journal.<sup>[[3]](#references)</sup>

| Errore | Causa tipica | Correzione |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS con journal (ext4) non smontato correttamente | usa `-o ro,noload` |
| `bad superblock …` | Offset errato o FS danneggiato | calcola l'offset (`sector*size`) o esegui `fsck -n` su una copia |
| `mount: unknown filesystem type 'LVM2_member'` | Container LVM | attiva il volume group con `vgchange -ay` |

### Pulizia

Ricorda di eseguire **umount** e **disconnect** dei device loop/nbd per evitare di lasciare mapping pendenti che potrebbero corrompere le operazioni successive:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Specifiche dello standard AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentazione di QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Pagina del manuale Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Il filesystem XFS di SGI (documentazione del kernel Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
