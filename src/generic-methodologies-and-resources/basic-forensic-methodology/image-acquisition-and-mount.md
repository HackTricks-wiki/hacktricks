# Image-Erfassung & Mounten

{{#include ../../banners/hacktricks-training.md}}


## Erfassung

> Erfasse immer **nur lesend** und **hashe während des Kopierens**. Halte das Originalgerät **schreibgeschützt** und arbeite ausschließlich mit verifizierten Kopien.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` ist der aktiv gepflegte Fork von dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Grafisches, multithreaded Imager-Tool, das **raw (dd)**-, **EWF (E01/EWFX)**- und **AFF4**-Ausgabe mit paralleler Verifizierung unterstützt. In den meisten Linux-Repositories verfügbar (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 ist Googles modernes Abbildformat, das für *sehr* große Beweismaterialien entwickelt wurde (sparse, fortsetzbar, cloud-native).<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Sie können [FTK Imager herunterladen](https://accessdata.com/product-download) und **raw-, E01- oder AFF4-Images** erstellen:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF-Tools (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Forensische Abbilder von Cloud-Datenträgern

*AWS* – Erstelle einen **forensischen Snapshot**, ohne die Instanz herunterzufahren:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – verwende `az snapshot create` und exportiere zu einer SAS-URL.


## Einbinden

### Den richtigen Ansatz auswählen

1. Binde die **gesamte Festplatte** ein, wenn du die ursprüngliche Partitionstabelle (MBR/GPT) benötigst.
2. Binde eine **einzelne Partitionsdatei** ein, wenn du nur ein Volume benötigst.
3. Binde immer **schreibgeschützt** ein (`-o ro,norecovery`) und arbeite mit **Kopien**.<sup>[[2]](#references)</sup>

### Raw-Images (dd, AFF4-extracted)
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
Nach Abschluss aushängen:
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
Alternativ kannst du es mit **xmount** spontan konvertieren:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt-Volumes

Nach dem Anhängen des Blockgeräts (loop oder nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx-Hilfsprogramme

`kpartx` ordnet Partitionen aus einem Image automatisch `/dev/mapper/` zu:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Häufige mount-Fehler und Lösungen

| Fehler | Typische Ursache | Lösung |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaling-FS (ext4) nicht sauber ausgehängt | `-o ro,norecovery` verwenden |
| `bad superblock …` | Falscher Offset oder beschädigtes FS | Offset berechnen (`sector*size`) oder `fsck -n` auf einer Kopie ausführen |
| `mount: unknown filesystem type 'LVM2_member'` | LVM-Container | Volume Group mit `vgchange -ay` aktivieren |

### Bereinigung

Denke daran, **umount** auszuführen und Loop-/nbd-Geräte zu **disconnecten**, damit keine verwaisten Mappings zurückbleiben, die weitere Arbeiten beschädigen können:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Referenzen

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [qemu-nbd manual page (mounting disk images safely)](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}
