# Image Acquisition & Mount

{{#include ../../banners/hacktricks-training.md}}

## Erfassung

> Erfasse immer **read-only** und **hashe während des Kopierens**. Halte das Originalgerät **schreibgeschützt** und arbeite ausschließlich mit verifizierten Kopien.

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
Grafisches, multithreadfähiges Imaging-Tool, das **raw (dd)**-, **EWF (E01/EWFX)**- und **AFF4**-Ausgabe mit paralleler Verifizierung unterstützt. In den meisten Linux-Repositories verfügbar (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Die AFF4 v1.0-Spezifikation, verfasst von Bradley L. Schatz und Michael I. Cohen, definiert einen forensischen Container mit virtualisiertem Speicher, beliebigen Metadaten, erweiterbarer Komprimierung und Hashing sowie einem hohen Durchsatz.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Sie können [FTK Imager herunterladen](https://accessdata.com/product-download) und **raw-, E01- oder AFF4**-Abbilder erstellen:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF-Werkzeuge (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Abbild von Cloud-Datenträgern erstellen

*AWS* – erstelle einen **forensischen Snapshot**, ohne die instance herunterzufahren:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – verwende `az snapshot create` und exportiere zu einer SAS-URL.


## Mounten

### Den richtigen Ansatz auswählen

1. Mounten Sie die **gesamte Festplatte**, wenn Sie die ursprüngliche Partitionstabelle (MBR/GPT) benötigen.
2. Mounten Sie eine **einzelne Partitionsdatei**, wenn Sie nur ein Volume benötigen.
3. Halten Sie Image-Anhänge schreibgeschützt (zum Beispiel mit `--read-only` von qemu-nbd).<sup>[[2]](#references)</sup> Mounten Sie Dateisysteme schreibgeschützt (`-o ro`).<sup>[[3]](#references)</sup> Arbeiten Sie mit **Kopien**.

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
Bitte stelle den Inhalt der Datei bereit, damit ich ihn übersetzen kann.
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
Für dateisystemspezifische No-Replay-Mounts verwenden ext3/ext4 `noload`, während XFS `norecovery` verwendet und den schreibgeschützten Modus erfordert.<sup>[[3]](#references)[[4]](#references)</sup>

Alternativ kann die Konvertierung direkt während des Vorgangs mit **xmount** erfolgen:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

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
### Häufige Mount-Fehler und Lösungen

Bei einem nicht sauber ausgehängten ext3/ext4-Dateisystem verwenden Sie `ro,noload`, wenn die Journal-Wiedergabe verhindert werden muss.<sup>[[3]](#references)</sup>

| Fehler | Typische Ursache | Lösung |
|-------|------------------|--------|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) wurde nicht sauber ausgehängt | `-o ro,noload` verwenden |
| `bad superblock …` | Falscher Offset oder beschädigtes FS | Offset berechnen (`sector*size`) oder `fsck -n` auf einer Kopie ausführen |
| `mount: unknown filesystem type 'LVM2_member'` | LVM-Container | Volume Group mit `vgchange -ay` aktivieren |

### Bereinigung

Denken Sie daran, Loop-/nbd-Geräte zu **umount**en und zu **disconnect**en, damit keine verwaisten Mappings zurückbleiben, die weitere Arbeiten beschädigen können:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [AFF4-Standardspezifikation (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU-qemu-nbd-Dokumentation](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8)-Handbuchseite für Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Das SGI-XFS-Dateisystem (Linux-Kernel-Dokumentation)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
