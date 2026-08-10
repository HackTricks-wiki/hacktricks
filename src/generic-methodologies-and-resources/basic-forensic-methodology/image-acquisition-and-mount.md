# Acquisition et montage

## Acquisition

> Acquérez toujours en **read-only** et calculez le **hash** pendant la copie. Gardez le périphérique d’origine **write-blocked** et travaillez uniquement sur des copies vérifiées.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` est le fork activement maintenu de dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Outil d’imagerie graphique et multithread prenant en charge les formats de sortie **raw (dd)**, **EWF (E01/EWFX)** et **AFF4**, avec vérification parallèle. Disponible dans la plupart des dépôts Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

La spécification AFF4 v1.0, rédigée par Bradley L. Schatz et Michael I. Cohen, définit un conteneur forensique doté d’un stockage virtualisé, de métadonnées arbitraires, d’une compression et d’un hachage extensibles, ainsi que d’opérations à haut débit.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows et Linux)

Vous pouvez [télécharger FTK Imager](https://accessdata.com/product-download) et créer des images **raw, E01 ou AFF4** :
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Outils EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imagerie des disques Cloud

*AWS* – créez un **forensic snapshot** sans arrêter l’instance :
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – utilisez `az snapshot create` et exportez vers une URL SAS.


## Montage

### Choisir la bonne approche

1. Montez le **disque entier** lorsque vous voulez conserver la table de partitions d’origine (MBR/GPT).
2. Montez un **fichier de partition unique** lorsque vous n’avez besoin que d’un seul volume.
3. Gardez les pièces jointes d’image en lecture seule (par exemple, `--read-only` de qemu-nbd).<sup>[[2]](#references)</sup> Montez les systèmes de fichiers en lecture seule (`-o ro`).<sup>[[3]](#references)</sup> Travaillez sur des **copies**.

### Images brutes (dd, extraites d’AFF4)
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
No content was provided for translation.
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
Pour les montages sans rejeu spécifiques au système de fichiers, ext3/ext4 utilisent `noload`, tandis que XFS utilise `norecovery` et nécessite le mode lecture seule.<sup>[[3]](#references)[[4]](#references)</sup>

Vous pouvez également convertir à la volée avec **xmount** :
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### Volumes LVM / BitLocker / VeraCrypt

Après avoir attaché le block device (loop ou nbd) :
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### Helpers kpartx

`kpartx` mappe automatiquement les partitions d’une image vers `/dev/mapper/` :
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Erreurs courantes de montage et corrections

Pour un système de fichiers ext3/ext4 « dirty », utilisez `ro,noload` lorsque la relecture du journal doit être empêchée.<sup>[[3]](#references)</sup>

| Erreur | Cause typique | Correction |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | FS journalisé (ext4) non démonté proprement | utilisez `-o ro,noload` |
| `bad superblock …` | Offset incorrect ou FS endommagé | calculez l’offset (`sector*size`) ou exécutez `fsck -n` sur une copie |
| `mount: unknown filesystem type 'LVM2_member'` | Conteneur LVM | activez le volume group avec `vgchange -ay` |

### Nettoyage

N’oubliez pas de **umount** et de **disconnect** les devices loop/nbd afin d’éviter de laisser des mappings orphelins susceptibles de corrompre les opérations ultérieures :
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Spécification de la norme AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Documentation de QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Page du manuel Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Le système de fichiers SGI XFS (documentation du noyau Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
