# Akwizycja i montowanie

## Akwizycja

> Zawsze wykonuj akwizycję w trybie **tylko do odczytu** i **obliczaj hash podczas kopiowania**. Oryginalne urządzenie powinno pozostać **zablokowane przed zapisem**, a praca powinna odbywać się wyłącznie na zweryfikowanych kopiach.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` jest aktywnie utrzymywanym forkiem dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Graficzne, wielowątkowe narzędzie do tworzenia obrazów, obsługujące formaty wyjściowe **raw (dd)**, **EWF (E01/EWFX)** i **AFF4** z równoległą weryfikacją. Dostępne w większości repozytoriów Linuxa (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Specyfikacja AFF4 v1.0, opracowana przez Bradleya L. Schatza i Michaela I. Cohena, definiuje kontener forensyczny z wirtualizowaną pamięcią masową, dowolnymi metadanymi, rozszerzalną kompresją i hashowaniem oraz obsługą operacji o wysokiej przepustowości.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Możesz [pobrać FTK Imager](https://accessdata.com/product-download) i utworzyć obrazy **raw, E01 lub AFF4**:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Narzędzia EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Obrazowanie dysków Cloud

*AWS* – utwórz **forensic snapshot** bez wyłączania instancji:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – użyj `az snapshot create` i wyeksportuj do adresu URL SAS.


## Montowanie

### Wybór właściwego podejścia

1. Zamontuj **cały dysk**, gdy potrzebujesz oryginalnej tablicy partycji (MBR/GPT).
2. Zamontuj **plik pojedynczej partycji**, gdy potrzebujesz tylko jednego woluminu.
3. Zachowaj załączone obrazy w trybie tylko do odczytu (na przykład `--read-only` w qemu-nbd).<sup>[[2]](#references)</sup> Zamontuj systemy plików w trybie tylko do odczytu (`-o ro`).<sup>[[3]](#references)</sup> Pracuj na **kopiach**.

### Obrazy surowe (wyodrębnione za pomocą dd, AFF4)
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
Odłącz po zakończeniu:
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
W przypadku montowań bez odtwarzania dziennika, specyficznych dla systemu plików, ext3/ext4 używają `noload`, natomiast XFS używa `norecovery` i wymaga trybu tylko do odczytu.<sup>[[3]](#references)[[4]](#references)</sup>

Alternatywnie można przeprowadzić konwersję w locie za pomocą **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### Woluminy LVM / BitLocker / VeraCrypt

Po dołączeniu urządzenia blokowego (loop lub nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### Pomocniki kpartx

`kpartx` automatycznie mapuje partycje z obrazu do `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Typowe błędy montowania i poprawki

W przypadku „brudnego” systemu plików ext3/ext4 użyj `ro,noload`, gdy należy zapobiec odtwarzaniu journalu.<sup>[[3]](#references)</sup>

| Błąd | Typowa przyczyna | Poprawka |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | System plików z journalem (ext4) nie został poprawnie odmontowany | użyj `-o ro,noload` |
| `bad superblock …` | Nieprawidłowy offset lub uszkodzony system plików | oblicz offset (`sector*size`) lub uruchom `fsck -n` na kopii |
| `mount: unknown filesystem type 'LVM2_member'` | Kontener LVM | aktywuj volume group za pomocą `vgchange -ay` |

### Czyszczenie

Pamiętaj, aby wykonać **umount** i **odłączyć** urządzenia loop/nbd, aby uniknąć pozostawienia wiszących mapowań, które mogą uszkodzić dalsze prace:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Specyfikacja standardu AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Dokumentacja QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Strona podręcznika systemu Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [System plików SGI XFS (dokumentacja jądra Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
