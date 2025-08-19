# Здобуття зображення та монтування

{{#include ../../banners/hacktricks-training.md}}


## Здобуття

> Завжди здобувайте **тільки для читання** та **хешуйте під час копіювання**. Тримайте оригінальний пристрій **заблокованим для запису** і працюйте лише з перевіреними копіями.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` є активно підтримуваним форком dcfldd (DoD Computer Forensics Lab dd).
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Графічний, багатопотоковий іміджер, який підтримує **raw (dd)**, **EWF (E01/EWFX)** та **AFF4** вихід з паралельною перевіркою. Доступний у більшості репозиторіїв Linux (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4 - це сучасний формат зображень Google, розроблений для *дуже* великих доказів (рідкісні, відновлювальні, хмарні).
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Ви можете [завантажити FTK Imager](https://accessdata.com/product-download) та створити **сирі, E01 або AFF4** образи:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Інструменти EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – створити **судово-експертний знімок** без вимкнення екземпляра:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – використовуйте `az snapshot create` та експортуйте до SAS URL.

## Монтування

### Вибір правильного підходу

1. Монтуйте **весь диск**, коли вам потрібна оригінальна таблиця розділів (MBR/GPT).
2. Монтуйте **файл одного розділу**, коли вам потрібен лише один том.
3. Завжди монтуйте **тільки для читання** (`-o ro,norecovery`) та працюйте з **копіями**.

### Сирі зображення (dd, AFF4-extracted)
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
Від'єднайте, коли закінчите:
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
Альтернативно конвертуйте на льоту за допомогою **xmount**:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt томи

Після підключення блочного пристрою (loop або nbd):
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` автоматично відображає розділи з образу на `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Загальні помилки монтування та їх виправлення

| Помилка | Типова причина | Виправлення |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Журналізована FS (ext4) не була коректно відмонтована | використовуйте `-o ro,norecovery` |
| `bad superblock …` | Неправильний зсув або пошкоджена FS | розрахуйте зсув (`sector*size`) або запустіть `fsck -n` на копії |
| `mount: unknown filesystem type 'LVM2_member'` | Контейнер LVM | активуйте групу томів за допомогою `vgchange -ay` |

### Очищення

Не забудьте **umount** та **disconnect** пристрої loop/nbd, щоб уникнути залишкових відображень, які можуть пошкодити подальшу роботу:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Посилання

- Оголошення та специфікація інструменту зображення AFF4: https://github.com/aff4/aff4
- Сторінка мануалу qemu-nbd (безпечне монтування образів дисків): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
