# Отримання та монтування образу

{{#include ../../banners/hacktricks-training.md}}

## Отримання

> Завжди здійснюйте отримання **лише для читання** та **обчислюйте хеш під час копіювання**. Зберігайте оригінальний пристрій **заблокованим для запису** та працюйте лише з перевіреними копіями.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` — це форк `dcfldd` (DoD Computer Forensics Lab dd), який активно підтримується.
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Графічний багатопотоковий інструмент створення образів, який підтримує вивід у форматах **raw (dd)**, **EWF (E01/EWFX)** і **AFF4** із паралельною перевіркою. Доступний у більшості Linux-репозиторіїв (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Специфікація AFF4 v1.0, авторами якої є Bradley L. Schatz і Michael I. Cohen, визначає forensic container із віртуалізованим сховищем, довільними метаданими, розширюваними compression і hashing та високою пропускною здатністю.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

Ви можете [завантажити FTK Imager](https://accessdata.com/product-download) і створювати **raw, E01 або AFF4**-образи:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### Інструменти EWF (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Створення образів хмарних дисків

*AWS* – створіть **forensic snapshot**, не вимикаючи інстанс:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – use `az snapshot create` and export to a SAS URL.


## Монтування

### Вибір правильного підходу

1. Монтуйте **весь диск**, коли потрібна оригінальна таблиця розділів (MBR/GPT).
2. Монтуйте **файл окремого розділу**, коли потрібен лише один том.
3. Залишайте підключені образи доступними лише для читання (наприклад, використовуйте `--read-only` у qemu-nbd).<sup>[[2]](#references)</sup> Монтуйте файлові системи лише для читання (`-o ro`).<sup>[[3]](#references)</sup> Працюйте з **копіями**.

### Raw-образи (вилучені за допомогою dd, AFF4)
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
Від’єднайте після завершення:
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
Для файлових систем зі специфічними монтуваннями без відтворення журналу ext3/ext4 використовують `noload`, тоді як XFS використовує `norecovery` і потребує режиму лише для читання.<sup>[[3]](#references)[[4]](#references)</sup>

Альтернативно, перетворюйте на льоту за допомогою **xmount**:
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

`kpartx` автоматично відображає розділи з образу в `/dev/mapper/`:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Поширені помилки монтування та способи їх виправлення

Для «нечистої» файлової системи ext3/ext4 використовуйте `ro,noload`, якщо потрібно запобігти відтворенню журналу.<sup>[[3]](#references)</sup>

| Помилка | Типова причина | Виправлення |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Файлова система з журналюванням (ext4) некоректно відмонтована | використайте `-o ro,noload` |
| `bad superblock …` | Неправильне зміщення або пошкоджена файлова система | обчисліть зміщення (`sector*size`) або запустіть `fsck -n` на копії |
| `mount: unknown filesystem type 'LVM2_member'` | Контейнер LVM | активуйте volume group за допомогою `vgchange -ay` |

### Очищення

Не забудьте **umount** і **disconnect** loop/nbd-пристрої, щоб не залишати завислі mappings, які можуть пошкодити подальшу роботу:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [Специфікація стандарту AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Документація QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Сторінка посібника Linux для mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Файлова система SGI XFS (документація ядра Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
