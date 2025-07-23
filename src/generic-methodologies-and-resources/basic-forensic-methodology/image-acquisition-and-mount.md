# Görüntü Edinimi & Montaj

{{#include ../../banners/hacktricks-training.md}}


## Edinim

> Her zaman **salt okunur** edinim yapın ve **kopyalarken hash alın**. Orijinal cihazı **yazma engelli** tutun ve yalnızca doğrulanmış kopyalar üzerinde çalışın.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`, dcfldd (DoD Bilgisayar Adli Bilimler Laboratuvarı dd) için aktif olarak sürdürülen bir çatallamadır.
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
Grafiksel, çok iş parçacıklı bir imajlayıcıdır ve **raw (dd)**, **EWF (E01/EWFX)** ve **AFF4** çıktısını paralel doğrulama ile destekler. Çoğu Linux deposunda mevcuttur (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Gelişmiş Adli Format 4)

AFF4, *çok* büyük kanıtlar (dağınık, devam edilebilir, bulut yerel) için tasarlanmış Google'ın modern görüntüleme formatıdır.
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

FTK Imager'ı [indirip](https://accessdata.com/product-download) **ham, E01 veya AFF4** görüntüleri oluşturabilirsiniz:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF araçları (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Bulut Disklerinin Görüntülenmesi

*AWS* – örneği kapatmadan **adli anlık görüntü** oluşturun:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create` komutunu kullanın ve bir SAS URL'sine dışa aktarın. HackTricks sayfasına bakın {{#ref}}
../../cloud/azure/azure-forensics.md
{{#endref}}


## Mount

### Doğru yaklaşımı seçme

1. Orijinal bölüm tablosunu (MBR/GPT) istediğinizde **tüm diski** bağlayın.
2. Sadece bir hacme ihtiyacınız olduğunda **tek bir bölüm dosyasını** bağlayın.
3. Her zaman **salt okunur** (`-o ro,norecovery`) olarak bağlayın ve **kopyalar** üzerinde çalışın.

### Ham görüntüler (dd, AFF4 çıkarılmış)
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
Tamamlandığında ayırın:
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
Alternatif olarak **xmount** ile anında dönüştürün:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt hacimleri

Blok cihazı (loop veya nbd) bağlandıktan sonra:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx yardımcıları

`kpartx`, bir görüntüden bölümleri otomatik olarak `/dev/mapper/`'a haritalar:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Yayın hataları ve çözümleri

| Hata | Tipik Sebep | Çözüm |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journaled FS (ext4) düzgün bir şekilde çıkarılmamış | `-o ro,norecovery` kullanın |
| `bad superblock …` | Yanlış offset veya hasarlı FS | offset'i hesaplayın (`sector*size`) veya bir kopya üzerinde `fsck -n` çalıştırın |
| `mount: unknown filesystem type 'LVM2_member'` | LVM konteyneri | `vgchange -ay` ile hacim grubunu etkinleştirin |

### Temizlik

Daha fazla çalışmayı bozabilecek sarkan eşlemeleri bırakmamak için **umount** ve **disconnect** loop/nbd cihazlarını unutmayın:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## Referanslar

- AFF4 görüntüleme aracı duyurusu ve spesifikasyonu: https://github.com/aff4/aff4
- qemu-nbd kılavuz sayfası (disk görüntülerini güvenli bir şekilde bağlama): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
