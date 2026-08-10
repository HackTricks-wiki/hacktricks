# Disk İmajı Edinme ve Bağlama

## Edinme

> Her zaman **salt okunur** olarak edinin ve **kopyalama sırasında hash hesaplayın**. Orijinal cihazı **yazmaya karşı engelli** tutun ve yalnızca doğrulanmış kopyalar üzerinde çalışın.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`, dcfldd'nin (DoD Computer Forensics Lab dd) aktif olarak sürdürülen fork'udur.
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
**raw (dd)**, **EWF (E01/EWFX)** ve **AFF4** çıktısını paralel doğrulamayla destekleyen grafiksel, çok iş parçacıklı imaj alma aracı. Çoğu Linux deposunda kullanılabilir (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

Bradley L. Schatz ve Michael I. Cohen tarafından kaleme alınan AFF4 v1.0 specification, sanallaştırılmış depolama, rastgele metadata, genişletilebilir compression ve hashing ile yüksek throughput sağlayan bir forensic container tanımlar.<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

[FTK Imager'ı indirebilir](https://accessdata.com/product-download) ve **raw, E01 veya AFF4** imajları oluşturabilirsiniz:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF araçları (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Cloud Disk Görüntüleme

*AWS* – instance'ı kapatmadan bir **forensic snapshot** oluşturun:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create` kullanın ve bir SAS URL'ye aktarın.


## Bağlama

### Doğru yaklaşımı seçme

1. Orijinal bölümleme tablosunu (MBR/GPT) istediğinizde **tüm diski** bağlayın.
2. Yalnızca bir volume gerektiğinde **tek bir bölüm dosyasını** bağlayın.
3. Image eklerini salt okunur tutun (örneğin, qemu-nbd'nin `--read-only` seçeneğiyle).<sup>[[2]](#references)</sup> Filesystem'leri salt okunur olarak bağlayın (`-o ro`).<sup>[[3]](#references)</sup> **Kopyalar** üzerinde çalışın.

### Raw images (dd, AFF4-extracted)
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
Çevrilecek metni paylaşın.
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
Dosya sistemi özel no-replay mount'ları için ext3/ext4 `noload` kullanırken XFS `norecovery` kullanır ve salt okunur mod gerektirir.<sup>[[3]](#references)[[4]](#references)</sup>

Alternatif olarak **xmount** ile anında dönüştürün:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt birimleri

Block device'i (loop veya nbd) bağladıktan sonra:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx yardımcıları

`kpartx`, bir image içindeki partition'ları otomatik olarak `/dev/mapper/` konumuna map eder:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### Yaygın mount hataları ve düzeltmeleri

Dirty bir ext3/ext4 filesystem için journal replay işleminin engellenmesi gerektiğinde `ro,noload` kullanın.<sup>[[3]](#references)</sup>

| Hata | Yaygın Neden | Düzeltme |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | Journal kullanan FS (ext4) düzgün şekilde unmount edilmemiş | `-o ro,noload` kullanın |
| `bad superblock …` | Yanlış offset veya hasarlı FS | offset'i hesaplayın (`sector*size`) veya bir kopya üzerinde `fsck -n` çalıştırın |
| `mount: unknown filesystem type 'LVM2_member'` | LVM container | `vgchange -ay` ile volume group'u etkinleştirin |

### Temizleme

Daha sonraki çalışmaları bozabilecek dangling mapping'ler bırakmamak için **umount** işlemini gerçekleştirmeyi ve loop/nbd device'larını **disconnect** etmeyi unutmayın:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd documentation](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [The SGI XFS filesystem (Linux kernel documentation)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
{{#include ../../banners/hacktricks-training.md}}
