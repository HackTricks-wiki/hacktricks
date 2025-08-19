# 图像获取与挂载

{{#include ../../banners/hacktricks-training.md}}


## 获取

> 始终进行 **只读** 获取并 **在复制时进行哈希**。保持原始设备 **写保护**，仅在经过验证的副本上工作。

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd` 是 dcfldd (DoD 计算机取证实验室 dd) 的积极维护分支。
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
图形化的多线程成像工具，支持 **raw (dd)**、**EWF (E01/EWFX)** 和 **AFF4** 输出，并具有并行验证功能。可在大多数 Linux 仓库中获取（`apt install guymager`）。
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (高级取证格式 4)

AFF4 是谷歌为 *非常* 大的证据（稀疏、可恢复、云原生）设计的现代成像格式。
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

您可以 [下载 FTK Imager](https://accessdata.com/product-download) 并创建 **raw, E01 或 AFF4** 镜像：
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF工具 (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – 创建一个 **forensic snapshot** 而无需关闭实例：
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – 使用 `az snapshot create` 并导出到 SAS URL。

## 挂载

### 选择正确的方法

1. 当您需要原始分区表 (MBR/GPT) 时，挂载 **整个磁盘**。
2. 当您只需要一个卷时，挂载 **单个分区文件**。
3. 始终以 **只读** 模式挂载 (`-o ro,norecovery`) 并在 **副本** 上工作。

### 原始图像 (dd, AFF4-extracted)
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
完成后分离：
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
或者使用 **xmount** 进行实时转换：
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt 卷

在附加块设备（loop 或 nbd）后：
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx` 自动将映像中的分区映射到 `/dev/mapper/`：
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### 常见挂载错误及修复

| 错误 | 典型原因 | 修复 |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | 日志文件系统 (ext4) 未干净卸载 | 使用 `-o ro,norecovery` |
| `bad superblock …` | 错误的偏移量或损坏的文件系统 | 计算偏移量 (`sector*size`) 或在副本上运行 `fsck -n` |
| `mount: unknown filesystem type 'LVM2_member'` | LVM 容器 | 使用 `vgchange -ay` 激活卷组 |

### 清理

记得 **umount** 和 **disconnect** 循环/nbd 设备，以避免留下可能会损坏后续工作的悬挂映射：
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## 参考

- AFF4 成像工具公告与规格: https://github.com/aff4/aff4
- qemu-nbd 手册页（安全挂载磁盘映像）: https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
