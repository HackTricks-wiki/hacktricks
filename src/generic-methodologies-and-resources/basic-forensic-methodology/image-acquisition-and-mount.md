# 이미지 획득 및 마운트

{{#include ../../banners/hacktricks-training.md}}


## 획득

> 항상 **읽기 전용**으로 획득하고, **복사하는 동안 해시를 계산**하세요. 원본 장치는 **쓰기 차단** 상태로 유지하고, 검증된 복사본만 사용하세요.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`는 dcfldd(DoD Computer Forensics Lab dd)의 actively maintained fork입니다.
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
**raw (dd)**, **EWF (E01/EWFX)** 및 **AFF4** 출력을 지원하고 병렬 검증이 가능한 그래픽 기반 멀티스레드 이미저입니다. 대부분의 Linux 저장소에서 사용할 수 있습니다 (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4는 *매우* 큰 증거를 위해 설계된 Google의 최신 imaging format입니다(sparse, resumable, cloud-native).<sup>[[1]](#references)</sup>
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

[FTK Imager를 다운로드](https://accessdata.com/product-download)하여 **raw, E01 또는 AFF4** 이미지를 생성할 수 있습니다:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF 도구 (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Cloud 디스크 이미징

*AWS* – 인스턴스를 종료하지 않고 **forensic snapshot**을 생성합니다:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create`를 사용하고 SAS URL로 export합니다.


## 마운트

### 적절한 접근 방식 선택

1. 원본 partition table(MBR/GPT)이 필요하면 **whole disk**를 마운트합니다.
2. 하나의 volume만 필요하면 **single partition file**을 마운트합니다.
3. 항상 **read-only**(`-o ro,norecovery`)로 마운트하고 **copies**에서 작업합니다.<sup>[[2]](#references)</sup>

### Raw 이미지(dd, AFF4-extracted)
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
완료되면 분리:
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
또는 **xmount**를 사용해 즉석에서 변환합니다:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt volumes

block device (loop 또는 nbd)를 연결한 후:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx helpers

`kpartx`는 image의 partition을 자동으로 `/dev/mapper/`에 매핑합니다:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### 일반적인 mount 오류 및 해결 방법

| 오류 | 일반적인 원인 | 해결 방법 |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | 저널링 FS (ext4)가 정상적으로 unmount되지 않음 | `-o ro,norecovery` 사용 |
| `bad superblock …` | 잘못된 offset 또는 손상된 FS | offset 계산 (`sector*size`) 또는 복사본에서 `fsck -n` 실행 |
| `mount: unknown filesystem type 'LVM2_member'` | LVM 컨테이너 | `vgchange -ay`로 volume group 활성화 |

### 정리

추가 작업을 손상시킬 수 있는 dangling mapping이 남지 않도록 loop/nbd devices를 **umount**하고 **disconnect**해야 합니다:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## 참조

- [1] [AFF4 Standard Specification (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [qemu-nbd manual page (mounting disk images safely)](https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html)

{{#include ../../banners/hacktricks-training.md}}
