# 이미지 수집 및 마운트

{{#include ../../banners/hacktricks-training.md}}


## 수집

> 항상 **읽기 전용**으로 수집하고 **복사하는 동안 해시를 생성**하세요. 원본 장치는 **쓰기 차단** 상태로 유지하고 검증된 복사본에서만 작업하세요.

### DD
```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```
### dc3dd / dcfldd

`dc3dd`는 dcfldd(DoD Computer Forensics Lab dd)의 적극적으로 유지 관리되는 포크입니다.
```bash
# Create an image and calculate multiple hashes at acquisition time
sudo dc3dd if=/dev/sdc of=/forensics/pc.img hash=sha256,sha1 hashlog=/forensics/pc.hashes log=/forensics/pc.log bs=1M
```
### Guymager
그래픽, 멀티스레드 이미저로 **raw (dd)**, **EWF (E01/EWFX)** 및 **AFF4** 출력을 지원하며 병렬 검증이 가능합니다. 대부분의 Linux 저장소에서 사용 가능 (`apt install guymager`).
```bash
# Start in GUI mode
sudo guymager
# Or acquire from CLI (since v0.9.5)
sudo guymager --simulate --input /dev/sdb --format EWF --hash sha256 --output /evidence/drive.e01
```
### AFF4 (Advanced Forensics Format 4)

AFF4는 *매우* 큰 증거(희소, 재개 가능, 클라우드 네이티브)를 위해 설계된 Google의 현대적인 이미지 형식입니다.
```bash
# Acquire to AFF4 using the reference tool
pipx install aff4imager
sudo aff4imager acquire /dev/nvme0n1 /evidence/nvme.aff4 --hash sha256

# Velociraptor can also acquire AFF4 images remotely
velociraptor --config server.yaml frontend collect --artifact Windows.Disk.Acquire --args device="\\.\\PhysicalDrive0" format=AFF4
```
### FTK Imager (Windows & Linux)

You can [download FTK Imager](https://accessdata.com/product-download) and create **raw, E01 or AFF4** images:
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
--description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```
### EWF 도구 (libewf)
```bash
sudo ewfacquire /dev/sdb -u evidence -c 1 -d "Seizure 2025-07-22" -e 1 -X examiner --format encase6 --compression best
```
### Imaging Cloud Disks

*AWS* – 인스턴스를 종료하지 않고 **포렌식 스냅샷**을 생성합니다:
```bash
aws ec2 create-snapshot --volume-id vol-01234567 --description "IR-case-1234 web-server 2025-07-22"
# Copy the snapshot to S3 and download with aws cli / aws snowball
```
*Azure* – `az snapshot create`를 사용하고 SAS URL로 내보냅니다.


## 마운트

### 올바른 접근 방식 선택

1. 원본 파티션 테이블(MBR/GPT)이 필요할 때 **전체 디스크**를 마운트합니다.
2. 하나의 볼륨만 필요할 때 **단일 파티션 파일**을 마운트합니다.
3. 항상 **읽기 전용**(`-o ro,norecovery`)으로 마운트하고 **복사본**에서 작업합니다.

### 원시 이미지 (dd, AFF4 추출)
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
완료되면 분리하십시오:
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
대신 **xmount**를 사용하여 실시간으로 변환합니다:
```bash
xmount --in ewf evidence.E01 --out raw /tmp/raw_mount
mount -o ro /tmp/raw_mount/image.dd /mnt
```
### LVM / BitLocker / VeraCrypt 볼륨

블록 장치(루프 또는 nbd)를 연결한 후:
```bash
# LVM
sudo vgchange -ay               # activate logical volumes
sudo lvscan | grep "/dev/nbd0"

# BitLocker (dislocker)
sudo dislocker -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/evidence
```
### kpartx 헬퍼

`kpartx`는 이미지를 `/dev/mapper/`에 자동으로 매핑합니다:
```bash
sudo kpartx -av disk.img  # creates /dev/mapper/loop0p1, loop0p2 …
mount -o ro /dev/mapper/loop0p2 /mnt
```
### 일반적인 마운트 오류 및 수정

| 오류 | 일반적인 원인 | 수정 |
|-------|---------------|-----|
| `cannot mount /dev/loop0 read-only` | 저널링 파일 시스템 (ext4)이 정상적으로 분리되지 않음 | `-o ro,norecovery` 사용 |
| `bad superblock …` | 잘못된 오프셋 또는 손상된 파일 시스템 | 오프셋 계산 (`sector*size`) 또는 복사본에서 `fsck -n` 실행 |
| `mount: unknown filesystem type 'LVM2_member'` | LVM 컨테이너 | `vgchange -ay`로 볼륨 그룹 활성화 |

### 정리

**umount** 및 **disconnect** 루프/nbd 장치를 기억하여 추가 작업을 손상시킬 수 있는 남아 있는 매핑을 남기지 않도록 하십시오:
```bash
umount -Rl /mnt/evidence
kpartx -dv /dev/loop0  # or qemu-nbd --disconnect /dev/nbd0
```
## References

- AFF4 imaging tool announcement & specification: https://github.com/aff4/aff4
- qemu-nbd 매뉴얼 페이지 (디스크 이미지를 안전하게 마운트하기): https://manpages.debian.org/qemu-system-common/qemu-nbd.1.en.html

{{#include ../../banners/hacktricks-training.md}}
