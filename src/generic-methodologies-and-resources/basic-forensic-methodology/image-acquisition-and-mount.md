# 이미지 수집 및 마운트

{{#include ../../banners/hacktricks-training.md}}


## 수집

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

You can [**여기에서 FTK 이미저를 다운로드하세요**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

디스크 이미지를 생성하려면 [**ewf tools**](https://github.com/libyal/libewf)를 사용할 수 있습니다.
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## 마운트

### 여러 유형

**Windows**에서는 Arsenal Image Mounter의 무료 버전을 사용하여 **포렌식 이미지를 마운트**할 수 있습니다.
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

Windows 애플리케이션으로 볼륨을 마운트합니다. 여기에서 다운로드할 수 있습니다 [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Errors

- **`cannot mount /dev/loop0 read-only`** 이 경우 플래그 **`-o ro,norecovery`**를 사용해야 합니다.
- **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** 이 경우 마운트가 실패한 이유는 파일 시스템의 오프셋이 디스크 이미지의 오프셋과 다르기 때문입니다. 섹터 크기와 시작 섹터를 찾아야 합니다:
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
섹터 크기는 **512**이고 시작은 **2048**임을 유의하십시오. 그런 다음 이미지를 다음과 같이 마운트하십시오:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
{{#include ../../banners/hacktricks-training.md}}
