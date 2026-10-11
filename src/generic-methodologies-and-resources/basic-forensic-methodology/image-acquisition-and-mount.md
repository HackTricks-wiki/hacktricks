# 이미지 획득 및 마운트

{{#include ../../banners/hacktricks-training.md}}

## 획득

> 항상 **읽기 전용**으로 획득하고 **복사하는 동안 해시를 계산하세요**. 원본 장치는 **쓰기 차단** 상태로 유지하고 검증된 복사본만 사용하세요.

원본 장치의 제조사, 모델, 일련번호, 크기, 도구 및 버전, 타임스탬프, 작업자, 대상, 오류, 획득 및 검증 해시를 기록하세요. 아카이브 이미지와 별도의 작업용 복사본을 보존하세요.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd`는 `dd` 작업 흐름에 실시간 해싱, 출력 검증, 오류 로깅 및 분할 출력을 추가합니다. `hof=`는 해시 검증 출력을 선택하며, `hash=`, `hlog=`, `log=` 및 `bufsz=`는 별도의 인자입니다.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager는 raw/dd, EWF 및 레거시 AFF 출력을 지원하는 Linux용 그래픽 멀티스레드 이미저입니다. **AFF와 AFF4는 서로 다른 형식**이며, Guymager는 AFF4 출력을 지원한다고 안내하지 않습니다. 획득 대화상자에서 SHA-256과 대상 검증을 활성화한 다음 `sudo guymager`로 실행합니다.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

AFF4 v1.0 사양은 가상화된 스토리지, 임의 메타데이터, 확장 가능한 압축 및 해싱, 고처리량 작업을 지원하는 포렌식 컨테이너를 정의합니다.<sup>[[1]](#references)</sup>

정식 C/C++ 구현에서는 `-i`를 소스로, `-o`를 AFF4 볼륨으로 지정합니다. 획득 기준값으로 외부 컨테이너 해시를 생성해 보관합니다.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

현재 FTK Imager 문서에는 해시 검증 기능과 함께 raw/DD, E01 및 AFF 출력이 안내되어 있습니다. AFF 출력을 AFF4로 표기하지 마세요.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF 도구 (libewf)

무인 획득에서는 대상에 `-t`를 사용하고, 케이스 메타데이터에는 `-C/-D/-E/-e`를 사용합니다. `-d sha256`은 SHA-256을 추가하고, `-l`은 획득 오류와 다이제스트를 기록합니다. 분석 전에 완료된 세그먼트 집합을 확인하세요.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Cloud 디스크 이미징

Provider snapshot은 특정 시점의 데이터 수집 소스이지, 자동으로 애플리케이션 일관성이 보장되는 forensic image는 아닙니다. EBS snapshot에는 게스트가 아직 캐시한 데이터가 포함되지 않습니다. 대응 계획상 허용된다면 쓰기를 일시 중지하고, 애플리케이션을 quiesce하거나, 데이터 볼륨을 마운트 해제하거나, 루트 볼륨을 캡처할 인스턴스를 중지하세요.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

EBS 스냅샷을 S3에 간단히 복사할 수 있는 파일로 설명하지 마세요. 볼륨을 생성하지 않고 블록 이미지를 재구성하려면 `ListSnapshotBlocks`로 할당된 블록을 열거하고, `GetSnapshotBlock`으로 각 512 KiB 블록을 가져와 반환된 체크섬을 검증한 다음, 스파스 스냅샷에 없는 블록 인덱스는 0으로 채우세요.<sup>[[14]](#references)</sup>

Azure에서는 스냅샷을 생성하고, 수명이 짧은 **읽기 전용** SAS를 발급한 뒤 VHD를 다운로드하고, 액세스를 취소한 다음 결과의 해시를 계산하세요. 수집 메커니즘이 일관된 시점의 상태를 보장하지 않는 한 각 디스크를 개별적으로 스냅샷하세요.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## 마운트

### 이미지를 신뢰할 수 없는 입력으로 취급하기

악성 파일시스템은 호스트 커널의 파티션 및 파일시스템 파서를 공격할 수 있습니다. QEMU는 신뢰할 수 없는 게스트 이미지를 호스트 NBD에 연결해 마운트하지 말라고 명시적으로 경고하며, libguestfs는 신뢰할 수 없는 게스트 파일시스템을 loop 또는 `kpartx`로 직접 마운트하지 말 것을 권장합니다.<sup>[[2]](#references)[[16]](#references)</sup>

알 수 없거나 공격자가 제어하는 이미지에는 `guestmount`를 사용하는 것이 좋습니다. `guestmount`는 작은 appliance 안에서 게스트를 파싱하고 마운트한 다음, FUSE를 통해 파일을 노출합니다. 자동 감지 대신 알려진 형식을 지정하고 appliance 쪽은 읽기 전용으로 유지하세요.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

검사로 OS를 추론할 수 없는 경우, `-i`를 `-m /dev/sda2`와 같은 명시적인 게스트 장치로 바꾸세요. 암호화된 LUKS 볼륨은 `--key` 선택자를 사용해 지정할 수 있습니다. 키를 셸 기록에 직접 입력하지 마세요.<sup>[[17]](#references)</sup>

### 직접 호스트 마운트 선택

신뢰할 수 있는 이미지나 일회용 분석 VM에서만 직접 호스트 마운트를 사용하세요.

1. 원래 파티션 테이블이 필요한 경우 **전체 디스크**를 마운트하세요.
2. 볼륨 하나만 필요한 경우 **단일 파티션 이미지**를 마운트하세요.
3. 연결을 읽기 전용으로 설정하고 이미지 형식을 강제하세요. 파일 시스템도 읽기 전용으로 마운트하세요. `ro`만으로는 ext3/ext4 저널 재생을 막을 수 없으므로, 변경 사항이 남아 있는 ext 파일 시스템에는 `ro,noload`를 사용하세요.<sup>[[2]](#references)[[3]](#references)</sup>

섹터 크기가 512바이트가 아니거나 파티션 메타데이터가 손상된 경우 `mmls`가 유용합니다. `-b`에는 실제 장치 섹터 크기를 지정합니다. 파티션 및 파일 시스템 분석은 여기서 계속하세요:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Raw 이미지(dd, AFF4에서 추출)

```bash
# Identify partitions without attaching the image
mmls -b 512 disk.img

# Attach a known raw image read-only and force its format
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only --format=raw disk.img
lsblk /dev/nbd0 -o NAME,SIZE,RO,TYPE,FSTYPE,LABEL,UUID

# Example ext4 partition: prevent journal replay
sudo mount -o ro,noload /dev/nbd0p2 /mnt/evidence
```

완료되면 분리하세요:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

qcow2, VMDK 또는 VHD/VHDX의 경우 신뢰할 수 있는 출처를 통해 형식을 확인하거나 격리된 분석 VM 내부에서 검사한 다음, `--format=raw`를 명시적인 형식으로 바꾸세요. 신뢰할 수 없는 입력에 대해 호스트 측 형식 자동 감지에 의존하지 마세요.<sup>[[2]](#references)</sup>

### EWF (E01/EWFX)

```bash
# Verify, then expose the embedded raw media stream
mkdir -p /mnt/ewf /mnt/evidence
ewfverify evidence.E01
ewfmount evidence.E01 /mnt/ewf

# ewf1 is raw media data; attach it explicitly as raw and read-only
sudo qemu-nbd --connect=/dev/nbd1 --read-only --format=raw /mnt/ewf/ewf1
# Example XFS partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```

파일시스템별 no-replay 마운트의 경우 ext3/ext4는 `noload`를 사용하고, XFS는 `norecovery`를 사용하며 읽기 전용 모드가 필요합니다.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount`는 가상 raw 뷰를 제공할 수 있지만, 이 뷰에도 원래 파티션 테이블이 포함되어 있습니다. 전체 디스크 파일을 파일시스템으로 마운트하는 대신, 동일한 `mmls`, 격리된 `guestmount` 또는 읽기 전용 NBD 워크플로에 전달하세요.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker 볼륨

두 계층 모두에서 읽기 전용 모드를 사용하세요. 값 없이 `-u`를 지정하면 암호를 입력하라는 메시지가 표시되므로, 암호가 프로세스 인수나 셸 기록에 남지 않습니다.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

LUKS 또는 LVM의 경우 `guestmount -i --ro`를 우선 사용하세요. 해당 appliance는 호스트에서 외부 볼륨 그룹을 활성화하지 않고도 일반적인 암호화 및 논리 볼륨 레이아웃을 검사할 수 있습니다.<sup>[[17]](#references)</sup>

### kpartx helpers

`kpartx`는 호스트의 device-mapper 노드를 생성하므로 신뢰할 수 없는 이미지에는 적합하지 않습니다. 직접 매핑해야 한다면 `-r`을 추가해 파티션 매핑을 읽기 전용으로 만들고, 매핑을 제거할 때는 생성에 사용한 것과 동일한 이미지 경로를 전달하세요.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### 일반적인 mount 오류 및 해결 방법

| 오류 | 일반적인 원인 | 안전한 다음 단계 |
|-------|---------------|----------------|
| `cannot mount ... read-only` | 저널이 기록된 파일시스템이 dirty 상태임 | ext4의 `ro,noload`처럼 파일시스템별 no-replay 옵션 사용 |
| `bad superblock ...` | 파티션/섹터 오프셋이 잘못되었거나 파일시스템이 손상됨 | `mmls`로 섹터 크기와 오프셋을 확인하고, 검증된 복사본에만 `fsck -n` 실행 |
| `unknown filesystem type 'LVM2_member'` | 선택한 파티션이 LVM physical volume임 | libguestfs가 검사하도록 하거나, 폐기 가능한 VM에서 수동 LVM 활성화를 격리 |

### 정리

기반 장치의 연결을 해제하기 전에 파일시스템을 unmount하세요. EWF/xmount용 FUSE 계층과 생성한 crypt 또는 device-mapper 매핑도 제거하세요:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [AFF4 표준 사양 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [QEMU qemu-nbd 문서](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [mount(8) Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [SGI XFS 파일 시스템 (Linux 커널 문서)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [디지털 증거 수집을 위한 SWGDE 모범 사례](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [컴퓨터 포렌식 획득을 위한 SWGDE 모범 사례](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [dc3dd(1) 매뉴얼 페이지](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Guymager 홈페이지 및 설정 문서](https://guymager.sourceforge.io/)
- [9] [c-aff4 문서](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Exterro FTK Imager 형식 및 검증](https://www.exterro.com/digital-forensics-software)
- [11] [libewf ewfacquire(1) 매뉴얼](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [libewf ewfverify(1) 매뉴얼](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Amazon EBS 스냅샷 생성](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [EBS direct APIs로 Amazon EBS 스냅샷 읽기](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Azure CLI 스냅샷 참조](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [libguestfs 보안](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
