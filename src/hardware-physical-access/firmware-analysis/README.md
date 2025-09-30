# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

## **소개**

### 관련 자료


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 사이의 통신을 관리하고 장치가 올바르게 동작하도록 하는 필수 소프트웨어입니다. 영구 메모리에 저장되어 전원이 켜지는 순간부터 장치가 중요한 명령을 접근할 수 있게 하며 운영체제의 부팅으로 이어집니다. 펌웨어를 조사하고 잠재적으로 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치의 구성과 사용되는 기술을 이해하는 데 있어 중요한 초기 단계입니다. 이 과정은 다음 항목에 대한 데이터를 수집하는 것을 포함합니다:

- CPU 아키텍처와 실행되는 운영 체제
- Bootloader 세부사항
- 하드웨어 배치 및 데이터시트
- 코드베이스 메트릭과 소스 위치
- 외부 라이브러리와 라이선스 유형
- 업데이트 이력과 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가 및 식별된 취약점

이를 위해 **오픈 소스 인텔리전스 (OSINT)** 도구와 수동 및 자동 검토 프로세스를 통한 사용 가능한 오픈 소스 소프트웨어 구성요소의 분석이 매우 중요합니다. Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) offer free static analysis that can be leveraged to find potential issues.

## **펌웨어 입수**

펌웨어를 획득하는 방법은 각기 다른 복잡성을 지닌 여러 방식으로 접근할 수 있습니다:

- **직접** 출처(개발자, 제조사)로부터
- 제공된 지침으로 **빌드**하여
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위한 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner) 같은 도구로 **cloud storage** 직접 접근
- 업데이트를 **가로채기** 위한 **man-in-the-middle** 기법 활용
- **UART**, **JTAG**, 또는 **PICit** 같은 연결을 통해 기기에서 **추출**
- 장치 통신 내에서 업데이트 요청을 **스니핑**
- 하드코딩된 업데이트 엔드포인트 식별 및 사용
- 부트로더나 네트워크에서 **덤프**
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용해 저장 칩을 **제거하고 읽기**

## 펌웨어 분석

이제 **펌웨어를 확보했으므로**, 어떻게 다룰지 알기 위해 펌웨어에 대한 정보를 추출해야 합니다. 사용할 수 있는 다양한 도구들이 있습니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
만약 그 도구들로 많은 것을 찾지 못했다면 `binwalk -E <bin>`로 이미지의 **엔트로피**를 확인하세요. 엔트로피가 낮으면 암호화되어 있을 가능성은 낮습니다. 엔트로피가 높으면 암호화되었거나(또는 어떤 방식으로든 압축되어) 있을 가능성이 큽니다.

또한, 이러한 도구들로 **firmware 내부에 포함된 파일들**을 추출할 수 있습니다:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Filesystem 가져오기

앞서 언급한 도구들(예: `binwalk -ev <bin>`)으로 **filesystem을 추출**했어야 합니다.\
Binwalk는 보통 이를 **filesystem 유형의 이름을 가진 폴더** 안에 추출하며, 일반적으로 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 Filesystem 추출

가끔 binwalk는 signature에 filesystem의 **magic byte**를 포함하고 있지 않을 수 있습니다. 이런 경우에는 binwalk로 filesystem의 오프셋을 찾아 바이너리에서 압축된 filesystem을 carve하고 해당 유형에 맞게 아래 단계에 따라 **수동으로 filesystem을 추출**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd command**를 실행하여 Squashfs filesystem을 추출하세요.
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

파일은 이후 `squashfs-root` 디렉터리에 있습니다.

- CPIO 아카이브 파일의 경우

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND flash가 있는 ubifs 파일시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 확보한 후에는 그 구조와 잠재적 취약점을 이해하기 위해 분해하는 것이 중요합니다. 이 과정은 펌웨어 이미지에서 유용한 데이터를 분석하고 추출하기 위해 다양한 도구를 활용하는 것을 포함합니다.

### 초기 분석 도구

바이너리 파일(이하 `<bin>`)의 초기 검사에 사용할 수 있는 명령들이 제공됩니다. 이 명령들은 파일 타입을 식별하고, 문자열을 추출하며, 이진 데이터를 분석하고, 파티션 및 파일시스템 세부사항을 이해하는 데 도움을 줍니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해, **entropy**는 `binwalk -E <bin>`로 확인합니다. 낮은 **entropy**는 암호화가 없음을 시사하고, 높은 **entropy**는 암호화 또는 압축 가능성을 나타냅니다.

임베디드 파일(**embedded files**)을 추출하기 위해서는 파일 검사용 **file-data-carving-recovery-tools** 문서와 **binvis.io** 같은 도구 및 리소스를 권장합니다.

### 파일 시스템 추출

`binwalk -ev <bin>`를 사용하면 일반적으로 파일 시스템을 추출할 수 있으며, 종종 파일 시스템 타입 이름(예: squashfs, ubifs)으로 된 디렉터리에 추출됩니다. 그러나 **binwalk**가 magic bytes 누락으로 인해 파일 시스템 타입을 인식하지 못하는 경우 수동 추출이 필요합니다. 이는 `binwalk`로 파일 시스템의 오프셋을 찾은 다음 `dd` 명령으로 파일 시스템을 추출하는 과정을 포함합니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
이후에는 파일시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하기 위해 서로 다른 명령이 사용됩니다.

### Filesystem Analysis

파일시스템을 추출한 후에는 보안 결함을 찾기 시작합니다. 안전하지 않은 네트워크 데몬, 하드코딩된 자격증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트 및 오프라인 분석을 위한 컴파일된 바이너리에 주의를 기울입니다.

**검사해야 할 주요 위치** 및 **항목**은 다음과 같습니다:

- **etc/shadow** 및 **etc/passwd** (사용자 자격증명 확인용)
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점을 찾아볼 설정 및 스크립트 파일
- 추가 분석을 위한 임베디드 바이너리
- 일반적인 IoT 장치의 웹 서버 및 바이너리

파일시스템 내에서 민감한 정보와 취약점을 발견하는 데 도움이 되는 여러 도구가 있습니다:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker) (민감한 정보 검색용)
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) (종합적인 펌웨어 분석용)
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba) (정적 및 동적 분석용)

### Security Checks on Compiled Binaries

파일시스템에서 발견된 소스 코드와 컴파일된 바이너리는 모두 취약점에 대해 면밀히 검토되어야 합니다. Unix 바이너리용 **checksec.sh**와 Windows 바이너리용 **PESecurity** 같은 도구는 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움을 줍니다.

## Emulating Firmware for Dynamic Analysis

펌웨어를 에뮬레이션하는 과정은 장치의 동작이나 개별 프로그램에 대한 동적 분석을 가능하게 합니다. 이 접근법은 하드웨어나 아키텍처 종속성으로 인해 어려움이 있을 수 있으나, Raspberry Pi와 같이 아키텍처 및 엔디안이 일치하는 장치로 루트 파일시스템이나 특정 바이너리를 옮기거나 사전 구성된 가상 머신으로 옮기면 추가 테스트를 용이하게 할 수 있습니다.

### Emulating Individual Binaries

단일 프로그램을 검사할 때는 해당 프로그램의 엔디안과 CPU 아키텍처를 식별하는 것이 중요합니다.

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

#### ARM Architecture Emulation

ARM 바이너리의 경우 절차는 유사하며, 에뮬레이션을 위해 `qemu-arm` 에뮬레이터를 사용합니다.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

이 단계에서는 실제 디바이스 환경이나 에뮬레이션된 환경 중 하나를 사용해 분석을 수행합니다. OS와 파일시스템에 대한 shell 접근을 유지하는 것이 중요합니다. 에뮬레이션은 하드웨어 상호작용을 완벽히 모사하지 못할 수 있어 가끔 에뮬레이션을 재시작해야 할 필요가 있습니다. 분석 시 파일시스템을 다시 살펴보고, 노출된 웹페이지와 네트워크 서비스를 조사하며, 부트로더(bootloader) 취약점을 탐색해야 합니다. 펌웨어 무결성 검사는 잠재적인 백도어 취약점을 식별하는 데 중요합니다.

## Runtime Analysis Techniques

런타임 분석은 프로세스나 바이너리를 해당 운영 환경에서 상호작용하며 검사하는 것을 의미합니다. 중단점 설정과 취약점 식별을 위해 gdb-multiarch, Frida, Ghidra 같은 도구를 사용하고, fuzzing 등 기법으로 취약점을 찾아냅니다.

## Binary Exploitation and Proof-of-Concept

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어로의 프로그래밍 능력이 필요합니다. 임베디드 시스템에서는 바이너리 런타임 보호가 드물지만, 존재하는 경우 Return Oriented Programming (ROP) 같은 기법이 필요할 수 있습니다.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 Internet of Things (IoT) 디바이스의 security assessment 및 penetration testing을 수행하는 데 도움을 주기 위해 설계된 배포판입니다. 필요한 도구들이 미리 구성된 환경을 제공하여 많은 시간을 절약해 줍니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 기반의 임베디드 보안 테스트 운영체제로, 펌웨어 보안 테스트 도구들이 사전 탑재되어 있습니다.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

벤더가 펌웨어 이미지에 대해 암호화 서명 검사를 구현하더라도, **버전 롤백(version rollback, downgrade) 보호가 종종 누락됩니다**. 부트로더나 복구 로더가 내장된 공개키로 서명만 검증하고 플래시되는 이미지의 *버전*(또는 단조 증가 카운터)을 비교하지 않으면, 공격자는 합법적으로 유효한 서명을 가진 **이전의 취약한 펌웨어를 설치**하여 패치된 취약점을 다시 도입할 수 있습니다.

Typical attack workflow:

1. **Obtain an older signed image**
* 벤더의 공개 다운로드 포털, CDN 또는 지원 사이트에서 가져옵니다.
* 동반 모바일/데스크탑 애플리케이션에서 추출(예: Android APK 내부의 `assets/firmware/`)합니다.
* VirusTotal, 인터넷 아카이브, 포럼 등 제3자 저장소에서 확보합니다.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* 많은 소비자용 IoT 디바이스는 *unauthenticated* HTTP(S) 엔드포인트를 노출하여 Base64-encoded 펌웨어 블롭을 수신하고 서버 측에서 디코딩한 뒤 복구/업그레이드를 트리거합니다.
3. 다운그레이드 후, 최신 릴리스에서 패치된 취약점을 악용합니다(예: 나중에 추가된 command-injection filter 우회).
4. 선택적으로 최신 이미지를 다시 플래시하거나 업데이트를 비활성화하여 지속성을 확보한 후 탐지를 피합니다.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
취약한(다운그레이드된) 펌웨어에서는 `md5` 파라미터가 입력 검증 없이 쉘 명령에 직접 연결되어 임의 명령을 주입할 수 있게 하며(여기서는 SSH 키 기반의 root 접근을 허용), 이후 펌웨어 버전에서 기본적인 문자 필터가 도입되었지만 다운그레이드 보호가 없어 해당 수정은 무의미해진다.

### 모바일 앱에서 펌웨어 추출하기

많은 벤더는 동반 모바일 애플리케이션 안에 전체 펌웨어 이미지를 번들로 포함시켜 앱이 Bluetooth/Wi-Fi를 통해 장치를 업데이트할 수 있도록 한다. 이러한 패키지는 일반적으로 APK/APEX의 `assets/fw/` 또는 `res/raw/` 같은 경로에 암호화되지 않은 상태로 저장된다. `apktool`, `ghidra`, 또는 단순한 `unzip` 같은 도구로 물리적 하드웨어에 손대지 않고 서명된 이미지를 추출할 수 있다.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### 업데이트 로직 평가를 위한 체크리스트

* *update endpoint*의 전송/인증이 충분히 보호되어 있는가 (TLS + authentication)?
* 플래싱 전에 **version numbers** 또는 **monotonic anti-rollback counter**를 비교하는가?
* 이미지가 secure boot chain 내부에서 검증되는가(예: ROM 코드에서 signatures를 확인)?
* userland 코드가 추가적인 sanity 검사(예: 허용되는 partition map, model number)를 수행하는가?
* *partial* 또는 *backup* 업데이트 흐름이 동일한 validation logic을 재사용하는가?

> 💡  위 항목들 중 하나라도 누락되어 있다면, 플랫폼은 아마 rollback attacks에 취약할 것입니다.

## Vulnerable firmware 연습용

firmware에서 취약점을 발견하는 연습을 하려면, 다음의 취약한 firmware 프로젝트들을 시작점으로 사용하세요.

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

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## 교육 및 인증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
