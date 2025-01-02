# 펌웨어 분석

{{#include ../../banners/hacktricks-training.md}}

## **소개**

펌웨어는 하드웨어 구성 요소와 사용자가 상호작용하는 소프트웨어 간의 통신을 관리하고 촉진하여 장치가 올바르게 작동하도록 하는 필수 소프트웨어입니다. 이는 영구 메모리에 저장되어 장치가 전원이 켜지는 순간부터 중요한 지침에 접근할 수 있도록 하여 운영 체제가 시작됩니다. 펌웨어를 조사하고 잠재적으로 수정하는 것은 보안 취약점을 식별하는 데 중요한 단계입니다.

## **정보 수집**

**정보 수집**은 장치의 구성과 사용되는 기술을 이해하는 데 중요한 초기 단계입니다. 이 과정은 다음에 대한 데이터를 수집하는 것을 포함합니다:

- CPU 아키텍처 및 운영 체제
- 부트로더 세부사항
- 하드웨어 레이아웃 및 데이터시트
- 코드베이스 메트릭 및 소스 위치
- 외부 라이브러리 및 라이센스 유형
- 업데이트 이력 및 규제 인증
- 아키텍처 및 흐름 다이어그램
- 보안 평가 및 식별된 취약점

이 목적을 위해 **오픈 소스 정보(OSINT)** 도구는 매우 유용하며, 수동 및 자동 검토 프로세스를 통해 사용 가능한 오픈 소스 소프트웨어 구성 요소를 분석하는 것도 중요합니다. [Coverity Scan](https://scan.coverity.com) 및 [Semmle의 LGTM](https://lgtm.com/#explore)과 같은 도구는 잠재적인 문제를 찾기 위해 활용할 수 있는 무료 정적 분석을 제공합니다.

## **펌웨어 획득**

펌웨어를 얻는 방법은 여러 가지가 있으며, 각 방법마다 복잡성의 수준이 다릅니다:

- **소스**(개발자, 제조업체)에서 직접
- 제공된 지침에 따라 **구축**
- 공식 지원 사이트에서 **다운로드**
- 호스팅된 펌웨어 파일을 찾기 위한 **Google dork** 쿼리 활용
- [S3Scanner](https://github.com/sa7mon/S3Scanner)와 같은 도구를 사용하여 **클라우드 스토리지**에 직접 접근
- 중간자 공격 기법을 통해 **업데이트** 가로채기
- **UART**, **JTAG** 또는 **PICit**와 같은 연결을 통해 장치에서 **추출**
- 장치 통신 내에서 업데이트 요청을 **스니핑**
- **하드코딩된 업데이트 엔드포인트** 식별 및 사용
- 부트로더 또는 네트워크에서 **덤프**
- 모든 방법이 실패할 경우 적절한 하드웨어 도구를 사용하여 저장 칩을 **제거하고 읽기**

## 펌웨어 분석

이제 **펌웨어를 확보**했으므로, 이를 처리하는 방법을 알기 위해 정보를 추출해야 합니다. 이를 위해 사용할 수 있는 다양한 도구:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
해당 도구로 많은 것을 찾지 못한 경우, `binwalk -E <bin>`로 이미지의 **엔트로피**를 확인하세요. 엔트로피가 낮으면 암호화되지 않았을 가능성이 높습니다. 엔트로피가 높으면 암호화되었거나 어떤 방식으로든 압축되었을 가능성이 있습니다.

또한, 이러한 도구를 사용하여 **펌웨어에 내장된 파일**을 추출할 수 있습니다:

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

또는 [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/))를 사용하여 파일을 검사할 수 있습니다.

### 파일 시스템 가져오기

이전의 주석 처리된 도구인 `binwalk -ev <bin>`를 사용하면 **파일 시스템을 추출할 수 있어야 합니다**.\
Binwalk는 일반적으로 **파일 시스템 유형으로 명명된 폴더** 안에 추출합니다. 이 폴더는 보통 다음 중 하나입니다: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### 수동 파일 시스템 추출

때때로, binwalk는 **파일 시스템의 매직 바이트를 시그니처에 포함하지 않을 수 있습니다**. 이러한 경우, binwalk를 사용하여 **파일 시스템의 오프셋을 찾고 이진 파일에서 압축된 파일 시스템을 조각내고** 아래 단계에 따라 파일 시스템을 **수동으로 추출**하세요.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
다음 **dd 명령어**를 실행하여 Squashfs 파일 시스템을 조각내십시오.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
대안으로, 다음 명령어를 실행할 수도 있습니다.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs (위의 예에서 사용됨)

`$ unsquashfs dir.squashfs`

파일은 이후에 "`squashfs-root`" 디렉토리에 있을 것입니다.

- CPIO 아카이브 파일

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 파일 시스템의 경우

`$ jefferson rootfsfile.jffs2`

- NAND 플래시가 있는 ubifs 파일 시스템의 경우

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## 펌웨어 분석

펌웨어를 얻은 후, 그 구조와 잠재적 취약점을 이해하기 위해 분석하는 것이 필수적입니다. 이 과정은 다양한 도구를 활용하여 펌웨어 이미지에서 귀중한 데이터를 분석하고 추출하는 것을 포함합니다.

### 초기 분석 도구

이진 파일( `<bin>`으로 언급됨)의 초기 검사를 위한 명령어 세트가 제공됩니다. 이 명령어들은 파일 유형을 식별하고, 문자열을 추출하며, 이진 데이터를 분석하고, 파티션 및 파일 시스템 세부 정보를 이해하는 데 도움을 줍니다:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
이미지의 암호화 상태를 평가하기 위해 **entropy**는 `binwalk -E <bin>`으로 확인됩니다. 낮은 엔트로피는 암호화가 없음을 나타내고, 높은 엔트로피는 가능한 암호화 또는 압축을 나타냅니다.

**임베디드 파일**을 추출하기 위해서는 **file-data-carving-recovery-tools** 문서와 파일 검사를 위한 **binvis.io**와 같은 도구와 리소스가 추천됩니다.

### 파일 시스템 추출

`binwalk -ev <bin>`을 사용하면 일반적으로 파일 시스템을 추출할 수 있으며, 종종 파일 시스템 유형(예: squashfs, ubifs) 이름의 디렉토리에 저장됩니다. 그러나 **binwalk**가 매직 바이트가 누락되어 파일 시스템 유형을 인식하지 못할 경우 수동 추출이 필요합니다. 이는 `binwalk`를 사용하여 파일 시스템의 오프셋을 찾고, 그 다음 `dd` 명령을 사용하여 파일 시스템을 추출하는 과정을 포함합니다:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
그 후, 파일 시스템 유형(예: squashfs, cpio, jffs2, ubifs)에 따라 내용을 수동으로 추출하는 데 사용되는 다양한 명령이 있습니다.

### 파일 시스템 분석

파일 시스템이 추출되면 보안 결함을 찾기 시작합니다. 불안전한 네트워크 데몬, 하드코딩된 자격 증명, API 엔드포인트, 업데이트 서버 기능, 컴파일되지 않은 코드, 시작 스크립트 및 오프라인 분석을 위한 컴파일된 바이너드에 주의가 기울여집니다.

**검사할 주요 위치** 및 **항목**은 다음과 같습니다:

- 사용자 자격 증명을 위한 **etc/shadow** 및 **etc/passwd**
- **etc/ssl**의 SSL 인증서 및 키
- 잠재적 취약점을 위한 구성 및 스크립트 파일
- 추가 분석을 위한 내장 바이너리
- 일반 IoT 장치 웹 서버 및 바이너리

여러 도구가 파일 시스템 내에서 민감한 정보와 취약점을 발견하는 데 도움을 줍니다:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) 및 [**Firmwalker**](https://github.com/craigz28/firmwalker)로 민감한 정보 검색
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)로 포괄적인 펌웨어 분석
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), 및 [**EMBA**](https://github.com/e-m-b-a/emba)로 정적 및 동적 분석

### 컴파일된 바이너리에 대한 보안 검사

파일 시스템에서 발견된 소스 코드와 컴파일된 바이너리는 취약점에 대해 면밀히 조사해야 합니다. Unix 바이너리를 위한 **checksec.sh**와 Windows 바이너리를 위한 **PESecurity**와 같은 도구는 악용될 수 있는 보호되지 않은 바이너리를 식별하는 데 도움을 줍니다.

## 동적 분석을 위한 펌웨어 에뮬레이션

펌웨어를 에뮬레이트하는 과정은 장치의 작동 또는 개별 프로그램의 **동적 분석**을 가능하게 합니다. 이 접근 방식은 하드웨어 또는 아키텍처 의존성으로 인해 어려움이 발생할 수 있지만, 루트 파일 시스템이나 특정 바이너리를 Raspberry Pi와 같은 일치하는 아키텍처 및 엔디안성을 가진 장치로 전송하거나 미리 구축된 가상 머신으로 전송하면 추가 테스트를 용이하게 할 수 있습니다.

### 개별 바이너리 에뮬레이션

단일 프로그램을 검사하기 위해 프로그램의 엔디안성과 CPU 아키텍처를 식별하는 것이 중요합니다.

#### MIPS 아키텍처 예시

MIPS 아키텍처 바이너리를 에뮬레이트하려면 다음 명령을 사용할 수 있습니다:
```bash
file ./squashfs-root/bin/busybox
```
필요한 에뮬레이션 도구를 설치하려면:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (빅 엔디안)의 경우 `qemu-mips`가 사용되며, 리틀 엔디안 바이너리의 경우 `qemu-mipsel`이 선택됩니다.

#### ARM 아키텍처 에뮬레이션

ARM 바이너리의 경우, 프로세스는 유사하며 `qemu-arm` 에뮬레이터가 에뮬레이션에 사용됩니다.

### 전체 시스템 에뮬레이션

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)와 같은 도구는 전체 펌웨어 에뮬레이션을 용이하게 하여 프로세스를 자동화하고 동적 분석을 지원합니다.

## 동적 분석 실습

이 단계에서는 실제 또는 에뮬레이션된 장치 환경을 사용하여 분석을 수행합니다. OS 및 파일 시스템에 대한 셸 접근을 유지하는 것이 중요합니다. 에뮬레이션이 하드웨어 상호작용을 완벽하게 모방하지 못할 수 있으므로 가끔 에뮬레이션을 재시작해야 할 필요가 있습니다. 분석은 파일 시스템을 재검토하고, 노출된 웹페이지 및 네트워크 서비스를 이용하며, 부트로더 취약점을 탐색해야 합니다. 펌웨어 무결성 테스트는 잠재적인 백도어 취약점을 식별하는 데 중요합니다.

## 런타임 분석 기법

런타임 분석은 gdb-multiarch, Frida 및 Ghidra와 같은 도구를 사용하여 운영 환경에서 프로세스 또는 바이너리와 상호작용하며, 중단점을 설정하고 퍼징 및 기타 기법을 통해 취약점을 식별하는 것을 포함합니다.

## 바이너리 익스플로잇 및 개념 증명

식별된 취약점에 대한 PoC를 개발하려면 대상 아키텍처에 대한 깊은 이해와 저수준 언어로 프로그래밍하는 능력이 필요합니다. 임베디드 시스템에서 바이너리 런타임 보호는 드물지만, 존재할 경우 Return Oriented Programming (ROP)과 같은 기법이 필요할 수 있습니다.

## 펌웨어 분석을 위한 준비된 운영 체제

[AttifyOS](https://github.com/adi0x90/attifyos) 및 [EmbedOS](https://github.com/scriptingxss/EmbedOS)와 같은 운영 체제는 펌웨어 보안 테스트를 위한 사전 구성된 환경을 제공하며, 필요한 도구가 장착되어 있습니다.

## 펌웨어 분석을 위한 준비된 OS

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS는 사물인터넷(IoT) 장치의 보안 평가 및 침투 테스트를 수행하는 데 도움을 주기 위해 설계된 배포판입니다. 필요한 모든 도구가 로드된 사전 구성된 환경을 제공하여 많은 시간을 절약할 수 있습니다.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 펌웨어 보안 테스트 도구가 사전 로드된 Ubuntu 18.04 기반의 임베디드 보안 테스트 운영 체제입니다.

## 연습을 위한 취약한 펌웨어

펌웨어에서 취약점을 발견하는 연습을 위해 다음의 취약한 펌웨어 프로젝트를 시작점으로 사용하세요.

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

## 참고 문헌

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## 교육 및 인증

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
