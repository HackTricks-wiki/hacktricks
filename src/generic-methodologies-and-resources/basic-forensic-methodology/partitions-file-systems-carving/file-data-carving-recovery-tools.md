# 파일/데이터 Carving 및 복구 도구

{{#include ../../../banners/hacktricks-training.md}}

## Carving 및 복구 도구

[https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)에서 더 많은 도구를 확인할 수 있습니다.

### Autopsy

이미지에서 파일을 추출할 때 forensics에서 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 이를 다운로드하고 설치한 다음, 파일을 ingest하여 "숨겨진" 파일을 찾습니다. Autopsy는 disk image 및 기타 종류의 image를 지원하도록 설계되었지만, 단순한 파일은 지원하지 않는다는 점에 유의하세요.

> **2024-2025 업데이트** – **4.21** 버전(2025년 2월 릴리스)에는 **SleuthKit v4.13**을 기반으로 다시 구축된 **carving module**이 추가되어 multi-terabyte image를 처리할 때 눈에 띄게 빨라졌으며, multi-core 시스템에서 병렬 추출을 지원합니다. 또한 작은 CLI wrapper(`autopsycli ingest <case> <image>`)가 도입되어 CI/CD 또는 대규모 lab environment에서 carving을 script로 실행할 수 있게 되었습니다.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 바이너리 파일을 분석하여 내장된 콘텐츠를 찾는 도구입니다. `apt`를 통해 설치할 수 있으며, 소스 코드는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Security note** – **≤2.3.3** 버전은 **Path Traversal** 취약점(CVE-2022-4510)의 영향을 받습니다. 신뢰할 수 없는 샘플을 carving하기 전에 업그레이드하거나(또는 컨테이너/비특권 UID로 격리하십시오).<sup>[[2]](#references)</sup>

### Foremost

숨겨진 파일을 찾는 데 사용되는 또 다른 일반적인 도구는 **foremost**입니다. `/etc/foremost.conf`에서 foremost의 구성 파일을 확인할 수 있습니다. 특정 파일만 검색하려면 해당 항목의 주석을 해제하십시오. 아무 항목의 주석도 해제하지 않으면 foremost는 기본적으로 설정된 파일 형식을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**은 **파일에 삽입된 files**을 찾고 추출하는 데 사용할 수 있는 또 다른 tool입니다. 이 경우 추출하려는 file types의 주석을 configuration file (_/etc/scalpel/scalpel.conf_)에서 해제해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

이 도구는 kali에 포함되어 있지만 여기에서도 찾을 수 있습니다: <https://github.com/simsong/bulk_extractor>

Bulk Extractor는 **여러 scanner를 사용하여 병렬로** 증거 이미지를 스캔하고 **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** 및 기타 여러 객체를 **carve**할 수 있습니다.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
유용한 후처리 스크립트(`bulk_diff`, `bulk_extractor_reader.py`)를 사용하면 두 이미지 간 artefact를 중복 제거하거나 결과를 JSON으로 변환하여 SIEM에 수집할 수 있습니다.

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download>에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec이 검색할 **file-types**를 선택할 수 있습니다.

![모든 scanner를 실행하고, JPEG를 적극적으로 carve하며, bodyfile을 생성 - PhotoRec: GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec이 검색할 file-types를 선택할 수 있습니다](<../../../images/image (242).png>)

### ddrescue + ddrescueview (불안정한 drive 이미징)

물리적 drive가 불안정한 경우에는 먼저 **image를 생성**한 후 해당 image에 대해서만 carving tools를 실행하는 것이 best practice입니다. `ddrescue`(GNU project)는 읽을 수 없는 sector의 log를 유지하면서 불량 disk를 안정적으로 복사하는 데 중점을 둡니다.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
버전 **1.28**(2024년 12월)에는 **`--cluster-size`**가 도입되었습니다. 이를 통해 기존 섹터 크기가 더 이상 플래시 블록과 일치하지 않는 고용량 SSD의 이미징 속도를 높일 수 있습니다.

### Extundelete / Ext4magic (EXT 3/4 undelete)

소스 파일 시스템이 Linux EXT 기반인 경우 **full carving** 없이 최근에 삭제된 파일을 복구할 수 있습니다. 두 도구 모두 read-only image에서 직접 작동합니다:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 파일 시스템이 삭제 후 마운트되었다면 데이터 블록이 이미 재사용되었을 수 있습니다. 이 경우에도 적절한 carving(Foremost/Scalpel)이 필요합니다.

### binvis

[code](https://code.google.com/archive/p/binvis/)와 [web page tool](https://binvis.io/#/)을 확인하세요.

#### BinVis의 기능

- 시각적이고 활성화된 **구조 뷰어**
- 다양한 초점 지점을 위한 여러 플롯
- 샘플의 특정 부분에 초점 맞추기
- PE 또는 ELF executable 등에서 **strings 및 resources 확인**
- 파일의 cryptanalysis를 위한 **patterns 확보**
- **packer 또는 encoder algorithms 식별**
- patterns를 통한 **Steganography 식별**
- **시각적** binary-diffing

BinVis는 black-boxing 시나리오에서 **알 수 없는 target에 익숙해지기 위한 훌륭한 시작점**입니다.

## 특정 Data Carving Tools

### FindAES

key schedules를 검색하여 AES keys를 찾습니다. TrueCrypt 및 BitLocker에서 사용하는 128, 192, 256-bit keys를 찾을 수 있습니다.

[여기](https://sourceforge.net/projects/findaes/)에서 Download하세요.

### YARA-X (carved artefacts triaging)

[YARA-X](https://github.com/VirusTotal/yara-x)는 2024년에 출시된 YARA의 Rust rewrite입니다. Classic YARA보다 **10~30배 빠르며**, 수천 개의 carved objects를 매우 빠르게 분류하는 데 사용할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
속도 향상 덕분에 대규모 조사에서 모든 carved 파일에 **auto-tag**를 적용하는 것이 현실적으로 가능해집니다.

## 보완 도구

터미널에서 이미지를 확인하려면 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.  \
Linux command line tool **pdftotext**를 사용하면 pdf를 텍스트로 변환하여 읽을 수 있습니다.



## 참고 자료

- [1] [Autopsy 4.21 릴리스 노트](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [binwalk의 Path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA는 죽고, YARA-X여 영원하라 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
