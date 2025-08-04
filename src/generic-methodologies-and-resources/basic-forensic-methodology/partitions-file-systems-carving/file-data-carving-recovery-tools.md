# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

더 많은 도구는 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)에서 확인할 수 있습니다.

### Autopsy

포렌식에서 이미지를 통해 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하여 설치한 후 파일을 가져와 "숨겨진" 파일을 찾으세요. Autopsy는 디스크 이미지 및 기타 종류의 이미지를 지원하도록 설계되었지만 단순 파일은 지원하지 않습니다.

> **2024-2025 업데이트** – 버전 **4.21** (2025년 2월 출시)에서는 다중 테라바이트 이미지를 처리할 때 눈에 띄게 빠른 **SleuthKit v4.13** 기반의 재구성된 **carving 모듈**이 추가되었으며, 다중 코어 시스템에서 병렬 추출을 지원합니다.¹ 작은 CLI 래퍼(`autopsycli ingest <case> <image>`)도 도입되어 CI/CD 또는 대규모 실험실 환경 내에서 carving을 스크립트화할 수 있게 되었습니다.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 임베디드 콘텐츠를 찾기 위해 바이너리 파일을 분석하는 도구입니다. `apt`를 통해 설치할 수 있으며, 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **보안 노트** – 버전 **≤2.3.3**는 **경로 탐색** 취약점(CVE-2022-4510)의 영향을 받습니다. 신뢰할 수 없는 샘플을 조각내기 전에 업그레이드(또는 컨테이너/비특권 UID로 격리)하세요.

### Foremost

숨겨진 파일을 찾기 위한 또 다른 일반적인 도구는 **foremost**입니다. foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 주석을 제거하세요. 아무것도 주석을 제거하지 않으면 foremost는 기본적으로 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**은 **파일에 포함된 파일**을 찾고 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우, 추출하려는 파일 유형을 구성 파일(_/etc/scalpel/scalpel.conf_)에서 주석을 제거해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

이 도구는 kali에 포함되어 있지만 여기에서 찾을 수 있습니다: <https://github.com/simsong/bulk_extractor>

Bulk Extractor는 증거 이미지를 스캔하고 **pcap 조각**, **네트워크 아티팩트 (URL, 도메인, IP, MAC, 이메일)** 및 많은 다른 객체를 **여러 스캐너를 사용하여 병렬로** 조각낼 수 있습니다.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
유용한 후처리 스크립트(`bulk_diff`, `bulk_extractor_reader.py`)는 두 이미지 간의 아티팩트를 중복 제거하거나 결과를 SIEM 수집을 위해 JSON으로 변환할 수 있습니다.

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download>에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec이 검색할 **파일 유형**을 선택할 수 있습니다.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (불량 드라이브 이미징)

물리적 드라이브가 불안정할 때는 **먼저 이미징하는 것이 최선의 방법**이며, 이미지를 대상으로만 카빙 도구를 실행하는 것이 좋습니다. `ddrescue` (GNU 프로젝트)는 읽을 수 없는 섹터의 로그를 유지하면서 불량 디스크를 신뢰성 있게 복사하는 데 중점을 둡니다.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
버전 **1.28** (2024년 12월)에서는 **`--cluster-size`**가 도입되어 전통적인 섹터 크기가 플래시 블록과 더 이상 정렬되지 않는 고용량 SSD의 이미징 속도를 높일 수 있습니다.

### Extundelete / Ext4magic (EXT 3/4 복구)

소스 파일 시스템이 Linux EXT 기반인 경우 최근에 삭제된 파일을 **전체 카빙 없이** 복구할 수 있습니다. 두 도구는 읽기 전용 이미지에서 직접 작동합니다:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 파일 시스템이 삭제 후에 마운트되었다면, 데이터 블록이 이미 재사용되었을 수 있습니다 – 이 경우 적절한 카빙(Foremost/Scalpel)이 여전히 필요합니다.

### binvis

[코드](https://code.google.com/archive/p/binvis/)와 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

#### BinVis의 특징

- 시각적이고 능동적인 **구조 뷰어**
- 다양한 초점에 대한 여러 플롯
- 샘플의 일부에 집중
- PE 또는 ELF 실행 파일에서 **스트링과 리소스 보기**
- 파일에 대한 암호 분석을 위한 **패턴** 얻기
- **패커** 또는 인코더 알고리즘 **찾기**
- 패턴으로 스테가노그래피 **식별**
- **시각적** 바이너리 차이 비교

BinVis는 블랙 박스 시나리오에서 **알려지지 않은 대상을 익히기 위한 훌륭한 시작점**입니다.

## 특정 데이터 카빙 도구

### FindAES

키 스케줄을 검색하여 AES 키를 찾습니다. TrueCrypt 및 BitLocker에서 사용되는 128, 192 및 256 비트 키를 찾을 수 있습니다.

[여기서 다운로드](https://sourceforge.net/projects/findaes/)하세요.

### YARA-X (카빙된 아티팩트 분류)

[YARA-X](https://github.com/VirusTotal/yara-x)는 2024년에 출시된 YARA의 Rust 재작성입니다. 고전 YARA보다 **10-30배 빠르며** 수천 개의 카빙된 객체를 매우 빠르게 분류하는 데 사용할 수 있습니다:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
속도 향상으로 인해 대규모 조사에서 모든 조각 파일을 **자동 태그**하는 것이 현실적으로 가능해졌습니다.

## 보조 도구

터미널에서 이미지를 보려면 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.  \
PDF를 텍스트로 변환하고 읽으려면 리눅스 명령줄 도구 **pdftotext**를 사용할 수 있습니다.

## 참고 문헌

1. Autopsy 4.21 릴리스 노트 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
