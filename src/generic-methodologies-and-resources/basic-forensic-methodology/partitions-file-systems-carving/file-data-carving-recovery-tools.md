# 파일/데이터 카빙 및 복구 도구

## 카빙 및 복구 도구

더 많은 도구는 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)에서 확인할 수 있습니다.

### Autopsy

이미지에서 파일을 추출하기 위해 forensics에서 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 이를 다운로드하고 설치한 다음, 파일을 ingest하여 "숨겨진" 파일을 찾습니다. Autopsy는 disk image 및 다른 종류의 image를 지원하도록 제작되었지만, 단순한 파일은 지원하지 않는다는 점에 유의하세요.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 binary file을 분석하여 내장된 콘텐츠를 찾는 도구입니다. `apt`를 통해 설치할 수 있으며, 소스 코드는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️ **Security note** – **2.1.2b부터 2.3.3까지** 버전은 **Path Traversal** 취약점(CVE-2022-4510)의 영향을 받습니다. 권고문에는 패치된 pip 버전이 명시되어 있지 않습니다. 영향을 받는 릴리스로 신뢰할 수 없는 샘플을 추출하지 말거나, container/non-privileged UID를 사용해 tool을 격리하세요.<sup>[[4]](#references)</sup>

### Foremost

숨겨진 파일을 찾는 데 사용되는 또 다른 일반적인 tool은 **foremost**입니다. `/etc/foremost.conf`에서 foremost의 configuration file을 확인할 수 있습니다. 특정 파일만 검색하려면 해당 파일의 주석을 해제하세요. 아무것도 주석 해제하지 않으면 foremost는 기본적으로 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**은 **파일에 포함된 파일을** 찾고 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우 추출하려는 파일 형식의 주석을 설정 파일 (_/etc/scalpel/scalpel.conf_)에서 해제해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

이 도구는 kali에 포함되어 있지만 여기에서 찾을 수 있습니다: <https://github.com/simsong/bulk_extractor>

Bulk Extractor는 증거 이미지를 스캔하고 **pcap 조각**, **네트워크 아티팩트(URL, 도메인, IP, MAC, e-mail)** 및 기타 여러 객체를 **여러 scanner를 사용해 병렬로** carve할 수 있습니다.

v2.1.1 릴리스에는 Autotools 빌드와 모든 연속 JPEG를 carving하기 위한 `-S jpeg_carve_mode=2` 설정이 문서화되어 있습니다.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
번들된 `bulk_diff.py`는 두 개의 bulk_extractor 실행 결과를 비교하고, `bulk_extractor_reader.py`는 report 및 feature 파일을 읽습니다.<sup>[[3]](#references)</sup>

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download>에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec에서 검색할 **파일 형식**을 선택할 수 있습니다.

![모든 scanner를 실행하고 JPEG를 적극적으로 carve하며 bodyfile을 생성 - PhotoRec: GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec에서 검색할 파일 형식을 선택할 수 있습니다](<../../../images/image (242).png>)

### ddrescue + ddrescueview (불안정한 drive 이미징)

물리적 drive가 불안정한 경우에는 먼저 **이미징**한 후 해당 image에 대해서만 carving 도구를 실행하는 것이 best practice입니다. `ddrescue` (GNU project)는 읽을 수 없는 sector의 log를 유지하면서 불량 disk를 안정적으로 복사하는 데 중점을 둡니다.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
**`--cluster-size`** 옵션은 한 번에 복사되는 섹터 수를 제어합니다. 값을 작게 설정하면 느린 드라이브에서 도움이 될 수 있습니다.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

소스 파일 시스템이 Linux EXT 기반인 경우 **전체 carving 없이도** 최근에 삭제된 파일을 복구할 수 있습니다. 이러한 journal 기반 도구는 마운트 해제된 파일 시스템 또는 read-only 이미지에서 작동합니다.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **호환성 참고** – ext4magic은 더 이상 개발되지 않으며, 프로젝트 페이지에서는 현재 파일 시스템이 더 이상 호환되지 않는다고 경고합니다.<sup>[[10]](#references)</sup>

> 🛈 파일 시스템이 삭제 후 마운트되었다면 데이터 블록이 이미 재사용되었을 수 있습니다. 이 경우에도 적절한 carving(Foremost/Scalpel)이 필요합니다.

### binvis

[code](https://code.google.com/archive/p/binvis/)와 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

#### BinVis의 기능

- 시각적이고 능동적인 **구조 뷰어**
- 서로 다른 초점 지점을 위한 여러 플롯
- 샘플의 특정 부분에 초점 맞추기
- PE 또는 ELF 실행 파일 등에서 **문자열과 리소스 확인**
- 파일에서 암호 분석을 위한 **패턴** 가져오기
- **packer 또는 encoder 알고리즘 식별**
- 패턴을 통한 **Steganography 식별**
- **시각적** 바이너리 diff 수행

BinVis는 black-boxing 시나리오에서 **알 수 없는 대상에 익숙해지기 위한 훌륭한 시작점**입니다.

## 특정 데이터 carving 도구

### FindAES

키 스케줄을 검색하여 AES 키를 찾습니다. TrueCrypt와 BitLocker에서 사용하는 것과 같은 128, 192, 256비트 키를 찾을 수 있습니다.

[여기](https://sourceforge.net/projects/findaes/)에서 다운로드하세요.

### YARA-X (carved artefacts triaging)

[YARA-X](https://github.com/VirusTotal/yara-x)는 2024년에 소개된 YARA의 Rust 재작성 버전입니다. VirusTotal에 따르면 일부 정규 표현식 및 복잡한 루프 규칙을 훨씬 더 빠르게 실행할 수 있습니다.<sup>[[5]](#references)</sup> CLI 이름은 `yr`이며, `scan` 명령은 recursive scan, 스레드 수 및 metadata 출력을 지원합니다.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## 보조 도구

터미널에서 이미지를 보려면 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.  \
linux command line tool **pdftotext**를 사용하여 pdf를 텍스트로 변환하고 읽을 수 있습니다.



## References

- [1] [Autopsy 4.21 릴리스 노트](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python tools README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk의 Path traversal (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA는 죽고, YARA-X 만세 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI commands](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue 매뉴얼](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic 매뉴얼](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic 프로젝트 상태](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
