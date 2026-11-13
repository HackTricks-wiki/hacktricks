# 파일/데이터 카빙 및 복구 도구

{{#include ../../../banners/hacktricks-training.md}}

## 카빙 및 복구 도구

원본 장치가 아니라 **검증된 복사본**을 항상 카빙하세요. 읽기 전용으로 이미지를 획득하고 해시를 계산하는 방법은 [이미지 획득 및 마운트](../image-acquisition-and-mount.md)를 참조하세요.

더 많은 도구는 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)에서 확인할 수 있습니다.

### Autopsy

이미지에서 파일을 추출할 때 포렌식에서 가장 흔히 사용하는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하여 설치한 다음, 파일을 분석하도록 설정해 "숨겨진" 파일을 찾으세요. Autopsy는 디스크 이미지와 다른 종류의 이미지를 지원하도록 만들어졌지만, 단순한 파일은 지원하지 않습니다.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 바이너리 파일을 분석하여 내부에 포함된 콘텐츠를 찾는 도구입니다. **Binwalk v3**는 자동 추출(`-e`), 알려진 객체와 알려지지 않은 객체의 raw 카빙(`-c`), 재귀적/Matryoshka 스캔(`-M`), 설정 가능한 작업자 스레드를 지원하는 Rust 재작성 버전입니다. 외부 추출기를 모두 사용하려면 Docker 빌드를 권장합니다. `cargo install binwalk`는 Rust CLI를 설치하지만 외부 종속성은 설치하지 않습니다.<sup>[[11]](#references)</sup>

**유용한 v3 명령어**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

legacy v2 `--dd='.*'` 레시피는 v3의 `-c`와 동일한 명령이 아닙니다. 이전 CTF/write-up 명령을 사용할 때는 먼저 `binwalk --version`을 확인하세요.<sup>[[11]](#references)</sup>

⚠️  **보안 참고** – **2.1.2b부터 2.3.3까지** 버전은 **Path Traversal** 취약점(CVE-2022-4510)의 영향을 받습니다. 권고문에는 패치된 pip 버전이 명시되어 있지 않습니다. 영향을 받는 버전으로 신뢰할 수 없는 샘플을 추출하지 말고, 컨테이너나 권한이 없는 UID로 도구를 격리하세요.<sup>[[4]](#references)</sup>

### Foremost

숨겨진 파일을 찾는 데 흔히 사용되는 또 다른 도구는 **foremost**입니다. foremost의 설정 파일은 `/etc/foremost.conf`에서 찾을 수 있습니다. 특정 파일만 검색하려면 해당 파일의 주석을 해제하세요. 아무것도 주석 해제하지 않으면 foremost는 기본으로 설정된 파일 형식을 검색합니다.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel**은 **파일 내에 삽입된 파일**을 찾아 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우 추출하려는 파일 형식을 설정 파일 (_/etc/scalpel/scalpel.conf_)에서 주석 해제해야 합니다.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 조각난 파일 카빙

메타데이터 우선 복구와 연속 데이터 카버로 분할 파일을 완전히 복구하지 못한 경우, **Scalpel3**는 파일/블록 검증기를 사용해 지원되는 형식을 재조립할 수 있습니다. 이는 위에서 설명한 레거시 `scalpel` 명령과는 다른 코드베이스입니다. 먼저 카빙에 사용할 **동일한 블록 크기**로 필수 blockmap을 만드세요. 크기를 알고 있다면 `fsstat`에서 파일시스템 클러스터 크기를 사용하고, 그렇지 않다면 파티션 이미지 스캔 전에 근거가 있는 값을 정하세요. 검증된 복사본만 대상으로 실행하고 출력은 별도의 볼륨에 저장하세요.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

`4096`을 선택한 block size로 바꾸세요. `-w`는 검증된 후보뿐 아니라 **PROMISING** 후보도 보존하며, `-b`는 재구성된 레이아웃을 확인하는 데 도움이 되는 blockvectors를 기록합니다. PROMISING에 있는 파일이나 익숙한 확장자를 가진 파일이라고 해서 완전히 복구되었다는 증거는 아닙니다. 사용하기 전에 콘텐츠를 검증하세요.<sup>[[13]](#references)[[14]](#references)</sup> carving 전에 삭제된 파티션이나 빈 공간을 찾으려면 [나열된 파티션 외부의 데이터 찾기](./#finding-data-outside-listed-partitions)를 참조하세요.

### Bulk Extractor 2.x   

이 도구는 kali에 포함되어 있지만 여기에서 찾을 수 있습니다: <https://github.com/simsong/bulk_extractor>

Bulk Extractor는 증거 이미지를 스캔하고 **pcap 조각**, **네트워크 아티팩트(URL, 도메인, IP, MAC, 이메일)** 및 여러 다른 객체를 **여러 scanner를 사용해 병렬로** carve할 수 있습니다.

v2.1.1 릴리스에는 Autotools 빌드와 모든 연속된 JPEG를 carving하기 위한 `-S jpeg_carve_mode=2` 설정이 문서화되어 있습니다.<sup>[[2]](#references)</sup>

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

함께 제공되는 `bulk_diff.py`는 두 개의 bulk_extractor 실행 결과를 비교하고, `bulk_extractor_reader.py`는 보고서 및 feature 파일을 읽습니다.<sup>[[3]](#references)</sup>

### PhotoRec

<https://www.cgsecurity.org/wiki/TestDisk_Download>에서 찾을 수 있습니다.

GUI 버전과 CLI 버전이 제공됩니다. PhotoRec에서 검색할 **file-types**를 선택할 수 있습니다.

![모든 scanner를 실행하고 JPEG를 적극적으로 carve하며 bodyfile을 생성 - PhotoRec: GUI 버전과 CLI 버전이 제공됩니다. PhotoRec에서 검색할 file-types를 선택할 수 있습니다](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (메타데이터 우선)

Raw signature carving을 하기 전에, 볼륨 메타데이터를 여전히 파싱할 수 있다면 파일시스템을 고려한 복구를 시도하세요. 기본적으로 `tsk_recover`는 할당되지 않은 파일만 내보냅니다. `-a`는 할당된 파일을 선택하고, `-e`는 두 종류 모두 내보냅니다. 전체 디스크 이미지의 경우 `mmls`에서 확인한 파티션의 **시작 섹터**를 `-o`에 전달하세요(바이트 단위로 변환하지 마세요). 입력이 이미 파티션 이미지라면 `-o`를 생략하세요.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

이 과정은 header/footer carving으로는 복구할 수 없는 파일시스템에서 파생된 이름과 경로를 보존할 수 있습니다. 메타데이터가 없거나 사용할 수 없는 항목은 이후 Foremost, Scalpel 또는 PhotoRec을 실행해 처리하세요.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (불안정한 드라이브 이미징)

물리 드라이브가 불안정한 경우, 먼저 **이미지를 생성한 다음** 이미지에 대해서만 carving 도구를 실행하는 것이 좋습니다. GNU 프로젝트의 `ddrescue`는 읽을 수 없는 섹터의 로그를 유지하면서 손상된 디스크를 안정적으로 복사하는 데 중점을 둡니다.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

**`--cluster-size`** 옵션은 한 번에 복사할 섹터 수를 제어합니다. 값을 낮추면 속도가 느린 드라이브에서 도움이 될 수 있습니다.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

소스 파일 시스템이 Linux EXT 기반이라면 **full carving 없이** 최근 삭제된 파일을 복구할 수 있습니다. 이 저널 기반 도구는 마운트 해제된 파일 시스템이나 읽기 전용 이미지에서 작동합니다.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **호환성 참고** – ext4magic은 더 이상 유지 관리되지 않습니다. 프로젝트 페이지에는 현재 파일 시스템이 더 이상 호환되지 않는다고 안내되어 있습니다.<sup>[[10]](#references)</sup>

> 🛈 삭제 후 파일 시스템이 마운트되었다면 데이터 블록이 이미 재사용되었을 수 있습니다. 이 경우 적절한 carving(Foremost/Scalpel)이 여전히 필요합니다.

### binvis

[코드](https://code.google.com/archive/p/binvis/)와 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

#### BinVis 기능

- 시각적이고 능동적인 **구조 뷰어**
- 다양한 초점 지점을 위한 여러 플롯
- 샘플의 일부에 초점 맞추기
- 예를 들어 PE 또는 ELF 실행 파일에서 **문자열과 리소스 보기**
- 파일에서 암호 분석을 위한 **패턴** 가져오기
- 패커 또는 인코더 알고리즘 **식별**
- 패턴을 통해 Steganography **탐지**
- 시각적 바이너리 diff

BinVis는 블랙박스 시나리오에서 알 수 없는 대상을 파악하기 위한 훌륭한 **시작점**입니다.

## 특정 데이터 카빙 도구

### FindAES

키 스케줄을 검색하여 AES 키를 찾습니다. TrueCrypt와 BitLocker에서 사용하는 것과 같은 128, 192, 256비트 키를 찾을 수 있습니다.

[여기서](https://sourceforge.net/projects/findaes/) 다운로드하세요.

### YARA-X (카빙된 아티팩트 분류)

[YARA-X](https://github.com/VirusTotal/yara-x)는 2024년에 공개된 YARA의 Rust 재작성 버전입니다. VirusTotal에 따르면 일부 정규 표현식 및 복잡한 루프 규칙을 훨씬 빠르게 실행할 수 있습니다.<sup>[[5]](#references)</sup> CLI 이름은 `yr`이며, `scan` 명령은 재귀 스캔, 스레드 수 지정, 메타데이터 출력을 지원합니다.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## 보조 도구

터미널에서 이미지를 보려면 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.  \
Linux 명령줄 도구인 **pdftotext**를 사용하면 PDF를 텍스트로 변환해 읽을 수 있습니다.







## References

- [1] [Autopsy 4.21 릴리스 노트](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [bulk_extractor Python 도구 README](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [binwalk의 경로 순회 (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA는 죽었다, YARA-X 만세 - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI 명령어](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue 매뉴얼](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic 매뉴얼](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [ext4magic 프로젝트 상태](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover 매뉴얼](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3 매뉴얼](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3 테스트 워크플로](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
