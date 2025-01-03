# 파일/데이터 카빙 및 복구 도구

{{#include ../../../banners/hacktricks-training.md}}

## 카빙 및 복구 도구

더 많은 도구는 [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)에서 확인할 수 있습니다.

### Autopsy

포렌식에서 이미지를 통해 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하여 설치한 후 파일을 입력하여 "숨겨진" 파일을 찾으세요. Autopsy는 디스크 이미지 및 기타 종류의 이미지를 지원하도록 설계되었지만 단순 파일은 지원하지 않습니다.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk**는 이진 파일을 분석하여 내장된 콘텐츠를 찾는 도구입니다. `apt`를 통해 설치할 수 있으며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에 있습니다.

**유용한 명령어**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

또 다른 일반적인 도구는 **foremost**입니다. foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 주석을 제거하면 됩니다. 아무것도 주석을 제거하지 않으면 foremost는 기본 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel**은 **파일에 포함된 파일**을 찾고 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우, 추출하려는 파일 유형을 구성 파일(_/etc/scalpel/scalpel.conf_)에서 주석을 제거해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

이 도구는 이미지를 스캔하고 그 안에서 **pcap**을 **추출**하며, **네트워크 정보 (URL, 도메인, IP, MAC, 메일)** 및 더 많은 **파일**을 추출할 수 있습니다. 당신이 해야 할 일은:
```
bulk_extractor memory.img -o out_folder
```
모든 정보를 탐색하세요(비밀번호?), 패킷을 분석하세요(읽기[ **Pcaps analysis**](../pcap-inspection/)), 이상한 도메인을 검색하세요(악성코드 또는 존재하지 않는 도메인과 관련된 도메인).

### PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec이 검색할 **파일 유형**을 선택할 수 있습니다.

![](<../../../images/image (242).png>)

### binvis

[코드](https://code.google.com/archive/p/binvis/)와 [웹 페이지 도구](https://binvis.io/#/)를 확인하세요.

#### BinVis의 기능

- 시각적이고 능동적인 **구조 뷰어**
- 다양한 초점에 대한 여러 플롯
- 샘플의 일부에 집중
- PE 또는 ELF 실행 파일에서 **문자열 및 리소스 보기**
- 파일에 대한 암호 분석을 위한 **패턴** 얻기
- 패커 또는 인코더 알고리즘 **찾기**
- 패턴으로 스테가노그래피 **식별**
- **시각적** 바이너리 차이 비교

BinVis는 블랙박스 시나리오에서 알려지지 않은 대상을 익히는 데 훌륭한 **출발점**입니다.

## 특정 데이터 카빙 도구

### FindAES

키 스케줄을 검색하여 AES 키를 검색합니다. TrueCrypt 및 BitLocker에서 사용하는 128, 192 및 256 비트 키를 찾을 수 있습니다.

[여기에서 다운로드](https://sourceforge.net/projects/findaes/)하세요.

## 보조 도구

터미널에서 이미지를 보려면 [**viu** ](https://github.com/atanunq/viu)를 사용할 수 있습니다.\
PDF를 텍스트로 변환하고 읽으려면 리눅스 명령줄 도구 **pdftotext**를 사용할 수 있습니다.

{{#include ../../../banners/hacktricks-training.md}}
