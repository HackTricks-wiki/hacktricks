{{#include ../../../banners/hacktricks-training.md}}

# 카빙 도구

## Autopsy

포렌식에서 이미지를 통해 파일을 추출하는 데 가장 일반적으로 사용되는 도구는 [**Autopsy**](https://www.autopsy.com/download/)입니다. 다운로드하여 설치한 후 파일을 분석하여 "숨겨진" 파일을 찾으세요. Autopsy는 디스크 이미지 및 기타 종류의 이미지를 지원하도록 설계되었지만 단순 파일은 지원하지 않습니다.

## Binwalk <a id="binwalk"></a>

**Binwalk**는 이미지 및 오디오 파일과 같은 이진 파일에서 내장된 파일과 데이터를 검색하는 도구입니다. `apt`를 사용하여 설치할 수 있으며, [소스](https://github.com/ReFirmLabs/binwalk)는 github에서 찾을 수 있습니다.  
**유용한 명령어**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

또 다른 일반적인 도구는 **foremost**로, 숨겨진 파일을 찾는 데 사용됩니다. foremost의 구성 파일은 `/etc/foremost.conf`에 있습니다. 특정 파일을 검색하려면 주석을 제거하면 됩니다. 아무것도 주석을 제거하지 않으면 foremost는 기본적으로 구성된 파일 유형을 검색합니다.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **스칼펠**

**스칼펠**은 **파일에 포함된 파일**을 찾고 추출하는 데 사용할 수 있는 또 다른 도구입니다. 이 경우 추출하려는 파일 유형을 구성 파일 \(_/etc/scalpel/scalpel.conf_\)에서 주석을 제거해야 합니다.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

이 도구는 칼리 안에 포함되어 있지만 여기에서 찾을 수 있습니다: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

이 도구는 이미지를 스캔하고 **pcaps**를 추출하며, **네트워크 정보(URLs, 도메인, IPs, MACs, 메일)** 및 더 많은 **파일**을 추출할 수 있습니다. 당신이 해야 할 일은:
```text
bulk_extractor memory.img -o out_folder
```
모든 정보를 탐색하십시오 \(비밀번호?\), 패킷을 분석하십시오 \(읽기 [ **Pcaps 분석**](../pcap-inspection/)\), 이상한 도메인을 검색하십시오 \(악성코드 또는 존재하지 않는 도메인과 관련된 도메인\).

## PhotoRec

[https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)에서 찾을 수 있습니다.

GUI 및 CLI 버전이 함께 제공됩니다. PhotoRec이 검색할 **파일 유형**을 선택할 수 있습니다.

![](../../../images/image%20%28524%29.png)

# 특정 데이터 카빙 도구

## FindAES

키 스케줄을 검색하여 AES 키를 검색합니다. TrueCrypt 및 BitLocker에서 사용하는 것과 같은 128, 192 및 256 비트 키를 찾을 수 있습니다.

[여기에서 다운로드](https://sourceforge.net/projects/findaes/).

# 보조 도구

[**viu** ](https://github.com/atanunq/viu)를 사용하여 터미널에서 이미지를 볼 수 있습니다. 리눅스 명령줄 도구 **pdftotext**를 사용하여 pdf를 텍스트로 변환하고 읽을 수 있습니다.

{{#include ../../../banners/hacktricks-training.md}}
