# 파티션/파일 시스템/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 파티션

디스크에는 여러 **파티션**이 있을 수 있습니다. 파티션은 물리적으로 분리된 저장 공간이 아니라 논리적인 블록 범위입니다. 파티션의 시작 위치와 길이는 **논리 섹터** 단위로 측정됩니다. 모든 이미지가 512바이트 섹터를 사용한다고 가정하지 마세요. 4096바이트 논리 섹터도 존재합니다.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

MBR은 첫 번째 논리 섹터(LBA 0)에 있으며, 16바이트 파티션 항목 4개는 바이트 오프셋 446부터 시작합니다. 그 앞 영역에는 부트 코드가 있고 디스크 시그니처가 포함될 수도 있습니다.<sup>[[4]](#references)</sup>\
최대 **4개의 파티션**을 허용하며(최대 **1개만** active/**bootable**일 수 있음), 파티션이 더 필요하면 **extended partitions**를 사용할 수 있습니다. 512바이트 MBR의 마지막 **2바이트**는 부트 시그니처 **0x55 0xAA**입니다. active로 표시할 수 있는 파티션은 하나뿐입니다.\
512바이트 논리 섹터를 사용할 경우, MBR의 32비트 섹터 필드로 인해 주소 지정 가능 용량은 약 **2 TiB**(2.2 TB)로 제한됩니다.<sup>[[4]](#references)</sup>

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (304).png>)

Windows를 사용하는 경우 MBR의 **바이트 440~443**에서 **Windows Disk Signature**를 찾을 수 있습니다. 하드 디스크의 논리 드라이브 문자는 Windows Disk Signature에 따라 결정됩니다. 이 시그니처를 변경하면 Windows가 부팅되지 않을 수 있습니다(도구: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): Windows를 사용하는 경우 MBR의 바이트 440~443에서 Windows Disk Signature를 찾을 수 있습니다. 하드 디스크의 논리 드라이브 문자...](<../../../images/image (310).png>)

**형식**

| 오프셋      | 길이       | 항목                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | 부트 코드           |
| 446 (0x1BE) | 16 (0x10)  | 첫 번째 파티션      |
| 462 (0x1CE) | 16 (0x10)  | 두 번째 파티션      |
| 478 (0x1DE) | 16 (0x10)  | 세 번째 파티션      |
| 494 (0x1EE) | 16 (0x10)  | 네 번째 파티션      |
| 510 (0x1FE) | 2 (0x2)    | 시그니처 0x55 0xAA   |

**파티션 레코드 형식**

| 오프셋    | 길이     | 항목                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active 플래그 (0x80 = bootable)                        |
| 1 (0x01)  | 1 (0x01) | 시작 헤드                                              |
| 2 (0x02)  | 1 (0x01) | 시작 섹터 (비트 0~5); 실린더 상위 비트 (6~7)           |
| 3 (0x03)  | 1 (0x01) | 시작 실린더 하위 8비트                                 |
| 4 (0x04)  | 1 (0x01) | 파티션 유형 코드 (0x83 = Linux)                        |
| 5 (0x05)  | 1 (0x01) | 끝 헤드                                                |
| 6 (0x06)  | 1 (0x01) | 끝 섹터 (비트 0~5); 실린더 상위 비트 (6~7)             |
| 7 (0x07)  | 1 (0x01) | 끝 실린더 하위 8비트                                   |
| 8 (0x08)  | 4 (0x04) | 파티션 앞의 섹터 수 (리틀 엔디안)                       |
| 12 (0x0C) | 4 (0x04) | 파티션의 섹터 수                                       |

전체 디스크 MBR 이미지에서 파티션을 검사하려면 먼저 시작 LBA와 논리 섹터 크기를 확인하세요. `mount`는 LBA가 아니라 **바이트 오프셋**을 사용합니다. 아래 예시는 512바이트 섹터 이미지에서 파티션이 LBA 63에서 시작하는 경우에만 유효합니다. 신뢰할 수 없는 이미지나 저널링 파일 시스템에는 [Image Acquisition & Mount](../image-acquisition-and-mount.md)의 격리된 읽기 전용 절차를 사용하세요.<sup>[[5]](#references)[[11]](#references)</sup>

![Partitions - MBR (master Boot Record): Linux에서 MBR을 mount하려면 먼저 시작 오프셋을 확인해야 합니다(fdisk를 실행하고 p 명령을 사용할 수 있습니다)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**)는 컴퓨터 저장 장치, 일반적으로 하드 디스크 드라이브와 같은 보조 저장 장치에 저장된 데이터 **블록의 위치를 지정하는 데** 사용되는 일반적인 방식입니다. LBA는 특히 단순한 선형 주소 지정 방식으로, **정수 인덱스로 블록의 위치를 지정**합니다. 첫 번째 블록은 LBA 0, 두 번째 블록은 LBA 1이며, 이런 식으로 이어집니다.

### GPT (GUID Partition Table)

GUID Partition Table(GPT)는 각 파티션에 고유한 GUID를 저장하며, 기본 메타데이터와 백업 메타데이터를 사용합니다. 레이아웃은 다음과 같이 MBR과 다릅니다:<sup>[[4]](#references)</sup>

- **위치와 크기**: LBA 0에는 **보호 MBR**이 있습니다. 기본 GPT 헤더는 LBA 1에 있고, 그 뒤에 파티션 항목 배열이 이어지며, 백업 배열과 헤더는 디스크 끝에 있습니다. GPT는 64비트 LBA 필드를 사용하는 반면 MBR 파티션 항목은 32비트 LBA 필드를 사용합니다.
- **파티션 제한**: 일반적인 16-KiB 항목 배열에는 **128바이트 크기의 항목 128개**가 들어가지만, 항목 수는 GPT에서 고정하지 않고 헤더에 기록합니다. 주소 지정 가능한 크기는 논리 섹터 크기에도 좌우됩니다(512바이트 섹터에서 약 **9.4 ZB**).<sup>[[4]](#references)</sup>
- **파티션 이름**: 파티션에 최대 36개의 Unicode 문자로 이름을 지정할 수 있습니다.

**데이터 복원력 및 복구**:

- **중복성**: MBR과 달리 GPT는 파티션 및 부팅 데이터를 한 곳에만 두지 않습니다. 디스크 전체에 걸쳐 이 데이터를 복제하여 데이터 무결성과 복원력을 높입니다.
- **순환 중복 검사(CRC)**: 헤더와 파티션 항목 배열에는 각각 CRC32가 있습니다. CRC는 불일치를 감지하지만 디스크를 지속적으로 모니터링하거나 자체적으로 복구하지는 않습니다. 기본 사본이 유효하지 않으면, 작업 사본에서 복구하기 전에 마지막 LBA에 있는 백업을 검증하세요.<sup>[[4]](#references)</sup>

**보호 MBR(LBA0)**:

- GPT는 보호 MBR을 통해 하위 호환성을 유지합니다. 이 기능은 레거시 MBR 영역에 있지만, 이전 MBR 기반 유틸리티가 GPT 디스크를 실수로 덮어쓰지 못하도록 설계되어 GPT로 포맷된 디스크의 데이터 무결성을 보호합니다.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**하이브리드 MBR(LBA 0 + GPT)**

[Wikipedia에서](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

EFI가 아닌 **BIOS** 서비스를 통해 **GPT 기반 부팅**을 지원하는 운영 체제에서는 첫 번째 섹터를 여전히 **bootloader** 코드의 첫 단계를 저장하는 데 사용할 수 있지만, **GPT** **파티션**을 인식하도록 **수정**해야 합니다. MBR의 bootloader는 섹터 크기가 512바이트라고 가정해서는 안 됩니다.

**파티션 테이블 헤더(LBA 1)**

[Wikipedia에서](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

파티션 테이블 헤더는 디스크에서 사용할 수 있는 블록을 정의합니다. 또한 파티션 테이블을 구성하는 파티션 항목의 수와 크기도 정의합니다(테이블의 오프셋 80 및 84).

| 오프셋    | 길이   | 내용                                                                                                                                                                         |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | 서명("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 또는 리틀 엔디안 시스템에서 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8의 Revision 1.0(00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | 리틀 엔디안 헤더 크기(바이트 단위, 일반적으로 5Ch 00h 00h 00h 또는 92바이트)                                                                                                 |
| 16 (0x10) | 4 bytes  | 리틀 엔디안 헤더의 [CRC32](https://en.wikipedia.org/wiki/CRC32)(오프셋 +0부터 헤더 크기까지). 계산 중 이 필드는 0으로 설정됨                                               |
| 20 (0x14) | 4 bytes  | 예약됨; 0이어야 함                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | 현재 LBA(이 헤더 사본의 위치)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | 백업 LBA(다른 헤더 사본의 위치)                                                                                                                               |
| 40 (0x28) | 8 bytes  | 파티션에 사용할 수 있는 첫 번째 LBA(기본 파티션 테이블의 마지막 LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | 사용할 수 있는 마지막 LBA(보조 파티션 테이블의 첫 번째 LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | 혼합 엔디안 형식의 디스크 GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | 파티션 항목 배열의 시작 LBA(기본 사본에서는 항상 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | 배열의 파티션 항목 수                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 단일 파티션 항목의 크기(일반적으로 80h 또는 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | 리틀 엔디안 형식의 파티션 항목 배열 CRC32                                                                                                                            |
| 92 (0x5C) | \*       | 예약됨; 블록의 나머지 부분은 0이어야 함(섹터 크기가 512바이트일 때 420바이트이며, 섹터 크기가 더 크면 늘어날 수 있음)                                      |

**파티션 항목(LBA 2–33)**

| GUID 파티션 항목 형식 |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| 오프셋                      | 길이   | 내용                                                                                                      |
| 0 (0x00)                    | 16 bytes | [파티션 유형 GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs)(혼합 엔디안) |
| 16 (0x10)                   | 16 bytes | 고유 파티션 GUID(혼합 엔디안)                                                                          |
| 32 (0x20)                   | 8 bytes  | 첫 번째 LBA([리틀 엔디안](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | 마지막 LBA(포함, 보통 홀수)                                                                             |
| 48 (0x30)                   | 8 bytes  | 속성 플래그(예: 비트 60은 읽기 전용을 나타냄)                                                               |
| 56 (0x38)                   | 72 bytes | 파티션 이름(36개의 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE 코드 단위)                               |

**파티션 유형**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | 파티션 이름(36개의 UTF-16LE 코드 단위)](<../../../images/image (83).png>)

더 많은 파티션 유형은 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)에서 확인하세요.<sup>[[1]](#references)</sup>

### 검사

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)로 포렌식 이미지를 마운트한 후, Windows 도구 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**를 사용해 첫 번째 섹터를 검사할 수 있습니다.** 다음 이미지에서는 **섹터 0**에서 **MBR**을 감지하고 해석했습니다:

![GPT (GUID Partition Table) - 검사: ArsenalImageMounter로 포렌식 이미지를 마운트한 후 Windows 도구 Active Disk Editor를 사용해 첫 번째 섹터를 검사할 수 있습니다. 다음...](<../../../images/image (354).png>)

GPT의 경우 기본 헤더에서 **LBA 1**의 _EFI PART_ 서명을 찾으세요. LBA 0에는 여전히 보호 MBR이 있습니다.<sup>[[4]](#references)</sup>

### 나열된 파티션 외부에서 데이터 찾기

삭제된 파티션 항목이나 의도적으로 비워 둔 영역 때문에 현재 파티션 맵 외부에 파일 시스템이 남아 있을 수 있습니다. **검증된 원시 작업 사본**에서 할당되지 않은 범위를 나열한 다음, 후보 시작 LBA를 파일 시스템으로 검사합니다. `mmls`와 `fsstat`는 **섹터 오프셋**을 사용하므로 두 명령 모두에 실제 논리 섹터 크기를 지정하세요. GPT 메타데이터 섹터를 숨겨진 볼륨으로 오인하지 마세요.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

`fsstat`가 gap 시작 부분에서 파일 시스템을 식별하지 못하면 TestDisk의 **Analyse → Quick Search**를 사용하고, 필요한 경우 **Deeper Search**를 실행하세요. 후보에서 `P`를 눌러 파일을 확인하고, 증거 이미지에서는 **Write**를 선택하지 마세요. GPT 이미지에서 `sgdisk --verify disk.img`는 CRC와 주 파티션 테이블/백업 파티션 테이블의 일치 여부를 확인하지만, 파티션을 다시 나눈 뒤 백업 헤더가 오래된 상태일 수 있으므로 복구 전에 파일 시스템 구조를 통해 후보 경계를 교차 확인하세요.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## 파일 시스템

### Windows 파일 시스템 목록

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** 파일 시스템은 핵심 구성 요소인 파일 할당 테이블을 볼륨 시작 부분에 두는 방식으로 설계되었습니다. 일반적으로 볼륨에는 **FAT 복사본이 두 개** 있지만, BPB에서는 하나만 허용합니다. FAT12/16은 루트 디렉터리를 고정 영역에 두고, FAT32는 `BPB_RootClus`에 지정된 클러스터의 데이터 영역에 루트 디렉터리를 저장합니다.<sup>[[7]](#references)</sup>

할당 단위는 **클러스터**이며, 크기는 `BPB_BytsPerSec × BPB_SecPerClus`로 결정되므로 반드시 512바이트인 것은 아닙니다. FAT 유형은 부트 섹터의 버전 문자열이 아니라 데이터 클러스터 수로 결정됩니다. 클러스터 수의 경계는 다음과 같습니다.<sup>[[7]](#references)</sup>

- **FAT12**: 데이터 클러스터 4,085개 미만.
- **FAT16**: 데이터 클러스터 4,085~65,524개.
- **FAT32**: 데이터 클러스터 65,525개 이상. 32비트 FAT 항목 중 클러스터 번호에는 28비트만 사용됩니다.

32비트 파일 크기 필드로 인해 일반 파일의 최대 크기는 **2³²−1바이트**(4GiB보다 약간 작음)입니다.<sup>[[7]](#references)</sup>

루트 디렉터리의 주요 구성 요소는 특히 FAT12 및 FAT16에서 다음과 같습니다.

- **파일/폴더 이름** (최대 8자)
- **속성**
- **생성, 수정 및 마지막 액세스 날짜**
- **FAT 테이블 주소** (파일의 시작 클러스터를 나타냄)
- **파일 크기**

### EXT

**Ext2**는 부트 파티션처럼 **저널링을 사용하지 않는**(**변경이 거의 없는**) 파티션에 가장 흔히 사용되는 파일 시스템입니다. **Ext3/4**는 **저널링을 사용하며**, 일반적으로 **나머지 파티션**에 사용됩니다.

## **메타데이터**

일부 파일에는 메타데이터가 포함되어 있습니다. 이 정보는 파일의 콘텐츠에 관한 것으로, 파일 형식에 따라 분석가에게 유용한 정보가 포함될 수 있습니다. 예를 들면 다음과 같습니다.

- 제목
- 사용된 MS Office 버전
- 작성자
- 생성 및 마지막 수정 날짜
- 카메라 모델
- GPS 좌표
- 이미지 정보

[**exiftool**](https://exiftool.org) 및 [**Metadiver**](https://www.easymetadata.com/metadiver-2/) 같은 도구를 사용해 파일의 메타데이터를 확인할 수 있습니다.

## **삭제된 파일 복구**

### 기록된 삭제 파일

앞서 살펴본 것처럼 파일이 "삭제된" 뒤에도 파일이 저장된 상태로 남아 있을 수 있는 위치가 여러 곳 있습니다. 파일 시스템에서 파일을 삭제하면 일반적으로 파일을 삭제된 것으로 표시할 뿐 데이터 자체는 건드리지 않기 때문입니다. 따라서 MFT 같은 파일 레지스트리를 살펴보고 삭제된 파일을 찾을 수 있습니다.<sup>[[2]](#references)</sup>

또한 OS는 파일 시스템 변경 및 백업에 관한 정보를 많이 저장하므로, 이를 사용해 파일이나 가능한 한 많은 정보를 복구할 수 있습니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**은 **데이터 덩어리에서 파일을 찾는** 기법입니다. 이와 같은 도구는 크게 세 가지 방식으로 작동합니다. **파일 형식의 헤더와 푸터를 기반으로 하는 방식**, 파일 형식의 **구조를 기반으로 하는 방식**, 그리고 **콘텐츠 자체를 기반으로 하는 방식**입니다.

단순한 헤더/푸터 carving은 데이터 블록이 연속되어 있다고 가정하므로 파일이 조각나 있으면 일부만 반환할 수 있습니다. 하지만 이것이 절대적인 한계는 아닙니다. PhotoRec에는 일부 조각난 JPEG를 대상으로 하는 CPU 집약적인 **Paranoid → bruteforce** 옵션이 있으며, 형식을 고려한 fragment reassembly를 통해 다른 지원 형식도 복구할 수 있습니다. 최신 fragment-reassembly 워크플로는 [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving)를 참조하세요.<sup>[[8]](#references)</sup>

검색할 파일 형식을 지정해 File Carving을 수행할 수 있는 도구가 여러 가지 있습니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving은 File Carving과 비슷하지만 **완전한 파일을 찾는 대신 관심 있는 정보 조각을 찾습니다**.\
예를 들어, 기록된 URL이 포함된 완전한 파일을 찾는 대신 이 기법은 URL을 검색합니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 안전한 삭제

물론 파일과 파일에 관한 로그 일부를 **"안전하게" 삭제하는** 방법도 있습니다. 예를 들어 파일의 콘텐츠를 여러 차례 쓰레기 데이터로 **덮어쓴 다음**, 파일에 관한 **$MFT** 및 **$LOGFILE**의 **로그를 제거하고**, **Volume Shadow Copies를 삭제**할 수 있습니다.<sup>[[3]](#references)</sup>\
이런 작업을 수행하더라도 파일의 존재가 기록된 다른 부분이 남아 있을 수 있습니다. 이는 사실이며, 이를 찾아내는 것도 포렌식 전문가의 업무 중 하나입니다.



## References

- [1] [GUID 파티션 테이블 - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [삭제된 파일의 증거를 찾기 위해 NTFS $I30(디렉터리) 항목을 검사하는 방법](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI 사양: GPT 디스크 레이아웃](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit mmls 매뉴얼](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit fsstat 매뉴얼](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT 사양](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec 복구 옵션](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDisk 삭제된 파티션 복구](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdisk 매뉴얼](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8) 매뉴얼](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
