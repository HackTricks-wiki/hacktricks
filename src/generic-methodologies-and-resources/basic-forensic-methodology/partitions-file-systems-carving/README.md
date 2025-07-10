# Partitions/File Systems/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

하드 드라이브 또는 **SSD 디스크는 데이터를 물리적으로 분리하기 위해 서로 다른 파티션을 포함할 수 있습니다**.\
디스크의 **최소** 단위는 **섹터**(정상적으로 512B로 구성됨)입니다. 따라서 각 파티션 크기는 그 크기의 배수여야 합니다.

### MBR (master Boot Record)

이는 **부트 코드의 446B 이후 디스크의 첫 번째 섹터에 할당됩니다**. 이 섹터는 PC에 파티션을 어디서 어떻게 마운트해야 하는지를 나타내는 데 필수적입니다.\
최대 **4개의 파티션**을 허용합니다(최대 **1개**만 활성/**부팅 가능**). 그러나 더 많은 파티션이 필요하면 **확장 파티션**을 사용할 수 있습니다. 이 첫 번째 섹터의 **마지막 바이트**는 부트 레코드 서명 **0x55AA**입니다. 하나의 파티션만 활성으로 표시할 수 있습니다.\
MBR은 **최대 2.2TB**를 허용합니다.

![](<../../../images/image (350).png>)

![](<../../../images/image (304).png>)

**MBR의 440에서 443 바이트**에서 **Windows 디스크 서명**을 찾을 수 있습니다(Windows가 사용되는 경우). 하드 디스크의 논리 드라이브 문자는 Windows 디스크 서명에 따라 달라집니다. 이 서명을 변경하면 Windows가 부팅되지 않을 수 있습니다(도구: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Partition Record Format**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active flag (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start head                                             |
| 2 (0x02)  | 1 (0x01) | Start sector (bits 0-5); upper bits of cylinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Start cylinder lowest 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partition type code (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End head                                               |
| 6 (0x06)  | 1 (0x01) | End sector (bits 0-5); upper bits of cylinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | End cylinder lowest 8 bits                             |
| 8 (0x08)  | 4 (0x04) | Sectors preceding partition (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sectors in partition                                   |

MBR을 Linux에 마운트하려면 먼저 시작 오프셋을 가져와야 합니다( `fdisk` 및 `p` 명령을 사용할 수 있습니다)

![](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

그런 다음 다음 코드를 사용하십시오.
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (논리 블록 주소 지정)**

**논리 블록 주소 지정** (**LBA**)은 컴퓨터 저장 장치에 저장된 데이터 블록의 위치를 지정하는 데 사용되는 일반적인 방식으로, 일반적으로 하드 디스크 드라이브와 같은 보조 저장 시스템에서 사용됩니다. LBA는 특히 간단한 선형 주소 지정 방식으로, **블록은 정수 인덱스로 위치가 지정되며**, 첫 번째 블록은 LBA 0, 두 번째는 LBA 1 등으로 이어집니다.

### GPT (GUID 파티션 테이블)

GUID 파티션 테이블, 즉 GPT는 MBR (마스터 부트 레코드)와 비교하여 향상된 기능으로 선호됩니다. 파티션에 대한 **전 세계적으로 고유한 식별자**로 구별되는 GPT는 여러 면에서 두드러집니다:

- **위치 및 크기**: GPT와 MBR은 모두 **섹터 0**에서 시작합니다. 그러나 GPT는 **64비트**로 작동하며, MBR의 32비트와 대조됩니다.
- **파티션 한계**: GPT는 Windows 시스템에서 최대 **128개의 파티션**을 지원하며, 최대 **9.4ZB**의 데이터를 수용할 수 있습니다.
- **파티션 이름**: 최대 36개의 유니코드 문자로 파티션 이름을 지정할 수 있습니다.

**데이터 복원력 및 복구**:

- **중복성**: MBR과 달리 GPT는 파티션 및 부트 데이터를 단일 위치에 제한하지 않습니다. 이 데이터를 디스크 전반에 복제하여 데이터 무결성과 복원력을 향상시킵니다.
- **순환 중복 검사 (CRC)**: GPT는 데이터 무결성을 보장하기 위해 CRC를 사용합니다. 데이터 손상을 적극적으로 모니터링하며, 손상이 감지되면 GPT는 다른 디스크 위치에서 손상된 데이터를 복구하려고 시도합니다.

**보호 MBR (LBA0)**:

- GPT는 보호 MBR을 통해 하위 호환성을 유지합니다. 이 기능은 레거시 MBR 공간에 존재하지만, 이전 MBR 기반 유틸리티가 GPT 디스크를 실수로 덮어쓰지 않도록 설계되어 GPT 형식의 디스크에서 데이터 무결성을 보호합니다.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**하이브리드 MBR (LBA 0 + GPT)**

[위키백과에서](https://en.wikipedia.org/wiki/GUID_Partition_Table)

**EFI** 대신 **BIOS** 서비스를 통해 **GPT 기반 부팅**을 지원하는 운영 체제에서는 첫 번째 섹터가 **부트로더** 코드의 첫 번째 단계를 저장하는 데 여전히 사용될 수 있지만, **GPT** **파티션**을 인식하도록 **수정**됩니다. MBR의 부트로더는 섹터 크기가 512바이트라고 가정해서는 안 됩니다.

**파티션 테이블 헤더 (LBA 1)**

[위키백과에서](https://en.wikipedia.org/wiki/GUID_Partition_Table)

파티션 테이블 헤더는 디스크에서 사용 가능한 블록을 정의합니다. 또한 파티션 테이블을 구성하는 파티션 항목의 수와 크기를 정의합니다 (테이블의 오프셋 80 및 84).

| 오프셋    | 길이   | 내용                                                                                                                                                                     |
| --------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0 (0x00)  | 8 바이트  | 서명 ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 또는 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)리틀 엔디안 머신에서) |
| 8 (0x08)  | 4 바이트  | UEFI 2.8을 위한 수정 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 바이트  | 리틀 엔디안의 헤더 크기 (바이트 단위, 일반적으로 5Ch 00h 00h 00h 또는 92 바이트)                                                                                                 |
| 16 (0x10) | 4 바이트  | [CRC32](https://en.wikipedia.org/wiki/CRC32) 헤더의 CRC (오프셋 +0에서 헤더 크기까지) 리틀 엔디안, 이 필드는 계산 중에 0으로 설정됨                                         |
| 20 (0x14) | 4 바이트  | 예약; 0이어야 함                                                                                                                                                           |
| 24 (0x18) | 8 바이트  | 현재 LBA (이 헤더 복사의 위치)                                                                                                                                           |
| 32 (0x20) | 8 바이트  | 백업 LBA (다른 헤더 복사의 위치)                                                                                                                                         |
| 40 (0x28) | 8 바이트  | 파티션의 첫 번째 사용 가능한 LBA (기본 파티션 테이블의 마지막 LBA + 1)                                                                                                   |
| 48 (0x30) | 8 바이트  | 마지막 사용 가능한 LBA (보조 파티션 테이블의 첫 번째 LBA − 1)                                                                                                          |
| 56 (0x38) | 16 바이트 | 혼합 엔디안의 디스크 GUID                                                                                                                                               |
| 72 (0x48) | 8 바이트  | 파티션 항목 배열의 시작 LBA (기본 복사본에서 항상 2)                                                                                                                   |
| 80 (0x50) | 4 바이트  | 배열의 파티션 항목 수                                                                                                                                                   |
| 84 (0x54) | 4 바이트  | 단일 파티션 항목의 크기 (일반적으로 80h 또는 128)                                                                                                                        |
| 88 (0x58) | 4 바이트  | 리틀 엔디안의 파티션 항목 배열의 CRC32                                                                                                                                |
| 92 (0x5C) | \*       | 예약; 블록의 나머지 부분에 대해 0이어야 함 (512바이트의 섹터 크기에 대해 420바이트; 그러나 더 큰 섹터 크기로 더 많을 수 있음)                                      |

**파티션 항목 (LBA 2–33)**

| GUID 파티션 항목 형식 |          |                                                                                                               |
| ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| 오프셋                 | 길이     | 내용                                                                                                         |
| 0 (0x00)               | 16 바이트 | [파티션 유형 GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (혼합 엔디안) |
| 16 (0x10)              | 16 바이트 | 고유 파티션 GUID (혼합 엔디안)                                                                               |
| 32 (0x20)              | 8 바이트  | 첫 번째 LBA ([리틀 엔디안](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)              | 8 바이트  | 마지막 LBA (포함, 일반적으로 홀수)                                                                           |
| 48 (0x30)              | 8 바이트  | 속성 플래그 (예: 비트 60은 읽기 전용을 나타냄)                                                               |
| 56 (0x38)              | 72 바이트 | 파티션 이름 (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE 코드 유닛)                               |

**파티션 유형**

![](<../../../images/image (83).png>)

더 많은 파티션 유형은 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)에서 확인할 수 있습니다.

### 검사

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)로 포렌식 이미지를 마운트한 후, Windows 도구인 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**를 사용하여 첫 번째 섹터를 검사할 수 있습니다.** 다음 이미지에서 **섹터 0**에서 **MBR**이 감지되고 해석되었습니다:

![](<../../../images/image (354).png>)

만약 **MBR** 대신 **GPT 테이블**이었다면, **섹터 1**에 서명 _EFI PART_가 나타나야 합니다 (이전 이미지에서는 비어 있습니다).

## 파일 시스템

### Windows 파일 시스템 목록

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (파일 할당 테이블)** 파일 시스템은 볼륨의 시작에 위치한 파일 할당 테이블을 중심으로 설계되었습니다. 이 시스템은 **두 개의 복사본**을 유지하여 데이터 무결성을 보장합니다. 테이블과 루트 폴더는 **고정된 위치**에 있어야 하며, 이는 시스템의 시작 프로세스에 중요합니다.

파일 시스템의 기본 저장 단위는 **클러스터, 일반적으로 512B**로, 여러 섹터로 구성됩니다. FAT는 다음과 같은 버전으로 발전해왔습니다:

- **FAT12**, 12비트 클러스터 주소를 지원하며 최대 4078 클러스터를 처리합니다 (UNIX와 함께 4084).
- **FAT16**, 16비트 주소로 향상되어 최대 65,517 클러스터를 수용합니다.
- **FAT32**, 32비트 주소로 더욱 발전하여 볼륨당 최대 268,435,456 클러스터를 허용합니다.

모든 FAT 버전에서의 주요 제한 사항은 **4GB 최대 파일 크기**로, 이는 파일 크기 저장에 사용되는 32비트 필드에 의해 부과됩니다.

특히 FAT12 및 FAT16의 루트 디렉토리의 주요 구성 요소는 다음과 같습니다:

- **파일/폴더 이름** (최대 8자)
- **속성**
- **생성, 수정 및 마지막 접근 날짜**
- **FAT 테이블 주소** (파일의 시작 클러스터를 나타냄)
- **파일 크기**

### EXT

**Ext2**는 **저널링하지 않는** 파티션 (**변경이 많지 않은 파티션**)에 가장 일반적인 파일 시스템입니다. **Ext3/4**는 **저널링**을 지원하며 일반적으로 **나머지 파티션**에 사용됩니다.

## **메타데이터**

일부 파일에는 메타데이터가 포함되어 있습니다. 이 정보는 파일의 내용에 대한 것으로, 파일 유형에 따라 분석가에게 흥미로울 수 있는 정보가 포함될 수 있습니다:

- 제목
- 사용된 MS Office 버전
- 저자
- 생성 및 마지막 수정 날짜
- 카메라 모델
- GPS 좌표
- 이미지 정보

[**exiftool**](https://exiftool.org) 및 [**Metadiver**](https://www.easymetadata.com/metadiver-2/)와 같은 도구를 사용하여 파일의 메타데이터를 얻을 수 있습니다.

## **삭제된 파일 복구**

### 기록된 삭제된 파일

이전에 보았듯이, 파일이 "삭제"된 후에도 여러 장소에 여전히 저장되어 있습니다. 이는 일반적으로 파일 시스템에서 파일을 삭제하는 것이 단순히 삭제로 표시할 뿐, 데이터는 손대지 않기 때문입니다. 따라서 파일의 레지스트리(예: MFT)를 검사하고 삭제된 파일을 찾는 것이 가능합니다.

또한, OS는 파일 시스템 변경 및 백업에 대한 많은 정보를 저장하므로, 이를 사용하여 파일이나 가능한 한 많은 정보를 복구할 수 있습니다.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **파일 카빙**

**파일 카빙**은 **대량의 데이터에서 파일을 찾으려는 기술**입니다. 이러한 도구는 **파일 유형 헤더 및 풋터**를 기반으로 하거나, 파일 유형의 **구조**를 기반으로 하거나, **내용** 자체를 기반으로 작동하는 3가지 주요 방법이 있습니다.

이 기술은 **조각화된 파일을 검색하는 데는 작동하지 않음을 유의하십시오**. 파일이 **연속 섹터에 저장되지 않으면**, 이 기술은 파일을 찾거나 적어도 일부를 찾을 수 없습니다.

파일 카빙을 위해 검색할 파일 유형을 지정할 수 있는 여러 도구가 있습니다.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 데이터 스트림 **C**arving

데이터 스트림 카빙은 파일 카빙과 유사하지만 **완전한 파일을 찾는 대신, 흥미로운 정보 조각을 찾습니다**.\
예를 들어, 기록된 URL을 포함하는 완전한 파일을 찾는 대신, 이 기술은 URL을 검색합니다.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### 안전한 삭제

물론, 파일 및 해당 로그의 일부를 **"안전하게" 삭제하는 방법이 있습니다**. 예를 들어, 파일의 내용을 여러 번 쓰레기 데이터로 덮어쓰고, **$MFT** 및 **$LOGFILE**에서 파일에 대한 **로그**를 제거하고, **볼륨 섀도 복사본**을 제거하는 것이 가능합니다.\
이 작업을 수행하더라도 **파일의 존재가 여전히 기록된 다른 부분이 있을 수 있음을 알 수 있습니다**, 이는 사실이며 포렌식 전문가의 작업 중 하나는 이를 찾는 것입니다.

## 참고 문헌

- [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
- [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- **iHackLabs 인증 디지털 포렌식 Windows**

{{#include ../../../banners/hacktricks-training.md}}
