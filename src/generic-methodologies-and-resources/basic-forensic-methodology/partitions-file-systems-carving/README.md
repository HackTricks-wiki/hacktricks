# 파티션/파일 시스템/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 파티션

하드 드라이브 또는 **SSD disk에는 데이터를 물리적으로 분리하기 위한 여러 파티션이 포함될 수 있습니다**.\
디스크의 **최소** 단위는 **sector**(일반적으로 512B로 구성됨)입니다. 따라서 각 파티션의 크기는 해당 크기의 배수여야 합니다.

### MBR (master Boot Record)

MBR은 **446B의 boot code 다음 디스크의 첫 번째 sector**에 할당됩니다. 이 sector는 PC에 어떤 파티션을 어디에서 mount해야 하는지 알려주는 데 필수적입니다.\
최대 **4개의 파티션**을 지원하며(최대 **1개만** active/**bootable**일 수 있음), 더 많은 파티션이 필요한 경우 **extended partitions**를 사용할 수 있습니다. 이 첫 번째 sector의 **마지막 byte**는 boot record signature인 **0x55AA**입니다. active로 표시할 수 있는 파티션은 하나뿐입니다.\
MBR은 **최대 2.2TB**를 지원합니다.

![파티션 - MBR (master Boot Record): MBR은 최대 2.2TB를 지원합니다](<../../../images/image (350).png>)

![파티션 - MBR (master Boot Record): MBR은 최대 2.2TB를 지원합니다](<../../../images/image (304).png>)

MBR의 **440~443 bytes**에서 **Windows Disk Signature**를 확인할 수 있습니다(Windows를 사용하는 경우). 하드 디스크의 logical drive letter는 Windows Disk Signature에 따라 결정됩니다. 이 signature를 변경하면 Windows가 boot되지 않을 수 있습니다(tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![파티션 - MBR (master Boot Record): MBR의 440~443 bytes에서 Windows Disk Signature를 확인할 수 있습니다(Windows를 사용하는 경우). 하드 디스크의 logical drive letter...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | 첫 번째 파티션     |
| 462 (0x1CE) | 16 (0x10)  | 두 번째 파티션      |
| 478 (0x1DE) | 16 (0x10)  | 세 번째 파티션      |
| 494 (0x1EE) | 16 (0x10)  | 네 번째 파티션      |
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

Linux에서 MBR을 mount하려면 먼저 start offset을 확인해야 합니다(`fdisk`와 `p` command를 사용할 수 있음).

![파티션 - MBR (master Boot Record): Linux에서 MBR을 mount하려면 먼저 start offset을 확인해야 합니다(fdisk와 p command를 사용할 수 있음)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

그런 다음 다음 code를 사용합니다
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**)은 컴퓨터 저장 장치, 일반적으로 하드 디스크 드라이브와 같은 보조 저장 시스템에 저장된 **데이터 블록의 위치를 지정하는** 데 사용되는 일반적인 방식입니다. LBA는 특히 단순한 선형 주소 지정 방식으로, **블록은 정수 인덱스로 위치를 지정**하며 첫 번째 블록은 LBA 0, 두 번째 블록은 LBA 1, 그다음은 계속 증가합니다.

### GPT (GUID Partition Table)

GUID Partition Table(GPT)은 MBR (Master Boot Record)에 비해 향상된 기능을 제공하므로 선호됩니다. 파티션에 대한 **globally unique identifier**가 특징인 GPT는 다음과 같은 여러 차이점이 있습니다.

- **위치 및 크기**: GPT와 MBR 모두 **sector 0**에서 시작합니다. 그러나 GPT는 MBR의 32bits와 달리 **64bits**로 동작합니다.
- **파티션 제한**: GPT는 Windows 시스템에서 최대 **128개의 파티션**을 지원하며 최대 **9.4ZB**의 데이터를 처리할 수 있습니다.
- **파티션 이름**: 최대 36개의 Unicode 문자로 파티션 이름을 지정할 수 있습니다.

**데이터 복원력 및 복구**:

- **Redundancy**: MBR과 달리 GPT는 파티션 및 boot 데이터를 단일 위치에만 저장하지 않습니다. 이 데이터를 디스크 전체에 복제하여 데이터 무결성과 복원력을 향상합니다.
- **Cyclic Redundancy Check (CRC)**: GPT는 데이터 무결성을 보장하기 위해 CRC를 사용합니다. 데이터 손상을 적극적으로 감시하며, 손상이 감지되면 GPT는 다른 디스크 위치에서 손상된 데이터를 복구하려고 시도합니다.

**Protective MBR (LBA0)**:

- GPT는 protective MBR을 통해 backward compatibility를 유지합니다. 이 기능은 legacy MBR 영역에 위치하지만, 이전 MBR 기반 utility가 GPT 디스크를 실수로 덮어쓰지 못하도록 설계되어 GPT 형식 디스크의 데이터 무결성을 보호합니다.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

EFI가 아닌 **BIOS** services를 통해 **GPT 기반 boot**를 지원하는 operating systems에서는 첫 번째 sector가 여전히 **bootloader** code의 첫 번째 stage를 저장하는 데 사용될 수 있지만, **GPT** **partitions**를 인식하도록 **modified**됩니다. MBR의 bootloader는 sector size가 512 bytes라고 가정해서는 안 됩니다.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

partition table header는 디스크에서 사용할 수 있는 blocks를 정의합니다. 또한 partition table을 구성하는 partition entries의 수와 크기도 정의합니다(table의 offsets 80 및 84).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 또는 little-endian machines에서 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8의 Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian의 Header size (bytes 단위, 일반적으로 5Ch 00h 00h 00h 또는 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | little endian의 header [CRC32](https://en.wikipedia.org/wiki/CRC32) (offset +0부터 header size까지); 계산 중에는 이 field를 zero로 설정                             |
| 20 (0x14) | 4 bytes  | Reserved; zero여야 함                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (이 header copy의 location)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (다른 header copy의 location)                                                                                                                               |
| 40 (0x28) | 8 bytes  | partitions에 사용할 수 있는 First usable LBA (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endian의 Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | partition entries array의 Starting LBA (primary copy에서는 항상 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | array 내 partition entries의 수                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 단일 partition entry의 Size (일반적으로 80h 또는 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endian의 partition entries array CRC32                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; block의 나머지 부분은 zeroes여야 함 (sector size가 512 bytes인 경우 420 bytes이며, sector size가 더 크면 더 많을 수 있음)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, 일반적으로 odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (예: bit 60은 read-only를 나타냄)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

더 많은 partition types는 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>에서 확인할 수 있습니다.

### Inspecting

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)로 forensics image를 mount한 후, Windows tool인 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.**를 사용하여 first sector를 inspect할 수 있습니다. 다음 image에서는 **MBR**이 **sector 0**에서 감지되고 해석되었습니다.

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

**MBR** 대신 **GPT table**이었다면 **sector 1**에 _EFI PART_ signature가 표시되어야 합니다(이전 image에서는 비어 있는 위치).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system은 volume 시작 부분에 배치된 핵심 component인 file allocation table을 중심으로 설계되었습니다. 이 system은 table의 **두 개 copy**를 유지하여 한 copy가 손상되더라도 data integrity를 보장합니다. table과 root folder는 system startup process에 중요하므로 **fixed location**에 있어야 합니다.

file system의 기본 storage 단위는 **cluster(일반적으로 512B)**이며, 여러 sector로 구성됩니다. FAT는 다음과 같이 발전해 왔습니다.

- **FAT12**: 12-bit cluster addresses를 지원하며 최대 4078개의 clusters(UNIX에서는 4084개)를 처리합니다.
- **FAT16**: 16-bit addresses로 확장되어 최대 65,517개의 clusters를 수용합니다.
- **FAT32**: 32-bit addresses로 더욱 확장되어 volume당 최대 268,435,456개의 clusters를 허용합니다.

모든 FAT versions의 중요한 limitation은 **4GB maximum file size**이며, 이는 file size 저장에 사용되는 32-bit field에 의해 발생합니다.

root directory의 주요 components, 특히 FAT12 및 FAT16에는 다음이 포함됩니다.

- **File/Folder Name** (최대 8 characters)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (file의 start cluster를 나타냄)
- **File Size**

### EXT

**Ext2**는 **not journaling** partitions(**자주 변경되지 않는 partitions**)에 사용되는 가장 일반적인 file system이며, boot partition이 그 예입니다. **Ext3/4**는 **journaling** 방식이며 일반적으로 **나머지 partitions**에 사용됩니다.

## **Metadata**

일부 files에는 metadata가 포함되어 있습니다. 이 정보는 file content에 관한 것으로, file type에 따라 다음과 같은 정보가 포함될 수 있으므로 analyst에게 흥미로울 수 있습니다.

- Title
- 사용된 MS Office Version
- Author
- Creation 및 last modification dates
- Camera model
- GPS coordinates
- Image information

[**exiftool**](https://exiftool.org) 및 [**Metadiver**](https://www.easymetadata.com/metadiver-2/)와 같은 tools를 사용하여 file의 metadata를 가져올 수 있습니다.

## **Deleted Files Recovery**

### Logged Deleted Files

앞서 살펴본 것처럼 file이 "deleted"된 후에도 여전히 저장되는 여러 위치가 있습니다. 일반적으로 file system에서 file을 삭제하면 단순히 deleted로 표시할 뿐 data 자체는 건드리지 않기 때문입니다. 따라서 files의 registries(예: MFT)를 inspect하여 deleted files를 찾을 수 있습니다.<sup>[[2]](#references)</sup>

또한 OS는 일반적으로 file system changes 및 backups에 관한 많은 정보를 저장하므로, 이를 사용하여 file 또는 가능한 한 많은 정보를 recover할 수 있습니다.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**은 **bulk of data에서 files를 찾으려는** technique입니다. 이러한 tools가 동작하는 주요 방식은 3가지입니다. **file types의 headers 및 footers 기반**, file types의 **structures 기반**, 그리고 **content 자체 기반**입니다.

이 technique은 **fragmented files를 retrieve하는 데는 동작하지 않는다**는 점에 유의해야 합니다. file이 **contiguous sectors에 저장되지 않은** 경우 이 technique은 해당 file 또는 적어도 그 일부를 찾을 수 없습니다.

검색하려는 file types를 지정하여 File Carving에 사용할 수 있는 여러 tools가 있습니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving은 File Carving과 유사하지만 **complete files를 찾는 대신 흥미로운 information fragments를 찾습니다**.\
예를 들어 logged URLs가 포함된 complete file을 찾는 대신, 이 technique은 URLs를 검색합니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

물론 files와 해당 files에 관한 logs의 일부를 **"secure하게" delete**하는 방법이 있습니다. 예를 들어 file의 **content를 junk data로 여러 번 overwrite**한 다음, file에 관한 **$MFT** 및 **$LOGFILE**의 **logs**를 **remove**하고 **Volume Shadow Copies**를 **remove**할 수 있습니다.<sup>[[3]](#references)</sup>\
이 작업을 수행하더라도 file의 존재가 여전히 **다른 부분에 기록되어 있을 수 있음**을 알 수 있으며, 이는 사실입니다. 이러한 부분을 찾는 것이 forensics professional의 업무 중 하나입니다.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
