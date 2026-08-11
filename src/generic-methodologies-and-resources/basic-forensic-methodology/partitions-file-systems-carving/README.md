# 파티션/파일 시스템/Carving

{{#include ../../../banners/hacktricks-training.md}}

## 파티션

하드 드라이브 또는 **SSD 디스크에는 데이터를 물리적으로 분리하기 위한 서로 다른 파티션이 포함될 수 있습니다**.\
디스크의 **최소** 단위는 **sector**(일반적으로 512B로 구성됨)입니다. 따라서 각 파티션의 크기는 해당 크기의 배수여야 합니다.

### MBR (master Boot Record)

이는 **446B의 boot code 이후 디스크의 첫 번째 sector**에 할당됩니다. 이 sector는 PC에 파티션을 무엇으로, 어디에서 mount해야 하는지 나타내는 데 필수적입니다.\
최대 **4개의 파티션**을 허용하며(최대 **1개만** active/**bootable**일 수 있음), 더 많은 파티션이 필요한 경우 **extended partitions**를 사용할 수 있습니다. 이 첫 번째 sector의 **마지막 byte**는 boot record signature인 **0x55AA**입니다. active로 표시할 수 있는 파티션은 하나뿐입니다.\
MBR은 **최대 2.2TB**를 허용합니다.

![Partitions - MBR (master Boot Record): MBR은 최대 2.2TB를 허용합니다](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR은 최대 2.2TB를 허용합니다](<../../../images/image (304).png>)

MBR의 **bytes 440~443**에서는 **Windows Disk Signature**(Windows를 사용하는 경우)를 찾을 수 있습니다. 하드 디스크의 logical drive letter는 Windows Disk Signature에 따라 결정됩니다. 이 signature를 변경하면 Windows가 boot되지 않을 수 있습니다(tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): MBR의 bytes 440~443에서는 Windows Disk Signature(Windows를 사용하는 경우)를 찾을 수 있습니다. 하드 디스크의 logical drive letter는 Windows Disk Signature에 따라 결정됩니다...](<../../../images/image (310).png>)

**형식**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Partition Record 형식**

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

Linux에서 MBR을 mount하려면 먼저 start offset을 확인해야 합니다(`fdisk`와 `p` 명령을 사용할 수 있음).

![Partitions - MBR (master Boot Record): Linux에서 MBR을 mount하려면 먼저 start offset을 확인해야 합니다(fdisk와 p 명령을 사용할 수 있음)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

그런 다음 다음 code를 사용합니다
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**)는 컴퓨터 저장 장치, 일반적으로 하드 디스크 드라이브와 같은 보조 저장 시스템에 저장된 데이터 **블록의 위치를 지정**하는 데 사용되는 일반적인 방식입니다. LBA는 특히 간단한 선형 주소 지정 방식입니다. **블록은 정수 인덱스로 위치가 지정**되며, 첫 번째 블록은 LBA 0, 두 번째 블록은 LBA 1과 같은 방식으로 이어집니다.

### GPT (GUID Partition Table)

GUID Partition Table, 즉 GPT는 MBR (Master Boot Record)과 비교해 향상된 기능을 제공하므로 선호됩니다. 파티션에 대한 **globally unique identifier**가 특징인 GPT는 다음과 같은 여러 차이점이 있습니다.

- **위치 및 크기**: GPT와 MBR 모두 **sector 0**에서 시작합니다. 그러나 GPT는 MBR의 32bits와 대조적으로 **64bits**에서 동작합니다.
- **파티션 제한**: GPT는 Windows 시스템에서 최대 **128개 파티션**을 지원하며 최대 **9.4ZB**의 데이터를 수용합니다.
- **파티션 이름**: 최대 36개의 Unicode 문자로 파티션 이름을 지정할 수 있습니다.

**Data Resilience and Recovery**:

- **Redundancy**: MBR과 달리 GPT는 파티션 및 boot data를 한 곳에만 저장하지 않습니다. 이 데이터를 디스크 전체에 복제하여 data integrity와 resilience를 향상합니다.
- **Cyclic Redundancy Check (CRC)**: GPT는 data integrity를 보장하기 위해 CRC를 사용합니다. 데이터 손상을 적극적으로 모니터링하며, 손상이 감지되면 GPT는 다른 디스크 위치에서 손상된 데이터를 복구하려고 시도합니다.

**Protective MBR (LBA0)**:

- GPT는 protective MBR을 통해 backward compatibility를 유지합니다. 이 기능은 legacy MBR 영역에 존재하지만, 이전 MBR 기반 utility가 GPT 디스크를 실수로 덮어쓰지 못하도록 설계되어 GPT 형식 디스크의 data integrity를 보호합니다.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

EFI가 아닌 **BIOS** services를 통해 **GPT-based boot**를 지원하는 operating system에서는 첫 번째 sector가 여전히 **bootloader** code의 첫 번째 단계를 저장하는 데 사용될 수 있지만, **GPT** **partitions**를 인식하도록 **modified**되어야 합니다. MBR의 bootloader는 sector size가 512 bytes라고 가정해서는 안 됩니다.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Partition table header는 디스크에서 사용할 수 있는 block을 정의합니다. 또한 partition table을 구성하는 partition entry의 수와 크기도 정의합니다 (table의 offset 80 및 84).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h 또는 little-endian machine에서 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8용 Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | little endian의 Header size (bytes 단위, 일반적으로 5Ch 00h 00h 00h 또는 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | little endian의 header CRC32 ([CRC32](https://en.wikipedia.org/wiki/CRC32)) (offset +0부터 header size까지), 계산 중에는 이 field를 zero로 설정                             |
| 20 (0x14) | 4 bytes  | Reserved; 반드시 zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (이 header copy의 위치)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (다른 header copy의 위치)                                                                                                                               |
| 40 (0x28) | 8 bytes  | 파티션에서 사용할 수 있는 첫 번째 LBA (primary partition table의 마지막 LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | 사용할 수 있는 마지막 LBA (secondary partition table의 첫 번째 LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | mixed endian의 Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | partition entry 배열의 Starting LBA (primary copy에서는 항상 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | 배열의 partition entry 수                                                                                                                                         |
| 84 (0x54) | 4 bytes  | 단일 partition entry의 크기 (일반적으로 80h 또는 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | little endian의 partition entry 배열 CRC32                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; block의 나머지 부분은 zero여야 함 (sector size가 512 bytes인 경우 420 bytes이며, 더 큰 sector size에서는 더 클 수 있음)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, 일반적으로 홀수)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (예: bit 60은 read-only를 나타냄)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

더 많은 partition type은 [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)을 참조하십시오.<sup>[[1]](#references)</sup>

### Inspecting

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/)로 forensics image를 mount한 후, Windows tool인 [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.**를 사용하여 첫 번째 sector를 inspect할 수 있습니다. 다음 이미지에서는 **sector 0**에서 **MBR**이 감지되고 해석되었습니다.

![GPT (GUID Partition Table) - Inspecting: ArsenalImageMounter로 forensics image를 mount한 후 Windows tool인 Active Disk Editor를 사용하여 첫 번째 sector를 inspect할 수 있습니다. 다음 이미지에서는...](<../../../images/image (354).png>)

**MBR** 대신 **GPT table**인 경우 **sector 1**에 signature _EFI PART_가 표시되어야 합니다 (이전 이미지에서는 비어 있는 위치).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system은 volume 시작 부분에 배치된 핵심 구성 요소인 file allocation table을 중심으로 설계되었습니다. 이 system은 table을 **두 개 복사본**으로 유지하여 한 복사본이 손상되더라도 data integrity를 보장합니다. table과 root folder는 **fixed location**에 있어야 하며, 이는 system의 startup process에 필수적입니다.

file system의 기본 storage unit은 **cluster, 일반적으로 512B**이며 여러 sector로 구성됩니다. FAT는 다음과 같이 발전해 왔습니다.

- **FAT12**: 12-bit cluster address를 지원하며 최대 4078개의 cluster를 처리합니다 (UNIX에서는 4084개).
- **FAT16**: 16-bit address로 확장되어 최대 65,517개의 cluster를 수용합니다.
- **FAT32**: 32-bit address로 더욱 발전하여 volume당 최대 268,435,456개의 cluster를 허용합니다.

모든 FAT version에서 중요한 limitation은 **4GB maximum file size**입니다. 이는 file size 저장에 사용되는 32-bit field에 의해 부과됩니다.

root directory의 주요 구성 요소, 특히 FAT12와 FAT16의 구성 요소는 다음과 같습니다.

- **File/Folder Name** (최대 8 characters)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (file의 시작 cluster를 나타냄)
- **File Size**

### EXT

**Ext2**는 **not journaling** partition (**변경이 많지 않은 partition**)에서 가장 일반적인 file system이며, boot partition과 같은 곳에 사용됩니다. **Ext3/4**는 **journaling** file system이며 일반적으로 **나머지 partition**에 사용됩니다.

## **Metadata**

일부 file에는 metadata가 포함되어 있습니다. 이 정보는 file content에 관한 것으로, file type에 따라 다음과 같은 정보가 포함될 수 있으므로 analyst에게 흥미로울 수 있습니다.

- Title
- 사용된 MS Office Version
- Author
- Creation 및 last modification dates
- Camera model
- GPS coordinates
- Image information

[**exiftool**](https://exiftool.org) 및 [**Metadiver**](https://www.easymetadata.com/metadiver-2/)와 같은 tool을 사용하여 file의 metadata를 확인할 수 있습니다.

## **Deleted Files Recovery**

### Logged Deleted Files

앞서 살펴본 것처럼 file이 "deleted"된 후에도 여전히 저장되는 여러 위치가 있습니다. 일반적으로 file system에서 file을 삭제해도 deleted로 표시만 할 뿐 data 자체는 건드리지 않기 때문입니다. 따라서 file registry (예: MFT)를 inspect하여 deleted file을 찾을 수 있습니다.<sup>[[2]](#references)</sup>

또한 OS는 일반적으로 file system 변경 사항과 backup에 대한 많은 정보를 저장하므로, 이를 사용하여 file 또는 가능한 한 많은 정보를 복구할 수 있습니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving**은 **대량의 데이터에서 file을 찾으려는** technique입니다. 이러한 tool이 동작하는 주요 방식은 3가지입니다. **file type header와 footer 기반**, file type **structure 기반**, 그리고 **content 자체 기반**입니다.

이 technique은 **fragmented file을 retrieve하는 데 동작하지 않는다**는 점에 유의해야 합니다. file이 **contiguous sector에 저장되어 있지 않으면**, 이 technique은 file 전체 또는 최소한 그 일부를 찾을 수 없습니다.

File Carving에 사용할 수 있는 여러 tool이 있으며, 검색하려는 file type을 지정할 수 있습니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving은 File Carving과 유사하지만 **완전한 file을 찾는 대신 흥미로운 information fragment를 찾습니다**.\
예를 들어 logged URL이 포함된 완전한 file을 찾는 대신, 이 technique은 URL을 검색합니다.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

분명히 file과 file에 관한 log의 일부를 **"secure하게" 삭제**하는 방법이 있습니다. 예를 들어 file의 **content를 junk data로 여러 번 overwrite**한 다음, 해당 file에 대한 **log**를 **$MFT**와 **$LOGFILE**에서 **remove**하고 **Volume Shadow Copies**를 **remove**할 수 있습니다.<sup>[[3]](#references)</sup>\
이 작업을 수행하더라도 file의 존재가 여전히 **log로 기록된 다른 부분**이 있을 수 있으며, 이는 사실입니다. 이러한 부분을 찾는 것이 forensics professional의 업무 중 일부입니다.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [삭제된 file의 증거를 찾기 위해 NTFS $I30 (directory) entry를 scan하는 방법](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
