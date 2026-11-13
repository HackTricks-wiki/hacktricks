# Partitions/File Systems/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

A disk can contain multiple **partitions**: logical ranges of blocks, not physically separate storage. Partition starts and lengths are measured in **logical sectors**; do not assume every image uses 512-byte sectors, because 4096-byte logical sectors also exist.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

The MBR occupies the first logical sector (LBA 0); its four 16-byte partition entries begin at byte 446. The preceding area includes boot code and may include a disk signature.<sup>[[4]](#references)</sup>\
It allows up to **4 partitions** (at most **just 1** can be active/**bootable**). However, if you need more partitions you can use **extended partitions**. The last **two bytes** of the 512-byte MBR are the boot signature **0x55 0xAA**. Only one partition can be marked as active.\
With 512-byte logical sectors, MBR's 32-bit sector fields limit addressability to about **2 TiB** (2.2 TB).<sup>[[4]](#references)</sup>

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (304).png>)

From the **bytes 440 to the 443** of the MBR you can find the **Windows Disk Signature** (if Windows is used). The logical drive letter of the hard disk depends on the Windows Disk Signature. Changing this signature could prevent Windows from booting (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): From the bytes 440 to the 443 of the MBR you can find the Windows Disk Signature (if Windows is used). The logical drive letter of the hard disk...](<../../../images/image (310).png>)

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

To inspect a partition in a whole-disk MBR image, obtain its start LBA and logical sector size first. `mount` takes a **byte offset**, not an LBA; the example below is valid only for a 512-byte-sector image whose partition begins at LBA 63. For untrusted images or journaled filesystems, use the isolated, read-only workflow in [Image Acquisition & Mount](../image-acquisition-and-mount.md) instead.<sup>[[5]](#references)[[11]](#references)</sup>

![Partitions - MBR (master Boot Record): In order to mount an MBR in Linux you first need to get the start offset (you can use fdisk and the p command)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) is a common scheme used for **specifying the location of blocks** of data stored on computer storage devices, generally secondary storage systems such as hard disk drives. LBA is a particularly simple linear addressing scheme; **blocks are located by an integer index**, with the first block being LBA 0, the second LBA 1, and so on.

### GPT (GUID Partition Table)

The GUID Partition Table (GPT) stores a unique GUID for each partition and uses primary and backup metadata. Its layout differs from MBR as follows:<sup>[[4]](#references)</sup>

- **Location and Size**: LBA 0 contains a **protective MBR**. The primary GPT header is at LBA 1; its partition-entry array follows it, and a backup array and header are at the end of the disk. GPT uses 64-bit LBA fields, while MBR partition entries use 32-bit LBA fields.
- **Partition Limits**: A common 16-KiB entry array holds **128 entries of 128 bytes**, but the entry count is recorded in the header rather than fixed by GPT. The addressable size also depends on logical sector size (about **9.4 ZB** with 512-byte sectors).<sup>[[4]](#references)</sup>
- **Partition Names**: Offers the ability to name partitions with up to 36 Unicode characters.

**Data Resilience and Recovery**:

- **Redundancy**: Unlike MBR, GPT doesn't confine partitioning and boot data to a single place. It replicates this data across the disk, enhancing data integrity and resilience.
- **Cyclic Redundancy Check (CRC)**: The header and partition-entry array each have a CRC32. A CRC detects inconsistency; it does not continuously monitor or itself repair the disk. If the primary copy is invalid, validate the backup at the last LBA before any recovery on a working copy.<sup>[[4]](#references)</sup>

**Protective MBR (LBA0)**:

- GPT maintains backward compatibility through a protective MBR. This feature resides in the legacy MBR space but is designed to prevent older MBR-based utilities from mistakenly overwriting GPT disks, hence safeguarding the data integrity on GPT-formatted disks.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

In operating systems that support **GPT-based boot through BIOS** services rather than EFI, the first sector may also still be used to store the first stage of the **bootloader** code, but **modified** to recognize **GPT** **partitions**. The bootloader in the MBR must not assume a sector size of 512 bytes.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

The partition table header defines the usable blocks on the disk. It also defines the number and size of the partition entries that make up the partition table (offsets 80 and 84 in the table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

More partition types in [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspecting

After mounting the forensics image with [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), you can inspect the first sector using the Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** In the following image an **MBR** was detected on the **sector 0** and interpreted:

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

For GPT, look for the _EFI PART_ signature in the primary header at **LBA 1**; LBA 0 still contains the protective MBR.<sup>[[4]](#references)</sup>

### Finding data outside listed partitions

A deleted partition entry or deliberately unused gap can leave a filesystem outside the current partition map. On a **verified raw working copy**, list unallocated ranges, then test a candidate start LBA as a filesystem. `mmls` and `fsstat` use **sector offsets**; give both the actual logical sector size. Do not mistake GPT metadata sectors for a hidden volume.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

If `fsstat` cannot identify a filesystem at the gap start, use TestDisk **Analyse → Quick Search**, then **Deeper Search** if needed. Press `P` on a candidate to inspect files; do not select **Write** on evidence. On GPT images, `sgdisk --verify disk.img` checks CRCs and main/backup agreement, but a backup header can be stale after repartitioning, so corroborate candidate boundaries with filesystem structures before recovery.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

The **FAT (File Allocation Table)** file system is designed around its core component, the file allocation table, positioned at the volume's start. A volume commonly has **two FAT copies**, though the BPB permits one. FAT12/16 place the root directory in a fixed region; FAT32 stores its root directory in the data area at the cluster named by `BPB_RootClus`.<sup>[[7]](#references)</sup>

The allocation unit is a **cluster**: `BPB_BytsPerSec × BPB_SecPerClus`, not necessarily 512 bytes. FAT type is determined by the number of data clusters, not by a version string in the boot sector. The cluster-count boundaries are:<sup>[[7]](#references)</sup>

- **FAT12**: fewer than 4,085 data clusters.
- **FAT16**: 4,085 to 65,524 data clusters.
- **FAT32**: at least 65,525 data clusters; only 28 bits of each 32-bit FAT entry are used for the cluster number.

The 32-bit file-size field limits a regular file to **2³²−1 bytes** (just under 4 GiB).<sup>[[7]](#references)</sup>

Key components of the root directory, particularly for FAT12 and FAT16, include:

- **File/Folder Name** (up to 8 characters)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (indicating the start cluster of the file)
- **File Size**

### EXT

**Ext2** is the most common file system for **not journaling** partitions (**partitions that don't change much**) like the boot partition. **Ext3/4** are **journaling** and are used usually for the **rest partitions**.

## **Metadata**

Some files contain metadata. This information is about the content of the file which sometimes might be interesting to an analyst as depending on the file type, it might have information like:

- Title
- MS Office Version used
- Author
- Dates of creation and last modification
- Model of the camera
- GPS coordinates
- Image information

You can use tools like [**exiftool**](https://exiftool.org) and [**Metadiver**](https://www.easymetadata.com/metadiver-2/) to get the metadata of a file.

## **Deleted Files Recovery**

### Logged Deleted Files

As was seen before there are several places where the file is still saved after it was "deleted". This is because usually the deletion of a file from a file system just marks it as deleted but the data isn't touched. Then, it's possible to inspect the registries of the files (like the MFT) and find the deleted files.<sup>[[2]](#references)</sup>

Also, the OS usually saves a lot of information about file system changes and backups, so it's possible to try to use them to recover the file or as much information as possible.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** is a technique that tries to **find files in the bulk of data**. There are 3 main ways tools like this work: **Based on file types headers and footers**, based on file types **structures** and based on the **content** itself.

Simple header/footer carving assumes contiguous blocks and can return only a fragment when a file is split. This is not an absolute limit: PhotoRec has a CPU-intensive **Paranoid → bruteforce** option for some fragmented JPEGs, while format-aware fragment reassembly can recover other supported types. See [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) for a current fragment-reassembly workflow.<sup>[[8]](#references)</sup>

There are several tools that you can use for file Carving indicating the file types you want to search for


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving is similar to File Carving but **instead of looking for complete files, it looks for interesting fragments** of information.\
For example, instead of looking for a complete file containing logged URLs, this technique will search for URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Obviously, there are ways to **"securely" delete files and part of logs about them**. For example, it's possible to **overwrite the content** of a file with junk data several times, and then **remove** the **logs** from the **$MFT** and **$LOGFILE** about the file, and **remove the Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
You may notice that even performing that action there might be **other parts where the existence of the file is still logged**, and that's true and part of the forensics professional job is to find them.



## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI specification: GPT disk layout](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit mmls manual](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit fsstat manual](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT specification](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec recovery options](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDisk deleted-partition recovery](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdisk manual](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8) manual](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
