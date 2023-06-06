# Partitions/File Systems/Carving

## Partitions/File Systems/Carving

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Partitions

A hard drive or an **SSD disk can contain different partitions** with the goal of separating data physically.\
The **minimum** unit of a disk is the **sector** (normally composed of 512B). So, each partition size needs to be multiple of that size.

### MBR (master Boot Record)

It's allocated in the **first sector of the disk after the 446B of the boot code**. This sector is essential to indicate to the PC what and from where a partition should be mounted.\
It allows up to **4 partitions** (at most **just 1** can be active/**bootable**). However, if you need more partitions you can use **extended partitions**. The **final byte** of this first sector is the boot record signature **0x55AA**. Only one partition can be marked as active.\
MBR allows **max 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

From the **bytes 440 to the 443** of the MBR you can find the **Windows Disk Signature** (if Windows is used). The logical drive letter of the hard disk depends on the Windows Disk Signature. Changing this signature could prevent Windows from booting (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

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

In order to mount an MBR in Linux you first need to get the start offset (you can use `fdisk` and the `p` command)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

And then use the following code

```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) is a common scheme used for **specifying the location of blocks** of data stored on computer storage devices, generally secondary storage systems such as hard disk drives. LBA is a particularly simple linear addressing scheme; **blocks are located by an integer index**, with the first block being LBA 0, the second LBA 1, and so on.

### GPT (GUID Partition Table)

It’s called GUID Partition Table because every partition on your drive has a **globally unique identifier**.

Just like MBR it starts in the **sector 0**. The MBR occupies 32bits while **GPT** uses **64bits**.\
GPT **allows up to 128 partitions** in Windows and up to **9.4ZB**.\
Also, partitions can have a 36 character Unicode name.

On an MBR disk, the partitioning and boot data are stored in one place. If this data is overwritten or corrupted, you’re in trouble. In contrast, **GPT stores multiple copies of this data across the disk**, so it’s much more robust and can recover if the data is corrupted.

GPT also stores **cyclic redundancy check (CRC)** values to check that its data is intact. If the data is corrupted, GPT can notice the problem and **attempt to recover the damaged data** from another location on the disk.

**Protective MBR (LBA0)**

For limited backward compatibility, the space of the legacy MBR is still reserved in the GPT specification, but it is now used in a **way that prevents MBR-based disk utilities from misrecognizing and possibly overwriting GPT disks**. This is referred to as a protective MBR.

![](<../../../.gitbook/assets/image (491).png>)

**Hybrid MBR (LBA 0 + GPT)**

In operating systems that support **GPT-based boot through BIOS** services rather than EFI, the first sector may also still be used to store the first stage of the **bootloader** code, but **modified** to recognize **GPT** **partitions**. The bootloader in the MBR must not assume a sector size of 512 bytes.

**Partition table header (LBA 1)**

The partition table header defines the usable blocks on the disk. It also defines the number and size of the partition entries that make up the partition table (offsets 80 and 84 in the table).

| Offset    | Length   | Contents                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                    |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                                |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                          |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                      |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                                  |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                          |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                       |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                       |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                        |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                            |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                           |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                               |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                         |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                          |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                              |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                                 |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                                   |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                                   |

**Partitions Types**

![](<../../../.gitbook/assets/image (492).png>)

More partition types in [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspecting

After mounting the forensics image with [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), you can inspect the first sector using the Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** In the following image an **MBR** was detected on the **sector 0** and interpreted:

![](<../../../.gitbook/assets/image (494).png>)

If it was a **GPT table instead of an MBR** it should appear the signature _EFI PART_ in the **sector 1** (which in the previous image is empty).

## File-Systems

### Windows file-systems list

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

The **FAT (File Allocation Table)** file system is named for its method of organization, the file allocation table, which resides at the beginning of the volume. To protect the volume, **two copies** of the table are kept, in case one becomes damaged. In addition, the file allocation tables and the root folder must be stored in a **fixed location** so that the files needed to start the system can be correctly located.

![](<../../../.gitbook/assets/image (495).png>)

The minimum space unit used by this file system is a **cluster, typically 512B** (which is composed of a number of sectors).

The earlier **FAT12** had a **cluster addresses to 12-bit** values with up to **4078** **clusters**; it allowed up to 4084 clusters with UNIX. The more efficient **FAT16** increased to **16-bit** cluster address allowing up to **65,517 clusters** per volume. FAT32 uses 32-bit cluster address allowing up to **268,435,456 clusters** per volume

The **maximum file size allowed by FAT is 4GB** (minus one byte) because the file system uses a 32-bit field to store the file size in bytes, and 2^32 bytes = 4 GiB. This happens for FAT12, FAT16 and FAT32.

The **root directory** occupies a **specific position** for both FAT12 and FAT16 (in FAT32 it occupies a position like any other folder). Each file/folder entry contains this information:

* Name of the file/folder (8 chars max)
* Attributes
* Date of creation
* Date of modification
* Date of last access
* Address of the FAT table where the first cluster of the file starts
* Size

When a file is "deleted" using a FAT file system, the directory entry remains almost **unchanged** except for the **first character of the file name** (modified to 0xE5), preserving most of the "deleted" file's name, along with its time stamp, file length and — most importantly — its physical location on the disk. The list of disk clusters occupied by the file will, however, be erased from the File Allocation Table, marking those sectors available for use by other files created or modified thereafter. In the case of FAT32, it is additionally an erased field responsible for the upper 16 bits of the file start cluster value.

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2** is the most common file system for **not journaling** partitions (**partitions that don't change much**) like the boot partition. **Ext3/4** are **journaling** and are used usually for the **rest partitions**.

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **Metadata**

Some files contain metadata. This information is about the content of the file which sometimes might be interesting to an analyst as depending on the file type, it might have information like:

* Title
* MS Office Version used
* Author
* Dates of creation and last modification
* Model of the camera
* GPS coordinates
* Image information

You can use tools like [**exiftool**](https://exiftool.org) and [**Metadiver**](https://www.easymetadata.com/metadiver-2/) to get the metadata of a file.

## **Deleted Files Recovery**

### Logged Deleted Files

As was seen before there are several places where the file is still saved after it was "deleted". This is because usually the deletion of a file from a file system just marks it as deleted but the data isn't touched. Then, it's possible to inspect the registries of the files (like the MFT) and find the deleted files.

Also, the OS usually saves a lot of information about file system changes and backups, so it's possible to try to use them to recover the file or as much information as possible.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **File Carving**

**File carving** is a technique that tries to **find files in the bulk of data**. There are 3 main ways tools like this work: **Based on file types headers and footers**, based on file types **structures** and based on the **content** itself.

Note that this technique **doesn't work to retrieve fragmented files**. If a file **isn't stored in contiguous sectors**, then this technique won't be able to find it or at least part of it.

There are several tools that you can use for file Carving indicating the file types you want to search for

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Data Stream **C**arving

Data Stream Carving is similar to File Carving but **instead of looking for complete files, it looks for interesting fragments** of information.\
For example, instead of looking for a complete file containing logged URLs, this technique will search for URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Secure Deletion

Obviously, there are ways to **"securely" delete files and part of logs about them**. For example, it's possible to **overwrite the content** of a file with junk data several times, and then **remove** the **logs** from the **$MFT** and **$LOGFILE** about the file, and **remove the Volume Shadow Copies**.\
You may notice that even performing that action there might be **other parts where the existence of the file is still logged**, and that's true and part of the forensics professional job is to find them.

## References

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
