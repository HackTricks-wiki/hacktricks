# NTFS

## **NTFS**

**NTFS** \(**New Technology File System**\) is a proprietary journaling file system developed by Microsoft.

The cluster is the minimum size unit of NTFS and the size of the cluster depends on the size of a partition.

| Partition size | Sectors per cluster | Cluster size |
| :--- | :--- | :--- |
| 512MB or less | 1 | 512 bytes |
| 513MB-1024MB \(1GB\) | 2 | 1KB |
| 1025MB-2048MB \(2GB\) | 4 | 2KB |
| 2049MB-4096MB \(4GB\) | 8 | 4KB |
| 4097MB-8192MB \(8GB\) | 16 | 8KB |
| 8193MB-16,384MB \(16GB\) | 32 | 16KB |
| 16,385MB-32,768MB \(32GB\) | 64 | 32KB |
| Greater than 32,768MB | 128 | 64KB |

### **Slack-Space**

As the **minimum** size unit of NTFS is a **cluster**. Each file will be occupying a number of complete clusters. Then, it's highly probable that **each file occupies more space than necessary**. These **unused** **spaces** **booked** by a file which is called **slacking** **space**. And people could take advantage of this technique to **hide** **information**.

![](../../../.gitbook/assets/image%20%28464%29.png)

### **NTFS boot sector**

When you format an NTFS volume, the format program allocates the first 16 sectors for the $Boot metadata file. First sector, in fact, is a boot sector with a "bootstrap" code and the following 15 sectors are the boot sector's IPL \(initial program loader\). To increase file system reliability the very last sector an NTFS partition contains a spare copy of the boot sector.

### **Master File Table o $MFT**

The NTFS file system contains a file called the _master file table_, or MFT. There is at least **one entry in the MFT for every file on an NTFS file system** volume, including the MFT itself. All information about a file, including its **size, time and date stamps, permissions, and data content**, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries.

As **files are added** to an NTFS file system volume, more entries are added to the MFT and the **MFT increases in size**. When **files** are **deleted** from an NTFS file system volume, their **MFT entries are marked as free** and may be reused. However, disk space that has been allocated for these entries is not reallocated, and the size of the MFT does not decrease.

The NTFS file system **reserves space for the MFT to keep the MFT as contiguous as possible** as it grows. The space reserved by the NTFS file system for the MFT in each volume is called the **MFT zone**. Space for file and directories are also allocated from this space, but only after all of the volume space outside of the MFT zone has been allocated.

Depending on the average file size and other variables, **either the reserved MFT zone or the unreserved space on the disk may be allocated first as the disk fills to capacity**. Volumes with a small number of relatively large files will allocate the unreserved space first, while volumes with a large number of relatively small files allocate the MFT zone first. In either case, fragmentation of the MFT starts to take place when one region or the other becomes fully allocated. If the unreserved space is completely allocated, space for user files and directories will be allocated from the MFT zone. If the MFT zone is completely allocated, space for new MFT entries will be allocated from the unreserved space.

NTFS file systems also generate a **$MFTMirror**. This is a **copy** of the **first 4 entries** of the MFT: $MFT, $MFT Mirror, $Log, $Volume.

NTFS reserves the first 16 records of the table for special information:

| System File | File Name | MFT Record | Purpose of the File |
| :--- | :--- | :--- | :--- |
| Master file table | $Mft | 0 | Contains one base file record for each file and folder on an NTFS volume. If the allocation information for a file or folder is too large to fit within a single record, other file records are allocated as well. |
| Master file table 2 | $MftMirr | 1 | A duplicate image of the first four records of the MFT. This file guarantees access to the MFT in case of a single-sector failure. |
| Log file | $LogFile | 2 | Contains a list of transaction steps used for NTFS recoverability. Log file size depends on the volume size and can be as large as 4 MB. It is used by Windows NT/2000 to restore consistency to NTFS after a system failure. |
| Volume | $Volume | 3 | Contains information about the volume, such as the volume label and the volume version. |
| Attribute definitions | $AttrDef | 4 | A table of attribute names, numbers, and descriptions. |
| Root file name index | $ | 5 | The root folder. |
| Cluster bitmap | $Bitmap | 6 | A representation of the volume showing which clusters are in use. |
| Boot sector | $Boot | 7 | Includes the BPB used to mount the volume and additional bootstrap loader code used if the volume is bootable. |
| Bad cluster file | $BadClus | 8 | Contains bad clusters for the volume. |
| Security file | $Secure | 9 | Contains unique security descriptors for all files within a volume. |
| Upcase table | $Upcase | 10 | Converts lowercase characters to matching Unicode uppercase characters. |
| NTFS extension file | $Extend | 11 | Used for various optional extensions such as quotas, reparse point data, and object identifiers. |
|  |  | 12-15 | Reserved for future use. |
| Quota management file | $Quota | 24 | Contains user assigned quota limits on the volume space. |
| Object Id file | $ObjId | 25 | Contains file object IDs. |
| Reparse point file | $Reparse | 26 | This file contains information about files and folders on the volume include reparse point data. |

### Each entry of the MFT looks like the following:

![](../../../.gitbook/assets/image%20%28483%29.png)

Note how each entry starts with "FILE". Each entry occupies 1024 bits. So after 1024 bit from the start of a MFT entry you will find the next one.

Using the [**Active Disk Editor**](https://www.disk-editor.org/index.html) it's very easy to inspect the entry of a file in the MFT. Just right click on the file and then click "Inspect File Record"

![](../../../.gitbook/assets/image%20%28493%29.png)

![](../../../.gitbook/assets/image%20%28482%29.png)

Checking the **"In use**" flag it's very easy to know if a file was deleted \(a value of **0x0 means deleted**\).

![](../../../.gitbook/assets/image%20%28520%29.png)

It's also possible to recover deleted files using FTKImager:

![](../../../.gitbook/assets/image%20%28490%29.png)

### MFT Attributes

Each MFT entry has several attributes as the following image indicates:

![](../../../.gitbook/assets/image%20%28495%29.png)

Each attribute indicates some entry information identified by the type:

| Type Identifier | Name | Description |
| :--- | :--- | :--- |
| 16 | $STANDARD\_INFORMATION | General information, such as flags; the last accessed, written, and created times; and the owner and security ID. |
| 32 | $ATTRIBUTE\_LIST | List where other attributes for file can be found. |
| 48 | $FILE\_NAME | File name, in Unicode, and the last accessed, written, and created times. |
| 64 | $VOLUME\_VERSION | Volume information. Exists only in version 1.2 \(Windows NT\). |
| 64 | $OBJECT\_ID | A 16-byte unique identifier for the file or directory. Exists only in versions 3.0+ and after \(Windows 2000+\). |
| 80 | $SECURITY\_ DESCRIPTOR | The access control and security properties of the file. |
| 96 | $VOLUME\_NAME | Volume name. |
| 112 | $VOLUME\_ INFORMATION | File system version and other flags. |
| 128 | $DATA | File contents. |
| 144 | $INDEX\_ROOT | Root node of an index tree. |
| 160 | $INDEX\_ALLOCATION | Nodes of an index tree rooted in $INDEX\_ROOT attribute. |
| 176 | $BITMAP | A bitmap for the $MFT file and for indexes. |
| 192 | $SYMBOLIC\_LINK | Soft link information. Exists only in version 1.2 \(Windows NT\). |
| 192 | $REPARSE\_POINT | Contains data about a reparse point, which is used as a soft link in version 3.0+ \(Windows 2000+\). |
| 208 | $EA\_INFORMATION | Used for backward compatibility with OS/2 applications \(HPFS\). |
| 224 | $EA | Used for backward compatibility with OS/2 applications \(HPFS\). |
| 256 | $LOGGED\_UTILITY\_STREAM | Contains keys and information about encrypted attributes in version 3.0+ \(Windows 2000+\). |

For example the **type 48 \(0x30\)** identifies the **file name**:

![](../../../.gitbook/assets/image%20%28515%29.png)

It is also useful to understand that **these attributes can be resident** \(meaning, they exist within a given MFT record\) or **nonresident** \(meaning, they exist outside a given MFT record, elsewhere on the disk, and are simply referenced within the record\). For example, if the attribute **$Data is resident**, these means that the **whole file is saved in the MFT**, if it's nonresident, then the content of the file is in other part of the file system.

Some interesting attributes:

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard_information.html) \(among others\):
  * Creation date
  * Modification date
  * Access date
  * MFT update date
  * DOS File permissions
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file_name.html) \(among others\): 
  * File name
  * Creation date
  * Modification date
  * Access date
  * MFT update date
  * Allocated size
  * Real size
  * [File reference](https://flatcap.org/linux-ntfs/ntfs/concepts/file_reference.html) to the parent directory.
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html) \(among others\):
  * Contains the file's data or the indication of the sectors where the data resides. In the following example the attribute data is not resident so the attribute gives information about the sectors where the data resides.

![](../../../.gitbook/assets/image%20%28507%29%20%281%29.png)

![](../../../.gitbook/assets/image%20%28512%29.png)

### NTFS timestamps

![](../../../.gitbook/assets/image%20%28521%29.png)

Another useful tool to analyze the MFT is [**MFT2csv**](https://github.com/jschicht/Mft2Csv).  
This program will extract all the MFT data and present it in CSV format. It can also be used to dump the files.

![](../../../.gitbook/assets/image%20%28514%29.png)

### $LOGFILE

The file **`$LOGFILE`** contains **logs** about the **actions** that have been **performed** **to** **files**. It also **saves** the **action** it would need to perform in case of a **redo** and the action needed to **go back** to the **previous** **state**.  
These logs are useful for the MFT to rebuild the file system in case some kind of error happened.

The maximum file size of this file is **65536KB**.

In order to inspect the `$LOGFILE` you need to extract it and inspect the `$MFT` previously with [**MFT2csv**](https://github.com/jschicht/Mft2Csv).  
Then run [**LogFileParser**](https://github.com/jschicht/LogFileParser) against this file and selecting the exported `$LOGFILE` file and the CVS of the inspection of the `$MFT` you will obtain a csv file with the logs of the file system activity recorded by the `$LOGFILE` log.

![](../../../.gitbook/assets/image%20%28519%29.png)

Filtering by filenames you can see **all the actions performed against a file**:

![](../../../.gitbook/assets/image%20%28513%29.png)

### $USNJnrl

The file `$EXTEND/$USNJnrl/$J` is and alternate data stream of the file `$EXTEND$USNJnrl` . This artifact contains a **registry of changes produced inside the NTFS volume with more detail than `$LOGFILE`**.

To inspect this file you can use the tool [**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv).

Filtering by the filename it's possible to see **all the actions performed against a file**. Also you can find the `MFTReference` of the parent folder. Then, looking for that `MFTReference` you can find i**nformation of the parent folder.**

![](../../../.gitbook/assets/image%20%28517%29.png)

### $I30

Every **directory** in the file system contains an **`$I30`** **attribute** that must be maintained whenever there are changes to the directory's contents. When files or folders are removed from the directory, the **`$I30`** index records are re-arranged accordingly. However, **re-arranging of the index records may leave remnants of the deleted file/folder entry within the slack space**. This can be useful in forensics analysis for identifying files that may have existed on the drive.

You can get the `$I30` file of a directory from the **FTK Imager** and inspect it with the tool [Indx2Csv](https://github.com/jschicht/Indx2Csv).

![](../../../.gitbook/assets/image%20%28527%29.png)

With this data you can find **information about the file changes performed inside the folder** but note that the deletion time of a file isn't saved inside this logs. However, you can see that **last modified date** of the **`$I30` file**, and if the **last action performed** over the directory is the **deletion** of a file, the times may be the same.

### $Bitmap

The **`$BitMap`** is a special file within the NTFS file system. This file keeps **track of all of the used and unused clusters** on an NTFS volume. When a file takes up space on the NTFS volume the location is uses is marked out in the `$BitMap`.

![](../../../.gitbook/assets/image%20%28526%29.png)

### ADS \(Alternate Data Stream\)

Alternate data streams allow files to contain more than one stream of data. Every file has at least one data stream. In Windows, this default data stream is called `:$DATA`.  
In this [page you can see different ways to create/access/discover alternate data streams](../../../windows/basic-cmd-for-pentesters.md#alternate-data-streams-cheatsheet-ads-alternate-data-stream) from the console. In the past this cause a vulnerability in IIS as people was able to access the source code of a page by accessing the `:$DATA` stream like `http://www.alternate-data-streams.com/default.asp::$DATA`.

Using the tool [**AlternateStreamView**](https://www.nirsoft.net/utils/alternate_data_streams.html) you can search and export all the files with some ADS.

![](../../../.gitbook/assets/image%20%28528%29.png)

Using the FTK imager and double clicking in a file with ADS you can **access the ADS data**:

![](../../../.gitbook/assets/image%20%28529%29.png)

If you find an ADS called **`Zone.Identifier`** \(see previous image\) this usually contains **information about how was the file downloaded**. There would be a "ZoneId" field with the following info:

* Zone ID = 0 -&gt; Mycomputer
* Zone ID = 1 -&gt; Intranet
* Zone ID = 2 -&gt; Trusted
* Zone ID = 3 -&gt; Internet
* Zone ID = 4 -&gt; Unstrusted

Moreover, different software may store additional information:

| Software | Info |
| :--- | :--- |
| Google Chrome, Opera, Vivaldi, | ZoneId=3, ReferrerUrl, HostUrl |
| Microsoft Edge | ZoneId=3, LastWriterPackageFamilyName=Microsoft.MicrosoftEdge\_8wekyb3d8bbwe |
| Firefox, Tor browser, Outlook2016, Thunderbird, Windows Mail, Skype | ZoneId=3 |
| μTorrent | ZoneId=3, HostUrl=about:internet |

