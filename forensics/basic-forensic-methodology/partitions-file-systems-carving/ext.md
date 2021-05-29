# EXT

## Ext - Extended Filesystem

**Ext2** is the most common filesystem for **not journaling** partitions \(**partitions that don't change much**\) like the boot partition. **Ext3/4** are **journaling** and are used usually for the **rest partitions**.

All block groups in the filesystem have the same size and are stored sequentially. This allows the kernel to easily derive the location of a block group in a disk from its integer index.

Every block group contains the following pieces of information:

* A copy of the filesystem’s superblock
* A copy of the block group descriptors
* A data block bitmap which is used to identify the free blocks inside the group
* An inode bitmap, which is used to identify the free inodes inside the group
* inode table: it consists of a series of consecutive blocks, each of which contains a predefined Figure 1 Ext2 inode number of inodes. All inodes have the same size: 128 bytes. A 1,024 byte block contains 8 inodes, while a 4,096-byte block contains 32 inodes. Note that in Ext2, there is no need to store on disk a mapping between an inode number and the corresponding block number because the latter value can be derived from the block group number and the relative position inside the inode table. For example, suppose that each block group contains 4,096 inodes and that we want to know the address on disk of inode 13,021. In this case, the inode belongs to the third block group and its disk address is stored in the 733rd entry of the corresponding inode table. As you can see, the inode number is just a key used by the Ext2 routines to retrieve the proper inode descriptor on disk quickly
* data blocks, containing files. Any block which does not contain any meaningful information, it is said to be free.

![](../../../.gitbook/assets/image%20%28418%29.png)

### Ext Optional Features

**Features affect where** the data is located, **how** the data is stored in inodes and some of them might supply **additional metadata** for analysis, therefore features are important in Ext.

Ext has optional features that your OS may or may not support, there are 3 possibilities:

* Compatible
* Incompatible
* Compatible Read Only: It can be mounted but not for writing

If there are **incompatible** features you won't be able to mount the filesystem as the OS won't know how the access the data.

{% hint style="info" %}
Suspected attacker might have non-standard extensions
{% endhint %}

**Any utility** that reads the **superblock** will be able to indicate the **features** of a **Ext filesystem**, but you could also use `file -sL /dev/sd*`

### Superblock

The superblock is the first 1024 bytes from the start, it's repeated in the first block of each group and contains:

* Block size
* Total blocks
* Blocks per block group
* Reserved blocks before the first block group
* Total inodes
* Inodes per block group
* Volume name
* Last write time
* Last mount time
* Path where the file system was last mounted
* Filesystem status \(clean?\)

It's possible to obtain this information from an Ext filesystem file using:

```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```

You can also use the free gui application: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)  
Or you can also use **python** to obtain the superblock information: [https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

### inodes

The **inodes** contain the list of **blocks** that **contains** the actual **data** of a **file**.  
If the file is big, and inode **may contain pointers** to **other inodes** that points to the blocks/more inodes containing the file data.

![](../../../.gitbook/assets/image%20%28423%29.png)

In **Ext2** and **Ext3** inodes are of size **128B**, **Ext4** currently uses **156B** but allocates **256B** on disk to allow a future expansion.

Inode structure:

| Offset | Size | Name | DescriptionF |
| :--- | :--- | :--- | :--- |
| 0x0 | 2 | File Mode | File mode and type |
| 0x2 | 2 | UID | Lower 16 bits of owner ID |
| 0x4 | 4 | Size Il | Lower 32 bits of file size |
| 0x8 | 4 | Atime | Access time in seconds since epoch |
| 0xC | 4 | Ctime | Change time in seconds since epoch |
| 0x10 | 4 | Mtime | Modify time in seconds since epoch |
| 0x14 | 4 | Dtime | Delete time in seconds since epoch |
| 0x18 | 2 | GID | Lower 16 bits of group ID |
| 0x1A | 2 | Hlink count | Hard link count |
| 0xC | 4 | Blocks Io | Lower 32 bits of block count |
| 0x20 | 4 | Flags | Flags |
| 0x24 | 4 | Union osd1 | Linux: I version |
| 0x28 | 69 | Block\[15\] | 15 pointes to data block |
| 0x64 | 4 | Version | File version for NFS |
| 0x68 | 4 | File ACL low | Lower 32 bits of extended attributes \(ACL, etc\) |
| 0x6C | 4 | File size hi | Upper 32 bits of file size \(ext4 only\) |
| 0x70 | 4 | Obsolete fragment | An obsoleted fragment address |
| 0x74 | 12 | Osd 2 | Second operating system dependent union |
| 0x74 | 2 | Blocks hi | Upper 16 bits of block count |
| 0x76 | 2 | File ACL hi | Upper 16 bits of extended attributes \(ACL, etc.\) |
| 0x78 | 2 | UID hi | Upper 16 bits of owner ID |
| 0x7A | 2 | GID hi | Upper 16 bits of group ID |
| 0x7C | 2 | Checksum Io | Lower 16 bits of inode checksum |

"Modify" is the timestamp of the last time the file's _content_ has been mofified. This is often called "_mtime_".  
"Change" is the timestamp of the last time the file's _inode_ has been changed, like by changing permissions, ownership, file name, number of hard links. It's often called "_ctime_".

Inode structure extended \(Ext4\):

| Offset | Size | Name | Description |
| :--- | :--- | :--- | :--- |
| 0x80 | 2 | Extra size | How many bytes beyond standard 128 are used |
| 0x82 | 2 | Checksum hi | Upper 16 bits of inode checksum |
| 0x84 | 4 | Ctime extra | Change time extra bits |
| 0x88 | 4 | Mtime extra | Modify time extra bits |
| 0x8C | 4 | Atime extra | Access time extra bits |
| 0x90 | 4 | Crtime | File create time \(seconds since epoch\) |
| 0x94 | 4 | Crtime extra | File create time extra bits |
| 0x98 | 4 | Version hi | Upper 32 bits of version |
| 0x9C |  | Unused | Reserved space for future expansions |

Special inodes:

| Inode | Special Purpose |
| :--- | :--- |
| 0 | No such inode, numberings starts at 1 |
| 1 | Defective block list |
| 2 | Root directory |
| 3 | User quotas |
| 4 | Group quotas |
| 5 | Boot loader |
| 6 | Undelete directory |
| 7 | Reserved group descriptors \(for resizing filesystem\) |
| 8 | Journal |
| 9 | Exclude inode \(for snapshots\) |
| 10 | Replica inode |
| 11 | First non-reserved inode \(often lost + found\) |

{% hint style="info" %}
Not that the creation time only appears in Ext4.
{% endhint %}

Knowing the inode number you can easily find it's index:

* **Block group** where an inode belongs: \(Inode number - 1\) / \(Inodes per group\)
* **Index inside it's group**: \(Inode number - 1\) mod\(Inodes/groups\)
* **Offset** into **inode table**: Inode number \* \(Inode size\)
* The "-1" is because the inode 0 is undefined \(not used\)

```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```

File Mode

| Number | Description |
| :--- | :--- |
| **15** | **Reg/Slink-13/Socket-14** |
| **14** | **Directory/Block Bit 13** |
| **13** | **Char Device/Block Bit 14** |
| **12** | **FIFO** |
| 11 | Set UID |
| 10 | Set GID |
| 9 | Sticky Bit \(without it, anyone with Write & exec perms on a directory can delete and rename files\)  |
| 8 | Owner Read |
| 7 | Owner Write |
| 6 | Owner Exec |
| 5 | Group Read |
| 4 | Group Write |
| 3 | Group Exec |
| 2 | Others Read |
| 1 | Others Write |
| 0 | Others Exec |

The bold bits \(12, 13, 14, 15\) indicate the type of file the file is \(a directory, socket...\) only one of the options in bold may exit.

Directories

<table>
  <thead>
    <tr>
      <th style="text-align:left">Offset</th>
      <th style="text-align:left">Size</th>
      <th style="text-align:left">Name</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">0x0</td>
      <td style="text-align:left">4</td>
      <td style="text-align:left">Inode</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">0x4</td>
      <td style="text-align:left">2</td>
      <td style="text-align:left">Rec len</td>
      <td style="text-align:left">Record length</td>
    </tr>
    <tr>
      <td style="text-align:left">0x6</td>
      <td style="text-align:left">1</td>
      <td style="text-align:left">Name len</td>
      <td style="text-align:left">Name length</td>
    </tr>
    <tr>
      <td style="text-align:left">0x7</td>
      <td style="text-align:left">1</td>
      <td style="text-align:left">File type</td>
      <td style="text-align:left">
        <p>0x00 Unknown
          <br />0x01 Regular</p>
        <p>0x02 Director</p>
        <p>0x03 Char device</p>
        <p>0x04 Block device</p>
        <p>0x05 FIFO</p>
        <p>0x06 Socket</p>
        <p>0x07 Sym link</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">0x8</td>
      <td style="text-align:left"></td>
      <td style="text-align:left">Name</td>
      <td style="text-align:left">Name string (up to 255 characters)</td>
    </tr>
  </tbody>
</table>

**In order to increase the performance, Root hash Directory blocks may be used.**

**Extended Attributes**

Can be stored in

* Extra space between inodes \(256 - inode size, usually = 100\)
* A data block pointed to by file\_acl in inode

Can be used to store anything as a users attribute if name starts with "user".

Data can ne hidden this way.

Extended Attributes Entries

<table>
  <thead>
    <tr>
      <th style="text-align:left">Offset</th>
      <th style="text-align:left">Size</th>
      <th style="text-align:left">Name</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">0x0</td>
      <td style="text-align:left">1</td>
      <td style="text-align:left">Name len</td>
      <td style="text-align:left">Length of attribute name</td>
    </tr>
    <tr>
      <td style="text-align:left">0x1</td>
      <td style="text-align:left">1</td>
      <td style="text-align:left">Name index</td>
      <td style="text-align:left">
        <p>0x0 = no prefix</p>
        <p>0x1 = user. Prefix</p>
        <p>0x2 = system.posix_acl_access</p>
        <p>0x3 = system.posix_acl_default</p>
        <p>0x4 = trusted.</p>
        <p>0x6 = security.</p>
        <p>0x7 = system.</p>
        <p>0x8 = system.richacl</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">0x2</td>
      <td style="text-align:left">2</td>
      <td style="text-align:left">Value offs</td>
      <td style="text-align:left">Offset from first inode entry or start of block</td>
    </tr>
    <tr>
      <td style="text-align:left">0x4</td>
      <td style="text-align:left">4</td>
      <td style="text-align:left">Value blocks</td>
      <td style="text-align:left">Disk block where value stored or zero for this block</td>
    </tr>
    <tr>
      <td style="text-align:left">0x8</td>
      <td style="text-align:left">4</td>
      <td style="text-align:left">Value size</td>
      <td style="text-align:left">Length of value</td>
    </tr>
    <tr>
      <td style="text-align:left">0xC</td>
      <td style="text-align:left">4</td>
      <td style="text-align:left">Hash</td>
      <td style="text-align:left">Hash for attribs in block or zero if in inode</td>
    </tr>
    <tr>
      <td style="text-align:left">0x10</td>
      <td style="text-align:left"></td>
      <td style="text-align:left">Name</td>
      <td style="text-align:left">Attribute name w/o trailing NULL</td>
    </tr>
  </tbody>
</table>

```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```

### Filesystem View

In order to see the contents of the file system you can **use the free tool**: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)  
Or you can mount it in your linux using `mount` command.

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz\#:~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class_profile/get_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.)

