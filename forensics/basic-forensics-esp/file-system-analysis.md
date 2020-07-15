# File System Analysis

From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Occasionally, a CTF forensics challenge consists of a full disk image, and the player needs to have a strategy for finding a needle \(the flag\) in this haystack of data. Triage, in computer forensics, refers to the ability to quickly narrow down what to look at. Without a strategy, the only option is looking at everything, which is time-prohibitive \(not to mention exhausting\).

Example of mounting a CD-ROM filesystem image:

```text
mkdir /mnt/challenge
mount -t iso9660 challengefile /mnt/challenge
```

Once you have mounted the filesystem, the `tree` command is not bad for a quick look at the directory structure to see if anything sticks out to you for further analysis.

You may not be looking for a file in the visible filesystem at all, but rather a hidden volume, unallocated space \(disk space that is not a part of any partition\), a deleted file, or a non-file filesystem structure like an [http://www.nirsoft.net/utils/alternate\_data\_streams.html](https://trailofbits.github.io/ctf/forensics/NTFS). For EXT3 and EXT4 filesystems, you can attempt to find deleted files with [extundelete](http://extundelete.sourceforge.net/). For everything else, there's [TestDisk](http://www.cgsecurity.org/wiki/TestDisk): recover missing partition tables, fix corrupted ones, undelete files on FAT or NTFS, etc.

[The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/) and its accompanying web-based user interface, "Autopsy," is a powerful open-source toolkit for filesystem analysis. It's a bit geared toward law-enforcement tasks, but can be helpful for tasks like searching for a keyword across the entire disk image, or looking at the unallocated space.

Embedded device filesystems are a unique category of their own. Made for fixed-function low-resource environments, they can be compressed, single-file, or read-only. [Squashfs](https://en.wikipedia.org/wiki/SquashFS) is one popular implementation of an embedded device filesystem. For images of embedded devices, you're better off analyzing them with [firmware-mod-kit](https://code.google.com/archive/p/firmware-mod-kit/) or [binwalk](https://github.com/devttys0/binwalk).

