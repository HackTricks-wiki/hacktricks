# Linux Forensics

## Initial Information Gathering

### Basic Information

First of all, it's recommended to have some **USB** with **good known binaries and libraries on it** \(you can just get a ubuntu and copy the folders _/bin_, _/sbin_, _/lib,_ and _/lib64_\), then mount the USN, and modify the env variables to use those binaries:

```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```

Once you have configured the system to use good and known binaries you can start **extracting some basic information**:

```bash
date #Date and time (Clock my be skewed, Might be in different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuosu mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```

#### Suspicious information

While obtaining the basic information you should check for weird things like:

* **root processes** usually run with low PIDS, so if you find a root process with a big PID you may suspect
* Check **registered logins** of users without a shell inside `/etc/passwd`
* Check for **password hashes** inside `/etc/shadow` for users without a shell

### Memory Dump

In order to obtain the memory of the running system it's recommended to use [**LiME**](https://github.com/504ensicsLabs/LiME).  
In order to **compile** it you need to use the **exact same kernel** the victim machine is using.

{% hint style="info" %}
Remember that you **cannot install LiME or any other thing** in the victim machine it will make several changes to it
{% endhint %}

So, if you have an identical version of Ubuntu you can use `apt-get install lime-forensics-dkms`  
In other cases you need to download [**LiME**](https://github.com/504ensicsLabs/LiME) from github can compile it with correct kernel headers. In order to **obtain the exact kernel headers** of the victim machine, you can just **copy the directory** `/lib/modules/<kernel version>` to your machine, and then **compile** LiME using them:

```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```

LiME supports 3 **formats**:

* Raw \(every segment concatenated together\)
* Padded \(same as raw, but with zeroes in right bits\)
* Lime \(recommended format with metadata

LiME can also be use to **send the dump via network** instead of storing it on the system using something like: `path=tcp:4444`

### Disk Imaging

#### Shutting down

First of all you will need to **shutdown the system**. This isn't always an option as some times system will be a production server that the company cannot afford to shutdown.  
There are **2 ways** of shutting down the system, a **normal shutdown** and a **"plug the plug" shutdown**. The first one will allow the **processes to terminate as usual** and the **filesystem** to be **synchronized**, but I will also allow the possible **malware** to **destroy evidences**. The "pull the plug" approach may carry **some information loss** \(as we have already took an image of the memory not much info is going to be lost\) and the **malware won't have any opportunity** to do anything about it. Therefore, if you **suspect** that there may be a **malware**, just execute the **`sync`** **command** on the system and pull the plug.

#### Taking an image of the disk

It's important to note that **before connecting to your computer anything related to the case**, you need to be sure that it's going to be **mounted as read only** to avoid modifying the any information.

```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secur s it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```

### Disk Image pre-analysis

Imaging that you receive a disk image with no more data.

```bash
#Find that it's actually a disk imageusing "file" command
file disk.img 
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img 
raw
#You can list supported types with
img_stat -i list
Supported image format types:
        raw (Single or split raw file (dd))
        aff (Advanced Forensic Format)
        afd (AFF Multiple File)
        afm (AFF with external metadata)
        afflib (All AFFLIB image formats (including beta ones))
        ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img 
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name: 
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```

## Search for known Malware

### Modified System Files

Some Linux systems have a feature to **verify the integrity of many installed components**, providing an effective way to identify unusual or out of place files. For instance, `rpm -Va` on Linux is designed to verify all packages that were installed using RedHat Package Manager.

```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```

### Malware/Rootkit Detectors

Read the following page to learn about tools that can be useful to find malware:

{% page-ref page="../malware-analysis.md" %}

## Search installed programs

### Package Manager

On Debian-based systems, the _**/var/ lib/dpkg/status**_ file contains details about installed packages and the _**/var/log/dpkg.log**_ file records information when a package is installed.  
On RedHat and related Linux distributions the **`rpm -qa --root=/ mntpath/var/lib/rpm`** command will list the contents of an RPM database on a subject systems.

```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```

### Other

**Not all installed programs will be listed by the above commands** because some applications are not available as packages for certain systems and must be installed from source. Therefore, a review of locations such as _**/usr/local**_ and _**/opt**_ may reveal other applications that have been compiled and installed from source code. 

```bash
ls /opt /usr/local
```

Another good idea is to **check** the **common folders** inside **$PATH** for **binaries not related** to **installed packages:**

```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```

## Inspect AutoStart locations

### Scheduled Tasks

```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```

### Services

It is extremely common for malware to entrench itself as a new, unauthorized service. Linux has a number of scripts that are used to start services as the computer boots. The initialization startup script _**/etc/inittab**_ calls other scripts such as rc.sysinit and various startup scripts under the _**/etc/rc.d/**_ directory, or _**/etc/rc.boot/**_ in some older versions. On other versions of Linux, such as Debian, startup scripts are stored in the _**/etc/init.d/**_ directory. In addition, some common services are enabled in _**/etc/inetd.conf**_ or _**/etc/xinetd/**_ depending on the version of Linux. Digital investigators should inspect each of these startup scripts for anomalous entries.

* _**/etc/inittab**_
* _**/etc/rc.d/**_ 
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_ 
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Kernel Modules

On Linux systems, kernel modules are commonly used as rootkit components to malware packages. Kernel modules are loaded when the system boots up based on the configuration information in the `/lib/modules/'uname -r'` and `/etc/modprobe.d` directories, and the `/etc/modprobe` or `/etc/modprobe.conf` file. These areas should be inspected for items that are related to malware.

### Other AutoStart Locations

There are several configuration files that Linux uses to automatically launch an executable when a user logs into the system that may contain traces of malware.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ are executed when any user account logs in.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**~/.profile**_ ,  _**∼/.config/autostart**_ are executed when the specific user logs in.
* _**/etc/rc.local**_ It is traditionally executed after all the normal system services are started, at the end of the process of switching to a multiuser runlevel.

## Examine Logs

Look in all available log files on the compromised system for traces of malicious execution and associated activities such as creation of a new service.

### Pure Logs

**Logon** events recorded in the system and security logs, including logons via the network, can reveal that **malware** or an **intruder gained access** to a compromised system via a given account at a specific time. Other events around the time of a malware infection can be captured in system logs, including the **creation** of a **new** **service** or new accounts around the time of an incident.  
Interesting system logons:

*  **/var/log/syslog** \(debian\) ****or **/var/log/messages** \(Redhat\)
  * Shows general messages and info regarding the system. Basically a data log of all activity throughout the global system.
*  **/var/log/auth.log** \(debian\) ****or **/var/log/secure** \(Redhat\)
  * Keep authentication logs for both successful or failed logins, and authentication processes. Storage depends on system type.
  * `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: start-up messages and boot info.
* **/var/log/maillog** or **var/log/mail.log:** is for mail server logs, handy for postfix, smtpd, or email-related services info running on your server.
* **/var/log/kern.log**: keeps in Kernel logs and warning info. Kernel activity logs \(e.g., dmesg, kern.log, klog\) can show that a particular service crashed repeatedly, potentially indicating that an unstable trojanized version was installed.
* **/var/log/dmesg**: a repository for device driver messages. Use **dmesg** to see messages in this file.
* **/var/log/faillog:** records info on failed logins. Hence, handy for examining potential security breaches like login credential hacks and brute-force attacks.
* **/var/log/cron**: keeps a record of Crond-related messages \(cron jobs\). Like when the cron daemon started a job.
* **/var/log/daemon.log:** keeps track of running background services but doesn’t represent them graphically.
* **/var/log/btmp**: keeps a note of all failed login attempts.
* **/var/log/httpd/**: a directory containing error\_log and access\_log files of the Apache httpd daemon. Every error that httpd comes across is kept in the **error\_log** file. Think of memory problems and other system-related errors. **access\_log** logs all requests which come in via HTTP.
* **/var/log/mysqld.log** or **/var/log/mysql.log** : MySQL log file that records every  debug, failure and success message, including starting, stopping and restarting of MySQL daemon mysqld. The system decides on the directory. RedHat, CentOS, Fedora, and other RedHat-based systems use /var/log/mariadb/mariadb.log. However, Debian/Ubuntu use /var/log/mysql/error.log directory.
* **/var/log/xferlog**: keeps FTP file transfer sessions. Includes info like file names and user-initiated FTP transfers.
* **/var/log/\*** : You should always check for unexpected logs in this directory

{% hint style="info" %}
Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. In fact, because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.
{% endhint %}

### Command History

Many Linux systems are configured to maintain a command history for each user account:

* ~/.bash\_history
* ~/.history
* ~/.sh\_history
* ~/.\*\_history

### Logins

Using the command `last -Faiwx` it's possible to get the list of users that have logged in.  
It's recommended to check if those logins make sense:

* Any unknown user?
* Any user that shouldn't have a shell has logged in?

This is important as **attackers** some times may copy `/bin/bash` inside `/bin/false` so users like **lightdm** may be **able to login**.

Note that you can also **take a look to this information reading the logs**.

### Application Traces

* **SSH**: Connections to systems made using SSH to and from a compromised system result in entries being made in files for each user account \(_**∼/.ssh/authorized\_keys**_ and _**∼/.ssh/known\_keys**_\). These entries can reveal the hostname or IP address of the remote hosts.
* **Gnome Desktop**: User accounts may have a _**∼/.recently-used.xbel**_ file that contains information about files that were recently accessed using applications running in the Gnome desktop.
* **VIM**: User accounts may have a _**∼/.viminfo**_ file that contains details about the use of VIM, including search string history and paths to files that were opened using vim.
* **Open Office**: Recent files.
* **MySQL**: User accounts may have a _**∼/.mysql\_history**_ file that contains queries executed using MySQL.
* **Less**: User accounts may have a _**∼/.lesshst**_ file that contains details about the use of less, including search string history and shell commands executed via less

## Review User Accounts and Logon Activities

Examine the _**/etc/passwd**_, _**/etc/shadow**_ and **security logs** for unusual names or accounts created and/or used in close proximity to known unauthorized events. Also check possible sudo brute-force attacks.  
Moreover, check files like _**/etc/sudoers**_ and _**/etc/groups**_ for unexpected privileges given to users.  
Finally look for accounts with **no passwords** or **easily guessed** passwords.

## Examine File System

File system data structures can provide substantial amounts of **information** related to a **malware** incident, including the **timing** of events and the actual **content** of **malware**.  
**Malware** is increasingly being designed to **thwart file system analysis**. Some malware alter date-time stamps on malicious files to make it more difficult to find them with time line analysis. Other malicious code is designed to only store certain information in memory to minimize the amount of data stored in the file system.  
To deal with such anti-forensic techniques, it is necessary to pay **careful attention to time line analysis** of file system date-time stamps and to files stored in common locations where malware might be found.

* Using **autopsy** you can see the timeline of events that may be useful to discover suspicions activity. You can also use the `mactime` feature from **Sleuth Kit** directly.
* Check for **unexpected scripts** inside **$PATH** \(maybe some sh or php scripts?\)
* Files in `/dev` use to be special files, you may find non-special files here related to malware.
* Look for unusual or **hidden files** and **directories**, such as “.. ” \(dot dot space\) or “..^G ” \(dot dot control-G\)
* setuid copies of /bin/bash on the system `find / -user root -perm -04000 –print`
* Review date-time stamps of deleted **inodes for large numbers of files being deleted around the same time**, which might indicate malicious activity such as installation of a rootkit or trojanized service.
* Because inodes are allocated on a next available basis, **malicious files placed on the system at around the same time may be assigned consecutive inodes**. Therefore, after one component of malware is located, it can be productive to inspect neighbouring inodes.
* Also check directories like _/bin_ or _/sbin_ as the **modified and/or changed time** of new or modified files me be interesting.
* It's interesting to see the files and folders of a directory **sorted by creation date** instead alphabetically to see which files/folders are more recent \(last ones usually\).

You can check the most recent files of a folder using `ls -laR --sort=time /bin`  
You can check the inodes of the files inside a folder using `ls -lai /bin |sort -n` 

{% hint style="info" %}
Note that an **attacker** can **modify** the **time** to make **files appear** **legitimate**, but he **cannot** modify the **inode**. If you find that a **file** indicates that it was created and modify at the **same time** of the rest of the files in the same folder, but the **inode** is **unexpectedly bigger**, then the **timestamps of that file were modified**.
{% endhint %}

## Compare files of different filesystem versions

#### Find added files

```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```

#### Find Modified content

```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```

#### Find deleted files

```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```

#### Other filters

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

Select only files that are Added \(`A`\), Copied \(`C`\), Deleted \(`D`\), Modified \(`M`\), Renamed \(`R`\), have their type \(i.e. regular file, symlink, submodule, …​\) changed \(`T`\), are Unmerged \(`U`\), are Unknown \(`X`\), or have had their pairing Broken \(`B`\). Any combination of the filter characters \(including none\) can be used. When `*` \(All-or-none\) is added to the combination, all paths are selected if there is any file that matches other criteria in the comparison; if there is no file that matches other criteria, nothing is selected.

Also, **these upper-case letters can be downcased to exclude**. E.g. `--diff-filter=ad` excludes added and deleted paths.

Note that not all diffs can feature all types. For instance, diffs from the index to the working tree can never have Added entries \(because the set of paths included in the diff is limited by what is in the index\). Similarly, copied and renamed entries cannot appear if detection for those types is disabled.

## References

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

## MBR - Master Boot Record

The **MBR** occupies the **sector 0 of the disk** \(the first sector\) and it's used to indicate the partitions of the disc. This sector is essential to indicate the PC what and from where a partition should be mounted.  
It allows up to **four partitions** \(at most **just 1** can be active/**bootable**\). However, if you need more partitions you can use **extended partitions**.

Format:

| Offset | Length | Item |
| :--- | :--- | :--- |
| 0 \(0x00\) | 446\(0x1BE\) | Boot code |
| 446 \(0x1BE\) | 16 \(0x10\) | First Partition |
| 462 \(0x1CE\) | 16 \(0x10\) | Second Partition |
| 478 \(0x1DE\) | 16 \(0x10\) | Third Partition |
| 494 \(0x1EE\) | 16 \(0x10\) | Fourth Partition |
| 510 \(0x1FE\) | 2 \(0x2\) | Signature 0x55 0xAA |

Partition Record Format:

| Offset | Length | Item |
| :--- | :--- | :--- |
| 0 \(0x00\) | 1 \(0x01\) | Active flag \(0x80 = bootable\) |
| 1 \(0x01\) | 1 \(0x01\) | Start head |
| 2 \(0x02\) | 1 \(0x01\) | Start sector \(bits 0-5\); upper bits of cylinder \(6- 7\) |
| 3 \(0x03\) | 1 \(0x01\) | Start cylinder lowest 8 bits |
| 4 \(0x04\) | 1 \(0x01\) | Partition type code \(0x83 = Linux\) |
| 5 \(0x05\) | 1 \(0x01\) | End head |
| 6 \(0x06\) | 1 \(0x01\) | End sector \(bits 0-5\); upper bits of cylinder \(6- 7\) |
| 7 \(0x07\) | 1 \(0x01\) | End cylinder lowest 8 bits |
| 8 \(0x08\) | 4 \(0x04\) | Sectors preceding partition \(little endian\) |
| 12 \(0x0C\) | 4 \(0x04\) | Sectors in partition |

In order to mount a MBR in Linux you first need to get the start offset \(you can use `fdisk` and the the `p` command\)

![](../../.gitbook/assets/image%20%28413%29%20%283%29%20%283%29%20%283%29%20%282%29%20%281%29.png)

An then use the following code

```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```

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

![](../../.gitbook/assets/image%20%28418%29.png)

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

![](../../.gitbook/assets/image%20%28423%29.png)

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

