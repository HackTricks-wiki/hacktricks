# Linux Forensics

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Initial Information Gathering

### Basic Information

First of all, it's recommended to have some **USB** with **good known binaries and libraries on it** (you can just get ubuntu and copy the folders _/bin_, _/sbin_, _/lib,_ and _/lib64_), then mount the USB, and modify the env variables to use those binaries:

```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```

Once you have configured the system to use good and known binaries you can start **extracting some basic information**:

```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
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

* **Root processes** usually run with low PIDS, so if you find a root process with a big PID you may suspect
* Check **registered logins** of users without a shell inside `/etc/passwd`
* Check for **password hashes** inside `/etc/shadow` for users without a shell

### Memory Dump

To obtain the memory of the running system, it's recommended to use [**LiME**](https://github.com/504ensicsLabs/LiME).\
To **compile** it, you need to use the **same kernel** that the victim machine is using.

{% hint style="info" %}
Remember that you **cannot install LiME or any other thing** in the victim machine as it will make several changes to it
{% endhint %}

So, if you have an identical version of Ubuntu you can use `apt-get install lime-forensics-dkms`\
In other cases, you need to download [**LiME**](https://github.com/504ensicsLabs/LiME) from github and compile it with correct kernel headers. To **obtain the exact kernel headers** of the victim machine, you can just **copy the directory** `/lib/modules/<kernel version>` to your machine, and then **compile** LiME using them:

```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```

LiME supports 3 **formats**:

* Raw (every segment concatenated together)
* Padded (same as raw, but with zeroes in right bits)
* Lime (recommended format with metadata

LiME can also be used to **send the dump via network** instead of storing it on the system using something like: `path=tcp:4444`

### Disk Imaging

#### Shutting down

First of all, you will need to **shut down the system**. This isn't always an option as some times system will be a production server that the company cannot afford to shut down.\
There are **2 ways** of shutting down the system, a **normal shutdown** and a **"plug the plug" shutdown**. The first one will allow the **processes to terminate as usual** and the **filesystem** to be **synchronized**, but it will also allow the possible **malware** to **destroy evidence**. The "pull the plug" approach may carry **some information loss** (not much of the info is going to be lost as we already took an image of the memory ) and the **malware won't have any opportunity** to do anything about it. Therefore, if you **suspect** that there may be a **malware**, just execute the **`sync`** **command** on the system and pull the plug.

#### Taking an image of the disk

It's important to note that **before connecting your computer to anything related to the case**, you need to be sure that it's going to be **mounted as read only** to avoid modifying any information.

```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```

### Disk Image pre-analysis

Imaging a disk image with no more data.

```bash
#Find out if it's a disk image using "file" command
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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

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

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Search installed programs

### Package Manager

On Debian-based systems, the _**/var/ lib/dpkg/status**_ file contains details about installed packages and the _**/var/log/dpkg.log**_ file records information when a package is installed.\
On RedHat and related Linux distributions the **`rpm -qa --root=/ mntpath/var/lib/rpm`** command will list the contents of an RPM database on a system.

```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```

### Other

**Not all installed programs will be listed by the above commands** because some applications are not available as packages for certain systems and must be installed from the source. Therefore, a review of locations such as _**/usr/local**_ and _**/opt**_ may reveal other applications that have been compiled and installed from source code.

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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recover Deleted Running Binaries

![](<../../.gitbook/assets/image (641).png>)

## Inspect Autostart locations

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

On Linux systems, kernel modules are commonly used as rootkit components for malware packages. Kernel modules are loaded when the system boots up based on the configuration information in the `/lib/modules/'uname -r'` and `/etc/modprobe.d` directories, and the `/etc/modprobe` or `/etc/modprobe.conf` file. These areas should be inspected for items that are related to malware.

### Other Autostart Locations

There are several configuration files that Linux uses to automatically launch an executable when a user logs into the system that may contain traces of malware.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ are executed when any user account logs in.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ are executed when the specific user logs in.
* _**/etc/rc.local**_ It is traditionally executed after all the normal system services are started, at the end of the process of switching to a multiuser runlevel.

## Examine Logs

Look in all available log files on the compromised system for traces of malicious execution and associated activities such as the creation of a new service.

### Pure Logs

**Login** events recorded in the system and security logs, including logins via the network, can reveal that **malware** or an **intruder gained access** to a compromised system via a given account at a specific time. Other events around the time of a malware infection can be captured in system logs, including the **creation** of a **new** **service** or new accounts around the time of an incident.\
Interesting system logins:

* **/var/log/syslog** (debian) or **/var/log/messages** (Redhat)
  * Shows general messages and info regarding the system. It is a data log of all activity throughout the global system.
* **/var/log/auth.log** (debian) or **/var/log/secure** (Redhat)
  * Keep authentication logs for both successful or failed logins, and authentication processes. Storage depends on the system type.
  * `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: start-up messages and boot info.
* **/var/log/maillog** or **var/log/mail.log:** is for mail server logs, handy for postfix, smtpd, or email-related services info running on your server.
* **/var/log/kern.log**: keeps in Kernel logs and warning info. Kernel activity logs (e.g., dmesg, kern.log, klog) can show that a particular service crashed repeatedly, potentially indicating that an unstable trojanized version was installed.
* **/var/log/dmesg**: a repository for device driver messages. Use **dmesg** to see messages in this file.
* **/var/log/faillog:** records info on failed logins. Hence, handy for examining potential security breaches like login credential hacks and brute-force attacks.
* **/var/log/cron**: keeps a record of Crond-related messages (cron jobs). Like when the cron daemon started a job.
* **/var/log/daemon.log:** keeps track of running background services but doesn’t represent them graphically.
* **/var/log/btmp**: keeps a note of all failed login attempts.
* **/var/log/httpd/**: a directory containing error\_log and access\_log files of the Apache httpd daemon. Every error that httpd comes across is kept in the **error\_log** file. Think of memory problems and other system-related errors. **access\_log** logs all requests which come in via HTTP.
* **/var/log/mysqld.log** or **/var/log/mysql.log**: MySQL log file that records every debug, failure and success message, including starting, stopping and restarting of MySQL daemon mysqld. The system decides on the directory. RedHat, CentOS, Fedora, and other RedHat-based systems use /var/log/mariadb/mariadb.log. However, Debian/Ubuntu use /var/log/mysql/error.log directory.
* **/var/log/xferlog**: keeps FTP file transfer sessions. Includes info like file names and user-initiated FTP transfers.
* **/var/log/\*** : You should always check for unexpected logs in this directory

{% hint style="info" %}
Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.
{% endhint %}

### Command History

Many Linux systems are configured to maintain a command history for each user account:

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### Logins

Using the command `last -Faiwx` it's possible to get the list of users that have logged in.\
It is recommended to check if those logins make sense:

* Any unknown user?
* Any user that shouldn't have a shell logged in?

This is important as **attackers** some times may copy `/bin/bash` inside `/bin/false` so users like **lightdm** may be **able to login**.

Note that you can also **take a look at this information by reading the logs**.

### Application Traces

* **SSH**: Connections to systems made using SSH to and from a compromised system result in entries being made in files for each user account (_**∼/.ssh/authorized\_keys**_ and _**∼/.ssh/known\_keys**_). These entries can reveal the hostname or IP address of the remote hosts.
* **Gnome Desktop**: User accounts may have a _**∼/.recently-used.xbel**_ file that contains information about files that were recently accessed using applications running on the Gnome desktop.
* **VIM**: User accounts may have a _**∼/.viminfo**_ file that contains details about the use of VIM, including search string history and paths to files that were opened using vim.
* **Open Office**: Recent files.
* **MySQL**: User accounts may have a _**∼/.mysql\_history**_ file that contains queries executed using MySQL.
* **Less**: User accounts may have a _**∼/.lesshst**_ file that contains details about the use of less, including search string history and shell commands executed via less.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is a small piece of software written in pure Python 3 which parses Linux log files (`/var/log/syslog*` or `/var/log/messages*` depending on the distro) for constructing USB event history tables.

It is interesting to **know all the USBs that have been used** and it will be more useful if you have an authorized list of USBs to find "violation events" (the use of USBs that aren't inside that list).

### Installation

```
pip3 install usbrip
usbrip ids download #Download USB ID database
```

### Examples

```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```

More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Review User Accounts and Logon Activities

Examine the _**/etc/passwd**_, _**/etc/shadow**_ and **security logs** for unusual names or accounts created and or used in close proximity to known unauthorized events. Also, check possible sudo brute-force attacks.\
Moreover, check files like _**/etc/sudoers**_ and _**/etc/groups**_ for unexpected privileges given to users.\
Finally, look for accounts with **no passwords** or **easily guessed** passwords.

## Examine File System

File system data structures can provide substantial amounts of **information** related to a **malware** incident, including the **timing** of events and the actual **content** of **malware**.\
**Malware** is increasingly being designed to **thwart file system analysis**. Some malware alter date-time stamps on malicious files to make it more difficult to find them with timeline analysis. Other malicious codes are designed to only store certain information in memory to minimize the amount of data stored in the file system.\
To deal with such anti-forensic techniques, it is necessary to pay **careful attention to timeline analysis** of file system date-time stamps and to files stored in common locations where malware might be found.

* Using **autopsy** you can see the timeline of events that may be useful to discover suspicious activity. You can also use the `mactime` feature from **Sleuth Kit** directly.
* Check for **unexpected scripts** inside **$PATH** (maybe some sh or php scripts?)
* Files in `/dev` used to be special files, you may find non-special files here related to malware.
* Look for unusual or **hidden files** and **directories**, such as “.. ” (dot dot space) or “..^G ” (dot dot control-G)
* Setuid copies of /bin/bash on the system `find / -user root -perm -04000 –print`
* Review date-time stamps of deleted **inodes for large numbers of files being deleted around the same time**, which might indicate malicious activity such as the installation of a rootkit or trojanized service.
* Because inodes are allocated on a next available basis, **malicious files placed on the system at around the same time may be assigned consecutive inodes**. Therefore, after one component of malware is located, it can be productive to inspect neighbouring inodes.
* Also check directories like _/bin_ or _/sbin_ as the **modified and or changed time** of new or modified files may be interesting.
* It's interesting to see the files and folders of a directory **sorted by creation date** instead of alphabetically to see which files or folders are more recent (the last ones usually).

You can check the most recent files of a folder using `ls -laR --sort=time /bin`\
You can check the inodes of the files inside a folder using `ls -lai /bin |sort -n`

{% hint style="info" %}
Note that an **attacker** can **modify** the **time** to make **files appear** **legitimate**, but he **cannot** modify the **inode**. If you find that a **file** indicates that it was created and modified at the **same time** as the rest of the files in the same folder, but the **inode** is **unexpectedly bigger**, then the **timestamps of that file were modified**.
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

Select only files that are Added (`A`), Copied (`C`), Deleted (`D`), Modified (`M`), Renamed (`R`), and have their type (i.e. regular file, symlink, submodule, …​) changed (`T`), are Unmerged (`U`), are Unknown (`X`), or have had their pairing Broken (`B`). Any combination of the filter characters (including none) can be used. When `*` (All-or-none) is added to the combination, all paths are selected if there is any file that matches other criteria in the comparison; if there is no file that matches other criteria, nothing is selected.

Also, **these upper-case letters can be downcased to exclude**. E.g. `--diff-filter=ad` excludes added and deleted paths.

Note that not all diffs can feature all types. For instance, diffs from the index to the working tree can never have Added entries (because the set of paths included in the diff is limited by what is in the index). Similarly, copied and renamed entries cannot appear if detection for those types is disabled.

## References

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

**Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
