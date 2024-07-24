# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

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

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Search for known Malware

### Modified System Files

Linux offers tools for ensuring the integrity of system components, crucial for spotting potentially problematic files.

* **RedHat-based systems**: Use `rpm -Va` for a comprehensive check.
* **Debian-based systems**: `dpkg --verify` for initial verification, followed by `debsums | grep -v "OK$"` (after installing `debsums` with `apt-get install debsums`) to identify any issues.

### Malware/Rootkit Detectors

Read the following page to learn about tools that can be useful to find malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Search installed programs

To effectively search for installed programs on both Debian and RedHat systems, consider leveraging system logs and databases alongside manual checks in common directories.

* For Debian, inspect _**`/var/lib/dpkg/status`**_ and _**`/var/log/dpkg.log`**_ to fetch details about package installations, using `grep` to filter for specific information.
* RedHat users can query the RPM database with `rpm -qa --root=/mntpath/var/lib/rpm` to list installed packages.

To uncover software installed manually or outside of these package managers, explore directories like _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, and _**`/sbin`**_. Combine directory listings with system-specific commands to identify executables not associated with known packages, enhancing your search for all installed programs.

```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recover Deleted Running Binaries

Imagine a process that was executed from /tmp/exec and then deleted. It's possible to extract it

```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```

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

Paths where a malware could be installed as a service:

* **/etc/inittab**: Calls initialization scripts like rc.sysinit, directing further to startup scripts.
* **/etc/rc.d/** and **/etc/rc.boot/**: Contain scripts for service startup, the latter being found in older Linux versions.
* **/etc/init.d/**: Used in certain Linux versions like Debian for storing startup scripts.
* Services may also be activated via **/etc/inetd.conf** or **/etc/xinetd/**, depending on the Linux variant.
* **/etc/systemd/system**: A directory for system and service manager scripts.
* **/etc/systemd/system/multi-user.target.wants/**: Contains links to services that should be started in a multi-user runlevel.
* **/usr/local/etc/rc.d/**: For custom or third-party services.
* **\~/.config/autostart/**: For user-specific automatic startup applications, which can be a hiding spot for user-targeted malware.
* **/lib/systemd/system/**: System-wide default unit files provided by installed packages.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

* **/lib/modules/$(uname -r)**: Holds modules for the running kernel version.
* **/etc/modprobe.d**: Contains configuration files to control module loading.
* **/etc/modprobe** and **/etc/modprobe.conf**: Files for global module settings.

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

* **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Executed for any user login.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, and **\~/.config/autostart**: User-specific files that run upon their login.
* **/etc/rc.local**: Runs after all system services have started, marking the end of the transition to a multiuser environment.

## Examine Logs

Linux systems track user activities and system events through various log files. These logs are pivotal for identifying unauthorized access, malware infections, and other security incidents. Key log files include:

* **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Capture system-wide messages and activities.
* **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Record authentication attempts, successful and failed logins.
  * Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
* **/var/log/boot.log**: Contains system startup messages.
* **/var/log/maillog** or **/var/log/mail.log**: Logs email server activities, useful for tracking email-related services.
* **/var/log/kern.log**: Stores kernel messages, including errors and warnings.
* **/var/log/dmesg**: Holds device driver messages.
* **/var/log/faillog**: Records failed login attempts, aiding in security breach investigations.
* **/var/log/cron**: Logs cron job executions.
* **/var/log/daemon.log**: Tracks background service activities.
* **/var/log/btmp**: Documents failed login attempts.
* **/var/log/httpd/**: Contains Apache HTTPD error and access logs.
* **/var/log/mysqld.log** or **/var/log/mysql.log**: Logs MySQL database activities.
* **/var/log/xferlog**: Records FTP file transfers.
* **/var/log/**: Always check for unexpected logs here.

{% hint style="info" %}
Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.
{% endhint %}

**Linux maintains a command history for each user**, stored in:

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

Moreover, the `last -Faiwx` command provides a list of user logins. Check it for unknown or unexpected logins.

Check files that can grant extra rprivileges:

* Review `/etc/sudoers` for unanticipated user privileges that may have been granted.
* Review `/etc/sudoers.d/` for unanticipated user privileges that may have been granted.
* Examine `/etc/groups` to identify any unusual group memberships or permissions.
* Examine `/etc/passwd` to identify any unusual group memberships or permissions.

Some apps alse generates its own logs:

* **SSH**: Examine _\~/.ssh/authorized\_keys_ and _\~/.ssh/known\_hosts_ for unauthorized remote connections.
* **Gnome Desktop**: Look into _\~/.recently-used.xbel_ for recently accessed files via Gnome applications.
* **Firefox/Chrome**: Check browser history and downloads in _\~/.mozilla/firefox_ or _\~/.config/google-chrome_ for suspicious activities.
* **VIM**: Review _\~/.viminfo_ for usage details, such as accessed file paths and search history.
* **Open Office**: Check for recent document access that may indicate compromised files.
* **FTP/SFTP**: Review logs in _\~/.ftp\_history_ or _\~/.sftp\_history_ for file transfers that might be unauthorized.
* **MySQL**: Investigate _\~/.mysql\_history_ for executed MySQL queries, potentially revealing unauthorized database activities.
* **Less**: Analyze _\~/.lesshst_ for usage history, including viewed files and commands executed.
* **Git**: Examine _\~/.gitconfig_ and project _.git/logs_ for changes to repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is a small piece of software written in pure Python 3 which parses Linux log files (`/var/log/syslog*` or `/var/log/messages*` depending on the distro) for constructing USB event history tables.

It is interesting to **know all the USBs that have been used** and it will be more useful if you have an authorized list of USBs to find "violation events" (the use of USBs that aren't inside that list).

### Installation

```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```

### Examples

```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```

More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Review User Accounts and Logon Activities

Examine the _**/etc/passwd**_, _**/etc/shadow**_ and **security logs** for unusual names or accounts created and or used in close proximity to known unauthorized events. Also, check possible sudo brute-force attacks.\
Moreover, check files like _**/etc/sudoers**_ and _**/etc/groups**_ for unexpected privileges given to users.\
Finally, look for accounts with **no passwords** or **easily guessed** passwords.

## Examine File System

### Analyzing File System Structures in Malware Investigation

When investigating malware incidents, the structure of the file system is a crucial source of information, revealing both the sequence of events and the malware's content. However, malware authors are developing techniques to hinder this analysis, such as modifying file timestamps or avoiding the file system for data storage.

To counter these anti-forensic methods, it's essential to:

* **Conduct a thorough timeline analysis** using tools like **Autopsy** for visualizing event timelines or **Sleuth Kit's** `mactime` for detailed timeline data.
* **Investigate unexpected scripts** in the system's $PATH, which might include shell or PHP scripts used by attackers.
* **Examine `/dev` for atypical files**, as it traditionally contains special files, but may house malware-related files.
* **Search for hidden files or directories** with names like ".. " (dot dot space) or "..^G" (dot dot control-G), which could conceal malicious content.
* **Identify setuid root files** using the command: `find / -user root -perm -04000 -print` This finds files with elevated permissions, which could be abused by attackers.
* **Review deletion timestamps** in inode tables to spot mass file deletions, possibly indicating the presence of rootkits or trojans.
* **Inspect consecutive inodes** for nearby malicious files after identifying one, as they may have been placed together.
* **Check common binary directories** (_/bin_, _/sbin_) for recently modified files, as these could be altered by malware.

````bash
# List recent files in a directory: 
ls -laR --sort=time /bin```

# Sort files in a directory by inode: 
ls -lai /bin | sort -n```
````

{% hint style="info" %}
Note that an **attacker** can **modify** the **time** to make **files appear** **legitimate**, but he **cannot** modify the **inode**. If you find that a **file** indicates that it was created and modified at the **same time** as the rest of the files in the same folder, but the **inode** is **unexpectedly bigger**, then the **timestamps of that file were modified**.
{% endhint %}

## Compare files of different filesystem versions

### Filesystem Version Comparison Summary

To compare filesystem versions and pinpoint changes, we use simplified `git diff` commands:

* **To find new files**, compare two directories:

```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```

* **For modified content**, list changes while ignoring specific lines:

```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```

* **To detect deleted files**:

```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```

* **Filter options** (`--diff-filter`) help narrow down to specific changes like added (`A`), deleted (`D`), or modified (`M`) files.
  * `A`: Added files
  * `C`: Copied files
  * `D`: Deleted files
  * `M`: Modified files
  * `R`: Renamed files
  * `T`: Type changes (e.g., file to symlink)
  * `U`: Unmerged files
  * `X`: Unknown files
  * `B`: Broken files

## References

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
