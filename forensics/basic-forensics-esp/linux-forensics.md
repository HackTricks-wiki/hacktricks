# Linux Forensics

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
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**∼/.config/autostart**_ are executed when the specific user logs in.

## Examine Logs

Look in all available log files on the compromised system for traces of malicious execution and associated activities such as creation of a new service.

### Pure Logs

**Logon** events recorded in the system and security logs, including logons via the network, can reveal that **malware** or an **intruder gained access** to a compromised system via a given account at a specific time. Other events around the time of a malware infection can be captured in system logs, including the **creation** of a **new** **service** or new accounts around the time of an incident.  
Interesting system logons:

*  **/var/log/syslog** \(debian\) ****or **/var/log/messages** \(Redhat\)
  * Shows general messages and info regarding the system. Basically a data log of all activity throughout the global system.
*  **/var/log/auth.log** \(debian\) ****or **/var/log/secure** \(Redhat\)
  * Keep authentication logs for both successful or failed logins, and authentication processes. Storage depends on system type.
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

## Review User Accounts and Logon Activities

Examine the _**/etc/passwd**_, _**/etc/shadow**_ and **security logs** for unusual names or accounts created and/or used in close proximity to known unauthorized events. Also check possible sudo brute-force attacks.  
Moreover, check files like _**/etc/sudoers**_ and _**/etc/groups**_ for unexpected privileges given to users.  
Finally look for accounts with **no passwords** or **easily guessed** passwords.

## References

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)



