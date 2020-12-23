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

