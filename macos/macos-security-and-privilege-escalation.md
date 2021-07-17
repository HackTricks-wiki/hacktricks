# MacOS Security & Privilege Escalation

First of all, please note that **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. So see:

{% page-ref page="../linux-unix/privilege-escalation/" %}

## Security Restrictions

### Gatekeeper

_Gatekeeper_ is designed to ensure that, by default, **only trusted software runs on a user’s Mac**. Gatekeeper is used when a user **downloads** and **opens** an app, a plug-in or an installer package from outside the App Store. Gatekeeper verifies that the **software is from an identified developer**, is notarised by Apple to be **free of known malicious content**, and **hasn’t been altered**. Gatekeeper also **requests user approval** before opening downloaded software for the first time to make sure the user hasn’t been tricked into running executable code they believed to simply be a data file.

Gatekeeper builds upon **File Quarantine.**  
Upon download of an application, a particular **extended file attribute** \("quarantine flag"\) can be **added** to the **downloaded** **file**. This attribute **is added by the application that downloads the file**, such as a **web** **browser** or email client, but is not usually added by others like common BitTorrent client software.  
When a user executes a "quarentined" file, **Gatekeeper** is the one that **performs the mentioned actions** to allow the execution of the file.

It's possible to **check it's status and enable/disable** \(root required\) with:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

You can also **find if a file has the quarantine extended attribute** with:

```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```

Check the **value** of the **extended** **attributes** with:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 0081;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
```

And **remove** that attribute with:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*.webarchive' -print0 | xargs -0 xattr -d com.apple.quarantine
```

## Common users

* **Daemon**: User reserved for system daemons
* **Guest**: Account for guests with very strict permissions
* **Nobody**: Processes are executed with this user when minimal permissions are required
* **Root**

## **File ACLs**

When the file contains ACLs you will **find a "+" when listing the permissions like in**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

You can **read the ACLs** of the file with:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

You can find **all the files with ACLs** with \(this is veeery slow\):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

## Resource Forks or MacOS ADS

This is a way to obtain **Alternate Data Streams in MacOS** machines. You can save content inside an extended attribute called **com.apple.ResourceFork** inside a file by saving it in **file/..namedfork/rsrc**.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

You can **find all the files containing this extended attribute** with:

```bash
find / -exec xattr -vl {} \; | grep com.apple.ResourceFork 2>/dev/null
```

## Specific MacOS Enumeration

```bash
smbutil statshares -a #View smb shares mounted to the hard drive
launchctl list #List services
atq #List "at" tasks for the user
mdfind password #Show all the files that contains the word password
mfind -name password #List all the files containing the word password in the name
sysctl -a #List kernel configuration
diskutil list #List connected hard drives
codesign -vv -d /bin/ls #Check the signature of a binary
nettop #Monitor network usage of processes in top style

#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)



#networksetup - set or view network options: Proxies, FW options and more
networksetup -listallnetworkservices #List network services
networksetup -listallhardwareports #Hardware ports
networksetup -getinfo Wi-Fi #Wi-Fi info
networksetup -getautoproxyurl Wi-Fi #Get proxy URL for Wifi
networksetup -getwebproxy Wi-Fi #Wifi Web proxy
networksetup -getftpproxy Wi-Fi #Wifi ftp proxy
```

