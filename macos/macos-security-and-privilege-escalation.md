# MacOS Security & Privilege Escalation

First of all, please note that **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. So see:

{% page-ref page="../linux-unix/privilege-escalation/" %}

## Security Restrictions

### Gatekeeper

_Gatekeeper_ is designed to ensure that, by default, **only trusted software runs on a user’s Mac**. Gatekeeper is used when a user **downloads** and **opens** an app, a plug-in or an installer package from outside the App Store. Gatekeeper verifies that the **software is from an identified developer**, is notarised by Apple to be **free of known malicious content**, and **hasn’t been altered**. Gatekeeper also **requests user approval** before opening downloaded software for the first time to make sure the user hasn’t been tricked into running executable code they believed to simply be a data file.

Gatekeeper builds upon **File Quarantine.**  
Upon download of an application, a particular **extended file attribute** \("quarantine flag"\) can be **added** to the **downloaded** **file**. This attribute **is added by the application that downloads the file**, such as a **web** **browser** or email client, but is not usually added by others like common BitTorrent client software.  
When a user executes a "quarentined" file, **Gatekeeper** is the one that **performs the mentioned actions** to allow the execution of the file.

It's possible to check it's status and enable/disable \(root required\) with:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

## Common users

* **Daemon**: User reserved for system daemons
* **Guest**: Account for guests with very strict permissions
* **Nobody**: Processes are executed with this user when minimal permissions are required
* **Root**

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

