# MacOS Security & Privilege Escalation

First of all, please note that **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. So see:

{% page-ref page="../../linux-unix/privilege-escalation/" %}

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
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

And find all the quarantined files with:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

### XProtect

**X-Protect is Apple’s built in malware scanner.** It keeps track of known malware hashes and patterns.  
You can get information about the latest XProtect update running:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

## Sandbox

MacOS Sandbox works with the kernel extension Seatbelt. It makes applications run inside the sandbox **need to request access to resources outside of the limited sandbox**. This helps to ensure that **the application will be accessing only expected resources** and if it wants to access anything else it will need to ask for permissions to the user.

Important **system services** also run inside their own custom **sandbox** such as the mdnsresponder service. You can view these custom **sandbox profiles** inside the **`/usr/share/sandbox`** directory. Other sandbox profiles can be checked in [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Check some of the **already given permissions** to apps in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

To start an application with a sandbox config you can use:

```bash
sandbox-exec -f example.sb /Path/To/The/Application
```

{% hint style="info" %}
Note that the **Apple-authored** **software** that runs on **Windows** **doesn’t have additional security precautions**, such as application sandboxing.
{% endhint %}

### SIP - System Integrity Protection

This protection was enabled to **help keep root level malware from taking over certain parts** of the operating system. Although this means **applying limitations to the root user** many find it to be worthwhile trade off.  
The most notable of these limitations are that **users can no longer create, modify, or delete files inside** of the following four directories in general: 

* /System
* /bin
* /sbin
* /usr

Note that there are **exceptions specified by Apple**: The file **`/System/Library/Sandbox/rootless.conf`** holds a list of **files and directories that cannot be modified**. But if the line starts with an **asterisk** it means that it can be **modified** as **exception**.  
For example, the config lines:

```bash
        /usr
*				/usr/libexec/cups
*				/usr/local
*				/usr/share/man
```

Means that `/usr` **cannot be modified** **except** for the **3 allowed** folders allowed.

The final exception to these rules is that **any installer package signed with the Apple’s certificate can bypass SIP protection**, but **only Apple’s certificate**. Packages signed by standard developers will still be rejected when trying to modify SIP protected directories.

Note that if **a file is specified** in the previous config file **but** it **doesn't exist, it can be created**. This might be used by malware to obtain stealth persistence. For example, imagine that a **.plist** in `/System/Library/LaunchDaemons` appears listed but it doesn't exist. A malware may c**reate one and use it as persistence mechanism.**

Also, not how files and directories specified in **`rootless.conf`** have a **rootless extended attribute**:

```bash
xattr /System/Library/LaunchDaemons/com.apple.UpdateSettings.plist
com.apple.rootless

ls -lO /System/Library/LaunchDaemons/com.apple.UpdateSettings.plist
-rw-r--r--@ 1 root  wheel  restricted,compressed 412  1 Jan  2020 /System/Library/LaunchDaemons/com.apple.UpdateSettings.plist
```

**SIP** handles a number of **other limitations as well**. Like it **doesn't allows for the loading of unsigned kext**s.  SIP is also responsible for **ensuring** that no OS X **system processes are debugged**. This also means that Apple put a stop to dtrace inspecting system processes.

Check if SIP is enabled with:

```bash
csrutil status
System Integrity Protection status: enabled.
```

If you want to disable it, you need to put the computer in recovery mode \(start it pressing command+R\) and execute: `csrutil disable`

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
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

## OS X Specific Extensions

* **`.dmg`**: Apple Disk Image files are very frequent for installers.
* **`.kext`**: It must follow a specific structure and it's the OS X version of a driver.
* **`.plist`**: Also known as property list stores information in XML or binary format.
  * Can be XML or binary. Binary ones can be read with:
    * `defaults read config.plist`
    * `/usr/libexec/PlistBuddy -c print config.plsit`
    * `plutil -p config.plist`
* **`.app`**: Apple applications that follows  directory structure.
* **`.dylib`**: Dynamic libraries \(like Windows DLL files\)
* **`.pkg`**: Are the same as xar \(eXtensible Archive format\). The installer command can be use to install the contents of these files.

## File hierarchy layout

* **/Applications**: The installed apps should be here. All the users will be able to access them.
* **/bin**: Command line binaries
* **/cores**: If exists, it's used to store core dumps
* **/dev**: Everything is treated as a file so you may see hardware devices stored here.
* **/etc**: Configuration files
* **/Library**: A lot of subdirectories and files related to preferences, caches and logs can be found here. A Library folder exists in root and on each user's directory.
* **/private**: Undocumented but a lot of the mentioned folders are symbolic links to the private directory.
* **/sbin**: Essential system binaries \(related to administration\)
* **/System**: File fo making OS X run. You should find mostly only Apple specific files here \(not third party\).
* **/tmp**: Files are deleted after 3 days \(it's a soft link to /private/tmp\)
* **/Users**: Home directory for users.
* **/usr**: Config and system binaries
* **/var**: Log files
* **/Volumes**: The mounted drives will apear here.
* **/.vol**: Running `stat a.txt` you obtain something like `16777223 7545753 -rw-r--r-- 1 username wheel ...` where the first number is the id number of the volume where the file exists and the second one is the inode number. You can access the content of this file through /.vol/ with that information running  `cat /.vol/16777223/7545753`

### Special MacOS files and folders

* **`.DS_Store`**: This file is on each directory, it saves the attributes and customisations of the directory.
* **`.Spotlight-V100`**: This folder appears on the root directory of every volume on the system.
* **`.metadata_never_index`**: If this file is at the root of a volume Spotlight won't index that volume.
* **`<name>.noindex`**: Files and folder with this extension won't be indexed by Spotlight.
* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV`**2: Contains information about downloaded files, like the URL from where they were downloaded.
* **`/var/log/system.log`**: Main log of OSX systems. com.apple.syslogd.plist is responsible for the execution of syslogging \(you can check if it's disabled looking for "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: These are the Apple System Logs which may contain interesting information.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stores recently accessed files and applications through "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stores items to launch upon system startup
* **`$HOME/Library/Logs/DiskUtility.log`**: Log file for thee DiskUtility App \(info about drives, including USBs\)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data about wireless access points.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List of daemons deactivated.
* **`/private/etc/kcpassword`**: If autologin is enabled this file will contain the users login password XORed with a key.

## Auto Start Extensibility Point \(ASEP\)

An **ASEP** is a location on the system that could lead to the **execution** of a binary **without** **user** **interaction**. The main ones used in OS X take the form of plists.

### Launchd

**`launchd`** is the **first** **process** executed by OX S kernel at startup and the last one to finish at shut down. It should always have the **PID 1**. This process will **read and execute** the configurations indicated in the **ASEP** **plists** in:

* `/Library/LaunchAgents`: Per-user agents installed by the admin
* `/Library/LaunchDaemons`: System-wide daemons installed by the admin
* `/System/Library/LaunchAgents`: Per-user agents provided by Apple.
* `/System/Library/LaunchDaemons`: System-wide daemons provided by Apple.

When a user logs in the plists located in `/Users/$USER/Library/LaunchAgents` are started with the **logged users permissions**.

The **main difference between agents and daemons is that agents are loaded when the user logs in and the daemons are loaded at system startup** \(as there are services like ssh that needs to be executed before any user access the system\). Also agents may use GUI while daemons need to run in the background.

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/username/malware</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

There are cases where an **agent needs to be executed before the user logins**, these are called **PreLoginAgents**. For example, this is useful to provide assistive technology at login. They can be found also in `/Library/LaunchAgents`\(see [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) an example\).

{% hint style="info" %}
New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` \(however those plist files won't be automatically loaded after reboot\).  
It's also possible to **unload** with `launchctl unload <target.plist>` \(the process pointed by it will be terminated\),

To **ensure** that there isn't **anything** \(like an override\) **preventing** an **Agent** or **Daemon** **from** **running** run: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

List all the agents and daemons loaded by the current user:

```bash
launchctl list
```

### Cron

List the cron jobs of the **current user** with:

```bash
crontab -l
```

You can also see all the cron jobs of the users in **`/usr/lib/cron/tabs/`** \(needs root\).

### kext

In order to install a KEXT as a startup item, it needs to be **installed in one of the following locations**:

* `/System/Library/Extensions`
  * KEXT files built into the OS X operating system.
* `/Library/Extensions`
  * KEXT files installed by 3rd party software

You can list currently loaded kext files with:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information about [**kernel extensions check this section**](mac-os-architecture.md#i-o-kit-drivers).

### **Login Items**

In System Preferences -&gt; Users & Groups -&gt; **Login Items** you can find  **items to be executed when the user logs in**.  
It it's possible to list them, add and remove from the command line:

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}' 

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"' 

```

### At

“At tasks” are used to **schedule tasks at specific times**.  
These tasks differ from cron in that **they are one time tasks** t**hat get removed after executing**. However, they will **survive a system restart** so they can’t be ruled out as a potential threat.

By **default** they are **disabled** but the **root** user can **enable** **them** with:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

This will create a file at 13:37:

```bash
echo hello > /tmp/hello | at 1337
```

If AT tasks aren't enabled the created tasks won't be executed.

### Login/Logout Hooks

They are deprecated but can be used to execute commands when a user logs in.

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```

This setting is stored in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

To delete it:

```bash
defaults delete com.apple.loginwindow LoginHook
```

In the previous example we have created and deleted a **LoginHook**, it's also possible to create a **LogoutHook**.

The root user one is stored in `/private/var/root/Library/Preferences/com.apple.loginwindow.plist`

### Startup Items

This is deprecated, so nothing should be found in the following directories.

A **StartupItem** is a **directory** that gets **placed** in one of these two folders. `/Library/StartupItems/` or `/System/Library/StartupItems/`

After placing a new directory in one of these two locations, **two more items** need to be placed inside that directory. These two items are a **rc script** **and a plist** that holds a few settings. This plist must be called “**StartupParameters.plist**”.

{% code title="StartupParameters.plist" %}
```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```
{% endcode %}

{% code title="superservicename" %}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```
{% endcode %}

### /etc/rc.common

It's also possible to place here **commands that will be executed at startup.** Example os regular rc.common script:

```bash
##
# Common setup for startup scripts.
##
# Copyright 1998-2002 Apple Computer, Inc.
##

#######################
# Configure the shell #
#######################

##
# Be strict
##
#set -e
set -u

##
# Set command search path
##
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

##
# Set the terminal mode
##
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

####################
# Useful functions #
####################

##
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
##
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

##
# Process management
##
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

##
# Generic action handler
##
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

## Memory Artifacts

### Swap Files

* **`/private/var/vm/swapfile0`**: This file is used as a **cache when physical memory fills up**. Data in physical memory will be pushed to the swapfile and then swapped back into physical memory if it’s needed again. More than one file can exist in here. For example, you might see swapfile0, swapfile1, and so on.
* **`/private/var/vm/sleepimage`**: When OS X goes into **hibernation**, **data stored in memory is put into the sleepimage file**. When the user comes back and wakes the computer, memory is restored from the sleepimage and the user can pick up where they left off.

  By default in modern MacOS systems this file will be encrypted, so it might be not recuperable.

  * However, the encryption of this file might be disabled. Check the out of `sysctl vm.swapusage`.

### Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```

If you find this error: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` You can fix it doing:

```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```

**Other errors** might be fixed by **allowing the load of the kext** in "Security & Privacy --&gt; General", just **allow** it.

You can also use this **oneliner** to download the application, load the kext and dump the memory:

```bash
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```

## User Privileges

* **Standard User:** The most basic of users. This user needs permissions granted from an admin user when attempting to install software or perform other advanced tasks. They are not able to do it on their own.
* **Admin User**: A user who operates most of the time as a standard user but is also allowed to perform root actions such as install software and other administrative tasks. All users belonging to the admin group are **given access to root via the sudoers file**.
* **Root**: Root is a user allowed to perform almost any action \(there are limitations imposed by protections like System Integrity Protection\).
  * For example root won't be able to place a file inside `/System`

## Passwords

### Shadow Passwords

Shadow password is stored withe the users configuration in plists located in **`/var/db/dslocal/nodes/Default/users/`**.  
The following oneliner can be use to dump **all the information about the users** \(including hash info\):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

\*\*\*\*[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transform the hash to **hashcat** **format**.

### [Keychaindump](https://github.com/juuso/keychaindump)

The attacker still needs to gain access to the system as well as escalate to root privileges in order to run keychaindump. This approach comes with its own conditions. As mentioned earlier, upon login your keychain is unlocked by default and remains unlocked while you use your system. This is for convenience so that the user doesn’t need to enter their password every time an application wishes to access the keychain. If the user has changed this setting and chosen to lock the keychain after every use, keychaindump will no longer work; it relies on an unlocked keychain to function.

It’s important to understand how Keychaindump extracts passwords out of memory. The most important process in this transaction is the ”securityd“ process. Apple refers to this process as a security context daemon for authorization and cryptographic operations. The Apple developer libraries don’t say a whole lot about it; however, they do tell us that securityd handles access to the keychain. In his research, Juuso refers to the key needed to decrypt the keychain as ”The Master Key“. A number of steps need to be taken to acquire this key as it is derived from the user’s OS X login password. If you want to read the keychain file you must have this master key. The following steps can be done to acquire it. Perform a scan of securityd’s heap \(keychaindump does this with the vmmap command\). Possible master keys are stored in an area flagged as MALLOC\_TINY. You can see the locations of these heaps yourself with the following command:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

**Keychaindump** will then search the returned heaps for occurrences of 0x0000000000000018. If the following 8-byte value points to the current heap, we’ve found a potential master key. From here a bit of deobfuscation still needs to occur which can be seen in the source code, but as an analyst the most important part to note is that the necessary data to decrypt this information is stored in securityd’s process memory. Here’s an example of keychain dump output.

```bash
sudo ./keychaindump
```

### Keychain Dump

Note that when using the security binary to **dump the passwords decrypted**, several prompts will ask the user to allow this operation.

```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password \(which isn't very secure\).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.  
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## **Library injection**

### Dylib Hijacking

As in Windows, in MacOS you can also **hijack dylibs** to make **applications** **execute** **arbitrary** **code**.  
However, the way **MacOS** applications **load** libraries is **more restricted** than in Windows. This implies that **malware** developers can still use this technique for **stealth**, but the probably to be able to **abuse this to escalate privileges is much lower**.

First of all, is **more common** to find that **MacOS binaries indicates the full path** to the libraries to load. And second, **MacOS never search** in the folders of the **$PATH** for libraries.

However, there are 2 types of dylib hijacking:

* **Missing weak linked libraries**: This means that the application will try to load a library that doesn't exist configured with **LC\_LOAD\_WEAK\_DYLIB**. Then, **if an attacker places a dylib where it's expected it will be loaded**.
  * The fact that the link is "weak" means that the application will continue running even if the library isn't found.
* **Configured with @rpath**: The path to the library configured contains "**@rpath**" and it's configured with **multiple** **LC\_RPATH** containing **paths**. Therefore, **when loading** the dylib, the loader is going to **search** \(in order\) **through all the paths** specified in the **LC\_RPATH** **configurations**. If anyone is missing and **an attacker can place a dylib there** and it will be loaded.

The way to **escalate privileges** abusing this functionality would be in the rare case that an **application** being executed **by** **root** is **looking** for some **library in some folder where the attacker has write permissions.**

**A nice scanner to find missing libraries in applications is** [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html)**.  
A nice report with technical details about this technique can be found** [**here**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x)**.**

### **DYLD\_INSERT\_LIBRARIES**

> This is a colon separated **list of dynamic libraries** to l**oad before the ones specified in the program**. This lets you test new modules of existing dynamic shared libraries that are used in flat-namespace images by loading a temporary dynamic shared library with just the new modules. Note that this has no effect on images built a two-level namespace images using a dynamic shared library unless DYLD\_FORCE\_FLAT\_NAMESPACE is also used.

This is like the [**LD\_PRELOAD on Linux**](../../linux-unix/privilege-escalation/#ld_preload).

This technique may be also **used as an ASEP technique** as every application installed has a plist called "Info.plist" that allows for the **assigning of environmental variables** using a key called `LSEnvironmental`.

## Crons

In MacOS several folders executing scripts with **certain frequency** can be found in:

```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```

There you can find the regular **cron** **jobs**, the **at** **jobs** \(not very used\) and the **periodic** **jobs** \(mainly used for cleaning temporary files\). The daily periodic jobs can be executed for example with: `periodic daily`.

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

#networksetup - set or view network options: Proxies, FW options and more
networksetup -listallnetworkservices #List network services
networksetup -listallhardwareports #Hardware ports
networksetup -getinfo Wi-Fi #Wi-Fi info
networksetup -getautoproxyurl Wi-Fi #Get proxy URL for Wifi
networksetup -getwebproxy Wi-Fi #Wifi Web proxy
networksetup -getftpproxy Wi-Fi #Wifi ftp proxy
```

