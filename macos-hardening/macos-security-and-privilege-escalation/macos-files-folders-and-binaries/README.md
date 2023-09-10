# macOS Files, Folders, Binaries & Memory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## File hierarchy layout

* **/Applications**: The installed apps should be here. All the users will be able to access them.
* **/bin**: Command line binaries
* **/cores**: If exists, it's used to store core dumps
* **/dev**: Everything is treated as a file so you may see hardware devices stored here.
* **/etc**: Configuration files
* **/Library**: A lot of subdirectories and files related to preferences, caches and logs can be found here. A Library folder exists in root and on each user's directory.
* **/private**: Undocumented but a lot of the mentioned folders are symbolic links to the private directory.
* **/sbin**: Essential system binaries (related to administration)
* **/System**: File fo making OS X run. You should find mostly only Apple specific files here (not third party).
* **/tmp**: Files are deleted after 3 days (it's a soft link to /private/tmp)
* **/Users**: Home directory for users.
* **/usr**: Config and system binaries
* **/var**: Log files
* **/Volumes**: The mounted drives will apear here.
* **/.vol**: Running `stat a.txt` you obtain something like `16777223 7545753 -rw-r--r-- 1 username wheel ...` where the first number is the id number of the volume where the file exists and the second one is the inode number. You can access the content of this file through /.vol/ with that information running `cat /.vol/16777223/7545753`

### Applications Folders

* **System applications** are located under `/System/Applications`
* **Installed** applications are usually installed in `/Applications` or in `~/Applications`
* **Application data** can be found in `/Library/Application Support` for the applications running as root and `~/Library/Application Support` for applications running as the user.
* Third-party applications **daemons** that **need to run as root** as usually located in `/Library/PrivilegedHelperTools/`
* **Sandboxed** apps are mapped into the `~/Library/Containers` folder. Each app has a folder named according to the application’s bundle ID (`com.apple.Safari`).
* The **kernel** is located in `/System/Library/Kernels/kernel`
* **Apple's kernel extensions** are located in `/System/Library/Extensions`
* **Third-party kernel extensions** are stored in `/Library/Extensions`

### Files with Sensitive Information

MacOS stores information such as passwords in several places:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Vulnerable pkg installers

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X Specific Extensions

* **`.dmg`**: Apple Disk Image files are very frequent for installers.
* **`.kext`**: It must follow a specific structure and it's the OS X version of a driver. (it's a bundle)
* **`.plist`**: Also known as property list stores information in XML or binary format.
  * Can be XML or binary. Binary ones can be read with:
    * `defaults read config.plist`
    * `/usr/libexec/PlistBuddy -c print config.plsit`
    * `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    * `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    * `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Apple applications that follows directory structure (It's a bundle).
* **`.dylib`**: Dynamic libraries (like Windows DLL files)
* **`.pkg`**: Are the same as xar (eXtensible Archive format). The installer command can be use to install the contents of these files.
* **`.DS_Store`**: This file is on each directory, it saves the attributes and customisations of the directory.
* **`.Spotlight-V100`**: This folder appears on the root directory of every volume on the system.
* **`.metadata_never_index`**: If this file is at the root of a volume Spotlight won't index that volume.
* **`.noindex`**: Files and folder with this extension won't be indexed by Spotlight.

### macOS Bundles

Basically, a bundle is a **directory structure** within the file system. Interestingly, by default this directory **looks like a single object in Finder** (like `.app`).&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

On macOS (and iOS) all system shared libraries, like frameworks and dylibs, are **combined into a single file**, called the **dyld shared cache**. This improved performance, since code can be loaded faster.

Similar to the dyld shared cache, the kernel and the kernel extensions are also compiled into a kernel cache, which is loaded at boot time.

In order to extract the libraries from the single file dylib shared cache it was possible to use the binary  [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) which migh not be working nowadays:

{% code overflow="wrap" %}
```bash
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```
{% endcode %}

## Special File Permissions

### Folder permissions

In a **folder**, **read** allows to **list it**, **write** allows to **delete** and **write** files on it, and **execute** allows to **traverse** the directory. So, for example, a user with **read permission over a file** inside a directory where he **doesn't have execute** permission **won't be able to read** the file.

### Flag modifiers

There are some flags that could be set in the files that will make file behave differently. You can **check the flags** of the files inside a directory with `ls -lO /path/directory`

* **`uchg`**: Known as **uchange** flag will **prevent any action** changing or deleting the **file**. To set it do: `chflags uchg file.txt`
  * The root user could **remove the flag** and modify the file
* **`restricted`**: This flag makes the file be **protected by SIP** (you cannot add this flag to a file).
* **`Sticky bit`**: If a directory with sticky bit, **only** the **directories owner or root can remane or delete** files. Typically this is set on the /tmp directory to prevent ordinary users from deleting or moving other users’ files.

### **File ACLs**

File **ACLs** contain **ACE** (Access Control Entries) where more **granular permissions** can be assigned to different users.

It's possible to grant a **directory** these permissions: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Ans to a **file**: `read`, `write`, `append`, `execute`.

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

You can find **all the files with ACLs** with (this is veeery slow):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Resource Forks | macOS ADS

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

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Universal binaries &** Mach-o Format

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS memory dumping

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risk Category Files Mac OS

The files `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contains the risk associated to files depending on the file extension.

The possible categories include the following:

* **LSRiskCategorySafe**: **Totally** **safe**; Safari will auto-open after download
* **LSRiskCategoryNeutral**: No warning, but **not auto-opened**
* **LSRiskCategoryUnsafeExecutable**: **Triggers** a **warning** “This file is an application...”
* **LSRiskCategoryMayContainUnsafeExecutable**: This is for things like archives that contain an executable. It **triggers a warning unless Safari can determine all the contents are safe or neutral**.

## Log files

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contains information about downloaded files, like the URL from where they were downloaded.
* **`/var/log/system.log`**: Main log of OSX systems. com.apple.syslogd.plist is responsible for the execution of syslogging (you can check if it's disabled looking for "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: These are the Apple System Logs which may contain interesting information.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stores recently accessed files and applications through "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stores items to launch upon system startup
* **`$HOME/Library/Logs/DiskUtility.log`**: Log file for thee DiskUtility App (info about drives, including USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data about wireless access points.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List of daemons deactivated.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
