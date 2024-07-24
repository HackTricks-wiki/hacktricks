# macOS Files, Folders, Binaries & Memory

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
* **`.sdef`**: Files inside bundles specifying how it's possible to interact wth the application from an AppleScript.

### macOS Bundles

A bundle is a **directory** which **looks like an object in Finder** (a Bundle example are `*.app` files).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Library Cache (SLC)

On macOS (and iOS) all system shared libraries, like frameworks and dylibs, are **combined into a single file**, called the **dyld shared cache**. This improved performance, since code can be loaded faster.

This is located in macOS in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` and in older versions you might be able to find the **shared cache** in **`/System/Library/dyld/`**.\
In iOS you can find them in **`/System/Library/Caches/com.apple.dyld/`**.

Similar to the dyld shared cache, the kernel and the kernel extensions are also compiled into a kernel cache, which is loaded at boot time.

In order to extract the libraries from the single file dylib shared cache it was possible to use the binary [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) which might not be working nowadays but you can also use [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

{% hint style="success" %}
Note that even if `dyld_shared_cache_util` tool doesn't work, you can pass the **shared dyld binary to Hopper** and Hopper will be able to identify all the libraries and let you **select which one** you want to investigate:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Some extractors won't work as dylibs are prelinked with hard coded addresses in therefore they might be jumping to unknown addresses

{% hint style="success" %}
It's also possible to download the Shared Library Cache of other \*OS devices in macos by using an emulator in Xcode. They will be downloaded inside: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, like:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### Mapping SLC

**`dyld`** uses the syscall **`shared_region_check_np`** to know if the SLC has been mapped (which returns the address) and **`shared_region_map_and_slide_np`** to map the SLC.

Note that even if the SLC is slid on the first use, all the **processes** use the **same copy**, which **eliminated the ASLR** protection if the attacker was able to run processes in the system. This was actually exploited in the past and fixed with shared region pager.

Branch pools are little Mach-O dylibs that creates small spaces between image mappings making impossible to interpose the functions.

### Override SLCs

Using the the env variables:

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> This will allow to load a new shared library cache
* **`DYLD_SHARED_CACHE_DIR=avoid`** and manually replace the libraries with symlinks to the shared cache with the real ones (you will need to extract them)

## Special File Permissions

### Folder permissions

In a **folder**, **read** allows to **list it**, **write** allows to **delete** and **write** files on it, and **execute** allows to **traverse** the directory. So, for example, a user with **read permission over a file** inside a directory where he **doesn't have execute** permission **won't be able to read** the file.

### Flag modifiers

There are some flags that could be set in the files that will make file behave differently. You can **check the flags** of the files inside a directory with `ls -lO /path/directory`

* **`uchg`**: Known as **uchange** flag will **prevent any action** changing or deleting the **file**. To set it do: `chflags uchg file.txt`
  * The root user could **remove the flag** and modify the file
* **`restricted`**: This flag makes the file be **protected by SIP** (you cannot add this flag to a file).
* **`Sticky bit`**: If a directory with sticky bit, **only** the **directories owner or root can remane or delete** files. Typically this is set on the /tmp directory to prevent ordinary users from deleting or moving other users’ files.

All the flags can be found in the file `sys/stat.h` (find it using `mdfind stat.h | grep stat.h`) and are:

* `UF_SETTABLE` 0x0000ffff: Mask of owner changeable flags.
* `UF_NODUMP` 0x00000001: Do not dump file.
* `UF_IMMUTABLE` 0x00000002: File may not be changed.
* `UF_APPEND` 0x00000004: Writes to file may only append.
* `UF_OPAQUE` 0x00000008: Directory is opaque wrt. union.
* `UF_COMPRESSED` 0x00000020: File is compressed (some file-systems).
* `UF_TRACKED` 0x00000040: No notifications for deletes/renames for files with this set.
* `UF_DATAVAULT` 0x00000080: Entitlement required for reading and writing.
* `UF_HIDDEN` 0x00008000: Hint that this item should not be displayed in a GUI.
* `SF_SUPPORTED` 0x009f0000: Mask of superuser supported flags.
* `SF_SETTABLE` 0x3fff0000: Mask of superuser changeable flags.
* `SF_SYNTHETIC` 0xc0000000: Mask of system read-only synthetic flags.
* `SF_ARCHIVED` 0x00010000: File is archived.
* `SF_IMMUTABLE` 0x00020000: File may not be changed.
* `SF_APPEND` 0x00040000: Writes to file may only append.
* `SF_RESTRICTED` 0x00080000: Entitlement required for writing.
* `SF_NOUNLINK` 0x00100000: Item may not be removed, renamed or mounted on.
* `SF_FIRMLINK` 0x00800000: File is a firmlink.
* `SF_DATALESS` 0x40000000: File is dataless object.

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

### Extended Attributes

Extended attributes have a name and any desired value, and can be seen using `ls -@` and manipulated using the `xattr` command. Some common extended attributes are:

* `com.apple.resourceFork`: Resource fork compatibility. Also visible as `filename/..namedfork/rsrc`
* `com.apple.quarantine`: MacOS: Gatekeeper quarantine mechanism (III/6)
* `metadata:*`: MacOS: various metadata, such as `_backup_excludeItem`, or `kMD*`
* `com.apple.lastuseddate` (#PS): Last file use date
* `com.apple.FinderInfo`: MacOS: Finder information (e.g., color Tags)
* `com.apple.TextEncoding`: Specifies text encoding of ASCII text files
* `com.apple.logd.metadata`: Used by logd on files in `/var/db/diagnostics`
* `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` in root of filesystem)
* `com.apple.rootless`: MacOS: Used by System Integrity Protection to label file (III/10)
* `com.apple.uuidb.boot-uuid`: logd markings of boot epochs with unique UUID
* `com.apple.decmpfs`: MacOS: Transparent file compression (II/7)
* `com.apple.cprotect`: \*OS: Per-file encryption data (III/11)
* `com.apple.installd.*`: \*OS: Metadata used by installd, e.g., `installType`, `uniqueInstallID`

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

### decmpfs

The extended attribute `com.apple.decmpfs` indicates that the file is stored encrypted, `ls -l` will report a **size of 0** and the compressed data is inside this attribute. Whenever the file is accessed it'll be decrypted in memory.

This attr can be seen with `ls -lO` indicated as compressed because compressed files are also tagged with the flag `UF_COMPRESSED`. If a compressed file is removed this flag with `chflags nocompressed </path/to/file>`, the system won't know that the file was compressed and therefore it won't be able to decompress and access the data (it will think that it's actually empty).

The tool afscexpand can be used to force decompress a dile.

## **Universal binaries &** Mach-o Format

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS Process Memory

## macOS memory dumping

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risk Category Files Mac OS

The directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` is where information about the **risk associated with different file extensions is stored**. This directory categorizes files into various risk levels, influencing how Safari handles these files upon download. The categories are as follows:

* **LSRiskCategorySafe**: Files in this category are considered **completely safe**. Safari will automatically open these files after they are downloaded.
* **LSRiskCategoryNeutral**: These files come with no warnings and are **not automatically opened** by Safari.
* **LSRiskCategoryUnsafeExecutable**: Files under this category **trigger a warning** indicating that the file is an application. This serves as a security measure to alert the user.
* **LSRiskCategoryMayContainUnsafeExecutable**: This category is for files, such as archives, that might contain an executable. Safari will **trigger a warning** unless it can verify that all contents are safe or neutral.

## Log files

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contains information about downloaded files, like the URL from where they were downloaded.
* **`/var/log/system.log`**: Main log of OSX systems. com.apple.syslogd.plist is responsible for the execution of syslogging (you can check if it's disabled looking for "com.apple.syslogd" in `launchctl list`.
* **`/private/var/log/asl/*.asl`**: These are the Apple System Logs which may contain interesting information.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stores recently accessed files and applications through "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stores items to launch upon system startup
* **`$HOME/Library/Logs/DiskUtility.log`**: Log file for thee DiskUtility App (info about drives, including USBs)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data about wireless access points.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: List of daemons deactivated.

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
