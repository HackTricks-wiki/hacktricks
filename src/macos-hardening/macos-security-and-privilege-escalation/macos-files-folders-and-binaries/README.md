# macOS Files, Folders, Binaries & Memory

{{#include ../../../banners/hacktricks-training.md}}

## File hierarchy layout

Apple documents the macOS filesystem as a hierarchy of system, local, network, and user domains. Exact contents vary by OS release, and system locations are increasingly protected or synthesized. <sup>[[1]](#references)</sup>

- **/Applications**: The installed apps should be here. All the users will be able to access them.
- **/bin**: Command line binaries
- **/cores**: If exists, it's used to store core dumps
- **/dev**: Everything is treated as a file so you may see hardware devices stored here.
- **/etc**: Configuration files
- **/Library**: A lot of subdirectories and files related to preferences, caches and logs can be found here. A Library folder exists in root and on each user's directory.
- **/private**: Undocumented but a lot of the mentioned folders are symbolic links to the private directory.
- **/sbin**: Essential system binaries (related to administration)
- **/System**: Files required by macOS; this tree primarily contains Apple-provided components.
- **/tmp**: Temporary files (a symbolic link to `/private/tmp`). Historical installations commonly cleaned old temporary files on a periodic schedule, sometimes described as three days, but current cleanup timing is system- and policy-dependent; do not rely on data persisting there.
- **/Users**: Home directory for users.
- **/usr**: Config and system binaries
- **/var**: Log files
- **/Volumes**: Mounted volumes appear here.
- **/.vol**: Running `stat a.txt` you obtain something like `16777223 7545753 -rw-r--r-- 1 username wheel ...` where the first number is the id number of the volume where the file exists and the second one is the inode number. You can access the content of this file through /.vol/ with that information running `cat /.vol/16777223/7545753`

### Applications Folders

- **System applications** are located under `/System/Applications`
- **Installed** applications are usually installed in `/Applications` or in `~/Applications`
- **Application data** can be found in `/Library/Application Support` for the applications running as root and `~/Library/Application Support` for applications running as the user.
- Third-party application **daemons** that **need to run as root** are usually located in `/Library/PrivilegedHelperTools/`.
- **Sandboxed** apps are mapped into the `~/Library/Containers` folder. Each app has a folder named according to the application’s bundle ID (`com.apple.Safari`).
- The **kernel** is located in `/System/Library/Kernels/kernel`
- **Apple's kernel extensions** are located in `/System/Library/Extensions`
- **Third-party kernel extensions** are stored in `/Library/Extensions`

### Files with Sensitive Information

macOS stores sensitive information, including credentials, in several places:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Vulnerable pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X Specific Extensions

- **`.dmg`**: Apple Disk Image files are very frequent for installers.
- **`.kext`**: It must follow a specific structure and it's the OS X version of a driver. (it's a bundle)
- **`.plist`**: A property list stores structured information in XML or binary format.
  - Can be XML or binary. Binary ones can be read with:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: An application bundle that follows the standard macOS directory structure.
- **`.dylib`**: Dynamic libraries (like Windows DLL files)
- **`.pkg`**: Are the same as xar (eXtensible Archive format). The installer command can be use to install the contents of these files.
- **`.DS_Store`**: This file is on each directory, it saves the attributes and customisations of the directory.
- **`.Spotlight-V100`**: This folder appears on the root directory of every volume on the system.
- **`.metadata_never_index`**: If this file is at the root of a volume Spotlight won't index that volume.
- **`.noindex`**: Files and folder with this extension won't be indexed by Spotlight.
- **`.sdef`**: A scripting definition file that describes how AppleScript can interact with an application.

### macOS Bundles

A bundle is a directory with a standardized hierarchy that Finder can present as a single object; application bundles use the `.app` extension. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

On macOS and iOS, commonly used system libraries and frameworks are prelinked into the **dyld shared cache**, which improves application startup performance. Although it is treated as one logical cache, current releases may store it as a main cache plus multiple subcache files rather than literally one file. Its format and location are implementation details that change across OS releases. <sup>[[3]](#references)</sup>

This is located in macOS in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` and in older versions you might be able to find the **shared cache** in **`/System/Library/dyld/`**.\
In iOS you can find them in **`/System/Library/Caches/com.apple.dyld/`**.

Similar to the dyld shared cache, the kernel and the kernel extensions are also compiled into a kernel cache, which is loaded at boot time.

Older releases could be extracted with [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). That build may not support current cache formats; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) is another option:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Note that even if `dyld_shared_cache_util` tool doesn't work, you can pass the **shared dyld binary to Hopper** and Hopper will be able to identify all the libraries and let you **select which one** you want to investigate:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Some extractors won't work as dylibs are prelinked with hard coded addresses in therefore they might be jumping to unknown addresses

> [!TIP]
> It's also possible to download the Shared Library Cache of other \*OS devices in macos by using an emulator in Xcode. They will be downloaded inside: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, like:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** uses the syscall **`shared_region_check_np`** to know if the SLC has been mapped (which returns the address) and **`shared_region_map_and_slide_np`** to map the SLC.

Note that even if the SLC is slid on the first use, all the **processes** use the **same copy**, which **eliminated the ASLR** protection if the attacker was able to run processes in the system. This was actually exploited in the past and fixed with shared region pager.

Branch pools are little Mach-O dylibs that creates small spaces between image mappings making impossible to interpose the functions.

### Override SLCs

Using the the env variables:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> This will allow to load a new shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** and manually replace the libraries with symlinks to the shared cache with the real ones (you will need to extract them)

## Special File Permissions

### Folder permissions

For a directory, **read** permits listing entries, **write** permits creating or removing entries, and **execute** permits traversal. Consequently, a user who can read a file but cannot traverse a parent directory cannot access that file by path. <sup>[[4]](#references)</sup>

### Flag modifiers

Files can carry flags that alter their behavior. Inspect flags in a directory with `ls -lO /path/directory`.

- **`uchg`**: Known as **uchange** flag will **prevent any action** changing or deleting the **file**. To set it do: `chflags uchg file.txt`
  - The root user could **remove the flag** and modify the file
- **`restricted`**: This flag makes the file be **protected by SIP** (you cannot add this flag to a file).
- **`Sticky bit`**: In a directory with the sticky bit set, only the file owner, directory owner, or root can rename or delete an entry. This is typically enabled on `/tmp` to prevent users from deleting or moving other users' files.

All the flags can be found in the file `sys/stat.h` (find it using `mdfind stat.h | grep stat.h`) and are:

- `UF_SETTABLE` 0x0000ffff: Mask of owner changeable flags.
- `UF_NODUMP` 0x00000001: Do not dump file.
- `UF_IMMUTABLE` 0x00000002: File may not be changed.
- `UF_APPEND` 0x00000004: Writes to file may only append.
- `UF_OPAQUE` 0x00000008: Directory is opaque wrt. union.
- `UF_COMPRESSED` 0x00000020: File is compressed (some file-systems).
- `UF_TRACKED` 0x00000040: No notifications for deletes/renames for files with this set.
- `UF_DATAVAULT` 0x00000080: Entitlement required for reading and writing.
- `UF_HIDDEN` 0x00008000: Hint that this item should not be displayed in a GUI.
- `SF_SUPPORTED` 0x009f0000: Mask of superuser supported flags.
- `SF_SETTABLE` 0x3fff0000: Mask of superuser changeable flags.
- `SF_SYNTHETIC` 0xc0000000: Mask of system read-only synthetic flags.
- `SF_ARCHIVED` 0x00010000: File is archived.
- `SF_IMMUTABLE` 0x00020000: File may not be changed.
- `SF_APPEND` 0x00040000: Writes to file may only append.
- `SF_RESTRICTED` 0x00080000: Entitlement required for writing.
- `SF_NOUNLINK` 0x00100000: Item may not be removed, renamed or mounted on.
- `SF_FIRMLINK` 0x00800000: File is a firmlink.
- `SF_DATALESS` 0x40000000: File is dataless object.

### **File ACLs**

File **ACLs** contain **ACE** (Access Control Entries) where more **granular permissions** can be assigned to different users.

It's possible to grant a **directory** these permissions: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
For a **file**: `read`, `write`, `append`, and `execute`.

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

You can find **all files with ACLs** with the following command (this is very slow):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Extended Attributes

Extended attributes are named metadata values stored separately from a file's ordinary attributes. List them with `ls -l@` and inspect or modify them with `xattr`. <sup>[[5]](#references)</sup> Some common extended attributes are:

- `com.apple.resourceFork`: Resource fork compatibility. Also visible as `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS Gatekeeper quarantine metadata
- `metadata:*`: macOS metadata, such as `_backup_excludeItem` or `kMD*`
- `com.apple.lastuseddate` (#PS): Last file use date
- `com.apple.FinderInfo`: macOS Finder information, such as color tags
- `com.apple.TextEncoding`: Specifies text encoding of ASCII text files
- `com.apple.logd.metadata`: Used by logd on files in `/var/db/diagnostics`
- `com.apple.genstore.*`: Generational storage (`/.DocumentRevisions-V100` in root of filesystem)
- `com.apple.rootless`: macOS metadata associated with System Integrity Protection
- `com.apple.uuidb.boot-uuid`: logd markings of boot epochs with unique UUID
- `com.apple.decmpfs`: macOS transparent file compression metadata
- `com.apple.cprotect`: \*OS: Per-file encryption data (III/11)
- `com.apple.installd.*`: \*OS: Metadata used by installd, e.g., `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks provide an alternate data stream on macOS. Content can be stored in the `com.apple.ResourceFork` extended attribute and accessed through `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

You can **find all the files containing this extended attribute** with:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

The extended attribute `com.apple.decmpfs` stores metadata for transparent compression; it does not indicate encryption. Depending on the compression format, compressed data may be stored in the attribute or in a resource fork and is decompressed transparently when read.

The `UF_COMPRESSED` flag appears as `compressed` in `ls -lO`. Do not clear it manually: doing so can make the system interpret the compressed representation incorrectly.

The command that clears the flag is shown here because it is useful during forensic review, but running it against a compressed file can make that file appear empty or inaccessible until its metadata is repaired:

```bash
chflags nocompressed /path/to/file
```

The built-in `/usr/bin/afscexpand` utility can force expansion of transparently compressed files. The separate third-party `afsctool` utility can also inspect or decompress Apple filesystem compression, but it should not be confused with the built-in command. <sup>[[8]](#references)</sup>


### Interesting configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Stores Apple’s feature-flag plist files controlling optional or experimental behaviors in system daemons / frameworks | If an attacker can bypass SIP or gain privilege, tampering these could enable hidden code paths or disable safeguards |
| `/System/Library/CoreServices/systemVersion.plist` | Holds macOS version metadata (ProductVersion, BuildVersion) used by apps / installers to gate behavior | Modification may trick apps or installers into accepting unsupported OS versions or unlocking features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | If writable, attackers can inject settings to steer app behavior, disable protections, or cause misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Plist definitions for background daemons and agents | Malicious plist insertion or manipulation (if permissions allow) enables persistence or privilege escalations |
| `/etc/hosts` | Hostname ↔ IP mappings used by the system DNS resolver | Redirecting domain names, intercepting traffic, spoofing services under local control |
| `/etc/sudoers` | Defines who can run commands with `sudo` and under what conditions | A corrupted sudoers file can grant root or improper privileges to attacker accounts |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | Tampering allows creation or modification of user accounts, password hashes, or user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | Installing or modifying kexts can lead to kernel-level control; heavily protected by SIP / signature policies |
| `/private/var/db/SystemPolicyConfiguration/` | Stores configuration for system policy enforcement (e.g. Gatekeeper, notarization) | Tampering these may allow circumvention of policy checks or trust rules |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries and config files | Misconfiguration leads to weak SSH security, unauthorized access, or insecure algorithms |
| `/System/Library/Sandbox/Profiles` | System sandbox profiles (SBPL) used to restrict process actions | Replacing or altering profiles can open sandbox escape vectors or weaken containment |

> **Note**: Many of these paths lie under SIP-protected directories (e.g. `/System`) and are protected against writes unless SIP is disabled or bypassed.  


## Universal Binaries And Mach-O Format

Mach-O is the native executable format on macOS. A universal, or fat, binary wraps multiple architecture-specific Mach-O slices in one file; the dedicated page explains both formats:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices, file quarantine, and Gatekeeper collectively influence how macOS handles downloaded files and selects applications for extensions and URL schemes. Their databases and internal resource files change across releases; use the dedicated pages instead of treating a private CoreTypes path as a stable policy interface:

On releases that expose the legacy CoreTypes risk metadata under `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, the commonly encountered categories are:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: content considered safe enough for automatic opening under the applicable application policy.
- **`LSRiskCategoryNeutral`**: content that does not normally trigger a warning and is not automatically opened.
- **`LSRiskCategoryUnsafeExecutable`**: executable content for which the user should receive an application warning.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: containers such as archives that may hold executable content and require further inspection.

These are implementation details, not a stable public policy API; confirm the actual metadata and Safari/Gatekeeper behavior on the macOS version under test.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contains information about downloaded files, like the URL from where they were downloaded.
- **Unified log**: On current macOS versions, query system and application events with `log show` and `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** and **`/private/var/log/asl/*.asl`**: Legacy logging artifacts that may still be relevant on older systems. On those releases, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configures `syslogd`; `launchctl list | grep com.apple.syslogd` can help determine whether the service is loaded.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stores recently accessed files and applications through "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Legacy preference path associated with login items; modern macOS versions use additional mechanisms.
- **`$HOME/Library/Logs/DiskUtility.log`**: Legacy Disk Utility log that may contain information about drives, including USB devices.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Data about wireless access points.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Legacy launchd override data.

## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)

{{#include ../../../banners/hacktricks-training.md}}
