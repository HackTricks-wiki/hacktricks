# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **基本信息**

macOS 中的 **系统完整性保护（System Integrity Protection，SIP）** 是一种旨在防止即使是最高权限用户也对关键系统文件夹进行未经授权更改的机制。该功能通过限制在受保护区域中添加、修改或删除文件等操作，在维护系统完整性方面发挥着关键作用。SIP 主要保护的文件夹包括：

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP 行为所遵循的规则定义在位于 **`/System/Library/Sandbox/rootless.conf`** 的配置文件中。在该文件中，以星号（\*）作为前缀的路径表示不受 SIP 严格限制的例外路径。

请考虑以下示例：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
此代码片段表明，虽然 SIP 通常会保护 **`/usr`** 目录，但其中有一些特定子目录（`/usr/libexec/cups`、`/usr/local` 和 `/usr/share/man`）允许进行修改，这一点由路径前的星号（*）表示。

要验证某个目录或文件是否受 SIP 保护，可以使用 **`ls -lOd`** 命令检查是否存在 **`restricted`** 或 **`sunlnk`** 标志。例如：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
在这种情况下，**`sunlnk`** 标志表示 `/usr/libexec/cups` 目录本身**无法被删除**，但其中的文件可以被创建、修改或删除。

另一方面：
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
这里，**`restricted`** 标志表示 `/usr/libexec` 目录受 SIP 保护。在受 SIP 保护的目录中，无法创建、修改或删除文件。

此外，如果文件包含 **`com.apple.rootless`** 扩展**属性**，该文件也会受到 **SIP** 保护。

> [!TIP]
> 注意，**Sandbox** hook **`hook_vnode_check_setextattr`** 会阻止任何修改扩展属性 **`com.apple.rootless`** 的尝试。

**SIP 还会限制其他 root 操作**，例如：

- 加载不受信任的 kernel extensions
- 获取 Apple 签名进程的 task-ports
- 修改 NVRAM 变量
- 允许 kernel debugging

这些选项以位标志（bitflag）的形式保存在 nvram 变量中（Intel 使用 `csr-active-config`，ARM 则从已启动的 Device Tree 中读取 `lp-sip0`）。你可以在 XNU 源代码的 `csr.sh` 中找到这些标志：

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP 状态

你可以使用以下命令检查系统是否启用了 SIP：
```bash
csrutil status
```
如果需要禁用 SIP，必须将计算机重新启动到恢复模式（启动时按下 Command+R），然后执行以下命令：
```bash
csrutil disable
```
如果希望保持 SIP 启用但移除调试保护，可以使用：
```bash
csrutil enable --without debug
```
### 其他限制

- **禁止加载未签名的 kernel extensions**（kexts），确保只有经过验证的 extensions 才能与系统 kernel 交互。
- **阻止对 macOS 系统进程进行 debugging**，保护核心系统组件免受未经授权的访问和修改。
- **阻止 dtrace 等工具检查系统进程**，进一步保护系统运行的完整性。

[**在此演讲中了解更多 SIP 信息**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**。**<sup>[[1]](#references)</sup>

### **SIP 相关 Entitlements**

- `com.apple.rootless.xpc.bootstrap`: 控制 launchd
- `com.apple.rootless.install[.heritable]`: 访问文件系统
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: 管理 UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: XPC 设置能力
- `com.apple.rootless.xpc.effective-root`: 通过 launchd XPC 获取 Root 权限
- `com.apple.rootless.restricted-block-devices`: 访问原始 block devices
- `com.apple.rootless.internal.installer-equivalent`: 不受限制的文件系统访问权限
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: 完全访问 NVRAM
- `com.apple.rootless.storage.label`: 修改受 `com.apple.rootless` xattr 限制且具有相应 label 的文件
- `com.apple.rootless.volume.VM.label`: 在 volume 上维护 VM swap

## SIP Bypasses

绕过 SIP 可使攻击者：

- **访问用户数据**：读取所有用户账户中的敏感用户数据，例如邮件、消息和 Safari 历史记录。
- **TCC Bypass**：直接操作 TCC（Transparency, Consent, and Control）数据库，以授予对 webcam、microphone 和其他资源的未授权访问权限。
- **建立 Persistence**：将 malware 放置在受 SIP 保护的位置，使其难以被移除，即使拥有 root 权限也一样。这还包括篡改 Malware Removal Tool（MRT）的潜在可能。
- **加载 Kernel Extensions**：尽管还存在其他防护措施，但绕过 SIP 会简化加载未签名 kernel extensions 的过程。

### Installer Packages

**使用 Apple 证书签名的 Installer packages** 可以绕过其保护机制。这意味着，即使是由标准开发者签名的 packages，只要尝试修改受 SIP 保护的目录，也会被阻止。

### 不存在的 SIP 文件

一个潜在的漏洞在于：如果某个文件在 **`rootless.conf` 中被指定但当前并不存在**，则可以创建该文件。Malware 可能利用这一点在系统上**建立 Persistence**。例如，如果某个 `.plist` 文件已列在 `rootless.conf` 中但实际不存在，malicious program 就可以在 `/System/Library/LaunchDaemons` 中创建该文件。

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** 允许绕过 SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

研究人员发现，在系统验证 Installer package 的 code signature 后，可以替换该 Installer package，之后系统会安装 malicious package，而不是原始 package。由于这些操作由 **`system_installd`** 执行，因此可以绕过 SIP。<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

如果 package 是从 mounted image 或 external drive 安装的，**installer** 会从**该文件系统**执行 binary（而不是从受 SIP 保护的位置执行），从而使 **`system_installd`** 执行任意 binary。<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**此 blog post 的研究人员**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) 发现了 macOS System Integrity Protection（SIP）机制中的一个漏洞，该漏洞被称为 “Shrootless” vulnerability。该漏洞以 **`system_installd`** daemon 为核心，该 daemon 具有 **`com.apple.rootless.install.heritable`** entitlement，允许其所有 child processes 绕过 SIP 的文件系统限制。<sup>[[4]](#references)</sup>

**`system_installd`** daemon 会安装由 **Apple** 签名的 packages。

研究人员发现，在安装 Apple 签名的 package（`.pkg` 文件）期间，**`system_installd`** 会**运行** package 中包含的所有 **post-install** scripts。这些 scripts 由默认 shell **`zsh`** 执行；如果 **`/etc/zshenv`** 文件存在，`zsh` 会自动运行其中的命令，即使处于 non-interactive mode 也是如此。攻击者可以利用这一行为：创建恶意的 `/etc/zshenv` 文件，并等待 **`system_installd` 调用 `zsh`**，从而在设备上执行任意操作。<sup>[[4]](#references)</sup>

此外，研究人员发现，**`/etc/zshenv` 还可作为一种通用 attack technique**，而不仅仅用于 SIP bypass。每个 user profile 都有一个 `~/.zshenv` 文件，其行为与 `/etc/zshenv` 相同，但不需要 root 权限。该文件可用作 persistence mechanism，在每次 `zsh` 启动时触发，也可用作 privilege elevation mechanism。如果 admin user 通过 `sudo -s` 或 `sudo <command>` 提升为 root，`~/.zshenv` 文件就会被触发，从而实际提升至 root。<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

在 [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) 中，研究人员发现，同一个 **`system_installd`** process 仍可被滥用，因为它会将 **post-install script 放入 `/tmp` 中受 SIP 保护的随机命名文件夹内**。问题在于，**`/tmp` 本身不受 SIP 保护**，因此可以在其上**挂载**一个 **virtual image**；随后，**installer** 会将 **post-install script** 放入其中，接着**卸载** virtual image，**重新创建**所有**文件夹**，并添加包含待执行 **payload** 的 **post-installation** script。<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

研究人员发现了一个漏洞：由于 **`fsck_cs`** 能够跟随 **symbolic links**，攻击者可以误导它破坏关键文件。具体而言，攻击者创建了从 _`/dev/diskX`_ 指向 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` 的 link。在 _`/dev/diskX`_ 上执行 **`fsck_cs`** 会导致 `Info.plist` 被破坏。该文件的完整性对操作系统的 SIP（System Integrity Protection）至关重要，因为 SIP 控制 kernel extensions 的加载。一旦该文件被破坏，SIP 管理 kernel exclusions 的能力就会受到影响。<sup>[[6]](#references)</sup>

利用此漏洞的 commands 如下：
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
利用此漏洞会产生严重影响。通常负责管理 kernel extensions 权限的 `Info.plist` 文件将失效。这包括无法将某些 extensions（例如 `AppleHWAccess.kext`）加入 blacklist。因此，随着 SIP 的控制机制失效，该 extension 可以被加载，从而获得对系统 RAM 未经授权的读写权限。<sup>[[6]](#references)</sup>

#### [在受 SIP 保护的文件夹上挂载](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

可以在 **SIP protected folders 上挂载新的 file system，以绕过保护**。<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

系统设置为从 `Install macOS Sierra.app` 中的嵌入式安装程序磁盘映像启动，以升级 OS，并使用 `bless` utility。使用的命令如下：<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
如果攻击者在启动前修改升级映像（`InstallESD.dmg`），此过程的安全性就可能遭到破坏。该策略涉及将 dynamic loader（dyld）替换为恶意版本（`libBaseIA.dylib`）。替换完成后，启动 installer 时就会执行攻击者的代码。<sup>[[7]](#references)</sup>

攻击者的代码会在升级过程中取得控制权，并利用系统对 installer 的信任。该攻击通过 method swizzling 修改 `InstallESD.dmg` 映像，尤其是针对 `extractBootBits` 方法。这样便可在使用 disk image 之前注入恶意代码。<sup>[[7]](#references)</sup>

此外，`InstallESD.dmg` 中还包含一个 `BaseSystem.dmg`，它充当升级代码的 root file system。向其中注入 dynamic library 后，恶意代码便可在能够修改 OS-level 文件的进程中运行，从而大幅提升系统遭到 compromise 的可能性。<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

在这场来自 [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) 的演讲中，展示了 **`systemmigrationd`**（可以绕过 SIP）如何执行一个 **bash** 和一个 **perl** script，而攻击者可以通过 env variables **`BASH_ENV`** 和 **`PERL5OPT`** 对其加以 abuse。<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

正如[**这篇 blog post 中的详细介绍**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)所述，`InstallAssistant.pkg` packages 中的一个 `postinstall` script 被允许执行：<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
并且可以在 `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` 中创建一个符号链接，从而允许用户 **解除任意文件的限制，绕过 SIP 保护**。<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> entitlement **`com.apple.rootless.install`** 允许绕过 SIP

已知 entitlement `com.apple.rootless.install` 可以绕过 macOS 上的 System Integrity Protection (SIP)。这在与 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) 相关的讨论中被特别提及。<sup>[[10]](#references)</sup>

在这个特定案例中，位于 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` 的系统 XPC service 拥有此 entitlement。这使相关进程能够绕过 SIP 限制。此外，该 service 还提供了一个允许移动文件且不执行任何安全检查的方法。<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots 是 Apple 在 **macOS Big Sur (macOS 11)** 中引入的一项功能，作为其 **System Integrity Protection (SIP)** 机制的一部分，用于提供额外的安全性和系统稳定性。它们本质上是系统卷的只读版本。

以下是更详细的说明：

1. **不可变系统**：Sealed System Snapshots 使 macOS 系统卷变为“不可变”，意味着它无法被修改。这可以防止可能危及安全性或系统稳定性的未经授权或意外的系统更改。
2. **系统软件更新**：安装 macOS 更新或升级时，macOS 会创建一个新的 system snapshot。随后，macOS startup volume 使用 **APFS (Apple File System)** 切换到这个新 snapshot。由于系统始终可以在更新过程中出现问题时恢复到之前的 snapshot，应用更新的整个过程变得更加安全可靠。
3. **数据分离**：结合 macOS Catalina 中引入的 Data 和 System volume 分离概念，Sealed System Snapshot 功能确保所有数据和设置都存储在单独的 "**Data**" volume 中。这种分离使数据独立于系统，从而简化系统更新过程并增强系统安全性。

请注意，这些 snapshot 由 macOS 自动管理，并且得益于 APFS 的空间共享功能，不会占用磁盘上的额外空间。同样重要的是，这些 snapshot 不同于 **Time Machine snapshots**，后者是用户可访问的整个系统备份。

### Check Snapshots

命令 **`diskutil apfs list`** 会列出 **APFS volumes 的详细信息**及其布局：

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

从前面的输出可以看到，**用户可访问的位置**挂载在 `/System/Volumes/Data` 下。

此外，**macOS System volume snapshot** 挂载在 `/`，并且它是 **sealed** 的（由 OS 进行加密签名）。因此，如果绕过 SIP 并对其进行修改，**OS 将无法再启动**。

还可以通过运行以下命令来**验证 seal 是否已启用**：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
此外，snapshot disk 也以**只读**方式挂载：
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## 参考资料

- [1] [SyScan360 - Stefan Esser - OS X El Capitan 沉没的 S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854：“Unauthd”（three）逻辑漏洞 ftw！- Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft 发现新的 macOS 漏洞 Shrootless，可绕过 System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis：CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple 的 fruitless rootless security 被一段能放进推文的代码攻破 - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypassing Apple's System Integrity Protection - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple Mitigates Vulnerabilities in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712：SIP-Bypass 的 POC 甚至可以发进推文](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
