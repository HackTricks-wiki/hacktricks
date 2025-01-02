# macOS 启动/环境约束与信任缓存

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

macOS 中的启动约束旨在通过**规范进程的启动方式、启动者和启动来源**来增强安全性。自 macOS Ventura 开始引入，它们提供了一个框架，将**每个系统二进制文件分类为不同的约束类别**，这些类别在**信任缓存**中定义，该列表包含系统二进制文件及其各自的哈希值。这些约束扩展到系统中的每个可执行二进制文件，涉及一组**规则**，规定了**启动特定二进制文件的要求**。规则包括二进制文件必须满足的自我约束、其父进程必须满足的父约束，以及其他相关实体必须遵守的责任约束​。

该机制通过**环境约束**扩展到第三方应用程序，自 macOS Sonoma 开始，允许开发者通过指定**一组环境约束的键和值**来保护他们的应用程序。

您可以在约束字典中定义**启动环境和库约束**，这些字典可以保存在**`launchd` 属性列表文件**中，或在代码签名中使用的**单独属性列表**文件中。

约束有 4 种类型：

- **自我约束**：应用于**运行中的**二进制文件的约束。
- **父进程**：应用于**进程的父进程**的约束（例如 **`launchd`** 运行 XP 服务）
- **责任约束**：应用于**在 XPC 通信中调用服务的进程**的约束
- **库加载约束**：使用库加载约束选择性地描述可以加载的代码

因此，当一个进程尝试通过调用 `execve(_:_:_:)` 或 `posix_spawn(_:_:_:_:_:_:)` 启动另一个进程时，操作系统会检查**可执行**文件是否**满足**其**自身的自我约束**。它还会检查**父进程**的可执行文件是否**满足**可执行文件的**父约束**，以及**责任进程**的可执行文件是否**满足**可执行文件的责任进程约束。如果这些启动约束中的任何一个不满足，操作系统将不会运行该程序。

如果在加载库时，**库约束**的任何部分不成立，您的进程**将不会加载**该库。

## LC 类别

LC 由**事实**和**逻辑操作**（与，或..）组成，结合事实。

[**LC 可以使用的事实已记录**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例如：

- is-init-proc：一个布尔值，指示可执行文件是否必须是操作系统的初始化进程（`launchd`）。
- is-sip-protected：一个布尔值，指示可执行文件是否必须是受系统完整性保护（SIP）保护的文件。
- `on-authorized-authapfs-volume:` 一个布尔值，指示操作系统是否从授权的、经过身份验证的 APFS 卷加载了可执行文件。
- `on-authorized-authapfs-volume`：一个布尔值，指示操作系统是否从授权的、经过身份验证的 APFS 卷加载了可执行文件。
- Cryptexes 卷
- `on-system-volume:` 一个布尔值，指示操作系统是否从当前启动的系统卷加载了可执行文件。
- 在 /System 内...
- ...

当 Apple 二进制文件被签名时，它**将其分配到信任缓存**中的 LC 类别。

- **iOS 16 LC 类别**已在此处[**反向工程并记录**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。
- 当前的 **LC 类别（macOS 14 - Sonoma）**已被反向工程，其[**描述可以在这里找到**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。

例如，类别 1 是：
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`：必须在系统或Cryptexes卷中。
- `launch-type == 1`：必须是系统服务（LaunchDaemons中的plist）。
- `validation-category == 1`：操作系统可执行文件。
- `is-init-proc`：Launchd

### 反向工程 LC 类别

您可以在这里找到更多信息 [**关于它**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)，但基本上，它们在 **AMFI (AppleMobileFileIntegrity)** 中定义，因此您需要下载内核开发工具包以获取 **KEXT**。以 **`kConstraintCategory`** 开头的符号是 **有趣** 的。提取它们后，您将获得一个 DER (ASN.1) 编码流，您需要使用 [ASN.1 解码器](https://holtstrom.com/michael/tools/asn1decoder.php) 或 python-asn1 库及其 `dump.py` 脚本 [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) 进行解码，这将为您提供一个更易于理解的字符串。

## 环境约束

这些是配置在 **第三方应用程序** 中的启动约束。开发人员可以选择在其应用程序中使用的 **事实** 和 **逻辑运算符** 来限制对自身的访问。

可以使用以下命令枚举应用程序的环境约束：
```bash
codesign -d -vvvv app.app
```
## 信任缓存

在 **macOS** 中有几个信任缓存：

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

在 iOS 中，它看起来在 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**。

> [!WARNING]
> 在运行在 Apple Silicon 设备上的 macOS 上，如果 Apple 签名的二进制文件不在信任缓存中，AMFI 将拒绝加载它。

### 枚举信任缓存

之前的信任缓存文件格式为 **IMG4** 和 **IM4P**，IM4P 是 IMG4 格式的有效载荷部分。

您可以使用 [**pyimg4**](https://github.com/m1stadev/PyIMG4) 来提取数据库的有效载荷：
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
（另一个选项是使用工具 [**img4tool**](https://github.com/tihmstar/img4tool)，即使发布版本较旧，它也可以在 M1 上运行，并且如果您将其安装在正确的位置，它也可以在 x86_64 上运行）。

现在您可以使用工具 [**trustcache**](https://github.com/CRKatri/trustcache) 以可读格式获取信息：
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
信任缓存遵循以下结构，因此 **LC 类别是第 4 列**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
然后，您可以使用像[**这个**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)这样的脚本来提取数据。

从这些数据中，您可以检查具有**启动约束值为`0`**的应用程序，这些应用程序没有受到约束（[**在这里检查**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)每个值的含义）。

## 攻击缓解

启动约束将通过**确保进程不会在意外条件下执行**来缓解几种旧攻击：例如，从意外位置启动或被意外的父进程调用（如果只有launchd应该启动它）。

此外，启动约束还**缓解降级攻击**。

然而，它们**并不缓解常见的XPC**滥用、**Electron**代码注入或**dylib注入**，而不进行库验证（除非已知可以加载库的团队ID）。

### XPC守护进程保护

在Sonoma版本中，一个显著的点是守护进程XPC服务的**责任配置**。XPC服务对自己负责，而不是连接的客户端负责。这在反馈报告FB13206884中有记录。这个设置可能看起来有缺陷，因为它允许与XPC服务进行某些交互：

- **启动XPC服务**：如果被认为是一个bug，这个设置不允许通过攻击者代码启动XPC服务。
- **连接到活动服务**：如果XPC服务已经在运行（可能由其原始应用程序激活），则没有连接到它的障碍。

虽然对XPC服务实施约束可能通过**缩小潜在攻击的窗口**而有益，但它并没有解决主要问题。确保XPC服务的安全性根本上需要**有效验证连接的客户端**。这仍然是加强服务安全性的唯一方法。此外，值得注意的是，提到的责任配置目前是有效的，这可能与预期设计不符。

### Electron保护

即使要求应用程序必须由**LaunchService**打开（在父约束中）。这可以通过使用**`open`**（可以设置环境变量）或使用**Launch Services API**（可以指示环境变量）来实现。

## 参考文献

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
