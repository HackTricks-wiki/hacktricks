# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

macOS 中引入 Launch constraints 是为了通过**规范进程的启动方式、启动者以及启动来源**来增强安全性。该机制于 macOS Ventura 中启用，提供了一个框架，将**每个系统二进制文件归类到不同的约束类别**中，这些类别定义在 **trust cache** 中；trust cache 是一个包含系统二进制文件及其对应哈希值的列表。这些约束适用于系统中的每个可执行二进制文件，其中包含一组**规则**，用于规定**启动特定二进制文件**所需满足的条件。这些规则包括二进制文件必须满足的 self constraints、其父进程必须满足的 parent constraints，以及其他相关实体必须遵守的 responsible constraints。<sup>[[1]](#references)[[4]](#references)</sup>

从 macOS Sonoma 开始，该机制通过 **Environment Constraints** 扩展到第三方 app，使开发者能够通过指定一组**环境约束的键和值**来保护其 app。<sup>[[5]](#references)</sup>

你可以在约束字典中定义**启动环境和库约束**，并将其保存到 **`launchd` property list 文件**中，或保存到用于代码签名的**单独 property list** 文件中。<sup>[[5]](#references)</sup>

共有 4 种约束类型：

- **Self Constraints**：应用于**正在运行的**二进制文件的约束。
- **Parent Process**：应用于进程**父进程**的约束（例如运行 XP service 的 **`launchd`**）
- **Responsible Constraints**：在 XPC 通信中，应用于**调用该 service 的进程**的约束
- **Library load constraints**：使用 library load constraints 有选择地描述可以加载的代码

因此，当一个进程尝试启动另一个进程时——通过调用 `execve(_:_:_:)` 或 `posix_spawn(_:_:_:_:_:_:)`——操作系统会检查该**可执行**文件是否满足其**自身的 self constraint**。操作系统还会检查**父**进程的可执行文件是否满足该可执行文件的 **parent constraint**，并检查**负责进程**的可执行文件是否满足该可执行文件的 **responsible process constraint**。如果这些启动约束中的任何一个未得到满足，操作系统就不会运行该程序。

如果加载库时**库约束**的任何部分不成立，你的进程就**不会加载**该库。

## LC 类别

LC 由**事实**和用于组合事实的**逻辑运算**（and、or 等）组成。

[**LC 可以使用的事实已在此文档中说明**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例如：

- is-init-proc：一个布尔值，表示可执行文件是否必须是操作系统的初始化进程（`launchd`）。
- is-sip-protected：一个布尔值，表示可执行文件是否必须是受 System Integrity Protection（SIP）保护的文件。
- `on-authorized-authapfs-volume:`：一个布尔值，表示操作系统是否从经过授权和身份验证的 APFS 卷加载了可执行文件。
- `on-authorized-authapfs-volume`：一个布尔值，表示操作系统是否从经过授权和身份验证的 APFS 卷加载了可执行文件。
- Cryptexes volume
- `on-system-volume:`：一个布尔值，表示操作系统是否从当前启动的系统卷加载了可执行文件。
- 位于 /System 中...
- ...

当 Apple 二进制文件完成签名后，系统会将其**分配到 trust cache 中的某个 LC 类别**。

- **iOS 16 LC 类别**已在[**此处完成逆向分析并记录**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[[6]](#references)</sup>
- 当前的 **LC 类别（macOS 14** - Somona）已完成逆向分析，其[**描述可以在此处找到**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[[7]](#references)</sup>

例如，类别 1 为：<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`：必须位于 System 或 Cryptexes volume 中。
- `launch-type == 1`：必须是 system service（LaunchDaemons 中的 plist）。
- `validation-category == 1`：操作系统可执行文件。
- `is-init-proc`：Launchd

### 逆向 LC Categories

你可以在[**这里查看相关详细信息**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)，但基本上，它们定义在 **AMFI (AppleMobileFileIntegrity)** 中，因此你需要下载 Kernel Development Kit 以获取 **KEXT**。以 **`kConstraintCategory`** 开头的符号是**值得关注的**。提取这些符号后，你会得到一个 DER (ASN.1) 编码的数据流，需要使用 [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 或 python-asn1 library 及其 `dump.py` script 进行解码，[andrivet/python-asn1](https://github.com/andrivet/python-asn1)，它会输出更易理解的字符串。<sup>[[3]](#references)[[8]](#references)</sup>

## 环境约束

这些是配置在**第三方应用程序**中的 Launch Constraints。开发者可以在其应用程序中选择要使用的**事实**和**逻辑操作数**，以限制对应用程序本身的访问。

可以使用以下命令枚举应用程序的 Environment Constraints：
```bash
codesign -d -vvvv app.app
```
## Trust Caches

在 **macOS** 中，有几个 Trust Cache：

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

在 iOS 中，它似乎位于 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**。

> [!WARNING]
> 在 Apple Silicon 设备上运行的 macOS 中，如果 Apple 签名的二进制文件不在 Trust Cache 中，AMFI 将拒绝加载它。

### 枚举 Trust Caches

上述 Trust Cache 文件采用 **IMG4** 和 **IM4P** 格式，其中 IM4P 是 IMG4 格式的 payload 部分。

你可以使用 [**pyimg4**](https://github.com/m1stadev/PyIMG4) 提取数据库的 payload：
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
（另一个选项是使用工具 [**img4tool**](https://github.com/tihmstar/img4tool)，即使该 release 较旧，它也能在 M1 上运行；如果将其安装到正确的位置，也能在 x86_64 上运行）。

现在可以使用工具 [**trustcache**](https://github.com/CRKatri/trustcache) 以可读格式获取信息：
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
trust cache 遵循以下结构，因此 **LC category 是第 4 列**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
然后，你可以使用类似[**这个脚本**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)的脚本来提取数据。

从这些数据中，你可以检查 **launch constraints 值为 `0`** 的 Apps，它们是不受约束的 Apps（关于每个值的含义，参见[**此处**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)）。<sup>[[6]](#references)</sup>

## Attack Mitigations

Launch Constraints 可以通过**确保进程不会在意外条件下执行**来缓解多种旧的攻击：例如从意外位置执行，或由意外的父进程调用（如果只有 launchd 应该启动该进程）。

此外，Launch Constraints 还可以**缓解 downgrade attacks**。

不过，它们**无法缓解常见的 XPC** 滥用、**Electron** code injection，或在没有 library validation 的情况下进行的 **dylib injection**（除非已知哪些 team IDs 可以加载 libraries）。<sup>[[3]](#references)</sup>

### XPC Daemon Protection

在 Sonoma 发布版本中，一个值得注意的点是 daemon XPC service 的**责任配置**。XPC service 对自身负责，而不是由连接的 client 负责。这一点记录在 feedback report FB13206884 中。这种设置可能存在缺陷，因为它允许与 XPC service 进行某些交互：

- **启动 XPC Service**：如果这被认为是一个 bug，那么该设置不会允许通过 attacker code 启动 XPC service。
- **连接到 Active Service**：如果 XPC service 已经在运行（可能由其原始 application 激活），则不存在阻止连接到它的障碍。

虽然对 XPC service 实施 constraints 可能有助于**缩小潜在攻击的窗口**，但它无法解决主要问题。确保 XPC service 的安全性，根本上需要**有效验证连接的 client**。这仍然是强化该 service 安全性的唯一方法。另外值得注意的是，上述责任配置目前确实在运行，这可能与设计意图不一致。<sup>[[3]](#references)</sup>

### Electron Protection

即使要求 application 必须由 **LaunchService** 打开（位于 parents constraints 中），也可以通过 **`open`**（它可以设置 env variables）或使用 **Launch Services API**（其中可以指定 env variables）来实现。<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Overriding the built-in constraints at spawn time

Launch constraints（官方称为**轻量级代码要求**，*LWCR*）由 **AMFI MAC policy** 强制执行。`posix_spawn` 允许 caller 通过 **`posix_spawnattr_setmacpolicyinfo_np()`** 将任意 blob 传递给 MAC policy，而 AMFI 会通过该路径接受 caller 提供的 LWCR dictionary。该 bug 的问题在于：**attacker 提供的 constraints 替换了 binary 内置的 constraints**，而不是在其基础上进行额外检查：

- 构建一个最小的（甚至为空的）launch-constraints dictionary。
- 将 **constraint category 设置为 `127`**。这是一个 AMFI 允许出现在 spawn attributes 中、但不会强制执行的值——它只会记录 `Launch Constraint Violation (not enforcing)`，而不会阻止执行。
- 通过 spawn attributes 传递该 dictionary，之后进程会在其真实 self/parent constraints 原本禁止的 context 中启动。

修复后，**内置 constraints 和提供的 constraints 都会被验证**，因此提供的 dictionary 无法再削弱内置 constraints。<sup>[[2]](#references)</sup>

> [!TIP]
> 审计 constraint enforcement 时，应寻找这种通用模式：允许 untrusted input *提供* policy 的 API 通常值得关注，尤其是在 policy engine 将所提供的值视为替代项，而不是额外要求时。

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2（Live-Stream）](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253：绕过 macOS 上的 Launch Constraints（wts.dev）](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints 深入解析 - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [为什么 system app 或 command tool 无法运行？Launch constraints 和 trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [使用 environment constraints 保护你的 Mac app - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16 中引入的 Launch Constraints 说明（LinusHenze gist）](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints（theevilbit gist）](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Beyond the good ol` LaunchAgents - about it in here](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}
