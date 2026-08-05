# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

macOS 引入了 Launch constraints，以通过**规范进程的启动方式、启动者及启动来源**来增强安全性。该机制始于 macOS Ventura，提供了一个框架，将**每个系统二进制文件归类到不同的约束类别**中。这些类别定义在 **trust cache** 内；trust cache 是一个包含系统二进制文件及其对应哈希值的列表。这些约束适用于系统中的每个可执行二进制文件，并包含一组用于规定**启动特定二进制文件**所需条件的**规则**。这些规则包括：二进制文件必须满足的 self constraints、其父进程必须满足的 parent constraints，以及其他相关实体必须遵守的 responsible constraints。

从 macOS Sonoma 开始，该机制通过 **Environment Constraints** 扩展到第三方应用，允许开发者通过指定一组**环境约束的键和值**来保护其应用。

你可以在约束字典中定义**启动环境和 library 约束**，然后将其保存到 **`launchd` property list 文件**中，或者保存到用于代码签名的**独立 property list**文件中。

约束有 4 种类型：

- **Self Constraints**：应用于**正在运行的**二进制文件的约束。
- **Parent Process**：应用于进程**父进程**的约束（例如，运行 XP service 的 **`launchd`**）
- **Responsible Constraints**：应用于 XPC 通信中**调用 service 的进程**的约束
- **Library load constraints**：使用 library load constraints 来选择性描述可以加载的代码

因此，当一个进程尝试通过调用 `execve(_:_:_:)` 或 `posix_spawn(_:_:_:_:_:_:)` 来启动另一个进程时，操作系统会检查该**可执行文件**是否满足其**自身的 self constraint**。它还会检查**父进程**的可执行文件是否满足该可执行文件的**parent constraint**，并检查**responsible 进程**的可执行文件是否满足该可执行文件的 responsible process constrain**t**。如果这些 launch constraints 中有任何一项未得到满足，操作系统就不会运行该程序。

如果加载 library 时，**library constraint 的任何部分不成立**，你的进程就**不会加载**该 library。

## LC 类别

LC 由 **facts** 和将这些 facts 组合起来的**逻辑运算**（and、or 等）构成。

[**LC 可以使用的 facts 已在此处记录**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例如：

- is-init-proc：一个 Boolean 值，表示该可执行文件是否必须是操作系统的初始化进程（`launchd`）。
- is-sip-protected：一个 Boolean 值，表示该可执行文件是否必须是受 System Integrity Protection (SIP) 保护的文件。
- `on-authorized-authapfs-volume:` 一个 Boolean 值，表示操作系统是否从已授权且经过身份验证的 APFS volume 加载了该可执行文件。
- `on-authorized-authapfs-volume`：一个 Boolean 值，表示操作系统是否从已授权且经过身份验证的 APFS volume 加载了该可执行文件。
- Cryptexes volume
- `on-system-volume:`一个 Boolean 值，表示操作系统是否从当前启动的 system volume 加载了该可执行文件。
- 位于 /System...
- ...

Apple 二进制文件签名时，会在 **trust cache** 中将其**分配到某个 LC 类别**。

- **iOS 16 LC 类别**已在[**此处完成逆向分析并记录**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[6]</sup>
- 当前的 **LC 类别（macOS 14** - Somona）已完成逆向分析，其[**描述可在此处找到**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[7]</sup>

例如，类别 1 为：<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`：必须位于 System 或 Cryptexes 卷中。
- `launch-type == 1`：必须是 system service（LaunchDaemons 中的 plist）。
- `validation-category == 1`：操作系统可执行文件。
- `is-init-proc`：Launchd

### 逆向 LC Categories

你可以在[**这里查看相关的更多信息**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)，但基本上，它们定义于 **AMFI (AppleMobileFileIntegrity)** 中，因此你需要下载 Kernel Development Kit 以获取 **KEXT**。以 **`kConstraintCategory`** 开头的符号就是**需要关注的符号**。提取这些符号后，你会得到一个 DER（ASN.1）编码的流，需要使用 [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 或 python-asn1 library 及其 `dump.py` 脚本进行解码，[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) 会输出更易理解的字符串。<sup>[3]</sup>

## Environment Constraints

这些是配置于**第三方应用程序**中的 Launch Constraints。开发者可以在其应用程序中选择要使用的 **facts** 和**逻辑运算符**，以限制对应用程序自身的访问。

可以使用以下方式枚举应用程序的 Environment Constraints：
```bash
codesign -d -vvvv app.app
```
## Trust Caches

在 **macOS** 中有几个 trust caches：

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

而在 iOS 中，它似乎位于 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**。

> [!WARNING]
> 在 Apple Silicon 设备上运行的 macOS 中，如果 Apple 签名的 binary 不在 trust cache 中，AMFI 将拒绝加载它。

### 枚举 Trust Caches

前面提到的 trust cache 文件采用 **IMG4** 格式，而 **IM4P** 是 IMG4 格式的 payload 部分。

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
（另一种选择是使用工具 [**img4tool**](https://github.com/tihmstar/img4tool)，即使该版本较旧，它也能在 M1 上运行；如果将其安装到正确的位置，也能在 x86_64 上运行）。

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
然后，你可以使用类似于[**这个脚本**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)的脚本来提取数据。

通过这些数据，你可以检查 **launch constraints value 为 `0`** 的 App，它们是不受约束的 App（有关每个值的含义，请[**查看这里**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)）。<sup>[6]</sup>

## 攻击缓解措施

Launch Constraints 可以通过**确保进程不会在意外条件下执行**来缓解多种旧有攻击：例如从意外位置执行，或由意外的父进程调用（如果只有 launchd 应该启动它）。

此外，Launch Constraints 还可以**缓解 downgrade attacks**。

但是，它们**无法缓解常见的 XPC** 滥用、**Electron** code injection，或未启用 library validation 的 **dylib injection**（除非已知可以加载库的 team IDs）。<sup>[3]</sup>

### XPC Daemon Protection

在 Sonoma 版本中，一个值得注意的点是 daemon XPC service 的**责任配置**。XPC service 对自身负责，而不是由连接的 client 负责。相关内容记录在 feedback report FB13206884 中。这种设置可能存在缺陷，因为它允许与 XPC service 进行某些交互：

- **Launching the XPC Service**：如果将其视为 bug，这种设置不允许通过 attacker code 启动 XPC service。
- **Connecting to an Active Service**：如果 XPC service 已经在运行（可能由其原始 application 激活），则不存在阻止连接到它的限制。

虽然在 XPC service 上实施 constraints 可能有助于**缩小潜在攻击的窗口**，但这并没有解决主要问题。要确保 XPC service 的安全，根本上必须**有效验证连接的 client**。这仍然是强化该 service 安全性的唯一方法。此外，值得注意的是，上述责任配置目前确实在运行，这可能与预期设计不一致。<sup>[3]</sup>

### Electron Protection

即使要求 application 必须由 **LaunchService** 打开（位于 parents constraints 中），也可以通过使用 **`open`**（它可以设置 env variables）或使用 **Launch Services API**（其中可以指定 env variables）来实现。<sup>[3]</sup>

### CVE-2025-43253 - Overriding the built-in constraints at spawn time

Launch constraints（官方称为 **lightweight code requirements**，*LWCR*）由 **AMFI MAC policy** 强制执行。`posix_spawn` 允许 caller 通过 **`posix_spawnattr_setmacpolicyinfo_np()`** 向 MAC policy 传入任意 blob，而 AMFI 会通过该路径接受 caller 提供的 LWCR dictionary。该 bug 的问题在于，**attacker 提供的 constraints 替换了 binary 内置的 constraints**，而不是在其基础上进行额外检查：

- 构建一个最小的（甚至为空的）launch-constraints dictionary。
- 将 **constraint category 设置为 `127`**，这是 AMFI 允许在 spawn attributes 中使用、但不会强制执行的值——它只会记录 `Launch Constraint Violation (not enforcing)`，而不是阻止执行。
- 通过 spawn attributes 传入它，此时 process 会在其真实 self/parent constraints 原本禁止的 context 中启动。

修复后，**内置 constraints 和提供的 constraints 都会被验证**，因此提供的 dictionary 不再能够削弱内置 constraints。<sup>[2]</sup>

> [!TIP]
> 审计 constraint enforcement 时，可以重点关注这种常见模式：如果某个 API 允许 untrusted input *提供* policy，那么当 policy engine 将该值视为替换项而非额外要求时，它通常会很有研究价值。

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
