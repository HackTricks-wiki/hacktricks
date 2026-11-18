# macOS 启动/环境约束与 Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

macOS 引入启动约束以增强安全性，**规范进程如何、由谁以及从何处启动**。该机制始于 macOS Ventura，提供了一个框架，将**每个系统二进制文件归入不同的约束类别**。这些类别定义在 **trust cache** 中；trust cache 是一个包含系统二进制文件及其对应哈希值的列表​。这些约束适用于系统中的每个可执行二进制文件，并包含一组**规则**，用于规定**启动特定二进制文件的要求**。规则包括二进制文件必须满足的自身约束、其父进程必须满足的父进程约束，以及其他相关实体必须遵守的责任进程约束​。<sup>[[1]](#references)[[4]](#references)</sup>

从 macOS Sonoma 开始，该机制通过**环境约束**扩展到第三方 app，开发者可以指定一**组环境约束的键和值**来保护自己的 app。<sup>[[5]](#references)</sup>

你可以在约束字典中定义**启动环境和库约束**，并将其保存到 **`launchd` 属性列表文件**中，或保存到用于代码签名的**独立属性列表**文件中。<sup>[[5]](#references)</sup>

约束共有 4 种类型：

- **自身约束**：应用于**正在运行的**二进制文件的约束。
- **父进程约束**：应用于**进程的父进程**的约束（例如，运行某个 XPC 服务的 **`launchd`**）
- **责任进程约束**：应用于 XPC 通信中**调用服务的进程**的约束
- **库加载约束**：使用库加载约束来选择性地描述可加载的代码

因此，当进程尝试启动另一个进程（通过调用 `execve(_:_:_:)` 或 `posix_spawn(_:_:_:_:_:_:)`）时，操作系统会检查该**可执行文件**是否**满足**其**自身约束**。操作系统还会检查**父进程**的可执行文件是否**满足该可执行文件的父进程约束**，并检查**责任进程**的可执行文件是否**满足该可执行文件的责任进程约束**。如果不满足任何一项启动约束，操作系统就不会运行该程序。

加载库时，如果**库约束**的任何部分不成立，进程就**不会加载**该库。

## LC 类别

LC 由**事实**和**逻辑运算**（and、or 等）组成，用于组合这些事实。

[**LC 可使用的事实已在此处记录**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例如：

- is-init-proc：一个布尔值，表示该可执行文件是否必须是操作系统的初始化进程（`launchd`）。
- is-sip-protected：一个布尔值，表示该可执行文件是否必须是受系统完整性保护（SIP）保护的文件。
- `on-authorized-authapfs-volume:`：一个布尔值，表示操作系统是否从已授权且经过身份验证的 APFS 卷加载了该可执行文件。
- `on-authorized-authapfs-volume`：一个布尔值，表示操作系统是否从已授权且经过身份验证的 APFS 卷加载了该可执行文件。
  - Cryptexes 卷
- `on-system-volume:`一个布尔值，表示操作系统是否从当前已启动的系统卷加载了该可执行文件。
  - 位于 /System... 中
- ...

Apple 二进制文件签名时，会在 **trust cache** 中将其**分配到一个 LC 类别**。

- **iOS 16 的 LC 类别**已在[**此处逆向分析并记录**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[[6]](#references)</sup>
- 当前的 **LC 类别（macOS 14 - Somona）**已完成逆向分析，其[**说明可在此处查看**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[[7]](#references)</sup>

例如，类别 1 是：<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: 必须位于 System 或 Cryptexes 卷上。
- `launch-type == 1`: 必须是系统服务（plist 位于 LaunchDaemons 中）。
- `validation-category == 1`: 操作系统可执行文件。
- `is-init-proc`: Launchd

### 反向分析 LC 类别

你可以在[**这里**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)了解更多信息。简单来说，这些类别定义在 **AMFI (AppleMobileFileIntegrity)** 中，因此你需要下载 Kernel Development Kit 来获取 **KEXT**。以 **`kConstraintCategory`** 开头的符号是**重点**。提取这些符号后，你会得到 DER（ASN.1）编码的数据流，需要使用 [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 或 python-asn1 库及其 `dump.py` 脚本 [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) 解码，从而获得更易读的字符串。<sup>[[3]](#references)[[8]](#references)</sup>

## 环境约束

这些是配置在**第三方应用程序**中的 Launch Constraints。开发者可以在应用程序中选择要使用的**事实**和**逻辑运算符**，以限制对该应用程序本身的访问。

可以通过以下方式枚举应用程序的环境约束：

```bash
codesign -d -vvvv app.app
```

## 信任缓存

在 **macOS** 中有几个信任缓存：

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

而在 iOS 中，它似乎位于 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**。

> [!WARNING]
> 在 Apple Silicon 设备上运行的 macOS 中，如果 Apple 签名的二进制文件不在信任缓存中，AMFI 将拒绝加载它。

### 枚举信任缓存

前面提到的信任缓存文件采用 **IMG4** 和 **IM4P** 格式，其中 IM4P 是 IMG4 格式的 payload 部分。

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

（另一个选项是使用工具 [**img4tool**](https://github.com/tihmstar/img4tool)，即使它的版本较旧，只要将它安装在正确的位置，也可以在 M1 上运行；如果安装在正确的位置，它也可以在 x86_64 上运行。）

现在，你可以使用工具 [**trustcache**](https://github.com/CRKatri/trustcache) 以易读的格式获取信息：

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

Trust cache 遵循以下结构，因此 **LC category 是第 4 列**

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

从这些数据中，你可以检查 **launch constraints 值为 `0`** 的应用，这些应用不受约束（有关各个值的含义，请[**查看这里**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)）。<sup>[[6]](#references)</sup>

## 攻击缓解

Launch Constraints 可以通过**确保进程不会在意料之外的条件下执行**来缓解一些旧攻击：例如从意料之外的位置启动，或由意料之外的父进程调用（如果该进程本应仅由 launchd 启动）。

此外，Launch Constraints 还可以**缓解降级攻击**。

但是，它们**无法缓解常见的 XPC 滥用**、**Electron** 代码注入或缺少 library validation 的 **dylib 注入**（除非已知允许加载库的 team ID）。<sup>[[3]](#references)</sup>

### XPC Daemon 防护

在 Sonoma 版本中，一个值得注意的方面是 daemon XPC 服务的**责任配置**。XPC 服务对自身负责，而不是由连接的客户端负责。反馈报告 FB13206884 记录了这一点。这种设置可能看起来有缺陷，因为它允许与 XPC 服务进行某些交互：

- **启动 XPC Service**：即使认为这是一个 bug，这种设置也不允许通过攻击者代码启动 XPC Service。
- **连接到正在运行的 Service**：如果 XPC 服务已经在运行（可能是由其原始应用启动的），则连接它不会受到任何限制。

虽然对 XPC 服务实施约束可能有助于**缩小潜在攻击窗口**，但这并未解决主要问题。要从根本上确保 XPC 服务的安全，必须**有效验证连接的客户端**。这是加强服务安全性的唯一方法。另外值得注意的是，上述责任配置目前确实在运行，但这可能与设计初衷不符。<sup>[[3]](#references)</sup>

### Electron 防护

即使要求应用必须由 **LaunchService** 打开（在父进程约束中），也可以通过 **`open`**（可以设置环境变量）或 **Launch Services API**（可以指定环境变量）来实现。<sup>[[3]](#references)</sup>

关于 policy-specific spawn attributes 背后的通用 MACF 机制，请参阅 [MACF 特定策略的 spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input)。

### CVE-2025-43253 - 在 spawn 时覆盖内置约束

Launch Constraints（官方名称为 **lightweight code requirements**，*LWCR*）由 **AMFI MAC policy** 强制执行。`posix_spawn` 允许调用方通过 **`posix_spawnattr_setmacpolicyinfo_np()`** 向 MAC policy 传递任意 blob，而 AMFI 会接受通过此路径传入的调用方提供的 LWCR 字典。这个 bug 的问题在于，**攻击者提供的约束会替代二进制文件内置的约束**，而不是在内置约束之外额外进行检查：

- 构建一个最小的（甚至为空的）launch-constraints 字典。
- 将**约束类别设为 `127`**。AMFI 允许在 spawn attributes 中使用此值，但**不会强制执行**——它只会记录 `Launch Constraint Violation (not enforcing)`，而不会阻止执行。
- 通过 spawn attributes 传入该字典，进程便会在其实际自身/父进程约束本应禁止的上下文中启动。

修复后，**内置约束和调用方提供的约束都会**经过验证，因此提供的字典无法再削弱内置约束。<sup>[[2]](#references)</sup>

> [!TIP]
> 审计约束强制机制时，可以留意这种常见模式：如果某个 API 允许不受信任的输入*提供*策略，那么当策略引擎将所提供的值视为替代项而非额外要求时，就值得关注。



## References

- [1] [Objective by the Sea #OBTS v6.0 第 2 天（直播）](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253：绕过 macOS 上的 Launch Constraints（wts.dev）](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch 和 Environment Constraints 深入解析 - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [为什么系统应用或命令行工具无法运行？Launch Constraints 和信任缓存 - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [使用 environment constraints 保护你的 Mac 应用 - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16 中引入的 Launch Constraints 说明（LinusHenze gist）](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints（theevilbit gist）](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [超越老式 LaunchAgents - 相关内容见此处](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
