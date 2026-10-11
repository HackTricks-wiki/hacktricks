# Mythic

{{#include ../banners/hacktricks-training.md}}

## 什么是 Mythic？

Mythic 是一个面向红队的开源、模块化、协作式命令与控制（C2）框架。它允许操作人员跨不同操作系统（包括 Windows、Linux 和 macOS）管理和部署 agents（payloads）。Mythic 提供浏览器 UI，支持多操作人员任务分配、文件处理、SOCKS/rpfwd 管理和 payload 生成。

与单体框架不同，Mythic 仓库本身**不**附带 payload 类型或 C2 profiles。Agents、wrappers 和 C2 profiles 通常作为外部组件安装，并且可以独立于 Mythic 核心进行更新。

### 安装

如需安装 Mythic，请按照官方 **[Mythic repo](https://github.com/its-a-feature/Mythic)** 中的说明操作。常见的初始化方式是在 Mythic 目录中运行：

```bash
sudo make
sudo ./mythic-cli start
```

如果 Mythic 已在运行，通常可以使用 `./mythic-cli install github ...` 添加新的 agent 或 profile，然后重启 Mythic，或者直接启动新的组件。

### Agents

Mythic 支持多个 agent，它们是**在受感染系统上执行任务的 payload**。每个 agent 都可以根据特定需求进行定制，并可在不同操作系统上运行。

默认情况下，Mythic 不会安装任何 agent。开源社区的 agent 位于 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)，而[**社区功能矩阵**](https://mythicmeta.github.io/overview/agent_matrix.html)可帮助你快速查看支持的操作系统、payload 格式、wrapper 和 C2 profile。<sup>[[1]](#references)</sup>

要从该组织安装 agent，可以运行：

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

`sudo -E` 形式适用于在非 root 环境中安装。即使 Mythic 已在运行，你也可以使用前面的命令添加新 agents。

### C2 Profiles

Mythic 中的 C2 profiles 定义了 **agents 如何与 Mythic 服务器通信**。它们指定通信协议、加密方法和其他设置。你可以通过 Mythic Web 界面创建和管理 C2 profiles。

默认情况下，Mythic 安装时不包含任何 profiles，不过你可以从 repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) 下载一些 profiles，运行：

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

当前与 operator 相关、需要牢记的 profiles：

- [`http`](https://github.com/MythicC2Profiles/http)：基础的异步 GET/POST 流量。
- [`httpx`](https://github.com/MythicC2Profiles/httpx)：更灵活的 HTTP 流量，支持多个 callback 域名、故障转移/轮询轮换、自定义 headers/query 参数，以及消息转换（`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`），并可将转换后的内容放入 cookies、headers、query 参数或正文中。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp)：通过 JSON/TOML 驱动的 HTTP 消息定制；当静态 `http` profile 过于容易识别时可使用。

### 当前平台注意事项

- 现在，许多公开的 agents 和 profiles 都会通过预构建的远程容器镜像安装。
  如果你 fork 了某个组件或在本地打了补丁，但 Mythic 仍在使用旧行为，请检查生成的 `.env` 项中的 `*_REMOTE_IMAGE`、`*_USE_BUILD_CONTEXT` 和 `*_USE_VOLUME`；通常启用 `*_USE_BUILD_CONTEXT="true"` 后，Mythic 才会从本地 Docker context 重新构建，而不是悄悄复用远程镜像。
- Browser scripts 是 Mythic 中对 operator 最有用的功能之一：它们可以将原始命令输出转换为表格、截图查看器、下载链接、搜索链接，以及可直接从 UI 发起后续 tasking 的按钮。当前版本的 Mythic 允许每个 operator 保存自己的 scripts，并按全局或单个 task 启用或禁用它们；agent 返回结构化 JSON 而非纯文本时，效果最佳。这对重复执行 `ls`、`ps`、triage 和文件浏览器工作流尤其有用。<sup>[[4]](#references)[[6]](#references)</sup>
- 较新的 Mythic 版本还支持 interactive tasking 和 Push C2 模式，从而减少 PTY/SOCKS/rpfwd 密集型操作对 `sleep 0` 轮询的需求。如果 agent/profile 支持这些功能，通常比为了维持交互通道可用而持续向服务器发送 check-in 的开销更低。<sup>[[3]](#references)</sup>
- 当前 3.4 时代的 Mythic builders 比较旧的文章所描述的更加了解上下文：现在可以根据所选 OS 或其他构建选项对 build 参数进行分组或隐藏；payload 类型可以声明是否支持在一次构建中使用多个 C2 profiles，或同一个 C2 的多个实例；C2 参数差异也允许 agent 隐藏其实际并未实现的字段。当你在 `http`、`httpx`、`smb`、`tcp` 和 `websocket` 之间切换时，这一点很重要，因为安全且有效的构建选项已不再是固定不变的表单。<sup>[[5]](#references)</sup>
- 如果你正在构建自定义 agent/profile 组合，并且不希望 Mythic 在传输时使用 JSON 消息格式或默认加密，请使用 `translation_container`：Mythic 会剥离 UUID，通过 gRPC 将加密 blob 和密钥材料交给 translator，并接收 agent 原生字节作为返回结果。这是支持二进制协议、自定义 framing 或 agent 端加密的简洁方式，无需重写整个服务器。
- 请记住，linked/P2P callbacks 不只是转发 tasking。Mythic 的 `get_tasking` 流程还可以携带 responses，以及 `delegates`、`socks`、`rpfwd` 和 `interactive` 数据。实际操作中，一个 egress callback 可以在同一轮轮询中为内部 callbacks 和 pivot 通道提供服务；如果子 agents 会自行定期 check-in，设置 `get_delegate_tasks=false` 可避免父 agent 意外取走内部 callback 队列中的任务。

### Wrapper payloads

Wrapper payloads 可以让你保留相同的 agent 逻辑，同时更改交付或持久化到磁盘上的表示形式。

- `service_wrapper`：将另一个 payload 转换为 Windows service 可执行文件，适用于执行路径要求使用有效 service 二进制文件的情况。
- `scarecrow_wrapper`：使用 ScareCrow loader 封装兼容的 shellcode，生成由 loader 加载的输出，例如 EXE/DLL/CPL。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo 是一个使用 4.0 .NET Framework 编写的 Windows agent，采用 C# 开发，旨在用于 SpecterOps 的培训项目。<sup>[[2]](#references)</sup>

安装方式如下：

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### 当前 build/profile 说明

- Apollo 目前可以生成 `WinExe`、`Shellcode`、`Service` 和 `Source` payload。
- 常用的 Apollo profiles 包括 `http`、`httpx`、`smb`、`tcp` 和 `websocket`。
- 如果需要域名轮换、代理支持、自定义消息位置和消息转换，通常应选择 `httpx`，而不是较旧的静态 `http` profile。
- Apollo 是功能较为完善的社区 agent 之一，目前提供 Mythic 端集成，例如 browser scripts、file/process browser views、screenshots、keylogging、SOCKS、rpfwd、Push C2 和 P2P routing。
- Apollo 支持 `service_wrapper` 和 `scarecrow_wrapper` 等 wrapper payload。
- Apollo 支持动态加载命令，因此可以让初始 payload 保持精简，之后再加载额外命令或 Forge modules，而不必在首次 build 时就编译所有 post-ex 能力。
- 生成 shellcode 输出时，Apollo 当前的 builder 还提供 Donut 格式选项（`Binary`、`Base64`、`C`、`Ruby`、`Python`、`Powershell`、`C#`、`Hex`）和 Donut bypass 行为（`None`、`Abort on fail`、`Continue on fail`）。如果最终目的是用 `service_wrapper`、`scarecrow_wrapper` 或自定义 loader 重新封装 shellcode，这些选项会很有用。
- `register_file` 和 `register_assembly` 是 `execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import` 和 `powerpick` 使用的 staging 原语。在当前 Apollo builds 中，这些 staged artifacts 会以受 DPAPI 保护的 AES256 blobs 缓存在客户端。
- `ls` 和 `ps` 结果与 Mythic 的 browser scripts 以及 file/process browser 集成效果尤其好，可明显加快协作行动中的操作员研判速度。
- Apollo 的 fork-and-run jobs 会继承 `spawnto_x86` / `spawnto_x64` 中设置的牺牲进程配置，从 `ppid` 继承父进程选择，然后使用当前选定的 injection primitive。实际上，这意味着针对某个命令所做的 OPSEC 调整，通常会同时影响 `execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe` 和 `spawn`。
- 当前 Apollo 文档记录的 injection 后端包括 `CreateRemoteThread`、`QueueUserAPC`（early-bird 风格）以及通过 syscalls 实现的 `NtCreateThreadEx`。在执行容易产生噪声的 post-exploitation 操作前，请使用 `get_injection_techniques`；如果需要避开与目标或待运行命令不兼容的 primitive，则使用 `set_injection_technique`。
- `blockdlls` 只影响为 post-exploitation jobs 创建的牺牲进程。配合一个比默认裸 `rundll32.exe` 更不显眼的 `spawnto_x64` 目标，这是运行大量 assembly/PowerShell tasking 前最容易进行的 Apollo 端调整之一。

### 具备检测规避意识的 .NET agent build pipeline

具备检测规避意识的 Apollo fork 应被视为一个**完整的 build-system 问题**，而不是最后加上 `obfuscate.exe` 这一步。本案例研究补充了通用的 [AV evasion methodology](av-bypass.md) 和 [.NET inspection tools](../reversing/reversing-tools-basic-methods/README.md)：对 wire identifiers、IL metadata、dependency packaging、reflection 和动态编译任务所做的改动，共同构成一个兼容性边界。<sup>[[8]](#references)</sup>

#### YARA 感知的协议变更

修改代码前，先审查公开的文件/内存规则。例如，Elastic 的 `Multi_Trojan_Mythic_4beb7e17` 会在 Mythic JSON/action 字符串中任意 **7 个（共 11 个）** 存在时触发，其中包括 `task_id`、`post_response`、`c2_profile`、`get_tasking` 和 `get_delegate_tasks`。重命名足够多的字段可以绕过该阈值，但这些是协议值，而非外观符号：agent 和对应的 server/profile 实现必须同步修改。<sup>[[7]](#references)[[8]](#references)</sup>

这只能移除一组静态特征。Check-in 频率、消息形态、任务/响应流程以及运行时字符串重建，仍可能成为行为或内存指标；因此，应同时验证 build 产物和实际运行过的 callback，而不是把字符串扫描结果干净视为成功。<sup>[[8]](#references)</sup>

#### 在应用全局变换前先合并

使用 Costura 等工具嵌入资源时，依赖程序集会以压缩资源的形式保留。因此，只处理外层模块的 obfuscator 会遗漏其中的类型名称和 metadata；而分别 obfuscate 每个 DLL，则可能为跨程序集契约分配不兼容的名称。先在 IL 层面合并 build 输出（例如使用 [ILRepack](https://github.com/gluck/il-repack)），再对生成的模块应用同一份 rename map。<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

自定义 pass 可以使用 [dnlib](https://github.com/0xd4d/dnlib) 执行托管 IL/metadata 转换，并使用 [AsmResolver](https://github.com/Washi1337/AsmResolver) 在写入后修补 PE/resource。在案例研究中，符合条件的 `ldstr` 指令被替换为整数 token/解密器调用，并由新生成的 16 字节 rolling-XOR key 提供支持；符号和命名空间则被映射为看似合理的企业风格名称，而不是简短的顺序标识符。其他 pass 会移除选定的编译器/调试器属性、清理合并/嵌入引用、重命名资源并修补版本信息。每次独立构建都应重新生成名称、dead code 和加密材料：更改密文可以移除稳定字节，但稳定的解密器或可识别的转换模式本身就是一种 signature。<sup>[[8]](#references)</sup>

#### 让动态任务与 payload 保持同步

Apollo 可以在服务器端编译任务源码、发送 DLL 字节，并使用 `Assembly.Load()` 加载它们。一旦基础 agent 的 public types 被重命名，之后根据原始 API 编译的任务就无法再解析这些类型。应将导出的重命名映射视为特定 payload 的 ABI artifact：<sup>[[8]](#references)</sup>

1. 将映射和类型上下文绑定到确切的 payload/build identifier。
2. 每次构建任务时，获取该映射并重写临时源码树。
3. 仅重写已解析的 namespace、type、嵌套/generic type、field 和 property 引用，然后针对混淆后的合并程序集进行编译。
4. 在交付任务前拒绝缺失或不匹配的映射，并在编译后运行初始化测试。

盲目全局替换并不安全，因为标识符也可能出现在字符串、局部声明、成员访问、framework type 或无关 namespace 中。如果仍使用文本/regex 重写器，就应明确保护这些上下文，并在映射 schema 或重命名 pass 发生变化时进行回归测试。<sup>[[8]](#references)</sup>

#### 让反射契约不依赖 namespace

通过检查 `t.FullName.StartsWith("Tasks.")` 来发现类型的代码会依赖该 namespace，因此在 namespace 映射后会失效。应改用稳定的类型关系来发现类型；如果分发仍使用 `t.Name`，则保留 command class 名称：<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

维护一份明确的 allowlist，列出反射可见的名称、序列化器字段、入口点以及不得重命名的跨程序集 API。最后，使用 ILSpy/dnSpy 反编译结果，扫描文件和内存中的表示，并在 EDR 实验室中测试每条命令和 loader 路径；构建成功启动并不代表一切正常，重命名仍可能导致任务失效，或只有在执行后才会触发检测。<sup>[[8]](#references)</sup>

此 agent 有大量命令，功能与 Cobalt Strike 的 Beacon 非常相似，同时还提供了一些额外功能。其中包括：

### 常用操作

- `cat`：打印文件内容
- `cd`：更改当前工作目录
- `cp`：将文件从一个位置复制到另一个位置
- `ls`：列出当前目录或指定路径中的文件和目录
- `ifconfig`：获取网络适配器和接口信息
- `netstat`：获取 TCP 和 UDP 连接信息
- `pwd`：打印当前工作目录
- `ps`：列出目标系统上正在运行的进程（包含额外信息）
- `jobs`：列出与长时间运行任务相关的所有正在运行的作业
- `download`：将文件从目标系统下载到本地计算机
- `upload`：将文件从本地计算机上传到目标系统
- `reg_query`：查询目标系统上的注册表项和值
- `reg_write_value`：向指定的注册表项写入新值
- `sleep`：更改 agent 的休眠间隔，该间隔决定它多久与 Mythic 服务器通信一次
- 还有许多其他命令，使用 `help` 查看可用命令的完整列表。

### 权限提升

- `getprivs`：在当前线程令牌上启用尽可能多的权限
- `getsystem`：打开 winlogon 的句柄并复制其令牌，从而有效地将权限提升至 SYSTEM 级别
- `make_token`：创建新的登录会话并将其应用于 agent，以便模拟另一位用户
- `steal_token`：从另一个进程窃取主令牌，使 agent 能够模拟该进程所属用户
- `pth`：Pass-the-Hash 攻击，使 agent 无需明文密码即可使用用户的 NTLM 哈希进行身份验证
- `mimikatz`：运行 Mimikatz 命令，从内存或 SAM 数据库中提取凭据、哈希及其他敏感信息
- `rev2self`：将 agent 的令牌还原为其主令牌，从而有效地将权限降回原始级别
- `ppid`：通过指定新的父进程 ID，更改后渗透作业的父进程，以便更好地控制作业执行环境
- `printspoofer`：执行 PrintSpoofer 命令以绕过打印后台处理程序的安全措施，从而实现权限提升或代码执行
- `dcsync`：将用户的 Kerberos 密钥同步到本地计算机，以便离线破解密码或进行进一步攻击
- `ticket_cache_add`：将 Kerberos 票据添加到当前或指定的登录会话，以便复用票据或进行模拟

### 进程执行

- `assembly_inject`：将 .NET 程序集 loader 注入远程进程
- `blockdlls`：阻止非 Microsoft 签名的 DLL 加载到后渗透作业中
- `execute_assembly`：在 agent 的上下文中执行 .NET 程序集
- `execute_coff`：在内存中执行 COFF 文件，从而实现编译代码的内存执行
- `execute_pe`：执行非托管可执行文件（PE）
- `keylog_inject`：将 keylogger 注入另一个进程，并将击键记录传回 Mythic 的 keylog 视图
- `screenshot` / `screenshot_inject`：直接捕获当前桌面，或将截图程序集注入目标进程/会话来捕获
- `get_injection_techniques`：显示可用的注入技术和当前选用的技术
- `inline_assembly`：在临时 AppDomain 中执行 .NET 程序集，以便临时执行代码而不影响 agent 的主进程
- `register_assembly`：注册 .NET 程序集，以供后续执行
- `register_file`：将文件注册到 agent 缓存中，以供后续 `execute_*` 或 PowerShell 任务使用
- `run`：使用系统的 PATH 查找可执行文件，并在目标系统上运行该文件
- `set_injection_technique`：更改后渗透作业使用的注入原语
- `shinject`：将 shellcode 注入远程进程，以便在内存中执行任意代码
- `inject`：将 agent shellcode 注入远程进程，以便在内存中执行 agent 代码
- `spawn`：在指定的可执行文件中启动新的 agent 会话，以便在新进程中执行 shellcode
- `spawnto_x64` 和 `spawnto_x86`：将后渗透作业使用的默认二进制文件更改为指定路径，而不是使用非常容易引起注意的、无参数运行的 `rundll32.exe`。

### Mythic Forge

这允许从 Mythic Forge **加载 COFF/BOF** 文件。Mythic Forge 是一个预编译 payload 和工具的存储库，这些文件可在目标系统上执行。加载这些命令后，即可将其作为 BOF 在当前 agent 进程中执行常见操作（通常比启动独立进程具有更好的 OPSEC）。

从安装它们开始：

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

然后，使用 `forge_collections` 显示 Mythic Forge 中的 COFF/BOF 模块，以便选择并加载到 agent 内存中执行。默认情况下，Apollo 中会添加以下 2 个 collection：

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

加载模块后，它会作为另一个命令出现在列表中，例如 `forge_bof_sa-whoami` 或 `forge_bof_sa-netuser`。

对于 BOF，请记住，Forge **不会**只是将一个扁平的参数字符串传给 Apollo。它会将 BOF 参数映射为 Mythic 的 typed-array 格式，然后转发到 Apollo 的 `execute_coff` 流程。如果 Forge 加载的 BOF 行为异常，请检查预期的 BOF 参数类型/entrypoint，而不只是检查你输入的命令行。另外请注意，Apollo 较新的 BOF loader 更改了参数处理方式，与早期 2.3.1 时代的版本有所不同，因此过时的 BOF 或旧 collection 可能仅仅因为参数编组要求发生变化而失效。

### PowerShell 和脚本执行

- `powershell_import`：将新的 PowerShell 脚本（.ps1）导入 agent 缓存，供后续执行
- `powershell`：在 agent 的上下文中执行 PowerShell 命令，以支持高级脚本编写和自动化
- `powerpick`：将 PowerShell loader assembly 注入一个牺牲进程，并执行 PowerShell 命令（不记录 PowerShell 日志）。
- `psinject`：在指定进程中执行 PowerShell，以便在另一个进程的上下文中定向执行脚本
- `shell`：在 agent 的上下文中执行 shell 命令，类似于在 cmd.exe 中运行命令

### 横向移动

- `jump_psexec`：使用 PsExec 技术横向移动到新主机：先复制 Apollo agent 可执行文件（apollo.exe），再执行它。
- `jump_wmi`：使用 WMI 技术横向移动到新主机：先复制 Apollo agent 可执行文件（apollo.exe），再执行它。
- `link` 和 `unlink`：在 callback 之间创建和拆除 P2P 链接（例如通过 SMB/TCP）。
- `wmiexecute`：使用 WMI 在本地或指定的远程系统上执行命令，并可选用凭据进行 impersonation。
- `net_dclist`：获取指定域的域控制器列表，有助于识别潜在的横向移动目标。
- `net_localgroup`：列出指定计算机上的本地组；若未指定计算机，则默认为 localhost。
- `net_localgroup_member`：获取本地或远程计算机上指定组的成员信息，以枚举特定组中的用户。
- `net_shares`：列出指定计算机上的远程共享及其可访问性，有助于识别潜在的横向移动目标。
- `socks`：在目标网络上启用兼容 SOCKS 5 的代理，以便通过已攻陷的主机隧道传输流量。兼容 proxychains 等工具。
- `rpfwd`：在目标主机的指定端口上开始监听，并通过 Mythic 将流量转发到远程 IP 和端口，以便远程访问目标网络上的服务。
- `listpipes`：列出本地系统上的所有命名管道，这有助于通过与 IPC 机制交互进行横向移动或权限提升。

有关 `jump_wmi` 或 `wmiexecute` 底层使用的 WMI 执行原语，请查看 [WmiExec](lateral-movement/wmiexec.md)。有关更广泛的 pivoting 模式，请查看 [隧道和端口转发](../generic-hacking/tunneling-and-port-forwarding.md)。

### 其他命令
- `help`：显示特定命令的详细信息，或显示 agent 中所有可用命令的一般信息。
- `clear`：将任务标记为“已清除”，使 agent 无法获取这些任务。可以指定 `all` 清除所有任务，或指定 `task Num` 清除某个特定任务。  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon 是一个用 Golang 编写的 agent，可编译为 **Linux 和 macOS** 可执行文件。

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### 当前 build/profile 说明

- 当前 Poseidon builds 面向 Linux 和 macOS，支持 `x86_64` 和 `arm64`。
- 支持的输出格式包括原生可执行文件，以及 `dylib` 和 `so` 等共享库形式的输出。
- Poseidon 支持 `http`、`websocket`、`tcp` 和 `dynamichttp`，当前 builders 还提供 `egress_order` 和故障转移阈值等多出口设置。
- Poseidon 当前的 capability metadata 还声明支持 browser scripts、文件/进程 browser 集成、interactive tasking、keylogging、screenshots、Push C2、SOCKS、rpfwd 和 P2P，因此它可以作为真正的 Linux/macOS pivot node，而不仅是简单的远程 shell。
- 需要更顺畅的网络行为或额外的 Go binary obfuscation 时，值得检查 `proxy_bypass` 和 `garble` 等 build-time 选项。
- 对 Linux/macOS 操作而言，`pty` 是较新的实用命令之一：它会打开交互式 PTY，并可在 Mythic 端暴露端口，以便进行更完整的终端交互，而无需使用旧的 `sleep 0` + SOCKS workaround。
- Poseidon 当前文档中特别值得关注的是适用于 macOS 的 tradecraft：`jxa` 在内存中执行 JavaScript for Automation，`screencapture` 捕获已登录用户的桌面，`clipboard_monitor` 流式传输 pasteboard 更改，`execute_library` 加载本地 dylib 并调用其中的函数，`libinject` 则强制远程进程加载磁盘上的 dylib。
- 对于长时间运行的任务，请记住，Poseidon 通过协作式 goroutines/threads 执行 post-exploitation 工作，因此无法强制终止。文档还明确指出，目前没有内置的 agent obfuscation，因此相较于经过高度 obfuscation 的商业 implants，build/profile 层面的 tradecraft 更为重要。

有关 Mythic 支持的操作、JAMF 滥用或 MDM-as-C2 思路的 macOS 特定 tradecraft，请参阅 [macOS 红队操作](../macos-hardening/macos-red-teaming/README.md)。

在 Linux 或 macOS 上使用时，它有一些有趣的命令：

### 常见操作

- `cat`：打印文件内容
- `cd`：更改当前工作目录
- `chmod`：更改文件权限
- `config`：查看当前配置和主机信息
- `cp`：将文件从一个位置复制到另一个位置
- `curl`：执行单次 Web 请求，可选指定 headers 和 method
- `upload`：将文件上传到目标
- `download`：将文件从目标系统下载到本地计算机
- 还有更多

### 搜索敏感信息

- `triagedirectory`：查找主机目录中的有趣文件，例如敏感文件或凭据。
- `getenv`：获取所有当前环境变量。

### macOS 特定 tradecraft

- `jxa`：通过 `OSAScript` 在内存中执行 JavaScript for Automation，适用于无需落地单独脚本文件的原生 macOS post-exploitation。
- `clipboard_monitor`：轮询 pasteboard 并将更改报告回 Mythic，适用于依赖复制/粘贴的凭据/token 窃取工作流。
- `screencapture`：捕获 macOS 用户的桌面。
- `execute_library`：从磁盘加载 dylib 并调用指定的导出函数。
- `libinject`：注入 shellcode stub，强制另一个 macOS 进程从磁盘加载 dylib。
- `persist_launchd`：直接通过 agent 创建 LaunchAgent / LaunchDaemon persistence。

### 横向移动

- `ssh`：使用指定凭据 SSH 到主机并打开 PTY，而不启动 ssh。
- `sshauth`：使用指定凭据 SSH 到指定主机。也可以通过 SSH 在远程主机上执行特定命令，或使用它通过 SCP 传输文件。
- `link_tcp`：通过 TCP 链接到另一个 agent，实现 agent 之间的直接通信。
- `link_webshell`：使用 webshell P2P profile 链接到 agent，以远程访问其 Web 界面。
- `rpfwd`：启动或停止 Reverse Port Forward，以便远程访问目标网络中的服务。
- `socks`：在目标网络上启动或停止 SOCKS5 proxy，以便通过受控主机隧道传输流量。兼容 proxychains 等工具。
- `portscan`：扫描主机上的开放端口，用于识别潜在的横向移动或进一步攻击目标。

### 进程执行

- `shell`：通过 /bin/sh 执行单条 shell 命令，从而直接在目标系统上执行命令。
- `run`：使用参数执行磁盘上的命令，以便在目标系统上运行二进制文件或脚本。
- `pty`：打开交互式 PTY，以便直接与目标系统上的 shell 交互。

## References

- [1] [Mythic 社区 Agent 功能矩阵](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 重点更新：Interactive Tasking、Push C2 和动态文件浏览器](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic 文档](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 更新](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [利用 Mythic 的隐藏功能变革红队行动：Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts：Multi_Trojan_Mythic YARA 规则](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [从 Fork 到 Framework：修改 Apollo 教会我们的 Agent Invasion](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
