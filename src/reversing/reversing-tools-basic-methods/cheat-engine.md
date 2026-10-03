# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，用于查找运行中游戏的重要数值在内存中的保存位置，并修改这些数值。\
下载并运行它后，你会看到一个关于如何使用该工具的**教程**。如果你想学习如何使用该工具，强烈建议完成该教程。

## 你在搜索什么？

![Cheat Engine - 你在搜索什么？：你在搜索什么？](<../../images/image (762).png>)

该工具非常适合查找程序的**某个数值**（通常是数字）**存储在内存中的位置**。\
**通常，数字**以 **4bytes** 形式存储，但你也可以在 **double** 或 **float** 格式中找到它们，或者你可能想查找某些**非数字内容**。因此，你需要确保**选择**要**搜索的内容**：

![Cheat Engine - 你在搜索什么？：通常，数字以 4bytes 形式存储，但你也可以在 double 或 float 格式中找到它们，或者你可能想查找某些内容……](<../../images/image (324).png>)

你还可以指定不同类型的**搜索**：

![Cheat Engine - 你在搜索什么？：你还可以指定不同类型的搜索](<../../images/image (311).png>)

你还可以勾选复选框，以便**在扫描内存时暂停游戏**：

![Cheat Engine - 你在搜索什么？：你还可以勾选复选框，以便在扫描内存时暂停游戏](<../../images/image (1052).png>)

### 热键

在 _**Edit --> Settings --> Hotkeys**_ 中，你可以为不同用途设置不同的**热键**，例如**暂停** **游戏**（如果你想在某个时候扫描内存，这会非常有用）。还有其他选项可用：

![你在搜索什么？- 热键：在 Edit -- Settings -- Hotkeys 中，你可以为不同用途设置不同的热键，例如暂停游戏（如果你想在某个时候……](<../../images/image (864).png>)

## 修改数值

当你**找到**正在**查找的数值**所在的位置后（后续步骤会对此进行更多介绍），你可以双击该数值，然后再次双击其值来**修改它**：

![热键 - 修改数值：当你找到正在查找的数值所在的位置后（后续步骤会对此进行更多介绍），你可以双击该数值，然后再次双击……](<../../images/image (563).png>)

最后**勾选复选框**，使修改写入内存：

![热键 - 修改数值：最后勾选复选框，使修改写入内存](<../../images/image (385).png>)

对**内存**的**更改**会立即**应用**（请注意，除非游戏再次使用该数值，否则该数值**不会在游戏中更新**）。

## 搜索数值

假设存在一个你想要提升的重要数值（例如用户的生命值），现在你要在内存中查找这个数值。

### 通过已知的变化

假设你要查找数值 100，你**执行扫描**来搜索该数值，并找到大量匹配项：

![搜索数值 - 通过已知的变化：假设你要查找数值 100，你执行扫描来搜索该数值，并找到大量匹配项](<../../images/image (108).png>)

然后，你进行某项操作，使**数值发生变化**，接着**暂停**游戏并**执行** **下一次扫描**：

![搜索数值 - 通过已知的变化：然后，你进行某项操作，使数值发生变化，接着暂停游戏并执行下一次扫描](<../../images/image (684).png>)

Cheat Engine 会搜索从 **100 变为新数值**的**数值**。恭喜，你已经**找到**了目标数值的**地址**，现在可以修改它了。\
_如果仍然存在多个数值，请再次进行操作以修改该数值，然后执行另一次“下一次扫描”来筛选地址。_

### 未知数值，已知变化

在这种情况下，你**不知道数值本身**，但知道**如何使它发生变化**（甚至知道变化量），因此可以查找该数值。

首先，执行一次类型为“**Unknown initial value**”的扫描：

![通过已知的变化 - 未知数值，已知变化：首先，执行一次类型为“Unknown initial value”的扫描](<../../images/image (890).png>)

然后，使数值发生变化，指明**数值**发生了**怎样的变化**（在本例中，数值减少了 1），并执行**下一次扫描**：

![通过已知的变化 - 未知数值，已知变化：然后，使数值发生变化，指明数值发生了怎样的变化（在本例中，数值减少了 1），并执行下一次扫描](<../../images/image (371).png>)

你将看到所有以所选方式发生变化的**数值**：

![通过已知的变化 - 未知数值，已知变化：你将看到所有以所选方式发生变化的数值](<../../images/image (569).png>)

找到目标数值后，就可以修改它。

请注意，存在**大量可能的变化**，你可以根据需要重复这些**步骤**，以筛选结果：

![通过已知的变化 - 未知数值，已知变化：请注意，存在大量可能的变化，你可以根据需要重复这些步骤，以筛选结果](<../../images/image (574).png>)

### 随机内存地址 - 查找代码

到目前为止，我们已经学会了如何查找存储某个数值的地址，但在**不同的游戏执行过程中，该地址很可能位于内存中的不同位置**。下面来了解如何始终找到该地址。

使用前面提到的一些技巧，找到当前游戏存储重要数值的地址。然后（如果愿意，可以先暂停游戏），右键单击找到的**地址**，并选择“**Find out what accesses this address**”或“**Find out what writes to this address**”：

![未知数值，已知变化 - 随机内存地址 - 查找代码：使用前面提到的一些技巧，找到当前游戏存储重要数值的地址。然后……](<../../images/image (1067).png>)

**第一个选项**用于了解**代码**的哪些**部分**正在**使用**该**地址**（这对于其他用途也很有帮助，例如**了解可以在哪里修改游戏代码**）。\
**第二个选项**更加**具体**，在本例中也更有帮助，因为我们想知道**该数值是从哪里写入的**。

选择其中一个选项后，**debugger** 会**附加**到程序，一个新的**空窗口**会出现。现在，**运行**游戏并**修改**该**数值**（不要重启游戏）。该**窗口**应当会填充正在**修改**该**数值**的**地址**：

![未知数值，已知变化 - 随机内存地址 - 查找代码：选择其中一个选项后，debugger 会附加到程序，一个新的空窗口会出现。现在……](<../../images/image (91).png>)

现在你已经找到了修改该数值的地址，可以按自己的需求**修改代码**（Cheat Engine 支持快速将其修改为 NOPs）：

![未知数值，已知变化 - 随机内存地址 - 查找代码：现在你已经找到了修改该数值的地址，可以按自己的需求修改代码（Cheat Engine……](<../../images/image (1057).png>)

这样，你就可以修改代码，使其不再影响该数值，或者始终以有利的方式影响它。

### 随机内存地址 - 查找指针

按照前面的步骤，找到目标数值所在的位置。然后使用“**Find out what writes to this address**”，找出哪个地址写入了该数值，并双击它以查看反汇编视图：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：按照前面的步骤，找到目标数值所在的位置。然后使用“Find out……](<../../images/image (1039).png>)

然后，执行新的扫描，**搜索位于“\[]”之间的十六进制数值**（本例中是 $edx 的值）：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：然后，执行新的扫描，搜索位于“\[]”之间的十六进制数值（本例中是 $edx 的值）](<../../images/image (994).png>)

（_如果出现多个结果，通常需要选择地址最小的那个_）\
现在，我们已经**找到将修改目标数值的指针**。

点击“**Add Address Manually**”：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：点击“Add Address Manually”](<../../images/image (990).png>)

现在，勾选“Pointer”复选框，并在文本框中添加找到的地址（在本例中，上一张图片中找到的地址是“Tutorial-i386.exe”+2426B0）：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：现在，勾选“Pointer”复选框，并在文本框中添加找到的地址（在本例中……](<../../images/image (392).png>)

（注意，第一个“Address”会根据你输入的指针地址自动填充）

点击 OK，将创建一个新的指针：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：点击 OK，将创建一个新的指针](<../../images/image (308).png>)

现在，每次修改该数值时，你修改的都是重要数值，即使该数值所在的内存地址发生了变化。

### Code Injection

Code injection 是一种将一段代码注入目标进程，然后重新引导代码执行流程，使其经过你编写的代码的技术（例如给你增加分数，而不是扣除分数）。

假设你找到了将玩家生命值减 1 的地址：

![随机内存地址 - 查找指针 - Code Injection：假设你找到了将玩家生命值减 1 的地址](<../../images/image (203).png>)

点击 Show disassembler 以查看**反汇编代码**。\
然后，点击 **CTRL+a** 调出 Auto assemble 窗口，并选择 _**Template --> Code Injection**_

![随机内存地址 - 查找指针 - Code Injection：然后，点击 CTRL+a 调出 Auto assemble 窗口，并选择 Template -- Code Injection](<../../images/image (902).png>)

填写要修改的指令的**地址**（通常会自动填充）：

![随机内存地址 - 查找指针 - Code Injection：填写要修改的指令的地址（通常会自动填充）](<../../images/image (744).png>)

随后会生成一个模板：

![随机内存地址 - 查找指针 - Code Injection：随后会生成一个模板](<../../images/image (944).png>)

在“**newmem**”部分插入新的 assembly 代码；如果不希望原始代码执行，则从“**originalcode**”中删除原始代码**。**在本例中，注入的代码会增加 2 分，而不是减少 1 分：

![随机内存地址 - 查找指针 - Code Injection：在“newmem”部分插入新的 assembly 代码；如果不希望原始代码执行，则从“originalcode”中删除原始代码……](<../../images/image (521).png>)

**点击 execute 等按钮，你的代码就会被注入程序，从而改变该功能的行为！**

## 使用 AOB signatures 的 Relocation-safe code injection

一个 hook `game.exe+123456` 的脚本可能会在 ASLR 或软件更新后失效。**Array of Bytes (AOB) signature** 会根据指令周围的 machine code 查找该指令。使用 `aobscanmodule` 将搜索范围限制在一个模块内。使 signature 足够长，以确保只返回一个匹配项。对 relocation bytes、地址以及其他可能发生变化的 bytes 使用 wildcard。不要对需要恢复的整个指令使用 wildcard。<sup>[[4]](#references)</sup>

在 Memory View 中选择该指令，然后使用 **Tools → Auto Assemble → Template → AOB Injection**。生成的 `[DISABLE]` 块非常重要，必须恢复所有被覆盖的 bytes，并释放分配的内存。<sup>[[4]](#references)</sup>

<details>
<summary>最小 x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

启用脚本前，请确认以下几点：

1. AOB 返回**一个**地址。如果返回多个地址，请在两侧添加稳定的指令。
2. 跳转会替换完整的指令。绝不要拆分指令。
3. 分配的 cave 可通过生成的跳转到达。在 x64 上，远距离分配可能需要 14 字节的跳转。
4. 注入的代码保留原函数所需的寄存器、标志位和栈对齐。
5. disable block 恢复准确的原始字节。保存 table 前，多次测试启用和禁用。

## 可靠的指针工作流

一次运行中找到的指针只能算候选项。在多次全新执行中构建 pointer maps，并针对所有执行结果重新扫描。每次捕获之间都重启 target，使 ASLR 和 heap 分配发生变化。优先选择基址为 module 或其他稳定 symbol 的路径。拒绝只适用于某个存档、关卡或对象实例的路径。

**pointer must end with specific offsets** filter 及其 deviation 选项，可以在构建版本之间附近字段发生移动时保留有用路径。7.5 release 也加入了此 deviation 控制。它只是 filter，不能证明 pointer chain 是稳定的。<sup>[[1]](#references)</sup>

当某个 structure 移动过于频繁而不适合进行 pointer scanning 时，可以 hook 访问它的指令。将 live object pointer 从寄存器捕获到一个 allocated symbol 中。对于 entity lists 和 managed objects，这通常更加可靠。

## 跟踪代码而不是扫描值

当值被直接修改时，使用 **Find out what writes to this address**。当你需要找到所属 object，或写入通过 copied data 发生时，使用 **Find out what accesses this address**。在 target 中只触发一个操作。然后比较命中次数和寄存器状态。

**Ultimap 2** 在受支持的 Intel CPU 上使用 Intel Processor Trace。与逐条指令进行单步执行相比，它可以用更少的中断记录已执行的 control flow。筛选 interesting action 发生期间执行过的代码，并移除 idle capture 期间也执行过的代码。Intel PT 不是 stealth 功能。target 仍然可以检测到 tracing、timing changes 或 Cheat Engine 本身。<sup>[[1]](#references)</sup>

Cheat Engine 7.5 还加入了由 Windows 提供的 Intel PT interface。旧版基于 DBVM 的 Ultimap mode 与 Intel PT mode 具有不同的 hardware 和 OS 要求。不要假设支持 DBVM 的 CPU 也支持 Intel PT。<sup>[[1]](#references)</sup>

## Debugger 和 breakpoint 选择

选择能够正常工作的侵入性最低的 debugger：

- **Windows debugger** 很简单，但会创建普通的 debug events。Anti-debugging 检查可以检测到它。
- **VEH debugger** 通过 vectored exception handler 处理 breakpoints。它可以规避一些基本的 debugger 检查，但并非不可见。
- **Hardware breakpoints** 不会修改 instruction bytes，但 x86/x64 只提供少量 debug-register slots。
- **Software breakpoints** 会将一个字节替换为 `INT3`。它们很容易被检测到，也可能与 integrity checks 冲突。
- **DBVM debugger** 将部分操作移至 guest OS 之下。它拥有更高的权限，配置错误时可能导致 host 崩溃。

当没有足够空间容纳普通 relative jump 时，Cheat Engine 7.5 可以使用基于 exception handler 和 `INT3` 的单字节跳转。将其视为 software breakpoint。验证 exception flow，不要假设它可以绕过 anti-tamper checks。<sup>[[1]](#references)</sup>

DBVM 是 hypervisor，而不是通用的 invisibility switch。仅在 disposable lab 中使用它。不要将其 control interface 暴露给不受信任的代码。Kernel anti-cheat 和 endpoint products 仍然可能检测到 driver、hypervisor state 或被修改的 memory。

## Managed runtimes 和近期的 7.6/7.7 features

对于 Mono、IL2CPP、.NET 和 Java targets，在可用时优先使用 runtime metadata，而不是盲目扫描。打开 **Mono → Activate mono features** 或对应的 runtime information window。首先定位 class、field 或 method。然后在 managed method 被 JIT-compiled 后，使用 native disassembly。

7.6 line 加入了仅针对 executable memory 的 `AOBSCANEX`、`gdbserver` debugger interface、Java metadata inspection、更快的 IL2CPP enumeration，以及一种忽略 ARM memory tagging 所使用的 upper pointer byte 的 pointer-scan 选项。7.7 line 加入了 native Linux builds、`HOOK`/`UNHOOK`、`aobscanfunction`、更好的 generic Mono method lookup、改进的 PDB structure support，以及基本的 Unreal Engine structure dissection。<sup>[[3]](#references)</sup>

这些 additions 支持以下实用工作流：

1. 从 metadata 中解析 managed method 或 static field。
2. 跟踪或反汇编该 method 生成的 native code。
3. 使用 `AOBSCANEX` 或 `aobscanfunction` 定位稳定的 executable signature。
4. 生成可逆的 hook。保留 original instructions，并验证 disable path。
5. 每次 target 更新后重新检查 signature。成功匹配并不保证周围 logic 仍具有相同含义。

## 使用 `ceserver` 的 remote targets

`ceserver` 向 Cheat Engine GUI 提供 process enumeration、memory access 和 debugging。官方 builds 支持 Linux 和 Android。在 target 上运行匹配的 architecture，并通过 **Network** tab 进行连接。在 Android 上，转发 default port 可以避免将其暴露在 network 上：<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
第三方 `frida-ceserver` bridge 可为 iOS targets 提供与 Cheat Engine 兼容的 interface。它不是官方的 `ceserver`，其支持的 operations 可能有所不同。<sup>[[2]](#references)</sup>

假设该 protocol 授予 debugger-level access。将其绑定到 loopback，或将其置于 SSH/ADB tunnel 后。绝不要将 TCP 52736 暴露到不受信任的网络。session 结束后停止 server。

## Operational safety

只能连接到你拥有或获授权测试的软件。不要在 online game 或 production endpoint 旁运行 Cheat Engine。Memory writes、injected code、drivers 和 DBVM 可能导致 target 崩溃或损坏。<sup>[[3]](#references)</sup>

请从 official site 下载 builds，或编译已发布的 source。Security products 经常将 memory editors、debuggers 及其 drivers 归类为 hack tools。不要全局禁用 host protection。请使用专用 VM 或 lab host，并在运行前验证 artifact。<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5 发行说明](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [用于 remote targets 的 frida-ceserver bridge](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine 官方发行新闻](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki：Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
