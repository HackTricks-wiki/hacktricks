# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用程序，用于查找重要数值在运行中游戏内存中的保存位置，并对其进行修改。\
下载并运行后，程序会向你展示一个关于如何使用该工具的**教程**。如果你想学习如何使用该工具，强烈建议完成该教程。

## 你在搜索什么？

![Cheat Engine - 你在搜索什么？：你在搜索什么？](<../../images/image (762).png>)

该工具非常适合查找程序的**某个数值**（通常是数字）**存储在内存中的位置**。\
**数字通常**以 **4bytes** 形式存储，但你也可能在 **double** 或 **float** 格式中找到它们，或者你可能想查找**非数字的内容**。因此，你需要确认自己**选择**了想要**搜索的内容**：

![Cheat Engine - 你在搜索什么？：数字通常以 4bytes 形式存储，但你也可能在 double 或 float 格式中找到它们，或者你可能想查找某些内容……](<../../images/image (324).png>)

你还可以指定**不同类型**的**搜索**：

![Cheat Engine - 你在搜索什么？：你还可以指定不同类型的搜索](<../../images/image (311).png>)

你还可以勾选复选框，以便**在扫描内存时暂停游戏**：

![Cheat Engine - 你在搜索什么？：你还可以勾选复选框，以便在扫描内存时暂停游戏](<../../images/image (1052).png>)

### 热键

在 _**Edit --> Settings --> Hotkeys**_ 中，你可以为不同用途设置不同的**热键**，例如**暂停****游戏**（如果你想在某个时刻扫描内存，这会非常有用）。还有其他可用选项：

![你在搜索什么？ - 热键：在 Edit -- Settings -- Hotkeys 中，你可以为不同用途设置不同的热键，例如暂停游戏（如果你想在某个时刻……](<../../images/image (864).png>)

## 修改数值

**找到**你**要查找的数值**所在位置后（后续步骤将对此进行更多说明），你可以通过双击该数值，然后再次双击其值来**修改它**：

![热键 - 修改数值：找到你要查找的数值所在位置后（后续步骤将对此进行更多说明），你可以通过双击该数值，然后再次双击……](<../../images/image (563).png>)

最后，**勾选复选框**，使修改写入内存：

![热键 - 修改数值：最后，勾选复选框，使修改写入内存](<../../images/image (385).png>)

对**内存**的**更改**会立即**应用**（注意，在游戏再次使用该数值之前，该数值**不会在游戏中更新**）。

## 搜索数值

假设存在一个重要数值（例如用户的生命值），你想要提高它，并且正在内存中查找该数值。

### 通过已知变化

假设你要查找数值 100，你**执行扫描**来搜索该数值，并发现大量匹配项：

![搜索数值 - 通过已知变化：假设你要查找数值 100，你执行扫描来搜索该数值，并发现大量匹配项](<../../images/image (108).png>)

然后，你进行某个操作，使**数值发生变化**，接着**暂停**游戏并**执行**一次**下一次扫描**：

![搜索数值 - 通过已知变化：然后，你进行某个操作，使数值发生变化，接着暂停游戏并执行一次下一次扫描](<../../images/image (684).png>)

Cheat Engine 会搜索从 **100 变为新数值**的**数值**。恭喜，你已经**找到**了目标数值的**地址**，现在可以修改它了。\
_如果仍然存在多个数值，请再次进行操作来修改该数值，然后执行另一次“下一次扫描”，以过滤地址。_

### 未知数值，已知变化

在这种情况下，你**不知道数值本身**，但知道**如何使它发生变化**（甚至知道变化量），此时可以查找该数值。

首先，执行一次类型为“**Unknown initial value**”的扫描：

![通过已知变化 - 未知数值，已知变化：首先，执行一次类型为“Unknown initial value”的扫描](<../../images/image (890).png>)

然后，使数值发生变化，指定该**数值**是**如何变化**的（在我的示例中，它减少了 1），并执行一次**下一次扫描**：

![通过已知变化 - 未知数值，已知变化：然后，使数值发生变化，指定数值是如何变化的（在我的示例中，它减少了 1），并执行一次下一次扫描](<../../images/image (371).png>)

此时会显示所有以指定方式发生变化的**数值**：

![通过已知变化 - 未知数值，已知变化：此时会显示所有以指定方式发生变化的数值](<../../images/image (569).png>)

找到目标数值后，就可以修改它。

注意，可能的变化**非常多**，你可以根据需要重复这些**步骤**，以过滤结果：

![通过已知变化 - 未知数值，已知变化：注意，可能的变化非常多，你可以根据需要重复这些步骤，以过滤结果](<../../images/image (574).png>)

### 随机内存地址 - 查找代码

到目前为止，我们已经学会了如何查找存储某个数值的地址，但在**不同次游戏运行中，该地址很可能位于内存中的不同位置**。因此，下面来了解如何始终找到该地址。

使用前面提到的一些技巧，找到当前游戏存储重要数值的地址。然后（如果需要，可以先暂停游戏），右键单击找到的**地址**，并选择“**Find out what accesses this address**”或“**Find out what writes to this address**”：

![未知数值，已知变化 - 随机内存地址 - 查找代码：使用前面提到的一些技巧，找到当前游戏存储重要数值的地址。然后……](<../../images/image (1067).png>)

**第一个选项**用于了解**代码**的哪些**部分**正在**使用**该**地址**（这对许多其他用途也很有帮助，例如**了解可以在哪里修改游戏代码**）。\
**第二个选项**更加**具体**，在本例中也更有用，因为我们想知道**该数值是从哪里写入的**。

选择其中一个选项后，**debugger** 会**附加**到程序，并出现一个新的**空窗口**。现在，**运行**游戏并**修改**该**数值**（不要重启游戏）。该**窗口**中应会填充正在**修改**该**数值**的**地址**：

![未知数值，已知变化 - 随机内存地址 - 查找代码：选择其中一个选项后，debugger 会附加到程序，并出现一个新的空窗口……](<../../images/image (91).png>)

现在你已经找到了修改该数值的地址，可以**随意修改代码**（Cheat Engine 支持快速将其修改为 NOPs）：

![未知数值，已知变化 - 随机内存地址 - 查找代码：现在你已经找到了修改该数值的地址，可以随意修改代码（Cheat Engine……](<../../images/image (1057).png>)

这样，你就可以修改代码，使其不再影响该数值，或者始终以有利的方式影响该数值。

### 随机内存地址 - 查找指针

按照前面的步骤，找到目标数值所在的位置。然后，使用“**Find out what writes to this address**”找出哪个地址写入了该数值，并双击它以查看反汇编视图：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：按照前面的步骤，找到目标数值所在的位置。然后，使用“Find out……](<../../images/image (1039).png>)

接着，执行一次新扫描，**搜索“\[]”中的十六进制数值**（本例中为 $edx 的值）：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：接着，执行一次新扫描，搜索“()”中的十六进制数值（本例中为 $edx 的值）](<../../images/image (994).png>)

_（如果出现多个结果，通常需要选择地址最小的那个。）_\
现在，我们已经**找到了将修改目标数值的指针**。

点击“**Add Address Manually**”：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：点击“Add Address Manually”](<../../images/image (990).png>)

现在，勾选“Pointer”复选框，并在文本框中添加找到的地址（在本例中，上一张图中找到的地址为“Tutorial-i386.exe”+2426B0）：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：现在，勾选“Pointer”复选框，并在文本框中添加找到的地址（在本例中……](<../../images/image (392).png>)

（注意，第一个“Address”会根据你输入的指针地址自动填充。）

点击 OK，即可创建一个新指针：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：点击 OK，即可创建一个新指针](<../../images/image (308).png>)

现在，无论何时修改该数值，你都在**修改重要数值，即使该数值所在的内存地址发生了变化**。

### Code Injection

Code injection 是一种将一段代码注入目标进程，然后重新路由代码执行流程，使其经过你编写的代码的技术（例如给你增加分数，而不是扣除分数）。

假设你找到了将玩家生命值减 1 的地址：

![随机内存地址 - 查找指针 - Code Injection：假设你找到了将玩家生命值减 1 的地址](<../../images/image (203).png>)

点击 Show disassembler 以查看**反汇编代码**。\
然后，点击 **CTRL+a** 调出 Auto assemble 窗口，并选择 _**Template --> Code Injection**_

![随机内存地址 - 查找指针 - Code Injection：然后，点击 CTRL+a 调出 Auto assemble 窗口，并选择 Template -- Code Injection](<../../images/image (902).png>)

填写你想要修改的指令的**地址**（通常会自动填充）：

![随机内存地址 - 查找指针 - Code Injection：填写你想要修改的指令的地址（通常会自动填充）](<../../images/image (744).png>)

此时会生成一个模板：

![随机内存地址 - 查找指针 - Code Injection：此时会生成一个模板](<../../images/image (944).png>)

在“**newmem**”部分插入新的 assembly 代码；如果不希望原始代码执行，则从“**originalcode**”部分删除原始代码**。**在本例中，注入的代码会增加 2 分，而不是减少 1 分：

![随机内存地址 - 查找指针 - Code Injection：在“newmem”部分插入新的 assembly 代码；如果不希望原始代码执行，则从“originalcode”部分删除原始代码……](<../../images/image (521).png>)

**点击 execute 等按钮，你的代码就会被注入程序，从而改变该功能的行为！**

## Cheat Engine 7.x 中的高级功能（2023-2025）

自 7.0 版本以来，Cheat Engine 持续发展，并加入了多项质量改进和 *offensive-reversing* 功能，在分析现代软件（而不仅是游戏）时非常实用。下面是一份**高度浓缩的实战指南**，介绍你在 red-team/CTF 工作中最可能使用的新增功能。<sup>[[1]](#references)</sup>

### Pointer Scanner 2 改进
* `Pointers must end with specific offsets` 以及新增的 **Deviation** 滑块（≥7.4）可以在更新后重新扫描时大幅减少误报。将其与多映射比较功能（`.PTR` → *Compare results with other saved pointer map*）结合使用，只需几分钟即可获得一个**可靠的单一基础指针**。
* 批量过滤快捷操作：第一次扫描后按 `Ctrl+A → Space` 全选，然后按 `Ctrl+I`（反选），取消选择重新扫描失败的地址。

### Ultimap 3 – Intel PT tracing
*从 7.5 版本开始，旧版 Ultimap 基于 **Intel Processor-Trace (IPT)** 重新实现。这意味着现在可以记录目标执行的**每一个分支**，而无需 single-stepping（仅限 user-mode，不会触发大多数 anti-debug gadget）。
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
几秒后停止 capture，然后 **right-click → Save execution list to file**。将分支地址与 `Find out what addresses this instruction accesses` session 结合起来，可以极快地定位高频 game-logic hotspots。

### 1-byte `jmp` / auto-patch templates
7.5 版本引入了一个 *one-byte* JMP stub（0xEB），它会安装一个 SEH handler，并在原始位置放置 INT3。当你对无法使用 5-byte relative jump 进行 patch 的指令使用 **Auto Assembler → Template → Code Injection** 时，该 stub 会自动生成。这使得在 packed 或受 size 限制的 routine 内执行“tight” hooks 成为可能。<sup>[[1]](#references)</sup>

### 使用 DBVM 实现 kernel-level stealth（AMD & Intel）
*DBVM* 是 CE 内置的 Type-2 hypervisor。最近的 build 终于加入了 **AMD-V/SVM support**，因此你可以在 Ryzen/EPYC hosts 上运行 `Driver → Load DBVM`。DBVM 允许你：

1. 创建对 Ring-3/anti-debug checks 不可见的 hardware breakpoints。
2. 即使 user-mode driver 被禁用，也能读取/写入 pageable 或受保护的 kernel memory regions。
3. 执行无需 VM-EXIT 的 timing-attack bypasses（例如从 hypervisor 查询 `rdtsc`）。

**Tip：**当 Windows 11 启用了 HVCI/Memory-Integrity 时，DBVM 将拒绝加载 → 关闭该功能，或启动一个专用的 VM-host。

### 使用 **ceserver** 进行 Remote / cross-platform debugging
CE 现在附带了完全重写的 *ceserver*，可以通过 TCP attach 到 **Linux、Android、macOS & iOS** targets。一个常用 fork 集成了 *Frida*，可将 dynamic instrumentation 与 CE 的 GUI 结合起来——当你需要 patch 在手机上运行的 Unity 或 Unreal games 时非常理想：
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
For the Frida bridge see `bb33bb/frida-ceserver` on GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### 其他值得关注的功能
* **Patch Scanner**（MemView → Tools）– 检测可执行 sections 中的异常代码更改；对 malware analysis 很有帮助。
* **Structure Dissector 2** – 将地址拖入工具后按 `Ctrl+D`，然后选择 *Guess fields*，即可自动评估 C-structures。
* **.NET & Mono Dissector** – 改进了对 Unity game 的支持；可直接从 CE Lua console 调用 methods。
* **Big-Endian custom types** – 扫描或编辑时反转 byte order（适用于 console emulators 和 network packet buffers）。
* AutoAssembler/Lua windows 的 **Autosave & tabs**，以及用于多行 instruction rewrite 的 `reassemble()`。<sup>[[1]](#references)</sup>

### Installation & OPSEC 注意事项（2024-2025）
* 官方 installer 包含 InnoSetup **ad-offers**（`RAV` 等）。**始终点击 *Decline*** *或从 source 编译*，以避免 PUPs。AVs 仍可能将 `cheatengine.exe` 标记为 *HackTool*，这是正常现象。
* Modern anti-cheat drivers（EAC/Battleye、ACE-BASE.sys、mhyprot2.sys）即使在重命名后也能检测到 CE 的 window class。请将 reversing copy **运行在 disposable VM 中**，或先禁用 network play。
* 如果只需要 user-mode access，请选择 **`Settings → Extra → Kernel mode debug = off`**，以避免加载 CE 的 unsigned driver；该 driver 可能在 Windows 11 24H2 Secure-Boot 上导致 BSOD。

---

## References

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
