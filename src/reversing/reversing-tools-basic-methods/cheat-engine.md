# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个实用的程序，用于查找运行中游戏的内存中保存重要值的位置，并对其进行修改。\
当你下载并运行它时，程序会向你展示一个关于如何使用该工具的**教程**。如果你想学习如何使用该工具，强烈建议完成该教程。<sup>[[3]](#references)</sup>

## 你在搜索什么？

![Cheat Engine - 你在搜索什么？：你在搜索什么？](<../../images/image (762).png>)

该工具对于查找程序内存中**某个值**（通常是数字）**存储的位置**非常有用。\
**通常，数字**以 **4bytes** 形式存储，但你也可以在 **double** 或 **float** 格式中找到它们，或者你可能想查找**非数字**的内容。因此，你需要确认自己**选择**了要**搜索的内容**：

![Cheat Engine - 你在搜索什么？：通常数字以 4bytes 形式存储，但你也可以在 double 或 float 格式中找到它们，或者你可能想查找某些内容……](<../../images/image (324).png>)

你还可以指定不同类型的**搜索**：

![Cheat Engine - 你在搜索什么？：你还可以指定不同类型的搜索](<../../images/image (311).png>)

你还可以勾选复选框，以便**在扫描内存时暂停游戏**：

![Cheat Engine - 你在搜索什么？：你还可以勾选复选框，以便在扫描内存时暂停游戏](<../../images/image (1052).png>)

### Hotkeys

在 _**Edit --> Settings --> Hotkeys**_ 中，你可以为不同用途设置不同的 **hotkeys**，例如**暂停** **游戏**（如果你想在某个时刻扫描内存，这会非常有用）。还有其他可用选项：

![你在搜索什么？ - Hotkeys：在 Edit -- Settings -- Hotkeys 中，你可以为不同用途设置不同的 hotkeys，例如暂停游戏（如果你想在某个时刻……](<../../images/image (864).png>)

## 修改值

当你**找到**了所需的**值**所在的位置后（后续步骤会对此进行更多介绍），你可以双击该值所在的项目，然后再次双击它的值来**修改它**：

![Hotkeys - 修改值：当你找到所需的值所在的位置后（后续步骤会对此进行更多介绍），你可以双击该项目，然后再次双击……](<../../images/image (563).png>)

最后，**勾选复选框**，即可将修改写入内存：

![Hotkeys - 修改值：最后，勾选复选框，即可将修改写入内存](<../../images/image (385).png>)

对**内存**的**修改**会立即**应用**（注意，在游戏再次使用该值之前，游戏中的值**不会更新**）。

## 搜索值

假设存在一个你想要修改的重要值（例如角色的生命值），现在你要在内存中查找这个值。

### 通过已知的变化

假设你要查找值 100，先**执行扫描**来搜索该值，随后会找到大量匹配项：

![搜索值 - 通过已知的变化：假设你要查找值 100，先执行扫描来搜索该值，随后会找到大量匹配项](<../../images/image (108).png>)

然后，执行某些操作使**值发生变化**，接着**暂停**游戏并**执行**一次**下一次扫描**：

![搜索值 - 通过已知的变化：然后，执行某些操作使值发生变化，接着暂停游戏并执行下一次扫描](<../../images/image (684).png>)

Cheat Engine 会搜索从 100 **变为新值的值**。恭喜，你已经**找到**了所需值的**地址**，现在可以修改它了。\
_如果仍然有多个值，可以再次执行某个操作来修改该值，然后再次执行“next scan”以筛选地址。_

### 未知值，已知变化

在这种情况下，你**不知道该值是多少**，但知道**如何使它发生变化**（甚至知道变化的数值），此时仍然可以查找它。

首先，执行一次类型为“**Unknown initial value**”的扫描：

![通过已知的变化 - 未知值，已知变化：首先，执行一次类型为“Unknown initial value”的扫描](<../../images/image (890).png>)

然后使该值发生变化，指定该**值**发生了**怎样的变化**（在本例中，该值减少了 1），并执行一次**下一次扫描**：

![通过已知的变化 - 未知值，已知变化：然后使该值发生变化，指定该值发生了怎样的变化（在本例中，该值减少了 1），并执行下一次扫描](<../../images/image (371).png>)

此时会显示**所有按照所选方式发生变化的值**：

![通过已知的变化 - 未知值，已知变化：此时会显示所有按照所选方式发生变化的值](<../../images/image (569).png>)

找到目标值后，就可以修改它。

注意，可选的**变化类型很多**，你可以根据需要重复这些**步骤**，以筛选结果：

![通过已知的变化 - 未知值，已知变化：注意，可选的变化类型很多，你可以根据需要重复这些步骤，以筛选结果](<../../images/image (574).png>)

### 随机内存地址 - 查找代码

到目前为止，我们已经学会了如何查找保存某个值的地址，但很可能在**不同次的游戏运行中，该地址位于内存中的不同位置**。下面来了解如何始终找到该地址。

使用前面提到的一些技巧，找到当前游戏保存重要值的地址。然后（如果愿意，也可以先暂停游戏），在找到的**地址**上单击**右键**，选择“**Find out what accesses this address**”或“**Find out what writes to this address**”：

![未知值，已知变化 - 随机内存地址 - 查找代码：使用前面提到的一些技巧，找到当前游戏保存重要值的地址。然后……](<../../images/image (1067).png>)

**第一个选项**用于了解**代码**中的哪些**部分**正在**使用**该**地址**（这对于其他用途也很有帮助，例如**了解可以在哪里修改游戏代码**）。\
**第二个选项**更加**具体**，在本例中也更有用，因为我们想知道**该值是从哪里写入的**。

选择其中一个选项后，**debugger** 会**附加**到程序，并出现一个新的**空窗口**。现在，**运行**游戏并**修改**该**值**（不要重启游戏）。该**窗口**中应该会填充正在**修改**该**值的**地址**：

![未知值，已知变化 - 随机内存地址 - 查找代码：选择其中一个选项后，debugger 会附加到程序，并出现一个新的空窗口……](<../../images/image (91).png>)

现在你已经找到了修改该值的地址，可以**随意修改代码**了（Cheat Engine 支持快速将其修改为 NOPs）：

![未知值，已知变化 - 随机内存地址 - 查找代码：现在你已经找到了修改该值的地址，可以随意修改代码（Cheat Engine……](<../../images/image (1057).png>)

因此，你可以修改它，使代码不再影响该数值，或者始终以有利的方式影响它。

### 随机内存地址 - 查找指针

按照前面的步骤，找到目标值所在的位置。然后使用“**Find out what writes to this address**”查找向该值写入的地址，并双击该地址以打开反汇编视图：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：按照前面的步骤，找到目标值所在的位置。然后使用“Find out……](<../../images/image (1039).png>)

然后执行一次新扫描，**搜索“\[]”之间的十六进制值**（本例中是 $edx 的值）：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：然后执行一次新扫描，搜索“()”之间的十六进制值（本例中是 $edx 的值）](<../../images/image (994).png>)

(_如果出现多个结果，通常需要选择地址最小的那个_)\
现在，我们已经**找到将要修改目标值的指针**。

点击“**Add Address Manually**”：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：点击“Add Address Manually”](<../../images/image (990).png>)

现在，点击“Pointer”复选框，并在文本框中添加找到的地址（在本例中，上一张图片中找到的地址是“Tutorial-i386.exe”+2426B0）：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：现在，点击“Pointer”复选框，并在文本框中添加找到的地址（在本例中……](<../../images/image (392).png>)

（注意，第一个“Address”会根据你输入的指针地址自动填充）

点击 OK，即可创建一个新的指针：

![随机内存地址 - 查找代码 - 随机内存地址 - 查找指针：点击 OK，即可创建一个新的指针](<../../images/image (308).png>)

现在，每次修改该值时，你都在**修改重要值，即使保存该值的内存地址发生了变化**。

### Code Injection

Code injection 是一种将一段代码注入目标进程，然后重新导向代码执行路径，使其经过你编写的代码的技术（例如给你增加分数而不是扣除分数）。

假设你已经找到将玩家生命值减 1 的地址：

![随机内存地址 - 查找指针 - Code Injection：假设你已经找到将玩家生命值减 1 的地址](<../../images/image (203).png>)

点击 Show disassembler 以查看**反汇编代码**。\
然后点击 **CTRL+a** 调出 Auto assemble 窗口，并选择 _**Template --> Code Injection**_

![随机内存地址 - 查找指针 - Code Injection：然后点击 CTRL+a 调出 Auto assemble 窗口，并选择 Template -- Code Injection](<../../images/image (902).png>)

填写你要修改的指令的**地址**（通常会自动填充）：

![随机内存地址 - 查找指针 - Code Injection：填写你要修改的指令的地址（通常会自动填充）](<../../images/image (744).png>)

此时会生成一个模板：

![随机内存地址 - 查找指针 - Code Injection：此时会生成一个模板](<../../images/image (944).png>)

接下来，将新的 assembly code 插入“**newmem**”部分；如果不希望原始代码执行，则从“**originalcode**”部分删除原始代码**。**在本例中，注入的代码会增加 2 分，而不是减少 1 分：

![随机内存地址 - 查找指针 - Code Injection：接下来，将新的 assembly code 插入“newmem”部分；如果不希望原始代码执行，则从“originalcode”部分删除原始代码……](<../../images/image (521).png>)

**点击 execute 等按钮，你的代码就会被注入程序，从而改变该功能的行为！**

## Cheat Engine 7.x 中的高级功能（2023-2025）

自 7.0 版本以来，Cheat Engine 持续发展，并新增了多项质量改进和 *offensive-reversing* 功能。这些功能在分析现代软件（不仅是游戏）时非常实用。下面是一份**高度精简的实战指南**，介绍你在 red-team/CTF 工作中最可能使用的新增功能。<sup>[[1]](#references)</sup>

### Pointer Scanner 2 改进
* `Pointers must end with specific offsets` 以及新的 **Deviation** 滑块（≥7.4）可以在更新后重新扫描时大幅减少误报。将其与多映射比较（`.PTR` → *Compare results with other saved pointer map*）结合使用，可以在几分钟内获得一个**稳定的基础指针**。
* 批量筛选快捷方式：首次扫描后按下 `Ctrl+A → Space` 全选，然后按 `Ctrl+I`（反选），取消选择重新扫描失败的地址。

### Ultimap 3 – Intel PT tracing
*从 7.5 版本开始，旧版 Ultimap 基于 **Intel Processor-Trace (IPT)** 重新实现。*这意味着现在可以记录目标执行的**每一条分支**，而无需单步执行（仅支持 user-mode，不会触发大多数 anti-debug gadgets）。
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
几秒后停止捕获，并**右键单击 → Save execution list to file**。将分支地址与 `Find out what addresses this instruction accesses` 会话结合使用，即可极快地定位高频游戏逻辑热点。

### 1-byte `jmp` / auto-patch 模板
7.5 版本引入了一个 *one-byte* JMP stub（0xEB），它会安装一个 SEH handler，并在原始位置放置 INT3。当你对无法使用 5-byte relative jump 进行 patch 的指令使用 **Auto Assembler → Template → Code Injection** 时，系统会自动生成该 stub。这使得在 packed 或受大小限制的 routine 内部执行“紧凑型”hook 成为可能。

### 使用 DBVM 实现 Kernel-level stealth（AMD & Intel）
*DBVM* 是 CE 内置的 Type-2 hypervisor。近期版本终于加入了 **AMD-V/SVM support**，因此你可以在 Ryzen/EPYC 主机上运行 `Driver → Load DBVM`。DBVM 允许你：

1. 创建对 Ring-3/anti-debug 检查不可见的 hardware breakpoints。
2. 读取/写入 pageable 或受保护的 kernel memory 区域，即使 user-mode driver 已被禁用也可以。
3. 执行无需 VM-EXIT 的 timing-attack bypass（例如从 hypervisor 查询 `rdtsc`）。

**提示：**当 Windows 11 启用了 HVCI/Memory-Integrity 时，DBVM 将拒绝加载 → 将其关闭，或启动专用的 VM-host。

### 使用 **ceserver** 进行 Remote / cross-platform debugging
CE 现在随附了完全重写的 *ceserver*，可以通过 TCP 连接到 **Linux、Android、macOS 和 iOS** targets。一个热门 fork 集成了 *Frida*，可将 dynamic instrumentation 与 CE 的 GUI 结合使用——当你需要 patch 运行在手机上的 Unity 或 Unreal games 时非常理想：
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
对于 Frida bridge，请参阅 GitHub 上的 `bb33bb/frida-ceserver`。<sup>[[2]](#references)</sup>

### 其他值得注意的功能
* **Patch Scanner**（MemView → Tools）——检测可执行区段中的意外代码更改；便于 malware analysis。
* **Structure Dissector 2**——将地址拖入窗口 → 按 `Ctrl+D`，然后选择 *Guess fields*，即可自动评估 C-structures。
* **.NET & Mono Dissector**——改进 Unity 游戏支持；可直接从 CE Lua console 调用方法。
* **Big-Endian custom types**——扫描/编辑反转字节顺序（适用于 console emulators 和 network packet buffers）。
* AutoAssembler/Lua 窗口支持 **Autosave & tabs**，并提供用于重写多行指令的 `reassemble()`。

### Installation & OPSEC notes（2024-2025）
* 官方安装程序捆绑了 InnoSetup **ad-offers**（`RAV` 等）。为避免 PUPs，**始终点击 *Decline***，*或从源代码编译*。AVs 仍会将 `cheatengine.exe` 标记为 *HackTool*，这是预期行为。
* 现代 anti-cheat drivers（EAC/Battleye、ACE-BASE.sys、mhyprot2.sys）甚至会在重命名后检测 CE 的 window class。请将用于 reversing 的副本运行在 **disposable VM** 中，或先禁用 network play。
* 如果只需要 user-mode access，请选择 **`Settings → Extra → Kernel mode debug = off`**，以避免加载 CE 的 unsigned driver；该驱动可能会在 Windows 11 24H2 Secure-Boot 下导致 BSOD。

---

## References

- [1] [Cheat Engine 7.5 release notes（GitHub）](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine tutorial，完成该教程以了解如何开始使用 Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
