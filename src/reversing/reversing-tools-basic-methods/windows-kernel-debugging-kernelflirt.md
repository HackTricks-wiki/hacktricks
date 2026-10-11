# 使用 KernelFlirt 调试 Windows 内核

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt 是一款用于受控逆向工程实验室的 Windows x64 调试器。主机端的 WPF UI 或 `KfConsole.exe` 会向测试签名的 Windows VM 中的 `KfRelay.exe` 发送命令。Relay 会将这些命令转换为发往 `KernelFlirt.sys` 的 `DeviceIoControl` 请求；该驱动提供内存、寄存器、断点、执行控制和内核模块操作。驱动还会通过 `KdpStub`/`KdTrap` inline hook 修改内核调试路径，因此只能在一次性 VM 中使用。<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Relay 是一个特权调试边界，而不是普通的远程服务。请将 TCP `31337` 保持在隔离的仅主机网络中，绝不要将测试签名的驱动或 relay 暴露到不可信网络。<sup>[[1]](#references)</sup>

相关 Windows exploitation 技术：

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## 实验环境搭建与首次暂停

构建需要 Windows 10/11 x64、带 C++ 的 Visual Studio 2022、WDK 10.0.26100.0 或更高版本，以及 .NET 9。在 VM 内加载驱动和 relay，然后从主机连接。UI 可以打开远程 EXE 或 SYS，而 **Kernel Modules** 视图可以在已加载的驱动中设置断点。<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

实验结束后，使用 `KfLoader.exe unload`。控制台支持未连接的 REPL、直接访问本地设备和中继访问；只有中继模式实现了下文所述的确定性 `open` 工作流。<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

最简控制台工作流程如下：<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

地址是表达式。裸数字按十六进制处理，表达式可以使用寄存器、算术运算、`[rsp]` 这类解引用，以及 `ntdll!NtCreateFile` 这类符号。只有在 `open` 或 `attach` 枚举模块并加载其 PDB 后，才能添加符号断点。<sup>[[2]](#references)</sup>

## 使用 `EB FE` 确定性地拦截入口点

Relay 端的 `open` 会创建挂起状态的目标进程，保存其入口点处的原始字节，写入 `EB FE`，恢复入口线程，然后轮询，直到指令指针到达该地址。`EB FE` 是一条跳回自身的两字节短跳转指令，因此无需依赖用户态调试异常的传递即可拦截执行。随后，relay 会恢复原始字节，并让目标进程停在入口点处。<sup>[[2]](#references)</sup>

当需要在常规调试器设置完成前观察早期加载器路径时，这种模式也很有用。<sup>[[2]](#references)</sup>

1. 挂起状态下创建进程，并在映像映射后解析其实际入口点。
2. 保存入口点处的原始字节，并将其替换为两字节自循环指令。
3. 恢复入口线程，并轮询其指令指针，直到到达已修补的地址。
4. 挂起目标进程，并在继续分析前精确恢复原始字节。

这种技术会有意干预目标进程。如果调试器或 relay 在恢复原始字节前退出，目标进程可能会一直循环。KernelFlirt 本地模式不提供 relay 端入口点修补；请手动启动进程，然后使用 `attach <pid>`。<sup>[[2]](#references)</sup>

## 选择断点机制

KernelFlirt 提供了多种副作用各异的断点机制。当加壳代码会自我重写、可执行页面为只读，或软件断点字节受到完整性检查时，分析人员可以使用以下命令切换机制。<sup>[[1]](#references)[[2]](#references)</sup>

| 机制 | 命令 | 原理和用途 |
| --- | --- | --- |
| 软件 | `bp <expr>` | 基于 MDL 的 `INT3`；可对 RX `.text` 页面进行插桩 |
| 条件软件 | `bp <expr> if <condition>` | 每次命中时都会求值；条件为假时静默继续执行 |
| 硬件执行 | `ba e1 <expr>` | 使用 DR0-DR3，不修改代码字节 |
| 硬件数据 | `ba w4 <expr>` / `ba r8 <expr>` | 监视 1、2、4 或 8 字节的写入或读写 |
| 保护页 | `bm <expr> [size]` | 使用 `PAGE_GUARD` 设置内存范围断点 |
| 临时 | `g <expr>`、`p` 或 `o` | 分别用于运行至地址、单步越过和单步跳出 |

使用 `bl` 区分软件、硬件、内存和临时断点，并使用 `bc <address|handle|all>` 删除它们。硬件槽位有限，并通过调试寄存器状态生效；保护页覆盖的范围更大，但同一页面上的无关访问也会触发断点。

## 原生 x64 与 WoW64 单步执行

原生 x64 单步执行通过 `IOCTL_KF_SINGLE_STEP` 设置处理器陷阱标志。Step Over 会解码当前指令，并在可能的下一条指令地址处设置临时断点。Step Out 会从当前栈顶读取返回地址。在函数序言处，栈顶假设可能不成立，因此最好使用已知的内部断点。<sup>[[2]](#references)</sup>

`KdTrap` 钩子无法以相同方式捕获 32 位异常。对于 WoW64 目标，调试器使用 Iced 解码指令，在计算出的下一条 `EIP` 地址处写入 `EB FE`，并轮询线程指令指针。因此，WoW64 不支持 `g <address>`，而普通的 `g` 会阻塞控制台，直到命中断点。请先设置一个可到达的断点，并避免无限期运行，因为 `Ctrl+C` 会终止控制台，而不是取消轮询。<sup>[[2]](#references)</sup>

## 使用内存、寄存器和符号辅助分析

控制台可以将符号断点与内存检查和受控修补结合使用。搜索调用支持字节通配符、ASCII 或 UTF-16，搜索范围上限为 4 MB，最多报告 256 个匹配项。内存分配和保护命令会分别调用驱动程序的 allocate、free 和 protect IOCTL。<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB 加载会读取每个远程模块的 PE 调试目录，提取其 RSDS 标识符，通过 DbgHelp/SymSrv 查找匹配的 PDB，并验证它是否以 PDB 格式加载。在中继机器上，将私有 PDB 放在目标旁边，或将其目录添加到主机的 `_NT_SYMBOL_PATH` 中。<sup>[[2]](#references)</sup>

## 基于内核的 anti-debug 状态更改

内核访问权限允许调试器移除用户态调试器无法可靠隐藏的指示器。每次只进行一项更改，确认目标检查结果，并在结束会话前还原对应的 hook。<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` 清除 `EPROCESS.DebugPort`。
- `clr_thread_hide` 从目标线程中移除 `HideFromDebugger`。
- `ntqsi on` 会伪造 `NtQuerySystemInformation` 类 `0x23`（`SystemKernelDebuggerInformation`）的结果。
- `spoof on` 会让用户态对 `KUSER_SHARED_DATA.KdDebuggerEnabled` 的读取返回 false，同时保留 trap mechanism 所需的内核状态。
- `stats` 会检查 hook 计数器，以及记录的 `KiDebugRoutine`、`KdpStub` 和 `KdTrap` 状态。

这些操作会更改进程和内核状态。崩溃、失效的 inline hook、不正确的结构偏移，或未完成的补丁还原，都可能导致 VM 不稳定，因此必须使用快照和隔离的测试签名环境。<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt 仓库和主要文档](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt 控制台参考](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
