# 面向目标检测的 WinDbg 自动化

{{#include ../../banners/hacktricks-training.md}}

WinDbg 和 WinDbgX 可以在启动时、发生异常时以及触发断点时运行调试器命令。这样，fuzzing 或 reversing 会话就能只收集输入驱动路径上的状态，而不必在每个事件发生时手动暂停。<sup>[[1]](#references)</sup>

## 从有用的异常处开始

`-c` 会在调试器首次中断时运行命令。追加 `;g` 可在设置完成后继续运行。对于无人值守的 WinDbg Classic 运行，`-logo` 会将命令窗口写入日志，`-Q` 会禁用自动保存工作区，`-G` 则会忽略最终断点，使会话在目标退出时结束。WinDbgX 也接受 `-c`；之后会运行其已配置的 Startup commands。<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

对于 access violation，**`sxe av` 会在 first chance 时中断**，**`sxd av` 会跳过 first chance，但在未处理的 second chance 时中断**，**`sxi av` 会忽略这两次机会**。本文对 `sxi`/`sxd` 的描述颠倒了：Microsoft 将 `sxd` 定义为 second-chance filter，将 `sxi` 定义为忽略。使用 `-c` 设置 first-chance 命令，使用 `-c2` 设置 second-chance 命令；即使 filter 是 `sxd`，first-chance `-c` handler 也不会因此变成 second-chance handler。使用 `sx` 确认当前启用的 filters。<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

第一个命令仅在发生未处理的 access violation 时收集寄存器、stack trace 和异常分析。第二个命令会在模块加载时运行 `lm`。Breakpoint（`bp`）、模块加载（`ld`）和 access-violation（`av`）事件的生命周期各不相同，因此依赖 debugger breakpoint 时，不要全局忽略 `bp` 事件。<sup>[[1]](#references)[[2]](#references)</sup>

## 用受控触发器启用高开销断点

选择一个可通过脚本调用或以其他方式受输入控制的函数，使其能在目标路径执行前立即调用。在要检查的 allocator、parser 或 API 调用处设置 **action breakpoint**。使用 `bd` 按 ID 禁用这些断点。设置一个 **trigger breakpoint**，并为其附加命令，以 `be` 启用这些断点，然后用 `g` 恢复执行；还可以用第二个受控触发器再次禁用它们。连接触发器前，先用 `bl` 检查 ID，因为 ID 取决于断点的创建顺序。这样可以将开销低的控制点与高开销跟踪分开，并尽量减少对目标程序时序和 heap layout 的影响。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

解析出两个符号后，命令格式如下。替换方括号中的符号以及 `bl` 返回的 action breakpoint ID；不要假设它是零。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

动作断点命令可以打印 `@$ip` 和 `%y`（符号化地址）、dump 选定的参数或内存，然后继续执行。如果条件断点只记录选定范围内的指针，请先确认该范围确实包含测试输入；条件设置错误会导致证据悄然丢失。<sup>[[1]](#references)</sup>

### 使用符号查找触发点

如果不知道实现所在的模块，就搜索所有已加载模块。`bm` 会在每个匹配的符号上设置断点；调用脚本可见的函数，然后检查哪个断点被触发。例如，源码会在正在调试的 renderer 中执行 `Math.cos(0)`，而不是在任意浏览器进程中执行。<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

一旦命中确定了确切函数，使用 `lm a <symbol>` 解析其所属映像，并使用 `? <symbol> - <module>` 计算模块相对偏移。WinDbg 可能会为可执行文件和 DLL 显示相同的短模块名，因此在其他进程中使用该偏移前，请先核实映像路径。将通配符断点缩小到已核实的符号，以避免额外开销。<sup>[[1]](#references)</sup>

### 在没有符号的情况下查找候选项

Corelan 基于 Frida 的 `corelan_trigscan.py` 会扫描选定的进程模块，查找浮点、SSE、AVX 和三角函数指令模式。它会将 WinDbg 断点命令输出到 `corelan_trigscan.bps` 和较小的编号 `.bps` 文件中。使用 Python 和 `frida-tools` 对目标运行该脚本，**不要附加其他调试器**；随后将 WinDbg 附加到同一进程/模块，并加载适量的断点批次。<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

对于已知的模块相对偏移，在导入所有生成的断点之前，先验证它是否通过了阈值筛选：<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` 表示相关指令密度，`--min-relevant` 和 `--min-total` 设置指令数量下限，`--min-trig` 则要求存在明显的类 trig 信号。如果漏掉了已知函数，请将其**相对于模块的**偏移传给 `--check-offset`，以检查它的序言、密度、数量和间接调用。薄包装函数的密度可能较低，也可能没有 trig 指令。降低阈值；如果要搜索包装函数，请使用脚本实际支持的 `--min-icall 1` 选项（而不是 `--min-ical`）；脚本会分析直接被调用的函数，但无法可靠地跟踪间接调用的目标。当生成的断点过多、拖慢 WinDbg 时，较小的 `--splitsize` 批次会有所帮助。只有当预期输入触发断点后，候选项才算通过验证。<sup>[[1]](#references)[[6]](#references)</sup>

## 小型调试器程序与 PyKD

条件可靠时使用 `.if`，使用 `.foreach` 遍历以空白符分隔的输出，并使用带伪寄存器的 `.for` 遍历内存或结构体。`.foreach` **不会**保留列信息：例如，`lm` 输出的列宽不固定，不适合作为输入；而 `lm 1m` 每个 token 只包含一个模块名。如果猜测的条件可能会隐藏故障路径，请先记录未经筛选的数据。<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

使用 `as name value` 创建的别名是文本替换，而不是有类型的变量。`al` 列出别名，`ad name` 删除别名，`${name}` 则确保明确展开。避免使用 `bp`、`x` 或 `r` 等名称，因为别名可能遮蔽内置命令。MASM 表达式适用于指针运算，例如 `poi(@$t0)`；存在符号时，`@@c++(...)` 可访问有类型的字段，避免硬编码结构偏移量。<sup>[[1]](#references)</sup>

将较长的命令序列放入命令文件。`$$><filename` 会将多行合并为单个命令块，并允许后接以分号分隔的调试器命令。多行控制结构仍可能不稳定；将每个 `.if` 或 `.for` 语句保持在同一行。启动时也可以通过 `-c` 调用同一个文件。<sup>[[1]](#references)[[8]](#references)</sup>

对于命令语言难以实现的逻辑，PyKD 可通过 Python 访问有类型的结构、寄存器、内存和调试器输出。例如，`pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` 可访问 PEB 字段，`pykd.loadBytes(address, size)` 可读取内存，而 `pykd.dbgCommand("lm")` 会返回供解析的调试器输出。对于可能未以空字符终止的数据，优先使用有界的 `loadChars`/`loadWChars`，而不是无界字符串读取。PyKD 的 `disasm(address).asm(instruction)` **会在该地址写入汇编后的字节**；如果在活动进程中用它获取操作码，请先保存并恢复原始内存。<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan：调试 - WinDBG(X) 自动化与脚本编写 - 第 1 部分](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft：sx、sxd、sxe、sxi、sxn、sxr、sx-（设置异常）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft：be（启用断点）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft：bd（禁用断点）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft：bp、bu、bm（设置断点）](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan 源码](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft：WinDbg 命令行选项](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft：运行脚本文件](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
