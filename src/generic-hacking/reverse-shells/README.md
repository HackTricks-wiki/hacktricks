# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## 虚拟化 Windows payload 执行

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

如需让本地 listener 可通过互联网访问，请参阅[公开 HTTP 和 TCP 隧道选项](../expose-local-to-the-internet.md)。

---

## 自动生成的 shell 工具

多种 Web 和命令行辅助工具可以为不同的解释器和操作系统生成 bind shell 和 reverse shell payload：

- **reverse-shell.sh** 和 **revshells.com** 提供基于浏览器的 payload 生成器。<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**、**ShellPop**、**ShellReverse**、**Reverse Shell Generator**、**revshellgen** 和 **rsg** 可通过命令行或本地界面生成 payload。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** 是一个适用于 Linux 和 Windows 的小型跨平台 reverse shell。<sup>[[7]](#references)</sup>
- **pyminifier** 不是 shell 生成器，但在适用时可以对 Python payload 进行缩减或混淆。<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell 生成器](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell 生成器](https://www.revshells.com/)
- [3] [Shellerator - 用于以多种语言生成 bind shell 和 reverse shell 的 CLI 工具](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - 像大师一样弹出 shell](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - 用于创建 Python、Perl、Ruby、Bash、Netcat、PHP、Java、PowerShell 等的 reverse shell](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python 代码缩减器/混淆器](https://liftoff.github.io/pyminifier/)
- [7] [xc - 适用于 Linux 和 Windows 的小型 reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - 使用 Python 3 编写的 reverse shell 生成器](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - 用于生成多种 reverse shell 实现方式的工具](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
