# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## 自動生成 shell tools

複数の web および command-line helper を使用すると、異なる interpreter と operating system 向けの bind- および reverse-shell payload を生成できます。

- **reverse-shell.sh** と **revshells.com** は、browser-based payload generator を提供します。<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**、**ShellPop**、**ShellReverse**、**Reverse Shell Generator**、**revshellgen**、**rsg** は、command line または local interface から payload を生成します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** は Linux と Windows 向けの小規模な cross-platform reverse shell です。<sup>[[7]](#references)</sup>
- **pyminifier** は shell generator ではありませんが、その変換が有用な場合、Python payload を minify または obfuscate できます。<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell generator](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell generator](https://www.revshells.com/)
- [3] [Shellerator - 複数の言語で bind および reverse shell を生成する CLI tool](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - master のように shell を起動](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - python、perl、ruby、bash、netcat、php、java、powershell など向けの shell reverse creator](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python code minifier/obfuscator](https://liftoff.github.io/pyminifier/)
- [7] [xc - Linux と Windows 向けの小規模な reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3 で記述された reverse shell generator](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - reverse shell を実行するさまざまな方法を生成する tool](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
