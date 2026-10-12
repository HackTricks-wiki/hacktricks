# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## 仮想化されたWindowsペイロードの実行

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## 自動生成shellツール

さまざまなWebツールやコマンドラインツールを使って、異なるインタープリターやオペレーティングシステム向けのbind-shellおよびreverse-shellペイロードを生成できます。

- **reverse-shell.sh** と **revshells.com** は、ブラウザー上でペイロードを生成します。<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**、**ShellPop**、**ShellReverse**、**Reverse Shell Generator**、**revshellgen**、**rsg** は、コマンドラインまたはローカルインターフェースからペイロードを生成します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** は、LinuxとWindows向けの小型クロスプラットフォームreverse shellです。<sup>[[7]](#references)</sup>
- **pyminifier** はshell生成ツールではありませんが、その変換が有用な場合にPythonペイロードをminifyまたは難読化できます。<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell生成ツール](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell生成ツール](https://www.revshells.com/)
- [3] [Shellerator - 複数の言語でbind shellとreverse shellを生成するCLIツール](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - 熟練者のようにshellを起動](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - python、perl、ruby、bash、netcat、php、java、powershellなど向けのreverse shell作成ツール](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Pythonコードのminifier/難読化ツール](https://liftoff.github.io/pyminifier/)
- [7] [xc - LinuxとWindows向けの小型reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3で書かれたreverse shell生成ツール](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - reverse shellを実行するさまざまな方法を生成するツール](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
