# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## 仮想化された Windows payload の実行

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

ローカルリスナーをインターネット経由で到達可能にする方法については、[HTTP および TCP の公開トンネルオプション](../expose-local-to-the-internet.md)を参照してください。

---

## 自動生成 shell ツール

さまざまなインタープリターやオペレーティングシステム向けに、bind shell および reverse shell の payload を生成できる Web ヘルパーやコマンドラインヘルパーがいくつかあります。

- **reverse-shell.sh** と **revshells.com** は、ブラウザー上で動作する payload ジェネレーターを提供します。<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**、**ShellPop**、**ShellReverse**、**Reverse Shell Generator**、**revshellgen**、**rsg** は、コマンドラインまたはローカルインターフェースから payload を生成します。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** は、Linux と Windows 向けの小型クロスプラットフォーム reverse shell です。<sup>[[7]](#references)</sup>
- **pyminifier** は shell ジェネレーターではありませんが、その変換が有用な場合に Python payload を圧縮または難読化できます。<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell ジェネレーター](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell ジェネレーター](https://www.revshells.com/)
- [3] [Shellerator - 複数の言語で bind shell と reverse shell を生成する CLI ツール](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - マスターのように shell を起動](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - python、perl、ruby、bash、netcat、php、java、powershell など向けの shell reverse 作成ツール](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python コードの圧縮・難読化ツール](https://liftoff.github.io/pyminifier/)
- [7] [xc - Linux と Windows 向けの小型 reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3 で書かれた reverse shell ジェネレーター](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - reverse shell を実行するさまざまな方法を生成するツール](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
