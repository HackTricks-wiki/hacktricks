# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Ausführung virtualisierter Windows-Payloads

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Informationen dazu, wie du einen lokalen Listener über das Internet erreichbar machst, findest du unter [Optionen für öffentliche HTTP- und TCP-Tunnel](../expose-local-to-the-internet.md).

---

## Automatisch generierte Shell-Tools

Verschiedene Web- und Kommandozeilen-Helfer können bind- und reverse-shell-Payloads für unterschiedliche Interpreter und Betriebssysteme generieren:

- **reverse-shell.sh** und **revshells.com** bieten browserbasierte Payload-Generatoren.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** und **rsg** generieren Payloads über die Kommandozeile oder eine lokale Schnittstelle.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** ist eine kleine plattformübergreifende Reverse Shell für Linux und Windows.<sup>[[7]](#references)</sup>
- **pyminifier** ist kein Shell-Generator, kann aber Python-Payloads minimieren oder verschleiern, wenn diese Transformation nützlich ist.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse-Shell-Generator](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse-Shell-Generator](https://www.revshells.com/)
- [3] [Shellerator - CLI-Tool zum Generieren von Bind- und Reverse-Shells in mehreren Sprachen](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Lass Shells wie ein Meister aufpoppen](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Reverse-Shell-Generator für Python, Perl, Ruby, Bash, Netcat, PHP, Java, PowerShell usw.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python-Code-Minimierer/Obfuscator](https://liftoff.github.io/pyminifier/)
- [7] [xc - Kleine Reverse Shell für Linux und Windows](https://github.com/xct/xc/)
- [8] [Reverse-Shell-Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - In Python 3 geschriebener Reverse-Shell-Generator](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Tool zum Generieren verschiedener Möglichkeiten für eine Reverse Shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
