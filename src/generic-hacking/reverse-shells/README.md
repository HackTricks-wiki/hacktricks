# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Gevirtualiseerde Windows-payload-uitvoering

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Om ’n plaaslike listener vanaf die internet bereikbaar te maak, sien [openbare HTTP- en TCP-tonnelopsies](../expose-local-to-the-internet.md).

---

## Outomaties gegenereerde shell-gereedskap

Verskeie web- en opdragreëlhulpmiddels kan bind- en reverse-shell-payloads vir verskillende interpreteerders en bedryfstelsels genereer:

- **reverse-shell.sh** en **revshells.com** bied blaaiergebaseerde payload-opwekkers.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** en **rsg** genereer payloads vanaf die opdragreël of ’n plaaslike koppelvlak.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** is ’n klein kruisplatform-reverse shell vir Linux en Windows.<sup>[[7]](#references)</sup>
- **pyminifier** is nie ’n shell-opwekker nie, maar kan Python-payloads verklein of verdoesel wanneer daardie transformasie nuttig is.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse-shell-opwekker](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse-shell-opwekker](https://www.revshells.com/)
- [3] [Shellerator - CLI-gereedskap om bind- en reverse shells in verskeie tale te genereer](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Skep shells soos ’n meester](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Skepper van reverse shells vir python, perl, ruby, bash, netcat, php, java, powershell, ens.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python-kodeverkleiner/-verdoeser](https://liftoff.github.io/pyminifier/)
- [7] [xc - Klein reverse shell vir Linux en Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Reverse-shell-opwekker geskryf in Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Gereedskap om verskillende maniere te genereer om ’n reverse shell te skep](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
