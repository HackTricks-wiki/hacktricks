# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Utekelezaji wa payload za Windows zilizovirtualishwa

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Ili listener ya ndani ipatikane kupitia intaneti, angalia [chaguo za tunnel za HTTP na TCP za umma](../expose-local-to-the-internet.md).

---

## Zana za shell zinazozalishwa kiotomatiki

Baadhi ya zana za wavuti na za command line zinaweza kuzalisha payload za bind shell na reverse shell kwa interpreters na mifumo mbalimbali ya uendeshaji:

- **reverse-shell.sh** na **revshells.com** hutoa jenereta za payload zinazotumika kupitia kivinjari.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen**, na **rsg** huzalisha payload kupitia command line au kiolesura cha ndani.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** ni reverse shell ndogo inayofanya kazi kwenye Linux na Windows.<sup>[[7]](#references)</sup>
- **pyminifier** si jenereta ya shell, lakini inaweza kufupisha au kuficha payload za Python pale mabadiliko hayo yanapofaa.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Jenereta ya reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Jenereta ya reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Zana ya CLI ya kutengeneza bind na reverse shells katika lugha nyingi](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Fungua shells kama mtaalamu](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Kisanidi cha reverse shell cha python, perl, ruby, bash, netcat, php, java, powershell, n.k.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Kipunguza/kifichaji cha code ya Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Reverse shell ndogo ya Linux na Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Jenereta ya reverse shell iliyoandikwa kwa Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Zana ya kutengeneza njia mbalimbali za kufanya reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
