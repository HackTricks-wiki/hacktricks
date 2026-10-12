# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Uruchamianie payloadów w zwirtualizowanym Windowsie

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## Automatycznie generowane narzędzia shell

Różne narzędzia webowe i wiersza poleceń mogą generować payloady bind-shell i reverse-shell dla różnych interpreterów i systemów operacyjnych:

- **reverse-shell.sh** i **revshells.com** udostępniają działające w przeglądarce generatory payloadów.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** i **rsg** generują payloady z wiersza poleceń lub za pomocą lokalnego interfejsu.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** to niewielki, wieloplatformowy reverse shell dla Linuxa i Windowsa.<sup>[[7]](#references)</sup>
- **pyminifier** nie jest generatorem shelli, ale może minifikować lub obfuskować payloady Python, gdy takie przekształcenie jest przydatne.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Generator reverse shelli](https://reverse-shell.sh/)
- [2] [revshells.com - Generator reverse shelli](https://www.revshells.com/)
- [3] [Shellerator - Narzędzie CLI do generowania bind shelli i reverse shelli w wielu językach](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Uruchamiaj shelle jak mistrz](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Generator reverse shelli dla python, perl, ruby, bash, netcat, php, java, powershell itd.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minifikator/obfuscator kodu Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Niewielki reverse shell dla Linuxa i Windowsa](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Generator reverse shelli napisany w Pythonie 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Narzędzie do generowania różnych sposobów na uzyskanie reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
