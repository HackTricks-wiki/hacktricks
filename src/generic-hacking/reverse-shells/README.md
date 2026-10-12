# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Izvršavanje virtuelizovanih Windows payload-a

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## Alati za shell koji se automatski generišu

Nekoliko web i komandnolinijskih pomoćnih alata može da generiše bind- i reverse-shell payload-e za različite interpretere i operativne sisteme:

- **reverse-shell.sh** i **revshells.com** nude generatore payload-a koji se koriste u pregledaču.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** i **rsg** generišu payload-e iz komandne linije ili lokalnog interfejsa.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** je mali cross-platform reverse shell za Linux i Windows.<sup>[[7]](#references)</sup>
- **pyminifier** nije generator shell-ova, ali može da minimizuje ili obfuskira Python payload-e kada je takva transformacija korisna.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Generator reverse shell-ova](https://reverse-shell.sh/)
- [2] [revshells.com - Generator reverse shell-ova](https://www.revshells.com/)
- [3] [Shellerator - CLI alat za generisanje bind i reverse shell-ova na više jezika](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Pokreni shell-ove kao profesionalac](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Kreator reverse shell-ova za python, perl, ruby, bash, netcat, php, java, powershell itd.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Alat za minimizovanje/obfuskaciju Python koda](https://liftoff.github.io/pyminifier/)
- [7] [xc - Mali reverse shell za Linux i Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Generator reverse shell-ova napisan u Pythonu 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Alat za generisanje različitih načina za uspostavljanje reverse shell-a](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
