# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Izvršavanje Windows payload-a u virtuelizovanom okruženju

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Da bi lokalni listener bio dostupan preko interneta, pogledajte [opcije za javne HTTP i TCP tunele](../expose-local-to-the-internet.md).

---

## Alati za automatsko generisanje shell-ova

Nekoliko veb i komandnolinijskih alata može da generiše bind i reverse shell payload-e za različite interpretere i operativne sisteme:

- **reverse-shell.sh** i **revshells.com** pružaju generatore payload-a koji rade u pregledaču.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** i **rsg** generišu payload-e iz komandne linije ili lokalnog interfejsa.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** je mali cross-platform reverse shell za Linux i Windows.<sup>[[7]](#references)</sup>
- **pyminifier** nije generator shell-ova, ali može da minimizuje ili obfuskira Python payload-e kada je takva transformacija korisna.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Generator reverse shell-ova](https://reverse-shell.sh/)
- [2] [revshells.com - Generator reverse shell-ova](https://www.revshells.com/)
- [3] [Shellerator - CLI alat za generisanje bind i reverse shell-ova na više jezika](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Otvarajte shell-ove kao majstor](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Alat za kreiranje reverse shell-ova za python, perl, ruby, bash, netcat, php, java, powershell itd.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Alat za minimizaciju i obfuskaciju Python koda](https://liftoff.github.io/pyminifier/)
- [7] [xc - Mali reverse shell za Linux i Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Generator reverse shell-ova napisan u Python-u 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Alat za generisanje različitih načina za pokretanje reverse shell-a](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
