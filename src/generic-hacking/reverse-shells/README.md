# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Esecuzione di payload Windows virtualizzati

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [TTY completi](full-ttys.md)

---

## Strumenti shell generati automaticamente

Diversi strumenti web e da riga di comando possono generare payload bind-shell e reverse-shell per diversi interpreti e sistemi operativi:

- **reverse-shell.sh** e **revshells.com** offrono generatori di payload utilizzabili dal browser.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** e **rsg** generano payload da riga di comando o tramite un'interfaccia locale.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** è una piccola reverse shell multipiattaforma per Linux e Windows.<sup>[[7]](#references)</sup>
- **pyminifier** non è un generatore di shell, ma può minimizzare o offuscare payload Python quando questa trasformazione è utile.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Generatore di reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Generatore di reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Strumento CLI per generare bind shell e reverse shell in più linguaggi](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Apri shell come un professionista](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Creatore di reverse shell per python, perl, ruby, bash, netcat, php, java, powershell, ecc.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minimizzatore/offuscatore di codice Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Piccola reverse shell per Linux e Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Generatore di reverse shell scritto in Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Strumento per generare vari metodi per ottenere una reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
