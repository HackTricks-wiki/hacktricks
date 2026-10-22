# Reverse Shell

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

## [Full TTYs](full-ttys.md)

Per rendere un listener locale raggiungibile tramite Internet, consulta [le opzioni per i tunnel HTTP e TCP pubblici](../expose-local-to-the-internet.md).

---

## Strumenti shell generati automaticamente

Diversi strumenti web e da riga di comando possono generare payload bind e reverse shell per vari interpreti e sistemi operativi:

- **reverse-shell.sh** e **revshells.com** offrono generatori di payload utilizzabili dal browser.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** e **rsg** generano payload dalla riga di comando o tramite un'interfaccia locale.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** è una piccola reverse shell multipiattaforma per Linux e Windows.<sup>[[7]](#references)</sup>
- **pyminifier** non è un generatore di shell, ma può minificare o offuscare payload Python quando questa trasformazione è utile.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Generatore di reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Generatore di reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Strumento CLI per generare bind e reverse shell in più linguaggi](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Ottieni shell come un maestro](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Creatore di reverse shell per Python, Perl, Ruby, Bash, Netcat, PHP, Java, PowerShell, ecc.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minificatore/offuscatore di codice Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Piccola reverse shell per Linux e Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Generatore di reverse shell scritto in Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Strumento per generare vari modi di eseguire una reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
