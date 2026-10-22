# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Execução de payloads Windows virtualizados

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Para tornar um listener local acessível pela internet, consulte [opções de túneis HTTP e TCP públicos](../expose-local-to-the-internet.md).

---

## Ferramentas de shell geradas automaticamente

Vários auxiliares web e de linha de comando podem gerar payloads de bind shell e reverse shell para diferentes interpretadores e sistemas operacionais:

- **reverse-shell.sh** e **revshells.com** fornecem geradores de payloads acessíveis pelo navegador.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** e **rsg** geram payloads pela linha de comando ou por uma interface local.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** é um reverse shell multiplataforma pequeno para Linux e Windows.<sup>[[7]](#references)</sup>
- **pyminifier** não é um gerador de shell, mas pode minimizar ou ofuscar payloads Python quando essa transformação for útil.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Gerador de reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Gerador de reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Ferramenta CLI para gerar bind shells e reverse shells em várias linguagens](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Abra shells como um mestre](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Criador de reverse shell para Python, Perl, Ruby, Bash, Netcat, PHP, Java, PowerShell etc.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minificador/ofuscador de código Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Reverse shell pequeno para Linux e Windows](https://github.com/xct/xc/)
- [8] [Gerador de Reverse Shell](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Gerador de reverse shell escrito em Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Ferramenta para gerar várias maneiras de criar um reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
