# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Ejecución de payloads en Windows virtualizado

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## Herramientas de shell autogeneradas

Varias herramientas web y de línea de comandos pueden generar payloads de bind shell y reverse shell para distintos intérpretes y sistemas operativos:

- **reverse-shell.sh** y **revshells.com** ofrecen generadores de payloads basados en navegador.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** y **rsg** generan payloads desde la línea de comandos o una interfaz local.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** es una reverse shell multiplataforma pequeña para Linux y Windows.<sup>[[7]](#references)</sup>
- **pyminifier** no es un generador de shell, pero puede minificar u ofuscar payloads de Python cuando esa transformación resulta útil.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Generador de reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Generador de reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Herramienta CLI para generar bind shells y reverse shells en varios lenguajes](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Abre shells como un maestro](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Creador de reverse shells para Python, Perl, Ruby, Bash, Netcat, PHP, Java, PowerShell, etc.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minificador/ofuscador de código Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Reverse shell pequeña para Linux y Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Generador de reverse shells escrito en Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Herramienta para generar distintas formas de hacer una reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
