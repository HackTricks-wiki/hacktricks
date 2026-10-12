# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Виконання payload у віртуалізованій Windows

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## Автоматично згенеровані інструменти для shell

Кілька вебінструментів і утиліт командного рядка можуть генерувати payload-и bind- і reverse-shell для різних інтерпретаторів та операційних систем:

- **reverse-shell.sh** і **revshells.com** — вебгенератори payload, доступні у браузері.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** і **rsg** генерують payload-и з командного рядка або через локальний інтерфейс.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** — невеликий кросплатформний reverse shell для Linux і Windows.<sup>[[7]](#references)</sup>
- **pyminifier** не генерує shell, але може мінімізувати або обфускувати Python payload-и, якщо таке перетворення потрібне.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Генератор reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Генератор reverse shell](https://www.revshells.com/)
- [3] [Shellerator - CLI-інструмент для генерації bind- і reverse-shell різними мовами](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Створюйте shell-и як майстер](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Генератор reverse shell для python, perl, ruby, bash, netcat, php, java, powershell тощо](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Мінімізатор/обфускатор коду Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Невеликий reverse shell для Linux і Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Генератор reverse shell, написаний на Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Інструмент для генерації різних способів створення reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
