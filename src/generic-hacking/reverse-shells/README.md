# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Exécution de payloads Windows virtualisés

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Pour rendre un listener local accessible sur Internet, consultez les [options de tunnel HTTP et TCP publics](../expose-local-to-the-internet.md).

---

## Outils de shell générés automatiquement

Plusieurs outils Web et en ligne de commande peuvent générer des payloads bind et reverse shell pour différents interpréteurs et systèmes d’exploitation :

- **reverse-shell.sh** et **revshells.com** proposent des générateurs de payloads accessibles dans un navigateur.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** et **rsg** génèrent des payloads en ligne de commande ou via une interface locale.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** est un petit reverse shell multiplateforme pour Linux et Windows.<sup>[[7]](#references)</sup>
- **pyminifier** n’est pas un générateur de shell, mais peut minifier ou obfusquer des payloads Python lorsque cette transformation est utile.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Générateur de reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Générateur de reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Outil CLI pour générer des bind et reverse shells dans plusieurs langages](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Faire apparaître des shells comme un maître](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Créateur de reverse shell pour python, perl, ruby, bash, netcat, php, java, powershell, etc.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Minificateur/obfuscateur de code Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Petit reverse shell pour Linux et Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Générateur de reverse shell écrit en Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Outil permettant de générer différentes méthodes pour établir un reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
