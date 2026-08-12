# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## स्वचालित रूप से जनरेट किए गए shell tools

कई web और command-line helpers अलग-अलग interpreters और operating systems के लिए bind- और reverse-shell payloads generate कर सकते हैं:

- **reverse-shell.sh** और **revshells.com** browser-based payload generators प्रदान करते हैं।<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen**, और **rsg** command line या local interface से payloads generate करते हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc**, Linux और Windows के लिए एक छोटा cross-platform reverse shell है।<sup>[[7]](#references)</sup>
- **pyminifier** कोई shell generator नहीं है, लेकिन जब यह transformation उपयोगी हो, तब Python payloads को minify या obfuscate कर सकता है।<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell generator](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell generator](https://www.revshells.com/)
- [3] [Shellerator - कई languages में bind और reverse shells generate करने के लिए CLI tool](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - एक master की तरह shells pop करें](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - python, perl, ruby, bash, netcat, php, java, powershell आदि के लिए Shell reverse creator](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python code minifier/obfuscator](https://liftoff.github.io/pyminifier/)
- [7] [xc - Linux और Windows के लिए छोटा reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3 में लिखा गया Reverse shell generator](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - reverse shell करने के विभिन्न तरीके generate करने का tool](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
