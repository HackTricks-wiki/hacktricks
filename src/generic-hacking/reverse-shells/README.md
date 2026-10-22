# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Virtualized Windows payload execution

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

लोकल listener को इंटरनेट के ज़रिए पहुँच योग्य बनाने के लिए, [public HTTP and TCP tunnel options](../expose-local-to-the-internet.md) देखें।

---

## स्वतः जनरेट किए गए shell tools

कई web और command-line helpers अलग-अलग interpreters और operating systems के लिए bind और reverse-shell payloads जनरेट कर सकते हैं:

- **reverse-shell.sh** और **revshells.com** browser-based payload generators उपलब्ध कराते हैं।<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen**, और **rsg** command line या local interface से payloads जनरेट करते हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** Linux और Windows के लिए एक छोटा cross-platform reverse shell है।<sup>[[7]](#references)</sup>
- **pyminifier** shell generator नहीं है, लेकिन उपयोगी होने पर Python payloads को minify या obfuscate कर सकता है।<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell जनरेटर](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell जनरेटर](https://www.revshells.com/)
- [3] [Shellerator - कई भाषाओं में bind और reverse shells जनरेट करने का CLI tool](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - मास्टर की तरह shells खोलें](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - python, perl, ruby, bash, netcat, php, java, powershell आदि के लिए shell reverse creator](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python code minifier/obfuscator](https://liftoff.github.io/pyminifier/)
- [7] [xc - Linux और Windows के लिए छोटा reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3 में लिखा गया Reverse shell जनरेटर](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - reverse shell के विभिन्न तरीके जनरेट करने का tool](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
