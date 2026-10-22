# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Sanallaştırılmış Windows payload yürütme

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Yerel bir listener'ı internet üzerinden erişilebilir kılmak için [public HTTP and TCP tunnel options](../expose-local-to-the-internet.md) sayfasına bakın.

---

## Otomatik oluşturulan shell araçları

Çeşitli web ve komut satırı yardımcıları, farklı yorumlayıcılar ve işletim sistemleri için bind ve reverse shell payload'ları oluşturabilir:

- **reverse-shell.sh** ve **revshells.com**, tarayıcı tabanlı payload oluşturucular sunar.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** ve **rsg**, komut satırından veya yerel bir arayüzden payload oluşturur.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc**, Linux ve Windows için küçük, platformlar arası bir reverse shell'dir.<sup>[[7]](#references)</sup>
- **pyminifier** bir shell oluşturucu değildir; ancak bu dönüşümün yararlı olduğu durumlarda Python payload'larını küçültebilir veya obfuscate edebilir.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell oluşturucu](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell oluşturucu](https://www.revshells.com/)
- [3] [Shellerator - Birden fazla dilde bind ve reverse shell oluşturmak için CLI aracı](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Usta gibi shell açın](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Python, perl, ruby, bash, netcat, php, java, powershell vb. için reverse shell oluşturucu](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python kodu küçültücü/obfuscator](https://liftoff.github.io/pyminifier/)
- [7] [xc - Linux ve Windows için küçük reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3 ile yazılmış reverse shell oluşturucu](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Reverse shell oluşturmanın çeşitli yollarını sağlayan araç](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
