# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## 가상화된 Windows payload 실행

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

---

## 자동 생성 shell 도구

여러 웹 및 명령줄 도구를 사용하면 다양한 인터프리터와 운영 체제용 bind- 및 reverse-shell payload를 생성할 수 있습니다.

- **reverse-shell.sh**와 **revshells.com**은 브라우저 기반 payload 생성기를 제공합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen**, **rsg**는 명령줄 또는 로컬 인터페이스에서 payload를 생성합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc**는 Linux와 Windows용 소형 크로스 플랫폼 reverse shell입니다.<sup>[[7]](#references)</sup>
- **pyminifier**는 shell 생성기가 아니지만, 변환이 유용한 경우 Python payload를 최소화하거나 난독화할 수 있습니다.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Reverse shell 생성기](https://reverse-shell.sh/)
- [2] [revshells.com - Reverse shell 생성기](https://www.revshells.com/)
- [3] [Shellerator - 여러 언어로 bind 및 reverse shell을 생성하는 CLI 도구](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - 전문가처럼 shell을 실행하세요](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Python, Perl, Ruby, Bash, Netcat, PHP, Java, PowerShell 등용 reverse shell 생성기](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Python 코드 최소화/난독화 도구](https://liftoff.github.io/pyminifier/)
- [7] [xc - Linux 및 Windows용 소형 reverse shell](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Python 3로 작성된 reverse shell 생성기](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - reverse shell을 다양한 방식으로 생성하는 도구](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
