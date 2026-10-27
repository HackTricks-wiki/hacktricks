# Reverse Shells

{{#include ../../banners/hacktricks-training.md}}

## [Shells - Linux](linux.md)

---

## [Shells - Windows](windows.md)

## Thực thi payload Windows được ảo hóa

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

---

## [MSFVenom - CheatSheet](msfvenom.md)

---

## [Full TTYs](full-ttys.md)

Để listener cục bộ có thể truy cập qua internet, xem [các tùy chọn tunnel HTTP và TCP công khai](../expose-local-to-the-internet.md).

---

## Công cụ shell tự động tạo

Một số công cụ web và dòng lệnh có thể tạo payload bind shell và reverse shell cho nhiều trình thông dịch và hệ điều hành:

- **reverse-shell.sh** và **revshells.com** cung cấp các công cụ tạo payload trên trình duyệt.<sup>[[1]](#references)[[2]](#references)</sup>
- **Shellerator**, **ShellPop**, **ShellReverse**, **Reverse Shell Generator**, **revshellgen** và **rsg** tạo payload từ dòng lệnh hoặc giao diện cục bộ.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- **xc** là một reverse shell nhỏ, đa nền tảng dành cho Linux và Windows.<sup>[[7]](#references)</sup>
- **pyminifier** không phải là công cụ tạo shell, nhưng có thể rút gọn hoặc làm rối payload Python khi cần đến phép biến đổi đó.<sup>[[6]](#references)</sup>

## References

- [1] [reverse-shell.sh - Công cụ tạo reverse shell](https://reverse-shell.sh/)
- [2] [revshells.com - Công cụ tạo reverse shell](https://www.revshells.com/)
- [3] [Shellerator - Công cụ CLI tạo bind shell và reverse shell bằng nhiều ngôn ngữ](https://github.com/ShutdownRepo/shellerator)
- [4] [ShellPop - Bật shell như một bậc thầy](https://github.com/0x00-0x00/ShellPop)
- [5] [ShellReverse - Công cụ tạo reverse shell cho python, perl, ruby, bash, netcat, php, java, powershell, v.v.](https://github.com/cybervaca/ShellReverse)
- [6] [pyminifier - Công cụ rút gọn/làm rối mã Python](https://liftoff.github.io/pyminifier/)
- [7] [xc - Reverse shell nhỏ dành cho Linux và Windows](https://github.com/xct/xc/)
- [8] [Reverse Shell Generator](https://weibell.github.io/reverse-shell-generator/)
- [9] [revshellgen - Công cụ tạo reverse shell viết bằng Python 3](https://github.com/t0thkr1s/revshellgen)
- [10] [rsg (ReverShellGenerator) - Công cụ tạo nhiều cách thực hiện reverse shell](https://github.com/mthbernardes/rsg)
{{#include ../../banners/hacktricks-training.md}}
