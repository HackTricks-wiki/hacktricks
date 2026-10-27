# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** là một kỹ thuật cho phép kẻ tấn công **bỏ qua xác thực Active Directory** bằng cách **chèn một mật khẩu chủ** vào tiến trình LSASS của từng domain controller. Sau khi được chèn, mật khẩu chủ (mặc định là **`mimikatz`**) có thể được dùng để xác thực dưới danh nghĩa **bất kỳ người dùng domain nào**, trong khi mật khẩu thật của họ vẫn hoạt động.<sup>[[1]](#references)[[2]](#references)</sup>

Các thông tin chính:

- Yêu cầu **Domain Admin/SYSTEM + SeDebugPrivilege** trên mọi DC và phải **áp dụng lại sau mỗi lần khởi động lại**.<sup>[[2]](#references)</sup>
- Cách triển khai Mimikatz kinh điển vá các đường xác thực **NTLM** và **Kerberos RC4 (etype 0x17)**; xác thực chỉ dùng AES **không chấp nhận mật khẩu skeleton đó qua hook RC4**.<sup>[[2]](#references)</sup>
- Có thể xung đột với các gói xác thực LSA của bên thứ ba hoặc các nhà cung cấp thẻ thông minh / MFA bổ sung.<sup>[[2]](#references)</sup>
- Module Mimikatz chấp nhận tùy chọn `/letaes` để tránh can thiệp vào các hook Kerberos/AES nếu gặp vấn đề tương thích.<sup>[[3]](#references)</sup>

### Thực thi

LSASS cổ điển, không được bảo vệ bằng PPL:

```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

Nếu **LSASS đang chạy dưới dạng protected process light (PPL)**, quyền debug từ user-mode sẽ bị chặn. Quy trình Mimikatz trước đây dưới đây tải kernel driver và gỡ bỏ cơ chế bảo vệ trước khi vá LSASS. Credential Guard là một biện pháp kiểm soát cách ly riêng biệt, không nên dùng như từ đồng nghĩa với PPL.<sup>[[3]](#references)[[4]](#references)</sup>

```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```

Sau khi injection, xác thực bằng bất kỳ tài khoản miền nào nhưng dùng mật khẩu `mimikatz` (hoặc giá trị do operator đặt). Hãy nhớ thực hiện lại trên **tất cả DC** trong môi trường nhiều DC.

## Biện pháp giảm thiểu

- **Giám sát log**
  - System **Event ID 7045** (cài đặt service/driver) để phát hiện driver chưa ký như `mimidrv.sys`.
  - **Sysmon**: Event ID 7 (tải driver) để phát hiện `mimidrv.sys`; Event ID 10 để phát hiện truy cập đáng ngờ vào `lsass.exe` từ các tiến trình không thuộc hệ thống.
  - Security **Event ID 4673/4611** để phát hiện việc sử dụng đặc quyền nhạy cảm hoặc bất thường khi đăng ký gói xác thực LSA; đối chiếu với các lần đăng nhập 4624 bất thường dùng RC4 (etype 0x17) từ DC.
- **Tăng cường bảo vệ LSASS**
  - Bật **RunAsPPL** và **Credential Guard** nếu được hỗ trợ. Chúng cung cấp các lớp bảo vệ khác nhau; khi bật cùng nhau, chúng làm tăng độ khó và lượng telemetry của các nỗ lực sửa đổi hoặc trích xuất secret từ LSASS.<sup>[[4]](#references)</sup>
  - Tắt **RC4** cũ nếu có thể; vé Kerberos chỉ dùng AES sẽ ngăn chặn đường hook RC4 mà skeleton key sử dụng.<sup>[[2]](#references)</sup>
- Các lệnh PowerShell rà soát nhanh:
  - Phát hiện cài đặt kernel driver chưa ký: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
  - Tìm driver Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
  - Xác minh PPL được áp dụng sau khi khởi động lại: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Để biết thêm hướng dẫn tăng cường bảo vệ thông tin xác thực, hãy xem [các biện pháp bảo vệ thông tin xác thực của Windows](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Tấn công Skeleton Key trong Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Module misc::skeleton của Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Cấu hình tính năng bảo vệ LSA bổ sung](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
