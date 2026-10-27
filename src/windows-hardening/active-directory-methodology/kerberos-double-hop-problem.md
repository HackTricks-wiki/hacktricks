# Vấn đề Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Giới thiệu

Vấn đề Kerberos "Double Hop" xảy ra khi attacker cố sử dụng **xác thực Kerberos qua hai** **hop**, chẳng hạn như khi dùng **PowerShell**/**WinRM**.

Khi **xác thực** bằng **Kerberos**, **thông tin xác thực** **không** được lưu vào bộ nhớ. Vì vậy, nếu chạy mimikatz, bạn **sẽ không tìm thấy thông tin xác thực** của người dùng trên máy, ngay cả khi người đó đang chạy các tiến trình.

Điều này là do khi kết nối bằng Kerberos, các bước diễn ra như sau:<sup>[[1]](#references)</sup>

1. User1 cung cấp thông tin xác thực và **domain controller** trả về một **TGT** Kerberos cho User1.
2. User1 dùng **TGT** để yêu cầu một **service ticket** nhằm **kết nối** với Server1.
3. User1 **kết nối** với **Server1** và cung cấp **service ticket**.
4. **Server1** **không** có **thông tin xác thực** của User1 được lưu trong bộ nhớ hoặc **TGT** của User1. Vì vậy, khi User1 từ Server1 cố đăng nhập vào server thứ hai, người đó **không thể xác thực**.

### Unconstrained Delegation

Nếu **unconstrained delegation** được bật trên PC, điều này sẽ không xảy ra vì **Server** sẽ **nhận** **TGT** của mỗi người dùng truy cập vào nó. Hơn nữa, nếu sử dụng unconstrained delegation, có khả năng bạn có thể **chiếm quyền kiểm soát Domain Controller** từ đó.\
[**Tìm hiểu thêm trên trang unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Một cách khác để tránh vấn đề này, nhưng [**không an toàn**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), là **Credential Security Support Provider**. Theo Microsoft:

> Xác thực CredSSP ủy quyền thông tin xác thực của người dùng từ máy tính cục bộ sang máy tính từ xa. Cách làm này làm tăng rủi ro bảo mật của thao tác từ xa. Nếu máy tính từ xa bị xâm nhập sau khi nhận thông tin xác thực, thông tin này có thể được dùng để kiểm soát phiên mạng.

Chúng tôi đặc biệt khuyến nghị tắt **CredSSP** trên các hệ thống production, mạng nhạy cảm và các môi trường tương tự do những lo ngại về bảo mật. Có thể chạy lệnh `Get-WSManCredSSP` để xác định **CredSSP** có được bật hay không. Lệnh này cho phép **kiểm tra trạng thái CredSSP** và thậm chí có thể được thực thi từ xa, miễn là **WinRM** được bật.

```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
    Get-WSManCredSSP
}
```

### Remote Credential Guard (RCG)

**Remote Credential Guard** giữ TGT của người dùng trên máy trạm khởi tạo, đồng thời vẫn cho phép phiên RDP yêu cầu các service ticket Kerberos mới ở hop tiếp theo. Bật **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** và chọn **Require Remote Credential Guard**, sau đó kết nối bằng `mstsc.exe /remoteGuard /v:server1` thay vì chuyển sang CredSSP.

Microsoft đã làm hỏng RCG khi truy cập multi-hop trên Windows 11 22H2+ cho đến khi phát hành **bản cập nhật tích lũy tháng 4 năm 2024** (KB5036896/KB5036899/KB5036894). Hãy cập nhật client và máy chủ trung gian, nếu không hop thứ hai vẫn sẽ thất bại.<sup>[[5]](#references)</sup> Cách kiểm tra hotfix nhanh:

```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
    Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```

Khi các bản build đó được cài đặt, RDP hop có thể đáp ứng các thử thách Kerberos ở máy chủ tiếp theo mà không làm lộ thông tin bí mật có thể tái sử dụng trên máy chủ đầu tiên.

## Workarounds

### Invoke Command

Để xử lý vấn đề double hop, tài liệu trình bày một phương pháp sử dụng `Invoke-Command` lồng nhau. Phương pháp này không trực tiếp giải quyết vấn đề, nhưng đưa ra một cách khắc phục không cần cấu hình đặc biệt. Cách tiếp cận này cho phép thực thi lệnh (`hostname`) trên máy chủ thứ hai thông qua lệnh PowerShell được chạy từ máy tấn công ban đầu hoặc thông qua một PS-Session đã thiết lập trước đó với máy chủ đầu tiên. Cách thực hiện như sau:<sup>[[2]](#references)</sup>

```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```

Ngoài ra, nên thiết lập một PS-Session với máy chủ đầu tiên rồi chạy `Invoke-Command` bằng `$cred` để tập trung hóa các tác vụ.

### Đăng ký cấu hình PSSession

Một giải pháp để vượt qua vấn đề double hop là dùng `Register-PSSessionConfiguration` với `Enter-PSSession`. Phương pháp này đòi hỏi cách tiếp cận khác với `evil-winrm` và cho phép tạo một phiên không bị giới hạn double hop.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```

### PortForwarding

Đối với quản trị viên cục bộ trên một target trung gian, port forwarding cho phép gửi các yêu cầu đến máy chủ đích. Có thể dùng `netsh` để thêm quy tắc port forwarding, đồng thời thêm quy tắc Windows Firewall để cho phép cổng được chuyển tiếp.<sup>[[2]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```

#### winrs.exe

`winrs.exe` có thể được dùng để chuyển tiếp các yêu cầu WinRM, có khả năng là một lựa chọn ít bị phát hiện hơn nếu việc giám sát PowerShell là mối lo ngại.<sup>[[2]](#references)</sup> Lệnh dưới đây minh họa cách sử dụng:

```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```

### OpenSSH

Cài đặt OpenSSH trên máy chủ đầu tiên giúp khắc phục sự cố double-hop, đặc biệt hữu ích trong các tình huống sử dụng jump box. Phương pháp này yêu cầu cài đặt và thiết lập OpenSSH cho Windows qua CLI. Khi được cấu hình với Password Authentication, phương pháp này cho phép máy chủ trung gian lấy TGT thay mặt người dùng.<sup>[[2]](#references)</sup>

#### Các bước cài đặt OpenSSH

1. Tải xuống và chuyển tệp zip bản phát hành OpenSSH mới nhất sang máy chủ mục tiêu.
2. Giải nén và chạy script `Install-sshd.ps1`.
3. Thêm quy tắc tường lửa để mở cổng 22 và xác minh các dịch vụ SSH đang chạy.

Để khắc phục lỗi `Connection reset`, có thể cần cập nhật quyền để cho phép mọi người có quyền đọc và thực thi trên thư mục OpenSSH.

```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```

### LSA Whisperer CacheLogon (Nâng cao)

**LSA Whisperer** (2024) cung cấp package call `msv1_0!CacheLogon` để bạn có thể nạp một NT hash đã biết vào *network logon* hiện có, thay vì tạo một session mới bằng `LogonUser`. Bằng cách inject hash vào logon session mà WinRM/PowerShell đã mở ở hop #1, host đó có thể xác thực với hop #2 mà không cần lưu thông tin xác thực tường minh hoặc tạo thêm các sự kiện 4624.<sup>[[6]](#references)</sup>

1. Có được quyền thực thi code bên trong LSASS (bằng cách vô hiệu hóa/lạm dụng PPL hoặc chạy trên một lab VM do bạn kiểm soát).
2. Liệt kê các logon session (ví dụ: `lsa.exe sessions`) và lấy LUID tương ứng với remoting context của bạn.
3. Tính trước NT hash rồi truyền nó vào `CacheLogon`, sau đó xóa hash khi hoàn tất.

```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```

Sau khi seed cache, chạy lại `Invoke-Command`/`New-PSSession` từ hop #1: LSASS sẽ dùng lại hash đã inject để đáp ứng các challenge Kerberos/NTLM cho hop thứ hai, qua đó dễ dàng vượt qua giới hạn double hop. Đổi lại, thao tác này tạo telemetry nhiều hơn (thực thi code trong LSASS), vì vậy chỉ nên dùng trong các môi trường có nhiều hạn chế, nơi CredSSP/RCG không được phép.

## References

- [1] [Tìm hiểu về Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Các cách xử lý Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Một giải pháp khác cho PowerShell remoting nhiều hop](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Khắc phục vấn đề PowerShell nhiều hop mà không dùng CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [Ngày 9 tháng 4 năm 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)
{{#include ../../banners/hacktricks-training.md}}
