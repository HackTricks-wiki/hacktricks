# Token truy cập

{{#include ../../banners/hacktricks-training.md}}

## Token truy cập

Mỗi tiến trình có một **token truy cập chính** xác định ngữ cảnh bảo mật của nó. Một luồng thường sử dụng token đó, nhưng đôi khi nó cũng có thể tạm thời có một **token mạo danh**. Token chứa SID của người dùng, SID của nhóm, các đặc quyền, thông tin về mức toàn vẹn và SID đăng nhập của phiên đăng nhập. Các tiến trình thường kế thừa một tham chiếu đến token chính của tiến trình cha; chúng không nhận được một bản sao độc lập của nội dung token đó.<sup>[[4]](#references)</sup>

Bạn có thể xem thông tin này bằng cách chạy `whoami /all`

```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

hoặc sử dụng _Process Explorer_ từ Sysinternals (chọn tiến trình rồi mở tab "Security"):

![Access Tokens - Access Tokens: hoặc sử dụng Process Explorer từ Sysinternals (chọn tiến trình rồi mở tab "Security")](<../../images/image (772).png>)

### Quản trị viên cục bộ

Khi **UAC Admin Approval Mode** áp dụng cho quản trị viên, quá trình đăng nhập tương tác sẽ tạo một token quản trị viên đầy đủ và một token bị lọc. Explorer và các tiến trình con thông thường mặc định sử dụng token bị lọc. Yêu cầu nâng quyền như **Run as administrator** sẽ yêu cầu UAC khởi chạy chương trình bằng token đầy đủ. Hành vi chính xác khác nhau tùy tài khoản Administrator tích hợp sẵn và việc Admin Approval Mode có bị tắt hay không.<sup>[[5]](#references)</sup>

Đọc [**trang UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) riêng để tìm hiểu các kỹ thuật bypass và chi tiết về chính sách.

Trên thực tế, điều này có nghĩa là **shell admin chưa được nâng quyền thường chạy bằng token bị lọc**. Đó là lý do `whoami /groups` thường hiển thị **`BUILTIN\Administrators` ở trạng thái `Deny only`** cho đến khi tiến trình được nâng quyền. Bên trong, Windows giữ một **token nâng quyền được liên kết** (`TokenLinkedToken`) và theo dõi trạng thái bằng các trường như `TokenElevationType`.

### Mạo danh người dùng bằng thông tin xác thực

Nếu bạn có **thông tin xác thực hợp lệ của bất kỳ người dùng nào khác**, bạn có thể **tạo** một **phiên đăng nhập mới** bằng thông tin xác thực đó:

```
runas /user:domain\username cmd.exe
```

**access token** cũng chứa một **tham chiếu** đến các phiên đăng nhập bên trong **LSASS**; điều này hữu ích nếu tiến trình cần truy cập một số đối tượng trên mạng.\
Bạn có thể khởi chạy một tiến trình **sử dụng thông tin xác thực khác để truy cập các dịch vụ mạng** bằng cách:

```
runas /user:domain\username /netonly cmd.exe
```

Điều này hữu ích nếu bạn có credentials phù hợp để truy cập các đối tượng trên mạng, nhưng các credentials đó không hợp lệ trên host hiện tại vì chúng chỉ được dùng trên mạng (trên host hiện tại, quyền của user hiện tại sẽ được sử dụng).

#### Chi tiết về `runas /netonly`

`runas /netonly` (và các C2 helper như `make_token`) tạo token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Hiểu rõ điều này rất hữu ích trong quá trình lateral movement vì:<sup>[[3]](#references)</sup>

- **Trên máy cục bộ**, process mới giữ nguyên **danh tính cục bộ**, các group, integrity level và hầu hết các quyết định truy cập của token hiện tại.
- **Trên máy từ xa**, xác thực outbound có thể sử dụng **credentials được cung cấp** cho SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Vì vậy, `whoami` vẫn có thể hiển thị **user cục bộ ban đầu**, trong khi truy cập mạng được thực hiện dưới danh nghĩa **tài khoản khác**.

Đây là lựa chọn phù hợp khi credentials hợp lệ trong domain hoặc trên host khác, nhưng user **không thể hoặc không nên đăng nhập cục bộ** vào máy hiện tại.

### Các loại token

Có hai loại token:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Đại diện cho ngữ cảnh bảo mật của một process. Process con thường kế thừa primary token của process cha, trong khi các API tạo process bằng token chỉ định sẽ áp dụng các yêu cầu riêng về quyền truy cập token và đặc quyền của caller.
- **Impersonation token**: Cho phép một thread của server tạm thời sử dụng ngữ cảnh bảo mật của client để kiểm tra quyền truy cập. Token này có bốn cấp độ:
  - **Anonymous**: Cấp cho server quyền truy cập tương tự như người dùng chưa được xác định danh tính.
  - **Identification**: Cho phép server xác minh danh tính của client mà không sử dụng danh tính đó để truy cập đối tượng.
  - **Impersonation**: Cho phép server hoạt động dưới danh tính của client.
  - **Delegation**: Cho phép server mạo danh client trên các hệ thống từ xa khi cơ chế xác thực và cấu hình tài khoản hỗ trợ delegation.

#### Đánh giá token thu được trước khi sử dụng

Không chọn token chỉ dựa vào username. Cùng một tài khoản có thể có nhiều token với logon session, service SID, đặc quyền, integrity level, giới hạn và network credentials khác nhau.<sup>[[9]](#references)</sup> Dùng `GetTokenInformation` để truy vấn ít nhất các trường **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** và **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Token bị hạn chế có thể chứa SID chỉ dùng để từ chối, các đặc quyền đã bị loại bỏ và SID hạn chế. Khi có SID hạn chế, Windows thực hiện một lần kiểm tra quyền truy cập bằng các SID được bật và một lần khác bằng các SID hạn chế; **cả hai lần kiểm tra đều phải cho phép truy cập**. Vì vậy, SID của user có vẻ hữu ích hoặc một group được bật trong kết quả không đủ để chứng minh rằng token có thể truy cập đối tượng đích.<sup>[[8]](#references)</sup>

Dùng quy trình quyết định sau cho các yêu cầu về token và tạo process đã được ghi nhận:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token** cần một handle có `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` trước khi có thể được cung cấp cho `CreateProcessWithTokenW` hoặc `CreateProcessAsUserW`.
2. Chuyển **impersonation token** bằng `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Token ở cấp Identification có thể cung cấp dữ liệu danh tính nhưng không thể thực hiện kiểm tra quyền truy cập với tư cách client đó.
3. `CreateProcessWithTokenW` cần `SeImpersonatePrivilege` và khởi chạy process con trong session của caller. Ngược lại, `CreateProcessAsUserW` sử dụng session của token, nhưng thường cần `SeIncreaseQuotaPrivilege` và có thể cần `SeAssignPrimaryTokenPrivilege`. Nếu có credentials nhưng thiếu các đặc quyền này, `CreateProcessWithLogonW` là phương án thay thế được ghi nhận.

#### Tìm handle token, không chỉ tìm chủ sở hữu process

Mở primary token của từng process có thể bỏ sót **impersonation token được giữ dưới dạng handle thông thường** bên trong service và broker process. Một quy trình có thể tái sử dụng để xử lý handle table là liệt kê system handle, lọc các đối tượng token, mở từng process sở hữu bằng `PROCESS_DUP_HANDLE`, duplicate handle cần kiểm tra vào process hiện tại, rồi truy vấn các trường ở trên. Xác nhận handle được duplicate có `TOKEN_QUERY` và `TOKEN_DUPLICATE`; nhìn thấy handle token không có nghĩa là có thể duplicate nó thành primary token sử dụng được. Protected process và DACL của process vẫn có thể chặn handle tới process sở hữu.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` tự động liệt kê cả primary token của process lẫn các handle token được giữ lại. `list_token` giữ lại một ứng viên ưu tiên cho mỗi username, còn `list_all_token` in ra mọi ứng viên. PID giới hạn việc liệt kê ở một process sở hữu duy nhất.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

For manual inspection và kiểm tra quyền truy cập, **TokenUniverse** có thể mở token của process/thread, tìm các handle token hiện có, kiểm tra các hạn chế và phiên đăng nhập, nhân bản token, đồng thời thử một số phương thức tạo process.<sup>[[13]](#references)</sup> Để xem primitive handle xuyên process nền tảng, hãy tham khảo:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Mạo danh token

Sử dụng module _**incognito**_ của metasploit, nếu có đủ đặc quyền, bạn có thể dễ dàng **liệt kê** và **mạo danh** các **token** khác. Điều này có thể hữu ích để thực hiện **hành động như thể bạn là người dùng khác**. Bạn cũng có thể **leo thang đặc quyền** bằng kỹ thuật này.

Một số lưu ý thực tế dễ bị quên khi thao tác:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** yêu cầu caller có **`SeImpersonatePrivilege`**, và process mới sẽ chạy trong **phiên của caller**.
- **`CreateProcessAsUserW`** là phương án dự phòng khả thi khi `CreateProcessWithTokenW` thất bại với lỗi `1314`, nhưng chỉ khi caller đáp ứng các yêu cầu về đặc quyền. Đây cũng là lựa chọn phù hợp khi process con cần chạy trong **phiên được tham chiếu bởi token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Nếu token đến từ **`LogonUser(LOGON32_LOGON_NETWORK)`**, thông thường đó là **impersonation token**, vì vậy bạn cần **`DuplicateTokenEx(..., TokenPrimary, ...)`** trước khi thử khởi chạy process bằng token đó.
- Không phải impersonation token nào cũng hữu ích như nhau: **`SecurityIdentification`** cho phép bạn kiểm tra người dùng nhưng **không thể hành động thay họ**. Nếu một coercion primitive hoặc client pipe/RPC chỉ cung cấp token ở cấp identification, hãy kiểm tra **`TokenImpersonationLevel`** và chuyển sang primitive tạo ra **`SecurityImpersonation`** trở lên.

#### Đánh cắp token mà không chạm đến LSASS

Nếu bạn đã có context **service** hoặc **SYSTEM**, và **người dùng có đặc quyền đang đăng nhập**, việc đánh cắp hoặc nhân bản token của người dùng đó thường kín đáo hơn dump **LSASS**. Trong nhiều cuộc xâm nhập thực tế, việc này đủ để:<sup>[[2]](#references)</sup>

- chạy các hành động cục bộ với tư cách người dùng đó
- truy cập tài nguyên từ xa với tư cách người dùng đó
- thực hiện các thao tác AD mà không cần trích xuất thông tin xác thực có thể tái sử dụng trước

Để xem ví dụ về **chiếm quyền token phiên/người dùng** từ context có đặc quyền, hãy xem [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Lưu ý rằng các API như **`WTSQueryUserToken`** dành cho **service có độ tin cậy cao** và thường yêu cầu **`LocalSystem` + `SeTcbPrivilege`**, nên chủ yếu hữu ích khi bạn đã kiểm soát được context cấp service. Để xem các cách lấy **SYSTEM** trước bằng đặc quyền cụ thể, hãy tham khảo các trang bên dưới.

### Đặc quyền token

Tìm hiểu những **đặc quyền token có thể bị lạm dụng để leo thang đặc quyền:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Tham khảo [**toàn bộ các đặc quyền token có thể có và một số định nghĩa trên trang bên ngoài này**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Tìm hiểu và lạm dụng Access Tokens — Phần II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Lạm dụng token của Windows để xâm phạm Active Directory mà không chạm đến LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Giải mã lệnh "make_token" của Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Tokens - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Cách User Account Control hoạt động - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Các cấp độ impersonation - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Liệt kê TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Token bị hạn chế - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Hàm CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Hàm CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Hàm DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
