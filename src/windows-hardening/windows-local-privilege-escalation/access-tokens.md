# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Mỗi tiến trình có một **primary access token** xác định ngữ cảnh bảo mật của nó. Một thread thường sử dụng token đó, nhưng đôi khi cũng có thể tạm thời có một **impersonation token**. Token chứa SID của người dùng, SID của nhóm, các đặc quyền, thông tin về mức độ toàn vẹn và SID đăng nhập cho phiên đăng nhập. Các tiến trình thường kế thừa một tham chiếu đến primary token của tiến trình cha; chúng không nhận được một bản sao độc lập của nội dung token.<sup>[[4]](#references)</sup>

Bạn có thể xem thông tin này bằng cách thực thi `whoami /all`

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

hoặc sử dụng _Process Explorer_ từ Sysinternals (chọn tiến trình và truy cập tab "Security"):

![Access Tokens - Access Tokens: hoặc sử dụng Process Explorer từ Sysinternals (chọn tiến trình và truy cập tab "Security")](<../../images/image (772).png>)

### Quản trị viên cục bộ

Khi **UAC Admin Approval Mode** áp dụng cho tài khoản quản trị viên, đăng nhập tương tác sẽ tạo một token quản trị viên đầy đủ và một token đã lọc. Explorer và các tiến trình con thông thường mặc định sử dụng token đã lọc. Một yêu cầu nâng quyền như **Run as administrator** yêu cầu UAC khởi chạy chương trình bằng token đầy đủ. Hành vi cụ thể sẽ khác với tài khoản Administrator tích hợp sẵn và khi Admin Approval Mode bị tắt.<sup>[[5]](#references)</sup>

Đọc [**trang UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md) chuyên biệt để tìm hiểu các kỹ thuật bypass và chi tiết về chính sách.

Trên thực tế, điều này có nghĩa là **shell quản trị viên chưa được nâng quyền thường chạy bằng token đã lọc**. Vì vậy, `whoami /groups` thường hiển thị **`BUILTIN\Administrators` là `Deny only`** cho đến khi tiến trình được nâng quyền. Bên trong, Windows giữ một **token đã liên kết được nâng quyền** (`TokenLinkedToken`) và theo dõi trạng thái bằng các trường như `TokenElevationType`.

### Mạo danh người dùng bằng thông tin xác thực

Nếu bạn có **thông tin xác thực hợp lệ của bất kỳ người dùng nào khác**, bạn có thể **tạo** một **phiên đăng nhập mới** bằng các thông tin xác thực đó :

```
runas /user:domain\username cmd.exe
```

**access token** cũng có **tham chiếu** đến các phiên đăng nhập bên trong **LSASS**; điều này hữu ích nếu tiến trình cần truy cập một số đối tượng trên mạng.\
Bạn có thể khởi chạy một tiến trình **sử dụng thông tin xác thực khác để truy cập các dịch vụ mạng** bằng cách:

```
runas /user:domain\username /netonly cmd.exe
```

Điều này hữu ích nếu bạn có credentials để truy cập các đối tượng trong network, nhưng các credentials đó không hợp lệ trên host hiện tại vì chúng chỉ được dùng trong network (trên host hiện tại, quyền của user hiện tại sẽ được sử dụng).

#### Chi tiết về `runas /netonly`

`runas /netonly` (và các C2 helper như `make_token`) tạo token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Hiểu rõ điều này rất hữu ích khi lateral movement vì:<sup>[[3]](#references)</sup>

- **Trên máy cục bộ**, process mới giữ nguyên **danh tính cục bộ**, các group, integrity level và hầu hết các quyết định truy cập như token hiện tại.
- **Trên máy từ xa**, xác thực outbound có thể dùng **credentials được cung cấp** cho SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Vì vậy, `whoami` vẫn có thể hiển thị **user cục bộ ban đầu**, trong khi quyền truy cập network được thực hiện bằng **account thay thế**.

Đây là lựa chọn rất phù hợp khi credentials hợp lệ trong domain hoặc trên host khác, nhưng user **không thể hoặc không nên đăng nhập cục bộ** vào máy hiện tại.

### Các loại token

Có hai loại token:<sup>[[4]](#references)[[6]](#references)</sup>

- **Primary token**: Đại diện cho security context của một process. Process con thường kế thừa primary token của process cha, trong khi các API tạo process bằng token được chỉ định có yêu cầu riêng về quyền truy cập token và privilege của caller.
- **Impersonation token**: Cho phép một thread phía server tạm thời sử dụng security context của client để kiểm tra quyền truy cập. Token này có bốn mức:
  - **Anonymous**: Cấp cho server quyền truy cập tương tự một user chưa xác định.
  - **Identification**: Cho phép server xác minh danh tính của client mà không sử dụng danh tính đó để truy cập đối tượng.
  - **Impersonation**: Cho phép server hoạt động dưới danh tính của client.
  - **Delegation**: Cho phép server impersonate client trên các hệ thống từ xa khi cơ chế xác thực và cấu hình account hỗ trợ delegation.

#### Đánh giá token đã thu thập trước khi sử dụng

Đừng chọn token chỉ dựa trên username. Cùng một account có thể có nhiều token với logon session, service SID, privilege, integrity level, restriction và network credential khác nhau.<sup>[[9]](#references)</sup> Dùng `GetTokenInformation` để truy vấn ít nhất **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** và **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Token bị hạn chế có thể chứa deny-only SID, privilege đã bị loại bỏ và restricting SID. Khi có restricting SID, Windows thực hiện một lần kiểm tra quyền truy cập với các SID được bật và một lần khác với restricting SID; **cả hai lần kiểm tra đều phải cho phép truy cập**. Vì vậy, SID của user có vẻ hữu ích hoặc group được bật trong kết quả không đủ để chứng minh token có thể truy cập đối tượng mục tiêu.<sup>[[8]](#references)</sup>

Dùng quy trình quyết định sau cho các yêu cầu về token và tạo process đã được ghi nhận:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Primary token** cần một handle có `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` trước khi có thể truyền token đó cho `CreateProcessWithTokenW` hoặc `CreateProcessAsUserW`.
2. Chuyển **impersonation token** bằng `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Token ở mức Identification có thể cung cấp dữ liệu danh tính nhưng không thể thực hiện kiểm tra quyền truy cập dưới danh nghĩa client đó.
3. `CreateProcessWithTokenW` cần `SeImpersonatePrivilege` và khởi chạy process con trong session của caller. Ngược lại, `CreateProcessAsUserW` dùng session của token nhưng thường cần `SeIncreaseQuotaPrivilege` và có thể cần `SeAssignPrimaryTokenPrivilege`. Nếu có credentials nhưng thiếu các privilege này, `CreateProcessWithLogonW` là phương án thay thế được ghi nhận.

#### Tìm token handle, không chỉ tìm process owner

Chỉ mở primary token của từng process có thể bỏ sót **impersonation token được giữ dưới dạng handle thông thường** bên trong service và broker process. Một quy trình có thể tái sử dụng để kiểm tra handle table là liệt kê system handle, lọc token object, mở từng owner bằng `PROCESS_DUP_HANDLE`, duplicate handle ứng viên vào process hiện tại, rồi truy vấn các trường trên. Xác nhận handle đã duplicate có `TOKEN_QUERY` và `TOKEN_DUPLICATE`; nhìn thấy token handle không có nghĩa là có thể duplicate nó thành primary token sử dụng được. Process được bảo vệ và process DACL vẫn có thể chặn handle tới owner process.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` tự động hóa việc liệt kê cả primary token của process lẫn token handle được giữ lại. `list_token` giữ lại một ứng viên ưu tiên cho mỗi username, còn `list_all_token` in ra mọi ứng viên. PID giới hạn việc liệt kê vào một owner process.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Để kiểm tra thủ công và xác minh quyền truy cập, **TokenUniverse** có thể mở token của tiến trình/luồng, tìm các handle token hiện có, kiểm tra các hạn chế và phiên đăng nhập, sao chép token và thử một số phương thức tạo tiến trình.<sup>[[13]](#references)</sup> Để tìm hiểu về primitive handle liên tiến trình nền tảng, xem:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Tìm token mạo danh của luồng đang hoạt động

Một luồng dịch vụ có thể tạm thời mạo danh client ngay cả khi **primary token của tiến trình** thuộc về tài khoản dịch vụ, vì vậy việc quét chủ sở hữu tiến trình có thể bỏ sót ngữ cảnh của client.<sup>[[4]](#references)</sup> TokenUniverse có thể liệt kê các token tiến trình/luồng có thể truy cập; trong System Informer, xem tab **Threads** của tiến trình và cột **Impersonation** để tìm các luồng tiềm năng.<sup>[[13]](#references)[[14]](#references)</sup>

Để kiểm tra API có mục tiêu, tạo snapshot `TH32CS_SNAPTHREAD`, lọc `THREADENTRY32.th32OwnerProcessID` theo PID của dịch vụ, sau đó gọi `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` và `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)` cho từng luồng có thể truy cập.<sup>[[15]](#references)[[16]](#references)</sup> `TRUE` khiến quá trình kiểm tra quyền truy cập khi mở token sử dụng ngữ cảnh **tiến trình** của caller; điều này rất quan trọng nếu chính scanner đang mạo danh ở mức identification.<sup>[[17]](#references)</sup> Truy vấn user, loại token, mức mạo danh và ID phiên đăng nhập của token trước khi thử quy trình sao chép/tạo tiến trình ở trên.<sup>[[7]](#references)</sup> Luồng có thể ngừng mạo danh giữa lúc liệt kê và mở; không có token, token anonymous, luồng được bảo vệ, DACL của luồng và DACL của token đều có thể ngăn việc thu thập.<sup>[[16]](#references)[[17]](#references)</sup> Không giống như quét các handle token mà dịch vụ giữ lại, cách này kiểm tra **token luồng hiện được gán**.

Để tìm hiểu đường tấn công lấy token luồng bằng cách khiến một client có đặc quyền kết nối đến pipe của bạn, thay vì quét các luồng hiện có, xem [mạo danh client qua named pipe](named-pipe-client-impersonation.md).

#### Mạo danh Token

Dùng module _**incognito**_ của metasploit, nếu có đủ đặc quyền, bạn có thể dễ dàng **liệt kê** và **mạo danh** các **token** khác. Cách này có thể hữu ích để thực hiện **hành động như thể bạn là người dùng khác**. Bạn cũng có thể **leo thang đặc quyền** bằng kỹ thuật này.

Một số lưu ý thực tế dễ bị quên khi thao tác:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** yêu cầu caller có **`SeImpersonatePrivilege`**, và tiến trình mới sẽ chạy trong **phiên của caller**.
- **`CreateProcessAsUserW`** là phương án dự phòng có thể dùng khi `CreateProcessWithTokenW` thất bại với mã lỗi `1314`, nhưng chỉ khi caller đáp ứng các yêu cầu đặc quyền của nó. Đây cũng là lựa chọn phù hợp khi tiến trình con cần chạy trong **phiên được token tham chiếu**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** trả về một **impersonation token**. Hãy chuyển đổi token này bằng **`DuplicateTokenEx(..., TokenPrimary, ...)`** trước khi tạo tiến trình. Ngay cả sau khi chuyển đổi, tiến trình kết quả vẫn không thể dùng kiểu đăng nhập mạng này để truy cập các share hoặc máy in từ xa cần xác thực: kiểu đăng nhập này không lưu thông tin xác thực vào bộ nhớ đệm. Nếu có thông tin xác thực và cần truy cập mạng tiếp theo, hãy dùng kiểu đăng nhập tương tác hoặc network-cleartext; đừng nhầm với `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), vốn giữ nguyên danh tính cục bộ trong khi cung cấp thông tin xác thực cho các kết nối đi ra.<sup>[[18]](#references)</sup>
- Không phải impersonation token nào cũng hữu ích như nhau: **`SecurityIdentification`** cho phép bạn kiểm tra user nhưng **không thể hành động thay họ**. Nếu một primitive coercion hoặc client pipe/RPC chỉ cung cấp cho bạn token ở mức identification, hãy kiểm tra **`TokenImpersonationLevel`** và chuyển sang primitive tạo ra **`SecurityImpersonation`** hoặc cao hơn.

#### Đánh cắp token mà không đụng đến LSASS

Nếu bạn đã có ngữ cảnh **dịch vụ** hoặc **SYSTEM** và một **người dùng có đặc quyền đang đăng nhập**, việc đánh cắp hoặc sao chép token của người dùng đó thường kín đáo hơn việc dump **LSASS**. Trong nhiều vụ xâm nhập thực tế, chỉ cần vậy là đủ để:<sup>[[2]](#references)</sup>

- thực hiện các hành động cục bộ với tư cách người dùng đó
- truy cập tài nguyên từ xa với tư cách người dùng đó
- thực hiện các thao tác AD mà không cần trích xuất thông tin xác thực có thể tái sử dụng trước

Để xem ví dụ về **chiếm quyền session/token của user** từ một ngữ cảnh có đặc quyền, xem [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Lưu ý rằng các API như **`WTSQueryUserToken`** dành cho **dịch vụ có mức độ tin cậy cao** và thường yêu cầu **`LocalSystem` + `SeTcbPrivilege`**, vì vậy chúng chủ yếu hữu ích khi bạn đã kiểm soát ngữ cảnh cấp dịch vụ. Để biết các cách lấy **SYSTEM** trước theo từng đặc quyền cụ thể, xem các trang bên dưới.

### Đặc quyền Token

Tìm hiểu những **đặc quyền token có thể bị lạm dụng để leo thang đặc quyền:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Xem [**tất cả các đặc quyền token có thể có và một số định nghĩa trên trang bên ngoài này**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Tìm hiểu và lạm dụng Access Token — Phần II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Lạm dụng token Windows để xâm phạm Active Directory mà không đụng đến LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Làm sáng tỏ lệnh "make_token" của Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Access Token - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Cách User Account Control hoạt động - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Các mức mạo danh - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Liệt kê TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Token bị hạn chế - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Hàm CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Hàm CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Hàm DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Yêu cầu tính năng token luồng trong System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Duyệt danh sách luồng - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
