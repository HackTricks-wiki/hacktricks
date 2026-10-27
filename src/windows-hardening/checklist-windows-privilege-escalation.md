# Checklist - Leo thang đặc quyền cục bộ trên Windows

{{#include ../banners/hacktricks-training.md}}

### **Công cụ tốt nhất để tìm các vector leo thang đặc quyền cục bộ trên Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Thông tin hệ thống](windows-local-privilege-escalation/index.html#system-info)

- [ ] Lấy [**thông tin hệ thống**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tìm **kernel** [**exploits bằng script**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Dùng **Google để tìm kiếm** **kernel exploits**
- [ ] Dùng **searchsploit để tìm kiếm** **kernel exploits**
- [ ] Có thông tin đáng chú ý trong [**biến môi trường**](windows-local-privilege-escalation/index.html#environment) không?
- [ ] Có mật khẩu trong [**lịch sử PowerShell**](windows-local-privilege-escalation/index.html#powershell-history) không?
- [ ] Có thông tin đáng chú ý trong [**cài đặt Internet**](windows-local-privilege-escalation/index.html#internet-settings) không?
- [ ] [**Ổ đĩa**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Tác nhân bên thứ ba tự cập nhật / lạm dụng IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Liệt kê nhật ký/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kiểm tra cài đặt [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)và [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Kiểm tra [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kiểm tra xem [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)có hoạt động không
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Thông tin xác thực đã lưu đệm**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kiểm tra xem có [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) nào không
- [ ] [**Chính sách AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / nâng quyền im lặng bằng UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Truyền registry khả năng truy cập của Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Đặc quyền người dùng**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kiểm tra [**đặc quyền của người dùng hiện tại**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Bạn có [**thuộc nhóm đặc quyền nào**](windows-local-privilege-escalation/index.html#privileged-groups) không?
- [ ] Kiểm tra xem bạn có [bất kỳ token nào sau đây được bật](windows-local-privilege-escalation/index.html#token-manipulation) không: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Kiểm tra xem bạn có [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) để đọc raw volume và bypass ACL của file không
- [ ] [**Phiên người dùng**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kiểm tra[ **thư mục home của người dùng**](windows-local-privilege-escalation/index.html#home-folders) (có quyền truy cập không?)
- [ ] Kiểm tra [**chính sách mật khẩu**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Có gì[ **trong Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mạng](windows-local-privilege-escalation/index.html#network)

- [ ] Kiểm tra [**thông tin mạng**](windows-local-privilege-escalation/index.html#network) **hiện tại**
- [ ] Kiểm tra **các dịch vụ cục bộ ẩn** không cho phép truy cập từ bên ngoài

### [Tiến trình đang chạy](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Quyền đối với file và thư mục**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) của binary tiến trình
- [ ] [**Đào mật khẩu trong bộ nhớ**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Ứng dụng GUI không an toàn**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Đánh cắp thông tin xác thực từ **các tiến trình đáng chú ý** bằng `ProcDump.exe`? (firefox, chrome, v.v.)

### [Dịch vụ](windows-local-privilege-escalation/index.html#services)

- [ ] [Bạn có thể **sửa đổi dịch vụ nào** không?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Bạn có thể **sửa đổi** **binary** được **thực thi** bởi **dịch vụ** nào không?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Bạn có thể **sửa đổi** **registry** của **dịch vụ** nào không?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Bạn có thể khai thác **đường dẫn binary dịch vụ** không được đặt trong dấu ngoặc kép nào không?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: liệt kê và kích hoạt các dịch vụ có đặc quyền](windows-local-privilege-escalation/service-triggers.md)

### [**Ứng dụng**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Quyền ghi** [**trên các ứng dụng đã cài đặt**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Ứng dụng khởi động cùng hệ thống**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Driver**](windows-local-privilege-escalation/index.html#drivers) **dễ bị tấn công**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Bạn có thể **ghi vào thư mục nào trong PATH** không?
- [ ] Có binary dịch vụ nào đã biết **cố tải DLL không tồn tại** không?
- [ ] Bạn có thể **ghi** vào **thư mục chứa binary** nào không?

### [Mạng](windows-local-privilege-escalation/index.html#network)

- [ ] Liệt kê mạng (share, giao diện, route, máy ngang hàng, ...)
- [ ] Đặc biệt chú ý đến các dịch vụ mạng đang lắng nghe trên localhost (127.0.0.1)

### [Thông tin xác thực Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Thông tin xác thực [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Có thể sử dụng thông tin xác thực trong [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) không?
- [ ] Có [**thông tin xác thực DPAPI**](windows-local-privilege-escalation/index.html#dpapi) đáng chú ý không?
- [ ] Mật khẩu của [**mạng Wifi**](windows-local-privilege-escalation/index.html#wifi) đã lưu?
- [ ] Có thông tin đáng chú ý trong [**các kết nối RDP đã lưu**](windows-local-privilege-escalation/index.html#saved-rdp-connections) không?
- [ ] Có mật khẩu trong [**các lệnh mới chạy gần đây**](windows-local-privilege-escalation/index.html#recently-run-commands) không?
- [ ] Mật khẩu trong [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Có [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe) không? Thông tin xác thực?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [File và Registry (thông tin xác thực)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Thông tin xác thực**](windows-local-privilege-escalation/index.html#putty-creds) **và** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] Có [**SSH key trong registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) không?
- [ ] Có mật khẩu trong [**file unattended**](windows-local-privilege-escalation/index.html#unattended-files) không?
- [ ] Có bản sao lưu [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) nào không?
- [ ] Nếu có [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), thử đọc raw volume để lấy `SAM`, `SYSTEM`, dữ liệu DPAPI và `MachineKeys`
- [ ] [**Thông tin xác thực cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Có file [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) không?
- [ ] Có [**mật khẩu GPP đã lưu đệm**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) không?
- [ ] Có mật khẩu trong [**file cấu hình Web IIS**](windows-local-privilege-escalation/index.html#iis-web-config) không?
- [ ] Có thông tin đáng chú ý trong [**log** **web**](windows-local-privilege-escalation/index.html#logs) không?
- [ ] Bạn có muốn [**yêu cầu người dùng cung cấp thông tin xác thực**](windows-local-privilege-escalation/index.html#ask-for-credentials) không?
- [ ] Có [**file đáng chú ý trong Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) không?
- [ ] Có [**registry khác chứa thông tin xác thực**](windows-local-privilege-escalation/index.html#inside-the-registry) không?
- [ ] Có gì trong [**dữ liệu trình duyệt**](windows-local-privilege-escalation/index.html#browsers-history) (cơ sở dữ liệu, lịch sử, dấu trang, ...)?
- [ ] [**Tìm mật khẩu tổng quát**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) trong file và registry
- [ ] [**Công cụ**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) tự động tìm mật khẩu

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Bạn có quyền truy cập vào handler nào của tiến trình do administrator chạy không?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kiểm tra xem bạn có thể lạm dụng nó không

## References

- [1] [Project Zero - Bypass Admin Protection bằng cách lạm dụng UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
