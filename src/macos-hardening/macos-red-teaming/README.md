# Red Teaming trên macOS

{{#include ../../banners/hacktricks-training.md}}


## Lạm dụng MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Nếu bạn **chiếm được thông tin đăng nhập admin** để truy cập nền tảng quản lý, bạn có thể **chiếm quyền kiểm soát tất cả máy tính** bằng cách phát tán malware lên các máy đó.

Để red teaming trong môi trường MacOS, bạn nên tìm hiểu cách hoạt động của MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Dùng MDM làm C2

MDM có quyền cài đặt, truy vấn hoặc xóa profile, cài ứng dụng, tạo tài khoản admin cục bộ, đặt firmware password, thay đổi khóa FileVault...

Để chạy MDM của riêng mình, bạn cần **CSR được vendor ký**. Bạn có thể thử xin chữ ký tại [**https://mdmcert.download/**](https://mdmcert.download/). Để chạy MDM của riêng mình cho các thiết bị Apple, bạn có thể dùng [**MicroMDM**](https://github.com/micromdm/micromdm).

Việc đăng ký MDM **không** tự động khiến TLS certificate của máy chủ quản lý trở thành CA đáng tin cậy hoặc cấp danh tính ký ứng dụng. Nếu máy chủ dùng private CA, cần cung cấp root và intermediate certificate trong enrollment profile hoặc một trust profile riêng. Client identity dùng để xác thực MDM là một certificate khác.<sup>[[7]](#references)</sup>

Enrollment profile MDM đã tải xuống (`.mobileconfig`) phải được mở và phê duyệt trong **System Settings → General → Device Management**. Chỉ đặt profile này trong `.pkg` được cài đặt với quyền root hoặc trong ZIP được mở bằng Safari sẽ không âm thầm đăng ký một máy Mac hiện hành. Xem [hành vi của configuration profile](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Automated Device Enrollment trong quá trình Setup Assistant là một quy trình riêng. Xem [đăng ký trái phép thiết bị của tổ chức khác](macos-mdm/enrolling-devices-in-other-organisations.md) để biết các điều kiện tiên quyết khác.<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** sử dụng kỹ thuật này.

### Triển khai package thông qua MDM được kiểm soát

Trên **máy Mac được giám sát đang chạy macOS 26 trở lên**, quyền kiểm soát dịch vụ MDM cho phép khai báo `com.apple.configuration.package` trong system scope.<sup>[[10]](#references)</sup> Package phải có chữ ký mà thiết bị có thể xác minh, nhưng ứng dụng bên trong không cần chữ ký Developer ID riêng: Gatekeeper không kiểm tra ứng dụng được cài đặt thông qua quản lý thiết bị.<sup>[[11]](#references)</sup> Chỉ có TLS certificate của máy chủ đáng tin cậy không đồng nghĩa với việc operator có private key hoặc quyền sử dụng để ký package đó.<sup>[[11]](#references)[[12]](#references)</sup>

Tạo một package thử nghiệm đã ký, tính digest của nó và đăng package cùng plist `ManifestURL` qua HTTPS. Manifest cần có một asset `software-package` với URL và SHA-256, cùng `bundle-identifier` và `bundle-version` duy nhất.<sup>[[11]](#references)</sup> Sau đó gửi package declaration có URL của manifest và đặt `InstallBehavior.Install` thành `Required`; kiểm tra mục trạng thái `package.list` để biết package đã cài đặt hay có lỗi.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Một khai báo cài đặt bắt buộc tối thiểu, được gửi qua dịch vụ MDM, trông như sau (thay URL và cả hai UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Lạm dụng JAMF PRO

JAMF có thể chạy **custom scripts** (script do sysadmin phát triển), **native payloads** (tạo tài khoản cục bộ, đặt mật khẩu EFI, giám sát file/process...) và **MDM** (cấu hình thiết bị, chứng chỉ thiết bị...).<sup>[[5]](#references)</sup>

#### Tự đăng ký JAMF

Truy cập một trang như `https://<company-name>.jamfcloud.com/enroll/` để kiểm tra xem họ có **bật tính năng tự đăng ký** hay không. Nếu có, trang này có thể **yêu cầu thông tin xác thực để truy cập**.

Bạn có thể dùng script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) để thực hiện tấn công password spraying.

Ngoài ra, sau khi tìm được thông tin xác thực hợp lệ, bạn có thể brute-force các tên người dùng khác bằng biểu mẫu sau:

![Lạm dụng JAMF PRO - Tự đăng ký JAMF: Ngoài ra, sau khi tìm được thông tin xác thực hợp lệ, bạn có thể brute-force các tên người dùng khác bằng biểu mẫu sau](<../../images/image (107).png>)

#### Xác thực thiết bị JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binary **`jamf`** chứa bí mật dùng để mở keychain; tại thời điểm phát hiện, bí mật này được **dùng chung** cho mọi người và là: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Ngoài ra, jamf **duy trì persistence** dưới dạng **LaunchDaemon** tại **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Chiếm quyền thiết bị JAMF

**URL** của **JSS** (Jamf Software Server) mà **`jamf`** sẽ sử dụng nằm trong **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Tệp này về cơ bản chứa URL:

```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
	<key>is_virtual_machine</key>
	<false/>
	<key>jss_url</key>
	<string>https://subdomain-company.jamfcloud.com/</string>
	<key>last_management_framework_change_id</key>
	<integer>4</integer>
[...]
```

Vì vậy, kẻ tấn công có thể thả một gói độc hại (`pkg`) để **ghi đè tệp này** khi cài đặt, đặt **URL thành listener Mythic C2 từ một agent Typhon**, qua đó lạm dụng JAMF làm C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### Giả mạo JAMF

Để **giả mạo giao tiếp** giữa thiết bị và JMF, bạn cần:

- **UUID** của thiết bị: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** tại: `/Library/Application\ Support/Jamf/JAMF.keychain`, chứa chứng chỉ thiết bị

Với thông tin này, **tạo một VM** có **UUID phần cứng bị đánh cắp** và **SIP đã tắt**, chép **JAMF keychain** vào đó, **hook** **agent** Jamf và đánh cắp thông tin của nó.

#### Đánh cắp secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Bạn cũng có thể theo dõi thư mục `/Library/Application Support/Jamf/tmp/` để tìm các **custom script** mà quản trị viên có thể muốn chạy thông qua Jamf, vì chúng **được đặt ở đây, thực thi rồi bị xóa**. Những script này **có thể chứa thông tin xác thực**.

Tuy nhiên, **thông tin xác thực** cũng có thể được truyền cho các script này dưới dạng **tham số**, vì vậy bạn cần theo dõi `ps aux | grep -i jamf` (ngay cả khi không phải root).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) có thể lắng nghe các file mới được thêm vào và các đối số tiến trình mới.

### Truy cập từ xa macOS

Và cả các **protocol** **mạng** "đặc biệt" của **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Trong một số trường hợp, bạn sẽ thấy **máy tính MacOS được kết nối với AD**. Trong tình huống này, hãy thử **enumerate** Active Directory như bạn vẫn thường làm. Tìm một số **hướng dẫn** trong các trang sau:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Một số **công cụ MacOS cục bộ** cũng có thể hữu ích là `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Ngoài ra còn có một số công cụ dành cho MacOS để tự động liệt kê AD và thao tác với kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound là phần mở rộng của công cụ Bloodhound audting, cho phép thu thập và nhập các mối quan hệ Active Directory trên máy chủ MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost là một dự án Objective-C được thiết kế để tương tác với các API Heimdal krb5 trên macOS. Mục tiêu của dự án là hỗ trợ kiểm thử bảo mật Kerberos trên thiết bị macOS hiệu quả hơn bằng cách sử dụng API gốc mà không cần bất kỳ framework hoặc package nào khác trên mục tiêu.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Công cụ JavaScript for Automation (JXA) để liệt kê Active Directory.

### Thông tin miền

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Người dùng

Ba loại người dùng trên MacOS là:

- **Người dùng cục bộ** — Được quản lý bởi dịch vụ OpenDirectory cục bộ, không kết nối với Active Directory theo bất kỳ cách nào.
- **Người dùng mạng** — Người dùng Active Directory tạm thời, cần kết nối với máy chủ DC để xác thực.
- **Người dùng di động** — Người dùng Active Directory có bản sao lưu cục bộ cho thông tin đăng nhập và tệp của họ.

Thông tin cục bộ về người dùng và nhóm được lưu trong thư mục _/var/db/dslocal/nodes/Default._\
Ví dụ: thông tin về người dùng có tên _mark_ được lưu trong _/var/db/dslocal/nodes/Default/users/mark.plist_, còn thông tin về nhóm _admin_ nằm trong _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Ngoài việc sử dụng các cạnh HasSession và AdminTo, **MacHound bổ sung ba cạnh mới** vào cơ sở dữ liệu Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - thực thể được phép SSH đến máy chủ
- **CanVNC** - thực thể được phép VNC đến máy chủ
- **CanAE** - thực thể được phép thực thi các tập lệnh AppleEvent trên máy chủ

```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```

Thông tin thêm tại [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Mật khẩu Computer$

Lấy mật khẩu bằng cách sử dụng:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Có thể truy cập mật khẩu **`Computer$`** bên trong System keychain.

### Over-Pass-The-Hash

Lấy TGT cho một người dùng và dịch vụ cụ thể:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Sau khi thu thập TGT, có thể inject nó vào phiên hiện tại bằng:

```bash
bifrost --action asktgt --username test_lab_admin \
       --hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
       --enctype aes256 --domain test.lab.local
```

### Kerberoasting

```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
       --username [user] --hash [hash] --enctype [enctype]
```

Với các service ticket đã thu được, có thể thử truy cập các share trên máy tính khác:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Truy cập Keychain

Keychain rất có thể chứa thông tin nhạy cảm mà nếu truy cập được mà không tạo lời nhắc, có thể giúp thúc đẩy một bài tập red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Dịch vụ bên ngoài

MacOS Red Teaming khác với Windows Red Teaming thông thường vì **MacOS thường được tích hợp trực tiếp với một số nền tảng bên ngoài**. Một cấu hình phổ biến của MacOS là truy cập máy tính bằng **thông tin xác thực được đồng bộ qua OneLogin, đồng thời truy cập một số dịch vụ bên ngoài** (như github, aws...) thông qua OneLogin.

## Các kỹ thuật Red Team khác

### Safari

Khi tải xuống một tệp trong Safari, nếu đó là tệp "an toàn", tệp sẽ **tự động được mở**. Ví dụ, nếu bạn **tải xuống tệp zip**, tệp sẽ tự động được giải nén:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Đi hái táo: Red Teaming môi trường MacOS năm 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Giới thiệu MacHound: Giải pháp cho các cuộc tấn công dựa trên Active Directory trên macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Các lệnh liệt kê domain (tương đương dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Hãy sang phe bóng tối, chúng tôi có Táo: Biến quản lý macOS thành công cụ xấu](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Góc nhìn của kẻ tấn công về các cấu hình Jamf" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Khám phá Active Directory bằng máy Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Quản lý chứng chỉ cho dịch vụ và thiết bị quản lý thiết bị](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Sử dụng configuration profile trên máy Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Triển khai enrollment profile quản lý thiết bị](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Khai báo package](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Cài đặt package](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Danh tính](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
