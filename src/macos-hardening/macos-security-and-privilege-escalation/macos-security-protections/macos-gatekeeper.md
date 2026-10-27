# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** là một tính năng bảo mật được phát triển cho hệ điều hành Mac, nhằm đảm bảo người dùng **chỉ chạy phần mềm đáng tin cậy** trên hệ thống của họ. Tính năng này hoạt động bằng cách **xác thực phần mềm** mà người dùng tải xuống và cố mở từ **các nguồn bên ngoài App Store**, chẳng hạn như ứng dụng, plug-in hoặc gói cài đặt.

Cơ chế cốt lõi của Gatekeeper nằm ở quy trình **xác minh**. Tính năng này kiểm tra xem phần mềm đã tải xuống có **được ký bởi nhà phát triển được công nhận** hay không, qua đó đảm bảo tính xác thực của phần mềm. Ngoài ra, Gatekeeper xác định xem phần mềm có được Apple **notarized** hay không, nhằm xác nhận rằng phần mềm không chứa nội dung độc hại đã biết và chưa bị chỉnh sửa sau khi notarization.

Bên cạnh đó, Gatekeeper tăng cường quyền kiểm soát và bảo mật cho người dùng bằng cách **nhắc người dùng phê duyệt việc mở** phần mềm đã tải xuống trong lần đầu tiên. Biện pháp bảo vệ này giúp ngăn người dùng vô tình chạy mã thực thi có khả năng gây hại mà họ có thể nhầm là tệp dữ liệu vô hại.

### Application Signatures

Application signature, còn được gọi là code signature, là một thành phần thiết yếu trong cơ sở hạ tầng bảo mật của Apple. Chúng được dùng để **xác minh danh tính của tác giả phần mềm** (nhà phát triển) và đảm bảo mã chưa bị chỉnh sửa kể từ lần ký gần nhất.

Quy trình hoạt động như sau:

1. **Ký ứng dụng:** Khi sẵn sàng phân phối ứng dụng, nhà phát triển **ký ứng dụng bằng khóa riêng**. Khóa riêng này gắn với **chứng chỉ Apple cấp cho nhà phát triển** khi họ đăng ký Apple Developer Program. Quá trình ký gồm việc tạo hash mật mã của tất cả các thành phần trong ứng dụng rồi mã hóa hash này bằng khóa riêng của nhà phát triển.
2. **Phân phối ứng dụng:** Sau đó, ứng dụng đã ký được phân phối cho người dùng cùng với chứng chỉ của nhà phát triển, trong đó có khóa công khai tương ứng.
3. **Xác minh ứng dụng:** Khi người dùng tải xuống và thử chạy ứng dụng, hệ điều hành Mac dùng khóa công khai trong chứng chỉ của nhà phát triển để giải mã hash. Sau đó, hệ thống tính toán lại hash dựa trên trạng thái hiện tại của ứng dụng và so sánh với hash đã giải mã. Nếu chúng khớp, điều đó có nghĩa là **ứng dụng chưa bị sửa đổi** kể từ khi nhà phát triển ký, và hệ thống cho phép ứng dụng chạy.

Application signature là một phần thiết yếu của công nghệ Gatekeeper của Apple. Khi người dùng cố **mở một ứng dụng tải xuống từ Internet**, Gatekeeper sẽ xác minh application signature. Nếu ứng dụng được ký bằng chứng chỉ do Apple cấp cho nhà phát triển đã biết và mã chưa bị chỉnh sửa, Gatekeeper cho phép ứng dụng chạy. Nếu không, Gatekeeper chặn ứng dụng và cảnh báo người dùng.

Kể từ macOS Catalina, **Gatekeeper cũng kiểm tra xem ứng dụng đã được Apple notarized hay chưa**, bổ sung thêm một lớp bảo mật. Quy trình notarization kiểm tra ứng dụng để tìm các vấn đề bảo mật đã biết và mã độc; nếu ứng dụng vượt qua các bước kiểm tra này, Apple sẽ thêm một ticket vào ứng dụng để Gatekeeper xác minh.

#### Check Signatures

Khi kiểm tra một **mẫu malware**, bạn luôn nên **kiểm tra chữ ký** của binary vì **nhà phát triển** ký nó có thể đã **liên quan** đến **malware**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```

### Công chứng

Quy trình công chứng của Apple là một biện pháp bảo vệ bổ sung nhằm bảo vệ người dùng khỏi phần mềm có khả năng gây hại. Quy trình này bao gồm việc **nhà phát triển gửi ứng dụng để** **Dịch vụ Công chứng của Apple** **kiểm tra**; không nên nhầm lẫn dịch vụ này với App Review. Đây là một **hệ thống tự động** kiểm tra kỹ phần mềm được gửi để tìm **nội dung độc hại** và mọi vấn đề tiềm ẩn liên quan đến ký mã.

Nếu phần mềm **vượt qua** quá trình kiểm tra này mà không phát sinh vấn đề đáng lo ngại, Dịch vụ Công chứng sẽ tạo một vé công chứng. Sau đó, nhà phát triển cần **đính kèm vé này vào phần mềm**; quá trình này được gọi là “stapling”. Ngoài ra, vé công chứng cũng được đăng trực tuyến để Gatekeeper, công nghệ bảo mật của Apple, có thể truy cập.

Khi người dùng cài đặt hoặc chạy phần mềm lần đầu, sự hiện diện của vé công chứng — dù được stapling vào tệp thực thi hay tìm thấy trực tuyến — **cho Gatekeeper biết rằng phần mềm đã được Apple công chứng**. Nhờ đó, Gatekeeper hiển thị thông báo mô tả trong hộp thoại khởi chạy lần đầu, cho biết Apple đã kiểm tra phần mềm để tìm nội dung độc hại. Quy trình này giúp người dùng yên tâm hơn về độ an toàn của phần mềm họ cài đặt hoặc chạy trên hệ thống.

### spctl & syspolicyd

> [!CAUTION]
> Lưu ý rằng kể từ phiên bản Sequoia, **`spctl`** không còn cho phép sửa đổi cấu hình Gatekeeper.

**`spctl`** là công cụ CLI dùng để liệt kê và tương tác với Gatekeeper (thông qua các thông điệp XPC gửi đến daemon `syspolicyd`). Ví dụ, có thể xem **trạng thái** của GateKeeper bằng:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Lưu ý rằng GateKeeper chỉ kiểm tra chữ ký đối với **các tệp có thuộc tính Quarantine**, không phải mọi tệp.

GateKeeper sẽ kiểm tra xem một binary có thể được thực thi hay không dựa trên **các tùy chọn và chữ ký**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** là daemon chính chịu trách nhiệm thực thi Gatekeeper. Nó duy trì một database tại `/var/db/SystemPolicy`; có thể tìm thấy mã hỗ trợ [database tại đây](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) và [mẫu SQL tại đây](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Lưu ý rằng database này không bị SIP hạn chế và root có thể ghi vào; database `/var/db/.SystemPolicy-default` được dùng làm bản sao lưu ban đầu trong trường hợp database kia bị hỏng.

Ngoài ra, các bundle **`/var/db/gke.bundle`** và **`/var/db/gkopaque.bundle`** chứa các tệp có quy tắc được chèn vào database. Bạn có thể kiểm tra database này với quyền root bằng lệnh:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

**`syspolicyd`** cũng cung cấp một XPC server với nhiều thao tác như `assess`, `update`, `record` và `cancel`. Các thao tác này cũng có thể được gọi bằng các API **`SecAssessment*`** của **`Security.framework`**, và **`spctl`** thực sự giao tiếp với **`syspolicyd`** qua XPC.

Lưu ý rằng quy tắc đầu tiên kết thúc bằng "**App Store**" và quy tắc thứ hai kết thúc bằng "**Developer ID**". Trong hình trước đó, tùy chọn cho phép chạy ứng dụng từ App Store và từ các nhà phát triển đã xác định đang **được bật**.\
Nếu bạn **thay đổi** cài đặt đó thành App Store, các quy tắc "**Notarized Developer ID" sẽ biến mất**.

Ngoài ra còn có hàng nghìn quy tắc thuộc **loại GKE**:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Đây là các hash từ:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Hoặc bạn có thể liệt kê thông tin trước đó bằng:

```bash
sudo spctl --list
```

Các tùy chọn **`--master-disable`** và **`--global-disable`** của **`spctl`** sẽ **vô hiệu hóa** hoàn toàn các bước kiểm tra chữ ký này:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Khi được bật hoàn toàn, một tùy chọn mới sẽ xuất hiện:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Có thể **kiểm tra xem một ứng dụng có được GateKeeper cho phép hay không** bằng cách:

```bash
spctl --assess -v /Applications/App.app
```

Trên macOS 14 trở lên, **`syspolicy_check`** là công cụ kiểm tra ở cấp cao hữu ích trước khi phân phối một application bundle. Công cụ này đưa ra chẩn đoán về trusted execution hữu ích hơn kết quả `spctl` đơn thuần, dù Apple vẫn khuyến nghị kiểm thử quy trình tải xuống/giải nén/khởi chạy lần đầu thực tế vì quy trình đó cũng kiểm tra việc lan truyền quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Có thể thêm các quy tắc mới trong GateKeeper để cho phép thực thi một số ứng dụng bằng:

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```

Đối với **kernel extensions**, thư mục `/var/db/SystemPolicyConfiguration` chứa các tệp liệt kê những kext được phép tải. Ngoài ra, `spctl` có entitlement `com.apple.private.iokit.nvram-csr` vì nó có thể thêm các kernel extension được phê duyệt trước; các extension này cũng cần được lưu trong NVRAM dưới khóa `kext-allowed-teams`.

#### Quản lý Gatekeeper trên macOS 15 (Sequoia) trở lên

- Cách vượt qua lâu đời bằng Finder **Ctrl+Open / nhấp chuột phải → Open** đã bị loại bỏ; sau hộp thoại chặn đầu tiên, người dùng phải cho phép rõ ràng ứng dụng bị chặn tại **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` không còn được chấp nhận để thay đổi chính sách mà không có sự giám sát của người dùng. Các thao tác sửa đổi cơ sở dữ liệu quy tắc hoặc trạng thái đánh giá toàn cục đã bị deprecated, vì vậy hãy dùng `spctl` để đánh giá và cấu hình việc thực thi thông qua giao diện người dùng hoặc MDM.

Kể từ macOS 15 Sequoia, người dùng cuối không còn có thể bật/tắt chính sách Gatekeeper bằng `spctl`. Việc quản lý được thực hiện qua System Settings hoặc bằng cách triển khai cấu hình MDM có payload `com.apple.systempolicy.control`. Ví dụ đoạn cấu hình để cho phép App Store và nhà phát triển đã xác định (nhưng không cho phép "Anywhere"):

<details>
<summary>Cấu hình MDM để cho phép App Store và nhà phát triển đã xác định</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.systempolicy.control</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.example.gatekeeper</string>
      <key>EnableAssessment</key>
      <true/>
      <key>AllowIdentifiedDevelopers</key>
      <true/>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.example.profile.gatekeeper</string>
  <key>PayloadUUID</key>
  <string>00000000-0000-0000-0000-000000000000</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadDisplayName</key>
  <string>Gatekeeper</string>
</dict>
</plist>
```

</details>

### Tệp Quarantine

Khi **tải xuống** một ứng dụng hoặc tệp, một số **ứng dụng** macOS như trình duyệt web hoặc ứng dụng email sẽ **đính kèm một thuộc tính tệp mở rộng**, thường được gọi là "**quarantine flag**", vào tệp đã tải xuống. Thuộc tính này đóng vai trò như một biện pháp bảo mật để **đánh dấu tệp** là đến từ một nguồn không đáng tin cậy (internet) và có thể tiềm ẩn rủi ro. Tuy nhiên, không phải ứng dụng nào cũng đính kèm thuộc tính này; chẳng hạn, phần mềm máy khách BitTorrent phổ biến thường bỏ qua quy trình này.

**Sự hiện diện của quarantine flag sẽ kích hoạt tính năng bảo mật Gatekeeper của macOS khi người dùng cố thực thi tệp**.

Nếu **quarantine flag không hiện diện** (như với các tệp được tải xuống bằng một số máy khách BitTorrent), **các bước kiểm tra của Gatekeeper có thể không được thực hiện**. Vì vậy, người dùng nên thận trọng khi mở các tệp được tải xuống từ những nguồn kém an toàn hoặc không xác định.

> [!NOTE] > Việc **kiểm tra** **tính hợp lệ** của chữ ký mã là một quy trình **tốn nhiều tài nguyên**, bao gồm tạo **hash** mật mã của mã và tất cả tài nguyên đi kèm. Ngoài ra, việc kiểm tra tính hợp lệ của chứng chỉ còn cần **kiểm tra trực tuyến** với máy chủ của Apple để xác định xem chứng chỉ có bị thu hồi sau khi được cấp hay không. Vì những lý do này, việc kiểm tra đầy đủ chữ ký mã và notarization **không khả thi nếu chạy mỗi khi ứng dụng được khởi chạy**.
>
> Do đó, các bước kiểm tra này **chỉ được thực hiện khi chạy ứng dụng có thuộc tính quarantine**.

> [!WARNING]
> Thuộc tính này phải được **ứng dụng tạo/tải xuống** tệp **thiết lập**.
>
> Tuy nhiên, các tệp được tạo trong sandbox sẽ có thuộc tính này. Các ứng dụng không chạy trong sandbox có thể tự thiết lập thuộc tính này hoặc chỉ định khóa [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) trong **Info.plist** để hệ thống thiết lập thuộc tính mở rộng `com.apple.quarantine` cho các tệp được tạo.

Ngoài ra, tất cả tệp được tạo bởi một tiến trình gọi **`qtn_proc_apply_to_self`** đều bị quarantine. Hoặc API **`qtn_file_apply_to_path`** sẽ thêm thuộc tính quarantine vào đường dẫn tệp được chỉ định.

Có thể **kiểm tra trạng thái và bật/tắt** (cần quyền root) bằng:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Bạn cũng có thể **kiểm tra xem một tệp có thuộc tính mở rộng quarantine hay không** bằng cách:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Kiểm tra **giá trị** của **thuộc tính** **mở rộng** và tìm ứng dụng đã ghi quarantine attr bằng:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

Thực ra, một tiến trình “có thể đặt cờ quarantine cho các tệp mà nó tạo ra” (tôi đã thử áp dụng cờ USER_APPROVED cho một tệp được tạo nhưng không áp dụng được):

<details>

<summary>Mã nguồn áp dụng cờ quarantine</summary>

```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
    QTN_FLAG_DOWNLOAD = 0x0001,
    QTN_FLAG_SANDBOX = 0x0002,
    QTN_FLAG_HARD = 0x0004,
    QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

  qtn_proc_t qp = qtn_proc_alloc();
  qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
  qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
  qtn_proc_apply_to_self(qp);
  qtn_proc_free(qp);

  FILE *fp;
  fp = fopen("thisisquarantined.txt", "w+");
  fprintf(fp, "Hello Quarantine\n");
  fclose(fp);

  return 0;

}
```

Và **xóa** thuộc tính đó bằng:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

Và tìm tất cả các tệp bị cách ly bằng:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Thông tin quarantine cũng được lưu trong cơ sở dữ liệu trung tâm do LaunchServices quản lý tại **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, cho phép GUI lấy dữ liệu về nguồn gốc của tệp. Ngoài ra, các ứng dụng muốn che giấu nguồn gốc của mình có thể ghi đè thông tin này. Việc này cũng có thể được thực hiện thông qua LaunchServices APIs.

#### **libquarantine.dylib**

Thư viện này xuất một số hàm cho phép thao tác với các trường extended attribute.

Các API `qtn_file_*` xử lý chính sách quarantine của tệp; các API `qtn_proc_*` được áp dụng cho tiến trình (các tệp do tiến trình tạo). Các hàm chưa được export `__qtn_syscall_quarantine*` là những hàm áp dụng chính sách bằng cách gọi `mac_syscall` với `"Quarantine"` làm đối số đầu tiên, qua đó gửi yêu cầu đến `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension này chỉ có trong **kernel cache trên hệ thống**; tuy nhiên, bạn _có thể_ tải **Kernel Debug Kit từ** [**https://developer.apple.com/**](https://developer.apple.com/), trong đó có phiên bản extension đã được symbolicate.

Kext này dùng MACF để hook một số lời gọi nhằm chặn mọi sự kiện trong vòng đời tệp: tạo, mở, đổi tên, tạo hard link... thậm chí cả `setxattr` để ngăn việc thiết lập extended attribute `com.apple.quarantine`.

Nó cũng sử dụng một vài MIB:

- `security.mac.qtn.sandbox_enforce`: Thực thi quarantine cùng với Sandbox
- `security.mac.qtn.user_approved_exec`: Các tiến trình bị quarantine chỉ có thể thực thi những tệp đã được phê duyệt

#### Provenance xattr (Ventura trở lên)

macOS 13 Ventura giới thiệu một cơ chế provenance riêng, được thiết lập lần đầu tiên khi một ứng dụng bị quarantine được phép chạy.<sup>[[2]](#references)</sup> Hai artefact được tạo ra:

- xattr `com.apple.provenance` trên thư mục bundle `.app` (giá trị nhị phân có kích thước cố định, chứa khóa chính và các cờ).
- Một hàng trong bảng `provenance_tracking` bên trong cơ sở dữ liệu ExecPolicy tại `/var/db/SystemPolicyConfiguration/ExecPolicy/`, lưu cdhash và metadata của ứng dụng.

Cách sử dụng thực tế:

```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```

### XProtect

XProtect là tính năng **chống phần mềm độc hại** tích hợp sẵn trong macOS. XProtect **kiểm tra mọi ứng dụng khi ứng dụng được khởi chạy lần đầu hoặc được sửa đổi, đối chiếu với cơ sở dữ liệu** về phần mềm độc hại đã biết và các loại tệp không an toàn. Khi bạn tải tệp xuống bằng một số ứng dụng nhất định, chẳng hạn như Safari, Mail hoặc Messages, XProtect sẽ tự động quét tệp. Nếu tệp khớp với phần mềm độc hại đã biết trong cơ sở dữ liệu, XProtect sẽ **ngăn tệp chạy** và cảnh báo bạn về mối đe dọa.

Apple **thường xuyên cập nhật** cơ sở dữ liệu XProtect bằng các định nghĩa phần mềm độc hại mới, và những bản cập nhật này được tự động tải xuống và cài đặt trên máy Mac của bạn. Điều này đảm bảo XProtect luôn được cập nhật với các mối đe dọa mới nhất đã biết.

Tuy nhiên, cần lưu ý rằng **XProtect không phải là giải pháp chống virus đầy đủ tính năng**. Tính năng này chỉ kiểm tra một danh sách cụ thể gồm các mối đe dọa đã biết và không thực hiện quét khi truy cập như hầu hết phần mềm chống virus.

Bạn có thể lấy thông tin về bản cập nhật XProtect mới nhất bằng cách chạy:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect nằm trong vị trí được SIP bảo vệ tại **/Library/Apple/System/Library/CoreServices/XProtect.bundle** và bên trong bundle, bạn có thể tìm thấy thông tin mà XProtect sử dụng:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Cho phép mã có các cdhash đó sử dụng legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Danh sách các plugin và extension không được phép tải, được xác định bằng BundleID và TeamID, hoặc chỉ định phiên bản tối thiểu.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Các quy tắc Yara để phát hiện malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Cơ sở dữ liệu SQLite3 chứa hash của các ứng dụng bị chặn và TeamID.

Lưu ý rằng có một App khác tại **`/Library/Apple/System/Library/CoreServices/XProtect.app`** liên quan đến XProtect nhưng không tham gia vào quy trình Gatekeeper.

> XProtect Remediator: Trên các phiên bản macOS hiện đại, Apple cung cấp các trình quét theo yêu cầu (XProtect Remediator), chạy định kỳ qua launchd để phát hiện và khắc phục các nhóm malware. Bạn có thể quan sát các lần quét này trong unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Không phải Gatekeeper

> [!CAUTION]
> Lưu ý rằng Gatekeeper **không được thực thi mỗi lần** bạn chạy một ứng dụng; chỉ có _**AppleMobileFileIntegrity**_ (AMFI) **xác minh chữ ký code thực thi** khi bạn chạy một ứng dụng đã được Gatekeeper chạy và xác minh trước đó.

Do đó, trước đây có thể chạy một ứng dụng để Gatekeeper cache ứng dụng đó, sau đó **sửa đổi các file không thực thi của ứng dụng** (như Electron asar hoặc file NIB) và nếu không có biện pháp bảo vệ nào khác, ứng dụng sẽ được **chạy** cùng các phần bổ sung **độc hại**.

Tuy nhiên, hiện nay điều này không còn khả thi vì macOS **ngăn sửa đổi file** bên trong application bundle. Vì vậy, nếu thử tấn công [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), bạn sẽ thấy không thể khai thác nó nữa: sau khi chạy ứng dụng để Gatekeeper cache ứng dụng đó, bạn sẽ không thể sửa đổi bundle. Và nếu bạn đổi tên thư mục Contents thành NotCon chẳng hạn (như exploit hướng dẫn), rồi chạy binary chính của ứng dụng để Gatekeeper cache ứng dụng đó, thao tác này sẽ gây ra lỗi và ứng dụng sẽ không chạy.

## Các cách vượt qua Gatekeeper

Bất kỳ cách nào vượt qua Gatekeeper (khiến người dùng tải xuống và chạy thứ gì đó mà Gatekeeper lẽ ra phải chặn) đều được xem là lỗ hổng trong macOS. Sau đây là một số CVE được gán cho các kỹ thuật từng cho phép vượt qua Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Người ta phát hiện rằng nếu dùng **Archive Utility** để giải nén, các file có **đường dẫn dài hơn 886 ký tự** sẽ không nhận được extended attribute com.apple.quarantine. Điều này vô tình cho phép các file đó **né tránh** các bước kiểm tra bảo mật của Gatekeeper.<sup>[[5]](#references)</sup>

Xem [**báo cáo gốc**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) để biết thêm thông tin.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Khi tạo ứng dụng bằng **Automator**, thông tin về những gì ứng dụng cần thực thi nằm trong `application.app/Contents/document.wflow`, chứ không nằm trong executable. Executable chỉ là một binary Automator dùng chung có tên **Automator Application Stub**.

Do đó, bạn có thể tạo symbolic link từ `application.app/Contents/MacOS/Automator\ Application\ Stub` đến một Automator Application Stub khác trong hệ thống, và nó sẽ thực thi nội dung trong `document.wflow` (script của bạn) **mà không kích hoạt Gatekeeper**, vì executable thực tế không có quarantine xattr.<sup>[[6]](#references)</sup>

Ví dụ về vị trí dự kiến: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Xem [**báo cáo gốc**](https://ronmasas.com/posts/bypass-macos-gatekeeper) để biết thêm thông tin.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Trong cách vượt qua này, một file zip được tạo bằng cách bắt đầu nén từ `application.app/Contents` thay vì `application.app`. Vì vậy, **quarantine attr** được áp dụng cho tất cả **file trong `application.app/Contents`** nhưng **không áp dụng cho `application.app`**, vốn là đối tượng Gatekeeper kiểm tra. Nhờ đó, Gatekeeper bị vượt qua vì khi `application.app` được kích hoạt, nó **không có quarantine attribute.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Xem [**báo cáo gốc**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) để biết thêm thông tin.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Dù các thành phần khác nhau, cách khai thác lỗ hổng này rất giống với lỗ hổng trước đó. Trong trường hợp này, chúng ta sẽ tạo một Apple Archive từ **`application.app/Contents`**, nhờ đó **`application.app` sẽ không có thuộc tính quarantine** khi được giải nén bằng **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Xem [**báo cáo gốc**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) để biết thêm thông tin.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** có thể được dùng để ngăn bất kỳ ai ghi thuộc tính vào một tệp:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Hơn nữa, định dạng tệp **AppleDouble** sao chép tệp cùng với các ACE của tệp đó.<sup>[[9]](#references)</sup>

Trong [**mã nguồn**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), có thể thấy biểu diễn văn bản ACL được lưu bên trong xattr có tên **`com.apple.acl.text`** sẽ được đặt làm ACL cho tệp sau khi giải nén. Vì vậy, nếu bạn nén một ứng dụng thành tệp zip ở định dạng **AppleDouble** với ACL ngăn không cho ghi các xattr khác vào ứng dụng đó... thì xattr quarantine sẽ không được đặt vào ứng dụng:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Xem [**báo cáo gốc**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) để biết thêm thông tin.<sup>[[9]](#references)</sup> Xem [hướng dẫn tái hiện AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) để biết các bước tạo và xác thực sidecar.

Lưu ý rằng cách này cũng có thể bị khai thác bằng AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Phát hiện rằng **Google Chrome không thiết lập thuộc tính quarantine** cho các tệp đã tải xuống do một số vấn đề nội bộ của macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble lưu trữ thuộc tính của tệp trong một tệp riêng có tên bắt đầu bằng `._`; điều này giúp sao chép thuộc tính tệp **giữa các máy macOS**. Tuy nhiên, sau khi giải nén tệp AppleDouble, tệp bắt đầu bằng `._` **không được gán thuộc tính quarantine**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Có thể **bypass Gatekeeper** bằng cách tạo một file không có thuộc tính quarantine. Thủ thuật này là **tạo một ứng dụng dưới dạng file DMG** theo quy ước đặt tên AppleDouble (bắt đầu bằng `._`), rồi tạo một **file hiển thị dưới dạng symlink trỏ đến file ẩn** không có thuộc tính quarantine.\
Khi **file DMG được thực thi**, do không có thuộc tính quarantine, nó sẽ **bypass Gatekeeper**.

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

### [CVE-2023-41067]

Apple đã khắc phục lỗi logic trong LaunchServices trên macOS Sonoma 14.0 bằng cách cải thiện các bước kiểm tra. Thông báo công khai chỉ nêu rằng một ứng dụng có thể bypass Gatekeeper, vì vậy không nên suy luận định dạng vật chứa cụ thể hay chuỗi khai thác chỉ từ mục CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Lỗ hổng bypass Gatekeeper trong macOS 14.4 (phát hành vào tháng 3 năm 2024), bắt nguồn từ cách `libarchive` xử lý các tệp ZIP độc hại, cho phép ứng dụng né bước đánh giá. Hãy cập nhật lên phiên bản 14.4 trở lên, nơi Apple đã khắc phục sự cố.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Một **quy trình Quick Action của Automator** được nhúng trong ứng dụng đã tải xuống có thể được kích hoạt mà không qua bước đánh giá của Gatekeeper, vì các quy trình được xem là dữ liệu và được helper của Automator thực thi bên ngoài luồng nhắc xác nhận notarization thông thường. Do đó, một tệp `.app` được tạo thủ công, chứa Quick Action chạy shell script (ví dụ: bên trong `Contents/PlugIns/*.workflow/Contents/document.wflow`), có thể thực thi ngay khi khởi chạy. Apple đã thêm hộp thoại xác nhận bổ sung và sửa luồng đánh giá trong Ventura **13.7**, Sonoma **14.7** và Sequoia **15**.<sup>[[3]](#references)</sup>

### Lỗi truyền trạng thái quarantine tại ranh giới giải nén và sao chép

Một nghiên cứu năm 2024 phát hiện các lỗ hổng truyền trạng thái quarantine trong những phiên bản đã thử nghiệm của iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) và 7z Utility (DMG/ZIP/7Z); nghiên cứu cũng ghi nhận thuộc tính này bị mất khi sao chép từ máy chủ sang máy khách bằng VMware Tools. Sau đó, một số nhà cung cấp đã thông báo phát hành bản sửa lỗi, vì vậy hãy xem các tên này là gợi ý để **kiểm tra lại theo từng phiên bản**, không phải danh sách phần mềm luôn dễ bị tấn công. Vấn đề ranh giới tin cậy tương tự cũng áp dụng cho quy trình Unix gốc: `curl`/`scp` không thêm quarantine, còn `tar`/`unzip` chạy qua command line không tự động kế thừa trạng thái này từ tệp lưu trữ vật chứa.<sup>[[15]](#references)</sup>

Khi kiểm thử offensive, hãy so sánh vật chứa và ứng dụng cuối cùng sau **mỗi** lần chuyển qua trình duyệt, ứng dụng email, công cụ lưu trữ, ảnh đĩa, đồng bộ đám mây, thư mục dùng chung và thao tác sao chép VM. Việc `spctl` từ chối rõ ràng không khắc phục được xattr bị thiếu: nếu không có quarantine, luồng Gatekeeper thông thường khi mở lần đầu có thể không bao giờ yêu cầu đánh giá ứng dụng đó.<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (từ [bài nói chuyện này](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Tạo một thư mục chứa một app.
- Thêm uchg vào app.
- Nén app thành tệp tar.gz.
- Gửi tệp tar.gz cho nạn nhân.
- Nạn nhân mở tệp tar.gz và chạy app.
- Gatekeeper không kiểm tra app.<sup>[[12]](#references)</sup>

### Ngăn thêm quarantine xattr

Trong một gói ".app", nếu quarantine xattr không được thêm vào thì khi thực thi, **Gatekeeper sẽ không được kích hoạt**.

Xem [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) để biết các primitive dựa trên filesystem, flag, ACL và AppleDouble có thể ngăn hoặc loại bỏ extended attributes.





## References

- [1] [Apple Platform Security: Nội dung bảo mật của macOS Sonoma 14.4 (bao gồm CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Cách macOS hiện theo dõi nguồn gốc của các app](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Nội dung bảo mật của macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia loại bỏ cách bypass Gatekeeper bằng thao tác Control-click “Open”](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Phát hiện CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypass macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs phát hiện lỗ hổng Safari cho phép bypass Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs phát hiện lỗ hổng macOS Archive Utility cho phép bypass Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Điểm yếu chí mạng của Gatekeeper: Phát hiện lỗ hổng macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Phát hiện cách bypass Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Phát hiện và báo cáo một exploit bypass Gatekeeper với sự trợ giúp của Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypass các cơ chế bảo mật và quyền riêng tư của macOS — Từ Gatekeeper đến System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Nội dung bảo mật của macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Kiểm thử sản phẩm đã notarize](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Bypass Gatekeeper — Khám phá điểm yếu trong một cơ chế bảo mật của macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
