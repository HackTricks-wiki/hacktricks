# Trình xử lý ứng dụng cho phần mở rộng tệp và URL scheme trên macOS

{{#include ../../banners/hacktricks-training.md}}

## Cơ sở dữ liệu LaunchServices

Đây là cơ sở dữ liệu chứa tất cả ứng dụng đã cài đặt trên macOS. Có thể truy vấn cơ sở dữ liệu này để lấy thông tin về từng ứng dụng đã cài đặt, chẳng hạn như **URL scheme**, **loại tài liệu**, **UTI** và trình xử lý mặc định.

Có thể dump cơ sở dữ liệu này bằng lệnh:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Hoặc sử dụng công cụ [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** là bộ não của cơ sở dữ liệu. Nó cung cấp **nhiều dịch vụ XPC** như `.lsd.installation`, `.lsd.open`, `.lsd.openurl` và các dịch vụ khác. Tuy nhiên, ứng dụng cũng **cần một số entitlements** để sử dụng các chức năng XPC được cung cấp, chẳng hạn như `.launchservices.changedefaulthandler` hoặc `.launchservices.changeurlschemehandler` để thay đổi ứng dụng mặc định cho các loại MIME hoặc URL scheme, cùng các chức năng khác.

**`/System/Library/CoreServices/launchservicesd`** đăng ký dịch vụ `com.apple.coreservices.launchservicesd` và có thể được truy vấn để lấy thông tin về các ứng dụng đang chạy. Có thể truy vấn dịch vụ này bằng công cụ hệ thống **`/usr/bin/lsappinfo`** hoặc bằng [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Ở góc độ vận hành, hãy nhớ rằng thường có **hai góc nhìn hữu ích**:

- **Cơ sở dữ liệu đăng ký** do LaunchServices / `lsd` quản lý (được lưu trong các tệp `.csstore`).
- **Các giá trị mặc định hiệu lực theo từng người dùng** được lưu trong mảng `LSHandlers` của `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`.

Sự khác biệt này rất quan trọng: một ứng dụng có thể được **đăng ký** để xử lý một loại hoặc scheme, nhưng **ứng dụng mặc định hiện tại** vẫn có thể là một bundle ID khác.

Trên các phiên bản macOS gần đây, việc phát hiện ứng dụng đã đăng ký không chỉ giới hạn ở `/Applications`: ứng dụng trong các thư mục khác mà Spotlight có thể tìm kiếm và người dùng có thể truy cập, cũng như trên các volume được gắn kết/chia sẻ, đều có thể được đưa vào registry. Vì vậy, khi điều tra, hãy lưu lại thông tin `path` và volume từ `lsregister -dump`, và đừng cho rằng việc hủy đăng ký ứng dụng sẽ có hiệu lực lâu dài khi bundle vẫn còn được phát hiện.<sup>[[4]](#references)</sup>

## Trình xử lý ứng dụng cho phần mở rộng tệp và URL scheme

Dòng lệnh sau có thể hữu ích để tìm các ứng dụng có thể mở tệp dựa trên phần mở rộng:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

Hoặc sử dụng thứ gì đó như [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

Bạn cũng có thể kiểm tra các phần mở rộng được ứng dụng hỗ trợ bằng cách:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## Liệt kê các trình xử lý đang hoạt động

Tệp hữu ích nhất để xác định **các mặc định của người dùng hiện tại** thường là:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Để dump các trình xử lý **URL scheme** từ đó:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Để dump các trình xử lý **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Để phân giải cây UTI của một tệp mẫu:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Nếu bạn muốn dùng CLI thân thiện hơn để truy vấn hoặc thay đổi các giá trị mặc định:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### Ghi đè `Open With` theo từng tệp

Việc phân giải trình xử lý còn có một lớp **riêng cho từng tệp**. Trước khi dùng UTI của tệp và mặc định toàn cục của người dùng, LaunchServices kiểm tra thuộc tính mở rộng `com.apple.LaunchServices.OpenWith`. Finder tạo thuộc tính này khi chọn **Always Open With** cho một tệp; giá trị của nó là danh sách thuộc tính nhị phân chứa đường dẫn ứng dụng, bundle identifier và bộ chọn phiên bản.<sup>[[3]](#references)</sup>

Kiểm tra và giải mã thuộc tính này mà không tin cậy phần mở rộng tên tệp:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Điều này hữu ích khi một mồi nhử mở bằng ứng dụng ngoài dự kiến, dù `duti`, `dutix` hoặc `LSHandlers` báo cáo giá trị mặc định toàn cục lành tính. Trong môi trường lab có kiểm soát, có thể sao chép chính xác giá trị khó hiểu này từ một tệp được cấu hình qua Finder; xóa giá trị đó sẽ khôi phục cơ chế phân giải thông thường dựa trên loại tệp:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Các key Info.plist đáng chú ý

Khi phân loại sơ bộ một application bundle, những key này quan trọng nhất:

- **`CFBundleDocumentTypes`**: các nhóm tài liệu mà bundle khai báo có thể mở.
- **`LSItemContentTypes`**: cách **hiện đại / được ưu tiên** để liên kết loại tài liệu với UTI.
- **`LSHandlerRank`**: thứ hạng được LaunchServices sử dụng (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: các URI scheme tùy chỉnh do app triển khai.
- **`UTExportedTypeDeclarations`**: các UTI mà app **sở hữu**.
- **`UTImportedTypeDeclarations`**: các UTI mà app không sở hữu nhưng muốn hệ thống nhận diện.

Một lệnh phân loại sơ bộ nhanh hữu ích là:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Một chi tiết tinh tế nhưng quan trọng: nếu **`LSItemContentTypes`** có mặt, các khóa cũ như **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** và **`CFBundleTypeOSTypes`** về cơ bản chỉ còn là dữ liệu tương thích legacy. Khi phân giải handler thực tế, hãy ưu tiên đường dẫn UTI.

## Offensive notes

Ứng dụng không cần chạy thì các khai báo handler của chúng mới đáng chú ý, nhưng **chỉ ghi một bundle `.app` không đảm bảo ứng dụng được đăng ký ngay lập tức**. Finder có thể đăng ký ứng dụng khi phát hiện ra nó, kể cả khi người dùng duyệt thư mục chứa ứng dụng; việc đăng ký cũng có thể diễn ra khi khởi động hoặc đăng nhập, hay thông qua một lệnh gọi đăng ký tường minh. Hãy kiểm tra `lsregister -dump` trước khi thử nghiệm khai báo. Việc đăng ký không tự khởi chạy ứng dụng cũng không khiến ứng dụng trở thành mặc định có hiệu lực.<sup>[[5]](#references)</sup> Để biết các điều kiện tiên quyết cho persistence, xem [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Điều này hữu ích cho cả **nghiên cứu persistence / hijacking** lẫn **các chuỗi initial access**:

- Ứng dụng độc hại có thể khai báo một **extension hiếm gặp** hoặc một **UTI tùy chỉnh**, rồi chờ nạn nhân mở tệp mồi.
- Ứng dụng độc hại có thể đăng ký một **URL scheme tùy chỉnh** có thể được gọi từ trình duyệt, ứng dụng Electron, tài liệu office, ứng dụng chat hoặc một ứng dụng helper khác.<sup>[[1]](#references)</sup>
- Để phân biệt việc phân giải mặc định thông thường với việc kiểm thử một handler cụ thể, hãy gọi scheme thông qua LaunchServices bằng `open 'targetscheme://host/path?value=test'`, sau đó nhắm đến một bundle đã đăng ký cụ thể bằng `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Cách này hữu ích để kiểm tra cách ứng dụng nhận xác thực và giải mã các thành phần URL do kẻ tấn công kiểm soát.<sup>[[1]](#references)</sup>
- Nếu bạn chỉnh sửa bundle ứng dụng sau khi tạo, bạn có thể buộc LaunchServices phân tích lại bằng:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Khi kiểm thử các bundle đáng ngờ, hãy đặc biệt chú ý đến:

- **`LSHandlerRank=Owner`** trên các loại tệp ít phổ biến.
- Các mảng **`CFBundleDocumentTypes`** rộng, khai báo hỗ trợ nhiều phần mở rộng.
- **Ứng dụng helper / wrapper** mà hành vi đáng chú ý duy nhất nằm sau trình xử lý tài liệu hoặc URI.
- Các tệp dạng shortcut (`.webloc`, `.inetloc`, `.fileloc`) cuối cùng chuyển tiếp đến LaunchServices. Để xem các thủ thuật kiểu `.fileloc` và những khía cạnh Gatekeeper liên quan, hãy xem [trang khác này](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Tham số URL được chuyển tiếp vào các tùy chọn ở bước sau

Xác nhận của trình duyệt về giao thức bên ngoài chỉ chấp thuận mở trình xử lý; điều đó không có nghĩa là các tham số URL đáng tin cậy. Theo dõi trình phân tích cú pháp URL của ứng dụng nhận đến thư viện, media engine, tiến trình helper hoặc tùy chọn ghi tệp. Tìm tiền tố khóa truy vấn có thể biến các trường URL thành tên tùy chọn ở bước sau. Kiểm thử cả dấu phân tách dạng ký tự thường lẫn dạng mã hóa phần trăm bằng một marker vô hại trong tài khoản dùng riêng.<sup>[[6]](#references)</sup>

Xác minh **tùy chọn cuối cùng được thành phần ở bước sau chấp nhận**, không chỉ cách ứng dụng phân tích cú pháp ban đầu. Một trình xử lý cho phép các khóa truy vấn có tiền tố truyền lệnh nhập liệu của mpv; chặn tùy chọn đó vẫn chưa loại bỏ được đường ghi tệp. Hãy kiểm thử lớp tùy chọn có thể tiếp cận, thay vì chỉ kiểm tra một khóa nguy hiểm đã biết.<sup>[[7]](#references)</sup>

### Trình xử lý tích hợp sẵn `applescript://`

Trình xử lý URL `applescript://com.apple.scripteditor` chấp nhận `action=new` và tham số `script` được mã hóa URL. Vì vậy, một liên kết trong trình duyệt có thể mở Script Editor với AppleScript do kẻ tấn công kiểm soát đã nằm sẵn trong trình soạn thảo, bỏ qua bước dán vào Terminal. Đây **không phải là tự động thực thi**: trình duyệt có thể hỏi người dùng có muốn mở Script Editor không, và người dùng phải chạy script.<sup>[[8]](#references)</sup>

Các phiên bản macOS gần đây có thể hiển thị cảnh báo về tài liệu script, trong khi XProtect quét AppleScript khi thực thi.<sup>[[8]](#references)[[9]](#references)</sup>

Dùng một phép thử cục bộ vô hại để kiểm tra trình xử lý và các lời nhắc trên phiên bản macOS đang được đánh giá; thao tác này chỉ nên điền nội dung vào trình soạn thảo cho đến khi nhấp **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Nếu mục tiêu của bạn là thực thi mã thụ động chỉ bằng cách duyệt đến một thư mục hoặc chọn một tệp, hãy xem thêm trang riêng về [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), vì đây là một bề mặt xử lý tệp khác nhưng có liên quan chặt chẽ.



## References

- [1] [Objective-See - Khai thác Mac từ xa qua custom URL schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Vượt qua cổng bảo vệ: Tìm hiểu sâu hơn về các lỗ hổng của Gatekeeper trên macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Cách macOS mở tệp bằng ứng dụng phù hợp](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kiểm soát LaunchServices trong macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Các khái niệm về Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Nghiên cứu thực thi lệnh qua URL scheme của IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Xử lý không an toàn các tùy chọn mpv trong URL scheme của ứng dụng](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - Kỹ thuật ClickFix sử dụng Script Editor thay vì Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Các biện pháp bảo vệ Terminal và script](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
