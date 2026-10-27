# Dấu vết trình duyệt

{{#include ../../../banners/hacktricks-training.md}}

## Dấu vết trình duyệt <a href="#id-3def" id="id-3def"></a>

Dấu vết trình duyệt bao gồm nhiều loại dữ liệu được trình duyệt web lưu trữ, chẳng hạn như lịch sử duyệt web, dấu trang và dữ liệu cache. Những dấu vết này được lưu trong các thư mục cụ thể của hệ điều hành. Vị trí và tên thư mục khác nhau tùy theo trình duyệt, nhưng nhìn chung chúng lưu trữ các loại dữ liệu tương tự nhau.

Dưới đây là tóm tắt về các dấu vết trình duyệt phổ biến nhất:

- **Lịch sử duyệt web**: Theo dõi những trang web người dùng đã truy cập, hữu ích để xác định việc truy cập các trang web độc hại.
- **Dữ liệu tự động hoàn tất**: Các đề xuất dựa trên những nội dung tìm kiếm thường xuyên, cung cấp thông tin chuyên sâu khi kết hợp với lịch sử duyệt web.
- **Dấu trang**: Các trang web được người dùng lưu để truy cập nhanh.
- **Tiện ích mở rộng và tiện ích bổ sung**: Các tiện ích mở rộng hoặc tiện ích bổ sung do người dùng cài đặt.
- **Cache**: Lưu trữ nội dung web (ví dụ: hình ảnh, tệp JavaScript) để cải thiện thời gian tải trang web; hữu ích cho phân tích pháp chứng.
- **Thông tin đăng nhập**: Thông tin đăng nhập được lưu trữ.
- **Favicon**: Biểu tượng gắn với các trang web, hiển thị trên tab và dấu trang, hữu ích để tìm hiểu thêm về các trang người dùng đã truy cập.
- **Phiên trình duyệt**: Dữ liệu liên quan đến các phiên trình duyệt đang mở.
- **Tệp đã tải xuống**: Bản ghi các tệp được tải xuống qua trình duyệt.
- **Dữ liệu biểu mẫu**: Thông tin được nhập vào biểu mẫu web và lưu lại để đưa ra đề xuất tự động điền sau này.
- **Hình thu nhỏ**: Hình ảnh xem trước của các trang web.
- **Custom Dictionary.txt**: Các từ do người dùng thêm vào từ điển của trình duyệt.

## Firefox

Firefox sắp xếp dữ liệu người dùng trong các profile, được lưu ở những vị trí cụ thể tùy theo hệ điều hành:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Tệp `profiles.ini` trong các thư mục này liệt kê các profile người dùng. Dữ liệu của mỗi profile được lưu trong một thư mục có tên được chỉ định trong biến `Path` của `profiles.ini`, nằm cùng thư mục với chính tệp `profiles.ini`. Nếu thiếu thư mục của một profile, có thể profile đó đã bị xóa.

Trong mỗi thư mục profile, bạn có thể tìm thấy một số tệp quan trọng:<sup>[[1]](#references)</sup>

- **places.sqlite**: Lưu trữ lịch sử duyệt web, dấu trang và nội dung tải xuống. Các công cụ như [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) trên Windows có thể truy cập dữ liệu lịch sử.
  - Sử dụng các truy vấn SQL cụ thể để trích xuất thông tin lịch sử duyệt web và nội dung tải xuống.
- **bookmarkbackups**: Chứa các bản sao lưu dấu trang.
- **formhistory.sqlite**: Lưu trữ dữ liệu biểu mẫu web.
- **handlers.json**: Quản lý trình xử lý giao thức.
- **persdict.dat**: Các từ trong từ điển tùy chỉnh.
- **addons.json** và **extensions.sqlite**: Thông tin về các tiện ích bổ sung và tiện ích mở rộng đã cài đặt.
- **cookies.sqlite**: Lưu trữ cookie; có thể dùng [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) để kiểm tra trên Windows.
- **cache2/entries** hoặc **startupCache**: Dữ liệu cache, có thể truy cập bằng các công cụ như [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Lưu trữ favicon.
- **prefs.js**: Cài đặt và tùy chọn của người dùng.
- **downloads.sqlite**: Cơ sở dữ liệu lưu nội dung tải xuống phiên bản cũ, hiện đã được tích hợp vào places.sqlite.
- **thumbnails**: Hình thu nhỏ của trang web.
- **logins.json**: Thông tin đăng nhập được mã hóa.
- **key4.db** hoặc **key3.db**: Lưu trữ khóa mã hóa dùng để bảo vệ thông tin nhạy cảm.

Ngoài ra, có thể kiểm tra cài đặt chống phishing của trình duyệt bằng cách tìm các mục `browser.safebrowsing` trong `prefs.js`; các mục này cho biết tính năng duyệt web an toàn đang được bật hay tắt.<sup>[[2]](#references)</sup>

Để giải mã thông tin đăng nhập đã lưu từ một profile có thể truy cập, cần cung cấp Primary Password của [Firefox](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), nếu đã được thiết lập, hoặc khôi phục mật khẩu này riêng; profile không tiết lộ mật khẩu đó. Hãy xác nhận rằng mọi thông tin đăng nhập khôi phục được đều đăng nhập thành công vào tài khoản web tương ứng. Quyền truy cập Unix root cần có bằng chứng riêng cho thấy thông tin xác thực đó cũng được hệ thống xác thực Unix chấp nhận cho root. Bạn có thể xem thông tin đăng nhập đã lưu bằng [firefox_decrypt](https://github.com/unode/firefox_decrypt). Ví dụ sau đây kiểm tra các mật khẩu Primary Password tiềm năng từ một tệp mật khẩu:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Dấu vết trình duyệt - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome lưu trữ hồ sơ người dùng tại các vị trí cụ thể tùy theo hệ điều hành:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Trong các thư mục này, hầu hết dữ liệu người dùng nằm trong các thư mục **Default/** hoặc **ChromeDefaultData/**. Những tệp sau chứa dữ liệu quan trọng:<sup>[[1]](#references)</sup>

- **History**: Chứa URL, nội dung tải xuống và từ khóa tìm kiếm. Trên Windows, có thể dùng [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) để đọc lịch sử. Cột "Transition Type" có nhiều ý nghĩa khác nhau, bao gồm người dùng nhấp vào liên kết, nhập URL, gửi biểu mẫu và tải lại trang.
- **Cookies**: Lưu trữ cookie. Có thể dùng [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) để kiểm tra.
- **Cache**: Chứa dữ liệu được lưu trong cache. Người dùng Windows có thể dùng [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) để kiểm tra.

  Các ứng dụng desktop dựa trên Electron (ví dụ: Discord) cũng sử dụng Chromium Simple Cache và để lại nhiều dấu vết trên đĩa. Xem:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Dấu trang của người dùng.
- **Web Data**: Chứa lịch sử biểu mẫu.
- **Favicons**: Lưu favicon của trang web.
- **Login Data**: Chứa thông tin đăng nhập như tên người dùng và mật khẩu.
- **Current Session**/**Current Tabs**: Dữ liệu về phiên duyệt web hiện tại và các tab đang mở.
- **Last Session**/**Last Tabs**: Thông tin về các trang web đang hoạt động trong phiên cuối cùng trước khi Chrome đóng.
- **Extensions**: Các thư mục chứa tiện ích mở rộng và addon của trình duyệt.
- **Thumbnails**: Lưu hình thu nhỏ của trang web.
- **Preferences**: Tệp chứa nhiều thông tin, bao gồm cài đặt plugin, tiện ích mở rộng, cửa sổ bật lên, thông báo và nhiều nội dung khác.
- **Browser’s built-in anti-phishing**: Để kiểm tra tính năng chống phishing và bảo vệ khỏi malware có được bật hay không, chạy `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Tìm `{"enabled: true,"}` trong kết quả.<sup>[[2]](#references)</sup>

Thư mục `Local Extension Settings/<extension-id>/` trong hồ sơ Chromium có thể chứa trạng thái riêng của tiện ích mở rộng, bao gồm dữ liệu khóa của password manager. Ví dụ, [Passbolt cho biết khóa riêng tư được mã hóa của họ được lưu trong bộ nhớ cục bộ của tiện ích mở rộng trình duyệt](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), và [Chrome extension ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) xác định thư mục tương ứng. Chỉ riêng sự hiện diện của thư mục không chứng minh rằng có khóa bên trong, cũng không mở khóa vault: người dùng cần có quyền truy cập vào dữ liệu hồ sơ, khóa riêng tư và passphrase có thể sử dụng, cùng một quy trình khôi phục/xác thực được máy chủ cho phép. Mục vault chứa mật khẩu tài khoản hệ điều hành cần được xác minh riêng để biết mật khẩu đó có được tái sử dụng cho tài khoản hay không. Hoạt động enumeration thông thường chỉ nên báo cáo đường dẫn lưu trữ, không trích xuất các tệp LevelDB hoặc giá trị bí mật.

## **Khôi phục dữ liệu DB SQLite**

Như đã thấy ở các phần trước, cả Chrome và Firefox đều dùng cơ sở dữ liệu **SQLite** để lưu dữ liệu. Có thể **khôi phục các bản ghi đã xóa bằng công cụ** [**sqlparse**](https://github.com/padfoot999/sqlparse) **hoặc** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 quản lý dữ liệu và metadata ở nhiều vị trí khác nhau, giúp tách riêng thông tin được lưu trữ và các chi tiết tương ứng để dễ dàng truy cập và quản lý.

### Lưu trữ metadata

Metadata của Internet Explorer được lưu tại `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (trong đó VX là V01, V16 hoặc V24). Tệp `V01.log` đi kèm có thể có thời gian chỉnh sửa không khớp với `WebcacheVX.data`, cho thấy cần sửa bằng lệnh `esentutl /r V01 /d`. Metadata này nằm trong cơ sở dữ liệu ESE, có thể được khôi phục và kiểm tra lần lượt bằng các công cụ như photorec và [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Trong bảng **Containers**, có thể xác định các bảng hoặc vùng chứa cụ thể lưu từng phân đoạn dữ liệu, bao gồm cả chi tiết cache của các công cụ Microsoft khác như Skype.

### Kiểm tra cache

Công cụ [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) cho phép kiểm tra cache; cần cung cấp vị trí thư mục chứa dữ liệu cache đã trích xuất. Metadata của cache bao gồm tên tệp, thư mục, số lần truy cập, URL nguồn và dấu thời gian cho biết thời điểm tạo, truy cập, chỉnh sửa và hết hạn của cache.

### Quản lý cookie

Có thể xem cookie bằng [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Metadata bao gồm tên, URL, số lần truy cập và nhiều thông tin thời gian khác. Cookie lâu dài được lưu tại `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, còn cookie phiên nằm trong bộ nhớ.

### Chi tiết nội dung tải xuống

Có thể truy cập metadata tải xuống bằng [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); các vùng chứa cụ thể lưu dữ liệu như URL, loại tệp và vị trí tải xuống. Các tệp thực tế có thể được tìm thấy tại `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Lịch sử duyệt web

Để xem lại lịch sử duyệt web, có thể dùng [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html); cần cung cấp vị trí các tệp lịch sử đã trích xuất và cấu hình cho Internet Explorer. Metadata bao gồm thời gian chỉnh sửa và truy cập, cùng số lần truy cập. Các tệp lịch sử nằm tại `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL đã nhập

URL đã nhập và thời điểm sử dụng được lưu trong registry thuộc `NTUSER.DAT`, tại `Software\Microsoft\InternetExplorer\TypedURLs` và `Software\Microsoft\InternetExplorer\TypedURLsTime`. Các mục này theo dõi 50 URL gần nhất do người dùng nhập và thời điểm nhập gần nhất của từng URL.

## Microsoft Edge

Microsoft Edge lưu dữ liệu người dùng tại `%userprofile%\Appdata\Local\Packages`. Đường dẫn của các loại dữ liệu khác nhau như sau:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dữ liệu Safari được lưu tại `/Users/$User/Library/Safari`. Các tệp quan trọng gồm:<sup>[[3]](#references)</sup>

- **History.db**: Chứa các bảng `history_visits` và `history_items` với URL và dấu thời gian truy cập. Dùng `sqlite3` để truy vấn.
- **Downloads.plist**: Thông tin về các tệp đã tải xuống.
- **Bookmarks.plist**: Lưu URL đã đánh dấu.
- **TopSites.plist**: Các trang được truy cập thường xuyên nhất.
- **Extensions.plist**: Danh sách tiện ích mở rộng của trình duyệt Safari. Dùng `plutil` hoặc `pluginkit` để truy xuất.
- **UserNotificationPermissions.plist**: Các domain được phép gửi thông báo đẩy. Dùng `plutil` để phân tích.
- **LastSession.plist**: Các tab từ phiên gần nhất. Dùng `plutil` để phân tích.
- **Browser’s built-in anti-phishing**: Kiểm tra bằng lệnh `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Kết quả 1 cho biết tính năng đang hoạt động.<sup>[[2]](#references)</sup>

## Opera

Dữ liệu của Opera nằm tại `/Users/$USER/Library/Application Support/com.operasoftware.Opera` và sử dụng định dạng giống Chrome cho lịch sử và nội dung tải xuống.

- **Browser’s built-in anti-phishing**: Xác minh bằng cách dùng `grep` kiểm tra xem `fraud_protection_enabled` trong tệp Preferences có được đặt thành `true` hay không.<sup>[[2]](#references)</sup>

Các đường dẫn và lệnh này rất quan trọng để truy cập và hiểu dữ liệu duyệt web được lưu bởi các trình duyệt khác nhau.

## References

- [1] [Pháp y trình duyệt web: Hướng dẫn thực hiện phân tích pháp y trình duyệt web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Ứng phó sự cố macOS | Phần 3: Thao túng hệ thống](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Ứng phó sự cố OS X: Lập trình kịch bản và phân tích, của Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
