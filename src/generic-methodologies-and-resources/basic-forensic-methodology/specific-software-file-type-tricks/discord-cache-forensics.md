# Forensics της Discord Cache (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πώς να κάνετε triage στα artifacts της Discord Desktop cache για τοπικά αποθηκευμένα media, webhook endpoints και συσχέτιση δραστηριότητας. Ο desktop client του Discord χρησιμοποιεί Electron, και το Electron αποθηκεύει δεδομένα συνεδρίας, όπως την disk cache, κάτω από το `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Πού να αναζητήσετε (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Αυτές είναι οι προεπιλεγμένες διαδρομές που χρησιμοποιεί ο parser που αναφέρεται εδώ. Το Electron επιτρέπει σε μια εφαρμογή να παρακάμπτει το `sessionData`, επομένως επιβεβαιώστε την πραγματική διαδρομή του profile κατά τη συλλογή.<sup>[[2]](#references)[[4]](#references)</sup>

Η διάταξη `index` + `data_#` + `f_######` αντιστοιχεί στο blockfile disk-cache backend του Chromium. Μην την χαρακτηρίζετε Simple Cache χωρίς να επαληθεύσετε το backend, επειδή το Chromium τεκμηριώνει διαφορετικές υλοποιήσεις cache.<sup>[[5]](#references)</sup>

Βασικές δομές στον δίσκο μέσα στο `Cache_Data`:
- `index`: Δείκτης cache τύπου Blockfile που χρησιμοποιείται για τον εντοπισμό καταχωρίσεων.
- `data_#`: Αρχεία σταθερού μεγέθους που μπορεί να περιέχουν metadata cache, HTTP headers και δεδομένα απόκρισης.
- `f_######`: Ξεχωριστά αρχεία για δεδομένα μεγαλύτερα από το όριο των block-file. Αυτά τα αρχεία περιέχουν τα αποθηκευμένα δεδομένα χωρίς τα block-file headers.

Η διαγραφή μηνυμάτων, καναλιών ή servers δεν εγγυάται την αφαίρεση bytes που έχουν ήδη αποθηκευτεί τοπικά στην cache, αλλά το Chromium μπορεί ανά πάσα στιγμή να αποβάλει ή να αναδημιουργήσει αρχεία cache. Αντιμετωπίστε τα artifacts που παραμένουν ως ενδεχομενικά αποδεικτικά στοιχεία και χρησιμοποιήστε τους χρόνους τροποποίησης αρχείων μόνο ως πρόχειρες ενδείξεις τοπικής εγγραφής, οι οποίες πρέπει να συσχετιστούν με άλλα telemetry.<sup>[[5]](#references)[[6]](#references)</sup>

## Τι μπορεί να ανακτηθεί

Ανάλογα με το τι ανακτήθηκε και δεν έχει ακόμη αποβληθεί από την cache, το triage μπορεί να ανακτήσει συνημμένα, media, URLs και hashes αρχείων. Η cache από μόνη της δεν αποδεικνύει ότι κάποιο στοιχείο έγινε exfiltrate.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Συνημμένα και thumbnails που αναφέρονται από Discord CDN URLs.
- Εικόνες, GIFs και videos (για παράδειγμα, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` και `.webm`).
- Webhook URLs όπως `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls όπως `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hashes ανακτημένων media για σύγκριση με γνωστά datasets ή intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Γρήγορο triage (χειροκίνητο)

- Κάντε grep στην cache για artifacts με ισχυρό σήμα. Αυτά τα patterns ακολουθούν τις εκφράσεις URL του parser που αναφέρεται εδώ και είναι φίλτρα triage, όχι εξαντλητικοί δείκτες.<sup>[[2]](#references)</sup>
  - Webhook endpoints:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Attachment/CDN URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API calls:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ταξινομήστε τις καταχωρίσεις cache βάσει χρόνου τροποποίησης για να σχηματίσετε μια πρόχειρη ακολουθία. Το mtime είναι ένδειξη από το filesystem και από μόνο του δεν αποδεικνύει πότε ανακτήθηκε ή στάλθηκε ένα αντικείμενο Discord.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Ανάλυση καταχωρίσεων f_* (HTTP body + headers)

Στη διάταξη blockfile, τα αρχεία `f_######` είναι ξεχωριστά data streams και δεν είναι βέβαιο ότι αρχίζουν με πλήρη HTTP response. Αν ένα αρχείο που συλλέχθηκε περιέχει serialized HTTP headers ακολουθούμενα από `\r\n\r\n`, διαχωρίστε το στο πρώτο delimiter και εξετάστε:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Για να συναγάγετε τον τύπο media
- Content-Location ή X-Original-URL: Το αρχικό remote URL για preview/συσχέτιση
- Content-Encoding: Μπορεί να είναι gzip/deflate/br (Brotli).

Στη συνέχεια, μπορείτε να εξαγάγετε media διαχωρίζοντας τα headers από το body και, προαιρετικά, να το αποσυμπιέσετε σύμφωνα με το `Content-Encoding`. Ο parser που αναφέρεται εδώ υποστηρίζει Brotli, gzip και deflate. Η ανίχνευση magic bytes είναι χρήσιμη όταν απουσιάζει το `Content-Type`, αλλά παραμένει ευρετική μέθοδος.<sup>[[2]](#references)</sup>

## Αυτοματοποιημένο DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Λειτουργία: Σαρώνει αναδρομικά τον φάκελο cache του Discord, εντοπίζει webhook/API/attachment URLs, αναλύει τα `f_*` bodies, προαιρετικά εξάγει media και δημιουργεί HTML και CSV reports, καθώς και ένα προαιρετικό χρονολογικό timeline με SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

Παράδειγμα χρήσης CLI:

```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
  --cache "$env:APPDATA\discord\Cache\Cache_Data" `
  --outdir "C:\IR\discord-cache" `
  --output discord_cache_report `
  --format both `
  --timeline `
  --extra `
  --carve `
  --verbose
```

Το CLI ορίζει τις εξής επιλογές και ονόματα εξόδου:<sup>[[2]](#references)</sup>
- --cache: Διαδρομή προς τον κατάλογο Discord Cache_Data
- --format html|csv|both
- --timeline: Δημιουργία ταξινομημένου χρονολογίου CSV (κατά modified time)
- --extra: Σάρωση και των γειτονικών Code Cache και GPUCache
- --carve: Εξαγωγή media από raw cache bytes με χρήση αναγνωρισμένων media signatures (εικόνες/βίντεο)
- Έξοδος: `<output>.html`, `<output>.csv`, προαιρετικά `<output>_timeline.csv` και φάκελος `<output>_media` με τα εξαχθέντα ή carved αρχεία.

## Συμβουλές αναλυτών

- Συσχετίστε το modified time (mtime) των αρχείων `f_*` και `data_*` με τα χρονικά διαστήματα δραστηριότητας χρηστών ή επιτιθέμενων και με ανεξάρτητα telemetry· το mtime δεν αποτελεί οριστική χρονική σήμανση συμβάντος.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Υπολογίστε hash των ανακτημένων media (SHA-256) και συγκρίνετέ τα με γνωστά κακόβουλα δεδομένα ή datasets εξαγωγής δεδομένων.<sup>[[1]](#references)[[2]](#references)</sup>
- Αντιμετωπίστε τα webhook URLs που εξήχθησαν ως διαπιστευτήρια. Μην τα χρησιμοποιείτε απλώς για να ελέγξετε αν είναι ενεργά· διαφυλάξτε τα με ασφάλεια, συντονίστε την ανάκληση ή την αλλαγή τους και χρησιμοποιήστε σχετικά network telemetry για retro-hunting.<sup>[[7]](#references)</sup>
- Η διαγραφή από την πλευρά του server δεν εγγυάται ότι έχουν καταστραφεί τα τοπικά cached bytes. Αν είναι δυνατή η απόκτηση, συλλέξτε ολόκληρο τον κατάλογο `Cache` και τις σχετικές γειτονικές cache (`Code Cache`, `GPUCache`) πριν από την εκκαθάριση ή την αναδημιουργία της cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Πώς το Discord αναβάθμισε απρόσκοπτα εκατομμύρια χρήστες σε αρχιτεκτονική 64-bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache δίσκου](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Το Discord ως C2 και τα cached στοιχεία που αφήνονται πίσω](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Εκτέλεση Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
