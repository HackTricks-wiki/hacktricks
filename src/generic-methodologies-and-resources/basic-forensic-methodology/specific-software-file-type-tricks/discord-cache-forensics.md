# Forensics Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει τον τρόπο triage των artifacts του Discord Desktop cache για locally cached media, webhook endpoints και συσχέτιση δραστηριότητας. Ο desktop client του Discord χρησιμοποιεί Electron, και το Electron αποθηκεύει session data, όπως το disk cache, μέσα στο `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Πού να αναζητήσετε (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Αυτά είναι τα default paths που χρησιμοποιεί ο parser που αναφέρεται· το Electron επιτρέπει σε μια εφαρμογή να παρακάμπτει το `sessionData`, επομένως επιβεβαιώστε το πραγματικό profile path κατά τη συλλογή.<sup>[[2]](#references)[[4]](#references)</sup>

Η διάταξη `index` + `data_#` + `f_######` αντιστοιχεί στο blockfile disk-cache backend του Chromium· μην το χαρακτηρίζετε Simple Cache χωρίς να επαληθεύσετε το backend, επειδή το Chromium τεκμηριώνει ξεχωριστές υλοποιήσεις cache.<sup>[[5]](#references)</sup>

Βασικές on-disk δομές μέσα στο `Cache_Data`:
- `index`: Blockfile cache index που χρησιμοποιείται για τον εντοπισμό entries.
- `data_#`: Αρχεία blocks σταθερού μεγέθους, τα οποία μπορεί να περιέχουν cache metadata, HTTP headers και response data.
- `f_######`: Ξεχωριστά αρχεία που χρησιμοποιούνται για data μεγαλύτερα από το όριο των block files· αυτά τα αρχεία περιέχουν τα αποθηκευμένα data χωρίς τα block-file headers.

Η διαγραφή messages, channels ή servers δεν εγγυάται την αφαίρεση bytes που έχουν ήδη αποθηκευτεί locally στο cache, όμως το Chromium μπορεί να κάνει eviction ή να δημιουργήσει ξανά cache files οποιαδήποτε στιγμή. Αντιμετωπίστε τα artifacts που παραμένουν ως opportunistic evidence και χρησιμοποιήστε τα file modification times μόνο ως πρόχειρες ενδείξεις local writes, οι οποίες πρέπει να συσχετίζονται με άλλα telemetry δεδομένα.<sup>[[5]](#references)[[6]](#references)</sup>

## Τι μπορεί να ανακτηθεί

Ανάλογα με το τι έγινε fetch και δεν έχει ακόμη γίνει eviction, το triage μπορεί να ανακτήσει cached attachments, media, URLs και file hashes· το cache από μόνο του δεν αποδεικνύει ότι ένα item έγινε exfiltrated.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments και thumbnails που αναφέρονται από Discord CDN URLs.
- Images, GIFs και videos (για παράδειγμα, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` και `.webm`).
- Webhook URLs όπως `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls όπως `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hashes των media που ανακτήθηκαν, για σύγκριση με γνωστά datasets ή intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Γρήγορο triage (χειροκίνητο)

- Κάντε Grep στο cache για high-signal artifacts. Αυτά τα patterns αντικατοπτρίζουν τα URL expressions του parser που αναφέρεται και αποτελούν triage filters, όχι εξαντλητικούς indicators.<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ταξινομήστε τα cached entries βάσει modified time για να δημιουργήσετε μια πρόχειρη ακολουθία· το mtime είναι filesystem signal και από μόνο του δεν καθορίζει πότε έγινε fetch ή send ενός Discord object.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Στη blockfile διάταξη, τα `f_######` αρχεία είναι ξεχωριστά data streams και δεν είναι εγγυημένο ότι ξεκινούν με ένα πλήρες HTTP response. Αν ένα acquired file περιέχει serialized HTTP headers ακολουθούμενα από `\r\n\r\n`, κάντε split στο πρώτο delimiter και εξετάστε:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Για την εξαγωγή του media type
- Content-Location ή X-Original-URL: Το αρχικό remote URL για preview/correlation
- Content-Encoding: Μπορεί να είναι gzip/deflate/br (Brotli).

Στη συνέχεια, το media μπορεί να εξαχθεί κάνοντας split τα headers από το body και προαιρετικά decompressing σύμφωνα με το `Content-Encoding`· ο parser που αναφέρεται χειρίζεται Brotli, gzip και deflate. Το magic-byte sniffing είναι χρήσιμο όταν απουσιάζει το `Content-Type`, αλλά παραμένει heuristic.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Κάνει recursive scan στον Discord cache folder, εντοπίζει webhook/API/attachment URLs, κάνει parsing στα `f_*` bodies, προαιρετικά κάνει carving media και παράγει HTML και CSV reports, καθώς και προαιρετικό chronological timeline με SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

Example CLI usage:
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
Το CLI ορίζει τις παρακάτω επιλογές και ονόματα output:<sup>[[2]](#references)</sup>
- --cache: Διαδρομή προς τον κατάλογο Discord Cache_Data
- --format html|csv|both
- --timeline: Δημιουργεί ταξινομημένο CSV timeline (κατά modified time)
- --extra: Σαρώνει επίσης τα sibling Code Cache και GPUCache
- --carve: Πραγματοποιεί carving media από raw cache bytes χρησιμοποιώντας αναγνωρισμένες media signatures (images/video)
- Output: `<output>.html`, `<output>.csv`, προαιρετικά `<output>_timeline.csv` και έναν φάκελο `<output>_media` με extracted ή carved files.

## Συμβουλές για analysts

- Συσχετίστε το modified time (mtime) των αρχείων `f_*` και `data_*` με τα χρονικά παράθυρα δραστηριότητας χρηστών ή attackers και με ανεξάρτητη telemetry· το mtime δεν αποτελεί οριστικό event timestamp.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Υπολογίστε hash για τα recovered media (SHA-256) και συγκρίνετέ τα με γνωστά κακόβουλα datasets ή datasets exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Αντιμετωπίστε τα extracted webhook URLs ως credentials. Μην τα καλείτε απλώς για να ελέγξετε αν είναι ενεργά· διατηρήστε τα με ασφαλή τρόπο, συντονίστε το revocation ή rotation και χρησιμοποιήστε σχετική network telemetry για retro-hunting.<sup>[[7]](#references)</sup>
- Η διαγραφή από την πλευρά του server δεν εγγυάται ότι τα local cached bytes έχουν καταστραφεί. Αν είναι δυνατή η acquisition, συλλέξτε ολόκληρο τον κατάλογο `Cache` και τα related sibling caches (`Code Cache`, `GPUCache`) πριν από το eviction ή την αναδημιουργία του cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Πώς το Discord αναβάθμισε απρόσκοπτα εκατομμύρια χρήστες σε αρχιτεκτονική 64-bit](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Το Discord ως C2 και τα cached evidence που παραμένουν](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Εκτέλεση Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
