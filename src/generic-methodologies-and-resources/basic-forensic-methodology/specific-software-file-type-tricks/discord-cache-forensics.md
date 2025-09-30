# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πώς να διαχειριστείτε την cache του Discord Desktop για να ανακτήσετε εξαχθέντα αρχεία, webhook endpoints και χρονολογίες δραστηριότητας. Το Discord Desktop είναι εφαρμογή Electron/Chromium και χρησιμοποιεί Chromium Simple Cache στο δίσκο.

## Πού να κοιτάξετε (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Βασικές δομές στο δίσκο μέσα στο Cache_Data:
- index: βάση δεδομένων ευρετηρίου του Simple Cache
- data_#: Δυαδικά αρχεία μπλοκ cache που μπορούν να περιέχουν πολλαπλά αποθηκευμένα αντικείμενα
- f_######: Ατομικές εγγραφές cache αποθηκευμένες ως ξεχωριστά αρχεία (συχνά μεγαλύτερα περιεχόμενα)

Σημείωση: Η διαγραφή μηνυμάτων/καναλιών/servers στο Discord δεν εκκαθαρίζει αυτήν την τοπική cache. Τα αποθηκευμένα στοιχεία συχνά παραμένουν και οι χρονικές σφραγίδες των αρχείων αντιστοιχούν στη δραστηριότητα του χρήστη, επιτρέποντας την ανακατασκευή χρονολογίου.

## Τι μπορεί να ανακτηθεί

- Εξαχθέντα συνημμένα και μικρογραφίες που λήφθηκαν μέσω cdn.discordapp.com/media.discordapp.net
- Εικόνες, GIFs, βίντεο (π.χ., .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API calls (https://discord.com/api/vX/…)
- Χρήσιμο για τη συσχέτιση beaconing/exfil δραστηριότητας και για το hashing μέσων για αντιστοίχιση intel

## Γρήγορη διαλογή (χειροκίνητη)

- Χρησιμοποιήστε grep/αναζητήσεις στην cache για artifacts υψηλής σημασίας:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ταξινομήστε τις εγγραφές cache κατά χρόνο τροποποίησης για να φτιάξετε ένα γρήγορο χρονολόγιο (mtime αντικατοπτρίζει πότε το αντικείμενο χτύπησε την cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Τα αρχεία που ξεκινούν με f_ περιέχουν HTTP response headers ακολουθούμενα από το σώμα. Το μπλοκ των headers συνήθως τελειώνει με \r\n\r\n. Χρήσιμα response headers περιλαμβάνουν:
- Content-Type: Για να εξαχθεί ο τύπος μέσου
- Content-Location or X-Original-URL: Το αρχικό απομακρυσμένο URL για συσχέτιση/προεπισκόπηση
- Content-Encoding: Μπορεί να είναι gzip/deflate/br (Brotli)

Τα μέσα μπορούν να εξαχθούν διαχωρίζοντας τα headers από το σώμα και προαιρετικά αποσυμπιέζοντας με βάση το Content-Encoding. Η ανίχνευση μέσω magic-bytes είναι χρήσιμη όταν το Content-Type λείπει.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Σαρώει αναδρομικά τον φάκελο cache του Discord, εντοπίζει webhook/API/attachment URLs, αναλύει τα f_* σώματα, προαιρετικά carve-άρει media, και εξάγει αναφορές χρονολογίου σε HTML + CSV με SHA‑256 hashes.

Example CLI usage:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
Key options:
- --cache: Path to Cache_Data
- --format html|csv|both
- --timeline: Εξάγει ταξινομημένο CSV timeline (κατά modified time)
- --extra: Επίσης σαρώστε τους παρεμφερείς φακέλους Code Cache και GPUCache
- --carve: Εξάγει media από raw bytes κοντά σε regex hits (images/video)
- Output: HTML report, CSV report, CSV timeline, και φάκελος media με carved/extracted αρχεία

## Analyst tips

- Συσχετίστε το modified time (mtime) των αρχείων f_* και data_* με τα παράθυρα δραστηριότητας χρήστη/επιτιθέμενου για να ανασυνθέσετε ένα χρονολόγιο.
- Υπολογίστε το hash των ανακτημένων media (SHA-256) και συγκρίνετέ το με γνωστά-κακόβουλα ή exfil datasets.
- Οι εξαγόμενοι webhook URLs μπορούν να ελεγχθούν για διαθεσιμότητα (liveness) ή να ανανεωθούν· σκεφτείτε να τα προσθέσετε σε blocklists και retro-hunting proxies.
- Η cache παραμένει μετά το “wiping” στην πλευρά του server. Αν είναι δυνατή η απόκτηση, συλλέξτε ολόκληρο τον κατάλογο Cache και τους σχετικούς παρεμφερείς caches (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
