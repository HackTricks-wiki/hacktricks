# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει τον τρόπο triage των cache artifacts του Discord Desktop για την ανάκτηση exfiltrated αρχείων, webhook endpoints και timelines δραστηριότητας. Το Discord Desktop είναι εφαρμογή Electron/Chromium και χρησιμοποιεί το Chromium Simple Cache στον δίσκο.

## Πού να αναζητήσετε (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Βασικές on-disk δομές μέσα στο Cache_Data:<sup>[[1]](#references)</sup>
- index: Βάση δεδομένων index του Simple Cache
- data_#: Binary αρχεία cache block που μπορούν να περιέχουν πολλά cached objects
- f_######: Μεμονωμένα cached entries που αποθηκεύονται ως standalone αρχεία (συχνά μεγαλύτερα bodies)

Σημείωση: Η διαγραφή messages/channels/servers στο Discord δεν διαγράφει τοπικά αυτό το cache. Τα cached items συχνά παραμένουν και τα timestamps των αρχείων τους συμπίπτουν με τη δραστηριότητα του χρήστη, επιτρέποντας την ανακατασκευή timeline.<sup>[[1]](#references)</sup>

## Τι μπορεί να ανακτηθεί

- Exfiltrated attachments και thumbnails που ανακτήθηκαν μέσω cdn.discordapp.com/media.discordapp.net
- Images, GIFs, videos (π.χ. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- Χρήσιμο για τη συσχέτιση beaconing/exfil activity και το hashing media για intel matching<sup>[[1]](#references)</sup>

## Quick triage (manual)

- Κάντε grep στο cache για high-signal artifacts:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ταξινομήστε τα cached entries με βάση τον χρόνο τροποποίησης για να δημιουργήσετε ένα quick timeline (το mtime αντικατοπτρίζει τη στιγμή που το object εισήλθε στο cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Τα αρχεία που ξεκινούν με f_ περιέχουν HTTP response headers ακολουθούμενα από το body. Το block των headers συνήθως τελειώνει με \r\n\r\n. Χρήσιμα response headers περιλαμβάνουν:
- Content-Type: Για την εξαγωγή του media type
- Content-Location ή X-Original-URL: Το αρχικό remote URL για preview/correlation
- Content-Encoding: Μπορεί να είναι gzip/deflate/br (Brotli)

Τα media μπορούν να εξαχθούν διαχωρίζοντας τα headers από το body και, προαιρετικά, κάνοντας decompress με βάση το Content-Encoding. Το magic-byte sniffing είναι χρήσιμο όταν απουσιάζει το Content-Type.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Σαρώνει recursively τον cache folder του Discord, εντοπίζει webhook/API/attachment URLs, κάνει parsing στα f_* bodies, προαιρετικά κάνει carve media και παράγει HTML + CSV timeline reports με SHA‑256 hashes.<sup>[[2]](#references)</sup>

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
Βασικές επιλογές:
- --cache: Διαδρομή προς το Cache_Data
- --format html|csv|both
- --timeline: Εξαγωγή ταξινομημένου CSV timeline (κατά modified time)
- --extra: Σάρωση επίσης των γειτονικών Code Cache και GPUCache
- --carve: Carve media από raw bytes κοντά σε regex hits (εικόνες/video)
- Έξοδος: HTML report, CSV report, CSV timeline και φάκελος media με carved/extracted files

## Συμβουλές για τον analyst

- Συσχετίστε το modified time (mtime) των αρχείων f_* και data_* με τα χρονικά διαστήματα δραστηριότητας του χρήστη/attacker, για να ανακατασκευάσετε ένα timeline.
- Υπολογίστε hash στα recovered media (SHA-256) και συγκρίνετέ τα με γνωστά κακόβουλα datasets ή datasets exfil.
- Τα extracted webhook URLs μπορούν να ελεγχθούν για liveness ή να περιστραφούν. Εξετάστε το ενδεχόμενο να τα προσθέσετε σε blocklists και να πραγματοποιήσετε retro-hunting σε proxies.
- Το Cache παραμένει μετά το “wiping” από την πλευρά του server. Αν είναι δυνατή η απόκτηση, συλλέξτε ολόκληρο το Cache directory και τα σχετικά γειτονικά caches (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Discord ως C2 και τα cached στοιχεία που παραμένουν πίσω](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
