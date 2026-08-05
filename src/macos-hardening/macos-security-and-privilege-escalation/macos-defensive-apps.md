# Εφαρμογές άμυνας του macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Παρακολουθεί κάθε σύνδεση που πραγματοποιείται από κάθε process. Ανάλογα με το mode (σιωπηρή αποδοχή συνδέσεων, σιωπηρή απόρριψη σύνδεσης και ειδοποίηση), θα **σας εμφανίζει μια ειδοποίηση** κάθε φορά που δημιουργείται μια νέα σύνδεση. Διαθέτει επίσης ένα πολύ καλό GUI για την προβολή όλων αυτών των πληροφοριών.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall της Objective-See. Πρόκειται για ένα βασικό firewall που σας ειδοποιεί για ύποπτες συνδέσεις (διαθέτει GUI, αλλά δεν είναι τόσο εντυπωσιακό όσο του Little Snitch).

## Ανίχνευση Persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Εφαρμογή της Objective-See που αναζητά σε διάφορες τοποθεσίες όπου **θα μπορούσε να έχει εγκατασταθεί malware για persistence** (είναι εργαλείο μίας εκτέλεσης και όχι υπηρεσία monitoring).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Όπως το KnockKnock, παρακολουθεί processes που δημιουργούν persistence.

## Ανίχνευση Keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Εφαρμογή της Objective-See για την εύρεση **keyloggers** που εγκαθιστούν keyboard "event taps"

## Endpoint telemetry / έλεγχος εκτέλεσης

- [**Santa**](https://santa.dev/): Σύστημα binary authorization και monitoring για macOS. Χρησιμοποιεί έναν client του **Endpoint Security** για την εξουσιοδότηση events **`exec`** πριν εκτελεστεί ο κώδικας, επομένως χρησιμοποιείται συχνά σε enterprise fleets που εστιάζουν σε **allowlisting/denylisting** αντί για αποκλειστικά post-execution detection.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Εργαλείο δυναμικής ανάλυσης macOS τύπου Procmon. Συλλέγει **Endpoint Security telemetry** (events σχετικά με processes, files, interprocess επικοινωνία, login και XProtect) και είναι χρήσιμο για την κατανόηση του τι μπορεί πραγματικά να παρατηρήσει ένας ώριμος sensor βασισμένος στο ES.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Ελαφριά εργαλεία της Objective-See για telemetry σχετικά με **processes**, **files** και **DNS**. Σε σύγχρονες εκδόσεις του macOS απαιτούν επιπλέον προϋποθέσεις, όπως **root**, **Terminal Full Disk Access** ή έγκριση **System/Network Extension**. Για περισσότερες ιδέες instrumentation, δείτε [αυτή την άλλη σελίδα σχετικά με την επιθεώρηση/debugging εφαρμογών macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Γρήγορο triage εργαλείων άμυνας

Τα περισσότερα σύγχρονα προϊόντα ασφάλειας για macOS εκτελούνται ως κάποιος συνδυασμός από **System Extensions / Endpoint Security clients**, **launchd agents/daemons** και εφαρμογές με **Full Disk Access**. Μια γρήγορη checklist για τον operator:
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
Αν το `systemextensionsctl list` εμφανίζει έναν αισθητήρα ως **`[activated enabled]`**, αυτό είναι συνήθως η ταχύτερη ένδειξη ότι το extension είναι πράγματι ενεργό. Στο **macOS 15 Sequoia και νεότερα**, το MDM μπορεί επίσης να επισημάνει συγκεκριμένα security extensions ως **μη αφαιρέσιμα από το UI**, επομένως η υπόθεση ότι «μπορείς να το απενεργοποιήσεις από τις Ρυθμίσεις συστήματος» δεν είναι πλέον ασφαλής. Για τα internals, δείτε [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Πρόσφατη εγγενής telemetry που μπορούν να αξιοποιήσουν οι defenders

Οι πρόσφατες εκδόσεις του macOS έκαναν ορισμένα user-driven bypasses που ήταν προηγουμένως δύσκολο να ανιχνευθούν πολύ πιο θορυβώδη για τις blue teams:

- **macOS 15+**: Οι clients του Endpoint Security μπορούν να λαμβάνουν events **`gatekeeper_user_override`**, επομένως τα χειροκίνητα Gatekeeper bypasses μπορούν να καταγράφονται κεντρικά.
- Τα **τρέχοντα εργαλεία Endpoint Security του macOS** μπορούν επίσης να εισάγουν events ανίχνευσης malware από το **XProtect**, διευκολύνοντας την επιβεβαίωση όσων έχει ήδη εντοπίσει η Apple στο endpoint.
- **macOS 15.4+**: Το Endpoint Security προσθέτει το **`tcc_modify`**, παρέχοντας επιτέλους στους defenders έναν υποστηριζόμενο τρόπο παρακολούθησης των **TCC grants/revokes**, αντί για scraping των TCC debug logs.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Αυτό είναι χρήσιμο τόσο για defenders όσο και για red teamers που κάνουν self-assessment: αν ο στόχος διαθέτει ώριμο ES-based stack, **οι αλυσίδες παράκαμψης του Gatekeeper / TCC που έχουν εγκριθεί από τον χρήστη μπορεί να είναι πολύ πιο ορατές από ό,τι παλαιότερα**. Για πληροφορίες σχετικά με αυτές τις προστασίες, δείτε τα [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) και [TCC](macos-security-protections/macos-tcc/README.md).

## Αναφορές

- [1] [Objective-See - Το TCCing είναι πεποίθηση! Η Apple προσθέτει επιτέλους events του TCC στο Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Παρουσίαση: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
