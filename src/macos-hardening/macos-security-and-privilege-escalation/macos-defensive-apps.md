# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Θα παρακολουθεί κάθε σύνδεση που γίνεται από κάθε διεργασία. Ανάλογα με τη λειτουργία (σιωπηλή επιτρεπόμενη σύνδεση, σιωπηλή απόρριψη σύνδεσης και ειδοποίηση) θα **σου εμφανίζει ειδοποίηση** κάθε φορά που δημιουργείται μια νέα σύνδεση. Έχει επίσης πολύ ωραίο GUI για να βλέπεις όλες αυτές τις πληροφορίες.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall της Objective-See. Αυτό είναι ένα βασικό firewall που θα σε ειδοποιεί για ύποπτες συνδέσεις (έχει GUI, αλλά δεν είναι τόσο εντυπωσιακό όσο του Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Εφαρμογή της Objective-See που θα ψάξει σε αρκετές τοποθεσίες όπου **το malware θα μπορούσε να επιμένει** (είναι εργαλείο μίας χρήσης, όχι υπηρεσία παρακολούθησης).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Όπως το KnockKnock, παρακολουθώντας διεργασίες που δημιουργούν persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Εφαρμογή της Objective-See για να βρει **keyloggers** που εγκαθιστούν keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Σύστημα binary authorization και παρακολούθησης για macOS. Χρησιμοποιεί έναν πελάτη **Endpoint Security** για να εξουσιοδοτεί γεγονότα **`exec`** πριν εκτελεστεί ο κώδικας, οπότε είναι συνηθισμένο σε enterprise fleets που εστιάζουν σε **allowlisting/denylisting** αντί μόνο σε ανίχνευση μετά την εκτέλεση.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Εργαλείο δυναμικής ανάλυσης macOS παρόμοιο με το Procmon. Εισάγει **Endpoint Security telemetry** (process, file, interprocess, login και XProtect-related events) και είναι χρήσιμο για να καταλάβεις τι μπορεί πραγματικά να παρατηρήσει ένας ώριμος ES-based sensor.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Ελαφριά εργαλεία της Objective-See για telemetry **process**, **file** και **DNS**. Σε σύγχρονο macOS έχουν επιπλέον προϋποθέσεις όπως **root**, **Terminal Full Disk Access** ή έγκριση **System/Network Extension**. Για περισσότερες ιδέες instrumentation δες [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

Τα περισσότερα σύγχρονα προϊόντα ασφάλειας macOS τρέχουν ως κάποιος συνδυασμός από **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, και εφαρμογές με **Full Disk Access**. Μια γρήγορη operator checklist:
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
If `systemextensionsctl list` shows a sensor as **`[activated enabled]`**, it is usually the fastest indicator that the extension is actually live. On **macOS 15 Sequoia and later**, MDM can also mark specific security extensions as **non-removable from the UI**, so "disable it from System Settings" is no longer a safe assumption. For internals, see [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Πρόσφατη native telemetry που μπορούν να αξιοποιήσουν οι defenders

Οι πρόσφατες εκδόσεις του macOS έκαναν κάποιους bypasses που βασίζονταν σε ενέργειες του χρήστη και ήταν δύσκολο να εντοπιστούν, πολύ πιο θορυβώδεις για τα blue teams:

- **macOS 15+**: Οι Endpoint Security clients μπορούν να λαμβάνουν **`gatekeeper_user_override`** events, οπότε τα manual Gatekeeper bypasses μπορούν να καταγράφονται κεντρικά.
- **Το τρέχον Endpoint Security tooling του macOS** μπορεί επίσης να εισάγει **XProtect malware detection** events, διευκολύνοντας την επιβεβαίωση του τι έχει ήδη εντοπίσει η Apple στο endpoint.
- **macOS 15.4+**: Το Endpoint Security προσθέτει το **`tcc_modify`**, που επιτέλους δίνει στους defenders έναν υποστηριζόμενο τρόπο να παρακολουθούν **TCC grants/revokes** αντί να κάνουν scraping τα TCC debug logs.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Αυτό είναι χρήσιμο τόσο για τους defenders όσο και για τους red teamers που κάνουν self-assessment: αν το target έχει ένα ώριμο ES-based stack, **τα user-approved Gatekeeper / TCC bypass chains μπορεί να είναι πολύ πιο ορατά από ό,τι παλαιότερα**. Για background σχετικά με αυτές τις προστασίες, δείτε [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) και [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
