# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Είναι μια γλώσσα scripting που χρησιμοποιείται για αυτοματοποίηση εργασιών **αλληλεπιδρώντας με απομακρυσμένες διεργασίες**. Κάνει πολύ εύκολο το να **ζητάς από άλλες διεργασίες να εκτελέσουν ορισμένες ενέργειες**. Το **Malware** μπορεί να καταχραστεί αυτές τις δυνατότητες για να εκμεταλλευτεί συναρτήσεις που εξάγονται από άλλες διεργασίες.\
Για παράδειγμα, ένα malware θα μπορούσε να **inject arbitrary JS code in browser opened pages**. Ή να **auto click** κάποιες άδειες allow permissions που ζητούνται από τον χρήστη;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Βρείτε περισσότερες πληροφορίες για malware χρησιμοποιώντας applescripts [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Οι εγκρίσεις Apple Events είναι **κατευθυντικές**: το prompt αφορά ένα ζεύγος **source process -> target process**. Μόλις ο χρήστης κάνει κλικ στο **Allow**, τα μελλοντικά αιτήματα από το ίδιο source προς το ίδιο target επιτρέπονται μέχρι να γίνει reset η εγγραφή. Κατά τη διάρκεια testing, η χορήγηση `Terminal -> Finder` ή `Terminal -> System Events` μία φορά αρκεί για να επαναχρησιμοποιηθεί αργότερα η permission χωρίς άλλο popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Αυτό είναι ιδιαίτερα σχετικό όταν ο **στόχος** είναι το **Finder**, επειδή το Finder έχει πάντα **Full Disk Access** ακόμα κι αν δεν εμφανίζεται στο FDA UI. Επομένως, οποιοσδήποτε host έχει ήδη Automation πάνω στο Finder μπορεί να χρησιμοποιηθεί ως AppleScript/JXA proxy για πρόσβαση σε αρχεία που προστατεύονται από TCC. Τα γενικά Finder και System Events payloads έχουν ήδη τεκμηριωθεί στο [the main TCC page](../README.md) και στο [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

Το `/usr/bin/osascript` είναι μόνο το πιο ορατό entry point. Το AppleScript και το JXA μπορούν επίσης να εκτελεστούν από **Mach-O binaries** μέσω των **`NSAppleScript`** / **`OSAScript`**, κάτι που είναι χρήσιμο τόσο για evasion όσο και για living inside a host που έχει ήδη ενδιαφέροντα TCC grants.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Αν δημιουργήσετε έναν προσαρμοσμένο helper που στέλνει απευθείας Apple Events, το να του δώσετε μια **πραγματική ταυτότητα app** κάνει το testing και τη λειτουργία πολύ πιο αξιόπιστα. Στην πράξη αυτό σημαίνει ενσωμάτωση ενός `Info.plist` με `CFBundleIdentifier` και `NSAppleEventsUsageDescription`, υπογραφή του binary, και παροχή του entitlement `com.apple.security.automation.apple-events`. Διαφορετικά, το Apple Events prompt συχνά αποδίδεται στο **parent host** (για παράδειγμα `Terminal`) ή η εκτέλεση του `NSAppleScript` απλώς αποτυγχάνει με μπερδεμένα σφάλματα `-1750` / `errOSASystemError`.

Τα Apple scripts μπορούν εύκολα να "**compiled**". Αυτές οι εκδόσεις μπορούν εύκολα να "**decompiled**" με το `osadecompile`

Ωστόσο, αυτά τα scripts μπορούν επίσης να εξαχθούν ως **"Read only"** (μέσω της επιλογής "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
και σε αυτή την περίπτωση το περιεχόμενο δεν μπορεί να αποσυμπιληθεί ακόμη και με `osadecompile`

Ωστόσο, εξακολουθούν να υπάρχουν κάποια εργαλεία που μπορούν να χρησιμοποιηθούν για να κατανοήσετε αυτό το είδος executables, [**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Το tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) με [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) θα είναι πολύ χρήσιμο για να καταλάβετε πώς λειτουργεί το script.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
