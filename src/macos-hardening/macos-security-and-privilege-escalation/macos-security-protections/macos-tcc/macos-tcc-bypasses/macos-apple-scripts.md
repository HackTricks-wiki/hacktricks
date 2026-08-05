# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Είναι μια scripting language που χρησιμοποιείται για αυτοματοποίηση εργασιών **αλληλεπιδρώντας με remote processes**. Καθιστά αρκετά εύκολο να **ζητηθεί από άλλες processes να εκτελέσουν ορισμένες ενέργειες**. Το **Malware** μπορεί να κάνει κατάχρηση αυτών των δυνατοτήτων, ώστε να κάνει κατάχρηση λειτουργιών που εξάγονται από άλλες processes.\
Για παράδειγμα, ένα malware θα μπορούσε να **εισάγει αυθαίρετο κώδικα JS σε σελίδες που έχουν ανοιχτεί σε browser**. Ή να πραγματοποιεί **auto click** σε ορισμένα allow permissions που ζητούνται από τον χρήστη·<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Εδώ θα βρείτε μερικά παραδείγματα: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Βρείτε περισσότερες πληροφορίες σχετικά με malware που χρησιμοποιεί AppleScripts [**εδώ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Αυτοματισμός / ιδιαιτερότητες του TCC

Οι εγκρίσεις του Apple Events είναι **κατευθυντικές**: το prompt αφορά ένα ζεύγος **process-πηγής -> process-στόχου**. Μόλις ο χρήστης κάνει κλικ στο **Allow**, τα μελλοντικά αιτήματα από την ίδια πηγή προς τον ίδιο στόχο επιτρέπονται μέχρι να γίνει reset της καταχώρισης. Κατά τη διάρκεια των δοκιμών, η παραχώρηση της άδειας `Terminal -> Finder` ή `Terminal -> System Events` μία φορά αρκεί για να επαναχρησιμοποιηθεί αργότερα η permission χωρίς άλλο popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Αυτό είναι ιδιαίτερα σημαντικό όταν το **target** είναι το **Finder**, επειδή το Finder έχει πάντα **Full Disk Access**, ακόμη και αν δεν εμφανίζεται στο FDA UI. Επομένως, οποιοσδήποτε host διαθέτει ήδη **Automation** προς το Finder μπορεί να χρησιμοποιηθεί ως AppleScript/JXA proxy για την πρόσβαση σε αρχεία που προστατεύονται από το TCC.<sup>[[1]](#references)</sup> Τα generic Finder και System Events payloads είναι ήδη τεκμηριωμένα [στην κύρια σελίδα του TCC](../README.md) και [στη σελίδα Apple Events](../macos-apple-events.md).

### Σύγχρονες offensive τεχνικές

Το `/usr/bin/osascript` είναι μόνο το πιο εμφανές entry point. Τα AppleScript και JXA μπορούν επίσης να εκτελεστούν από **Mach-O binaries** μέσω των **`NSAppleScript`** / **`OSAScript`**, κάτι που είναι χρήσιμο τόσο για evasion όσο και για την εκτέλεση κώδικα μέσα σε έναν host που διαθέτει ήδη ενδιαφέροντα TCC grants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Αν δημιουργήσετε ένα custom helper που στέλνει Apple Events απευθείας, η παροχή μιας **πραγματικής ταυτότητας εφαρμογής** καθιστά τις δοκιμές και τις λειτουργίες πολύ πιο αξιόπιστες. Στην πράξη, αυτό σημαίνει την ενσωμάτωση ενός `Info.plist` με `CFBundleIdentifier` και `NSAppleEventsUsageDescription`, την υπογραφή του binary και την εκχώρηση του entitlement `com.apple.security.automation.apple-events`. Διαφορετικά, το prompt των Apple Events αποδίδεται συχνά στο **parent host** (για παράδειγμα, στο `Terminal`) ή η εκτέλεση του `NSAppleScript` απλώς αποτυγχάνει με τα δυσνόητα σφάλματα `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Τα Apple scripts μπορούν εύκολα να γίνουν **compiled**. Αυτές οι εκδόσεις μπορούν εύκολα να γίνουν **decompiled** με το `osadecompile`

Ωστόσο, αυτά τα scripts μπορούν επίσης να **εξαχθούν ως "Read only"** (μέσω της επιλογής "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
και σε αυτή την περίπτωση το περιεχόμενο δεν μπορεί να γίνει decompiled ακόμη και με το `osadecompile`

Ωστόσο, υπάρχουν ορισμένα εργαλεία που μπορούν να χρησιμοποιηθούν για την κατανόηση αυτού του είδους των executables, [**διαβάστε αυτή την έρευνα για περισσότερες πληροφορίες**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Το εργαλείο [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) μαζί με το [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) θα είναι πολύ χρήσιμο για την κατανόηση του τρόπου λειτουργίας του script.

## Αναφορές

- [1] [Παράκαμψη των User Privacy Protections του macOS TCC κατά λάθος και εκ设计](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Πώς να κάνετε το AppleScript να λειτουργεί σε macOS CLI Tools: Τα μη τεκμηριωμένα μέρη](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Πώς οι Offensive Actors χρησιμοποιούν το AppleScript για επιθέσεις στο macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Περιπέτειες στο Reversing κακόβουλων Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
