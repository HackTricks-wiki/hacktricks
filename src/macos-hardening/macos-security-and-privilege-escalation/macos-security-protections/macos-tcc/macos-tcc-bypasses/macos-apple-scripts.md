# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Είναι μια scripting language που χρησιμοποιείται για την αυτοματοποίηση εργασιών, **αλληλεπιδρώντας με remote processes**. Καθιστά αρκετά εύκολο να **ζητηθεί από άλλες διεργασίες να εκτελέσουν κάποιες ενέργειες**. Το **malware** μπορεί να κάνει abuse αυτών των δυνατοτήτων για να κάνει abuse functions που εξάγονται από άλλες διεργασίες.\
Για παράδειγμα, ένα malware θα μπορούσε να **κάνει inject arbitrary JS code σε σελίδες που έχουν ανοιχτεί σε browser**. Ή να κάνει **auto click** σε ορισμένα allow permissions που ζητούνται από τον χρήστη·<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Εδώ θα βρείτε ορισμένα παραδείγματα: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Βρείτε περισσότερες πληροφορίες σχετικά με malware που χρησιμοποιεί applescripts [**εδώ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Ιδιαιτερότητες Automation / TCC

Οι εγκρίσεις Apple Events είναι **κατευθυντικές**: το prompt αφορά ένα ζεύγος **source process -> target process**. Μόλις ο χρήστης κάνει κλικ στο **Allow**, τα μελλοντικά requests από το ίδιο source προς το ίδιο target επιτρέπονται μέχρι να γίνει reset της καταχώρισης. Κατά τη διάρκεια των δοκιμών, η έγκριση των `Terminal -> Finder` ή `Terminal -> System Events` μία φορά αρκεί για την επαναχρησιμοποίηση του permission αργότερα, χωρίς άλλο popup.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Αυτό είναι ιδιαίτερα σημαντικό όταν το **target** είναι το **Finder**, επειδή το Finder έχει πάντα **Full Disk Access**, ακόμη και αν δεν εμφανίζεται στο FDA UI. Επομένως, οποιοσδήποτε host διαθέτει ήδη Automation over Finder μπορεί να χρησιμοποιηθεί ως AppleScript/JXA proxy για πρόσβαση σε TCC-protected αρχεία.<sup>[1]</sup> Τα generic Finder και System Events payloads τεκμηριώνονται ήδη στη [main TCC page](../README.md) και στη [Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

Το `/usr/bin/osascript` είναι μόνο το πιο εμφανές entry point. Τα AppleScript και JXA μπορούν επίσης να εκτελούνται από **Mach-O binaries** μέσω των **`NSAppleScript`** / **`OSAScript`**, κάτι που είναι χρήσιμο τόσο για evasion όσο και για να παραμένουν μέσα σε έναν host που διαθέτει ήδη ενδιαφέροντα TCC grants.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Αν δημιουργήσετε ένα custom helper που στέλνει Apple Events απευθείας, η παροχή μιας **πραγματικής ταυτότητας εφαρμογής** κάνει τις δοκιμές και τις λειτουργίες πολύ πιο αξιόπιστες. Στην πράξη, αυτό σημαίνει την ενσωμάτωση ενός `Info.plist` με τα `CFBundleIdentifier` και `NSAppleEventsUsageDescription`, την υπογραφή του binary και την παροχή του entitlement `com.apple.security.automation.apple-events`. Διαφορετικά, το prompt των Apple Events αποδίδεται συχνά στο **γονικό host** (για παράδειγμα, στο `Terminal`) ή η εκτέλεση του `NSAppleScript` απλώς αποτυγχάνει με τα δυσνόητα σφάλματα `-1750` / `errOSASystemError`.<sup>[2]</sup>

Τα Apple scripts μπορούν εύκολα να "**compiled**". Αυτές οι εκδόσεις μπορούν εύκολα να "**decompiled**" με το `osadecompile`

Ωστόσο, αυτά τα scripts μπορούν επίσης να **εξαχθούν ως "Read only"** (μέσω της επιλογής "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
και σε αυτή την περίπτωση το περιεχόμενο δεν μπορεί να γίνει decompiled ούτε με το `osadecompile`

Ωστόσο, εξακολουθούν να υπάρχουν ορισμένα εργαλεία που μπορούν να χρησιμοποιηθούν για την κατανόηση αυτού του είδους των executables, [**διαβάστε αυτή την έρευνα για περισσότερες πληροφορίες**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Το εργαλείο [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) μαζί με το [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) θα είναι πολύ χρήσιμο για την κατανόηση του τρόπου λειτουργίας του script.

## Αναφορές

- [1] [Παράκαμψη των User Privacy Protections του macOS TCC κατά λάθος και εκ σχεδιασμού](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Πώς να κάνετε το AppleScript να λειτουργεί σε macOS CLI Tools: Τα μη τεκμηριωμένα μέρη](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Πώς οι Offensive Actors χρησιμοποιούν το AppleScript για επιθέσεις σε macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Περιπέτειες στο Reversing κακόβουλων Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
