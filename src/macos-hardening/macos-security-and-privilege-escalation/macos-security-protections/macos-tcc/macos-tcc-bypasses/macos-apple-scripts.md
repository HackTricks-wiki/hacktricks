# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Το AppleScript είναι μια γλώσσα αυτοματοποίησης που μπορεί να στέλνει Apple Events σε εφαρμογές με υποστήριξη για scripting. Με τις σχετικές παραχωρήσεις, το malware μπορεί να εισαγάγει JavaScript σε μια καρτέλα scriptable browser ή να χρησιμοποιήσει τα System Events/Accessibility για να κάνει κλικ σε ένα παράθυρο διαλόγου δικαιωμάτων. Τα Apple Events και το Accessibility είναι διαφορετικές υπηρεσίες TCC και γενικά απαιτούν τις αντίστοιχες εγκρίσεις του χρήστη.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Το repository `abbeycode/AppleScripts` περιέχει παραδείγματα automation.<sup>[[7]](#references)</sup>\
Βρείτε περισσότερες πληροφορίες σχετικά με malware που χρησιμοποιεί applescripts [**εδώ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / ιδιομορφίες του TCC

Οι εγκρίσεις των Apple Events είναι **κατευθυντικές**: το prompt αφορά ένα ζεύγος **source process -> target process**. Μόλις ο χρήστης κάνει κλικ στο **Allow**, τα μελλοντικά requests από το ίδιο source προς το ίδιο target επιτρέπονται μέχρι να γίνει reset της καταχώρισης. Κατά τη διάρκεια του testing, η έγκριση των `Terminal -> Finder` ή `Terminal -> System Events` μία φορά αρκεί για την επαναχρησιμοποίηση του permission αργότερα, χωρίς άλλο popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Αυτό είναι ιδιαίτερα relevant όταν το **target** είναι το **Finder**, επειδή το Finder έχει πάντα **Full Disk Access**, ακόμη και αν δεν εμφανίζεται στο FDA UI. Επομένως, οποιοδήποτε host διαθέτει ήδη **Automation** προς το Finder μπορεί να χρησιμοποιηθεί ως AppleScript/JXA proxy για πρόσβαση σε TCC-protected αρχεία.<sup>[[1]](#references)</sup> Τα generic Finder και System Events payloads τεκμηριώνονται ήδη στη [main TCC page](../README.md) και στη [Apple Events page](../macos-apple-events.md).

### Σύγχρονο offensive tradecraft

Το `/usr/bin/osascript` είναι μόνο το πιο εμφανές entry point. Τα AppleScript και JXA μπορούν επίσης να εκτελεστούν από **Mach-O binaries** μέσω των **`NSAppleScript`** / **`OSAScript`**, κάτι που είναι χρήσιμο τόσο για evasion όσο και για να παραμένουν μέσα σε ένα host που διαθέτει ήδη ενδιαφέροντα TCC grants.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Αν δημιουργήσετε ένα custom helper που στέλνει Apple Events απευθείας, η χρήση μιας **real app identity** το καθιστά πολύ πιο αξιόπιστο για testing και operations. Στην πράξη, αυτό σημαίνει ενσωμάτωση ενός `Info.plist` με `CFBundleIdentifier` και `NSAppleEventsUsageDescription`, signing του binary και παραχώρηση του entitlement `com.apple.security.automation.apple-events`. Διαφορετικά, το prompt των Apple Events αποδίδεται συχνά στο **parent host** (για παράδειγμα, στο `Terminal`) ή η εκτέλεση του `NSAppleScript` απλώς αποτυγχάνει με τα ασαφή σφάλματα `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Τα AppleScripts μπορούν να αποθηκευτούν σε compiled μορφή και συνήθως να γίνουν decompiled με το `osadecompile`.

Ωστόσο, αυτά τα scripts μπορούν επίσης να **exported ως "Read only"** (μέσω της επιλογής "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Σε αυτή την περίπτωση, το `osadecompile` αρνείται να ανακτήσει κανονικό πηγαίο κώδικα, όμως το bytecode και η ορολογία του Apple Event μπορούν ακόμη να αναλυθούν.

Η έρευνα της SentinelOne για τα run-only scripts περιγράφει τον τρόπο ανάκτησης της δομής παρά αυτόν τον περιορισμό. Τα `applescript-disassembler` και `aevt_decompile` βοηθούν στην επιθεώρηση του compiled script και των δεδομένων Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Παράκαμψη των macOS TCC User Privacy Protections κατά λάθος και εκ σχεδιασμού](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Κάνοντας το AppleScript να λειτουργεί σε macOS CLI Tools: Τα μη τεκμηριωμένα μέρη](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Πώς οι Offensive Actors χρησιμοποιούν το AppleScript για επιθέσεις σε macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Περιπέτειες στο Reverse Engineering κακόβουλων Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts examples](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
