# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Είναι μια γλώσσα scripting που χρησιμοποιείται για την αυτοματοποίηση εργασιών **αλληλεπιδρώντας με απομακρυσμένες διαδικασίες**. Διευκολύνει πολύ το **να ζητάμε από άλλες διαδικασίες να εκτελέσουν κάποιες ενέργειες**. **Malware** μπορεί να εκμεταλλευτεί αυτές τις δυνατότητες για να εκμεταλλευτεί τις λειτουργίες που εξάγονται από άλλες διαδικασίες.\
Για παράδειγμα, ένα malware θα μπορούσε να **εισάγει αυθαίρετο κώδικα JS σε ανοιγμένες σελίδες του προγράμματος περιήγησης**. Ή να **κάνει αυτόματη κλικ** σε κάποιες άδειες που ζητούνται από τον χρήστη;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Εδώ έχετε μερικά παραδείγματα: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Βρείτε περισσότερες πληροφορίες σχετικά με το malware χρησιμοποιώντας applescripts [**εδώ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Τα Apple scripts μπορεί να είναι εύκολα "**συμπιεσμένα**". Αυτές οι εκδόσεις μπορούν να είναι εύκολα "**αποσυμπιεσμένες**" με το `osadecompile`

Ωστόσο, αυτά τα scripts μπορούν επίσης να **εξαχθούν ως "Μόνο για ανάγνωση"** (μέσω της επιλογής "Εξαγωγή..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
και σε αυτή την περίπτωση το περιεχόμενο δεν μπορεί να αποσυμπιεστεί ακόμη και με το `osadecompile`

Ωστόσο, υπάρχουν ακόμα μερικά εργαλεία που μπορούν να χρησιμοποιηθούν για να κατανοήσουν αυτούς τους τύπους εκτελέσιμων, [**διαβάστε αυτή την έρευνα για περισσότερες πληροφορίες**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Το εργαλείο [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) με το [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) θα είναι πολύ χρήσιμο για να κατανοήσετε πώς λειτουργεί το σενάριο.

{{#include ../../../../../banners/hacktricks-training.md}}
