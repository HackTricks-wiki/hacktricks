# Στατική Αποσυσκότιση Cached Bytecode Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Τα cached data του V8 είναι μια **αναπαράσταση με απώλειες, εξαρτώμενη από την έκδοση**, όχι πηγαίος κώδικας JavaScript ούτε συμβατικό native εκτελέσιμο. Επομένως, μια χρήσιμη στατική ροή εργασιών είναι: αφαιρέστε τυχόν εξωτερικό επίπεδο συσκευασίας, αποσυναρμολογήστε το cache με το αντίστοιχο build του V8, μετατρέψτε το σε ένα ενδιάμεσο μοντέλο ψευδοκώδικα και εφαρμόστε μετασχηματισμούς που λαμβάνουν υπόψη τις εξαρτήσεις, χωρίς να εκτελέσετε το δείγμα. Τα [View8](https://github.com/suleram/View8) και [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) υλοποιούν αυτή την προσέγγιση για payloads Node.js που προστατεύονται από το `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Λήψη και αποσυναρμολόγηση του cache

Αρχικά, εξετάστε το preload/launcher αντί να θεωρήσετε ότι όλα τα αρχεία `.jsc` έχουν το ίδιο wrapper. Για παράδειγμα, ένας launcher όπως το `node.exe -r preflight.js app.jsc` εκτελεί το `preflight.js` πριν από το κύριο module· στην οικογένεια που αναλύθηκε, το preload αφαίρεσε ένα επίπεδο Brotli. Μετά την αποσυσκευασία, προσδιορίστε τη συγκεκριμένη γενιά Node.js/V8 από το ενσωματωμένο runtime. Ένα cache που δημιουργήθηκε από μία έκδοση του V8 μπορεί να απορριφθεί ή να αποκωδικοποιηθεί εσφαλμένα από μια άλλη, επομένως δημιουργήστε ή αποκτήστε ένα `v8dasm` για το συγκεκριμένο V8 tag και εφαρμόστε τα απαιτούμενα patches του View8 και της εκτύπωσης συμβολοσειρών.<sup>[[1]](#references)[[2]](#references)</sup>

Η ροή εργασιών του toolkit που δεν εκτελεί το δείγμα είναι η εξής:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

Το `--normalize` δίνει στις παραγόμενες συναρτήσεις σταθερά αναγνωριστικά μεταξύ εκτελέσεων. Το κειμενικό αποτέλεσμα προορίζεται για επιθεώρηση· το serialized γράφημα αντικειμένων επιτρέπει σε ανεξάρτητα περάσματα να διατηρούν τις σχέσεις μεταξύ συναρτήσεων, δηλωτών, scopes και μεταδεδομένων. **Δεν είναι ανακατασκευασμένη ή εκτελέσιμη JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Διαλογή ενός cache χωρίς να γίνει build του V8

Για ένα raw ή Brotli-wrapped cache, το `jscd` μπορεί να αναγνωρίσει την κεφαλίδα και να απαριθμήσει σταθερές και συναρτήσεις χωρίς να φορτώσει το δείγμα στο Node.js. Χρησιμοποιήστε το πρώτα για να ελέγξετε αν οι πίνακες εκδόσεων υποστηρίζουν το αρχείο και να ιεραρχήσετε τις συναρτήσεις πριν από τα πιο εξειδικευμένα περάσματα αποαπόκρυψης του View8.<sup>[[4]](#references)</sup>

Το version hash είναι ένδειξη αναγνώρισης, όχι απόδειξη ότι ένας standalone disassembler έχει τα ίδια flags ή το ίδιο read-only snapshot με τον παραγωγό.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` παράγει μια λίστα συμβατή με το View8, επομένως η παραπάνω εντολή του View8 μπορεί να χρησιμοποιήσει αυτή την έξοδο αντί για το `v8dasm`, όταν υποστηρίζεται το cache. Επιθεωρήστε τα strings μαζί με το δέντρο συναρτήσεων για να εντοπίσετε κλήσεις decoder και πιθανά entry points· μην θεωρείτε ότι η κατά προσέγγιση έξοδος JavaScript του `jscd` είναι ο αρχικός πηγαίος κώδικας. Αν το εργαλείο απορρίψει την έκδοση ή αφήσει placeholders του read-only heap, επιστρέψτε σε ένα αντίστοιχο build του V8 ή δώστε έναν name map από το ίδιο build, αντί να μαντεύετε ονόματα ιδιοτήτων.<sup>[[4]](#references)</sup>

Για ένα cache μέσα σε εφαρμογή Electron, πρώτα [εξαγάγετε το ASAR και επιθεωρήστε τα entry points των main και preload](../../desktop-application-security/electron-desktop-apps/). Τα cache του Electron και του Node μπορεί να διαφέρουν στη διάταξη snapshot και pointer-compression, ακόμη κι όταν οι συμβολοσειρές έκδοσης του V8 ταυτίζονται.<sup>[[4]](#references)</sup>

### Διαβάστε το ψευδοκώδικα View8 ως IR

Τυπικά ονόματα είναι `func_<name>_0x<address>`, τα ορίσματα είναι `a0...aN`, οι virtual registers είναι `r0...rN` και το `ACCU` είναι ο accumulator του V8. Το `start` είναι η root declarer, ενώ τα `Scope[...]`, globals και dictionaries μοντελοποιούν τιμές που έχουν δεσμευτεί ή είναι κοινόχρηστες από nested functions. Μην αναλύετε κάθε έκφραση ως σύνταξη JavaScript: για παράδειγμα, το `!r6 === "0"` στο View8 αναπαριστά άρνηση ολόκληρης της σύγκρισης (`r6 !== "0"`), κάτι που έχει σημασία κατά την ανακατασκευή των branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Αποσυσκότιση με επίγνωση εξαρτήσεων

Εφαρμόστε μετασχηματισμούς με σειρά που αποκαλύπτει τις εισόδους που χρειάζεται το επόμενο πέρασμα και επαναλάβετε το propagation μέχρι να σταθεροποιηθεί η έξοδος. Μια πρακτική σειρά είναι:<sup>[[1]](#references)[[2]](#references)</sup>

1. Διατρέξτε την ιεραρχία των declarer και κάντε propagate τιμές από globals, registers, dictionaries και αναφορές `Scope[...]`.
2. Ανακτήστε τα ορίσματα του string-decoder και αντικαταστήστε τις κρυπτογραφημένες κλήσεις με plaintext.
3. Συγχωνεύστε γειτονικά τμήματα string· τα ονόματα ιδιοτήτων και τα strings σειράς dispatcher που προκύπτουν ξεκλειδώνουν τα επόμενα περάσματα.
4. Ξετυλίξτε τη ροή ελέγχου, κάντε inline τα call proxies και τα wrappers atomic-operation και επιλύστε αναφορές συναρτήσεων που βρίσκονται σε dictionary.
5. Κάντε ξανά propagate, επειδή κάθε string, key ή proxy που επιλύεται μπορεί να αποκαλύψει άλλο επίπεδο έμμεσης αναφοράς.
6. Συμπτύξτε αναγνωρισμένα one-shot initialization thunks και αφαιρέστε τους νεκρούς helpers μόνο αφού επιλυθούν τα call sites τους.

### Ανάκτηση shifted RC4 string arrays ως black box

Μια συνηθισμένη διάταξη του `javascript-obfuscator` αποθηκεύει chunks RC4 κωδικοποιημένα σε Base64 σε έναν πίνακα. Τα wrappers του decoder δίνουν ένα αριθμητικό offset και ένα σύντομο key, μερικές φορές με αντίστροφη σειρά ορισμάτων, και στη συνέχεια προσθέτουν ή αφαιρούν σταθερές που έχουν δεσμευτεί σε closure scopes. Όταν ο root decoder είναι υπερβολικά συσκοτισμένος, ανακτήστε εμπειρικά την άγνωστη μετατόπιση του δείκτη του πίνακα αντί να ανακατασκευάσετε ολόκληρη τη συνάρτηση.<sup>[[1]](#references)</sup>

Για έναν πίνακα με `N` chunks και αρκετές κλήσεις στον ίδιο decoder:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Μην αποδέχεστε μια μετατόπιση μόνο επειδή μία αποκρυπτογράφηση δίνει εκτυπώσιμο κείμενο: το λάθος ciphertext μπορεί να φαίνεται εκτυπώσιμο τυχαία. Χρησιμοποιήστε τουλάχιστον τρεις διαφορετικές παρατηρήσεις και αποδεχτείτε μόνο μια μοναδική μετατόπιση που δίνει εύλογο κείμενο για όλες. Έπειτα, διασχίστε το γράφημα wrapper/declarer, αθροίζοντας κάθε πρόσθεση ή αφαίρεση και καταγράφοντας αν το αριθμητικό όρισμα εμφανίζεται πρώτο. Αποθηκεύστε αυτά τα metadata ανά δείγμα, αντικαταστήστε τις κλήσεις decoder, συνενώστε τα γειτονικά τμήματα plaintext και εξαγάγετε τις συμβολοσειρές ξεχωριστά για triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Διατήρηση της σημασιολογίας κατά την αφαίρεση του flattening

Για dispatcher loops που καθοδηγούνται από strings όπως `3|2|1|0|4`, αποκωδικοποιήστε το string της σειράς, αντιστοιχίστε κάθε σύγκριση κατάστασης στο block της, λάβετε υπόψη τη σημειογραφία αρνητικών συνθηκών του View8 και, στη συνέχεια, εκπέμψτε τα blocks με τη σειρά του dispatcher. Ένα ένθετο `continue` μπορεί να αναπαριστά ένα πρόωρο άλμα πίσω στον dispatcher αντί για συνηθισμένη συνέχεια της ροής. Κατά την αφαίρεση του loop, διαγράψτε αυτό το `continue` και μετακινήστε τις εντολές που ακολουθούσαν αρχικά το `if` που το περιείχε σε ένα παραγόμενο branch `else`· η απλή διαγραφή του dispatcher αλλάζει τη συμπεριφορά.<sup>[[1]](#references)</sup>

### Ενσωμάτωση proxies, operations και lazy thunks

Κανονικοποιήστε forwarding helpers όπως το `return a0(a1, a2)` πριν αντικαταστήσετε τα σημεία κλήσης τους με απευθείας κλήσεις. Αντιμετωπίστε με τον ίδιο τρόπο wrappers για αφαίρεση, διαίρεση, σύγκριση, ελέγχους membership ή invocation. Επειδή η αναφορά του helper μπορεί να είναι αποθηκευμένη πίσω από ένα αποκρυπτογραφημένο dictionary key ή μια closure value, εκτελέστε propagation συμβολοσειρών και δομών πριν και μετά το inlining.<sup>[[1]](#references)</sup>

Αναγνωρίστε επίσης closures που καλούν μία φορά μια αποθηκευμένη συνάρτηση, εκκαθαρίζουν την αναφορά της, αποθηκεύουν το αποτέλεσμα στην cache και επιστρέφουν αυτήν την τιμή σε μεταγενέστερες κλήσεις. Η σύμπτυξη ενός τέτοιου thunk σε σημείο αρχικοποίησης αποκαλύπτει τον υποκείμενο dispatcher ή capability function, αλλά σημειώστε ότι η αρχική εκτέλεση ήταν **one-shot και cached**, αντί να μοντελοποιείτε κάθε κλήση ως νέα invocation.<sup>[[1]](#references)</sup>

## Σημειώσεις ασφάλειας και επικύρωσης

- Η φόρτωση Python `pickle` μπορεί να εκτελέσει κώδικα. Φορτώνετε μόνο αρχεία `.pkl` που δημιουργήθηκαν τοπικά από την έμπιστη εκτέλεση του View8· μην αντιμετωπίζετε ποτέ ένα pickle που παρέχεται από το δείγμα ως δεδομένα.<sup>[[2]](#references)</sup>
- Η απουσία του σώματος μιας συνάρτησης δεν αποδεικνύει ότι η πηγή δεν περιείχε αυτήν τη συνάρτηση: το V8 μπορεί να σειριοποιήσει μια lazy function ως metadata μέχρι να γίνει compile κατά την πρώτη κλήση. Διατηρείτε τέτοιες συναρτήσεις σημειωμένες ως unresolved κατά το static triage.<sup>[[6]](#references)</sup>
- Τα pattern-driven passes δεν αποτελούν γενικό JavaScript decompiler. Διατηρείτε τις unresolved expressions και επιθεωρείτε χειροκίνητα τις αμφίσημες παραλλαγές dispatcher, αντί να επιβάλλετε την αναδιατύπωσή τους.<sup>[[1]](#references)[[2]](#references)</sup>
- Τα ονόματα συναρτήσεων που προτείνονται με τη βοήθεια LLM είναι υποδείξεις πλοήγησης, όχι αποδεικτικά στοιχεία. Αν τα χρησιμοποιείτε, επεξεργαστείτε τις εξαρτήσεις από τα φύλλα προς τη ρίζα, αλλά επαληθεύστε κάθε ετικέτα με βάση το σώμα, τα ορίσματα, τις συμβολοσειρές, τη ροή δεδομένων, τα APIs και τις παρενέργειες.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Σπάζοντας τη σφραγίδα: Στατική αποσυσκότιση του μεταγλωττισμένου bytecode V8 του JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Κεφαλίδα V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache κώδικα του Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
