# Στατική αποσυσκότιση cached bytecode Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Τα cached data του V8 είναι **αναπαράσταση με απώλειες, εξαρτώμενη από την έκδοση**, όχι πηγαίος κώδικας JavaScript ούτε συμβατικό native εκτελέσιμο. Επομένως, μια χρήσιμη στατική ροή εργασίας είναι: αφαιρέστε τυχόν εξωτερικό packing, κάντε disassemble το cache με το αντίστοιχο build του V8, μετατρέψτε το σε ένα ενδιάμεσο μοντέλο pseudocode και εφαρμόστε μετασχηματισμούς που λαμβάνουν υπόψη τις εξαρτήσεις, χωρίς να εκτελέσετε το δείγμα. Τα [View8](https://github.com/suleram/View8) και [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) υλοποιούν αυτή την προσέγγιση για payloads Node.js που προστατεύονται με `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Απόκτηση και disassemble του cache

Πρώτα εξετάστε το preload/launcher, αντί να υποθέσετε ότι κάθε αρχείο `.jsc` έχει τον ίδιο wrapper. Για παράδειγμα, ένας launcher όπως ο `node.exe -r preflight.js app.jsc` εκτελεί το `preflight.js` πριν από το κύριο module· στη συγκεκριμένη οικογένεια δειγμάτων που αναλύθηκε, το preload αφαιρούσε ένα επίπεδο Brotli. Μετά την αποσυσκευασία, προσδιορίστε με ακρίβεια τη γενιά Node.js/V8 από το bundled runtime. Ένα cache που δημιουργήθηκε από μία έκδοση V8 μπορεί να απορριφθεί ή να αποκωδικοποιηθεί εσφαλμένα από μια άλλη, επομένως δημιουργήστε ή αποκτήστε ένα `v8dasm` για το ακριβές V8 tag και εφαρμόστε τα απαιτούμενα patches για το View8 και την εκτύπωση συμβολοσειρών.<sup>[[1]](#references)[[2]](#references)</sup>

Η ροή εργασίας του toolkit, η οποία δεν εκτελεί το δείγμα, είναι:<sup>[[2]](#references)</sup>

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

`--normalize` παρέχει στις παραγόμενες συναρτήσεις σταθερά αναγνωριστικά μεταξύ εκτελέσεων. Η έξοδος κειμένου προορίζεται για επιθεώρηση· το serialized γράφημα αντικειμένων επιτρέπει σε ανεξάρτητα passes να διατηρούν τις σχέσεις μεταξύ συναρτήσεων, δηλωτών, scopes και metadata. **Δεν είναι ανακατασκευασμένο JavaScript ούτε μπορεί να εκτελεστεί**.<sup>[[1]](#references)[[2]](#references)</sup>

### Διαλογή ενός cache χωρίς μεταγλώττιση του V8

Για ένα raw cache ή ένα cache τυλιγμένο με Brotli, το `jscd` μπορεί να αναγνωρίσει την κεφαλίδα και να απαριθμήσει constants και συναρτήσεις χωρίς να φορτώσει το δείγμα στο Node.js. Χρησιμοποιήστε το πρώτα για να ελέγξετε αν οι πίνακες εκδόσεών του υποστηρίζουν το αρχείο και για να ιεραρχήσετε τις συναρτήσεις πριν από τα πιο εξειδικευμένα passes αποσυσκότισης του View8.<sup>[[4]](#references)</sup>

Το hash έκδοσης είναι ένδειξη ταυτοποίησης, όχι απόδειξη ότι ένας αυτόνομος disassembler χρησιμοποιεί τα ίδια flags ή το ίδιο read-only snapshot με το εργαλείο που το παρήγαγε.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` παράγει listing συμβατό με το View8, επομένως η εντολή View8 παραπάνω μπορεί να χρησιμοποιήσει αυτή την έξοδο αντί για το `v8dasm`, όταν υποστηρίζεται το cache. Εξετάστε τα strings μαζί με το δέντρο συναρτήσεων για να εντοπίσετε κλήσεις decoder και πιθανά entry points· μην εκλαμβάνετε την κατά προσέγγιση έξοδο JavaScript του `jscd` ως τον αρχικό πηγαίο κώδικα. Αν το εργαλείο απορρίψει την έκδοση ή αφήσει placeholders του read-only heap, χρησιμοποιήστε ξανά ένα αντίστοιχο build του V8 ή δώστε ένα name map από το ίδιο build αντί να μαντέψετε ονόματα ιδιοτήτων.<sup>[[4]](#references)</sup>

Για cache μέσα σε εφαρμογή Electron, πρώτα [εξαγάγετε το ASAR και εξετάστε τα entry points main και preload](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Τα cache του Electron και του Node μπορεί να διαφέρουν στη διάταξη snapshot και pointer-compression, ακόμα κι όταν οι συμβολοσειρές έκδοσης του V8 ταιριάζουν.<sup>[[4]](#references)</sup>

### Διαβάστε το pseudocode του View8 ως IR

Τυπικά ονόματα είναι `func_<name>_0x<address>`, τα ορίσματα είναι `a0...aN`, οι virtual registers είναι `r0...rN` και το `ACCU` είναι ο accumulator του V8. Το `start` είναι ο root declarer, ενώ τα `Scope[...]`, globals και dictionaries μοντελοποιούν τιμές που καταγράφονται ή μοιράζονται από nested functions. Μην αναλύετε κάθε έκφραση ως σύνταξη JavaScript: για παράδειγμα, το `!r6 === "0"` στο View8 αναπαριστά άρνηση ολόκληρης της σύγκρισης (`r6 !== "0"`), κάτι που έχει σημασία κατά την ανακατασκευή των branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Αποσυσκότιση με επίγνωση εξαρτήσεων

Εφαρμόστε τους μετασχηματισμούς με σειρά που αποκαλύπτει τις εισόδους που χρειάζεται το επόμενο πέρασμα και επαναλάβετε τη διάδοση μέχρι να σταθεροποιηθεί η έξοδος. Μια πρακτική σειρά είναι:<sup>[[1]](#references)[[2]](#references)</sup>

1. Διατρέξτε την ιεραρχία των declarer και διαδώστε τιμές από globals, registers, dictionaries και αναφορές `Scope[...]`.
2. Ανακτήστε τα ορίσματα του string decoder και αντικαταστήστε τις κρυπτογραφημένες κλήσεις με plaintext.
3. Συγχωνεύστε γειτονικά string chunks· τα ονόματα ιδιοτήτων και τα strings σειράς dispatcher που προκύπτουν ξεκλειδώνουν τα επόμενα περάσματα.
4. Ξετυλίξτε το control flow, κάντε inline τα call proxies και τα wrappers atomic-operation και επιλύστε αναφορές συναρτήσεων που βρίσκονται σε dictionaries.
5. Επαναλάβετε τη διάδοση, επειδή κάθε επιλυμένο string, key ή proxy μπορεί να αποκαλύψει άλλο ένα επίπεδο έμμεσης αναφοράς.
6. Συμπτύξτε αναγνωρισμένα one-shot initialization thunks και αφαιρέστε dead helpers μόνο αφού επιλυθούν τα call sites τους.

### Ανακτήστε shifted RC4 string arrays ως black box

Μια συνηθισμένη διάταξη του `javascript-obfuscator` αποθηκεύει chunks κωδικοποιημένα με Base64 και RC4 σε ένα array. Τα decoder wrappers παρέχουν ένα numeric offset και ένα σύντομο key, μερικές φορές με αντίστροφη σειρά ορισμάτων, και έπειτα προσθέτουν ή αφαιρούν σταθερές που έχουν καταγραφεί σε closure scopes. Όταν ο root decoder είναι υπερβολικά συσκοτισμένος, ανακτήστε εμπειρικά το άγνωστο array-index shift αντί να ανακατασκευάσετε ολόκληρη τη συνάρτηση.<sup>[[1]](#references)</sup>

Για ένα array με `N` chunks και αρκετές κλήσεις στον ίδιο decoder:<sup>[[1]](#references)</sup>

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

Μην αποδέχεστε μια μετατόπιση αποκρυπτογράφησης επειδή παράγει ένα μόνο εκτυπώσιμο αποτέλεσμα: το λάθος ciphertext μπορεί να φαίνεται εκτυπώσιμο τυχαία. Χρησιμοποιήστε τουλάχιστον τρεις διαφορετικές παρατηρήσεις και αποδεχτείτε μόνο μια μοναδική μετατόπιση που παράγει εύλογο κείμενο για όλες. Στη συνέχεια, διασχίστε το γράφημα wrapper/declarer, αθροίζοντας κάθε πρόσθεση ή αφαίρεση και καταγράφοντας αν το αριθμητικό όρισμα προηγείται. Αποθηκεύστε αυτά τα metadata ανά δείγμα, αντικαταστήστε τις κλήσεις decoder, συνενώστε τα γειτονικά τμήματα plaintext και εξαγάγετε ξεχωριστά τις συμβολοσειρές για triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Διατήρηση της σημασιολογίας κατά το unflattening

Για βρόχους dispatcher που καθοδηγούνται από συμβολοσειρές όπως `3|2|1|0|4`, αποκωδικοποιήστε τη συμβολοσειρά σειράς, αντιστοιχίστε κάθε σύγκριση κατάστασης στο block της, λάβετε υπόψη τη σημειογραφία αρνημένης συνθήκης του View8 και, στη συνέχεια, εκδώστε τα blocks με τη σειρά του dispatcher. Ένα ένθετο `continue` μπορεί να αναπαριστά ένα πρόωρο άλμα πίσω στον dispatcher και όχι μια συνηθισμένη συνέχιση της ροής. Κατά την αφαίρεση του βρόχου, διαγράψτε αυτό το `continue` και μετακινήστε τις εντολές που αρχικά ακολουθούσαν το περιβάλλον `if` σε ένα παραγόμενο σκέλος `else`· η απλή διαγραφή του dispatcher αλλάζει τη συμπεριφορά.<sup>[[1]](#references)</sup>

### Ενσωμάτωση proxy, πράξεων και lazy thunks

Κανονικοποιήστε βοηθητικές συναρτήσεις προώθησης, όπως `return a0(a1, a2)`, πριν αντικαταστήσετε τα σημεία κλήσης τους με άμεσες κλήσεις. Αντιμετωπίστε με τον ίδιο τρόπο wrappers για αφαίρεση, διαίρεση, σύγκριση, ελέγχους συμμετοχής ή κλήση. Επειδή η αναφορά στη βοηθητική συνάρτηση μπορεί να είναι αποθηκευμένη πίσω από ένα αποκρυπτογραφημένο κλειδί λεξικού ή μια τιμή closure, εκτελέστε διάδοση συμβολοσειρών και δομών πριν και μετά το inlining.<sup>[[1]](#references)</sup>

Αναγνωρίστε επίσης closures που καλούν μία φορά μια αποθηκευμένη συνάρτηση, εκκαθαρίζουν την αναφορά της, αποθηκεύουν το αποτέλεσμα στην cache και επιστρέφουν αυτό το αποτέλεσμα σε επόμενες κλήσεις. Η σύμπτυξη ενός τέτοιου thunk στο σημείο αρχικοποίησης αποκαλύπτει τον υποκείμενο dispatcher ή τη συνάρτηση capability, αλλά σημειώστε ότι η αρχική εκτέλεση ήταν **μοναδικής εκτέλεσης και αποθηκευμένη στην cache**, αντί να μοντελοποιείτε κάθε κλήση ως νέα εκτέλεση.<sup>[[1]](#references)</sup>

## Σημειώσεις ασφάλειας και επικύρωσης

- Η φόρτωση Python `pickle` μπορεί να εκτελέσει κώδικα. Φορτώνετε αρχεία `.pkl` που δημιουργήθηκαν τοπικά μόνο από αξιόπιστη εκτέλεση του View8· μην αντιμετωπίζετε ποτέ ένα pickle που παρέχεται από δείγμα ως δεδομένα.<sup>[[2]](#references)</sup>
- Η απουσία σώματος συνάρτησης δεν αποδεικνύει ότι η αρχική πηγή δεν περιείχε αυτή τη συνάρτηση: το V8 μπορεί να σειριοποιήσει μια lazy function μόνο ως metadata, μέχρι να μεταγλωττιστεί κατά την πρώτη κλήση. Διατηρείτε τέτοιες συναρτήσεις σημειωμένες ως ανεπίλυτες κατά το static triage.<sup>[[6]](#references)</sup>
- Τα περάσματα που βασίζονται σε μοτίβα δεν αποτελούν γενικό JavaScript decompiler. Διατηρείτε τις ανεπίλυτες εκφράσεις και εξετάζετε χειροκίνητα τις αμφίσημες παραλλαγές dispatcher αντί να επιβάλλετε έναν μετασχηματισμό.<sup>[[1]](#references)[[2]](#references)</sup>
- Τα ονόματα συναρτήσεων που προτείνονται με τη βοήθεια LLM είναι ενδείξεις πλοήγησης, όχι αποδεικτικά στοιχεία. Αν τα χρησιμοποιείτε, επεξεργαστείτε τις εξαρτήσεις πρώτα από τα φύλλα, αλλά επαληθεύστε κάθε ετικέτα με βάση το σώμα, τα ορίσματα, τις συμβολοσειρές, τη ροή δεδομένων, τα API και τις παρενέργειες.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Αποσφράγιση: Στατική αποσυσκότιση του μεταγλωττισμένου bytecode V8 του JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Κεφαλίδα V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache κώδικα Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
