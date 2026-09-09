# Static Deobfuscation του Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

Τα V8 cached data είναι μια **version-dependent, lossy representation**, όχι JavaScript source και όχι ένα συμβατικό native executable. Επομένως, ένα χρήσιμο static workflow είναι: αφαίρεση τυχόν outer packing, disassemble του cache με το αντίστοιχο V8 build, μετατροπή του σε ένα intermediate pseudocode model και εφαρμογή dependency-aware transformations χωρίς εκτέλεση του sample. Τα [View8](https://github.com/suleram/View8) και [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) υλοποιούν αυτή την προσέγγιση για Node.js payloads που προστατεύονται από το `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Απόκτηση και disassemble του cache

Αρχικά εξετάστε το preload/launcher αντί να θεωρήσετε ότι κάθε αρχείο `.jsc` διαθέτει το ίδιο wrapper. Για παράδειγμα, ένας launcher όπως `node.exe -r preflight.js app.jsc` εκτελεί το `preflight.js` πριν από το κύριο module· στη συγκεκριμένη οικογένεια που αναλύθηκε, το preload αφαίρεσε ένα Brotli layer. Μετά το unpacking, εντοπίστε την ακριβή Node.js/V8 generation από το bundled runtime. Ένα cache που δημιουργήθηκε από μία V8 version μπορεί να απορριφθεί ή να γίνει decode εσφαλμένα από κάποια άλλη, επομένως κάντε build ή αποκτήστε ένα `v8dasm` για το συγκεκριμένο V8 tag και εφαρμόστε τα απαιτούμενα View8 και string-printing patches.<sup>[[1]](#references)[[2]](#references)</sup>

Το non-executing workflow του toolkit είναι:<sup>[[2]](#references)</sup>
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
Το `--normalize` δίνει στις παραγόμενες functions σταθερά αναγνωριστικά μεταξύ διαφορετικών runs. Η έξοδος κειμένου προορίζεται για επιθεώρηση· το serialized object graph επιτρέπει σε ανεξάρτητα passes να διατηρούν τις σχέσεις μεταξύ function, declarer, scope και metadata. **Δεν αποτελεί ανακατασκευασμένη ή εκτελέσιμη JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Ανάγνωση του pseudocode του View8 ως IR

Τα συνηθισμένα ονόματα είναι `func_<name>_0x<address>`, τα arguments είναι `a0...aN`, τα virtual registers είναι `r0...rN` και το `ACCU` είναι ο accumulator του V8. Το `start` είναι ο root declarer, ενώ τα `Scope[...]`, τα globals και τα dictionaries μοντελοποιούν τιμές που γίνονται captured ή διαμοιράζονται από nested functions. Μην αναλύετε κάθε expression ως σύνταξη JavaScript: για παράδειγμα, το `!r6 === "0"` του View8 αναπαριστά την άρνηση ολόκληρης της σύγκρισης (`r6 !== "0"`), κάτι που έχει σημασία κατά την ανακατασκευή των branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation με επίγνωση dependencies

Εφαρμόστε τους μετασχηματισμούς με σειρά που αποκαλύπτει τα inputs που απαιτούνται από το επόμενο pass και επαναλάβετε το propagation μέχρι να σταθεροποιηθεί η έξοδος. Μια πρακτική σειρά είναι:<sup>[[1]](#references)[[2]](#references)</sup>

1. Διασχίστε την ιεραρχία των declarers και κάντε propagate τις τιμές από globals, registers, dictionaries και references σε `Scope[...]`.
2. Ανακτήστε τα arguments των string-decoders και αντικαταστήστε τα encrypted calls με plaintext.
3. Κάντε fold τα γειτονικά string chunks· τα resulting property names και τα dispatcher-order strings ξεκλειδώνουν τα επόμενα passes.
4. Κάντε unflatten το control flow, κάντε inline τα call proxies και τα wrappers των atomic operations και επιλύστε τις function references που βρίσκονται σε dictionaries.
5. Κάντε ξανά propagate, επειδή κάθε resolved string, key ή proxy μπορεί να αποκαλύψει ένα ακόμη επίπεδο indirection.
6. Συγχωνεύστε τα αναγνωρισμένα one-shot initialization thunks και αφαιρέστε τα dead helpers μόνο αφού επιλυθούν τα call sites τους.

### Ανάκτηση shifted RC4 string arrays ως black box

Μια συνηθισμένη διάταξη του `javascript-obfuscator` αποθηκεύει Base64-encoded RC4 chunks σε έναν array. Τα decoder wrappers παρέχουν ένα numeric offset και ένα σύντομο key, μερικές φορές με reversed argument order, και στη συνέχεια προσθέτουν ή αφαιρούν constants που έχουν γίνει captured σε closure scopes. Όταν ο root decoder είναι υπερβολικά obfuscated, ανακτήστε εμπειρικά το άγνωστο array-index shift αντί να ανακατασκευάσετε ολόκληρη τη function.<sup>[[1]](#references)</sup>

Για έναν array με `N` chunks και several calls στον ίδιο decoder:<sup>[[1]](#references)</sup>
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
Μην αποδέχεστε μια μετατόπιση από μία μόνο printable αποκρυπτογράφηση: το λάθος ciphertext μπορεί τυχαία να φαίνεται printable. Χρησιμοποιήστε τουλάχιστον τρεις διαφορετικές παρατηρήσεις και αποδεχτείτε μόνο μια μοναδική μετατόπιση που παράγει plausible text για όλες. Στη συνέχεια, διατρέξτε το γράφημα wrapper/declarer, συσσωρεύοντας κάθε πρόσθεση ή αφαίρεση και καταγράφοντας αν το αριθμητικό όρισμα εμφανίζεται πρώτο. Κάντε cache αυτά τα metadata ανά sample, αντικαταστήστε τις decoder calls, ενώστε τα γειτονικά plaintext chunks και εξαγάγετε ξεχωριστά τα strings για triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Διατήρηση της semantics κατά το unflattening

Για dispatcher loops που καθοδηγούνται από strings όπως `3|2|1|0|4`, αποκωδικοποιήστε το order string, αντιστοιχίστε κάθε state comparison στο block του, λάβετε υπόψη τη negated-condition notation του View8 και, στη συνέχεια, εκδώστε τα blocks με τη σειρά του dispatcher. Ένα nested `continue` μπορεί να αντιπροσωπεύει ένα early jump πίσω στον dispatcher αντί για ένα συνηθισμένο fall-through. Κατά την αφαίρεση του loop, διαγράψτε αυτό το `continue` και μετακινήστε τις statements που αρχικά ακολουθούσαν το enclosing `if` σε ένα παραγόμενο `else` branch· η απλή διαγραφή του dispatcher αλλάζει τη συμπεριφορά.<sup>[[1]](#references)</sup>

### Inline proxies, operations και lazy thunks

Κανονικοποιήστε forwarding helpers όπως το `return a0(a1, a2)` πριν αντικαταστήσετε τα call sites τους με direct calls. Αντιμετωπίστε αντίστοιχα τα wrappers για subtraction, division, comparison, membership tests ή invocation. Επειδή το helper reference μπορεί να είναι αποθηκευμένο πίσω από ένα decrypted dictionary key ή closure value, εκτελέστε string και structure propagation πριν και μετά το inlining.<sup>[[1]](#references)</sup>

Αναγνωρίστε επίσης closures που καλούν μία φορά μια stored function, διαγράφουν το reference της, κάνουν cache το result και επιστρέφουν αυτό το cache σε μεταγενέστερες calls. Η σύμπτυξη ενός τέτοιου thunk σε initialization site αποκαλύπτει τον underlying dispatcher ή capability function, αλλά σημειώστε ότι η αρχική εκτέλεση ήταν **one-shot και cached**, αντί να μοντελοποιείτε κάθε call ως νέα invocation.<sup>[[1]](#references)</sup>

## Σημειώσεις ασφάλειας και validation

- Η φόρτωση Python `pickle` μπορεί να εκτελέσει code. Φορτώνετε μόνο αρχεία `.pkl` που δημιουργήθηκαν τοπικά από το trusted View8 run· μην αντιμετωπίζετε ποτέ ένα sample-supplied pickle ως data.<sup>[[2]](#references)</sup>
- Τα pattern-driven passes δεν αποτελούν general JavaScript decompiler. Διατηρήστε τα unresolved expressions και επιθεωρήστε χειροκίνητα τις ambiguous dispatcher variants αντί να επιβάλλετε rewrite.<sup>[[1]](#references)[[2]](#references)</sup>
- Τα LLM-assisted function names είναι navigation hints και όχι evidence. Αν τα χρησιμοποιείτε, επεξεργαστείτε τα dependencies leaf-first, αλλά επαληθεύστε κάθε label σε σχέση με το body, τα arguments, τα strings, το data flow, τα APIs και τα side effects.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
