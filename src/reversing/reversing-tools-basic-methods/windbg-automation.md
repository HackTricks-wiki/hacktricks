# Αυτοματοποίηση WinDbg για στοχευμένο instrumentation

{{#include ../../banners/hacktricks-training.md}}

Τα WinDbg και WinDbgX μπορούν να εκτελούν εντολές debugger κατά την εκκίνηση, σε exceptions και όταν ενεργοποιούνται breakpoints. Έτσι, μια συνεδρία fuzzing ή reversing μπορεί να συλλέγει κατάσταση μόνο γύρω από μια διαδρομή που καθορίζεται από το input, αντί να σταματά χειροκίνητα σε κάθε συμβάν.<sup>[[1]](#references)</sup>

## Έναρξη σε χρήσιμο exception

Το `-c` εκτελεί εντολές κατά το αρχικό break του debugger. Προσθέστε `;g` για να συνεχίσετε μετά την προετοιμασία. Για unattended εκτέλεση του WinDbg Classic, το `-logo` γράφει το παράθυρο εντολών σε log, το `-Q` απενεργοποιεί την αυτόματη αποθήκευση του workspace και το `-G` αγνοεί το τελικό breakpoint, ώστε η συνεδρία να τερματίζεται όταν κλείσει το target. Το WinDbgX δέχεται επίσης το `-c`· οι ρυθμισμένες εντολές Startup εκτελούνται στη συνέχεια.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Για παραβιάσεις πρόσβασης, το **`sxe av` διακόπτει στην πρώτη ευκαιρία**, το **`sxd av` παραλείπει την πρώτη ευκαιρία, αλλά διακόπτει στη δεύτερη ευκαιρία, αν η εξαίρεση δεν έχει αντιμετωπιστεί**, και το **`sxi av` αγνοεί και τις δύο ευκαιρίες**. Οι περιγραφές των `sxi`/`sxd` στο άρθρο είναι αντίστροφες: η Microsoft τεκμηριώνει το `sxd` ως φίλτρο δεύτερης ευκαιρίας και το `sxi` ως αγνόηση. Χρησιμοποιήστε το `-c` για εντολή πρώτης ευκαιρίας και το `-c2` για εντολή δεύτερης ευκαιρίας· ένας handler `-c` πρώτης ευκαιρίας δεν γίνεται handler δεύτερης ευκαιρίας απλώς και μόνο επειδή το φίλτρο είναι `sxd`. Επιβεβαιώστε τα ενεργά φίλτρα με `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Η πρώτη εντολή συλλέγει registers, stack trace και ανάλυση εξαίρεσης μόνο για μια μη χειριζόμενη παραβίαση πρόσβασης. Η δεύτερη εκτελεί την `lm` όταν φορτώνεται ένα module. Τα συμβάντα breakpoint (`bp`), φόρτωσης module (`ld`) και παραβίασης πρόσβασης (`av`) έχουν διαφορετικούς κύκλους ζωής, επομένως μην αγνοείτε καθολικά τα `bp` όταν βασίζεστε σε breakpoints του debugger.<sup>[[1]](#references)[[2]](#references)</sup>

## Ενεργοποίηση ακριβών breakpoints μέσω ελεγχόμενου trigger

Επιλέξτε μια συνάρτηση ορατή σε script ή ελεγχόμενη με άλλον τρόπο από την είσοδο, η οποία μπορεί να κληθεί αμέσως πριν από τη διαδρομή που σας ενδιαφέρει. Εγκαταστήστε **action breakpoints** στις κλήσεις allocator, parser ή API που θέλετε να επιθεωρήσετε. Απενεργοποιήστε τα με βάση το ID τους χρησιμοποιώντας `bd`. Εγκαταστήστε ένα **trigger breakpoint** με συνημμένη εντολή που ενεργοποιεί αυτά τα ID με `be` και, στη συνέχεια, συνεχίζει με `g`· ένα δεύτερο ελεγχόμενο trigger μπορεί να τα απενεργοποιήσει ξανά. Ελέγξτε τα ID με `bl` πριν συνδέσετε το trigger, επειδή εξαρτώνται από τη σειρά δημιουργίας των breakpoints. Έτσι διαχωρίζονται τα φθηνά σημεία ελέγχου από το ακριβό tracing και περιορίζονται οι αλλαγές στον χρονισμό και τη διάταξη του heap του target.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Αφού επιλύσετε τα δύο symbols, ακολουθεί το μοτίβο εντολών. Αντικαταστήστε τα symbols μέσα στις αγκύλες και το ID του action breakpoint που επέστρεψε το `bl`· μην θεωρείτε δεδομένο ότι είναι μηδέν.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Οι εντολές των action breakpoints μπορούν να εμφανίσουν τα `@$ip` και `%y` (διεύθυνση με σύμβολο), να κάνουν dump επιλεγμένων ορισμάτων ή μνήμης και, στη συνέχεια, να συνεχίσουν την εκτέλεση. Αν ένα conditional breakpoint καταγράφει μόνο pointers μέσα σε ένα επιλεγμένο εύρος, επαλήθευσε πρώτα ότι το εύρος καλύπτει πράγματι το input της δοκιμής· μια λανθασμένη συνθήκη χάνει σιωπηλά στοιχεία.<sup>[[1]](#references)</sup>

### Εντοπισμός trigger με σύμβολα

Αναζήτησε σε όλα τα φορτωμένα modules αν δεν γνωρίζεις το module που περιέχει την υλοποίηση. Το `bm` ορίζει breakpoints σε κάθε σύμβολο που ταιριάζει· κάλεσε τη συνάρτηση που είναι ορατή στο script και εξέτασε ποιο breakpoint ενεργοποιείται. Για παράδειγμα, ο source κώδικας καλεί το `Math.cos(0)` στον renderer που γίνεται debug, όχι σε οποιαδήποτε διεργασία browser.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Μόλις μια ενεργοποίηση εντοπίσει την ακριβή συνάρτηση, χρησιμοποιήστε `lm a <symbol>` για να εντοπίσετε το image που την περιέχει και `? <symbol> - <module>` για να υπολογίσετε ένα module-relative offset. Το WinDbg μπορεί να εμφανίζει το ίδιο σύντομο όνομα module για ένα εκτελέσιμο και ένα DLL, επομένως επαληθεύστε τη διαδρομή του image πριν χρησιμοποιήσετε το offset σε άλλη διεργασία. Περιορίστε τα wildcard breakpoints στο επαληθευμένο symbol για να αποφύγετε την επιβάρυνση.<sup>[[1]](#references)</sup>

### Εντοπισμός υποψηφίου χωρίς symbols

Το `corelan_trigscan.py` της Corelan, βασισμένο στο Frida, σαρώνει ένα επιλεγμένο module διεργασίας για μοτίβα εντολών κινητής υποδιαστολής, SSE, AVX και τριγωνομετρικών συναρτήσεων. Παράγει εντολές breakpoint του WinDbg στο `corelan_trigscan.bps` και μικρότερα αριθμημένα αρχεία `.bps`. Εκτελέστε το με Python και `frida-tools` στο target **χωρίς να είναι συνδεδεμένος άλλος debugger**· έπειτα συνδέστε το WinDbg στην ίδια διεργασία/module και φορτώστε μια διαχειρίσιμη ομάδα breakpoints.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Για μια γνωστή μετατόπιση ως προς τη μονάδα, επαληθεύστε ότι παραμένει έγκυρη μετά τα κατώφλια πριν εισαγάγετε όλα τα breakpoints που παρήχθησαν:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` είναι η πυκνότητα σχετικών εντολών, τα `--min-relevant` και `--min-total` ορίζουν κατώτατα όρια πλήθους εντολών, και το `--min-trig` απαιτεί ισχυρές ενδείξεις παρόμοιες με trig. Αν παραλειφθεί μια γνωστή συνάρτηση, δώστε τη **σχετική ως προς το module** μετατόπισή της στο `--check-offset` για να εξετάσετε το prologue, την πυκνότητα, τα πλήθη και τις έμμεσες κλήσεις. Ένα λεπτό wrapper μπορεί να έχει χαμηλή πυκνότητα και καμία εντολή trig. Μειώστε τα κατώτατα όρια και, αν αναζητάτε wrappers, χρησιμοποιήστε την πραγματική επιλογή `--min-icall 1` του script (όχι `--min-ical`): αναλύονται οι άμεσοι callees, αλλά δεν είναι δυνατό να ακολουθούνται αξιόπιστα οι έμμεσοι στόχοι. Μικρότερα batches με `--splitsize` βοηθούν όταν πολλά generated breakpoints επιβραδύνουν το WinDbg. Ένας υποψήφιος δεν έχει επικυρωθεί μέχρι το προβλεπόμενο input να ενεργοποιήσει το breakpoint του.<sup>[[1]](#references)[[6]](#references)</sup>

## Μικρά προγράμματα debugger και PyKD

Χρησιμοποιήστε το `.if` όταν μια συνθήκη είναι αξιόπιστη, το `.foreach` για επανάληψη σε έξοδο που διαχωρίζεται με whitespace, και το `.for` με pseudo-registers για περιήγηση στη μνήμη ή σε δομές. Το `.foreach` **δεν** διατηρεί τις στήλες: για παράδειγμα, η έξοδος του `lm` με μεταβλητό πλάτος είναι κακή είσοδος, ενώ το `lm 1m` δίνει ένα όνομα module ανά token. Καταγράψτε πρώτα τα μη φιλτραρισμένα δεδομένα, αν μια εικαζόμενη συνθήκη μπορεί να αποκρύψει τη διαδρομή που προκαλεί την αποτυχία.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Τα aliases που δημιουργούνται με `as name value` είναι αντικαταστάσεις κειμένου, όχι μεταβλητές με τύπο. Η `al` εμφανίζει τα aliases, η `ad name` διαγράφει ένα και το `${name}` επιβάλλει σαφή επέκταση. Αποφύγετε ονόματα όπως `bp`, `x` ή `r`, επειδή ένα alias μπορεί να επισκιάσει μια ενσωματωμένη εντολή. Οι εκφράσεις MASM είναι κατάλληλες για αριθμητική δεικτών, όπως `poi(@$t0)`· η `@@c++(...)` μπορεί να προσπελάσει πεδία με τύπους, όταν υπάρχουν σύμβολα, αποφεύγοντας τις σταθερά κωδικοποιημένες μετατοπίσεις δομών.<sup>[[1]](#references)</sup>

Τοποθετήστε τις μεγαλύτερες ακολουθίες εντολών σε ένα αρχείο εντολών. Το `$$><filename` ενώνει τις γραμμές σε ένα ενιαίο μπλοκ εντολών και επιτρέπει μια επόμενη εντολή του debugger, διαχωρισμένη με ελληνικό ερωτηματικό. Οι πολυγραμμικές δομές ελέγχου μπορεί και πάλι να είναι εύθραυστες· κρατήστε κάθε εντολή `.if` ή `.for` σε μία γραμμή. Το ίδιο αρχείο μπορεί να κληθεί από το `-c` κατά την εκκίνηση.<sup>[[1]](#references)[[8]](#references)</sup>

Για λογική που δεν εκφράζεται εύκολα στη γλώσσα εντολών, το PyKD παρέχει στην Python πρόσβαση σε δομές με τύπους, καταχωρητές, μνήμη και έξοδο του debugger. Για παράδειγμα, η `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` προσπελαύνει πεδία του PEB, η `pykd.loadBytes(address, size)` διαβάζει μνήμη και η `pykd.dbgCommand("lm")` επιστρέφει έξοδο του debugger για ανάλυση. Προτιμήστε τις οριοθετημένες `loadChars`/`loadWChars` αντί για μη οριοθετημένες αναγνώσεις συμβολοσειρών, όταν τα δεδομένα ενδέχεται να μην έχουν τερματισμό. Η `disasm(address).asm(instruction)` του PyKD **εγγράφει συναρμολογημένα bytes σε εκείνη τη διεύθυνση**, επομένως διατηρήστε και επαναφέρετε την αρχική μνήμη, αν τη χρησιμοποιήσετε για να αποκτήσετε opcodes σε ζωντανή διεργασία.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Αποσφαλμάτωση - Αυτοματοποίηση και scripting στο WinDBG(X) - Μέρος 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Ορισμός εξαιρέσεων)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Ενεργοποίηση breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Απενεργοποίηση breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Ορισμός breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Πηγαίος κώδικας του Corelan trigscan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Επιλογές γραμμής εντολών του WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Εκτέλεση αρχείου script](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
