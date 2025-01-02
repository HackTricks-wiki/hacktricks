# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Η πραγματική **είσοδος** ενός Mach-o δυαδικού είναι ο δυναμικά συνδεδεμένος, ο οποίος ορίζεται στο `LC_LOAD_DYLINKER` και συνήθως είναι το `/usr/lib/dyld`.

Αυτός ο σύνδεσμος θα χρειαστεί να εντοπίσει όλες τις εκτελέσιμες βιβλιοθήκες, να τις χαρτογραφήσει στη μνήμη και να συνδέσει όλες τις μη-τεμπέλικες βιβλιοθήκες. Μόνο μετά από αυτή τη διαδικασία, θα εκτελεστεί το σημείο εισόδου του δυαδικού.

Φυσικά, **`dyld`** δεν έχει καμία εξάρτηση (χρησιμοποιεί syscalls και αποσπάσματα libSystem).

> [!CAUTION]
> Εάν αυτός ο σύνδεσμος περιέχει οποιαδήποτε ευπάθεια, καθώς εκτελείται πριν από την εκτέλεση οποιουδήποτε δυαδικού (ακόμα και πολύ προνομιούχων), θα ήταν δυνατό να **κλιμακωθούν τα προνόμια**.

### Flow

Το Dyld θα φορτωθεί από **`dyldboostrap::start`**, το οποίο θα φορτώσει επίσης πράγματα όπως το **stack canary**. Αυτό συμβαίνει επειδή αυτή η συνάρτηση θα λάβει στο **`apple`** όρισμα της το vector και άλλες **ευαίσθητες** **τιμές**.

**`dyls::_main()`** είναι το σημείο εισόδου του dyld και η πρώτη του εργασία είναι να εκτελέσει το `configureProcessRestrictions()`, το οποίο συνήθως περιορίζει τις **`DYLD_*`** μεταβλητές περιβάλλοντος που εξηγούνται σε:

{{#ref}}
./
{{#endref}}

Στη συνέχεια, χαρτογραφεί την κοινή μνήμη dyld που προσυνδέει όλες τις σημαντικές βιβλιοθήκες συστήματος και στη συνέχεια χαρτογραφεί τις βιβλιοθήκες από τις οποίες εξαρτάται το δυαδικό και συνεχίζει αναδρομικά μέχρι να φορτωθούν όλες οι απαραίτητες βιβλιοθήκες. Επομένως:

1. αρχίζει να φορτώνει τις εισαχθείσες βιβλιοθήκες με `DYLD_INSERT_LIBRARIES` (αν επιτρέπεται)
2. Στη συνέχεια τις κοινές που έχουν αποθηκευτεί
3. Στη συνέχεια τις εισαγόμενες
1. &#x20;Στη συνέχεια συνεχίζει να εισάγει βιβλιοθήκες αναδρομικά

Μόλις φορτωθούν όλες, εκτελούνται οι **αρχικοποιητές** αυτών των βιβλιοθηκών. Αυτές είναι κωδικοποιημένες χρησιμοποιώντας **`__attribute__((constructor))`** που ορίζεται στο `LC_ROUTINES[_64]` (τώρα αποσυρμένο) ή μέσω δείκτη σε μια ενότητα που έχει σημαία με `S_MOD_INIT_FUNC_POINTERS` (συνήθως: **`__DATA.__MOD_INIT_FUNC`**).

Οι τερματιστές είναι κωδικοποιημένοι με **`__attribute__((destructor))`** και βρίσκονται σε μια ενότητα που έχει σημαία με `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Όλα τα δυαδικά αρχεία στο macOS είναι δυναμικά συνδεδεμένα. Επομένως, περιέχουν κάποιες ενότητες stub που βοηθούν το δυαδικό να πηδήξει στον σωστό κώδικα σε διαφορετικές μηχανές και συμφραζόμενα. Είναι το dyld όταν εκτελείται το δυαδικό που χρειάζεται να επιλύσει αυτές τις διευθύνσεις (τουλάχιστον τις μη-τεμπέλικες).

Ορισμένες ενότητες stub στο δυαδικό:

- **`__TEXT.__[auth_]stubs`**: Δείκτες από τις ενότητες `__DATA`
- **`__TEXT.__stub_helper`**: Μικρός κώδικας που καλεί τη δυναμική σύνδεση με πληροφορίες για τη συνάρτηση που θα καλέσει
- **`__DATA.__[auth_]got`**: Παγκόσμιος Πίνακας Μεταθέσεων (διευθύνσεις σε εισαγόμενες συναρτήσεις, όταν επιλυθούν, (δεσμευμένες κατά τη διάρκεια του χρόνου φόρτωσης καθώς είναι σημασμένες με τη σημαία `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Δείκτες μη-τεμπέλικων συμβόλων (δεσμευμένοι κατά τη διάρκεια του χρόνου φόρτωσης καθώς είναι σημασμένοι με τη σημαία `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Δείκτες τεμπέλικων συμβόλων (δεσμευμένοι κατά την πρώτη πρόσβαση)

> [!WARNING]
> Σημειώστε ότι οι δείκτες με το πρόθεμα "auth\_" χρησιμοποιούν ένα κλειδί κρυπτογράφησης εντός της διαδικασίας για να το προστατεύσουν (PAC). Επιπλέον, είναι δυνατό να χρησιμοποιηθεί η εντολή arm64 `BLRA[A/B]` για να επαληθευτεί ο δείκτης πριν τον ακολουθήσετε. Και η RETA\[A/B] μπορεί να χρησιμοποιηθεί αντί για μια διεύθυνση RET.\
> Στην πραγματικότητα, ο κώδικας στο **`__TEXT.__auth_stubs`** θα χρησιμοποιήσει **`braa`** αντί για **`bl`** για να καλέσει τη ζητούμενη συνάρτηση για να πιστοποιήσει τον δείκτη.
>
> Επίσης, σημειώστε ότι οι τρέχουσες εκδόσεις του dyld φορτώνουν **όλα ως μη-τεμπέλικα**.

### Finding lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Ενδιαφέρον μέρος αποσυναρμολόγησης:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Είναι δυνατόν να δούμε ότι η μετάβαση στην κλήση του printf πηγαίνει στο **`__TEXT.__stubs`**:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Στη διάσπαση της ενότητας **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
μπορείτε να δείτε ότι **πηδάμε στη διεύθυνση του GOT**, η οποία σε αυτή την περίπτωση επιλύεται μη-τεμπέλικα και θα περιέχει τη διεύθυνση της συνάρτησης printf.

Σε άλλες καταστάσεις, αντί να πηδήξει απευθείας στο GOT, θα μπορούσε να πηδήξει στο **`__DATA.__la_symbol_ptr`** το οποίο θα φορτώσει μια τιμή που αντιπροσωπεύει τη συνάρτηση που προσπαθεί να φορτώσει, και στη συνέχεια να πηδήξει στο **`__TEXT.__stub_helper`** το οποίο πηδά στο **`__DATA.__nl_symbol_ptr`** που περιέχει τη διεύθυνση του **`dyld_stub_binder`** που παίρνει ως παραμέτρους τον αριθμό της συνάρτησης και μια διεύθυνση.\
Αυτή η τελευταία συνάρτηση, αφού βρει τη διεύθυνση της αναζητούμενης συνάρτησης, την γράφει στην αντίστοιχη τοποθεσία στο **`__TEXT.__stub_helper`** για να αποφευχθούν οι αναζητήσεις στο μέλλον.

> [!TIP]
> Ωστόσο, σημειώστε ότι οι τρέχουσες εκδόσεις του dyld φορτώνουν τα πάντα ως μη-τεμπέλικα.

#### Dyld opcodes

Τέλος, ο **`dyld_stub_binder`** χρειάζεται να βρει τη δηλωμένη συνάρτηση και να την γράψει στη σωστή διεύθυνση για να μην την αναζητήσει ξανά. Για να το κάνει αυτό, χρησιμοποιεί opcodes (μια πεπερασμένη μηχανή καταστάσεων) μέσα στο dyld.

## apple\[] argument vector

Στο macOS, η κύρια συνάρτηση δέχεται στην πραγματικότητα 4 παραμέτρους αντί για 3. Η τέταρτη ονομάζεται apple και κάθε είσοδος είναι στη μορφή `key=value`. Για παράδειγμα:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Αποτέλεσμα:
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
> [!TIP]
> Μέχρι τη στιγμή που αυτές οι τιμές φτάνουν στη βασική συνάρτηση, ευαίσθητες πληροφορίες έχουν ήδη αφαιρεθεί από αυτές ή θα είχε υπάρξει διαρροή δεδομένων.

είναι δυνατόν να δούμε όλες αυτές τις ενδιαφέρουσες τιμές αποσφαλμάτωσης πριν μπούμε στη βασική συνάρτηση με:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Η τρέχουσα εκτελέσιμη ρύθμιση είναι '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

Αυτή είναι μια δομή που εξάγεται από το dyld με πληροφορίες σχετικά με την κατάσταση του dyld που μπορεί να βρεθεί στον [**κώδικα πηγής**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) με πληροφορίες όπως η έκδοση, δείκτης στον πίνακα dyld_image_info, στον dyld_image_notifier, αν η διαδικασία είναι αποσυνδεδεμένη από την κοινή μνήμη, αν κλήθηκε ο αρχικοποιητής libSystem, δείκτης στην κεφαλίδα Mach του dyls, δείκτης στη συμβολοσειρά έκδοσης dyld...

## dyld env variables

### debug dyld

Ενδιαφέρουσες μεταβλητές περιβάλλοντος που βοηθούν στην κατανόηση του τι κάνει το dyld:

- **DYLD_PRINT_LIBRARIES**

Ελέγξτε κάθε βιβλιοθήκη που φορτώνεται:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
- **DYLD_PRINT_SEGMENTS**

Ελέγξτε πώς φορτώνεται κάθε βιβλιοθήκη:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
- **DYLD_PRINT_INITIALIZERS**

Εκτυπώνει πότε εκτελείται κάθε αρχικοποιητής βιβλιοθήκης:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Άλλα

- `DYLD_BIND_AT_LAUNCH`: Οι καθυστερημένες συνδέσεις επιλύονται με τις μη καθυστερημένες
- `DYLD_DISABLE_PREFETCH`: Απενεργοποίηση της προφόρτωσης περιεχομένου \_\_DATA και \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Συνδέσεις ενός επιπέδου
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Διαδρομές επίλυσης
- `DYLD_INSERT_LIBRARIES`: Φόρτωση μιας συγκεκριμένης βιβλιοθήκης
- `DYLD_PRINT_TO_FILE`: Γράψτε την αποσφαλμάτωση dyld σε ένα αρχείο
- `DYLD_PRINT_APIS`: Εκτύπωση κλήσεων API libdyld
- `DYLD_PRINT_APIS_APP`: Εκτύπωση κλήσεων API libdyld που έγιναν από το κύριο
- `DYLD_PRINT_BINDINGS`: Εκτύπωση συμβόλων κατά την σύνδεση
- `DYLD_WEAK_BINDINGS`: Μόνο εκτύπωση αδύναμων συμβόλων κατά την σύνδεση
- `DYLD_PRINT_CODE_SIGNATURES`: Εκτύπωση λειτουργιών καταχώρισης υπογραφής κώδικα
- `DYLD_PRINT_DOFS`: Εκτύπωση τμημάτων μορφής αντικειμένου D-Trace καθώς φορτώνονται
- `DYLD_PRINT_ENV`: Εκτύπωση του περιβάλλοντος που βλέπει το dyld
- `DYLD_PRINT_INTERPOSTING`: Εκτύπωση λειτουργιών διαμεσολάβησης
- `DYLD_PRINT_LIBRARIES`: Εκτύπωση των βιβλιοθηκών που φορτώθηκαν
- `DYLD_PRINT_OPTS`: Εκτύπωση επιλογών φόρτωσης
- `DYLD_REBASING`: Εκτύπωση λειτουργιών επανασύνδεσης συμβόλων
- `DYLD_RPATHS`: Εκτύπωση επεκτάσεων του @rpath
- `DYLD_PRINT_SEGMENTS`: Εκτύπωση χαρτογραφήσεων τμημάτων Mach-O
- `DYLD_PRINT_STATISTICS`: Εκτύπωση στατιστικών χρόνου
- `DYLD_PRINT_STATISTICS_DETAILS`: Εκτύπωση λεπτομερών στατιστικών χρόνου
- `DYLD_PRINT_WARNINGS`: Εκτύπωση μηνυμάτων προειδοποίησης
- `DYLD_SHARED_CACHE_DIR`: Διαδρομή για χρήση για την κρυφή μνήμη κοινής βιβλιοθήκης
- `DYLD_SHARED_REGION`: "χρήση", "ιδιωτική", "αποφυγή"
- `DYLD_USE_CLOSURES`: Ενεργοποίηση κλεισίματος

Είναι δυνατόν να βρείτε περισσότερα με κάτι σαν:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ή κατεβάζοντας το έργο dyld από [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) και εκτελώντας μέσα στον φάκελο:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Αναφορές

- [**\*OS Internals, Volume I: User Mode. Από τον Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
