# Διαδικασία Dyld στο macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το πραγματικό **entrypoint** ενός Mach-o binary είναι ο δυναμικός σύνδεσμος, ο οποίος ορίζεται στο `LC_LOAD_DYLINKER` και συνήθως είναι το `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Αυτός ο σύνδεσμος πρέπει να εντοπίσει όλες τις βιβλιοθήκες του executable, να τις αντιστοιχίσει στη μνήμη και να συνδέσει όλες τις μη lazy βιβλιοθήκες. Μόνο μετά από αυτήν τη διαδικασία εκτελείται το entry point του binary.

Φυσικά, το **`dyld`** δεν έχει εξαρτήσεις (χρησιμοποιεί syscalls και αποσπάσματα του libSystem).

> [!CAUTION]
> Αν αυτός ο σύνδεσμος περιέχει κάποια ευπάθεια, επειδή εκτελείται πριν από οποιοδήποτε binary (ακόμη και με υψηλά προνόμια), θα ήταν δυνατό να γίνει **κλιμάκωση προνομίων**.

### Ροή

Το Dyld φορτώνεται από το **`dyldboostrap::start`**, το οποίο φορτώνει επίσης στοιχεία όπως το **stack canary**. Αυτό συμβαίνει επειδή αυτή η συνάρτηση λαμβάνει στο διάνυσμα ορισμάτων **`apple`** αυτήν και άλλες **ευαίσθητες** **τιμές**.<sup>[[1]](#references)</sup>

Το **`dyls::_main()`** είναι το entry point του dyld και η πρώτη του ενέργεια είναι να εκτελέσει την `configureProcessRestrictions()`, η οποία συνήθως περιορίζει τις μεταβλητές περιβάλλοντος **`DYLD_*`**, όπως εξηγείται στο:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Στη συνέχεια, αντιστοιχίζει στη μνήμη το dyld shared cache, το οποίο έχει κάνει prelink σε όλες τις σημαντικές βιβλιοθήκες συστήματος, και έπειτα αντιστοιχίζει στη μνήμη τις βιβλιοθήκες από τις οποίες εξαρτάται το binary. Συνεχίζει αναδρομικά μέχρι να φορτωθούν όλες οι απαραίτητες βιβλιοθήκες. Επομένως:

1. ξεκινά να φορτώνει τις βιβλιοθήκες που έχουν εισαχθεί με το `DYLD_INSERT_LIBRARIES` (αν επιτρέπεται)
2. Έπειτα, τις βιβλιοθήκες από το shared cache
3. Έπειτα, τις εισαγόμενες βιβλιοθήκες
   1. Στη συνέχεια, συνεχίζει να εισάγει βιβλιοθήκες αναδρομικά

Μόλις φορτωθούν όλες, εκτελούνται οι **initialisers** αυτών των βιβλιοθηκών. Ορίζονται με **`__attribute__((constructor))`** στο `LC_ROUTINES[_64]` (πλέον deprecated) ή ως δείκτες σε μια ενότητα με τη σημαία `S_MOD_INIT_FUNC_POINTERS` (συνήθως: **`__DATA.__MOD_INIT_FUNC`**).

Οι terminators ορίζονται με **`__attribute__((destructor))`** και βρίσκονται σε μια ενότητα με τη σημαία `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

Δείτε επίσης: [Reflective Mach-O Loading](../reflective-mach-o-loading.md).

### Stubs

Όλα τα binaries στο macOS συνδέονται δυναμικά. Επομένως, περιέχουν ενότητες stubs που βοηθούν το binary να μεταβεί στον σωστό κώδικα σε διαφορετικά μηχανήματα και περιβάλλοντα. Όταν εκτελείται το binary, το dyld είναι ο μηχανισμός που πρέπει να επιλύσει αυτές τις διευθύνσεις (τουλάχιστον τις μη lazy).

Ορισμένες ενότητες stubs στο binary:

- **`__TEXT.__[auth_]stubs`**: Δείκτες από ενότητες `__DATA`
- **`__TEXT.__stub_helper`**: Μικρό τμήμα κώδικα που καλεί τον dynamic linker και περιέχει πληροφορίες για τη συνάρτηση που θα κληθεί
- **`__DATA.__[auth_]got`**: Global Offset Table (διευθύνσεις εισαγόμενων συναρτήσεων, οι οποίες όταν επιλυθούν δεσμεύονται κατά τη φόρτωση, καθώς η ενότητα έχει τη σημαία `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Δείκτες μη lazy συμβόλων (δεσμεύονται κατά τη φόρτωση, καθώς η ενότητα έχει τη σημαία `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Δείκτες lazy συμβόλων (δεσμεύονται κατά την πρώτη πρόσβαση)

> [!WARNING]
> Σημειώστε ότι οι δείκτες με πρόθεμα "auth\_" χρησιμοποιούν ένα κλειδί κρυπτογράφησης ανά διεργασία για την προστασία τους (PAC). Επιπλέον, είναι δυνατό να χρησιμοποιηθεί η εντολή arm64 `BLRA[A/B]` για επαλήθευση του δείκτη πριν από την αποαναφορά του. Επίσης, η RETA\[A/B] μπορεί να χρησιμοποιηθεί αντί για διεύθυνση RET.\
> Στην πραγματικότητα, ο κώδικας στο **`__TEXT.__auth_stubs`** χρησιμοποιεί **`braa`** αντί για **`bl`** για να καλέσει τη ζητούμενη συνάρτηση και να πιστοποιήσει τον δείκτη.
>
> Σημειώστε επίσης ότι οι τρέχουσες εκδόσεις του dyld φορτώνουν **τα πάντα ως non-lazy**.

### Εντοπισμός lazy συμβόλων

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

Ενδιαφέρον σημείο του disassembly:

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

Μπορούμε να δούμε ότι το άλμα προς την κλήση printf οδηγεί στο **`__TEXT.__stubs`**:

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

Κατά την αποσυναρμολόγηση της ενότητας **`__stubs`**:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

μπορείτε να δείτε ότι **μεταβαίνουμε στη διεύθυνση του GOT**, η οποία σε αυτή την περίπτωση έχει επιλυθεί με μη lazy τρόπο και περιέχει τη διεύθυνση της συνάρτησης printf.

Σε άλλες περιπτώσεις, αντί να μεταβεί απευθείας στο GOT, μπορεί να μεταβεί στο **`__DATA.__la_symbol_ptr`**, το οποίο θα φορτώσει μια τιμή που αντιπροσωπεύει τη συνάρτηση που προσπαθεί να φορτώσει. Έπειτα, μεταβαίνει στο **`__TEXT.__stub_helper`**, το οποίο μεταβαίνει στο **`__DATA.__nl_symbol_ptr`**, που περιέχει τη διεύθυνση του **`dyld_stub_binder`**. Αυτός δέχεται ως παραμέτρους τον αριθμό της συνάρτησης και μια διεύθυνση.\
Ο binder επιλύει το σύμβολο και ενημερώνει τη θέση του στο **`__DATA.__la_symbol_ptr`**. Στις επόμενες κλήσεις, το stub χρησιμοποιεί αυτόν τον επιλυμένο δείκτη· δεν ξαναγράφεται στο `__TEXT.__stub_helper`.<sup>[[5]](#references)</sup>

> [!TIP]
> Ωστόσο, σημειώστε ότι οι τρέχουσες εκδόσεις του dyld φορτώνουν τα πάντα με μη lazy τρόπο.

#### Opcodes του dyld

Τέλος, το **`dyld_stub_binder`** πρέπει να εντοπίσει την υποδεικνυόμενη συνάρτηση και να τη γράψει στη σωστή διεύθυνση, ώστε να μην χρειαστεί να την αναζητήσει ξανά. Για να το κάνει αυτό, χρησιμοποιεί opcodes (μια μηχανή πεπερασμένων καταστάσεων) μέσα στο dyld.

## διάνυσμα ορισμάτων apple\[]

Στο macOS, η κύρια συνάρτηση λαμβάνει στην πραγματικότητα 4 ορίσματα αντί για 3. Το τέταρτο ονομάζεται apple και κάθε καταχώριση έχει τη μορφή `key=value`. Για παράδειγμα:

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
> Όταν αυτές οι τιμές φτάσουν στη main function, οι ευαίσθητες πληροφορίες έχουν ήδη αφαιρεθεί από αυτές, διαφορετικά θα υπήρχε διαρροή δεδομένων.

Μπορείτε να δείτε όλες αυτές τις ενδιαφέρουσες τιμές κάνοντας debugging πριν μπείτε στη main με:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
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
0x16fdffd9b: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
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

Πρόκειται για μια δομή που εξάγεται από το dyld και περιέχει πληροφορίες σχετικά με την κατάστασή του. Μπορείτε να τη βρείτε στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html), όπου υπάρχουν πληροφορίες όπως η έκδοση, ένας δείκτης στον πίνακα dyld_image_info, ένας δείκτης στο dyld_image_notifier, αν η διεργασία έχει αποσυνδεθεί από το shared cache, αν έχει κληθεί ο initializer του libSystem, ένας δείκτης στη δική του Mach header του dyld, ένας δείκτης στη συμβολοσειρά έκδοσης του dyld...<sup>[[4]](#references)</sup>

## μεταβλητές περιβάλλοντος dyld

### αποσφαλμάτωση dyld

Ενδιαφέρουσες μεταβλητές περιβάλλοντος που βοηθούν να κατανοήσετε τι κάνει το dyld:

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

### Ανιχνεύστε την επίλυση βιβλιοθηκών κατά τον χρόνο εκτέλεσης

Για μια εκκίνηση που μπορείτε να ελέγξετε, ανιχνεύστε έναν υποψήφιο `@rpath` ή weak-library πριν τοποθετήσετε ένα dylib αντικατάστασης. Το `DYLD_PRINT_SEARCHING` αναφέρει τις διαδρομές που εξετάζει το dyld, ενώ το `DYLD_PRINT_LIBRARIES` εμφανίζει τα images που φορτώθηκαν πραγματικά. Το `DYLD_PRINT_LOADERS` διακρίνει ένα `JustInTimeLoader` από ένα `PrebuiltLoader` και αναφέρει τη χρήση ενός συνόλου prebuilt loader.<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

Αναζητήστε τη γραμμή `LC_RPATH` που προσδιορίζει το image που παρείχε ένα run path και, στη συνέχεια, συγκρίνετε τις υποψήφιες διαδρομές `possible path(...)` με τις ενδείξεις `found: dylib-from-disk`, `found: dylib-from-cache` ή με κάποια απόρριψη. Μια υποψήφια διαδρομή **δεν** αποδεικνύει ότι φορτώθηκε το dylib. Η πρώτη έγκυρη διαδρομή δίσκου πριν από την αναμενόμενη βιβλιοθήκη είναι αυτή στην οποία πρέπει να ελέγξετε την πρόσβαση εγγραφής και τους [περιορισμούς library-validation](./#library-validation).<sup>[[7]](#references)</sup>

Ένας prebuilt loader μπορεί να επαναχρησιμοποιήσει καταγεγραμμένες πληροφορίες εξαρτήσεων αντί να επαναλάβει πλήρη αναζήτηση διαδρομών. Επομένως, η αραιή έξοδος αναζήτησης δεν αποδεικνύει ότι ένα image δεν έχει εξαρτήσεις· ελέγξτε τις εντολές φόρτωσής του με το `otool -l` και συγκρίνετε τη λίστα βιβλιοθηκών.<sup>[[8]](#references)</sup> Αυτά τα διαγνωστικά απαιτούν επίσης άδεια εκτύπωσης μεταβλητών από το dyld, οπότε ένας προστατευμένος στόχος μπορεί να τα αγνοήσει πλήρως.<sup>[[2]](#references)</sup> Δείτε το [Dylib Hijacking](./#dylib-hijacking) για τις προϋποθέσεις αντικατάστασης βιβλιοθήκης.

### Άλλα

Ορισμένοι από τους παρακάτω διακόπτες αφορούν συγκεκριμένες παλαιότερες εκδόσεις του dyld. Ελέγξτε αν υποστηρίζονται στην έκδοση-στόχο αντί να θεωρείτε δεδομένο ότι κάθε μεταβλητή εξακολουθεί να λειτουργεί.<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Οι Lazy bindings επιλύονται μαζί με τις non-lazy bindings
- `DYLD_DISABLE_PREFETCH`: Απενεργοποίηση της προανάκτησης περιεχομένου των \_\_DATA και \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings ενός επιπέδου
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Διαδρομές επίλυσης
- `DYLD_INSERT_LIBRARIES`: Φόρτωση συγκεκριμένης βιβλιοθήκης
- `DYLD_PRINT_TO_FILE`: Εγγραφή των δεδομένων αποσφαλμάτωσης του dyld σε αρχείο
- `DYLD_PRINT_APIS`: Εκτύπωση κλήσεων API του libdyld
- `DYLD_PRINT_APIS_APP`: Εκτύπωση κλήσεων API του libdyld που γίνονται από το main
- `DYLD_PRINT_BINDINGS`: Εκτύπωση συμβόλων κατά το binding
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): Εκτύπωση των bindings weak symbols
- `DYLD_PRINT_CODE_SIGNATURES`: Εκτύπωση των λειτουργιών καταχώρισης code signature
- `DYLD_PRINT_DOFS`: Εκτύπωση των τμημάτων D-Trace object format κατά τη φόρτωσή τους
- `DYLD_PRINT_ENV`: Εκτύπωση του περιβάλλοντος που βλέπει το dyld
- `DYLD_PRINT_INTERPOSING`: Εκτύπωση των λειτουργιών interposing
- `DYLD_PRINT_LIBRARIES`: Εκτύπωση των βιβλιοθηκών που φορτώθηκαν
- `DYLD_PRINT_OPTS`: Εκτύπωση των επιλογών φόρτωσης
- `DYLD_PRINT_REBASINGS` (dyld2): Εκτύπωση των λειτουργιών rebasing συμβόλων
- `DYLD_PRINT_RPATHS` (dyld2): Εκτύπωση των επεκτάσεων του `@rpath`
- `DYLD_PRINT_SEGMENTS`: Εκτύπωση των αντιστοιχίσεων των τμημάτων Mach-O
- `DYLD_PRINT_STATISTICS`: Εκτύπωση στατιστικών χρονισμού
- `DYLD_PRINT_STATISTICS_DETAILS`: Εκτύπωση αναλυτικών στατιστικών χρονισμού
- `DYLD_PRINT_WARNINGS`: Εκτύπωση προειδοποιητικών μηνυμάτων
- `DYLD_SHARED_CACHE_DIR`: Διαδρομή για χρήση ως shared library cache
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Ενεργοποίηση των closures

Μπορείτε να βρείτε περισσότερα με κάτι όπως:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

Ή κατεβάζοντας το project dyld από [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) και εκτελώντας μέσα στον φάκελο:

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp` (διαδρομή εκκίνησης διεργασίας)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (ρύθμιση διεργασίας/ασφάλειας)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (πλευρά του kernel για το `execve`, φόρτωση του dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (δομή `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — σύνδεση δεικτών συμβόλων lazy και non-lazy](https://github.com/meta/fishhook)
- [6] [dyld(1) — διαγνωστικά dynamic linker](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — αναζήτηση διαδρομών βιβλιοθηκών κατά τον χρόνο εκτέλεσης](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — προκατασκευασμένοι φορτωτές και φορτωτές just-in-time](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — ονόματα μεταβλητών διαγνωστικών παλαιού τύπου](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
