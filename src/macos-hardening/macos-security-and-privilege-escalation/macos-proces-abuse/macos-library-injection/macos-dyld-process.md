# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το πραγματικό **entrypoint** ενός Mach-o binary είναι το dynamic linker, ο οποίος ορίζεται στο `LC_LOAD_DYLINKER` και συνήθως είναι το `/usr/lib/dyld`.<sup>[[3]](#references)</sup>

Αυτός ο linker πρέπει να εντοπίσει όλες τις libraries του executable, να τις αντιστοιχίσει στη μνήμη και να συνδέσει όλες τις non-lazy libraries. Μόνο μετά από αυτήν τη διαδικασία θα εκτελεστεί το entry-point του binary.

Φυσικά, το **`dyld`** δεν έχει dependencies (χρησιμοποιεί syscalls και αποσπάσματα του libSystem).

> [!CAUTION]
> Αν αυτός ο linker περιέχει κάποια ευπάθεια, επειδή εκτελείται πριν από την εκτέλεση οποιουδήποτε binary (ακόμη και με highly privileged ones), θα ήταν δυνατή η **κλιμάκωση προνομίων**.

### Ροή

Το Dyld θα φορτωθεί από το **`dyldboostrap::start`**, το οποίο θα φορτώσει επίσης στοιχεία όπως το **stack canary**. Αυτό συμβαίνει επειδή αυτή η function θα λάβει στο **`apple`** argument vector της αυτήν και άλλες **ευαίσθητες** **τιμές**.<sup>[[1]](#references)</sup>

Το **`dyls::_main()`** είναι το entry point του dyld και η πρώτη του εργασία είναι να εκτελέσει το `configureProcessRestrictions()`, το οποίο συνήθως περιορίζει τις μεταβλητές περιβάλλοντος **`DYLD_*`** που εξηγούνται στο:<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

Στη συνέχεια, αντιστοιχίζει το dyld shared cache, το οποίο κάνει prelink όλες τις σημαντικές system libraries, και έπειτα αντιστοιχίζει τις libraries από τις οποίες εξαρτάται το binary και συνεχίζει αναδρομικά μέχρι να φορτωθούν όλες οι απαιτούμενες libraries. Επομένως:

1. αρχίζει να φορτώνει inserted libraries με το `DYLD_INSERT_LIBRARIES` (αν επιτρέπεται)
2. Έπειτα τις libraries από το shared cache
3. Έπειτα τις imported libraries
1. Στη συνέχεια συνεχίζει να εισάγει libraries αναδρομικά

Μόλις φορτωθούν όλες, εκτελούνται οι **initialisers** αυτών των libraries. Αυτοί κωδικοποιούνται με χρήση του **`__attribute__((constructor))`**, το οποίο ορίζεται στο `LC_ROUTINES[_64]` (πλέον deprecated), ή μέσω pointer σε section με flag `S_MOD_INIT_FUNC_POINTERS` (συνήθως: **`__DATA.__MOD_INIT_FUNC`**).

Οι terminators κωδικοποιούνται με **`__attribute__((destructor))`** και βρίσκονται σε section με flag `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Όλα τα binaries στο macOS είναι dynamically linked. Επομένως, περιέχουν ορισμένα stub sections που βοηθούν το binary να μεταπηδά στον σωστό κώδικα σε διαφορετικά machines και contexts. Όταν εκτελείται το binary, το dyld είναι ο μηχανισμός που πρέπει να επιλύσει αυτές τις διευθύνσεις (τουλάχιστον τις non-lazy).

Ορισμένα stub sections στο binary:

- **`__TEXT.__[auth_]stubs`**: Pointers από sections του `__DATA`
- **`__TEXT.__stub_helper`**: Μικρός κώδικας που καλεί το dynamic linking με πληροφορίες για τη function που θα κληθεί
- **`__DATA.__[auth_]got`**: Global Offset Table (διευθύνσεις imported functions, όταν επιλυθούν, (γίνεται binding κατά το load time επειδή έχει σημειωθεί με το flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers (γίνεται binding κατά το load time επειδή έχει σημειωθεί με το flag `S_NON_LAZY_SYMBOL_POINTERS`)
- **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers (γίνεται binding κατά την πρώτη πρόσβαση)

> [!WARNING]
> Σημειώστε ότι οι pointers με prefix "auth\_" χρησιμοποιούν ένα in-process encryption key για την προστασία τους (PAC). Επιπλέον, είναι δυνατή η χρήση της arm64 instruction `BLRA[A/B]` για την επαλήθευση του pointer πριν από την ακολούθησή του. Επίσης, η `RETA\[A/B]` μπορεί να χρησιμοποιηθεί αντί για διεύθυνση RET.\
> Στην πραγματικότητα, ο κώδικας στο **`__TEXT.__auth_stubs`** θα χρησιμοποιήσει το **`braa`** αντί για το **`bl`** για να καλέσει την requested function και να πιστοποιήσει τον pointer.
>
> Σημειώστε επίσης ότι οι τρέχουσες εκδόσεις του dyld φορτώνουν τα πάντα ως non-lazy.

### Εύρεση lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Ενδιαφέρον τμήμα αποσυναρμολόγησης:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Είναι δυνατό να δούμε ότι το άλμα για την κλήση της printf θα μεταβεί στο **`__TEXT.__stubs`**:
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
Στην αποσυναρμολόγηση του τμήματος **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
όπως μπορείτε να δείτε, **μεταβαίνουμε στη διεύθυνση του GOT**, η οποία σε αυτή την περίπτωση γίνεται resolve ως non-lazy και θα περιέχει τη διεύθυνση της συνάρτησης printf.

Σε άλλες περιπτώσεις, αντί να μεταβεί απευθείας στο GOT, θα μπορούσε να μεταβεί στο **`__DATA.__la_symbol_ptr`**, το οποίο θα φορτώσει μια τιμή που αντιπροσωπεύει τη συνάρτηση που προσπαθεί να φορτώσει, και στη συνέχεια να μεταβεί στο **`__TEXT.__stub_helper`**, το οποίο μεταβαίνει στο **`__DATA.__nl_symbol_ptr`**, που περιέχει τη διεύθυνση του **`dyld_stub_binder`**, το οποίο λαμβάνει ως παραμέτρους τον αριθμό της συνάρτησης και μια διεύθυνση.\
Αυτή η τελευταία συνάρτηση, αφού βρει τη διεύθυνση της αναζητούμενης συνάρτησης, την γράφει στην αντίστοιχη θέση στο **`__TEXT.__stub_helper`**, ώστε να αποφεύγονται οι αναζητήσεις στο μέλλον.

> [!TIP]
> Ωστόσο, σημειώστε ότι οι τρέχουσες εκδόσεις του dyld φορτώνουν τα πάντα ως non-lazy.

#### Dyld opcodes

Τέλος, το **`dyld_stub_binder`** πρέπει να βρει την υποδεικνυόμενη συνάρτηση και να την γράψει στη σωστή διεύθυνση, ώστε να μην χρειαστεί να την αναζητήσει ξανά. Για να το κάνει αυτό, χρησιμοποιεί opcodes (μια finite state machine) μέσα στο dyld.

## apple\[] vector ορισμάτων

Στο macOS, η main function λαμβάνει στην πραγματικότητα 4 ορίσματα αντί για 3. Το τέταρτο ονομάζεται apple και κάθε καταχώριση έχει τη μορφή `key=value`. Για παράδειγμα:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Δεν παρέχεται κείμενο προς μετάφραση.
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
> Μέχρι αυτές οι τιμές να φτάσουν στη main function, οι ευαίσθητες πληροφορίες έχουν ήδη αφαιρεθεί από αυτές ή διαφορετικά θα αποτελούσαν data leak.

είναι δυνατό να δείτε όλες αυτές τις ενδιαφέρουσες τιμές κάνοντας debugging πριν από την είσοδο στη main με:

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

Αυτή είναι μια δομή που εξάγεται από το dyld και περιέχει πληροφορίες σχετικά με την κατάσταση του dyld. Μπορεί να βρεθεί στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) και περιλαμβάνει πληροφορίες όπως την έκδοση, pointer προς τον πίνακα dyld_image_info, προς το dyld_image_notifier, αν το proc είναι detached από το shared cache, αν κλήθηκε ο initializer του libSystem, pointer προς το Mach header του ίδιου του dyld, pointer προς το string της έκδοσης του dyld...<sup>[[4]](#references)</sup>

## μεταβλητές περιβάλλοντος dyld

### debug dyld

Ενδιαφέρουσες μεταβλητές περιβάλλοντος που βοηθούν στην κατανόηση του τι κάνει το dyld:

- **DYLD_PRINT_LIBRARIES**

Ελέγχει κάθε library που φορτώνεται:
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

Ελέγξτε πώς φορτώνεται κάθε library:
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

Εκτυπώνει πότε εκτελείται κάθε library initializer:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Άλλα

- `DYLD_BIND_AT_LAUNCH`: Τα lazy bindings επιλύονται μαζί με τα non lazy
- `DYLD_DISABLE_PREFETCH`: Απενεργοποίηση του pre-fetching περιεχομένου των \_\_DATA και \_\_LINKEDIT
- `DYLD_FORCE_FLAT_NAMESPACE`: Bindings ενός επιπέδου
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Paths επίλυσης
- `DYLD_INSERT_LIBRARIES`: Φόρτωση συγκεκριμένης library
- `DYLD_PRINT_TO_FILE`: Εγγραφή του dyld debug σε αρχείο
- `DYLD_PRINT_APIS`: Εκτύπωση των κλήσεων API του libdyld
- `DYLD_PRINT_APIS_APP`: Εκτύπωση των κλήσεων API του libdyld που πραγματοποιούνται από το main
- `DYLD_PRINT_BINDINGS`: Εκτύπωση των symbols κατά το binding
- `DYLD_WEAK_BINDINGS`: Εκτύπωση μόνο των weak symbols κατά το binding
- `DYLD_PRINT_CODE_SIGNATURES`: Εκτύπωση των operations εγγραφής code signature
- `DYLD_PRINT_DOFS`: Εκτύπωση των sections σε μορφή D-Trace object κατά τη φόρτωσή τους
- `DYLD_PRINT_ENV`: Εκτύπωση του env που βλέπει το dyld
- `DYLD_PRINT_INTERPOSTING`: Εκτύπωση των interposting operations
- `DYLD_PRINT_LIBRARIES`: Εκτύπωση των libraries που φορτώθηκαν
- `DYLD_PRINT_OPTS`: Εκτύπωση των load options
- `DYLD_REBASING`: Εκτύπωση των operations rebasing των symbols
- `DYLD_RPATHS`: Εκτύπωση των expansions του @rpath
- `DYLD_PRINT_SEGMENTS`: Εκτύπωση των mappings των Mach-O segments
- `DYLD_PRINT_STATISTICS`: Εκτύπωση των timing statistics
- `DYLD_PRINT_STATISTICS_DETAILS`: Εκτύπωση λεπτομερών timing statistics
- `DYLD_PRINT_WARNINGS`: Εκτύπωση warning messages
- `DYLD_SHARED_CACHE_DIR`: Path που χρησιμοποιείται για το shared library cache
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: Ενεργοποίηση των closures

Είναι δυνατό να βρεθούν περισσότερα με κάτι όπως:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ή κατεβάζοντας το project dyld από [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) και εκτελώντας μέσα στον φάκελο:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp` (διαδρομή εκκίνησης διεργασίας)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp` (διαμόρφωση διεργασίας/ασφάλειας)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c` (πλευρά kernel του `execve`, φόρτωση του dyld)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h` (δομή `dyld_all_image_infos`)](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
