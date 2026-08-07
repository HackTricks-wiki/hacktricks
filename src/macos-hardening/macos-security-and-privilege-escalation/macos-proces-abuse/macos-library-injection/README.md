# Injection βιβλιοθηκών στο macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Ο κώδικας του **dyld είναι open source** και μπορεί να βρεθεί στο [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) και να ληφθεί ως tar μέσω ενός **URL όπως** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Διαδικασία Dyld**

Δείτε πώς το Dyld φορτώνει βιβλιοθήκες μέσα σε binaries:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Αυτό είναι παρόμοιο με το [**LD_PRELOAD στο Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Επιτρέπει να υποδείξετε σε μια διαδικασία που πρόκειται να εκτελεστεί να φορτώσει μια συγκεκριμένη βιβλιοθήκη από ένα path (αν είναι ενεργοποιημένη η env var)<sup>[[4]](#references)</sup>

Αυτή η τεχνική μπορεί επίσης να **χρησιμοποιηθεί ως τεχνική ASEP**, καθώς κάθε εγκατεστημένη εφαρμογή διαθέτει ένα plist με όνομα "Info.plist", το οποίο επιτρέπει την **ανάθεση environmental variables** με χρήση ενός key που ονομάζεται `LSEnvironmental`.

> [!TIP]
> Από το 2012, η **Apple έχει περιορίσει δραστικά τη δυνατότητα** του **`DYLD_INSERT_LIBRARIES`**. Μια διαδικασία θεωρείται **restricted** — και στη συνέχεια το `dyld` διαγράφει κάθε μεταβλητή `DYLD_*` από το environment της — όταν ισχύει οποιοδήποτε από τα παρακάτω:
>
> - Το binary είναι `setuid/setgid`
> - Το Mach-O διαθέτει section **`__RESTRICT/__restrict`**
> - Το binary είναι υπογεγραμμένο με hardened runtime και το AMFI δεν του παραχωρεί τα permissions "path/print variables", δηλαδή δεν διαθέτει το [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Ελέγξτε τα **entitlements** ενός binary με: `codesign -dv --entitlements :- </path/to/bin>`
>
> Στο τρέχον `dyld`, αυτό δεν αποφασίζεται πλέον μόνο από το `dyld`: η `ProcessConfig::Security::Security()` ζητά από το **AMFI** να εκτελέσει το `amfi_check_dyld_policy_self()` και στη συνέχεια καλεί το `pruneEnvVars()`. Ο ακριβής κώδικας παρουσιάζεται στην ενότητα [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) παρακάτω.

### Library Validation

Ακόμη και αν το binary επιτρέπει τη χρήση της env variable **`DYLD_INSERT_LIBRARIES`**, αν το binary ελέγχει την υπογραφή της βιβλιοθήκης που πρόκειται να φορτώσει, δεν θα φορτώσει μια custom βιβλιοθήκη.

Για να φορτωθεί μια custom βιβλιοθήκη, το binary πρέπει να διαθέτει **ένα από τα παρακάτω entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ή το binary **δεν πρέπει** να διαθέτει το **hardened runtime flag** ή το **library validation flag**.

Μπορείτε να ελέγξετε αν ένα binary διαθέτει **hardened runtime** με `codesign --display --verbose <bin>`, ελέγχοντας το runtime flag στο **`CodeDirectory`**, όπως: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Μπορείτε επίσης να φορτώσετε μια βιβλιοθήκη αν είναι **υπογεγραμμένη με το ίδιο certificate με το binary**.

Βρείτε ένα παράδειγμα για το πώς να κάνετε (ab)use αυτής της λειτουργίας και να ελέγξετε τους περιορισμούς στο:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Να θυμάστε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση επιθέσεων Dylib hijacking.

Όπως στα Windows, έτσι και στο MacOS μπορείτε να κάνετε **hijack dylibs** ώστε να κάνετε τις **εφαρμογές** να **εκτελούν** **αυθαίρετο** **κώδικα** (στην πραγματικότητα, από έναν απλό χρήστη αυτό μπορεί να μην είναι δυνατό, καθώς ενδέχεται να χρειάζεται permission TCC για εγγραφή μέσα σε ένα `.app` bundle και hijack μιας βιβλιοθήκης).\
Ωστόσο, ο τρόπος με τον οποίο οι εφαρμογές του **MacOS** **φορτώνουν** βιβλιοθήκες είναι πιο **περιορισμένος** από ό,τι στα Windows. Αυτό σημαίνει ότι οι developers **malware** μπορούν ακόμη να χρησιμοποιήσουν αυτή την τεχνική για **stealth**, αλλά η πιθανότητα να μπορέσουν να την **καταχραστούν για privilege escalation** είναι πολύ μικρότερη.

Καταρχάς, είναι **συνηθέστερο** τα **MacOS binaries** να υποδεικνύουν το πλήρες path των βιβλιοθηκών που πρέπει να φορτωθούν. Επιπλέον, το **MacOS δεν αναζητά ποτέ** βιβλιοθήκες στους φακέλους του **$PATH**.

Το **κύριο** μέρος του **κώδικα** που σχετίζεται με αυτή τη λειτουργία βρίσκεται στη `ImageLoader::recursiveLoadLibraries` στο `ImageLoader.cpp`.

Υπάρχουν **4 διαφορετικές header Commands** που μπορεί να χρησιμοποιήσει ένα macho binary για να φορτώσει βιβλιοθήκες:

- Η εντολή **`LC_LOAD_DYLIB`** είναι η συνηθισμένη εντολή για τη φόρτωση μιας dylib.
- Η εντολή **`LC_LOAD_WEAK_DYLIB`** λειτουργεί όπως η προηγούμενη, αλλά αν η dylib δεν βρεθεί, η εκτέλεση συνεχίζεται χωρίς σφάλμα.
- Η εντολή **`LC_REEXPORT_DYLIB`** λειτουργεί ως proxy (ή κάνει re-export) των symbols από διαφορετική βιβλιοθήκη.
- Η εντολή **`LC_LOAD_UPWARD_DYLIB`** χρησιμοποιείται όταν δύο βιβλιοθήκες εξαρτώνται η μία από την άλλη (αυτό ονομάζεται _upward dependency_).

Ωστόσο, υπάρχουν **2 τύποι dylib hijacking**:

- **Missing weak linked libraries**: Αυτό σημαίνει ότι η εφαρμογή θα προσπαθήσει να φορτώσει μια βιβλιοθήκη που δεν υπάρχει και έχει ρυθμιστεί με **LC_LOAD_WEAK_DYLIB**. Στη συνέχεια, **αν ένας attacker τοποθετήσει μια dylib εκεί όπου αναμένεται, αυτή θα φορτωθεί**.
- Το γεγονός ότι το link είναι "weak" σημαίνει ότι η εφαρμογή θα συνεχίσει να εκτελείται ακόμη και αν η βιβλιοθήκη δεν βρεθεί.
- Ο **σχετικός κώδικας** βρίσκεται στη function `ImageLoaderMachO::doGetDependentLibraries` του `ImageLoaderMachO.cpp`, όπου το `lib->required` είναι `false` μόνο όταν το `LC_LOAD_WEAK_DYLIB` είναι true.
- **Βρείτε weak linked libraries** σε binaries με (παρακάτω υπάρχει παράδειγμα για τη δημιουργία hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Τα Mach-O binaries μπορούν να διαθέτουν τις εντολές **`LC_RPATH`** και **`LC_LOAD_DYLIB`**. Με βάση τις **τιμές** αυτών των commands, οι **βιβλιοθήκες** θα **φορτωθούν** από **διαφορετικούς φακέλους**.
- Το **`LC_RPATH`** περιέχει τα paths ορισμένων φακέλων που χρησιμοποιούνται από το binary για τη φόρτωση βιβλιοθηκών.
- Το **`LC_LOAD_DYLIB`** περιέχει το path συγκεκριμένων βιβλιοθηκών προς φόρτωση. Αυτά τα paths μπορούν να περιέχουν **`@rpath`**, το οποίο θα **αντικατασταθεί** από τις τιμές του **`LC_RPATH`**. Αν υπάρχουν πολλά paths στο **`LC_RPATH`**, όλα θα χρησιμοποιηθούν για την αναζήτηση της βιβλιοθήκης προς φόρτωση. Παράδειγμα:
- Αν το **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και το **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`, θα χρησιμοποιηθούν και οι δύο φάκελοι για τη φόρτωση του `library.dylib`**.** Αν η βιβλιοθήκη δεν υπάρχει στο `[...]/v1/` και ο attacker μπορεί να τοποθετήσει εκεί μία, μπορεί να κάνει hijack της φόρτωσης της βιβλιοθήκης στο `[...]/v2/`, καθώς ακολουθείται η σειρά των paths στο **`LC_LOAD_DYLIB`**.
- **Βρείτε rpath paths και libraries** σε binaries με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Είναι το **path** του φακέλου που περιέχει το **κύριο executable file**.
>
> **`@loader_path`**: Είναι το **path** του **directory** που περιέχει το **Mach-O binary** το οποίο περιέχει το load command.
>
> - Όταν χρησιμοποιείται σε executable, το **`@loader_path`** είναι ουσιαστικά ίδιο με το **`@executable_path`**.
> - Όταν χρησιμοποιείται σε **dylib**, το **`@loader_path`** παρέχει το **path** προς τη **dylib**.

Ο τρόπος για **privilege escalation** μέσω abuse αυτής της λειτουργίας θα υπήρχε στη σπάνια περίπτωση όπου μια **εφαρμογή** που εκτελείται **από** τον **root** αναζητά κάποια **βιβλιοθήκη σε φάκελο στον οποίο ο attacker έχει write permissions**.

> [!TIP]
> Ένα καλό **scanner** για την εύρεση **missing libraries** σε εφαρμογές είναι το [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Μια καλή **αναφορά με τεχνικές λεπτομέρειες** σχετικά με αυτή την τεχνική βρίσκεται [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Παράδειγμα**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Να θυμάστε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση επιθέσεων Dlopen hijacking.

Από το **`man dlopen`**:

- Όταν το path **δεν περιέχει χαρακτήρα slash** (δηλαδή είναι απλώς leaf name), η **dlopen() θα πραγματοποιήσει αναζήτηση**. Αν το **`$DYLD_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα **αναζητήσει πρώτα σε αυτόν τον φάκελο**. Έπειτα, αν το calling mach-o file ή το main executable καθορίζει ένα **`LC_RPATH`**, το dyld θα **αναζητήσει σε αυτούς τους** φακέλους. Στη συνέχεια, αν η διαδικασία είναι **unrestricted**, το dyld θα αναζητήσει στον **τρέχοντα working directory**. Τέλος, για παλαιά binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους φακέλους**, διαφορετικά θα αναζητήσει στο **`/usr/local/lib/`** (αν η διαδικασία είναι unrestricted) και στη συνέχεια στο **`/usr/lib/`** (οι πληροφορίες προέρχονται από το **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(αν είναι unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (αν είναι unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Αν το name δεν περιέχει slashes, υπάρχουν 2 τρόποι για hijacking:
>
> - Αν οποιοδήποτε **`LC_RPATH`** είναι **writable** (όμως η υπογραφή ελέγχεται, επομένως για αυτό χρειάζεται επίσης το binary να είναι unrestricted)
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατή η φόρτωση κάποιου στοιχείου από το CWD (ή η κατάχρηση μίας από τις προαναφερθείσες env variables)

- Όταν το path **μοιάζει με path framework** (π.χ. `/stuff/foo.framework/foo`), αν το **`$DYLD_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει πρώτα σε αυτόν τον φάκελο το **partial path του framework** (π.χ. `foo.framework/foo`). Έπειτα, το dyld θα δοκιμάσει το **παρεχόμενο path ως έχει** (χρησιμοποιώντας τον τρέχοντα working directory για relative paths). Τέλος, για παλαιά binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους φακέλους. Διαφορετικά, θα αναζητήσει στο **`/Library/Frameworks`** (στο macOS αν η διαδικασία είναι unrestricted) και στη συνέχεια στο **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (χρησιμοποιώντας τον τρέχοντα working directory για relative paths αν είναι unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (αν είναι unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Αν πρόκειται για framework path, ο τρόπος για hijack θα ήταν:
>
> - Αν η διαδικασία είναι **unrestricted**, μέσω abuse του **relative path από το CWD** και των προαναφερθέντων env variables (ακόμη και αν αυτό δεν αναφέρεται στα docs, όταν η διαδικασία είναι restricted οι env vars DYLD\_\* αφαιρούνται)

- Όταν το path **περιέχει slash αλλά δεν είναι framework path** (δηλαδή full path ή partial path προς dylib), η dlopen() αναζητά πρώτα (αν έχει οριστεί) στο **`$DYLD_LIBRARY_PATH`** (χρησιμοποιώντας το leaf part του path). Στη συνέχεια, το dyld **δοκιμάζει το παρεχόμενο path** (χρησιμοποιώντας τον τρέχοντα working directory για relative paths (αλλά μόνο για unrestricted processes)). Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους φακέλους, διαφορετικά θα αναζητήσει στο **`/usr/local/lib/`** (αν η διαδικασία είναι unrestricted) και στη συνέχεια στο **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (χρησιμοποιώντας τον τρέχοντα working directory για relative paths αν είναι unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (αν είναι unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Αν το name περιέχει slashes και δεν είναι framework, ο τρόπος για hijack θα ήταν:
>
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατή η φόρτωση κάποιου στοιχείου από το CWD ή το `/usr/local/lib` (ή μέσω abuse μίας από τις προαναφερθείσες env variables)

> [!TIP]
> Σημείωση: Δεν υπάρχουν **configuration files** για τον **έλεγχο της αναζήτησης από το dlopen**.
>
> Σημείωση: Αν το main executable είναι **set\[ug]id binary ή codesigned με entitlements**, τότε όλες οι environment variables αγνοούνται και μπορεί να χρησιμοποιηθεί μόνο full path (δείτε τους [περιορισμούς του DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) για περισσότερες πληροφορίες).
>
> Σημείωση: Οι Apple platforms χρησιμοποιούν "universal" files για τον συνδυασμό 32-bit και 64-bit libraries. Αυτό σημαίνει ότι δεν υπάρχουν ξεχωριστά 32-bit και 64-bit search paths.
>
> Σημείωση: Στις Apple platforms, οι περισσότερες OS dylibs έχουν συνδυαστεί στο **dyld cache** και δεν υπάρχουν στον δίσκο. Επομένως, η κλήση της **`stat()`** για προκαταρκτικό έλεγχο ύπαρξης μιας OS dylib **δεν θα λειτουργήσει**. Ωστόσο, η **`dlopen_preflight()`** χρησιμοποιεί τα ίδια βήματα με την **`dlopen()`** για την εύρεση ενός συμβατού mach-o file.

**Έλεγχος paths**

Ας ελέγξουμε όλες τις επιλογές με τον ακόλουθο κώδικα:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Αν το κάνετε compile και execute, μπορείτε να δείτε **πού αναζητήθηκε ανεπιτυχώς κάθε library**. Επίσης, μπορείτε να **φιλτράρετε τα FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Αν ένα **privileged binary/app** (όπως ένα SUID ή κάποιο binary με ισχυρά entitlements) **φορτώνει μια βιβλιοθήκη από relative path** (για παράδειγμα χρησιμοποιώντας `@executable_path` ή `@loader_path`) και έχει απενεργοποιημένο το **Library Validation**, μπορεί να είναι δυνατή η μετακίνηση του binary σε μια τοποθεσία όπου ο attacker θα μπορούσε να **τροποποιήσει τη βιβλιοθήκη που φορτώνεται από το relative path** και να το εκμεταλλευτεί για την εισαγωγή κώδικα στη διεργασία.

## Prune `DYLD_*` env variables

Οι παλαιότερες εκδόσεις του `dyld` (`dyld2.cpp`) έπαιρναν αυτή την απόφαση in-process με τις `issetugid()`, `hasRestrictedSegment()` και `csops(CS_OPS_STATUS)`. Στο **current `dyld` η απόφαση ανατίθεται στο AMFI**, και ο κώδικας βρίσκεται στη `ProcessConfig::Security::Security()` στο `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
Από αυτό αξίζει να εξαχθούν δύο σημεία:

- Το **pruning** πραγματοποιείται μόνο σε **macOS / Mac Catalyst / DriverKit** — και μόνο όταν το AMFI δεν παραχώρησε κανένα από τα `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Το query του AMFI τροφοδοτείται με τις ίδιες τις ιδιότητες του executable:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
όπου το `isRestricted()` είναι κυριολεκτικά ο έλεγχος του segment `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` στη συνέχεια αφαιρεί **κάθε** μεταβλητή της οποίας το όνομα αρχίζει με `DYLD_` και μετακινεί τις παραμέτρους `apple[]` προς τα κάτω, ώστε ούτε τα child processes μιας restricted process να τις κληρονομούν:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Πρακτική συνέπεια: Τα **`DYLD_*`** αφαιρούνται όταν η διεργασία είναι περιορισμένη — μέσω setuid/setgid, μιας ενότητας `__RESTRICT/__restrict` ή hardened-runtime/entitled binaries στα οποία το AMFI αρνείται να παραχωρήσει τα flags path/print. Αν, αντίθετα, η διεργασία διαθέτει μόνο **library validation** (`CS_REQUIRE_LV`), οι μεταβλητές διατηρούνται, αλλά το dylib που εισάγεται πρέπει να έχει υπογραφεί από το **ίδιο Team ID** (ή από την Apple). Επομένως, χρειάζεστε ένα από τα entitlements που απενεργοποιούν το library validation, ώστε να εκτελεστεί πράγματι ο κώδικας.

Επειδή η απόφαση λαμβάνεται πλέον από το AMFI, ο ταχύτερος τρόπος για να γνωρίζετε τι θα επιτρέψει ένα συγκεκριμένο binary είναι να εξετάσετε τα στοιχεία στα οποία βασίζεται το AMFI — entitlements και signing flags — αντί για το ίδιο το `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Έλεγχος περιορισμών

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Ενότητα `__RESTRICT` με segment `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Δημιουργήστε ένα νέο certificate στο Keychain και χρησιμοποιήστε το για να υπογράψετε το binary:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> Σημειώστε ότι ακόμα και αν υπάρχουν binaries υπογεγραμμένα με flags **`0x0(none)`**, μπορούν να αποκτήσουν δυναμικά το flag **`CS_RESTRICT`** κατά την εκτέλεσή τους και, επομένως, αυτή η τεχνική δεν θα λειτουργήσει σε αυτά.
>
> Μπορείτε να ελέγξετε αν ένα proc έχει αυτό το flag με το (λάβετε το [**csops εδώ**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> και, στη συνέχεια, να ελέγξετε αν είναι ενεργοποιημένο το flag 0x800.

## Αναφορές

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / έλεγχος `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (εκκίνηση process και εισαγωγή library)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
