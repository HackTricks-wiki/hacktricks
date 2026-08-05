# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Ο κώδικας του **dyld είναι open source** και μπορεί να βρεθεί στο [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) και μπορεί να ληφθεί ως tar μέσω ενός **URL όπως** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Δείτε πώς το Dyld φορτώνει libraries μέσα σε binaries στο:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Αυτό είναι παρόμοιο με το [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Επιτρέπει να υποδείξετε σε μια process που πρόκειται να εκτελεστεί να φορτώσει μια συγκεκριμένη library από ένα path (αν το env var είναι ενεργοποιημένο).

Αυτή η τεχνική μπορεί επίσης να **χρησιμοποιηθεί ως τεχνική ASEP**, καθώς κάθε εγκατεστημένη εφαρμογή έχει ένα plist με όνομα "Info.plist", το οποίο επιτρέπει τον **ορισμό environmental variables** χρησιμοποιώντας ένα key με όνομα `LSEnvironmental`.

> [!TIP]
> Από το 2012, η **Apple έχει μειώσει δραστικά τη δύναμη** του **`DYLD_INSERT_LIBRARIES`**. Μια process θεωρείται **restricted** — και τότε το `dyld` διαγράφει κάθε μεταβλητή `DYLD_*` από το environment της — όταν ισχύει οποιοδήποτε από τα παρακάτω:
>
> - Το binary είναι `setuid/setgid`
> - Το Mach-O διαθέτει section **`__RESTRICT/__restrict`**
> - Το binary είναι signed με hardened runtime και το AMFI δεν του παραχωρεί τα "path/print variables" permissions, δηλαδή δεν διαθέτει το [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup>
>   - Ελέγξτε τα **entitlements** ενός binary με: `codesign -dv --entitlements :- </path/to/bin>`
>
> Στο τρέχον `dyld`, αυτό δεν αποφασίζεται πλέον μόνο από το `dyld`: η `ProcessConfig::Security::Security()` ρωτά το **AMFI** μέσω της `amfi_check_dyld_policy_self()` και στη συνέχεια καλεί την `pruneEnvVars()`. Ο ακριβής κώδικας αναλύεται παρακάτω στο [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Ακόμη και αν το binary επιτρέπει τη χρήση του env variable **`DYLD_INSERT_LIBRARIES`**, αν το binary ελέγχει το signature της library που πρόκειται να φορτώσει, δεν θα φορτώσει μια custom library.

Για να φορτώσει μια custom library, το binary πρέπει να διαθέτει **ένα από τα παρακάτω entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ή το binary **δεν πρέπει** να έχει το **hardened runtime flag** ή το **library validation flag**.

Μπορείτε να ελέγξετε αν ένα binary διαθέτει **hardened runtime** με `codesign --display --verbose <bin>`, ελέγχοντας το runtime flag στο **`CodeDirectory`**, όπως: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Μπορείτε επίσης να φορτώσετε μια library αν είναι **signed με το ίδιο certificate με το binary**.

Βρείτε ένα παράδειγμα για το πώς να κάνετε (ab)use αυτής της δυνατότητας και να ελέγξετε τους περιορισμούς στο:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Να θυμάστε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση επιθέσεων Dylib hijacking.

Όπως στα Windows, έτσι και στο MacOS μπορείτε επίσης να κάνετε **hijack dylibs**, ώστε να κάνετε τις **εφαρμογές** να **εκτελούν** **arbitrary** **code** (στην πραγματικότητα, από έναν regular user αυτό μπορεί να μην είναι δυνατό, καθώς ίσως χρειάζεστε άδεια TCC για να κάνετε write μέσα σε ένα `.app` bundle και να κάνετε hijack μια library).\
Ωστόσο, ο τρόπος με τον οποίο οι εφαρμογές **MacOS** **φορτώνουν** libraries είναι **πιο περιορισμένος** από ό,τι στα Windows. Αυτό σημαίνει ότι οι developers **malware** μπορούν ακόμη να χρησιμοποιήσουν αυτή την τεχνική για **stealth**, αλλά η πιθανότητα να μπορέσουν να κάνουν **abuse** αυτού για privilege escalation είναι πολύ μικρότερη.

Καταρχάς, είναι **πιο συνηθισμένο** να διαπιστώνεται ότι τα **MacOS binaries υποδεικνύουν το πλήρες path** των libraries που πρέπει να φορτωθούν. Και δεύτερον, το **MacOS δεν αναζητά ποτέ** libraries στους φακέλους του **$PATH**.

Το **κύριο** τμήμα του **code** που σχετίζεται με αυτή τη λειτουργία βρίσκεται στη `ImageLoader::recursiveLoadLibraries` στο `ImageLoader.cpp`.

Υπάρχουν **4 διαφορετικά header Commands** που μπορεί να χρησιμοποιήσει ένα macho binary για να φορτώσει libraries:

- Η εντολή **`LC_LOAD_DYLIB`** είναι η συνηθισμένη εντολή για τη φόρτωση ενός dylib.
- Η εντολή **`LC_LOAD_WEAK_DYLIB`** λειτουργεί όπως η προηγούμενη, αλλά αν το dylib δεν βρεθεί, η εκτέλεση συνεχίζεται χωρίς error.
- Η εντολή **`LC_REEXPORT_DYLIB`** κάνει proxy (ή re-export) τα symbols από διαφορετική library.
- Η εντολή **`LC_LOAD_UPWARD_DYLIB`** χρησιμοποιείται όταν δύο libraries εξαρτώνται η μία από την άλλη (αυτό ονομάζεται _upward dependency_).

Ωστόσο, υπάρχουν **2 τύποι dylib hijacking**:

- **Missing weak linked libraries**: Αυτό σημαίνει ότι η εφαρμογή θα προσπαθήσει να φορτώσει μια library που δεν υπάρχει και είναι configured με **LC_LOAD_WEAK_DYLIB**. Έτσι, **αν ένας attacker τοποθετήσει ένα dylib εκεί όπου αναμένεται, αυτό θα φορτωθεί**.
- Το γεγονός ότι το link είναι "weak" σημαίνει ότι η εφαρμογή θα συνεχίσει να εκτελείται ακόμη και αν η library δεν βρεθεί.
- Ο **code που σχετίζεται** με αυτό βρίσκεται στη function `ImageLoaderMachO::doGetDependentLibraries` του `ImageLoaderMachO.cpp`, όπου το `lib->required` είναι `false` μόνο όταν το `LC_LOAD_WEAK_DYLIB` είναι true.
- **Βρείτε weak linked libraries** σε binaries με (παρακάτω υπάρχει παράδειγμα για το πώς να δημιουργήσετε hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Τα Mach-O binaries μπορούν να έχουν τις εντολές **`LC_RPATH`** και **`LC_LOAD_DYLIB`**. Με βάση τις **τιμές** αυτών των εντολών, οι **libraries** θα **φορτωθούν** από **διαφορετικούς καταλόγους**.
- Το **`LC_RPATH`** περιέχει τα paths ορισμένων φακέλων που χρησιμοποιούνται από το binary για τη φόρτωση libraries.
- Το **`LC_LOAD_DYLIB`** περιέχει το path συγκεκριμένων libraries που πρέπει να φορτωθούν. Αυτά τα paths μπορεί να περιέχουν **`@rpath`**, το οποίο θα **αντικατασταθεί** από τις τιμές του **`LC_RPATH`**. Αν υπάρχουν πολλά paths στο **`LC_RPATH`**, όλα θα χρησιμοποιηθούν για την αναζήτηση της library που πρέπει να φορτωθεί. Παράδειγμα:
- Αν το **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και το **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`, και οι δύο φάκελοι θα χρησιμοποιηθούν για τη φόρτωση του `library.dylib`**.** Αν η library δεν υπάρχει στο `[...]/v1/` και ένας attacker μπορεί να την τοποθετήσει εκεί, μπορεί να κάνει hijack της φόρτωσης της library στο `[...]/v2/`, καθώς ακολουθείται η σειρά των paths στο **`LC_LOAD_DYLIB`**.
- **Βρείτε rpath paths και libraries** σε binaries με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Είναι το **path** προς τον κατάλογο που περιέχει το **main executable file**.
>
> **`@loader_path`**: Είναι το **path** προς τον **κατάλογο** που περιέχει το **Mach-O binary** το οποίο περιέχει την load command.
>
> - Όταν χρησιμοποιείται σε executable, το **`@loader_path`** είναι ουσιαστικά ίδιο με το **`@executable_path`**.
> - Όταν χρησιμοποιείται σε **dylib**, το **`@loader_path`** δίνει το **path** προς το **dylib**.

Ο τρόπος για να κάνετε **privilege escalation** κάνοντας abuse αυτής της λειτουργίας θα ήταν η σπάνια περίπτωση όπου μια **εφαρμογή** που εκτελείται **από** τον **root** αναζητά κάποια **library σε φάκελο όπου ο attacker έχει write permissions**.

> [!TIP]
> Ένα χρήσιμο **scanner** για την εύρεση **missing libraries** σε εφαρμογές είναι το [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Μπορείτε να βρείτε [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) μια χρήσιμη **report με technical details** σχετικά με αυτή την τεχνική.

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Να θυμάστε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση επιθέσεων Dlopen hijacking.

Από το **`man dlopen`**:

- Όταν το path **δεν περιέχει slash character** (δηλαδή είναι απλώς ένα leaf name), η **dlopen() θα πραγματοποιήσει searching**. Αν το **`$DYLD_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα **αναζητήσει πρώτα σε αυτόν τον κατάλογο**. Στη συνέχεια, αν το calling mach-o file ή το main executable καθορίζει ένα **`LC_RPATH`**, τότε το dyld θα **αναζητήσει σε αυτούς τους** καταλόγους. Έπειτα, αν η process είναι **unrestricted**, το dyld θα αναζητήσει στον **current working directory**. Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους καταλόγους**, διαφορετικά το dyld θα αναζητήσει στο **`/usr/local/lib/`** (αν η process είναι unrestricted) και στη συνέχεια στο **`/usr/lib/`** (αυτές οι πληροφορίες προέρχονται από το **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD` (αν είναι unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (αν είναι unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Αν δεν υπάρχουν slashes στο name, υπάρχουν 2 τρόποι για να γίνει hijacking:
>
> - Αν οποιοδήποτε **`LC_RPATH`** είναι **writable** (αλλά το signature ελέγχεται, επομένως για αυτό χρειάζεται επίσης το binary να είναι unrestricted)
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατό να φορτωθεί κάτι από το CWD (ή μέσω abuse ενός από τα αναφερόμενα env variables)

- Όταν το path **μοιάζει με path framework** (π.χ. `/stuff/foo.framework/foo`), αν το **`$DYLD_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει πρώτα σε αυτόν τον κατάλογο το **framework partial path** (π.χ. `foo.framework/foo`). Στη συνέχεια, το dyld θα δοκιμάσει το **supplied path as-is** (χρησιμοποιώντας το current working directory για relative paths). Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους καταλόγους. Διαφορετικά, θα αναζητήσει στο **`/Library/Frameworks`** (στο macOS αν η process είναι unrestricted) και στη συνέχεια στο **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (χρησιμοποιώντας το current working directory για relative paths αν είναι unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (αν είναι unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Αν πρόκειται για framework path, ο τρόπος για να γίνει hijack είναι:
>
> - Αν η process είναι **unrestricted**, να γίνει abuse του **relative path από το CWD** ή των αναφερόμενων env variables (ακόμη και αν δεν αναφέρεται στα docs, αν η process είναι restricted, τα DYLD\_\* env vars αφαιρούνται)

- Όταν το path **περιέχει slash αλλά δεν είναι framework path** (δηλαδή full path ή partial path προς ένα dylib), η dlopen() πρώτα αναζητά (αν έχει οριστεί) στο **`$DYLD_LIBRARY_PATH`** (με το leaf part από το path). Στη συνέχεια, το dyld **δοκιμάζει το supplied path** (χρησιμοποιώντας το current working directory για relative paths, αλλά μόνο για unrestricted processes). Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους καταλόγους, διαφορετικά το dyld θα αναζητήσει στο **`/usr/local/lib/`** (αν η process είναι unrestricted) και στη συνέχεια στο **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (χρησιμοποιώντας το current working directory για relative paths αν είναι unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (αν είναι unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Αν υπάρχουν slashes στο name και δεν πρόκειται για framework, ο τρόπος για να γίνει hijack είναι:
>
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατό να φορτωθεί κάτι από το CWD ή το `/usr/local/lib` (ή μέσω abuse ενός από τα αναφερόμενα env variables)

> [!TIP]
> Σημείωση: Δεν υπάρχουν **configuration files** για τον **έλεγχο του dlopen searching**.
>
> Σημείωση: Αν το main executable είναι **set\[ug]id binary** ή codesigned με **entitlements**, τότε **όλα τα environment variables αγνοούνται** και μπορεί να χρησιμοποιηθεί μόνο full path ([δείτε τους περιορισμούς του DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) για περισσότερες πληροφορίες).
>
> Σημείωση: Οι Apple platforms χρησιμοποιούν "universal" files για να συνδυάζουν 32-bit και 64-bit libraries. Αυτό σημαίνει ότι **δεν υπάρχουν ξεχωριστά 32-bit και 64-bit search paths**.
>
> Σημείωση: Στις Apple platforms, τα περισσότερα OS dylibs είναι **combined στο dyld cache** και δεν υπάρχουν στον δίσκο. Επομένως, η κλήση του **`stat()`** για preflight έλεγχο ύπαρξης ενός OS dylib **δεν θα λειτουργήσει**. Ωστόσο, το **`dlopen_preflight()`** χρησιμοποιεί τα ίδια βήματα με το **`dlopen()`** για να βρει ένα συμβατό mach-o file.

**Check paths**

Ας ελέγξουμε όλες τις επιλογές με τον παρακάτω code:
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
Αν το κάνετε compile και execute, μπορείτε να δείτε **πού αναζητήθηκε ανεπιτυχώς κάθε library**. Επίσης, μπορείτε να κάνετε **filter στα FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Εάν ένα **privileged binary/app** (όπως ένα SUID ή κάποιο binary με ισχυρά entitlements) **φορτώνει μια βιβλιοθήκη από relative path** (για παράδειγμα χρησιμοποιώντας `@executable_path` ή `@loader_path`) και έχει απενεργοποιημένο το **Library Validation**, μπορεί να είναι δυνατή η μετακίνηση του binary σε μια τοποθεσία όπου ο attacker θα μπορούσε να **τροποποιήσει τη βιβλιοθήκη που φορτώνεται από το relative path** και να την εκμεταλλευτεί για inject κώδικα στη διεργασία.

## Prune `DYLD_*` env variables

Παλαιότερες εκδόσεις του `dyld` (`dyld2.cpp`) έπαιρναν αυτή την απόφαση in-process, χρησιμοποιώντας τις `issetugid()`, `hasRestrictedSegment()` και `csops(CS_OPS_STATUS)`. Στο **τρέχον `dyld` η απόφαση ανατίθεται στο AMFI** και ο κώδικας βρίσκεται στη `ProcessConfig::Security::Security()` στο `dyld/DyldProcessConfig.cpp`:<sup>[1]</sup>
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
Αξίζει να εξαχθούν δύο πράγματα από αυτό:

- Το **pruning** πραγματοποιείται μόνο σε **macOS / Mac Catalyst / DriverKit** — και μόνο όταν το AMFI δεν έχει εκχωρήσει καμία από τις `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Το ερώτημα προς το AMFI τροφοδοτείται με τις ιδιότητες του ίδιου του εκτελέσιμου:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
όπου το `isRestricted()` είναι κυριολεκτικά ο έλεγχος του segment `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[2]</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
Στη συνέχεια, η `pruneEnvVars()` αφαιρεί **κάθε** μεταβλητή της οποίας το όνομα αρχίζει με `DYLD_` και μετακινεί τις παραμέτρους `apple[]` προς τα κάτω, ώστε ούτε οι θυγατρικές διεργασίες μιας περιορισμένης διεργασίας να τις κληρονομούν:
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
> Πρακτική συνέπεια: οι **`DYLD_*`** μεταβλητές αφαιρούνται όταν η διεργασία είναι περιορισμένη — μέσω setuid/setgid, μιας ενότητας `__RESTRICT/__restrict` ή hardened-runtime/entitled binaries, στα οποία το AMFI αρνείται να παραχωρήσει τα flags path/print. Αντίθετα, αν η διεργασία διαθέτει μόνο **library validation** (`CS_REQUIRE_LV`), οι μεταβλητές διατηρούνται, αλλά το dylib που εισάγεται πρέπει να είναι υπογεγραμμένο με το **ίδιο Team ID** (ή από την Apple), επομένως χρειάζεστε ένα από τα entitlements απενεργοποίησης του library validation για να εκτελεστεί πράγματι ο κώδικας.

Εφόσον η απόφαση λαμβάνεται πλέον από το AMFI, ο ταχύτερος τρόπος για να διαπιστώσετε τι θα επιτρέψει σε ένα δεδομένο binary είναι να εξετάσετε τα στοιχεία από τα οποία εξαρτάται το AMFI — τα entitlements και τα signing flags — αντί για το ίδιο το `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Έλεγχος Περιορισμών

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

Δημιουργήστε ένα νέο πιστοποιητικό στο Keychain και χρησιμοποιήστε το για να υπογράψετε το δυαδικό αρχείο:
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
> Σημειώστε ότι ακόμη και αν υπάρχουν binaries υπογεγραμμένα με flags **`0x0(none)`**, μπορούν να αποκτήσουν δυναμικά το flag **`CS_RESTRICT`** κατά την εκτέλεσή τους και επομένως αυτή η τεχνική δεν θα λειτουργήσει σε αυτά.
>
> Μπορείτε να ελέγξετε αν ένα proc έχει αυτό το flag με το (λάβετε το [**csops εδώ**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> και στη συνέχεια να ελέγξετε αν είναι ενεργοποιημένο το flag 0x800.

## Αναφορές

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / έλεγχος `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (εκκίνηση process και εισαγωγή library)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
