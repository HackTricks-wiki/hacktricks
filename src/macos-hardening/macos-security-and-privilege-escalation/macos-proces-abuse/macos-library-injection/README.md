# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Ο κώδικας του **dyld είναι open source** και μπορεί να βρεθεί στο [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) και να ληφθεί ως tar χρησιμοποιώντας ένα **URL όπως** το [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Δείτε πώς το Dyld φορτώνει libraries μέσα σε binaries στο:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Αυτό είναι αντίστοιχο με το [**LD_PRELOAD στο Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Επιτρέπει να υποδείξετε σε μια process που πρόκειται να εκτελεστεί να φορτώσει μια συγκεκριμένη library από ένα path (αν το env var είναι ενεργοποιημένο).

Αυτή η τεχνική μπορεί επίσης να **χρησιμοποιηθεί ως ASEP technique**, καθώς κάθε εγκατεστημένη εφαρμογή έχει ένα plist που ονομάζεται "Info.plist" και επιτρέπει τον **καθορισμό environmental variables** χρησιμοποιώντας ένα key που ονομάζεται `LSEnvironmental`.

> [!TIP]
> Από το 2012, **η Apple έχει μειώσει δραστικά την ισχύ** του **`DYLD_INSERT_LIBRARIES`**. Μια process θεωρείται **restricted** — και επομένως το `dyld` διαγράφει κάθε μεταβλητή `DYLD_*` από το environment της — όταν ισχύει οποιοδήποτε από τα παρακάτω:
>
> - Το binary είναι `setuid/setgid`
> - Το Mach-O περιέχει ένα **`__RESTRICT/__restrict`** section
> - Το binary είναι signed με hardened runtime και το AMFI δεν του εκχωρεί τα permissions "path/print variables", δηλαδή δεν διαθέτει το [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Ελέγξτε τα **entitlements** ενός binary με: `codesign -dv --entitlements :- </path/to/bin>`
>
> Στο τρέχον `dyld`, αυτό δεν αποφασίζεται πλέον μόνο από το `dyld`: το `ProcessConfig::Security::Security()` ρωτά το **AMFI** μέσω του `amfi_check_dyld_policy_self()` και στη συνέχεια καλεί το `pruneEnvVars()`. Ο ακριβής κώδικας αναλύεται παρακάτω στο [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Ακόμη και αν το binary επιτρέπει τη χρήση του **`DYLD_INSERT_LIBRARIES`** env variable, αν το binary ελέγχει την υπογραφή της library πριν τη φορτώσει, δεν θα φορτώσει μια custom library.

Για να φορτωθεί μια custom library, το binary πρέπει να διαθέτει **ένα από τα παρακάτω entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ή το binary **δεν πρέπει** να έχει το **hardened runtime flag** ή το **library validation flag**.

Μπορείτε να ελέγξετε αν ένα binary διαθέτει **hardened runtime** με `codesign --display --verbose <bin>`, ελέγχοντας το runtime flag στο **`CodeDirectory`**, όπως στο: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Μπορείτε επίσης να φορτώσετε μια library αν είναι **signed με το ίδιο certificate με το binary**.

Βρείτε ένα παράδειγμα για το πώς μπορεί να γίνει (ab)use αυτού και ελέγξτε τους περιορισμούς στο:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Θυμηθείτε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση Dylib hijacking attacks.

Όπως στα Windows, στο MacOS μπορείτε επίσης να κάνετε **hijack dylibs** ώστε να κάνετε τις **applications** να **εκτελούν** **arbitrary** **code** (στην πράξη, από έναν απλό user αυτό μπορεί να μην είναι δυνατό, καθώς ενδέχεται να χρειάζεται TCC permission για εγγραφή μέσα σε ένα `.app` bundle και hijack μιας library).\
Ωστόσο, ο τρόπος με τον οποίο οι **MacOS** applications **φορτώνουν** libraries είναι **περισσότερο περιορισμένος** σε σχέση με τα Windows. Αυτό σημαίνει ότι οι developers **malware** μπορούν ακόμη να χρησιμοποιήσουν αυτή την τεχνική για **stealth**, αλλά η πιθανότητα να γίνει **abuse** για privilege escalation είναι πολύ μικρότερη.

Καταρχάς, είναι **πιο συνηθισμένο** να διαπιστώνεται ότι τα **MacOS binaries υποδεικνύουν το πλήρες path** των libraries που θα φορτώσουν. Επιπλέον, το **MacOS δεν αναζητά ποτέ** libraries στους φακέλους του **$PATH**.

Το **κύριο** μέρος του **code** που σχετίζεται με αυτή τη λειτουργικότητα βρίσκεται στο **`ImageLoader::recursiveLoadLibraries`** του `ImageLoader.cpp`.

Υπάρχουν **4 διαφορετικά header Commands** που μπορεί να χρησιμοποιήσει ένα macho binary για να φορτώσει libraries:

- Το **`LC_LOAD_DYLIB`** command είναι το συνηθισμένο command για τη φόρτωση μιας dylib.
- Το **`LC_LOAD_WEAK_DYLIB`** command λειτουργεί όπως το προηγούμενο, αλλά αν η dylib δεν βρεθεί, η εκτέλεση συνεχίζεται χωρίς error.
- Το **`LC_REEXPORT_DYLIB`** command λειτουργεί ως proxy (ή κάνει re-export) των symbols από διαφορετική library.
- Το **`LC_LOAD_UPWARD_DYLIB`** command χρησιμοποιείται όταν δύο libraries εξαρτώνται η μία από την άλλη (αυτό ονομάζεται _upward dependency_).

Ωστόσο, υπάρχουν **2 τύποι dylib hijacking**:

- **Missing weak linked libraries**: Αυτό σημαίνει ότι η application θα προσπαθήσει να φορτώσει μια library που δεν υπάρχει, ρυθμισμένη με **LC_LOAD_WEAK_DYLIB**. Έπειτα, **αν ένας attacker τοποθετήσει μια dylib στο αναμενόμενο σημείο, θα φορτωθεί**.
- Το γεγονός ότι ο σύνδεσμος είναι "weak" σημαίνει ότι η application θα συνεχίσει να εκτελείται ακόμη και αν η library δεν βρεθεί.
- Ο **code που σχετίζεται** με αυτό βρίσκεται στη function `ImageLoaderMachO::doGetDependentLibraries` του `ImageLoaderMachO.cpp`, όπου το `lib->required` είναι `false` μόνο όταν το `LC_LOAD_WEAK_DYLIB` είναι true.
- **Βρείτε weak linked libraries** σε binaries με (παρακάτω υπάρχει παράδειγμα για τη δημιουργία hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Τα Mach-O binaries μπορούν να έχουν τα commands **`LC_RPATH`** και **`LC_LOAD_DYLIB`**. Με βάση τις **τιμές** αυτών των commands, οι **libraries** θα **φορτωθούν** από **διαφορετικούς καταλόγους**.
- Το **`LC_RPATH`** περιέχει τα paths ορισμένων φακέλων που χρησιμοποιούνται από το binary για τη φόρτωση libraries.
- Το **`LC_LOAD_DYLIB`** περιέχει το path συγκεκριμένων libraries προς φόρτωση. Αυτά τα paths μπορούν να περιέχουν **`@rpath`**, το οποίο θα **αντικατασταθεί** από τις τιμές του **`LC_RPATH`**. Αν υπάρχουν πολλά paths στο **`LC_RPATH`**, όλα θα χρησιμοποιηθούν για την αναζήτηση της library προς φόρτωση. Παράδειγμα:
- Αν το **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και το **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`. Και οι δύο φάκελοι θα χρησιμοποιηθούν για τη φόρτωση της `library.dylib`**.** Αν η library δεν υπάρχει στο `[...]/v1/` και ένας attacker μπορεί να την τοποθετήσει εκεί, μπορεί να γίνει hijack της φόρτωσης της library στο `[...]/v2/`, καθώς ακολουθείται η σειρά των paths στο **`LC_LOAD_DYLIB`**.
- **Βρείτε rpath paths και libraries** σε binaries με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Είναι το **path** του directory που περιέχει το **main executable file**.
>
> **`@loader_path`**: Είναι το **path** του **directory** που περιέχει το **Mach-O binary** το οποίο περιέχει το load command.
>
> - Όταν χρησιμοποιείται σε executable, το **`@loader_path`** είναι ουσιαστικά ίδιο με το **`@executable_path`**.
> - Όταν χρησιμοποιείται σε **dylib**, το **`@loader_path`** δίνει το **path** προς τη **dylib**.

Ο τρόπος για **privilege escalation** μέσω abuse αυτής της λειτουργικότητας θα υπήρχε στη σπάνια περίπτωση όπου μια **application** που εκτελείται από τον **root** αναζητά κάποια **library σε φάκελο στον οποίο ο attacker έχει write permissions**.

> [!TIP]
> Ένα καλό **scanner** για την εύρεση **missing libraries** σε applications είναι το [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Μια καλή **report με technical details** σχετικά με αυτή την τεχνική βρίσκεται [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Θυμηθείτε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση Dlopen hijacking attacks.

Από το **`man dlopen`**:

- Όταν το path **δεν περιέχει slash character** (δηλαδή είναι απλώς ένα leaf name), η **dlopen() θα κάνει searching**. Αν το **`$DYLD_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα **αναζητήσει πρώτα σε αυτό το directory**. Στη συνέχεια, αν το calling mach-o file ή το main executable καθορίζει ένα **`LC_RPATH`**, το dyld θα **αναζητήσει σε αυτούς τους** καταλόγους. Έπειτα, αν η process είναι **unrestricted**, το dyld θα αναζητήσει στο **current working directory**. Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους καταλόγους**, διαφορετικά θα αναζητήσει στο **`/usr/local/lib/`** (αν η process είναι unrestricted) και έπειτα στο **`/usr/lib/`** (αυτές οι πληροφορίες προέρχονται από το **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Αν το name δεν περιέχει slashes, υπάρχουν 2 τρόποι για hijacking:
>
> - Αν κάποιο **`LC_RPATH`** είναι **writable** (όμως η signature ελέγχεται, επομένως γι' αυτό χρειάζεται επίσης το binary να είναι unrestricted)
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατή η φόρτωση κάποιου στοιχείου από το CWD (ή το abuse ενός από τα αναφερόμενα env variables)

- Όταν το path **μοιάζει με** path framework (π.χ. `/stuff/foo.framework/foo`), αν το **`$DYLD_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει πρώτα σε αυτό το directory το **framework partial path** (π.χ. `foo.framework/foo`). Στη συνέχεια, το dyld θα δοκιμάσει το **supplied path as-is** (χρησιμοποιώντας το current working directory για relative paths). Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους καταλόγους. Διαφορετικά, θα αναζητήσει στο **`/Library/Frameworks`** (στο macOS αν η process είναι unrestricted) και έπειτα στο **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Αν πρόκειται για framework path, ο τρόπος για να γίνει hijack είναι:
>
> - Αν η process είναι **unrestricted**, μέσω abuse του **relative path από το CWD** και των αναφερόμενων env variables (ακόμη και αν δεν αναφέρεται στα docs, όταν η process είναι restricted, τα DYLD\_\* env vars αφαιρούνται)

- Όταν το path **περιέχει slash αλλά δεν είναι framework path** (δηλαδή full path ή partial path προς dylib), η dlopen() κοιτάζει πρώτα, **αν έχει οριστεί**, στο **`$DYLD_LIBRARY_PATH`** (με το leaf part από το path). Στη συνέχεια, το dyld **δοκιμάζει το supplied path** (χρησιμοποιώντας το current working directory για relative paths (αλλά μόνο για unrestricted processes)). Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους καταλόγους, διαφορετικά θα αναζητήσει στο **`/usr/local/lib/`** (αν η process είναι unrestricted) και έπειτα στο **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Αν το name περιέχει slashes και δεν είναι framework, ο τρόπος για να γίνει hijack είναι:
>
> - Αν το binary είναι **unrestricted**, είναι δυνατή η φόρτωση κάποιου στοιχείου από το CWD ή το `/usr/local/lib` (ή το abuse ενός από τα αναφερόμενα env variables)

> [!TIP]
> Σημείωση: Δεν υπάρχουν **configuration files για τον έλεγχο του dlopen searching**.
>
> Σημείωση: Αν το main executable είναι **set\[ug]id binary ή codesigned με entitlements**, τότε **όλα τα environment variables αγνοούνται** και μπορεί να χρησιμοποιηθεί μόνο full path ([δείτε τους περιορισμούς του DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) για περισσότερες πληροφορίες).
>
> Σημείωση: Οι Apple platforms χρησιμοποιούν "universal" files για τον συνδυασμό 32-bit και 64-bit libraries. Αυτό σημαίνει ότι **δεν υπάρχουν ξεχωριστά 32-bit και 64-bit search paths**.
>
> Σημείωση: Στις Apple platforms, οι περισσότερες OS dylibs είναι **combined στο dyld cache** και δεν υπάρχουν στον δίσκο. Επομένως, η κλήση της **`stat()`** για preflight έλεγχο της ύπαρξης μιας OS dylib **δεν θα λειτουργήσει**. Ωστόσο, η **`dlopen_preflight()`** χρησιμοποιεί τα ίδια βήματα με την **`dlopen()`** για να βρει ένα συμβατό mach-o file.

**Check paths**

Ας ελέγξουμε όλες τις επιλογές με τον ακόλουθο code:
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
Αν το κάνετε compile και το εκτελέσετε, μπορείτε να δείτε **πού έγινε ανεπιτυχής αναζήτηση για κάθε library**. Επίσης, θα μπορούσατε να **φιλτράρετε τα FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Αν ένα **privileged binary/app** (όπως ένα SUID ή κάποιο binary με ισχυρά entitlements) **φορτώνει μια βιβλιοθήκη μέσω relative path** (για παράδειγμα χρησιμοποιώντας `@executable_path` ή `@loader_path`) και έχει απενεργοποιημένο το **Library Validation**, θα μπορούσε να είναι δυνατή η μετακίνηση του binary σε μια τοποθεσία όπου ο attacker θα μπορούσε να **τροποποιήσει τη βιβλιοθήκη που φορτώνεται μέσω relative path** και να την εκμεταλλευτεί για inject κώδικα στη διεργασία.

## Prune `DYLD_*` env variables

Οι παλαιότερες εκδόσεις του `dyld` (`dyld2.cpp`) λάμβαναν αυτή την απόφαση εντός της διεργασίας, χρησιμοποιώντας τις `issetugid()`, `hasRestrictedSegment()` και `csops(CS_OPS_STATUS)`. Στο **τρέχον `dyld`, η απόφαση ανατίθεται στο AMFI**, και ο κώδικας βρίσκεται στη `ProcessConfig::Security::Security()` στο `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Από αυτό αξίζει να εξαχθούν δύο συμπεράσματα:

- Το **pruning** πραγματοποιείται μόνο σε **macOS / Mac Catalyst / DriverKit** — και μόνο όταν το AMFI δεν έχει εκχωρήσει καμία από τις `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Το ερώτημα προς το AMFI τροφοδοτείται με τις ίδιες τις ιδιότητες του εκτελέσιμου:
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
`pruneEnvVars()` κατόπιν αφαιρεί **κάθε** μεταβλητή της οποίας το όνομα αρχίζει με `DYLD_` και μετακινεί τις παραμέτρους `apple[]` προς τα κάτω, ώστε ούτε οι θυγατρικές διεργασίες μιας περιορισμένης διεργασίας να τις κληρονομούν:
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
> Πρακτική συνέπεια: τα **`DYLD_*`** αφαιρούνται όταν η διεργασία είναι περιορισμένη — μέσω setuid/setgid, μιας ενότητας `__RESTRICT/__restrict` ή hardened-runtime/entitled binaries στα οποία το AMFI αρνείται να εκχωρήσει τα path/print flags. Αν, αντίθετα, η διεργασία διαθέτει μόνο **library validation** (`CS_REQUIRE_LV`), οι μεταβλητές διατηρούνται, αλλά το dylib που εισάγεται πρέπει να είναι υπογεγραμμένο με το **ίδιο Team ID** (ή από την Apple), επομένως χρειάζεστε ένα από τα entitlements που απενεργοποιούν το library validation για να εισαγάγετε πράγματι κώδικα.

Επειδή η απόφαση λαμβάνεται πλέον από το AMFI, ο ταχύτερος τρόπος να μάθετε τι θα επιτρέψει ένα συγκεκριμένο binary είναι να εξετάσετε σε τι βασίζεται το AMFI — entitlements και signing flags — αντί για το ίδιο το `dyld`:
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
### Ενότητα `__RESTRICT` με τμήμα `__restrict`
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
> Μπορείτε να ελέγξετε αν ένα proc έχει αυτό το flag με το (βρείτε το [**csops here**](https://github.com/axelexic/CSOps)):
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
