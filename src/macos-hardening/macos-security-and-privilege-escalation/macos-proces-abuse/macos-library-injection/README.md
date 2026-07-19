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

Αυτή η τεχνική μπορεί επίσης να **χρησιμοποιηθεί ως τεχνική ASEP**, καθώς κάθε εγκατεστημένη εφαρμογή έχει ένα plist με όνομα "Info.plist", το οποίο επιτρέπει την **εκχώρηση environmental variables** χρησιμοποιώντας ένα key με όνομα `LSEnvironmental`.

> [!TIP]
> Από το 2012, η **Apple έχει περιορίσει δραστικά τις δυνατότητες** του **`DYLD_INSERT_LIBRARIES`**.
>
> Μεταβείτε στον κώδικα και **ελέγξτε το `src/dyld.cpp`**. Στη function **`pruneEnvironmentVariables`** μπορείτε να δείτε ότι οι μεταβλητές **`DYLD_*`** αφαιρούνται.
>
> Στη function **`processRestricted`** ορίζεται ο λόγος του περιορισμού. Ελέγχοντας αυτόν τον κώδικα, μπορείτε να δείτε ότι οι λόγοι είναι:
>
> - Το binary είναι `setuid/setgid`
> - Υπάρχει section `__RESTRICT/__restrict` στο macho binary.
> - Το software έχει entitlements (hardened runtime) χωρίς το entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Ελέγξτε τα **entitlements** ενός binary με: `codesign -dv --entitlements :- </path/to/bin>`
>
> Σε πιο ενημερωμένες versions μπορείτε να βρείτε αυτή τη λογική στο δεύτερο μέρος της function **`configureProcessRestrictions`.** Ωστόσο, αυτό που εκτελείται σε νεότερες versions είναι οι **αρχικοί έλεγχοι της function** (μπορείτε να αφαιρέσετε τα ifs που σχετίζονται με iOS ή simulation, καθώς δεν θα χρησιμοποιηθούν στο macOS.

### Library Validation

Ακόμη και αν το binary επιτρέπει τη χρήση του env variable **`DYLD_INSERT_LIBRARIES`**, αν το binary ελέγχει την υπογραφή της library πριν τη φορτώσει, δεν θα φορτώσει μια custom library.

Για να φορτώσει μια custom library, το binary πρέπει να έχει **ένα από τα ακόλουθα entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ή το binary **δεν πρέπει** να έχει το **hardened runtime flag** ή το **library validation flag**.

Μπορείτε να ελέγξετε αν ένα binary έχει **hardened runtime** με `codesign --display --verbose <bin>`, ελέγχοντας το runtime flag στο **`CodeDirectory`**, όπως: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Μπορείτε επίσης να φορτώσετε μια library αν είναι **υπογεγραμμένη με το ίδιο certificate με το binary**.

Βρείτε ένα παράδειγμα για το πώς να κάνετε (ab)use αυτής της δυνατότητας και να ελέγξετε τους περιορισμούς στο:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Να θυμάστε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση επιθέσεων Dylib hijacking.

Όπως στα Windows, έτσι και στο MacOS μπορείτε επίσης να κάνετε **hijack dylibs**, ώστε οι **applications** να **εκτελούν** **arbitrary** **code** (στην πραγματικότητα, από έναν regular user αυτό μπορεί να μην είναι δυνατό, καθώς ενδέχεται να χρειάζεστε TCC permission για να γράψετε μέσα σε ένα `.app` bundle και να κάνετε hijack μια library).\
Ωστόσο, ο τρόπος με τον οποίο οι **MacOS** applications **φορτώνουν** libraries είναι **πιο περιορισμένος** από ό,τι στα Windows. Αυτό σημαίνει ότι οι developers **malware** μπορούν ακόμη να χρησιμοποιήσουν αυτή την τεχνική για **stealth**, αλλά η πιθανότητα να μπορέσουν να κάνουν **abuse** αυτής της τεχνικής για privilege escalation είναι πολύ μικρότερη.

Καταρχάς, είναι **πιο συνηθισμένο** να βρείτε ότι τα **MacOS binaries υποδεικνύουν το πλήρες path** των libraries που θα φορτωθούν. Επιπλέον, το **MacOS δεν αναζητά ποτέ** libraries στους φακέλους του **$PATH**.

Το **κύριο** τμήμα του **κώδικα** που σχετίζεται με αυτή τη λειτουργικότητα βρίσκεται στη **`ImageLoader::recursiveLoadLibraries`** στο `ImageLoader.cpp`.

Υπάρχουν **4 διαφορετικές header Commands** που μπορεί να χρησιμοποιήσει ένα macho binary για να φορτώσει libraries:

- Η **`LC_LOAD_DYLIB`** command είναι η συνηθισμένη command για τη φόρτωση μιας dylib.
- Η **`LC_LOAD_WEAK_DYLIB`** command λειτουργεί όπως η προηγούμενη, αλλά αν η dylib δεν βρεθεί, η εκτέλεση συνεχίζεται χωρίς error.
- Η **`LC_REEXPORT_DYLIB`** command κάνει proxy (ή re-export) τα symbols από μια διαφορετική library.
- Η **`LC_LOAD_UPWARD_DYLIB`** command χρησιμοποιείται όταν δύο libraries εξαρτώνται η μία από την άλλη (αυτό ονομάζεται _upward dependency_).

Ωστόσο, υπάρχουν **2 τύποι Dylib hijacking**:

- **Missing weak linked libraries**: Αυτό σημαίνει ότι η application θα προσπαθήσει να φορτώσει μια library που δεν υπάρχει και έχει ρυθμιστεί με **LC_LOAD_WEAK_DYLIB**. Έπειτα, **αν ένας attacker τοποθετήσει μια dylib εκεί όπου αναμένεται, θα φορτωθεί**.
- Το γεγονός ότι το link είναι "weak" σημαίνει ότι η application θα συνεχίσει να εκτελείται ακόμη και αν η library δεν βρεθεί.
- Ο **κώδικας που σχετίζεται** με αυτό βρίσκεται στη function `ImageLoaderMachO::doGetDependentLibraries` του `ImageLoaderMachO.cpp`, όπου το `lib->required` είναι `false` μόνο όταν το `LC_LOAD_WEAK_DYLIB` είναι true.
- **Βρείτε weak linked libraries** σε binaries με το ακόλουθο (παρακάτω υπάρχει παράδειγμα για το πώς να δημιουργήσετε hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Τα Mach-O binaries μπορούν να έχουν τις commands **`LC_RPATH`** και **`LC_LOAD_DYLIB`**. Με βάση τις **τιμές** αυτών των commands, οι **libraries** θα **φορτωθούν** από **διαφορετικούς καταλόγους**.
- Το **`LC_RPATH`** περιέχει τα paths ορισμένων φακέλων που χρησιμοποιούνται από το binary για τη φόρτωση libraries.
- Το **`LC_LOAD_DYLIB`** περιέχει το path συγκεκριμένων libraries που θα φορτωθούν. Αυτά τα paths μπορεί να περιέχουν **`@rpath`**, το οποίο θα **αντικατασταθεί** από τις τιμές στο **`LC_RPATH`**. Αν υπάρχουν πολλά paths στο **`LC_RPATH`**, όλα θα χρησιμοποιηθούν για την αναζήτηση της library που θα φορτωθεί. Παράδειγμα:
- Αν το **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και το **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`. Και οι δύο φάκελοι θα χρησιμοποιηθούν για τη φόρτωση της `library.dylib`**.** Αν η library δεν υπάρχει στο `[...]/v1/` και ένας attacker μπορεί να την τοποθετήσει εκεί, μπορεί να κάνει hijack τη φόρτωση της library στο `[...]/v2/`, καθώς ακολουθείται η σειρά των paths στο **`LC_LOAD_DYLIB`**.
- **Βρείτε rpath paths και libraries** σε binaries με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Είναι το **path** προς τον κατάλογο που περιέχει το **κύριο executable file**.
>
> **`@loader_path`**: Είναι το **path** προς τον **κατάλογο** που περιέχει το **Mach-O binary** το οποίο περιέχει τη load command.
>
> - Όταν χρησιμοποιείται σε executable, το **`@loader_path`** είναι ουσιαστικά ίδιο με το **`@executable_path`**.
> - Όταν χρησιμοποιείται σε **dylib**, το **`@loader_path`** δίνει το **path** προς τη **dylib**.

Ο τρόπος για **privilege escalation** μέσω abuse αυτής της λειτουργικότητας θα ήταν η σπάνια περίπτωση όπου μια **application** που εκτελείται από τον **root** αναζητά κάποια **library σε φάκελο στον οποίο ο attacker έχει write permissions.**

> [!TIP]
> Ένα καλό **scanner** για την εύρεση **missing libraries** σε applications είναι το [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Μια καλή **αναφορά με technical details** σχετικά με αυτή την τεχνική βρίσκεται [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Να θυμάστε ότι οι **προηγούμενοι περιορισμοί του Library Validation ισχύουν επίσης** για την εκτέλεση επιθέσεων Dlopen hijacking.

Από το **`man dlopen`**:

- Όταν το path **δεν περιέχει χαρακτήρα slash** (δηλαδή είναι απλώς leaf name), η **dlopen() θα κάνει searching**. Αν το **`$DYLD_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα **αναζητήσει πρώτα σε αυτόν τον κατάλογο**. Στη συνέχεια, αν το calling mach-o file ή το main executable καθορίζει ένα **`LC_RPATH`**, το dyld θα **αναζητήσει σε αυτούς τους** καταλόγους. Έπειτα, αν η process είναι **unrestricted**, το dyld θα αναζητήσει στον **τρέχοντα working directory**. Τέλος, για παλαιά binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους καταλόγους**, διαφορετικά θα αναζητήσει στο **`/usr/local/lib/`** (αν η process είναι unrestricted) και στη συνέχεια στο **`/usr/lib/`** (αυτές οι πληροφορίες προέρχονται από το **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Αν δεν υπάρχουν slashes στο name, υπάρχουν 2 τρόποι για hijacking:
>
> - Αν κάποιο **`LC_RPATH`** είναι **writable** (αλλά γίνεται signature check, επομένως για αυτό χρειάζεται επίσης το binary να είναι unrestricted)
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατή η φόρτωση κάποιου στοιχείου από το CWD (ή το abuse ενός από τα προαναφερθέντα env variables)

- Όταν το path **μοιάζει με path framework** (π.χ. `/stuff/foo.framework/foo`), αν το **`$DYLD_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει πρώτα σε αυτόν τον κατάλογο το **partial path του framework** (π.χ. `foo.framework/foo`). Στη συνέχεια, το dyld θα δοκιμάσει το **παρεχόμενο path όπως είναι** (χρησιμοποιώντας τον τρέχοντα working directory για relative paths). Τέλος, για παλαιά binaries, το dyld θα δοκιμάσει ορισμένα fallbacks. Αν το **`$DYLD_FALLBACK_FRAMEWORK_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους καταλόγους. Διαφορετικά, θα αναζητήσει στο **`/Library/Frameworks`** (στο macOS αν η process είναι unrestricted) και στη συνέχεια στο **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Αν πρόκειται για framework path, ο τρόπος για να γίνει hijack είναι:
>
> - Αν η process είναι **unrestricted**, μέσω abuse του **relative path από το CWD** και των προαναφερθέντων env variables (ακόμη και αν δεν αναφέρεται στα docs, αν η process είναι restricted, τα DYLD\_\* env vars αφαιρούνται)

- Όταν το path **περιέχει slash αλλά δεν είναι framework path** (δηλαδή full path ή partial path προς μια dylib), η dlopen() κοιτάζει πρώτα (αν έχει οριστεί) στο **`$DYLD_LIBRARY_PATH`** (με το leaf part από το path). Στη συνέχεια, το dyld **δοκιμάζει το παρεχόμενο path** (χρησιμοποιώντας τον τρέχοντα working directory για relative paths (αλλά μόνο για unrestricted processes)). Τέλος, για παλαιότερα binaries, το dyld θα δοκιμάσει fallbacks. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** είχε οριστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους καταλόγους, διαφορετικά θα αναζητήσει στο **`/usr/local/lib/`** (αν η process είναι unrestricted) και στη συνέχεια στο **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Αν υπάρχουν slashes στο name και δεν είναι framework, ο τρόπος για να γίνει hijack είναι:
>
> - Αν το binary είναι **unrestricted**, οπότε είναι δυνατή η φόρτωση κάποιου στοιχείου από το CWD ή το `/usr/local/lib` (ή το abuse ενός από τα προαναφερθέντα env variables)

> [!TIP]
> Σημείωση: Δεν υπάρχουν configuration files για τον **έλεγχο του dlopen searching**.
>
> Σημείωση: Αν το main executable είναι **set\[ug]id binary** ή είναι codesigned με entitlements, τότε **όλα τα environment variables αγνοούνται** και μπορεί να χρησιμοποιηθεί μόνο full path ([ελέγξτε τους περιορισμούς του DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) για περισσότερες πληροφορίες)
>
> Σημείωση: Οι Apple platforms χρησιμοποιούν "universal" files για τον συνδυασμό 32-bit και 64-bit libraries. Αυτό σημαίνει ότι **δεν υπάρχουν ξεχωριστά 32-bit και 64-bit search paths**.
>
> Σημείωση: Στις Apple platforms, τα περισσότερα OS dylibs είναι **συνδυασμένα στο dyld cache** και δεν υπάρχουν στον δίσκο. Επομένως, η κλήση του **`stat()`** για preflight έλεγχο ύπαρξης μιας OS dylib **δεν θα λειτουργήσει**. Ωστόσο, το **`dlopen_preflight()`** χρησιμοποιεί τα ίδια βήματα με το **`dlopen()`** για να βρει ένα συμβατό mach-o file.

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
Αν το κάνετε compile και το εκτελέσετε, μπορείτε να δείτε **πού αναζητήθηκε ανεπιτυχώς κάθε library**. Επίσης, μπορείτε να **φιλτράρετε τα FS logs**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Εάν ένα **privileged binary/app** (όπως ένα SUID ή κάποιο binary με ισχυρά entitlements) **φορτώνει** μια βιβλιοθήκη μέσω **relative path** (για παράδειγμα χρησιμοποιώντας `@executable_path` ή `@loader_path`) και έχει απενεργοποιημένο το **Library Validation**, θα μπορούσε να είναι δυνατή η μετακίνηση του binary σε μια τοποθεσία όπου ο attacker θα μπορούσε να **τροποποιήσει τη βιβλιοθήκη που φορτώνεται μέσω relative path** και να την εκμεταλλευτεί για την εισαγωγή κώδικα στη διεργασία.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

Στο αρχείο `dyld-dyld-832.7.1/src/dyld2.cpp` είναι δυνατό να εντοπίσετε τη συνάρτηση **`pruneEnvironmentVariables`**, η οποία αφαιρεί οποιαδήποτε env variable **ξεκινά με `DYLD_`** και **`LD_LIBRARY_PATH=`**.

Επίσης, ορίζει συγκεκριμένα σε **null** τις env variables **`DYLD_FALLBACK_FRAMEWORK_PATH`** και **`DYLD_FALLBACK_LIBRARY_PATH`** για **suid** και **sgid** binaries.

Αυτή η συνάρτηση καλείται από τη συνάρτηση **`_main`** του ίδιου αρχείου όταν γίνεται targeting σε OSX, ως εξής:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
και αυτά τα boolean flags ορίζονται στο ίδιο αρχείο στον κώδικα:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Που βασικά σημαίνει ότι αν το binary είναι **suid** ή **sgid**, ή έχει ένα segment **RESTRICT** στα headers, ή έχει υπογραφεί με το flag **CS_RESTRICT**, τότε η συνθήκη **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** είναι true και οι μεταβλητές περιβάλλοντος αφαιρούνται.

Σημειώστε ότι αν το CS_REQUIRE_LV είναι true, τότε οι μεταβλητές δεν θα αφαιρεθούν, αλλά η library validation θα ελέγξει ότι χρησιμοποιούν το ίδιο certificate με το αρχικό binary.

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
> Σημειώστε ότι ακόμη και αν υπάρχουν binaries υπογεγραμμένα με flags **`0x0(none)`**, μπορούν να αποκτήσουν δυναμικά το flag **`CS_RESTRICT`** κατά την εκτέλεσή τους και, επομένως, αυτή η τεχνική δεν θα λειτουργήσει σε αυτά.
>
> Μπορείτε να ελέγξετε αν μια διεργασία έχει αυτό το flag με το (λάβετε το [**csops εδώ**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> και, στη συνέχεια, να ελέγξετε αν το flag 0x800 είναι ενεργοποιημένο.

## Αναφορές

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
