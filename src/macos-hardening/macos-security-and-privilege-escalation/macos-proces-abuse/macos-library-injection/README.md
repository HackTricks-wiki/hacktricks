# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Ο κώδικας του **dyld είναι ανοιχτού κώδικα** και μπορεί να βρεθεί στο [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) και μπορεί να κατέβει ως tar χρησιμοποιώντας μια **διεύθυνση URL όπως** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Ρίξτε μια ματιά στο πώς το Dyld φορτώνει βιβλιοθήκες μέσα σε δυαδικά αρχεία στο:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Αυτό είναι όπως το [**LD_PRELOAD στο Linux**](../../../../linux-hardening/privilege-escalation/#ld_preload). Επιτρέπει να υποδείξετε μια διαδικασία που πρόκειται να εκτελεστεί για να φορτώσει μια συγκεκριμένη βιβλιοθήκη από μια διαδρομή (αν η μεταβλητή περιβάλλοντος είναι ενεργοποιημένη)

Αυτή η τεχνική μπορεί επίσης να **χρησιμοποιηθεί ως τεχνική ASEP** καθώς κάθε εφαρμογή που είναι εγκατεστημένη έχει ένα plist που ονομάζεται "Info.plist" που επιτρέπει την **ανάθεση περιβαλλοντικών μεταβλητών** χρησιμοποιώντας ένα κλειδί που ονομάζεται `LSEnvironmental`.

> [!NOTE]
> Από το 2012 **η Apple έχει μειώσει δραστικά τη δύναμη** του **`DYLD_INSERT_LIBRARIES`**.
>
> Πηγαίνετε στον κώδικα και **ελέγξτε `src/dyld.cpp`**. Στη συνάρτηση **`pruneEnvironmentVariables`** μπορείτε να δείτε ότι οι μεταβλητές **`DYLD_*`** αφαιρούνται.
>
> Στη συνάρτηση **`processRestricted`** ορίζεται ο λόγος της περιορισμού. Ελέγχοντας αυτόν τον κώδικα μπορείτε να δείτε ότι οι λόγοι είναι:
>
> - Το δυαδικό αρχείο είναι `setuid/setgid`
> - Υπάρχει τμήμα `__RESTRICT/__restrict` στο macho δυαδικό αρχείο.
> - Το λογισμικό έχει δικαιώματα (hardened runtime) χωρίς δικαίωμα [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>   - Ελέγξτε τα **δικαιώματα** ενός δυαδικού αρχείου με: `codesign -dv --entitlements :- </path/to/bin>`
>
> Σε πιο ενημερωμένες εκδόσεις μπορείτε να βρείτε αυτή τη λογική στο δεύτερο μέρος της συνάρτησης **`configureProcessRestrictions`.** Ωστόσο, αυτό που εκτελείται σε νεότερες εκδόσεις είναι οι **έλεγχοι αρχής της συνάρτησης** (μπορείτε να αφαιρέσετε τα ifs που σχετίζονται με το iOS ή την προσομοίωση καθώς αυτά δεν θα χρησιμοποιηθούν στο macOS.

### Library Validation

Ακόμα και αν το δυαδικό αρχείο επιτρέπει τη χρήση της μεταβλητής περιβάλλοντος **`DYLD_INSERT_LIBRARIES`**, αν το δυαδικό αρχείο ελέγχει την υπογραφή της βιβλιοθήκης για να τη φορτώσει, δεν θα φορτώσει μια προσαρμοσμένη.

Για να φορτωθεί μια προσαρμοσμένη βιβλιοθήκη, το δυαδικό αρχείο πρέπει να έχει **ένα από τα παρακάτω δικαιώματα**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ή το δυαδικό αρχείο **δεν θα πρέπει** να έχει τη **σημαία hardened runtime** ή τη **σημαία validation βιβλιοθήκης**.

Μπορείτε να ελέγξετε αν ένα δυαδικό αρχείο έχει **hardened runtime** με `codesign --display --verbose <bin>` ελέγχοντας τη σημαία runtime στο **`CodeDirectory`** όπως: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Μπορείτε επίσης να φορτώσετε μια βιβλιοθήκη αν είναι **υπογεγραμμένη με το ίδιο πιστοποιητικό όπως το δυαδικό αρχείο**.

Βρείτε ένα παράδειγμα για το πώς να (κατα)χρησιμοποιήσετε αυτό και ελέγξτε τους περιορισμούς στο:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Θυμηθείτε ότι **οι προηγούμενοι περιορισμοί Validation Βιβλιοθήκης ισχύουν επίσης** για την εκτέλεση επιθέσεων Dylib hijacking.

Όπως στα Windows, στο MacOS μπορείτε επίσης να **καταχραστείτε dylibs** για να κάνετε **εφαρμογές** **να εκτελούν** **τυχαίο** **κώδικα** (καλά, στην πραγματικότητα από έναν κανονικό χρήστη αυτό δεν θα ήταν δυνατό καθώς μπορεί να χρειαστείτε άδεια TCC για να γράψετε μέσα σε ένα `.app` bundle και να καταχραστείτε μια βιβλιοθήκη).\
Ωστόσο, ο τρόπος που οι εφαρμογές **MacOS** **φορτώνουν** βιβλιοθήκες είναι **πιο περιορισμένος** από ότι στα Windows. Αυτό σημαίνει ότι οι προγραμματιστές **malware** μπορούν ακόμα να χρησιμοποιήσουν αυτή την τεχνική για **stealth**, αλλά η πιθανότητα να μπορέσουν να **καταχραστούν αυτό για να κλιμακώσουν δικαιώματα είναι πολύ χαμηλότερη**.

Πρώτα απ' όλα, είναι **πιο συνηθισμένο** να βρείτε ότι τα **MacOS δυαδικά αρχεία υποδεικνύουν την πλήρη διαδρομή** στις βιβλιοθήκες που πρέπει να φορτωθούν. Και δεύτερον, **MacOS ποτέ δεν ψάχνει** στους φακέλους του **$PATH** για βιβλιοθήκες.

Το **κύριο** μέρος του **κώδικα** που σχετίζεται με αυτή τη λειτουργικότητα είναι στη **`ImageLoader::recursiveLoadLibraries`** στο `ImageLoader.cpp`.

Υπάρχουν **4 διαφορετικές εντολές Header** που μπορεί να χρησιμοποιήσει ένα macho δυαδικό αρχείο για να φορτώσει βιβλιοθήκες:

- Η εντολή **`LC_LOAD_DYLIB`** είναι η κοινή εντολή για να φορτώσετε μια dylib.
- Η εντολή **`LC_LOAD_WEAK_DYLIB`** λειτουργεί όπως η προηγούμενη, αλλά αν η dylib δεν βρεθεί, η εκτέλεση συνεχίζεται χωρίς κανένα σφάλμα.
- Η εντολή **`LC_REEXPORT_DYLIB`** προξενεί (ή επανεξάγει) τα σύμβολα από μια διαφορετική βιβλιοθήκη.
- Η εντολή **`LC_LOAD_UPWARD_DYLIB`** χρησιμοποιείται όταν δύο βιβλιοθήκες εξαρτώνται η μία από την άλλη (αυτό ονομάζεται _upward dependency_).

Ωστόσο, υπάρχουν **2 τύποι dylib hijacking**:

- **Απουσία αδύναμων συνδεδεμένων βιβλιοθηκών**: Αυτό σημαίνει ότι η εφαρμογή θα προσπαθήσει να φορτώσει μια βιβλιοθήκη που δεν υπάρχει ρυθμισμένη με **LC_LOAD_WEAK_DYLIB**. Στη συνέχεια, **αν ένας επιτιθέμενος τοποθετήσει μια dylib όπου αναμένεται να φορτωθεί**.
- Το γεγονός ότι ο σύνδεσμος είναι "αδύναμος" σημαίνει ότι η εφαρμογή θα συνεχίσει να εκτελείται ακόμα και αν η βιβλιοθήκη δεν βρεθεί.
- Ο **κώδικας που σχετίζεται** με αυτό είναι στη συνάρτηση `ImageLoaderMachO::doGetDependentLibraries` του `ImageLoaderMachO.cpp` όπου `lib->required` είναι μόνο `false` όταν `LC_LOAD_WEAK_DYLIB` είναι true.
- **Βρείτε αδύναμες συνδεδεμένες βιβλιοθήκες** σε δυαδικά αρχεία με (έχετε αργότερα ένα παράδειγμα για το πώς να δημιουργήσετε βιβλιοθήκες hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Ρυθμισμένο με @rpath**: Τα Mach-O δυαδικά αρχεία μπορούν να έχουν τις εντολές **`LC_RPATH`** και **`LC_LOAD_DYLIB`**. Βασισμένο στις **τιμές** αυτών των εντολών, οι **βιβλιοθήκες** θα φορτωθούν από **διαφορετικούς φακέλους**.
- Η **`LC_RPATH`** περιέχει τις διαδρομές ορισμένων φακέλων που χρησιμοποιούνται για να φορτώσουν βιβλιοθήκες από το δυαδικό αρχείο.
- Η **`LC_LOAD_DYLIB`** περιέχει τη διαδρομή προς συγκεκριμένες βιβλιοθήκες που πρέπει να φορτωθούν. Αυτές οι διαδρομές μπορεί να περιέχουν **`@rpath`**, το οποίο θα **αντικατασταθεί** από τις τιμές στη **`LC_RPATH`**. Αν υπάρχουν πολλές διαδρομές στη **`LC_RPATH`**, όλες θα χρησιμοποιηθούν για να αναζητήσουν τη βιβλιοθήκη προς φόρτωση. Παράδειγμα:
- Αν η **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και η **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`. Και οι δύο φάκελοι θα χρησιμοποιηθούν για να φορτώσουν `library.dylib`**.** Αν η βιβλιοθήκη δεν υπάρχει στο `[...]/v1/` και ο επιτιθέμενος μπορούσε να την τοποθετήσει εκεί για να καταχραστεί τη φόρτωση της βιβλιοθήκης στο `[...]/v2/` καθώς η σειρά των διαδρομών στη **`LC_LOAD_DYLIB`** ακολουθείται.
- **Βρείτε διαδρομές rpath και βιβλιοθήκες** σε δυαδικά αρχεία με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Είναι η **διαδρομή** προς το φάκελο που περιέχει το **κύριο εκτελέσιμο αρχείο**.
>
> **`@loader_path`**: Είναι η **διαδρομή** προς το **φάκελο** που περιέχει το **Mach-O δυαδικό αρχείο** το οποίο περιέχει την εντολή φόρτωσης.
>
> - Όταν χρησιμοποιείται σε ένα εκτελέσιμο, **`@loader_path`** είναι ουσιαστικά το **ίδιο** με το **`@executable_path`**.
> - Όταν χρησιμοποιείται σε μια **dylib**, **`@loader_path`** δίνει τη **διαδρομή** προς τη **dylib**.

Ο τρόπος για να **κλιμακώσετε δικαιώματα** καταχρώντας αυτή τη λειτουργικότητα θα ήταν στην σπάνια περίπτωση που μια **εφαρμογή** που εκτελείται **από** **root** **ψάχνει** για κάποια **βιβλιοθήκη σε κάποιο φάκελο όπου ο επιτιθέμενος έχει δικαιώματα εγγραφής.**

> [!TIP]
> Ένας ωραίος **σάρωτης** για να βρείτε **ελλείπουσες βιβλιοθήκες** σε εφαρμογές είναι [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**CLI έκδοση**](https://github.com/pandazheng/DylibHijack).\
> Ένας ωραίος **αναφορά με τεχνικές λεπτομέρειες** σχετικά με αυτή την τεχνική μπορεί να βρεθεί [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Θυμηθείτε ότι **οι προηγούμενοι περιορισμοί Validation Βιβλιοθήκης ισχύουν επίσης** για την εκτέλεση επιθέσεων Dlopen hijacking.

Από **`man dlopen`**:

- Όταν η διαδρομή **δεν περιέχει χαρακτήρα slash** (δηλαδή είναι απλώς ένα όνομα φύλλου), **dlopen() θα κάνει αναζητήσεις**. Αν **`$DYLD_LIBRARY_PATH`** έχει ρυθμιστεί κατά την εκκίνηση, το dyld θα κοιτάξει πρώτα **σε αυτή τη διεύθυνση**. Στη συνέχεια, αν το καλούν macho αρχείο ή το κύριο εκτελέσιμο καθορίζει μια **`LC_RPATH`**, τότε το dyld θα **κοιτάξει σε αυτούς τους** φακέλους. Στη συνέχεια, αν η διαδικασία είναι **χωρίς περιορισμούς**, το dyld θα αναζητήσει στον **τρέχοντα φάκελο εργασίας**. Τέλος, για παλιά δυαδικά αρχεία, το dyld θα δοκιμάσει κάποιες εναλλακτικές. Αν **`$DYLD_FALLBACK_LIBRARY_PATH`** έχει ρυθμιστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους φακέλους**, αλλιώς, το dyld θα κοιτάξει στο **`/usr/local/lib/`** (αν η διαδικασία είναι χωρίς περιορισμούς), και στη συνέχεια στο **`/usr/lib/`** (αυτή η πληροφορία ελήφθη από **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(αν είναι χωρίς περιορισμούς)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (αν είναι χωρίς περιορισμούς)
6. `/usr/lib/`

> [!CAUTION]
> Αν δεν υπάρχουν slashes στο όνομα, θα υπάρχουν 2 τρόποι για να γίνει μια καταχρηστική:
>
> - Αν οποιαδήποτε **`LC_RPATH`** είναι **γραπτή** (αλλά η υπογραφή ελέγχεται, οπότε για αυτό χρειάζεστε επίσης το δυαδικό αρχείο να είναι χωρίς περιορισμούς)
> - Αν το δυαδικό αρχείο είναι **χωρίς περιορισμούς** και στη συνέχεια είναι δυνατό να φορτωθεί κάτι από το CWD (ή καταχρώντας μία από τις αναφερόμενες μεταβλητές περιβάλλοντος)

- Όταν η διαδρομή **φαίνεται να είναι διαδρομή framework** (π.χ. `/stuff/foo.framework/foo`), αν **`$DYLD_FRAMEWORK_PATH`** έχει ρυθμιστεί κατά την εκκίνηση, το dyld θα κοιτάξει πρώτα σε αυτή τη διεύθυνση για τη **μερική διαδρομή του framework** (π.χ. `foo.framework/foo`). Στη συνέχεια, το dyld θα δοκιμάσει τη **παρεχόμενη διαδρομή όπως είναι** (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας για σχετικές διαδρομές). Τέλος, για παλιά δυαδικά αρχεία, το dyld θα δοκιμάσει κάποιες εναλλακτικές. Αν **`$DYLD_FALLBACK_FRAMEWORK_PATH`** έχει ρυθμιστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους φακέλους. Διαφορετικά, θα αναζητήσει στο **`/Library/Frameworks`** (στο macOS αν η διαδικασία είναι χωρίς περιορισμούς), στη συνέχεια **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. παρεχόμενη διαδρομή (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας για σχετικές διαδρομές αν είναι χωρίς περιορισμούς)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (αν είναι χωρίς περιορισμούς)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Αν είναι διαδρομή framework, ο τρόπος για να την καταχραστείτε θα ήταν:
>
> - Αν η διαδικασία είναι **χωρίς περιορισμούς**, καταχρώντας τη **σχετική διαδρομή από το CWD** τις αναφερόμενες μεταβλητές περιβάλλοντος (ακόμα και αν δεν αναφέρεται στα έγγραφα αν η διαδικασία είναι περιορισμένη οι μεταβλητές DYLD\_\* αφαιρούνται)

- Όταν η διαδρομή **περιέχει slash αλλά δεν είναι διαδρομή framework** (δηλαδή μια πλήρη διαδρομή ή μια μερική διαδρομή προς μια dylib), το dlopen() πρώτα κοιτάζει (αν έχει ρυθμιστεί) στο **`$DYLD_LIBRARY_PATH`** (με το φύλλο μέρους από τη διαδρομή). Στη συνέχεια, το dyld **δοκιμάζει τη παρεχόμενη διαδρομή** (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας για σχετικές διαδρομές (αλλά μόνο για διαδικασίες χωρίς περιορισμούς)). Τέλος, για παλαιότερα δυαδικά αρχεία, το dyld θα δοκιμάσει εναλλακτικές. Αν **`$DYLD_FALLBACK_LIBRARY_PATH`** έχει ρυθμιστεί κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους φακέλους, αλλιώς, το dyld θα κοιτάξει στο **`/usr/local/lib/`** (αν η διαδικασία είναι χωρίς περιορισμούς), και στη συνέχεια στο **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. παρεχόμενη διαδρομή (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας για σχετικές διαδρομές αν είναι χωρίς περιορισμούς)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (αν είναι χωρίς περιορισμούς)
5. `/usr/lib/`

> [!CAUTION]
> Αν υπάρχουν slashes στο όνομα και δεν είναι framework, ο τρόπος για να το καταχραστείτε θα ήταν:
>
> - Αν το δυαδικό αρχείο είναι **χωρίς περιορισμούς** και στη συνέχεια είναι δυνατό να φορτωθεί κάτι από το CWD ή `/usr/local/lib` (ή καταχρώντας μία από τις αναφερόμενες μεταβλητές περιβάλλοντος)

> [!NOTE]
> Σημείωση: Δεν υπάρχουν **αρχεία ρυθμίσεων** για **έλεγχο της αναζήτησης dlopen**.
>
> Σημείωση: Αν το κύριο εκτελέσιμο είναι ένα **set\[ug]id δυαδικό αρχείο ή υπογεγραμμένο με δικαιώματα**, τότε **όλες οι μεταβλητές περιβάλλοντος αγνοούνται**, και μπορεί να χρησιμοποιηθεί μόνο μια πλήρης διαδρομή ([ελέγξτε τους περιορισμούς DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) για περισσότερες λεπτομέρειες)
>
> Σημείωση: Οι πλατφόρμες της Apple χρησιμοποιούν "καθολικά" αρχεία για να συνδυάσουν 32-bit και 64-bit βιβλιοθήκες. Αυτό σημαίνει ότι δεν υπάρχουν **χωριστές διαδρομές αναζήτησης 32-bit και 64-bit**.
>
> Σημείωση: Σε πλατφόρμες της Apple οι περισσότερες OS dylibs είναι **συνδυασμένες στο dyld cache** και δεν υπάρχουν στο δίσκο. Επομένως, η κλήση **`stat()`** για να ελέγξετε αν μια OS dylib υπάρχει **δεν θα λειτουργήσει**. Ωστόσο, **`dlopen_preflight()`** χρησιμοποιεί τα ίδια βήματα με το **`dlopen()`** για να βρει ένα συμβατό mach-o αρχείο.

**Check paths**

Ας ελέγξουμε όλες τις επιλογές με τον παρακάτω κώδικα:
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
Αν το μεταγλωττίσετε και το εκτελέσετε, μπορείτε να δείτε **πού αναζητήθηκε κάθε βιβλιοθήκη χωρίς επιτυχία**. Επίσης, θα μπορούσατε να **φιλτράρετε τα αρχεία καταγραφής FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Αν ένα **privileged binary/app** (όπως ένα SUID ή κάποιο binary με ισχυρά δικαιώματα) **φορτώνει μια βιβλιοθήκη σχετικής διαδρομής** (για παράδειγμα χρησιμοποιώντας `@executable_path` ή `@loader_path`) και έχει **απενεργοποιημένη την Επικύρωση Βιβλιοθήκης**, θα μπορούσε να είναι δυνατό να μετακινήσετε το binary σε μια τοποθεσία όπου ο επιτιθέμενος θα μπορούσε να **τροποποιήσει τη βιβλιοθήκη που φορτώνεται με σχετική διαδρομή**, και να την εκμεταλλευτεί για να εισάγει κώδικα στη διαδικασία.

## Prune `DYLD_*` and `LD_LIBRARY_PATH` env variables

Στο αρχείο `dyld-dyld-832.7.1/src/dyld2.cpp` είναι δυνατό να βρείτε τη συνάρτηση **`pruneEnvironmentVariables`**, η οποία θα αφαιρέσει οποιαδήποτε env μεταβλητή που **ξεκινά με `DYLD_`** και **`LD_LIBRARY_PATH=`**.

Θα ορίσει επίσης σε **null** συγκεκριμένα τις env μεταβλητές **`DYLD_FALLBACK_FRAMEWORK_PATH`** και **`DYLD_FALLBACK_LIBRARY_PATH`** για **suid** και **sgid** binaries.

Αυτή η συνάρτηση καλείται από τη **`_main`** συνάρτηση του ίδιου αρχείου αν στοχεύει το OSX με αυτόν τον τρόπο:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
και αυτές οι λογικές σημαίες ορίζονται στο ίδιο αρχείο στον κώδικα:
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
Το οποίο σημαίνει ότι αν το δυαδικό αρχείο είναι **suid** ή **sgid**, ή έχει ένα τμήμα **RESTRICT** στις κεφαλίδες ή έχει υπογραφεί με την ένδειξη **CS_RESTRICT**, τότε **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** είναι αληθές και οι μεταβλητές περιβάλλοντος αποκόπτονται.

Σημειώστε ότι αν το CS_REQUIRE_LV είναι αληθές, τότε οι μεταβλητές δεν θα αποκοπούν αλλά η επικύρωση της βιβλιοθήκης θα ελέγξει ότι χρησιμοποιούν το ίδιο πιστοποιητικό με το αρχικό δυαδικό αρχείο.

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
### Τμήμα `__RESTRICT` με τμήμα `__restrict`
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
> Σημειώστε ότι ακόμη και αν υπάρχουν δυαδικά αρχεία υπογεγραμμένα με σημαίες **`0x0(none)`**, μπορούν να αποκτήσουν τη σημαία **`CS_RESTRICT`** δυναμικά κατά την εκτέλεση και επομένως αυτή η τεχνική δεν θα λειτουργήσει σε αυτά.
>
> Μπορείτε να ελέγξετε αν μια διαδικασία έχει αυτή τη σημαία με (get [**csops εδώ**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> και στη συνέχεια να ελέγξετε αν η σημαία 0x800 είναι ενεργοποιημένη.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
