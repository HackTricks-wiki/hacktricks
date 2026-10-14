# macOS Apps - Επιθεώρηση, αποσφαλμάτωση και Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Στατική ανάλυση

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (παλιό jtool2)

Μπορείτε να [**κατεβάσετε το disarm από εδώ**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Σημειώστε ότι το **`disarm`** μπορεί να λειτουργήσει και με συμπιεσμένα αρχεία IM4P (όπως το `kernelcache`) και να εξαγάγει μόνο τα απαιτούμενα τμήματα ή ακόμη και να αναλύσει το απαιτούμενο τμήμα χωρίς να το εξαγάγει.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> Το **`Codesign`** μπορεί να βρεθεί στο **macOS**, ενώ το **`ldid`** μπορεί να βρεθεί στο **iOS**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

Το [**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) είναι ένα χρήσιμο εργαλείο για την επιθεώρηση αρχείων **.pkg** (installers) και τον έλεγχο των περιεχομένων τους πριν από την εγκατάστασή τους.\
Αυτοί οι installers περιέχουν bash scripts `preinstall` και `postinstall`, τα οποία οι δημιουργοί malware συνήθως καταχρώνται για να **persist** **το** **malware**.

### hdiutil

Αυτό το εργαλείο κάνει **mount** αρχεία Apple disk image (`.dmg`), ώστε να μπορούν να επιθεωρηθούν πριν εκτελεστεί οτιδήποτε:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Θα προσαρτηθεί στο `/Volumes`

### Συμπιεσμένα δυαδικά αρχεία

- Ελέγξτε αν έχει υψηλή εντροπία
- Ελέγξτε τα strings (αν υπάρχουν σχεδόν καθόλου κατανοητά strings, είναι συμπιεσμένο)
- Ο packer UPX για macOS δημιουργεί ένα section με το όνομα `__XHDR`.

## Στατική ανάλυση Objective-C

### Μεταδεδομένα

> [!CAUTION]
> Σημειώστε ότι τα προγράμματα που είναι γραμμένα σε Objective-C **διατηρούν** τις δηλώσεις των κλάσεών τους **όταν** **μεταγλωττίζονται** σε [δυαδικά αρχεία Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Τέτοιες δηλώσεις κλάσεων **περιλαμβάνουν** το όνομα και τον τύπο των εξής:

- Των interfaces που έχουν οριστεί
- Των μεθόδων των interfaces
- Των μεταβλητών στιγμιοτύπου των interfaces
- Των πρωτοκόλλων που έχουν οριστεί

Σημειώστε ότι αυτά τα ονόματα μπορεί να είναι obfuscated, ώστε να δυσκολέψει το reverse engineering του δυαδικού αρχείου.

### Κλήση συναρτήσεων

Όταν καλείται μια συνάρτηση σε ένα δυαδικό αρχείο που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας, αντί να καλέσει τη συνάρτηση, θα καλέσει την **`objc_msgSend`**. Αυτή θα καλέσει την τελική συνάρτηση:

![Μεταδεδομένα - Κλήση συναρτήσεων: Όταν καλείται μια συνάρτηση σε ένα δυαδικό αρχείο που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας, αντί να καλέσει τη συνάρτηση, θα καλέσει την objc_msgSend. Αυτή θα...](<../../../images/image (305).png>)

Οι παράμετροι που αναμένει αυτή η συνάρτηση είναι:

- Η πρώτη παράμετρος (**self**) είναι «ένας δείκτης που δείχνει στο **στιγμιότυπο της κλάσης που θα λάβει το μήνυμα**». Με απλά λόγια, είναι το αντικείμενο στο οποίο καλείται η μέθοδος. Αν η μέθοδος είναι μέθοδος κλάσης, αυτή θα είναι ένα στιγμιότυπο του αντικειμένου-κλάσης (ως σύνολο), ενώ για μια μέθοδο στιγμιοτύπου, το self θα δείχνει σε ένα στιγμιότυπο της κλάσης που έχει δημιουργηθεί ως αντικείμενο.
- Η δεύτερη παράμετρος (**op**) είναι «ο selector της μεθόδου που χειρίζεται το μήνυμα». Με απλά λόγια, είναι απλώς το **όνομα της μεθόδου.**
- Οι υπόλοιπες παράμετροι είναι οι **τιμές που απαιτούνται από τη μέθοδο** (op).

Δείτε πώς μπορείτε να **λάβετε εύκολα αυτές τις πληροφορίες με το `lldb` σε ARM64** σε αυτή τη σελίδα:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Όρισμα**       | **Καταχωρητής**                                                | **(για) objc_msgSend**                                      |
| ---------------- | -------------------------------------------------------------- | ----------------------------------------------------------- |
| **1ο όρισμα**    | **rdi**                                                        | **self: αντικείμενο στο οποίο καλείται η μέθοδος**          |
| **2ο όρισμα**    | **rsi**                                                        | **op: όνομα της μεθόδου**                                   |
| **3ο όρισμα**    | **rdx**                                                        | **1ο όρισμα της μεθόδου**                                   |
| **4ο όρισμα**    | **rcx**                                                        | **2ο όρισμα της μεθόδου**                                   |
| **5ο όρισμα**    | **r8**                                                         | **3ο όρισμα της μεθόδου**                                   |
| **6ο όρισμα**    | **r9**                                                         | **4ο όρισμα της μεθόδου**                                   |
| **7ο+ όρισμα**   | <p><strong>rsp+</strong><br><strong>(στη στοίβα)</strong></p> | **5ο+ όρισμα της μεθόδου**                                  |

### Εξαγωγή μεταδεδομένων Objective-C

### Dynadump

Το [**Dynadump**](https://github.com/DerekSelander/dynadump) είναι ένα εργαλείο για class-dump δυαδικών αρχείων Objective-C. Το GitHub αναφέρει ότι χρησιμοποιείται με dylibs, αλλά λειτουργεί και με executables.

```bash
./dynadump dump /path/to/bin
```

Κατά τη στιγμή της συγγραφής, αυτό είναι **αυτό που λειτουργεί καλύτερα αυτήν τη στιγμή**.

#### Κανονικά εργαλεία

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

Το [**class-dump**](https://github.com/nygard/class-dump/) είναι το αρχικό εργαλείο για τη δημιουργία δηλώσεων για τις κλάσεις, τις κατηγορίες και τα πρωτόκολλα σε μορφοποιημένο κώδικα ObjectiveC.

Είναι παλιό και δεν συντηρείται, επομένως πιθανότατα δεν θα λειτουργεί σωστά.

#### ICDump

Το [**iCDump**](https://github.com/romainthomas/iCDump) είναι ένα σύγχρονο και cross-platform εργαλείο για Objective-C class dump. Σε σύγκριση με τα υπάρχοντα εργαλεία, το iCDump μπορεί να εκτελείται ανεξάρτητα από το οικοσύστημα της Apple και παρέχει Python bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Στατική ανάλυση Swift

Με τα δυαδικά αρχεία Swift, λόγω της συμβατότητας με το Objective-C, μερικές φορές μπορείτε να εξαγάγετε δηλώσεις χρησιμοποιώντας το [class-dump](https://github.com/nygard/class-dump/), αλλά όχι πάντα.

Με τις γραμμές εντολών **`jtool -l`** ή **`otool -l`** μπορείτε να εντοπίσετε διάφορες ενότητες που ξεκινούν με το πρόθεμα **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Μπορείτε να βρείτε περισσότερες πληροφορίες σχετικά με τις [**πληροφορίες που αποθηκεύονται σε αυτές τις ενότητες σε αυτήν την ανάρτηση ιστολογίου**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Επιπλέον, **τα Swift binaries μπορεί να περιέχουν symbols** (για παράδειγμα, οι βιβλιοθήκες πρέπει να αποθηκεύουν symbols ώστε να μπορούν να καλούνται οι συναρτήσεις τους). Τα **symbols συνήθως περιέχουν πληροφορίες για το όνομα και τα χαρακτηριστικά της συνάρτησης με άσχημο τρόπο**, επομένως είναι πολύ χρήσιμα και υπάρχουν «**demanglers**» που μπορούν να ανακτήσουν το αρχικό όνομα:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Δυναμική ανάλυση

> [!WARNING]
> **Μην απενεργοποιείτε το SIP ως προεπιλεγμένο βήμα για debugging.** Τα development builds με `com.apple.security.get-task-allow` μπορούν να γίνουν debug με ενεργοποιημένο SIP. Ελέγξτε τον στόχο με `codesign -d --entitlements :- /path/to/binary` προτού δοκιμάσετε το LLDB. Ένα debugger entitlement από μόνο του δεν παρέχει πρόσβαση σε στόχους που προστατεύονται από το SIP.<sup>[[15]](#references)</sup>
>
> Μια διανεμόμενη εφαρμογή με hardened runtime συνήθως παραλείπει το `get-task-allow` και αποκλείει την προσάρτηση. Αν είναι δυνατόν, χρησιμοποιήστε debug build που παρέχεται από τον developer· η εκ νέου υπογραφή ενός προσωρινού αντιγράφου μπορεί να αλλάξει τη συμπεριφορά που εξετάζετε. Αν ένας προστατευμένος στόχος απαιτεί απενεργοποίηση του SIP, χρησιμοποιήστε αποκλειστικό μηχάνημα δοκιμών ή VM, αντί για μηχάνημα στο οποίο βασίζεστε.<sup>[[16]](#references)</sup>
>
> Παλαιότερες οδηγίες για προστατευμένο στόχο σε απομονωμένο περιβάλλον δοκιμών ανέφεραν τις εξής εναλλακτικές:
>
> Σημειώστε ότι για να κάνετε debug binaries, πρέπει να απενεργοποιήσετε το SIP (`csrutil disable` ή `csrutil enable --without debug`) ή να αντιγράψετε τα binaries σε έναν προσωρινό φάκελο και να αφαιρέσετε την υπογραφή με `codesign --remove-signature <binary-path>` ή να επιτρέψετε το debugging του binary (μπορείτε να χρησιμοποιήσετε [αυτό το script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Αυτό δεν αποτελεί γενική απαίτηση του SIP: προτιμήστε ένα debug build και λάβετε υπόψη ότι η αντιγραφή ή η αλλαγή μιας υπογραφής μπορεί να μεταβάλει τη συμπεριφορά που εξετάζετε.

> [!WARNING]
> Σημειώστε ότι για να κάνετε **instrumentation σε system binaries** (όπως το `cloudconfigurationd`) στο macOS, **πρέπει να απενεργοποιήσετε το SIP** (η απλή αφαίρεση της υπογραφής δεν αρκεί).

### APIs

Το macOS παρέχει ορισμένα ενδιαφέροντα APIs που δίνουν πληροφορίες για τις διεργασίες:

- `proc_info`: Το κύριο API, που παρέχει πολλές πληροφορίες για κάθε διεργασία. Χρειάζεστε δικαιώματα root για να λάβετε πληροφορίες για άλλες διεργασίες, αλλά δεν χρειάζεστε ειδικά entitlements ή mach ports.
- `libsysmon.dylib`: Παρέχει πληροφορίες διεργασιών μέσω συναρτήσεων XPC, αλλά οι callers χρειάζονται το entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

Το **stackshotting** είναι μια τεχνική για την καταγραφή της κατάστασης των διεργασιών, συμπεριλαμβανομένων των call stacks όλων των ενεργών threads. Είναι ιδιαίτερα χρήσιμη για debugging, ανάλυση επιδόσεων και κατανόηση της συμπεριφοράς του συστήματος σε μια συγκεκριμένη χρονική στιγμή. Σε iOS και macOS, το stackshotting μπορεί να γίνει με διάφορα εργαλεία και μεθόδους, όπως τα **`sample`** και **`spindump`**.

### Sysdiagnose

Αυτό το εργαλείο (`/usr/bini/ysdiagnose`) συλλέγει πολλές πληροφορίες από τον υπολογιστή σας εκτελώντας δεκάδες διαφορετικές εντολές, όπως `ps`, `zprint`...

Πρέπει να εκτελείται ως **root**, ενώ το daemon `/usr/libexec/sysdiagnosed` διαθέτει πολύ ενδιαφέροντα entitlements, όπως τα `com.apple.system-task-ports` και `get-task-allow`.

Το plist του βρίσκεται στη διαδρομή `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` και δηλώνει 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Διαγράφει παλιά αρχεία από το /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Ειδικό port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Διεπαφή user mode μέσω της κλάσης Obj-C `Libsysdiagnose`. Μπορούν να περαστούν τρία ορίσματα σε ένα dict (`compress`, `display`, `run`)

### Unified Logs

Το macOS δημιουργεί εκτενή logs, χρήσιμα για την ανάλυση της συμπεριφοράς μιας εφαρμογής.

Ορισμένα πεδία των logs περιέχουν την ετικέτα `<private>` για να αποκρύπτουν πληροφορίες που ταυτοποιούν τον χρήστη ή τη συσκευή. Παλαιότερες οδηγίες περιγράφουν μερικές φορές την εγκατάσταση πιστοποιητικού για την αποκάλυψη αυτών των πεδίων· οι τρέχουσες οδηγίες για debugging χρησιμοποιούν αντίθετα ένα configuration profile με σαφώς ορισμένο πεδίο εφαρμογής και `Enable-Private-Data`, ή `OSLogPreferences` ανά εφαρμογή. Η συμπεριφορά μπορεί να διαφέρει ανά subsystem και έκδοση macOS. Η παλαιότερη συζήτηση για πιστοποιητικά/profile διατηρείται στις αναφορές. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Αριστερό panel

Στο αριστερό panel του Hopper μπορείτε να δείτε τα σύμβολα (**Labels**) του binary, τη λίστα των procedures και functions (**Proc**) και τα strings (**Str**). Αυτά δεν είναι όλα τα strings, αλλά όσα έχουν οριστεί σε διάφορα τμήματα του αρχείου Mac-O (όπως τα _cstring ή `objc_methname`).

#### Μεσαίο panel

Στο μεσαίο panel μπορείτε να δείτε τον **disassembled κώδικα**. Μπορείτε να δείτε το disassembly σε **raw** μορφή, ως **graph**, ως **decompiled** κώδικα και ως **binary**, κάνοντας κλικ στο αντίστοιχο εικονίδιο:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Κάνοντας δεξί κλικ σε ένα code object, μπορείτε να δείτε **references προς/από αυτό το object** ή ακόμη και να αλλάξετε το όνομά του (αυτό δεν λειτουργεί σε decompiled pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Επιπλέον, **στο κάτω μέρος του μεσαίου panel μπορείτε να γράψετε εντολές Python**.

#### Δεξί panel

Στο δεξί panel μπορείτε να δείτε ενδιαφέρουσες πληροφορίες, όπως το **navigation history** (ώστε να γνωρίζετε πώς φτάσατε στην τρέχουσα κατάσταση), το **call graph**, όπου μπορείτε να δείτε όλες τις **functions που καλούν αυτή τη function** και όλες τις functions που **καλεί αυτή η function**, καθώς και πληροφορίες για τις **local variables**.

### dtrace

Παρέχει στους χρήστες πρόσβαση σε εφαρμογές σε εξαιρετικά **χαμηλό επίπεδο** και έναν τρόπο να κάνουν **trace** σε **programs** και ακόμη και να αλλάζουν τη ροή εκτέλεσής τους. Το DTrace χρησιμοποιεί **probes** που **τοποθετούνται σε όλο τον kernel** και βρίσκονται σε σημεία όπως η αρχή και το τέλος των system calls.

Το DTrace χρησιμοποιεί τη συνάρτηση **`dtrace_probe_create`** για να δημιουργήσει ένα probe για κάθε system call. Αυτά τα probes μπορούν να ενεργοποιηθούν στο **σημείο εισόδου και εξόδου κάθε system call**. Η επικοινωνία με το DTrace γίνεται μέσω του /dev/dtrace, το οποίο είναι διαθέσιμο μόνο στον χρήστη root.<sup>[[1]](#references)</sup>

> [!TIP]
> Για να ενεργοποιήσετε το DTrace χωρίς να απενεργοποιήσετε πλήρως την προστασία SIP, μπορείτε να εκτελέσετε σε recovery mode: `csrutil enable --without dtrace`
>
> Μπορείτε επίσης να χρησιμοποιήσετε **`dtrace`** ή **`dtruss`** σε binaries που **έχετε κάνει compile**.

Τα διαθέσιμα probes του dtrace μπορούν να εμφανιστούν με:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Το όνομα του probe αποτελείται από τέσσερα μέρη: τον provider, το module, τη function και το όνομα (`fbt:mach_kernel:ptrace:entry`). Αν δεν καθορίσετε κάποιο μέρος του ονόματος, το DTrace θα το χρησιμοποιήσει ως wildcard.

Για να ρυθμίσουμε το DTrace ώστε να ενεργοποιεί probes και να καθορίσουμε ποιες ενέργειες θα εκτελούνται όταν ενεργοποιούνται, θα χρειαστεί να χρησιμοποιήσουμε τη γλώσσα D.

Μπορείτε να βρείτε μια πιο λεπτομερή εξήγηση και περισσότερα παραδείγματα στη διεύθυνση [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Παραδείγματα

Εκτελέστε `man -k dtrace` για να εμφανίσετε τα **διαθέσιμα scripts του DTrace**. Παράδειγμα: `sudo dtruss -n binary`

- Σε γραμμή

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

Είναι μια δυνατότητα ανίχνευσης του kernel. Οι τεκμηριωμένοι κωδικοί βρίσκονται στο **`/usr/share/misc/trace.codes`**.

Εργαλεία όπως τα `latency`, `sc_usage`, `fs_usage` και `trace` τη χρησιμοποιούν εσωτερικά.

Για τη διασύνδεση με το `kdebug`, χρησιμοποιείται το `sysctl` μέσω του namespace `kern.kdebug`. Τα MIB που πρέπει να χρησιμοποιηθούν βρίσκονται στο `sys/sysctl.h`, ενώ οι συναρτήσεις υλοποιούνται στο `bsd/kern/kdebug.c`.

Για την αλληλεπίδραση με το kdebug μέσω ενός προσαρμοσμένου client, συνήθως ακολουθούνται τα εξής βήματα:

- Αφαίρεση των υφιστάμενων ρυθμίσεων με το KERN_KDSETREMOVE
- Ρύθμιση του trace με τα KERN_KDSETBUF και KERN_KDSETUP
- Χρήση του KERN_KDGETBUF για την εύρεση του αριθμού των καταχωρίσεων buffer
- Αφαίρεση του client από το trace με το KERN_KDPINDEX
- Ενεργοποίηση του tracing με το KERN_KDENABLE
- Ανάγνωση του buffer με κλήση του KERN_KDREADTR
- Αντιστοίχιση κάθε thread με τη διεργασία του μέσω κλήσης του KERN_KDTHRMAP.

Για να λάβετε αυτές τις πληροφορίες, μπορείτε να χρησιμοποιήσετε το εργαλείο της Apple **`trace`** ή το προσαρμοσμένο εργαλείο [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Σημειώστε ότι το Kdebug είναι διαθέσιμο μόνο σε έναν χρήστη κάθε φορά.** Επομένως, μπορεί να εκτελείται μόνο ένα εργαλείο που χρησιμοποιεί k-debug κάθε φορά.

### ktrace

Τα API `ktrace_*` προέρχονται από το `libktrace.dylib`, το οποίο περιβάλλει τα API του `Kdebug`. Έπειτα, ένας client μπορεί απλώς να καλέσει τις `ktrace_session_create` και `ktrace_events_[single/class]` για να ορίσει callbacks σε συγκεκριμένους κωδικούς και στη συνέχεια να ξεκινήσει το tracing με την `ktrace_start`.

Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο ακόμη και με ενεργοποιημένο το **SIP**.

Ως client μπορείτε να χρησιμοποιήσετε το βοηθητικό πρόγραμμα `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ή `tailspin`.

### kperf

Χρησιμοποιείται για profiling σε επίπεδο kernel και είναι χτισμένο με βάση τα `Kdebug` callouts.

Βασικά, ελέγχεται η global variable `kernel_debug_active` και, αν είναι ενεργοποιημένη, καλείται η `kperf_kdebug_handler` με τον κωδικό `Kdebug` και τη διεύθυνση του kernel frame που την καλεί. Αν ο κωδικός `Kdebug` ταιριάζει με έναν από τους επιλεγμένους, εκτελούνται οι «actions» που έχουν ρυθμιστεί ως bitmap (δείτε το `osfmk/kperf/action.h` για τις επιλογές).

Το Kperf διαθέτει επίσης έναν πίνακα sysctl MIB: (ως root) `sysctl kperf`. Ο σχετικός κώδικας βρίσκεται στο `osfmk/kperf/kperfbsd.c`.

Επιπλέον, ένα υποσύνολο των λειτουργιών του Kperf βρίσκεται στο `kpc`, το οποίο παρέχει πληροφορίες για τους performance counters του μηχανήματος.

### ProcessMonitor

Το [**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) είναι ένα πολύ χρήσιμο εργαλείο για να ελέγχετε τις ενέργειες που εκτελεί μια διεργασία (για παράδειγμα, να παρακολουθείτε ποιες νέες διεργασίες δημιουργεί).

### SpriteTree

Το [**SpriteTree**](https://themittenmac.com/tools/) είναι ένα εργαλείο που εμφανίζει τις σχέσεις μεταξύ διεργασιών.\
Πρέπει να παρακολουθείτε το Mac σας με μια εντολή όπως **`sudo eslogger fork exec rename create > cap.json`** (το Terminal από το οποίο εκτελείται χρειάζεται FDA). Έπειτα, μπορείτε να φορτώσετε το json σε αυτό το εργαλείο για να δείτε όλες τις σχέσεις:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

Το [**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) παρακολουθεί συμβάντα αρχείων, όπως τη δημιουργία, την τροποποίηση και τη διαγραφή τους.

### Crescendo

Το [**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) είναι ένα εργαλείο GUI με εμφάνιση και λειτουργικότητα που μπορεί να αναγνωρίσουν οι χρήστες των Windows από το _Procmon_ του Microsoft Sysinternals. Αυτό το εργαλείο επιτρέπει την έναρξη και τη διακοπή της καταγραφής διαφόρων τύπων συμβάντων, το φιλτράρισμά τους ανά κατηγορία, όπως αρχεία, διεργασίες, δίκτυο κ.λπ., καθώς και την αποθήκευση των καταγεγραμμένων συμβάντων σε μορφή json.

### Apple Instruments

Το [**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) αποτελεί μέρος των εργαλείων Developer του Xcode και χρησιμοποιείται για την παρακολούθηση της απόδοσης εφαρμογών, τον εντοπισμό memory leaks και την παρακολούθηση της δραστηριότητας του συστήματος αρχείων.

![Crescendo - Apple Instruments: Το Apple Instruments αποτελεί μέρος των εργαλείων Developer του Xcode και χρησιμοποιείται για την παρακολούθηση της απόδοσης εφαρμογών, τον εντοπισμό memory leaks και την παρακολούθηση της δραστηριότητας του συστήματος αρχείων](<../../../images/image (1138).png>)

### fs_usage

Επιτρέπει την παρακολούθηση των ενεργειών που εκτελούν οι διεργασίες:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

Το [**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) είναι χρήσιμο για να δείτε τις **libraries** που χρησιμοποιεί ένα binary, τα **files** που χρησιμοποιεί και τις συνδέσεις **network**.\
Ελέγχει επίσης τις διεργασίες binary με το **virustotal** και εμφανίζει πληροφορίες για το binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Στο [**this blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) θα βρείτε ένα παράδειγμα για το πώς να κάνετε **debug ένα running daemon** που χρησιμοποιούσε το **`PT_DENY_ATTACH`** για να αποτρέψει το debugging, ακόμη και αν το SIP ήταν απενεργοποιημένο.<sup>[[6]](#references)</sup>

Το `PT_DENY_ATTACH` είναι ένα ειδικό για το Darwin αίτημα `ptrace(2)` με τιμή **31** (`0x1f`)· τα υπόλοιπα ορίσματα αγνοούνται. Μια διεργασία μπορεί να το καλέσει απευθείας, χωρίς fork, ώστε να αρνηθεί μεταγενέστερο tracing από τον γονέα της.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Κατάσταση του XNU και σειρά κλήσεων

Το αποτέλεσμα εξαρτάται από το ποιο αίτημα `ptrace` φτάνει πρώτο στο XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **Το LLDB προσαρτάται πρώτο:** Το `debugserver` χρησιμοποιεί το `PT_ATTACHEXC`· το XNU το μετατρέπει σε `PT_ATTACH`, εκτελεί έλεγχο εξουσιοδότησης `KAUTH_PROCESS_CANTRACE` και ορίζει το `P_LTRACED στη διεργασία-στόχο. Ένα επόμενο `PT_DENY_ATTACH` εντοπίζει αυτήν τη σημαία και τερματίζει τη διεργασία-στόχο με `W_EXITCODE(ENOTSUP, 0)`, το οποίο συνήθως εμφανίζεται από το LLDB ως κατάσταση **45** (`0x2d`).
- **Η διεργασία-στόχος αρνείται πρώτη:** Το XNU ορίζει το `P_LNOATTACH`. Μια μεταγενέστερη προσπάθεια προσάρτησης απορρίπτεται από τον έλεγχο εξουσιοδότησης παρακολούθησης διεργασιών· η διαδρομή σφάλματος της προσάρτησης εντοπίζει το `P_LNOATTACH` και στέλνει `SIGSEGV` στη διεργασία που επιχειρεί την προσάρτηση, κάτι που στο LLDB μπορεί να εμφανιστεί ως απώλεια σύνδεσης με το `debugserver`.

Για να διακρίνετε αυτές τις διαδρομές, ενεργοποιήστε την καταγραφή του `debugserver` πριν από την εκκίνηση ή την προσάρτηση και ελέγξτε τα αιτήματά του `ptrace`:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Στατική αναγνώριση και παράκαμψη σε ARM64

Για ένα μη obfuscated ARM64 Mach-O, εντοπίστε το εισαγόμενο stub του `_ptrace` και εξετάστε τα σημεία κλήσης. Το πρώτο ακέραιο όρισμα περνά στο `w0`, επομένως αυτή η ακολουθία αποκαλύπτει άμεσα το αίτημα anti-debug. Η απουσία της εισαγωγής δεν είναι οριστική, καθώς ο κώδικας μπορεί να επιλύει δυναμικά το `ptrace`. Ένα εισαγόμενο `_sysctl` μπορεί επίσης να υποδεικνύει ελέγχους anti-debug, αν και και αυτό μπορεί να επιλυθεί δυναμικά.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Στο δείγμα που παρουσιάζεται, η αλλαγή του immediate από `0x1f` σε `0x0` αλλάζει το αίτημα σε `PT_TRACE_ME` και επιτρέπει στο πρόγραμμα να συνεχίσει υπό το LLDB. Πρόκειται για **παράκαμψη ειδικά για το συγκεκριμένο δείγμα**, όχι για γενικό no-op: εξετάστε τους ελέγχους της τιμής επιστροφής και τη ροή ελέγχου της καλούσας συνάρτησης πριν αποφασίσετε αν θα αλλάξετε το αίτημα, θα παραλείψετε την κλήση ή θα εξαναγκάσετε επιτυχή επιστροφή.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** είναι το de facto εργαλείο για το **debugging** binary αρχείων στο **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Μπορείτε να ορίσετε τη σύνταξη Intel όταν χρησιμοποιείτε το lldb, δημιουργώντας ένα αρχείο με όνομα **`.lldbinit`** στον προσωπικό σας φάκελο και προσθέτοντας την ακόλουθη γραμμή:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Μέσα στο lldb, κάντε dump μιας διεργασίας με `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Εντολή</strong></td><td><strong>Περιγραφή</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Εκκινεί την εκτέλεση, η οποία συνεχίζεται μέχρι να συναντηθεί breakpoint ή να τερματιστεί η διεργασία.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Εκκινεί την εκτέλεση και σταματά στο σημείο εισόδου.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Συνεχίζει την εκτέλεση της διεργασίας που βρίσκεται υπό debugging.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Εκτελεί την επόμενη εντολή. Αυτή η εντολή προσπερνά τις κλήσεις συναρτήσεων.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Εκτελεί την επόμενη εντολή. Σε αντίθεση με την εντολή <code>nexti</code>, αυτή η εντολή εισέρχεται στις κλήσεις συναρτήσεων.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Εκτελεί τις υπόλοιπες εντολές της τρέχουσας συνάρτησης (frame), επιστρέφει και σταματά.</td></tr>
<tr><td><strong>control + c</strong></td><td>Κάνει παύση στην εκτέλεση. Αν έχει γίνει εκκίνηση (<code>r</code>) ή συνέχιση (<code>c</code>) της διεργασίας, η εντολή αυτή τη σταματά στο σημείο όπου εκτελείται εκείνη τη στιγμή.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Οποιαδήποτε συνάρτηση με όνομα main</p>
<p><code>b &lt;binname&gt;`main</code> # Η κύρια συνάρτηση του binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Η κύρια συνάρτηση του υποδεικνυόμενου binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Οποιαδήποτε μέθοδος NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break σε όλες τις συναρτήσεις αυτής της βιβλιοθήκης</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Λίστα breakpoint</p>
<p><code>br e/dis &lt;num&gt;</code> # Ενεργοποίηση/απενεργοποίηση breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Εμφάνιση βοήθειας για την εντολή breakpoint</p>
<p><code>help memory write</code> # Εμφάνιση βοήθειας για την εγγραφή στη μνήμη</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Εμφανίζει τη μνήμη ως συμβολοσειρά με τερματισμό null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Εμφανίζει τη μνήμη ως εντολή assembly.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Εμφανίζει τη μνήμη ως byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Εμφανίζει το αντικείμενο στο οποίο αναφέρεται η παράμετρος.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Οι περισσότερες Apple Objective-C APIs ή μέθοδοι επιστρέφουν αντικείμενα και επομένως πρέπει να εμφανίζονται με την εντολή “print object” (<code>po</code>). Αν η <code>po</code> δεν παράγει ουσιαστικό αποτέλεσμα, χρησιμοποιήστε την <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Εγγραφή AAAA σε αυτή τη διεύθυνση<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Εγγραφή AAAA στη διεύθυνση
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Αποσυναρμολογεί την τρέχουσα συνάρτηση</p>
<p><code>dis -n &lt;funcname&gt;</code> # Αποσυναρμολογεί μια συνάρτηση</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Αποσυναρμολογεί μια συνάρτηση<br>
<code>dis -c 6</code> # Αποσυναρμολογεί έξι γραμμές<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Αποσυναρμολογεί από τη μία διεύθυνση έως την άλλη<br>
<code>dis -p -c 4</code> # Ξεκινά την αποσυναρμολόγηση από την τρέχουσα διεύθυνση</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Εξετάζει έναν πίνακα τριών στοιχείων στον καταχωρητή <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Εμφανίζει έναν χάρτη της μνήμης της τρέχουσας διεργασίας.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Εμφανίζει τη διεύθυνση κάθε συμβόλου από το CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Κατά την κλήση της συνάρτησης **`objc_sendMsg`**, ο καταχωρητής **rsi** περιέχει το **όνομα της μεθόδου** ως συμβολοσειρά με τερματισμό null (“C”). Για να εμφανίσετε το όνομα μέσω lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Ανάλυση κατά της δυναμικής ανάλυσης

#### Ανίχνευση VM

- Η εντολή **`sysctl hw.model`** επιστρέφει συνήθως ένα αναγνωριστικό μοντέλου Mac σε φυσικό hardware και μπορεί να επιστρέψει διαφορετική τιμή σε VM.<sup>[[3]](#references)</sup>
- Μεταβάλλοντας τις τιμές των **`hw.logicalcpu`** και **`hw.physicalcpu`**, ορισμένα malwares προσπαθούν να ανιχνεύσουν αν εκτελούνται σε VM.<sup>[[4]](#references)</sup>
- Ένας loader μπορεί επίσης να ελέγξει τα `kern.hv_vmm_present` και `machdep.cpu.brand_string` μέσω `sysctl` για να εντοπίσει VM πριν αποσυσκευάσει το επόμενο στάδιο. Αυτοί οι έλεγχοι συμπληρώνουν, αντί να αντικαθιστούν, τον παρακάτω έλεγχο για σύνδεση debugger.<sup>[[20]](#references)</sup>
- Ορισμένα malwares μπορούν επίσης να **ανιχνεύσουν** αν το μηχάνημα βασίζεται σε **VMware**, χρησιμοποιώντας τη διεύθυνση MAC (00:50:56).
- Είναι επίσης δυνατό να διαπιστωθεί **αν γίνεται debugging μιας διεργασίας** με απλό κώδικα όπως:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Μπορεί επίσης να καλέσει την κλήση συστήματος `ptrace` με τη σημαία `PT_DENY_ATTACH`. Αυτό εμποδίζει τη σύνδεση και την παρακολούθηση από debugger. Δείτε την ενότητα [PT_DENY_ATTACH section](#page-title) για τη συμπεριφορά του XNU που εξαρτάται από τη σειρά, την καταγραφή του `debugserver` και τη ροή εργασίας patching για ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
- Μπορεί επίσης να καλέσει την κλήση συστήματος **`ptrace`** με τη σημαία **`PT_DENY_ATTACH`**. Δείτε την ενότητα [PT_DENY_ATTACH section](#page-title) για τη συμπεριφορά του XNU που εξαρτάται από τη σειρά, την καταγραφή του `debugserver` και τη ροή εργασίας patching για ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
  - Μπορείτε να ελέγξετε αν γίνεται **import** της συνάρτησης **`sysctl`** ή **`ptrace`** (αλλά το malware μπορεί να κάνει import δυναμικά)
  - Όπως αναφέρεται σε αυτό το writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Το μήνυμα Process # exited with **status = 45 (0x0000002d)** είναι συνήθως ενδεικτικό ότι ο στόχος του debug χρησιμοποιεί **PT_DENY_ATTACH**_”
#### Μεταβίβαση διεργασίας μέσω `fork()`

Μια διεργασία μπορεί να αποφύγει έναν debugger που παραμένει συνδεδεμένος στο αρχικό PID καλώντας `fork()` κοντά στην εκκίνηση, τερματίζοντας τη γονική διεργασία (`fork()` επιστρέφει θετικό PID παιδιού) και συνεχίζοντας την προστατευμένη λογική μόνο στη διεργασία-παιδί (`fork()` επιστρέφει `0`). Η επίλυση του `fork` με `dlsym(RTLD_DEFAULT, "fork")` αφαιρεί επίσης το άμεσο σημείο κλήσης `_fork`, αλλά αυτό αποτελεί μόνο εμπόδιο στην ανάλυση: η συμβολοσειρά του ονόματος του συμβόλου και η ροή δεδομένων της δυναμικής επίλυσης παραμένουν ορατές στο binary Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

Σε arm64, εντοπίστε αυτό το μοτίβο ακολουθώντας τη ροή δεδομένων αντί για σταθερές διευθύνσεις: τα δύο πρώτα ορίσματα της `dlsym` περνούν στα `x0` και `x1`, το `RTLD_DEFAULT` μπορεί να εμφανιστεί ως `-2` (για παράδειγμα, `movn x0, #1`) και ένα ζεύγος `adrp`/`add` συνήθως κατασκευάζει τη διεύθυνση της συμβολοσειράς `"fork"`. Μετά το `bl` προς το stub της `dlsym`, ακολουθήστε τον δείκτη που επιστρέφεται στο `x0`, μέσω του ελέγχου null και της αποθήκευσής του, έως ένα μεταγενέστερο έμμεσο `blr`. Έπειτα ακολουθήστε το αποτέλεσμα της `fork()` στο `w0`: η τιμή μηδέν επιλέγει τη συνέχεια της διεργασίας-παιδιού, ενώ οι θετικές τιμές και η τιμή `-1` επιλέγουν τη διαδρομή γονέα/σφάλματος.<sup>[[13]](#references)[[14]](#references)</sup>

Μια στατική παράκαμψη είναι να καταργήσετε την έμμεση κλήση και να αναγκάσετε τον υπάρχοντα έλεγχο αποτελέσματος να επιλέξει τη διαδρομή της διεργασίας-παιδιού. Για παράδειγμα, αν ο compiler δημιούργησε την παρακάτω ακολουθία, κάντε patch τα `blr` και την αποθήκευση αποτελέσματος σε `nop`, ορίστε ένα συνθετικό αποτέλεσμα μηδέν και διατηρήστε τη λογική σύγκρισης/διακλάδωσης. Έτσι, η εφαρμογή συνεχίζει κάτω από το αρχικό PID χωρίς να δημιουργήσει παιδί· οι καταχωρητές εντολών και οι στόχοι διακλάδωσης πρέπει να προσαρμοστούν στο build που αναλύεται.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Τα core dumps δημιουργούνται αν:

- Το sysctl `kern.coredump` έχει οριστεί σε 1 (από προεπιλογή)
- Αν η διεργασία δεν ήταν suid/sgid ή το `kern.sugid_coredump` είναι 1 (από προεπιλογή είναι 0)
- Το όριο `AS_CORE` επιτρέπει τη λειτουργία. Είναι δυνατή η απενεργοποίηση της δημιουργίας core dumps με την κλήση `ulimit -c 0` και η επανενεργοποίησή τους με την `ulimit -c unlimited`.

Σε αυτές τις περιπτώσεις, τα core dumps δημιουργούνται σύμφωνα με το sysctl `kern.corefile` και συνήθως αποθηκεύονται στο `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

Το ReportCrash **αναλύει διεργασίες που καταρρέουν και αποθηκεύει αναφορά κατάρρευσης στον δίσκο**. Μια αναφορά κατάρρευσης περιέχει πληροφορίες που μπορούν να **βοηθήσουν έναν developer να διαγνώσει** την αιτία της κατάρρευσης.\
Για εφαρμογές και άλλες διεργασίες **που εκτελούνται στο per-user launchd context**, το ReportCrash εκτελείται ως LaunchAgent και αποθηκεύει αναφορές κατάρρευσης στο `~/Library/Logs/DiagnosticReports/` του χρήστη.\
Για daemons, άλλες διεργασίες **που εκτελούνται στο system launchd context** και άλλες προνομιούχες διεργασίες, το ReportCrash εκτελείται ως LaunchDaemon και αποθηκεύει αναφορές κατάρρευσης στο `/Library/Logs/DiagnosticReports` του συστήματος.

Αν ανησυχείτε μήπως οι αναφορές κατάρρευσης **σταλούν στην Apple**, μπορείτε να τις απενεργοποιήσετε. Διαφορετικά, οι αναφορές κατάρρευσης μπορούν να φανούν χρήσιμες για να **διαπιστώσετε πώς κατέρρευσε ένας server**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Αδράνεια

Κατά το fuzzing σε macOS, αποτρέψτε τον Mac από το να μπει σε κατάσταση ύπνου:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Αποσύνδεση SSH

Αν κάνετε fuzzing μέσω σύνδεσης SSH, είναι σημαντικό να βεβαιωθείτε ότι η συνεδρία δεν θα τερματιστεί. Αλλάξτε, λοιπόν, το αρχείο sshd_config ως εξής:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Εσωτερικοί χειριστές

**Δείτε την παρακάτω σελίδα** για να μάθετε πώς μπορείτε να εντοπίσετε ποια εφαρμογή είναι υπεύθυνη για **τον χειρισμό του καθορισμένου scheme ή protocol:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Καταγραφή διεργασιών δικτύου

Αυτό είναι χρήσιμο για τον εντοπισμό διεργασιών που διαχειρίζονται δεδομένα δικτύου:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ή χρησιμοποιήστε το `netstat` ή το `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzing Mach IPC με διατήρηση κατάστασης

Οι υπηρεσίες Mach που εκθέτουν προνομιούχοι δαίμονες αποτελούν χρήσιμους στόχους για fuzzing, όταν ένας μη προνομιούχος ή sandboxed client μπορεί να αποκτήσει send right. Ξεκινήστε από την καταχώριση `MachServices` του daemon στο launchd και χρησιμοποιήστε τη [ροή εργασίας ανάλυσης MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) για να αντιστοιχίσετε τα message ID στους handlers. Πριν τροποποιήσετε bytes, θέστε breakpoint στη ρουτίνα server του MIG, ενώ ένας κανονικός client χρησιμοποιεί την υπηρεσία, και αποθηκεύστε έγκυρα request messages ως seed inputs. Διατηρήστε τα απαιτούμενα πεδία της κεφαλίδας, τα μεγέθη των μηνυμάτων και τη διάταξη των descriptors, ώστε οι μεταλλάξεις να φτάνουν στον handler αντί να αποτυγχάνουν αμέσως κατά το dispatch.<sup>[[17]](#references)</sup>

Πολλοί handlers εξαρτώνται από προηγούμενες κλήσεις. Βάλτε το harness να αρχικοποιεί την κατάσταση της υπηρεσίας και, στη συνέχεια, να επεξεργάζεται κάθε είσοδο fuzzing ως ακολουθία από **operations και arguments**: στείλτε αιτήματα αρχικοποίησης (όπως open ή create), κρατήστε τα αναγνωριστικά που επιστρέφονται και χρησιμοποιήστε τα σε επόμενα αιτήματα. Έτσι, το feedback κάλυψης μπορεί να εξερευνήσει μεταβάσεις κατάστασης αντί να καταλήγει επανειλημμένα σε ελέγχους για μη αρχικοποιημένα αντικείμενα.<sup>[[17]](#references)</sup>

Για έναν closed-source στόχο, ένα in-process harness που καλεί τη ρουτίνα dispatch του MIG μπορεί να γίνει instrumented με Jackalope/TinyInst. Το [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) είναι μια συγκεκριμένη υλοποίηση, όχι harness έτοιμο για χρήση με άλλες υπηρεσίες.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Επικυρώστε κάθε crash μέσω της πραγματικής διαδρομής IPC.** Ένα harness άμεσου dispatch παραλείπει την επικύρωση των Mach messages από τον kernel και μπορεί να προκαλέσει false positives, ιδίως όταν παρέχει μη έγκυρη μνήμη out-of-line (OOL) ή descriptors θυρών. Δεσμεύστε έγκυρη μνήμη υποστήριξης OOL στο harness και, στη συνέχεια, αναπαράγετε το μειωμένο testcase μέσω `mach_msg` από client με την αρχική πρόσβαση στην υπηρεσία και επιβεβαιώστε ότι ο daemon εξακολουθεί να καταρρέει.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Λειτουργεί για εργαλεία CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

«**Απλώς λειτουργεί**» με πολλά εργαλεία GUI του macOS. Ορισμένες εφαρμογές έχουν επιπλέον απαιτήσεις, όπως μοναδικά ονόματα αρχείων, συγκεκριμένη επέκταση ή ανάγνωση αρχείων από το sandbox container τους (`~/Library/Containers/com.apple.Safari/Data`).

Μερικά παραδείγματα:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Περισσότερες πληροφορίες για fuzzing στο macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Αντιμετώπιση περιστατικών στο OS X: Scripting και ανάλυση](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Η τέχνη του Mac Malware, Τόμος I: Ανάλυση](https://taomm.org/)
- [4] [No Starch Press - Η τέχνη του Mac Malware: Ο οδηγός για την ανάλυση κακόβουλου λογισμικού](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - πληροφορίες που αποθηκεύονται σε αυτές τις ενότητες σε αυτήν την ανάρτηση ιστολογίου](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging δυαδικών αρχείων Apple που χρησιμοποιούν Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Εξουδετέρωση τεχνικών anti-debug: παραλλαγές του macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Δομημένα logs του Xcode και `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Εμφάνιση private data στο unified log του macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Ορισμοί αιτημάτων `ptrace.h` του Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Υλοποίηση του `ptrace` του Apple XNU στο `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - Εσωτερική λειτουργία του ptrace: Πώς αποτρέπει τη σύνδεση debugger](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - Παραδείγματα fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Τεχνική anti-debugging με χρήση dlsym και fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Entitlement εργαλείου debugging](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Debugging εφαρμογής τρίτου μέρους με hardened runtime](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Σπάζοντας το φράγμα του ήχου, Μέρος I: Fuzzing του CoreAudio με μηνύματα Mach](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - Harness του CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - Νέα έκδοση του MacSync macOS stealer στοχεύει λάτρεις των crypto και developers](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
