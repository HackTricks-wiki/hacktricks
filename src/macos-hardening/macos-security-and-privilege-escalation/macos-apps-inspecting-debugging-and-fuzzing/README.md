# Εφαρμογές macOS - Επιθεώρηση, αποσφαλμάτωση και Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Στατική Ανάλυση

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

### Disarm (old jtool2)

Μπορείτε να [**κατεβάσετε το disarm από εδώ**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Σημειώστε ότι το **`disarm`** μπορεί να λειτουργήσει και με συμπιεσμένα αρχεία IM4P (όπως το `kernelcache`) και να εξαγάγει μόνο τα απαιτούμενα μέρη ή ακόμη και να αναλύσει το απαιτούμενο μέρος χωρίς να το εξαγάγει.

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
> Το **`Codesign`** είναι διαθέσιμο στο **macOS**, ενώ το **`ldid`** είναι διαθέσιμο στο **iOS**.

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

Το [**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) είναι ένα χρήσιμο εργαλείο για την επιθεώρηση αρχείων **.pkg** (εγκαταστατών) και για να δείτε τι περιέχουν πριν τα εγκαταστήσετε.\
Αυτοί οι εγκαταστάτες περιλαμβάνουν bash scripts `preinstall` και `postinstall`, τα οποία οι δημιουργοί malware συνήθως καταχρώνται για να **persist** **the** **malware**.

### hdiutil

Αυτό το εργαλείο **προσαρτά** αρχεία εικόνας δίσκου της Apple (`.dmg`), ώστε να μπορούν να επιθεωρηθούν πριν εκτελεστεί οτιδήποτε:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Θα προσαρτηθεί στο `/Volumes`

### Packed binaries

- Ελέγξτε αν η εντροπία είναι υψηλή
- Ελέγξτε τα strings (αν υπάρχουν σχεδόν καθόλου κατανοητά strings, είναι packed)
- Ο packer UPX για macOS δημιουργεί ένα section με όνομα `__XHDR`.

## Στατική ανάλυση Objective-C

### Metadata

> [!CAUTION]
> Σημειώστε ότι τα προγράμματα που έχουν γραφτεί σε Objective-C **διατηρούν** τις δηλώσεις των κλάσεών τους **όταν** **μεταγλωττίζονται** σε [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Αυτές οι δηλώσεις κλάσεων **περιλαμβάνουν** το όνομα και τον τύπο των εξής:

- Των interfaces που έχουν οριστεί
- Των μεθόδων των interfaces
- Των μεταβλητών στιγμιότυπου των interfaces
- Των protocols που έχουν οριστεί

Σημειώστε ότι αυτά τα ονόματα μπορεί να είναι obfuscated, ώστε να δυσκολεύεται το reversing του binary.

### Κλήση συναρτήσεων

Όταν καλείται μια συνάρτηση σε ένα binary που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας, αντί να καλεί τη συνάρτηση, θα καλεί την **`objc_msgSend`**, η οποία θα καλεί την τελική συνάρτηση:

![Metadata - Κλήση συναρτήσεων: Όταν καλείται μια συνάρτηση σε ένα binary που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας, αντί να καλεί τη συνάρτηση, θα καλεί την objc msgSend . Η οποία θα...](<../../../images/image (305).png>)

Οι παράμετροι που δέχεται αυτή η συνάρτηση είναι:

- Η πρώτη παράμετρος (**self**) είναι «ένας δείκτης που δείχνει στο **στιγμιότυπο της κλάσης που θα λάβει το μήνυμα**». Με απλά λόγια, είναι το αντικείμενο στο οποίο καλείται η μέθοδος. Αν η μέθοδος είναι class method, θα είναι ένα στιγμιότυπο του αντικειμένου της κλάσης (ως σύνολο), ενώ για μια instance method, το self θα δείχνει σε ένα στιγμιότυπο της κλάσης ως αντικείμενο.
- Η δεύτερη παράμετρος, (**op**), είναι «ο selector της μεθόδου που χειρίζεται το μήνυμα». Με απλά λόγια, είναι απλώς το **όνομα της μεθόδου**.
- Οι υπόλοιπες παράμετροι είναι οι **τιμές που απαιτεί η μέθοδος** (op).

Δείτε σε αυτή τη σελίδα πώς μπορείτε να **λάβετε εύκολα αυτές τις πληροφορίες με `lldb` σε ARM64**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Όρισμα**         | **Register**                                                    | **(για) objc_msgSend**                                  |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ο όρισμα**     | **rdi**                                                         | **self: αντικείμενο στο οποίο καλείται η μέθοδος**     |
| **2ο όρισμα**     | **rsi**                                                         | **op: όνομα της μεθόδου**                              |
| **3ο όρισμα**     | **rdx**                                                         | **1ο όρισμα της μεθόδου**                              |
| **4ο όρισμα**     | **rcx**                                                         | **2ο όρισμα της μεθόδου**                              |
| **5ο όρισμα**     | **r8**                                                          | **3ο όρισμα της μεθόδου**                              |
| **6ο όρισμα**     | **r9**                                                          | **4ο όρισμα της μεθόδου**                              |
| **7ο+ όρισμα**    | <p><strong>rsp+</strong><br><strong>(στη στοίβα)</strong></p>   | **5ο+ όρισμα της μεθόδου**                             |

### Εξαγωγή metadata του ObjectiveC

### Dynadump

Το [**Dynadump**](https://github.com/DerekSelander/dynadump) είναι ένα εργαλείο για class-dump Objective-C binaries. Το GitHub αναφέρει dylibs, αλλά το εργαλείο λειτουργεί και με executables.

```bash
./dynadump dump /path/to/bin
```

Κατά τη στιγμή της συγγραφής, αυτό είναι **αυτήν τη στιγμή εκείνο που λειτουργεί καλύτερα**.

#### Συνήθη εργαλεία

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

Το [**class-dump**](https://github.com/nygard/class-dump/) είναι το αρχικό εργαλείο για τη δημιουργία δηλώσεων για τις κλάσεις, τις κατηγορίες και τα πρωτόκολλα σε μορφοποιημένο κώδικα Objective-C.

Είναι παλιό και δεν συντηρείται, επομένως πιθανότατα δεν θα λειτουργεί σωστά.

#### ICDump

Το [**iCDump**](https://github.com/romainthomas/iCDump) είναι ένα σύγχρονο, cross-platform εργαλείο για την εξαγωγή των κλάσεων Objective-C. Σε σύγκριση με τα υπάρχοντα εργαλεία, το iCDump μπορεί να εκτελεστεί ανεξάρτητα από το οικοσύστημα της Apple και προσφέρει bindings για Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Στατική ανάλυση Swift

Με τα binaries της Swift, λόγω της συμβατότητας με Objective-C, μερικές φορές μπορείτε να εξαγάγετε δηλώσεις χρησιμοποιώντας το [class-dump](https://github.com/nygard/class-dump/), αλλά όχι πάντα.

Με τις εντολές **`jtool -l`** ή **`otool -l`** μπορείτε να βρείτε αρκετές ενότητες που ξεκινούν με το πρόθεμα **`__swift5`**:

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

Επιπλέον, **τα Swift binaries μπορεί να περιέχουν symbols** (για παράδειγμα, οι βιβλιοθήκες πρέπει να αποθηκεύουν symbols ώστε να μπορούν να κληθούν οι συναρτήσεις τους). Τα **symbols συνήθως περιέχουν πληροφορίες για το όνομα και τα attributes της συνάρτησης** με άσχημη μορφή, γι' αυτό είναι πολύ χρήσιμα, ενώ υπάρχουν και «**demanglers**» που μπορούν να ανακτήσουν το αρχικό όνομα:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Δυναμική ανάλυση

> [!WARNING]
> Σημειώστε ότι για να κάνετε debug σε binaries, **το SIP πρέπει να είναι απενεργοποιημένο** (`csrutil disable` ή `csrutil enable --without debug`) ή πρέπει να αντιγράψετε τα binaries σε έναν προσωρινό φάκελο και να **αφαιρέσετε την υπογραφή** με `codesign --remove-signature <binary-path>` ή να επιτρέψετε το debugging του binary (μπορείτε να χρησιμοποιήσετε [αυτό το script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Σημειώστε ότι για να **κάνετε instrument system binaries** (όπως το `cloudconfigurationd`) στο macOS, **το SIP πρέπει να είναι απενεργοποιημένο** (η απλή αφαίρεση της υπογραφής δεν αρκεί).

### APIs

Το macOS εκθέτει ορισμένα ενδιαφέροντα APIs που παρέχουν πληροφορίες σχετικά με τις διεργασίες:

- `proc_info`: Το κύριο API, το οποίο παρέχει πολλές πληροφορίες για κάθε διεργασία. Πρέπει να είστε root για να λάβετε πληροφορίες για άλλες διεργασίες, αλλά δεν χρειάζεστε ειδικά entitlements ή mach ports.
- `libsysmon.dylib`: Εκθέτει πληροφορίες διεργασιών μέσω συναρτήσεων XPC, αλλά οι callers χρειάζονται το entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

Το **stackshotting** είναι μια τεχνική που χρησιμοποιείται για την καταγραφή της κατάστασης των διεργασιών, συμπεριλαμβανομένων των call stacks όλων των threads που εκτελούνται. Είναι ιδιαίτερα χρήσιμη για debugging, ανάλυση επιδόσεων και κατανόηση της συμπεριφοράς του συστήματος σε μια συγκεκριμένη χρονική στιγμή. Στα iOS και macOS, το stackshotting μπορεί να πραγματοποιηθεί με διάφορα εργαλεία και μεθόδους, όπως τα εργαλεία **`sample`** και **`spindump`**.

### Sysdiagnose

Αυτό το εργαλείο (`/usr/bini/ysdiagnose`) συλλέγει ουσιαστικά πολλές πληροφορίες από τον υπολογιστή σας, εκτελώντας δεκάδες διαφορετικές εντολές όπως οι `ps`, `zprint`...

Πρέπει να εκτελείται ως **root**, ενώ ο daemon `/usr/libexec/sysdiagnosed` διαθέτει πολύ ενδιαφέροντα entitlements όπως τα `com.apple.system-task-ports` και `get-task-allow`.

Το plist του βρίσκεται στη διαδρομή `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, όπου δηλώνονται 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Διαγράφει παλιά αρχεία στο /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Ειδική θύρα 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Διεπαφή user mode μέσω της κλάσης `Libsysdiagnose` Obj-C. Μπορούν να μεταβιβαστούν τρία ορίσματα σε ένα dict (`compress`, `display`, `run`)

### Ενοποιημένα Logs

Το macOS δημιουργεί εκτενή logs, τα οποία είναι χρήσιμα κατά την ανάλυση της συμπεριφοράς μιας εφαρμογής.

Ορισμένα πεδία των logs περιέχουν την ετικέτα `<private>` για να αποκρύπτουν πληροφορίες που ταυτοποιούν τον χρήστη ή τη συσκευή. Παλαιότερες οδηγίες περιγράφουν μερικές φορές την εγκατάσταση πιστοποιητικού για την αποκάλυψη αυτών των πεδίων· οι τρέχουσες οδηγίες debugging χρησιμοποιούν αντ’ αυτού ένα configuration profile με ρητά καθορισμένο scope και `Enable-Private-Data`, ή `OSLogPreferences` ανά εφαρμογή, ενώ η συμπεριφορά μπορεί να διαφέρει ανά subsystem και έκδοση macOS. Η παλαιότερη συζήτηση για τα πιστοποιητικά/profile παραμένει στις αναφορές. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Αριστερό πλαίσιο

Στο αριστερό πλαίσιο του Hopper μπορείτε να δείτε τα σύμβολα (**Labels**) του binary, τη λίστα των procedures και functions (**Proc**) και τα strings (**Str**). Αυτά δεν είναι όλα τα strings, αλλά εκείνα που ορίζονται σε διάφορα τμήματα του αρχείου Mac-O (όπως τα _cstring ή_ `objc_methname`).

#### Μεσαίο πλαίσιο

Στο μεσαίο πλαίσιο μπορείτε να δείτε τον **disassembled code**. Μπορείτε επίσης να τον δείτε ως **raw** disassembly, ως **graph**, ως **decompiled** ή ως **binary**, κάνοντας κλικ στο αντίστοιχο εικονίδιο:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Κάνοντας δεξί κλικ σε ένα code object μπορείτε να δείτε **references προς/από αυτό το object** ή ακόμη και να αλλάξετε το όνομά του (αυτό δεν λειτουργεί σε decompiled pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Επιπλέον, **στο κάτω μέρος του μεσαίου πλαισίου μπορείτε να γράψετε εντολές Python**.

#### Δεξί πλαίσιο

Στο δεξί πλαίσιο μπορείτε να δείτε ενδιαφέρουσες πληροφορίες, όπως το **navigation history** (ώστε να γνωρίζετε πώς φτάσατε στην τρέχουσα κατάσταση), το **call graph**, όπου μπορείτε να δείτε όλες τις **functions που καλούν αυτήν τη function** και όλες τις functions **που καλεί αυτή η function**, καθώς και πληροφορίες για τις **local variables**.

### dtrace

Παρέχει στους χρήστες πρόσβαση σε εφαρμογές σε εξαιρετικά **χαμηλό επίπεδο** και τους δίνει τη δυνατότητα να κάνουν **trace** σε **προγράμματα** και ακόμη και να αλλάξουν τη ροή εκτέλεσής τους. Το Dtrace χρησιμοποιεί **probes**, τα οποία **τοποθετούνται σε όλο τον kernel** και βρίσκονται σε σημεία όπως η αρχή και το τέλος των system calls.

Το DTrace χρησιμοποιεί τη συνάρτηση **`dtrace_probe_create`** για να δημιουργήσει ένα probe για κάθε system call. Αυτά τα probes μπορούν να ενεργοποιηθούν στο **σημείο εισόδου και εξόδου κάθε system call**. Η αλληλεπίδραση με το DTrace γίνεται μέσω του /dev/dtrace, το οποίο είναι διαθέσιμο μόνο στον χρήστη root.<sup>[[1]](#references)</sup>

> [!TIP]
> Για να ενεργοποιήσετε το Dtrace χωρίς να απενεργοποιήσετε πλήρως την προστασία SIP, μπορείτε να εκτελέσετε την ακόλουθη εντολή σε recovery mode: `csrutil enable --without dtrace`
>
> Μπορείτε επίσης να κάνετε **`dtrace`** ή **`dtruss`** σε binaries που **έχετε κάνει compile**.

Τα διαθέσιμα probes του dtrace μπορούν να ληφθούν με:

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

Μια πιο λεπτομερής επεξήγηση και περισσότερα παραδείγματα υπάρχουν στο [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Παραδείγματα

Εκτελέστε `man -k dtrace` για να εμφανιστούν τα **διαθέσιμα DTrace scripts**. Παράδειγμα: `sudo dtruss -n binary`

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

Είναι μια δυνατότητα tracing του kernel. Οι τεκμηριωμένοι κωδικοί βρίσκονται στο **`/usr/share/misc/trace.codes`**.

Εργαλεία όπως τα `latency`, `sc_usage`, `fs_usage` και `trace` το χρησιμοποιούν εσωτερικά.

Για τη διασύνδεση με το `kdebug` χρησιμοποιείται το `sysctl` μέσω του namespace `kern.kdebug`. Τα MIB που πρέπει να χρησιμοποιηθούν βρίσκονται στο `sys/sysctl.h`, ενώ οι συναρτήσεις υλοποιούνται στο `bsd/kern/kdebug.c`.

Για την αλληλεπίδραση με το kdebug μέσω ενός προσαρμοσμένου client, τα βήματα είναι συνήθως τα εξής:

- Αφαιρέστε τις υπάρχουσες ρυθμίσεις με το KERN_KDSETREMOVE
- Ορίστε το trace με τα KERN_KDSETBUF και KERN_KDSETUP
- Χρησιμοποιήστε το KERN_KDGETBUF για να λάβετε τον αριθμό των εγγραφών του buffer
- Αφαιρέστε το δικό σας client από το trace με το KERN_KDPINDEX
- Ενεργοποιήστε το tracing με το KERN_KDENABLE
- Διαβάστε το buffer καλώντας το KERN_KDREADTR
- Για να αντιστοιχίσετε κάθε thread στη διεργασία του, καλέστε το KERN_KDTHRMAP.

Για να λάβετε αυτές τις πληροφορίες, μπορείτε να χρησιμοποιήσετε το εργαλείο της Apple **`trace`** ή το προσαρμοσμένο εργαλείο [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Σημειώστε ότι το Kdebug είναι διαθέσιμο μόνο σε 1 πελάτη κάθε φορά.** Επομένως, μπορεί να εκτελείται μόνο ένα εργαλείο που χρησιμοποιεί k-debug κάθε φορά.

### ktrace

Τα API `ktrace_*` προέρχονται από το `libktrace.dylib`, το οποίο περιβάλλει τα API του `Kdebug`. Έτσι, ένας client μπορεί απλώς να καλέσει τα `ktrace_session_create` και `ktrace_events_[single/class]` για να ορίσει callbacks σε συγκεκριμένους κωδικούς και, στη συνέχεια, να ξεκινήσει το tracing με το `ktrace_start`.

Μπορείτε να το χρησιμοποιήσετε ακόμη και με ενεργοποιημένο το **SIP**.

Μπορείτε να χρησιμοποιήσετε το βοηθητικό πρόγραμμα `ktrace` ως client:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ή `tailspin`.

### kperf

Χρησιμοποιείται για profiling σε επίπεδο kernel και είναι υλοποιημένο με χρήση των κλήσεων `Kdebug`.

Βασικά, ελέγχεται η global μεταβλητή `kernel_debug_active` και, αν είναι ορισμένη, καλείται η `kperf_kdebug_handler` με τον κωδικό `Kdebug` και τη διεύθυνση του kernel frame που πραγματοποιεί την κλήση. Αν ο κωδικός `Kdebug` αντιστοιχεί σε έναν από τους επιλεγμένους κωδικούς, εκτελούνται οι «actions» που έχουν ρυθμιστεί ως bitmap (δείτε τις διαθέσιμες επιλογές στο `osfmk/kperf/action.h`).

Το Kperf διαθέτει επίσης έναν πίνακα sysctl MIB: (ως root) `sysctl kperf`. Ο κώδικας αυτός βρίσκεται στο `osfmk/kperf/kperfbsd.c`.

Επιπλέον, ένα υποσύνολο της λειτουργικότητας του Kperf βρίσκεται στο `kpc`, το οποίο παρέχει πληροφορίες για τους performance counters του συστήματος.

### ProcessMonitor

Το [**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) είναι ένα πολύ χρήσιμο εργαλείο για τον έλεγχο των ενεργειών που σχετίζονται με processes και εκτελούνται από ένα process (για παράδειγμα, την παρακολούθηση των νέων processes που δημιουργεί ένα process).

### SpriteTree

Το [**SpriteTree**](https://themittenmac.com/tools/) είναι ένα εργαλείο που εμφανίζει τις σχέσεις μεταξύ processes.\
Πρέπει να παρακολουθήσετε το Mac σας με μια εντολή όπως **`sudo eslogger fork exec rename create > cap.json`** (το terminal που εκτελεί αυτή την εντολή χρειάζεται FDA). Στη συνέχεια, μπορείτε να φορτώσετε το json σε αυτό το εργαλείο για να δείτε όλες τις σχέσεις:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

Το [**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) παρακολουθεί συμβάντα αρχείων, όπως τη δημιουργία, την τροποποίηση και τη διαγραφή.

### Crescendo

Το [**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) είναι ένα εργαλείο GUI με εμφάνιση και αίσθηση που μπορεί να αναγνωρίζουν οι χρήστες των Windows από το _Procmon_ του Microsoft Sysinternals. Με αυτό το εργαλείο μπορείτε να ξεκινάτε και να σταματάτε την καταγραφή διαφόρων τύπων συμβάντων, να φιλτράρετε αυτά τα συμβάντα ανά κατηγορία, όπως file, process, network κ.λπ., και να αποθηκεύετε τα καταγεγραμμένα συμβάντα σε μορφή json.

### Apple Instruments

Το [**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) αποτελεί μέρος των εργαλείων Developer του Xcode και χρησιμοποιείται για την παρακολούθηση της απόδοσης εφαρμογών, τον εντοπισμό memory leaks και την παρακολούθηση της δραστηριότητας του filesystem.

![Crescendo - Apple Instruments: Το Apple Instruments αποτελεί μέρος των εργαλείων Developer του Xcode και χρησιμοποιείται για την παρακολούθηση της απόδοσης εφαρμογών, τον εντοπισμό memory leaks και την παρακολούθηση της δραστηριότητας του filesystem](<../../../images/image (1138).png>)

### fs_usage

Επιτρέπει την παρακολούθηση των ενεργειών που εκτελούνται από processes:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

Το [**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) είναι χρήσιμο για να δείτε τις **libraries** που χρησιμοποιεί ένα binary, τα **αρχεία** που χρησιμοποιεί και τις **network** συνδέσεις του.\
Ελέγχει επίσης τις διεργασίες του binary μέσω του **virustotal** και εμφανίζει πληροφορίες σχετικά με το binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Στο [**this blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) θα βρείτε ένα παράδειγμα για το πώς να κάνετε **debug σε ένα daemon που εκτελείται** και χρησιμοποιεί το **`PT_DENY_ATTACH`** για να αποτρέψει το debugging, ακόμη κι αν το SIP ήταν απενεργοποιημένο.<sup>[[6]](#references)</sup>

### lldb

Το **lldb** είναι το de facto εργαλείο για **debugging** binary στο **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Μπορείτε να ορίσετε τη μορφή Intel όταν χρησιμοποιείτε το lldb, δημιουργώντας ένα αρχείο **`.lldbinit`** στον προσωπικό σας φάκελο με την ακόλουθη γραμμή:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Μέσα στο lldb, κάντε dump μιας διεργασίας με `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Εντολή</strong></td><td><strong>Περιγραφή</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Ξεκινά την εκτέλεση, η οποία συνεχίζεται μέχρι να ενεργοποιηθεί ένα breakpoint ή να τερματιστεί η διεργασία.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Ξεκινά την εκτέλεση και σταματά στο σημείο εισόδου.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Συνεχίζει την εκτέλεση της διεργασίας που αποσφαλματώνεται.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Εκτελεί την επόμενη εντολή. Αυτή η εντολή προσπερνά τις κλήσεις συναρτήσεων.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Εκτελεί την επόμενη εντολή. Σε αντίθεση με την εντολή <code>nexti</code>, αυτή η εντολή εισέρχεται στις κλήσεις συναρτήσεων.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Εκτελεί τις υπόλοιπες εντολές της τρέχουσας συνάρτησης (frame), επιστρέφει και σταματά.</td></tr>
<tr><td><strong>control + c</strong></td><td>Παύει την εκτέλεση. Αν η διεργασία έχει ξεκινήσει (<code>r</code>) ή συνεχιστεί (<code>c</code>), αυτό την κάνει να σταματήσει στο σημείο όπου εκτελείται εκείνη τη στιγμή.</td></tr>
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
<p><code>help breakpoint</code> # Λήψη βοήθειας για την εντολή breakpoint</p>
<p><code>help memory write</code> # Λήψη βοήθειας για την εγγραφή στη μνήμη</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Εμφανίζει τη μνήμη ως συμβολοσειρά που τερματίζεται με null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Εμφανίζει τη μνήμη ως εντολή assembly.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Εμφανίζει τη μνήμη ως byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Εκτυπώνει το αντικείμενο στο οποίο αναφέρεται η παράμετρος.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Οι περισσότερες Apple Objective-C APIs ή μέθοδοι επιστρέφουν αντικείμενα και, επομένως, πρέπει να εμφανίζονται με την εντολή «print object» (<code>po</code>). Αν η <code>po</code> δεν εμφανίσει χρήσιμη έξοδο, χρησιμοποιήστε την <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Εγγραφή AAAA σε αυτή τη διεύθυνση<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Εγγραφή AAAA στη διεύθυνση
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Αποσυναρμολόγηση της τρέχουσας συνάρτησης</p>
<p><code>dis -n &lt;funcname&gt;</code> # Αποσυναρμολόγηση μιας συνάρτησης</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Αποσυναρμολόγηση μιας συνάρτησης<br>
<code>dis -c 6</code> # Αποσυναρμολόγηση έξι γραμμών<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Αποσυναρμολόγηση από τη μία διεύθυνση έως την άλλη<br>
<code>dis -p -c 4</code> # Έναρξη αποσυναρμολόγησης από την τρέχουσα διεύθυνση</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Επιθεώρηση ενός πίνακα με τρία στοιχεία στον καταχωρητή <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Εκτυπώνει έναν χάρτη της μνήμης της τρέχουσας διεργασίας.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Λήψη της διεύθυνσης κάθε συμβόλου από το CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Κατά την κλήση της συνάρτησης **`objc_sendMsg`**, ο καταχωρητής **rsi** περιέχει το **όνομα της μεθόδου** ως συμβολοσειρά που τερματίζεται με null («C»). Για να εκτυπώσετε το όνομα μέσω lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Αντι-δυναμική ανάλυση

#### Ανίχνευση VM

- Η εντολή **`sysctl hw.model`** συνήθως επιστρέφει ένα αναγνωριστικό μοντέλου Mac σε φυσικό hardware, ενώ σε VM μπορεί να επιστρέψει διαφορετική τιμή.<sup>[[3]](#references)</sup>
- Αλλάζοντας τις τιμές των **`hw.logicalcpu`** και **`hw.physicalcpu`**, ορισμένα malwares προσπαθούν να εντοπίσουν αν πρόκειται για VM.<sup>[[4]](#references)</sup>
- Ορισμένα malwares μπορούν επίσης να **εντοπίσουν** αν το μηχάνημα βασίζεται σε **VMware**, βάσει της MAC address (00:50:56).
- Μπορεί επίσης να εντοπιστεί **αν μια διεργασία αποσφαλματώνεται** με κώδικα όπως ο εξής:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Μπορεί επίσης να καλέσει το system call **`ptrace`** με τη σημαία **`PT_DENY_ATTACH`**. Αυτό **εμποδίζει** έναν deb**u**gger να συνδεθεί και να παρακολουθήσει τη διεργασία.
  - Μπορείτε να ελέγξετε αν γίνεται **import** της συνάρτησης **`sysctl`** ή **`ptrace`** (το malware μπορεί, ωστόσο, να την κάνει import δυναμικά)
  - Όπως αναφέρεται σε αυτό το writeup, «[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)» :<sup>[[7]](#references)</sup>\
    «_Το μήνυμα Process # exited with **status = 45 (0x0000002d)** συνήθως αποτελεί σαφή ένδειξη ότι το debug target χρησιμοποιεί **PT_DENY_ATTACH**_»

#### Μεταβίβαση διεργασίας με `fork()`

Μια διεργασία μπορεί να αποφύγει έναν debugger που παραμένει συνδεδεμένος στο αρχικό PID καλώντας `fork()` κοντά στην εκκίνηση, τερματίζοντας τη γονική διεργασία (η `fork()` επιστρέφει θετικό child PID) και συνεχίζοντας την προστατευμένη λογική μόνο στη θυγατρική διεργασία (η `fork()` επιστρέφει `0`). Η επίλυση της `fork` μέσω `dlsym(RTLD_DEFAULT, "fork")` αφαιρεί επίσης το άμεσο σημείο κλήσης `_fork`, αλλά αυτό αποτελεί μόνο εμπόδιο στην ανάλυση: η συμβολοσειρά του ονόματος του symbol και η ροή δεδομένων της δυναμικής επίλυσης παραμένουν ορατές στο binary Mach-O.<sup>[[10]](#references)[[11]](#references)</sup>

Σε arm64, εντοπίστε αυτό το μοτίβο ακολουθώντας τη ροή δεδομένων και όχι σταθερές διευθύνσεις: τα δύο πρώτα ορίσματα της `dlsym` περνούν στους `x0` και `x1`, το `RTLD_DEFAULT` μπορεί να εμφανίζεται ως `-2` (για παράδειγμα, `movn x0, #1`) και ένα ζεύγος `adrp`/`add` συνήθως κατασκευάζει τη διεύθυνση της συμβολοσειράς `"fork"`. Μετά το `bl` προς το stub της `dlsym`, ακολουθήστε τον δείκτη που επιστρέφεται από τον `x0` μέσα από τον έλεγχο null και την αποθήκευσή του, μέχρι το μεταγενέστερο έμμεσο `blr`. Στη συνέχεια, ακολουθήστε το αποτέλεσμα της `fork()` στον `w0`: η τιμή μηδέν επιλέγει τη συνέχεια της θυγατρικής διεργασίας, ενώ οι θετικές τιμές και η τιμή `-1` επιλέγουν τη διαδρομή της γονικής διεργασίας ή του σφάλματος.<sup>[[10]](#references)[[11]](#references)</sup>

Μια στατική παράκαμψη είναι να καταργήσετε την έμμεση κλήση και να εξαναγκάσετε τον υπάρχοντα έλεγχο αποτελέσματος να ακολουθήσει τη διαδρομή της θυγατρικής διεργασίας. Για παράδειγμα, αν ο compiler δημιούργησε την παρακάτω ακολουθία, κάντε patch τα `blr` και την αποθήκευση αποτελέσματος σε `nop`, δώστε ένα συνθετικό αποτέλεσμα μηδέν και διατηρήστε τη λογική σύγκρισης/διακλάδωσης. Τότε η εφαρμογή συνεχίζει με το αρχικό PID χωρίς να δημιουργήσει θυγατρική διεργασία· οι καταχωρητές εντολών και οι στόχοι διακλάδωσης πρέπει να προσαρμοστούν στο build που αναλύεται.<sup>[[10]](#references)[[11]](#references)</sup>

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

Τα core dumps δημιουργούνται εάν:

- το sysctl `kern.coredump` έχει οριστεί σε 1 (από προεπιλογή)
- η διεργασία δεν εκτελούνταν με suid/sgid ή το `kern.sugid_coredump` είναι 1 (η προεπιλογή είναι 0)
- το όριο `AS_CORE` επιτρέπει τη λειτουργία. Είναι δυνατό να αποτραπεί η δημιουργία core dumps καλώντας `ulimit -c 0` και να ενεργοποιηθούν ξανά με `ulimit -c unlimited`.

Σε αυτές τις περιπτώσεις, τα core dumps δημιουργούνται σύμφωνα με το sysctl `kern.corefile` και συνήθως αποθηκεύονται στο `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

Το ReportCrash **αναλύει διεργασίες που καταρρέουν και αποθηκεύει μια αναφορά κατάρρευσης στον δίσκο**. Μια αναφορά κατάρρευσης περιέχει πληροφορίες που μπορούν να **βοηθήσουν έναν developer να διαγνώσει** την αιτία της κατάρρευσης.\
Για εφαρμογές και άλλες διεργασίες **που εκτελούνται στο πλαίσιο launchd ανά χρήστη**, το ReportCrash εκτελείται ως LaunchAgent και αποθηκεύει τις αναφορές κατάρρευσης στο `~/Library/Logs/DiagnosticReports/` του χρήστη.\
Για daemons, άλλες διεργασίες **που εκτελούνται στο πλαίσιο launchd του συστήματος** και άλλες προνομιούχες διεργασίες, το ReportCrash εκτελείται ως LaunchDaemon και αποθηκεύει τις αναφορές κατάρρευσης στο `/Library/Logs/DiagnosticReports` του συστήματος.

Αν ανησυχείτε μήπως οι αναφορές κατάρρευσης **σταλούν στην Apple**, μπορείτε να τις απενεργοποιήσετε. Διαφορετικά, οι αναφορές κατάρρευσης μπορεί να φανούν χρήσιμες για να **διαπιστώσετε πώς κατέρρευσε ένας server**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Αναστολή λειτουργίας

Κατά το fuzzing σε macOS, αποτρέψτε την αναστολή λειτουργίας του Mac:

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

**Δείτε την παρακάτω σελίδα** για να μάθετε πώς μπορείτε να βρείτε ποια εφαρμογή είναι υπεύθυνη για **τον χειρισμό του καθορισμένου scheme ή πρωτοκόλλου:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Απαρίθμηση διεργασιών δικτύου

Αυτό είναι χρήσιμο για να βρίσκετε διεργασίες που διαχειρίζονται δεδομένα δικτύου:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ή χρησιμοποιήστε `netstat` ή `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Λειτουργεί με εργαλεία CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

«**απλώς λειτουργεί**» με πολλά εργαλεία GUI του macOS. Ορισμένες εφαρμογές έχουν πρόσθετες απαιτήσεις, όπως μοναδικά ονόματα αρχείων, συγκεκριμένη επέκταση ή ανάγνωση αρχείων από το sandbox container τους (`~/Library/Containers/com.apple.Safari/Data`).

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

### Περισσότερες πληροφορίες για το Fuzzing στο macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Απόκριση σε περιστατικά OS X: Scripting και ανάλυση](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Καλοκαίρι του Fuzz: MacOS - AppSec Village του DEF CON 29](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Η τέχνη του Mac Malware, Τόμος I: Ανάλυση](https://taomm.org/)
- [4] [No Starch Press - Η τέχνη του Mac Malware: Ο οδηγός για την ανάλυση κακόβουλου λογισμικού](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - πληροφορίες αποθηκευμένες σε αυτές τις ενότητες αυτής της ανάρτησης ιστολογίου](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Αποσφαλμάτωση δυαδικών αρχείων της Apple που χρησιμοποιούν Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Παράκαμψη τεχνικών Anti-Debug: παραλλαγές ptrace του macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Δομημένα logs του Xcode και `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Εμφάνιση ιδιωτικών δεδομένων στο unified log του macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - παραδείγματα fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - Τεχνική anti-debugging με χρήση dlsym και fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
