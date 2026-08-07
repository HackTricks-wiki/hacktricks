# Εφαρμογές macOS - Επιθεώρηση, debugging και Fuzzing

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
> Σημειώστε ότι το **`disarm`** μπορεί επίσης να λειτουργήσει με συμπιεσμένα αρχεία IM4P (όπως το `kernelcache`) και να εξαγάγει μόνο τα απαιτούμενα τμήματα ή ακόμη και να αναλύσει το απαιτούμενο τμήμα χωρίς να το εξαγάγει.
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
> Το **`Codesign`** μπορεί να βρεθεί στο **macOS**, ενώ το **`ldid`** μπορεί να βρεθεί στο **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) είναι ένα χρήσιμο εργαλείο για την επιθεώρηση αρχείων **.pkg** (installers) και την προβολή του περιεχομένου τους πριν από την εγκατάστασή τους.\
Αυτοί οι installers περιέχουν bash scripts `preinstall` και `postinstall`, τα οποία οι malware authors συνήθως καταχρώνται για να διατηρούν **το** **malware**.

### hdiutil

Αυτό το εργαλείο επιτρέπει το **mount** αρχείων Apple disk images (**.dmg**), ώστε να τα επιθεωρείτε πριν εκτελέσετε οτιδήποτε:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Θα προσαρτηθεί στο `/Volumes`

### Packed binaries

- Ελέγξτε για υψηλή εντροπία
- Ελέγξτε τα strings (αν υπάρχει σχεδόν κανένα κατανοητό string, είναι packed)
- Ο UPX packer για MacOS δημιουργεί ένα section με το όνομα "\_\_XHDR"

## Static Objective-C analysis

### Metadata

> [!CAUTION]
> Σημειώστε ότι τα προγράμματα που είναι γραμμένα σε Objective-C **διατηρούν** τις δηλώσεις των κλάσεών τους **όταν** **μεταγλωττίζονται** σε [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Αυτές οι δηλώσεις κλάσεων **περιλαμβάνουν** το όνομα και τον τύπο των:

- Interfaces που έχουν οριστεί
- Interface methods
- Instance variables των interfaces
- Protocols που έχουν οριστεί

Σημειώστε ότι αυτά τα ονόματα μπορεί να είναι obfuscated, ώστε να γίνει δυσκολότερο το reversing του binary.

### Function calling

Όταν καλείται μια function σε ένα binary που χρησιμοποιεί Objective-C, ο compiled κώδικας, αντί να καλέσει απευθείας αυτή τη function, θα καλέσει την **`objc_msgSend`**, η οποία θα καλέσει την τελική function:

![Metadata - Function calling: Όταν καλείται μια function σε ένα binary που χρησιμοποιεί Objective-C, ο compiled κώδικας, αντί να καλέσει απευθείας αυτή τη function, θα καλέσει την objc msgSend. Η οποία θα...](<../../../images/image (305).png>)

Οι παράμετροι που αναμένει αυτή η function είναι:

- Η πρώτη παράμετρος (**self**) είναι "ένας pointer που δείχνει στο **instance της κλάσης που πρόκειται να λάβει το μήνυμα**". Ή, πιο απλά, είναι το object πάνω στο οποίο γίνεται invoke το method. Αν το method είναι class method, αυτό θα είναι ένα instance του class object (ως σύνολο), ενώ για ένα instance method, το self θα δείχνει σε ένα instantiated instance της κλάσης ως object.
- Η δεύτερη παράμετρος, (**op**), είναι "ο selector του method που χειρίζεται το μήνυμα". Και πάλι, πιο απλά, είναι απλώς το **όνομα του method.**
- Οι υπόλοιπες παράμετροι είναι οποιεσδήποτε **τιμές απαιτούνται από το method** (op).

Δείτε πώς μπορείτε να **λάβετε εύκολα αυτές τις πληροφορίες με το `lldb` σε ARM64** σε αυτή τη σελίδα:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Όρισμα**      | **Register**                                                    | **(για) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ο όρισμα**  | **rdi**                                                         | **self: object πάνω στο οποίο γίνεται invoke το method** |
| **2ο όρισμα**  | **rsi**                                                         | **op: όνομα του method**                             |
| **3ο όρισμα**  | **rdx**                                                         | **1ο όρισμα του method**                         |
| **4ο όρισμα**  | **rcx**                                                         | **2ο όρισμα του method**                         |
| **5ο όρισμα**  | **r8**                                                          | **3ο όρισμα του method**                         |
| **6ο όρισμα**  | **r9**                                                          | **4ο όρισμα του method**                         |
| **7ο+ όρισμα** | <p><strong>rsp+</strong><br><strong>(στο stack)</strong></p> | **5ο+ όρισμα του method**                        |

### Dump ObjectiveC metadata

### Dynadump

Το [**Dynadump**](https://github.com/DerekSelander/dynadump) είναι ένα tool για class-dump Objective-C binaries. Το github αναφέρει dylibs, αλλά αυτό λειτουργεί επίσης με executables.
```bash
./dynadump dump /path/to/bin
```
Κατά τη στιγμή της συγγραφής, αυτή είναι **αυτή που λειτουργεί καλύτερα προς το παρόν**.

#### Συνήθη εργαλεία
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) είναι το αρχικό εργαλείο που δημιουργεί δηλώσεις για τις κλάσεις, τις κατηγορίες και τα protocols σε μορφοποιημένο κώδικα Objective-C.

Είναι παλιό και δεν συντηρείται, επομένως πιθανότατα δεν θα λειτουργεί σωστά.

#### ICDump

Το [**iCDump**](https://github.com/romainthomas/iCDump) είναι ένα σύγχρονο και cross-platform εργαλείο για Objective-C class dump. Σε σύγκριση με τα υπάρχοντα εργαλεία, το iCDump μπορεί να εκτελείται ανεξάρτητα από το Apple ecosystem και παρέχει Python bindings.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Static ανάλυση Swift

Με binaries Swift, λόγω της συμβατότητας με Objective-C, μερικές φορές μπορείτε να εξαγάγετε δηλώσεις χρησιμοποιώντας το [class-dump](https://github.com/nygard/class-dump/), αλλά όχι πάντα.

Με τις γραμμές εντολών **`jtool -l`** ή **`otool -l`** είναι δυνατό να εντοπίσετε several sections που ξεκινούν με το πρόθεμα **`__swift5`**:
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

Επιπλέον, τα **Swift binaries ενδέχεται να περιέχουν symbols** (για παράδειγμα, οι βιβλιοθήκες πρέπει να αποθηκεύουν symbols ώστε να μπορούν να καλούνται οι συναρτήσεις τους). Τα **symbols συνήθως περιέχουν τις πληροφορίες για το όνομα της συνάρτησης** και τα attr με άσχημο τρόπο, επομένως είναι πολύ χρήσιμα και υπάρχουν "**demanglers"** που μπορούν να ανακτήσουν το αρχικό όνομα:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dynamic Analysis

> [!WARNING]
> Σημειώστε ότι για να κάνετε debug σε binaries, το **SIP πρέπει να είναι απενεργοποιημένο** (`csrutil disable` ή `csrutil enable --without debug`) ή πρέπει να αντιγράψετε τα binaries σε έναν προσωρινό φάκελο και να **αφαιρέσετε την υπογραφή** με `codesign --remove-signature <binary-path>` ή να επιτρέψετε το debugging του binary (μπορείτε να χρησιμοποιήσετε [αυτό το script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Σημειώστε ότι για να κάνετε **instrument system binaries**, (όπως το `cloudconfigurationd`) στο macOS, το **SIP πρέπει να είναι απενεργοποιημένο** (η απλή αφαίρεση της υπογραφής δεν θα λειτουργήσει).

### APIs

Το macOS εκθέτει ορισμένα ενδιαφέροντα APIs που παρέχουν πληροφορίες σχετικά με τις διεργασίες:

- `proc_info`: Αυτό είναι το κύριο API και παρέχει πολλές πληροφορίες για κάθε διεργασία. Χρειάζεστε δικαιώματα root για να λάβετε πληροφορίες σχετικά με άλλες διεργασίες, αλλά δεν χρειάζεστε ειδικά entitlements ή mach ports.
- `libsysmon.dylib`: Επιτρέπει τη λήψη πληροφοριών σχετικά με διεργασίες μέσω συναρτήσεων XPC που εκτίθενται, ωστόσο απαιτείται το entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

Το **Stackshotting** είναι μια τεχνική που χρησιμοποιείται για την καταγραφή της κατάστασης των διεργασιών, συμπεριλαμβανομένων των call stacks όλων των threads που εκτελούνται. Αυτό είναι ιδιαίτερα χρήσιμο για debugging, performance analysis και την κατανόηση της συμπεριφοράς του συστήματος σε μια συγκεκριμένη χρονική στιγμή. Σε iOS και macOS, το stackshotting μπορεί να εκτελεστεί χρησιμοποιώντας διάφορα εργαλεία και μεθόδους, όπως τα εργαλεία **`sample`** και **`spindump`**.

### Sysdiagnose

Αυτό το εργαλείο (`/usr/bini/ysdiagnose`) συλλέγει βασικά πολλές πληροφορίες από τον υπολογιστή σας, εκτελώντας δεκάδες διαφορετικές εντολές, όπως `ps`, `zprint`...

Πρέπει να εκτελείται ως **root** και το daemon `/usr/libexec/sysdiagnosed` έχει πολύ ενδιαφέροντα entitlements, όπως τα `com.apple.system-task-ports` και `get-task-allow`.

Το plist του βρίσκεται στο `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, το οποίο δηλώνει 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Διαγράφει παλιά αρχεία στο /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Ειδική port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: User mode interface μέσω της κλάσης `Libsysdiagnose` Obj-C. Μπορούν να περαστούν τρία arguments σε ένα dict (`compress`, `display`, `run`)

### Unified Logs

Το macOS δημιουργεί πολλά logs που μπορεί να είναι πολύ χρήσιμα όταν εκτελείται μια εφαρμογή και προσπαθείτε να κατανοήσετε **τι κάνει**.

Επιπλέον, υπάρχουν ορισμένα logs που περιέχουν το tag `<private>` για να **κρύψουν** ορισμένες **αναγνωρίσιμες** πληροφορίες σχετικά με τον **χρήστη** ή τον **υπολογιστή**. Ωστόσο, είναι δυνατή η **εγκατάσταση ενός certificate για την αποκάλυψη αυτών των πληροφοριών**. Ακολουθήστε τις οδηγίες από [**εδώ**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Left panel

Στο left panel του Hopper μπορείτε να δείτε τα symbols (**Labels**) του binary, τη λίστα των procedures και functions (**Proc**) και τα strings (**Str**). Αυτά δεν είναι όλα τα strings, αλλά εκείνα που ορίζονται σε διάφορα τμήματα του Mac-O file (όπως το _cstring ή το `objc_methname`).

#### Middle panel

Στο middle panel μπορείτε να δείτε τον **dissasembled code**. Μπορείτε να τον δείτε ως **raw** disassemble, ως **graph**, ως **decompiled** και ως **binary**, κάνοντας click στο αντίστοιχο icon:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Κάνοντας right click σε ένα code object μπορείτε να δείτε **references προς/από αυτό το object** ή ακόμη και να αλλάξετε το όνομά του (αυτό δεν λειτουργεί στο decompiled pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Επιπλέον, **στο κάτω μέρος του middle panel μπορείτε να γράψετε python commands**.

#### Right panel

Στο right panel μπορείτε να δείτε ενδιαφέρουσες πληροφορίες, όπως το **navigation history** (ώστε να γνωρίζετε πώς φτάσατε στην τρέχουσα κατάσταση), το **call graph**, όπου μπορείτε να δείτε όλες τις **functions που καλούν αυτήν τη function** και όλες τις functions που **καλεί αυτή η function**, καθώς και πληροφορίες για τις **local variables**.

### dtrace

Επιτρέπει στους χρήστες να έχουν πρόσβαση σε εφαρμογές σε εξαιρετικά **χαμηλό επίπεδο** και παρέχει έναν τρόπο για **trace** **programs** και ακόμη και για αλλαγή της ροής εκτέλεσής τους. Το Dtrace χρησιμοποιεί **probes**, τα οποία είναι **τοποθετημένα σε όλο τον kernel** και βρίσκονται σε σημεία όπως η αρχή και το τέλος των system calls.

Το DTrace χρησιμοποιεί τη συνάρτηση **`dtrace_probe_create`** για να δημιουργήσει ένα probe για κάθε system call. Αυτά τα probes μπορούν να ενεργοποιηθούν στο **entry και exit point κάθε system call**. Η αλληλεπίδραση με το DTrace πραγματοποιείται μέσω του /dev/dtrace, το οποίο είναι διαθέσιμο μόνο στον root user.<sup>[[1]](#references)</sup>

> [!TIP]
> Για να ενεργοποιήσετε το Dtrace χωρίς να απενεργοποιήσετε πλήρως την προστασία SIP, μπορείτε να εκτελέσετε σε recovery mode: `csrutil enable --without dtrace`
>
> Μπορείτε επίσης να χρησιμοποιήσετε τα binaries **`dtrace`** ή **`dtruss`** που **έχετε κάνει compile**.

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
Το όνομα του probe αποτελείται από τέσσερα μέρη: τον provider, το module, τη function και το name (`fbt:mach_kernel:ptrace:entry`). Αν δεν καθορίσετε κάποιο μέρος του name, το DTrace θα εφαρμόσει σε αυτό το μέρος έναν wildcard.

Για να ρυθμίσουμε το DTrace ώστε να ενεργοποιεί probes και να καθορίσουμε ποιες ενέργειες θα εκτελούνται όταν ενεργοποιούνται, θα χρειαστεί να χρησιμοποιήσουμε τη γλώσσα D.

Μια πιο λεπτομερής επεξήγηση και περισσότερα παραδείγματα θα βρείτε στο [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Παραδείγματα

Εκτελέστε `man -k dtrace` για να εμφανίσετε τα **διαθέσιμα DTrace scripts**. Παράδειγμα: `sudo dtruss -n binary`

- Στη γραμμή
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

Είναι μια kernel tracing facility. Οι τεκμηριωμένοι κωδικοί βρίσκονται στο **`/usr/share/misc/trace.codes`**.

Εργαλεία όπως τα `latency`, `sc_usage`, `fs_usage` και `trace` το χρησιμοποιούν εσωτερικά.

Για τη διασύνδεση με το `kdebug` χρησιμοποιείται το `sysctl` μέσω του namespace `kern.kdebug`, ενώ τα MIBs που πρέπει να χρησιμοποιηθούν βρίσκονται στο `sys/sysctl.h`, με τις συναρτήσεις να υλοποιούνται στο `bsd/kern/kdebug.c`.

Για την αλληλεπίδραση με το kdebug μέσω ενός custom client, συνήθως ακολουθούνται τα εξής βήματα:

- Αφαίρεση των υπαρχουσών ρυθμίσεων με το KERN_KDSETREMOVE
- Ρύθμιση του trace με τα KERN_KDSETBUF και KERN_KDSETUP
- Χρήση του KERN_KDGETBUF για τη λήψη του αριθμού των buffer entries
- Αφαίρεση του ίδιου του client από το trace με το KERN_KDPINDEX
- Ενεργοποίηση του tracing με το KERN_KDENABLE
- Ανάγνωση του buffer με κλήση του KERN_KDREADTR
- Για την αντιστοίχιση κάθε thread με τη διεργασία του, κλήση του KERN_KDTHRMAP.

Για τη λήψη αυτών των πληροφοριών είναι δυνατό να χρησιμοποιηθεί το Apple εργαλείο **`trace`** ή το custom εργαλείο [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Σημειώστε ότι το Kdebug είναι διαθέσιμο μόνο για 1 πελάτη κάθε φορά.** Επομένως, μόνο ένα εργαλείο που χρησιμοποιεί k-debug μπορεί να εκτελείται ταυτόχρονα.

### ktrace

Τα `ktrace_*` APIs προέρχονται από το `libktrace.dylib`, το οποίο περιβάλλει τα APIs του `Kdebug`. Έτσι, ένας client μπορεί απλώς να καλέσει τα `ktrace_session_create` και `ktrace_events_[single/class]` για να ορίσει callbacks σε συγκεκριμένους κωδικούς και, στη συνέχεια, να ξεκινήσει το trace με το `ktrace_start`.

Μπορείτε να το χρησιμοποιήσετε ακόμη και με **ενεργοποιημένο το SIP**

Μπορείτε να χρησιμοποιήσετε ως clients το utility `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ή `tailspin`.

### kperf

Χρησιμοποιείται για profiling σε επίπεδο kernel και έχει δημιουργηθεί με τη χρήση των callouts του `Kdebug`.

Βασικά, ελέγχεται η global μεταβλητή `kernel_debug_active` και, αν είναι ενεργή, καλεί τη `kperf_kdebug_handler` με τον κωδικό `Kdebug` και τη διεύθυνση του kernel frame που πραγματοποιεί την κλήση. Αν ο κωδικός `Kdebug` αντιστοιχεί σε κάποιον από τους επιλεγμένους, λαμβάνει τα "actions" που έχουν ρυθμιστεί ως bitmap (δείτε το `osfmk/kperf/action.h` για τις διαθέσιμες επιλογές).

Το Kperf διαθέτει επίσης έναν πίνακα sysctl MIB: (ως root) `sysctl kperf`. Ο κώδικας αυτός βρίσκεται στο `osfmk/kperf/kperfbsd.c`.

Επιπλέον, ένα υποσύνολο της λειτουργικότητας του Kperf βρίσκεται στο `kpc`, το οποίο παρέχει πληροφορίες σχετικά με τους performance counters του machine.

### ProcessMonitor

Το [**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) είναι ένα πολύ χρήσιμο tool για τον έλεγχο των ενεργειών που σχετίζονται με processes και εκτελεί ένα process (για παράδειγμα, την παρακολούθηση των νέων processes που δημιουργεί ένα process).

### SpriteTree

Το [**SpriteTree**](https://themittenmac.com/tools/) είναι ένα tool που εμφανίζει τις σχέσεις μεταξύ processes.\
Χρειάζεται να κάνετε monitor το Mac σας με μια εντολή όπως **`sudo eslogger fork exec rename create > cap.json`** (το terminal που εκτελεί αυτή την εντολή απαιτεί FDA). Στη συνέχεια, μπορείτε να φορτώσετε το json σε αυτό το tool για να δείτε όλες τις σχέσεις:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

Το [**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) επιτρέπει την παρακολούθηση file events (όπως δημιουργίες, τροποποιήσεις και διαγραφές), παρέχοντας λεπτομερείς πληροφορίες σχετικά με αυτά τα events.

### Crescendo

Το [**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) είναι ένα GUI tool με εμφάνιση και αίσθηση που μπορεί να γνωρίζουν οι χρήστες Windows από το _Procmon_ του Microsoft Sysinternals. Αυτό το tool επιτρέπει την έναρξη και τη διακοπή της καταγραφής διαφόρων τύπων events, το filtering αυτών των events ανά κατηγορία, όπως file, process, network κ.λπ., και παρέχει τη δυνατότητα αποθήκευσης των καταγεγραμμένων events σε json format.

### Apple Instruments

Το [**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) αποτελεί μέρος των Developer tools του Xcode και χρησιμοποιείται για την παρακολούθηση της απόδοσης applications, τον εντοπισμό memory leak και την παρακολούθηση δραστηριότητας στο filesystem.

![Crescendo - Apple Instruments: Τα Apple Instruments αποτελούν μέρος των Developer tools του Xcode και χρησιμοποιούνται για την παρακολούθηση της απόδοσης applications, τον εντοπισμό memory leak και την παρακολούθηση δραστηριότητας στο filesystem](<../../../images/image (1138).png>)

### fs_usage

Επιτρέπει την παρακολούθηση των ενεργειών που εκτελούνται από processes:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) είναι χρήσιμο για να δείτε τις **βιβλιοθήκες** που χρησιμοποιούνται από ένα binary, τα **αρχεία** που χρησιμοποιεί και τις **συνδέσεις δικτύου**.\
Επίσης ελέγχει τις διεργασίες του binary μέσω του **virustotal** και εμφανίζει πληροφορίες σχετικά με το binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Στο [**this blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) μπορείτε να βρείτε ένα παράδειγμα για το πώς να κάνετε **debugging σε έναν εκτελούμενο daemon** που χρησιμοποιούσε το **`PT_DENY_ATTACH`** για να αποτρέψει το debugging, ακόμη και αν το SIP ήταν απενεργοποιημένο.<sup>[[6]](#references)</sup>

### lldb

Το **lldb** είναι το de facto εργαλείο για **debugging** binary του **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Μπορείτε να ορίσετε το intel flavour όταν χρησιμοποιείτε το lldb, δημιουργώντας ένα αρχείο με όνομα **`.lldbinit`** στον προσωπικό σας φάκελο, με την ακόλουθη γραμμή:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Μέσα στο lldb, κάντε dump μιας διεργασίας με `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Περιγραφή</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Έναρξη εκτέλεσης, η οποία θα συνεχιστεί χωρίς διακοπή μέχρι να επιτευχθεί breakpoint ή να τερματιστεί η διεργασία.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Έναρξη εκτέλεσης με διακοπή στο entry point</td></tr><tr><td><strong>continue (c)</strong></td><td>Συνέχιση της εκτέλεσης της διεργασίας που γίνεται debug.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Εκτέλεση της επόμενης εντολής. Αυτή η εντολή παρακάμπτει τα function calls.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Εκτέλεση της επόμενης εντολής. Σε αντίθεση με την εντολή nexti, αυτή η εντολή εισέρχεται στα function calls.</td></tr><tr><td><strong>finish (f)</strong></td><td>Εκτέλεση των υπόλοιπων εντολών της τρέχουσας function (“frame”), επιστροφή και διακοπή.</td></tr><tr><td><strong>control + c</strong></td><td>Παύση της εκτέλεσης. Αν η διεργασία έχει εκτελεστεί με (r) ή έχει συνεχιστεί με (c), αυτό θα προκαλέσει τη διακοπή της διεργασίας ...στο σημείο όπου εκτελείται εκείνη τη στιγμή.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Οποιαδήποτε func με όνομα main</p><p><code>b <binname>`main</code> #Η κύρια func του bin</p><p><code>b set -n main --shlib <lib_name></code> #Η κύρια func του υποδεικνυόμενου bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Οποιαδήποτε μέθοδος NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break σε όλες τις functions της συγκεκριμένης library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Λίστα breakpoint</p><p><code>br e/dis <num></code> #Ενεργοποίηση/Απενεργοποίηση breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Λήψη βοήθειας για την εντολή breakpoint</p><p>help memory write #Λήψη βοήθειας για εγγραφή στη memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Εμφάνιση της memory ως string που τερματίζεται με null.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Εμφάνιση της memory ως assembly instruction.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Εμφάνιση της memory ως byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Αυτό θα εμφανίσει το object στο οποίο αναφέρεται η παράμετρος</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Σημειώστε ότι τα περισσότερα Objective-C APIs ή methods της Apple επιστρέφουν objects και, επομένως, θα πρέπει να εμφανίζονται μέσω της εντολής “print object” (po). Αν το po δεν παράγει meaningful output, χρησιμοποιήστε <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Εκτύπωση map της memory της τρέχουσας διεργασίας</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Λήψη της διεύθυνσης όλων των symbols από το CoreNLP</td></tr></tbody></table>

> [!TIP]
> Κατά την κλήση της function **`objc_sendMsg`**, ο register **rsi** περιέχει το **όνομα της method** ως string που τερματίζεται με null (“C”). Για να εμφανίσετε το όνομα μέσω lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Η εντολή **`sysctl hw.model`** επιστρέφει "Mac" όταν ο **host είναι MacOS**, αλλά κάτι διαφορετικό όταν πρόκειται για VM.<sup>[[3]](#references)</sup>
- Με την τροποποίηση των τιμών των **`hw.logicalcpu`** και **`hw.physicalcpu`**, ορισμένα malwares προσπαθούν να εντοπίσουν αν πρόκειται για VM.<sup>[[4]](#references)</sup>
- Ορισμένα malwares μπορούν επίσης να **εντοπίσουν** αν το σύστημα είναι **VMware**, με βάση τη MAC address (00:50:56).
- Είναι επίσης δυνατό να βρεθεί **αν μια διεργασία γίνεται debug** με έναν απλό κώδικα όπως:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Μπορεί επίσης να καλέσει το system call **`ptrace`** με το flag **`PT_DENY_ATTACH`**. Αυτό **εμποδίζει** έναν deb**u**gger να κάνει attach και tracing.
- Μπορείτε να ελέγξετε αν η function **`sysctl`** ή **`ptrace`** γίνεται **import** (όμως το malware μπορεί να την κάνει import δυναμικά)
- Όπως σημειώνεται σε αυτό το writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
“_Το μήνυμα Process # exited with **status = 45 (0x0000002d)** είναι συνήθως σαφής ένδειξη ότι το debug target χρησιμοποιεί **PT_DENY_ATTACH**_”

## Core Dumps

Τα Core dumps δημιουργούνται όταν:

- Το sysctl `kern.coredump` έχει οριστεί σε 1 (από προεπιλογή)
- Η διεργασία δεν ήταν suid/sgid ή το `kern.sugid_coredump` είναι 1 (από προεπιλογή είναι 0)
- Το όριο `AS_CORE` επιτρέπει τη λειτουργία. Είναι δυνατό να απενεργοποιήσετε τη δημιουργία core dumps καλώντας `ulimit -c 0` και να τα ενεργοποιήσετε ξανά με `ulimit -c unlimited`.

Σε αυτές τις περιπτώσεις, το core dump δημιουργείται σύμφωνα με το sysctl `kern.corefile` και συνήθως αποθηκεύεται στο `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

Το ReportCrash **αναλύει διεργασίες που έχουν καταρρεύσει και αποθηκεύει ένα crash report στον δίσκο**. Ένα crash report περιέχει πληροφορίες που μπορούν να **βοηθήσουν έναν developer να διαγνώσει** την αιτία ενός crash.\
Για applications και άλλες διεργασίες **που εκτελούνται στο per-user launchd context**, το ReportCrash εκτελείται ως LaunchAgent και αποθηκεύει τα crash reports στο `~/Library/Logs/DiagnosticReports/` του χρήστη.\
Για daemons, άλλες διεργασίες **που εκτελούνται στο system launchd context** και άλλες privileged διεργασίες, το ReportCrash εκτελείται ως LaunchDaemon και αποθηκεύει τα crash reports στο `/Library/Logs/DiagnosticReports` του system.

Αν ανησυχείτε μήπως τα crash reports **σταλούν στην Apple**, μπορείτε να τα απενεργοποιήσετε. Διαφορετικά, τα crash reports μπορούν να φανούν χρήσιμα για να **εντοπίσετε πώς κατέρρευσε ένας server**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Ύπνος

Κατά το fuzzing σε ένα MacOS είναι σημαντικό να μην επιτρέπετε στο Mac να μεταβαίνει σε κατάσταση ύπνου:

- systemsetup -setsleep Never
- pmset, Προτιμήσεις συστήματος
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Αποσύνδεση SSH

Αν κάνετε fuzzing μέσω σύνδεσης SSH, είναι σημαντικό να βεβαιωθείτε ότι η συνεδρία δεν πρόκειται να διακοπεί. Επομένως, αλλάξτε το αρχείο sshd_config ως εξής:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Εσωτερικοί Handlers

**Ελέγξτε την ακόλουθη σελίδα** για να μάθετε πώς μπορείτε να βρείτε ποια εφαρμογή είναι υπεύθυνη για τη **διαχείριση του καθορισμένου scheme ή protocol:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

Αυτό είναι ενδιαφέρον για την εύρεση processes που διαχειρίζονται network data:
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

Λειτουργεί για CLI tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**«απλώς λειτουργεί»** με macOS GUI tools. Σημειώστε ότι ορισμένες macOS apps έχουν συγκεκριμένες απαιτήσεις, όπως μοναδικά filenames, τη σωστή επέκταση, ή την ανάγκη ανάγνωσης των files από το sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Περισσότερες πληροφορίες για το Fuzzing στο MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Αναφορές

- [1] [Απόκριση σε περιστατικά στο OS X: Scripting και Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: Οδηγός για την Analysis κακόβουλου λογισμικού](https://taomm.org/)
- [5] [knight.sc - πληροφορίες αποθηκευμένες σε αυτή την ενότητα αυτής της ανάρτησης ιστολογίου](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging Apple Binaries That Use Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Αντιμετώπιση Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
