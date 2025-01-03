# macOS Εφαρμογές - Επιθεώρηση, αποσφαλμάτωση και Fuzzing

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
### jtool2 & Disarm

Μπορείτε να [**κατεβάσετε το disarm από εδώ**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Μπορείτε να [**κατεβάσετε το jtool2 εδώ**](http://www.newosxbook.com/tools/jtool.html) ή να το εγκαταστήσετε με `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **Το jtool έχει καταργηθεί υπέρ του disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** μπορεί να βρεθεί στο **macOS** ενώ το **`ldid`** μπορεί να βρεθεί στο **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) είναι ένα εργαλείο χρήσιμο για να επιθεωρείτε τα **.pkg** αρχεία (εγκαταστάτες) και να δείτε τι περιέχουν πριν τα εγκαταστήσετε.\
Αυτοί οι εγκαταστάτες έχουν `preinstall` και `postinstall` bash scripts που οι συγγραφείς κακόβουλου λογισμικού συνήθως εκμεταλλεύονται για να **persist** **the** **malware**.

### hdiutil

Αυτό το εργαλείο επιτρέπει να **mount** τις εικόνες δίσκων της Apple (**.dmg**) για να τις επιθεωρήσετε πριν εκτελέσετε οτιδήποτε:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Θα τοποθετηθεί στο `/Volumes`

### Συμπιεσμένα δυαδικά

- Έλεγχος για υψηλή εντροπία
- Έλεγχος των συμβολοσειρών (αν δεν υπάρχει σχεδόν καμία κατανοητή συμβολοσειρά, είναι συμπιεσμένο)
- Ο συμπιεστής UPX για MacOS δημιουργεί μια ενότητα που ονομάζεται "\_\_XHDR"

## Στατική ανάλυση Objective-C

### Μεταδεδομένα

> [!CAUTION]
> Σημειώστε ότι τα προγράμματα που έχουν γραφτεί σε Objective-C **διατηρούν** τις δηλώσεις κλάσης τους **όταν** **μεταγλωττίζονται** σε [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Τέτοιες δηλώσεις κλάσης **περιλαμβάνουν** το όνομα και τον τύπο των:

- Των διεπαφών που έχουν οριστεί
- Των μεθόδων διεπαφής
- Των μεταβλητών στιγμής διεπαφής
- Των πρωτοκόλλων που έχουν οριστεί

Σημειώστε ότι αυτά τα ονόματα θα μπορούσαν να είναι κρυπτογραφημένα για να καταστήσουν την αναστροφή του δυαδικού πιο δύσκολη.

### Κλήση συναρτήσεων

Όταν καλείται μια συνάρτηση σε ένα δυαδικό που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας αντί να καλεί αυτή τη συνάρτηση, θα καλέσει **`objc_msgSend`**. Αυτό θα καλεί τη τελική συνάρτηση:

![](<../../../images/image (305).png>)

Οι παράμετροι που αναμένει αυτή η συνάρτηση είναι:

- Η πρώτη παράμετρος (**self**) είναι "ένα δείκτη που δείχνει στην **περίπτωση της κλάσης που θα λάβει το μήνυμα**". Ή πιο απλά, είναι το αντικείμενο πάνω στο οποίο καλείται η μέθοδος. Αν η μέθοδος είναι μέθοδος κλάσης, αυτό θα είναι μια περίπτωση του αντικειμένου κλάσης (ως σύνολο), ενώ για μια μέθοδο στιγμής, το self θα δείχνει σε μια δημιουργημένη περίπτωση της κλάσης ως αντικείμενο.
- Η δεύτερη παράμετρος, (**op**), είναι "ο επιλεγέας της μεθόδου που χειρίζεται το μήνυμα". Και πάλι, πιο απλά, αυτό είναι απλώς το **όνομα της μεθόδου.**
- Οι υπόλοιπες παράμετροι είναι οποιεσδήποτε **τιμές απαιτούνται από τη μέθοδο** (op).

Δείτε πώς να **πάρετε αυτές τις πληροφορίες εύκολα με `lldb` σε ARM64** σε αυτή τη σελίδα:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: object that the method is being invoked upon** |
| **2nd argument**  | **rsi**                                                         | **op: name of the method**                             |
| **3rd argument**  | **rdx**                                                         | **1st argument to the method**                         |
| **4th argument**  | **rcx**                                                         | **2nd argument to the method**                         |
| **5th argument**  | **r8**                                                          | **3rd argument to the method**                         |
| **6th argument**  | **r9**                                                          | **4th argument to the method**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(on the stack)</strong></p> | **5th+ argument to the method**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) είναι ένα εργαλείο για την εξαγωγή κλάσεων από δυαδικά Objective-C. Το github καθορίζει dylibs αλλά αυτό λειτουργεί επίσης με εκτελέσιμα.
```bash
./dynadump dump /path/to/bin
```
Αυτή τη στιγμή, αυτό είναι **αυτό που λειτουργεί καλύτερα**.

#### Κανονικά εργαλεία
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) είναι το αρχικό εργαλείο που δημιουργεί δηλώσεις για τις κλάσεις, τις κατηγορίες και τα πρωτόκολλα σε κώδικα μορφής ObjectiveC.

Είναι παλιό και δεν συντηρείται, οπότε πιθανότατα δεν θα λειτουργήσει σωστά.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) είναι ένα σύγχρονο και διαλειτουργικό εργαλείο απόρριψης κλάσεων Objective-C. Σε σύγκριση με τα υπάρχοντα εργαλεία, το iCDump μπορεί να εκτελείται ανεξάρτητα από το οικοσύστημα της Apple και εκθέτει Python bindings.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Στατική ανάλυση Swift

Με τα δυαδικά αρχεία Swift, καθώς υπάρχει συμβατότητα με το Objective-C, μερικές φορές μπορείτε να εξάγετε δηλώσεις χρησιμοποιώντας [class-dump](https://github.com/nygard/class-dump/) αλλά όχι πάντα.

Με τις εντολές **`jtool -l`** ή **`otool -l`** είναι δυνατόν να βρείτε αρκετές ενότητες που ξεκινούν με το πρόθεμα **`__swift5`**:
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
Μπορείτε να βρείτε περισσότερες πληροφορίες σχετικά με το [**πληροφορίες που αποθηκεύονται σε αυτήν την ενότητα σε αυτήν την ανάρτηση ιστολογίου**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Επιπλέον, **τα Swift binaries μπορεί να έχουν σύμβολα** (για παράδειγμα, οι βιβλιοθήκες χρειάζονται να αποθηκεύουν σύμβολα ώστε οι συναρτήσεις τους να μπορούν να καλούνται). Τα **σύμβολα συνήθως έχουν πληροφορίες σχετικά με το όνομα της συνάρτησης** και τα attr με άσχημο τρόπο, οπότε είναι πολύ χρήσιμα και υπάρχουν "**demanglers"** που μπορούν να πάρουν το αρχικό όνομα:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Δυναμική Ανάλυση

> [!WARNING]
> Σημειώστε ότι για να αποσφαλματώσετε δυαδικά αρχεία, **η SIP πρέπει να είναι απενεργοποιημένη** (`csrutil disable` ή `csrutil enable --without debug`) ή να αντιγράψετε τα δυαδικά αρχεία σε έναν προσωρινό φάκελο και **να αφαιρέσετε την υπογραφή** με `codesign --remove-signature <binary-path>` ή να επιτρέψετε την αποσφαλμάτωση του δυαδικού αρχείου (μπορείτε να χρησιμοποιήσετε [αυτό το σενάριο](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Σημειώστε ότι για να **εργαστείτε με δυαδικά αρχεία συστήματος**, (όπως το `cloudconfigurationd`) στο macOS, **η SIP πρέπει να είναι απενεργοποιημένη** (απλώς η αφαίρεση της υπογραφής δεν θα λειτουργήσει).

### APIs

Το macOS εκθέτει μερικά ενδιαφέροντα APIs που παρέχουν πληροφορίες σχετικά με τις διαδικασίες:

- `proc_info`: Αυτό είναι το κύριο που παρέχει πολλές πληροφορίες για κάθε διαδικασία. Πρέπει να είστε root για να αποκτήσετε πληροφορίες για άλλες διαδικασίες, αλλά δεν χρειάζεστε ειδικά δικαιώματα ή mach ports.
- `libsysmon.dylib`: Επιτρέπει την απόκτηση πληροφοριών σχετικά με διαδικασίες μέσω εκτεθειμένων συναρτήσεων XPC, ωστόσο, απαιτείται να έχετε το δικαίωμα `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** είναι μια τεχνική που χρησιμοποιείται για την καταγραφή της κατάστασης των διαδικασιών, συμπεριλαμβανομένων των στοίβων κλήσεων όλων των εκτελούμενων νημάτων. Αυτό είναι ιδιαίτερα χρήσιμο για αποσφαλμάτωση, ανάλυση απόδοσης και κατανόηση της συμπεριφοράς του συστήματος σε μια συγκεκριμένη χρονική στιγμή. Στο iOS και το macOS, το stackshotting μπορεί να πραγματοποιηθεί χρησιμοποιώντας διάφορα εργαλεία και μεθόδους όπως τα εργαλεία **`sample`** και **`spindump`**.

### Sysdiagnose

Αυτό το εργαλείο (`/usr/bini/ysdiagnose`) συλλέγει βασικά πολλές πληροφορίες από τον υπολογιστή σας εκτελώντας δεκάδες διαφορετικές εντολές όπως `ps`, `zprint`...

Πρέπει να εκτελείται ως **root** και η διεργασία `/usr/libexec/sysdiagnosed` έχει πολύ ενδιαφέροντα δικαιώματα όπως `com.apple.system-task-ports` και `get-task-allow`.

Η plist του βρίσκεται στο `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` που δηλώνει 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Διαγράφει παλιές αρχειοθετήσεις στο /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Ειδική θύρα 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Διεπαφή λειτουργίας χρήστη μέσω της κλάσης `Libsysdiagnose` Obj-C. Τρία επιχειρήματα σε ένα dict μπορούν να περαστούν (`compress`, `display`, `run`)

### Ενοποιημένα Καταγραφικά

Το macOS παράγει πολλές καταγραφές που μπορεί να είναι πολύ χρήσιμες κατά την εκτέλεση μιας εφαρμογής προσπαθώντας να κατανοήσει **τι κάνει**.

Επιπλέον, υπάρχουν κάποιες καταγραφές που θα περιέχουν την ετικέτα `<private>` για να **κρύψουν** κάποιες **χρήστη** ή **υπολογιστή** **αναγνωρίσιμες** πληροφορίες. Ωστόσο, είναι δυνατή η **εγκατάσταση ενός πιστοποιητικού για την αποκάλυψη αυτών των πληροφοριών**. Ακολουθήστε τις εξηγήσεις από [**εδώ**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Αριστερό πάνελ

Στο αριστερό πάνελ του Hopper είναι δυνατή η προβολή των συμβόλων (**Labels**) του δυαδικού αρχείου, της λίστας διαδικασιών και συναρτήσεων (**Proc**) και των συμβολοσειρών (**Str**). Αυτές δεν είναι όλες οι συμβολοσειρές αλλά αυτές που ορίζονται σε διάφορα μέρη του αρχείου Mac-O (όπως _cstring ή_ `objc_methname`).

#### Μεσαίο πάνελ

Στο μεσαίο πάνελ μπορείτε να δείτε τον **αποσυναρμολογημένο κώδικα**. Και μπορείτε να τον δείτε σε **ακατέργαστο** αποσυναρμολόγηση, ως **γράφημα**, ως **αποκωδικοποιημένο** και ως **δυαδικό** κάνοντας κλικ στο αντίστοιχο εικονίδιο:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Κάνοντας δεξί κλικ σε ένα αντικείμενο κώδικα μπορείτε να δείτε **αναφορές προς/από αυτό το αντικείμενο** ή ακόμη και να αλλάξετε το όνομά του (αυτό δεν λειτουργεί σε αποκωδικοποιημένο ψευδοκώδικα):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Επιπλέον, στο **κάτω μέρος του μεσαίου πάνελ μπορείτε να γράψετε εντολές python**.

#### Δεξί πάνελ

Στο δεξί πάνελ μπορείτε να δείτε ενδιαφέρουσες πληροφορίες όπως το **ιστορικό πλοήγησης** (έτσι ξέρετε πώς φτάσατε στην τρέχουσα κατάσταση), το **γράφημα κλήσεων** όπου μπορείτε να δείτε όλες τις **συναρτήσεις που καλούν αυτή τη συνάρτηση** και όλες τις συναρτήσεις που **καλεί αυτή η συνάρτηση**, και πληροφορίες για **τοπικές μεταβλητές**.

### dtrace

Επιτρέπει στους χρήστες πρόσβαση σε εφαρμογές σε εξαιρετικά **χαμηλό επίπεδο** και παρέχει έναν τρόπο για τους χρήστες να **ιχνηλατούν** **προγράμματα** και ακόμη και να αλλάζουν τη ροή εκτέλεσής τους. Το Dtrace χρησιμοποιεί **probes** που είναι **τοποθετημένα σε όλο τον πυρήνα** και βρίσκονται σε θέσεις όπως η αρχή και το τέλος των κλήσεων συστήματος.

Το DTrace χρησιμοποιεί τη συνάρτηση **`dtrace_probe_create`** για να δημιουργήσει ένα probe για κάθε κλήση συστήματος. Αυτά τα probes μπορούν να ενεργοποιηθούν στο **σημείο εισόδου και εξόδου κάθε κλήσης συστήματος**. Η αλληλεπίδραση με το DTrace συμβαίνει μέσω του /dev/dtrace που είναι διαθέσιμο μόνο για τον χρήστη root.

> [!TIP]
> Για να ενεργοποιήσετε το Dtrace χωρίς να απενεργοποιήσετε πλήρως την προστασία SIP μπορείτε να εκτελέσετε σε λειτουργία ανάκτησης: `csrutil enable --without dtrace`
>
> Μπορείτε επίσης να χρησιμοποιήσετε τα δυαδικά αρχεία **`dtrace`** ή **`dtruss`** που **έχετε συντάξει**.

Οι διαθέσιμες probes του dtrace μπορούν να αποκτηθούν με:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Το όνομα της πρόβας αποτελείται από τέσσερα μέρη: τον πάροχο, το module, τη λειτουργία και το όνομα (`fbt:mach_kernel:ptrace:entry`). Αν δεν καθορίσετε κάποιο μέρος του ονόματος, το Dtrace θα εφαρμόσει αυτό το μέρος ως wildcard.

Για να ρυθμίσετε το DTrace ώστε να ενεργοποιεί τις πρόβες και να καθορίσετε ποιες ενέργειες να εκτελούνται όταν ενεργοποιούνται, θα χρειαστεί να χρησιμοποιήσουμε τη γλώσσα D.

Μια πιο λεπτομερής εξήγηση και περισσότερα παραδείγματα μπορείτε να βρείτε στο [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Παραδείγματα

Εκτελέστε `man -k dtrace` για να καταγράψετε τα **διαθέσιμα σενάρια DTrace**. Παράδειγμα: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- σενάριο
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

Είναι μια εγκατάσταση παρακολούθησης πυρήνα. Οι τεκμηριωμένοι κωδικοί μπορούν να βρεθούν στο **`/usr/share/misc/trace.codes`**.

Εργαλεία όπως το `latency`, `sc_usage`, `fs_usage` και `trace` το χρησιμοποιούν εσωτερικά.

Για να αλληλεπιδράσετε με το `kdebug`, χρησιμοποιείται το `sysctl` πάνω από το namespace `kern.kdebug` και οι MIBs που πρέπει να χρησιμοποιηθούν μπορούν να βρεθούν στο `sys/sysctl.h`, με τις συναρτήσεις να είναι υλοποιημένες στο `bsd/kern/kdebug.c`.

Για να αλληλεπιδράσετε με το kdebug με έναν προσαρμοσμένο πελάτη, αυτά είναι συνήθως τα βήματα:

- Αφαιρέστε τις υπάρχουσες ρυθμίσεις με KERN_KDSETREMOVE
- Ρυθμίστε την παρακολούθηση με KERN_KDSETBUF και KERN_KDSETUP
- Χρησιμοποιήστε KERN_KDGETBUF για να αποκτήσετε τον αριθμό των εγγραφών του buffer
- Αποκτήστε τον δικό σας πελάτη από την παρακολούθηση με KERN_KDPINDEX
- Ενεργοποιήστε την παρακολούθηση με KERN_KDENABLE
- Διαβάστε το buffer καλώντας KERN_KDREADTR
- Για να αντιστοιχίσετε κάθε νήμα με τη διαδικασία του, καλέστε KERN_KDTHRMAP.

Για να αποκτήσετε αυτές τις πληροφορίες, είναι δυνατόν να χρησιμοποιήσετε το εργαλείο της Apple **`trace`** ή το προσαρμοσμένο εργαλείο [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Σημειώστε ότι το Kdebug είναι διαθέσιμο μόνο για 1 πελάτη τη φορά.** Έτσι, μόνο ένα εργαλείο που υποστηρίζεται από k-debug μπορεί να εκτελείται ταυτόχρονα.

### ktrace

Οι APIs `ktrace_*` προέρχονται από το `libktrace.dylib`, το οποίο περιτυλίγει αυτά του `Kdebug`. Στη συνέχεια, ένας πελάτης μπορεί απλά να καλέσει `ktrace_session_create` και `ktrace_events_[single/class]` για να ορίσει callbacks σε συγκεκριμένους κωδικούς και στη συνέχεια να το ξεκινήσει με `ktrace_start`.

Μπορείτε να το χρησιμοποιήσετε ακόμη και με **SIP ενεργοποιημένο**

Μπορείτε να χρησιμοποιήσετε ως πελάτες το εργαλείο `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Αυτό χρησιμοποιείται για την εκτέλεση προφίλ σε επίπεδο πυρήνα και είναι κατασκευασμένο χρησιμοποιώντας κλήσεις `Kdebug`.

Βασικά, ελέγχεται η παγκόσμια μεταβλητή `kernel_debug_active` και αν είναι ενεργοποιημένη καλεί τον `kperf_kdebug_handler` με τον κωδικό `Kdebug` και τη διεύθυνση του πλαισίου πυρήνα που καλεί. Αν ο κωδικός `Kdebug` ταιριάζει με έναν επιλεγμένο, αποκτά τις "ενέργειες" που έχουν ρυθμιστεί ως bitmap (ελέγξτε το `osfmk/kperf/action.h` για τις επιλογές).

Το kperf έχει επίσης έναν πίνακα MIB sysctl: (ως root) `sysctl kperf`. Αυτοί οι κωδικοί μπορούν να βρεθούν στο `osfmk/kperf/kperfbsd.c`.

Επιπλέον, ένα υποσύνολο της λειτουργικότητας του Kperf βρίσκεται στο `kpc`, το οποίο παρέχει πληροφορίες σχετικά με τους μετρητές απόδοσης της μηχανής.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) είναι ένα πολύ χρήσιμο εργαλείο για να ελέγξετε τις ενέργειες που σχετίζονται με τη διαδικασία που εκτελεί μια διαδικασία (για παράδειγμα, να παρακολουθήσετε ποιες νέες διαδικασίες δημιουργεί μια διαδικασία).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) είναι ένα εργαλείο που εκτυπώνει τις σχέσεις μεταξύ διαδικασιών.\
Πρέπει να παρακολουθήσετε το mac σας με μια εντολή όπως **`sudo eslogger fork exec rename create > cap.json`** (ο τερματικός που εκκινεί αυτό απαιτεί FDA). Και στη συνέχεια μπορείτε να φορτώσετε το json σε αυτό το εργαλείο για να δείτε όλες τις σχέσεις:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) επιτρέπει την παρακολούθηση γεγονότων αρχείων (όπως δημιουργία, τροποποιήσεις και διαγραφές) παρέχοντας λεπτομερείς πληροφορίες σχετικά με αυτά τα γεγονότα.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) είναι ένα εργαλείο GUI με την εμφάνιση και την αίσθηση που μπορεί να γνωρίζουν οι χρήστες Windows από το Microsoft Sysinternal’s _Procmon_. Αυτό το εργαλείο επιτρέπει την καταγραφή διαφόρων τύπων γεγονότων να ξεκινά και να σταματά, επιτρέπει τη φιλτράρισή τους κατά κατηγορίες όπως αρχείο, διαδικασία, δίκτυο, κ.λπ., και παρέχει τη δυνατότητα αποθήκευσης των καταγεγραμμένων γεγονότων σε μορφή json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) είναι μέρος των εργαλείων προγραμματιστών του Xcode – χρησιμοποιούνται για την παρακολούθηση της απόδοσης εφαρμογών, την αναγνώριση διαρροών μνήμης και την παρακολούθηση της δραστηριότητας του συστήματος αρχείων.

![](<../../../images/image (1138).png>)

### fs_usage

Επιτρέπει την παρακολούθηση ενεργειών που εκτελούνται από διαδικασίες:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) είναι χρήσιμο για να δείτε τις **βιβλιοθήκες** που χρησιμοποιούνται από ένα δυαδικό αρχείο, τα **αρχεία** που χρησιμοποιεί και τις **συνδέσεις** δικτύου.\
Επίσης ελέγχει τις διαδικασίες του δυαδικού αρχείου σε σχέση με το **virustotal** και δείχνει πληροφορίες για το δυαδικό αρχείο.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Στο [**αυτό το blog post**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) μπορείτε να βρείτε ένα παράδειγμα για το πώς να **αποσφαλματώσετε έναν εκτελούμενο δαίμονα** που χρησιμοποίησε **`PT_DENY_ATTACH`** για να αποτρέψει την αποσφαλμάτωση ακόμη και αν το SIP ήταν απενεργοποιημένο.

### lldb

**lldb** είναι το de **facto εργαλείο** για **αποσφαλμάτωση** δυαδικών αρχείων **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Μπορείτε να ορίσετε τη γεύση intel όταν χρησιμοποιείτε lldb δημιουργώντας ένα αρχείο με το όνομα **`.lldbinit`** στον φάκελο του σπιτιού σας με την εξής γραμμή:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Μέσα στο lldb, εκτελέστε μια διαδικασία με `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Εντολή</strong></td><td><strong>Περιγραφή</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Ξεκινά την εκτέλεση, η οποία θα συνεχιστεί αδιάκοπα μέχρι να χτυπήσει ένα breakpoint ή να τερματιστεί η διαδικασία.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Ξεκινά την εκτέλεση σταματώντας στο σημείο εισόδου</td></tr><tr><td><strong>continue (c)</strong></td><td>Συνεχίζει την εκτέλεση της διαδικασίας που αποσφαλματώνεται.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Εκτελεί την επόμενη εντολή. Αυτή η εντολή θα παραλείψει τις κλήσεις συναρτήσεων.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Εκτελεί την επόμενη εντολή. Σε αντίθεση με την εντολή nexti, αυτή η εντολή θα εισέλθει στις κλήσεις συναρτήσεων.</td></tr><tr><td><strong>finish (f)</strong></td><td>Εκτελεί τις υπόλοιπες εντολές στην τρέχουσα συνάρτηση (“frame”) και επιστρέφει και σταματά.</td></tr><tr><td><strong>control + c</strong></td><td>Παύει την εκτέλεση. Εάν η διαδικασία έχει εκτελεστεί (r) ή συνεχιστεί (c), αυτό θα προκαλέσει την παύση της διαδικασίας ...όπου κι αν εκτελείται αυτή τη στιγμή.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Οποιαδήποτε συνάρτηση ονομάζεται main</p><p><code>b &#x3C;binname>`main</code> #Κύρια συνάρτηση του bin</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Κύρια συνάρτηση του υποδεικνυόμενου bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Οποιαδήποτε μέθοδος NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Σπάσιμο σε όλες τις συναρτήσεις αυτής της βιβλιοθήκης</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Λίστα breakpoint</p><p><code>br e/dis &#x3C;num></code> #Ενεργοποίηση/Απενεργοποίηση breakpoint</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Λάβετε βοήθεια για την εντολή breakpoint</p><p>help memory write #Λάβετε βοήθεια για να γράψετε στη μνήμη</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Εμφανίζει τη μνήμη ως μια null-terminated συμβολοσειρά.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Εμφανίζει τη μνήμη ως εντολή assembly.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Εμφανίζει τη μνήμη ως byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Αυτό θα εκτυπώσει το αντικείμενο που αναφέρεται από την παράμετρο</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Σημειώστε ότι οι περισσότερες από τις APIs ή μεθόδους Objective-C της Apple επιστρέφουν αντικείμενα, και επομένως θα πρέπει να εμφανίζονται μέσω της εντολής “print object” (po). Εάν το po δεν παράγει μια ουσιαστική έξοδο, χρησιμοποιήστε <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Γράψτε AAAA σε αυτή τη διεύθυνση<br>memory write -f s $rip+0x11f+7 "AAAA" #Γράψτε AAAA στη διεύθυνση</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Διαχωρισμός της τρέχουσας συνάρτησης</p><p>dis -n &#x3C;funcname> #Διαχωρισμός της συνάρτησης</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Διαχωρισμός της συνάρτησης<br>dis -c 6 #Διαχωρισμός 6 γραμμών<br>dis -c 0x100003764 -e 0x100003768 # Από μία προσθήκη μέχρι την άλλη<br>dis -p -c 4 # Ξεκινήστε στη τρέχουσα διεύθυνση διαχωρίζοντας</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Ελέγξτε τον πίνακα 3 στοιχείων στο x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Εκτυπώνει το χάρτη της μνήμης της τρέχουσας διαδικασίας</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #Λάβετε τη διεύθυνση όλων των συμβόλων από το CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Όταν καλείτε τη συνάρτηση **`objc_sendMsg`**, το **rsi** register περιέχει το **όνομα της μεθόδου** ως μια null-terminated (“C”) συμβολοσειρά. Για να εκτυπώσετε το όνομα μέσω lldb κάντε:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Αντι-Δυναμική Ανάλυση

#### Ανίχνευση VM

- Η εντολή **`sysctl hw.model`** επιστρέφει "Mac" όταν ο **host είναι MacOS** αλλά κάτι διαφορετικό όταν είναι VM.
- Παίζοντας με τις τιμές των **`hw.logicalcpu`** και **`hw.physicalcpu`** ορισμένα κακόβουλα λογισμικά προσπαθούν να ανιχνεύσουν αν είναι VM.
- Ορισμένα κακόβουλα λογισμικά μπορούν επίσης να **ανιχνεύσουν** αν η μηχανή είναι **VMware** με βάση τη διεύθυνση MAC (00:50:56).
- Είναι επίσης δυνατό να βρείτε **αν μια διαδικασία αποσφαλματώνεται** με έναν απλό κώδικα όπως:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //η διαδικασία αποσφαλματώνεται }`
- Μπορεί επίσης να καλέσει την κλήση συστήματος **`ptrace`** με την σημαία **`PT_DENY_ATTACH`**. Αυτό **αποτρέπει** έναν αποσφαλματωτή από το να συνδεθεί και να παρακολουθήσει.
- Μπορείτε να ελέγξετε αν η λειτουργία **`sysctl`** ή **`ptrace`** εισάγεται (αλλά το κακόβουλο λογισμικό θα μπορούσε να την εισάγει δυναμικά)
- Όπως σημειώνεται σε αυτή τη γραφή, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Το μήνυμα Process # exited with **status = 45 (0x0000002d)** είναι συνήθως ένα προειδοποιητικό σημάδι ότι ο στόχος αποσφαλμάτωσης χρησιμοποιεί **PT_DENY_ATTACH**_”

## Core Dumps

Οι core dumps δημιουργούνται αν:

- `kern.coredump` sysctl είναι ρυθμισμένο σε 1 (κατά προεπιλογή)
- Αν η διαδικασία δεν ήταν suid/sgid ή `kern.sugid_coredump` είναι 1 (κατά προεπιλογή είναι 0)
- Ο περιορισμός `AS_CORE` επιτρέπει τη λειτουργία. Είναι δυνατό να καταστείλετε τη δημιουργία core dumps καλώντας `ulimit -c 0` και να τις επανενεργοποιήσετε με `ulimit -c unlimited`.

Σε αυτές τις περιπτώσεις, οι core dumps δημιουργούνται σύμφωνα με το `kern.corefile` sysctl και αποθηκεύονται συνήθως στο `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

Το ReportCrash **αναλύει τις διαδικασίες που καταρρέουν και αποθηκεύει μια αναφορά σφάλματος στο δίσκο**. Μια αναφορά σφάλματος περιέχει πληροφορίες που μπορούν να **βοηθήσουν έναν προγραμματιστή να διαγνώσει** την αιτία ενός σφάλματος.\
Για εφαρμογές και άλλες διαδικασίες **που εκτελούνται στο πλαίσιο launchd ανά χρήστη**, το ReportCrash εκτελείται ως LaunchAgent και αποθηκεύει τις αναφορές σφαλμάτων στους `~/Library/Logs/DiagnosticReports/` του χρήστη.\
Για δαίμονες, άλλες διαδικασίες **που εκτελούνται στο πλαίσιο launchd του συστήματος** και άλλες προνομιακές διαδικασίες, το ReportCrash εκτελείται ως LaunchDaemon και αποθηκεύει τις αναφορές σφαλμάτων στα `/Library/Logs/DiagnosticReports` του συστήματος.

Εάν ανησυχείτε για τις αναφορές σφαλματος **που αποστέλλονται στην Apple**, μπορείτε να τις απενεργοποιήσετε. Αν όχι, οι αναφορές σφαλματος μπορεί να είναι χρήσιμες για **να καταλάβετε πώς κατέρρευσε ένας διακομιστής**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Ύπνος

Κατά τη διάρκεια του fuzzing σε MacOS, είναι σημαντικό να μην επιτρέψετε στον Mac να κοιμηθεί:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Αποσύνδεση SSH

Εάν κάνετε fuzzing μέσω σύνδεσης SSH, είναι σημαντικό να βεβαιωθείτε ότι η συνεδρία δεν θα αποσυνδεθεί. Έτσι, αλλάξτε το αρχείο sshd_config με:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Εσωτερικοί Διαχειριστές

**Δείτε την παρακάτω σελίδα** για να μάθετε πώς μπορείτε να βρείτε ποια εφαρμογή είναι υπεύθυνη για **τη διαχείριση του καθορισμένου σχήματος ή πρωτοκόλλου:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Αριθμητική Δικτυακών Διαδικασιών

Αυτό είναι ενδιαφέρον για να βρείτε διαδικασίες που διαχειρίζονται δεδομένα δικτύου:
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

Λειτουργεί για εργαλεία CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Λειτουργεί "**απλά"** με εργαλεία GUI macOS. Σημειώστε ότι ορισμένες εφαρμογές macOS έχουν συγκεκριμένες απαιτήσεις όπως μοναδικά ονόματα αρχείων, τη σωστή επέκταση, χρειάζεται να διαβάσουν τα αρχεία από το sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Ορισμένα παραδείγματα:
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
### Περισσότερες Πληροφορίες Fuzzing MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Αναφορές

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
