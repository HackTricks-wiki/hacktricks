# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το I/O Kit είναι ένα open-source, αντικειμενοστραφές **framework οδηγών συσκευών** στον πυρήνα XNU και διαχειρίζεται **δυναμικά φορτωμένους οδηγούς συσκευών**. Επιτρέπει την προσθήκη modular κώδικα στον πυρήνα on-the-fly, υποστηρίζοντας διαφορετικό hardware.

Οι IOKit drivers ουσιαστικά **εξάγουν functions από τον πυρήνα**. Οι **τύποι** των παραμέτρων αυτών των functions είναι **προκαθορισμένοι** και επαληθεύονται. Επιπλέον, όπως και το XPC, το IOKit είναι απλώς ένα ακόμη layer **πάνω από Mach messages**.

Ο **κώδικας του IOKit στον πυρήνα XNU** είναι open-sourced από την Apple στη διεύθυνση [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Επιπλέον, τα components του IOKit στον user space είναι επίσης open-source στη διεύθυνση [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ωστόσο, **κανένας IOKit driver** δεν είναι open-source. Παρ' όλα αυτά, κατά διαστήματα μια έκδοση ενός driver μπορεί να περιλαμβάνει symbols που διευκολύνουν το debugging του. Δείτε εδώ πώς να [**λάβετε τα driver extensions από το firmware**](#ipsw)**.**

Είναι γραμμένο σε **C++**. Μπορείτε να λάβετε demangled C++ symbols με:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Οι **exposed functions** του IOKit μπορούν να εκτελούν **επιπλέον ελέγχους ασφαλείας** όταν ένας client προσπαθεί να καλέσει μια function, αλλά σημειώστε ότι οι εφαρμογές συνήθως **περιορίζονται** από το **sandbox** ως προς τις functions του IOKit με τις οποίες μπορούν να αλληλεπιδρούν.

## Drivers

Στο macOS βρίσκονται στα:

- **`/System/Library/Extensions`**
- Αρχεία KEXT ενσωματωμένα στο λειτουργικό σύστημα OS X.
- **`/Library/Extensions`**
- Αρχεία KEXT που εγκαθίστανται από λογισμικό τρίτων

Στο iOS βρίσκονται στα:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Μέχρι τον αριθμό 9, οι listed drivers είναι **loaded στη διεύθυνση 0**. Αυτό σημαίνει ότι δεν είναι πραγματικοί drivers, αλλά **μέρος του kernel και δεν μπορούν να unloaded**.

Για να βρείτε συγκεκριμένα extensions, μπορείτε να χρησιμοποιήσετε:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Για τη φόρτωση και εκφόρτωση των kernel extensions, εκτελέστε:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Το **IORegistry** αποτελεί σημαντικό τμήμα του framework IOKit στο macOS και το iOS και λειτουργεί ως βάση δεδομένων για την αναπαράσταση της διαμόρφωσης και της κατάστασης του hardware του συστήματος. Είναι μια **ιεραρχική συλλογή αντικειμένων που αναπαριστούν όλο το hardware και τους drivers** που έχουν φορτωθεί στο σύστημα, καθώς και τις μεταξύ τους σχέσεις.

Μπορείτε να λάβετε το IORegistry χρησιμοποιώντας το cli **`ioreg`**, για να το επιθεωρήσετε από την κονσόλα (ιδιαίτερα χρήσιμο στο iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Μπορείτε να κατεβάσετε το **`IORegistryExplorer`** από τα **Xcode Additional Tools** στη διεύθυνση [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) και να επιθεωρήσετε το **macOS IORegistry** μέσω ενός **γραφικού** περιβάλλοντος.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Στο IORegistryExplorer, τα "planes" χρησιμοποιούνται για την οργάνωση και την προβολή των σχέσεων μεταξύ διαφορετικών αντικειμένων στο IORegistry. Κάθε plane αναπαριστά έναν συγκεκριμένο τύπο σχέσης ή μια συγκεκριμένη άποψη της διαμόρφωσης του hardware και των drivers του συστήματος. Ακολουθούν ορισμένα από τα συνηθισμένα planes που μπορεί να συναντήσετε στο IORegistryExplorer:

1. **IOService Plane**: Πρόκειται για το πιο γενικό plane, το οποίο εμφανίζει τα service objects που αναπαριστούν drivers και nubs (κανάλια επικοινωνίας μεταξύ drivers). Εμφανίζει τις σχέσεις provider-client μεταξύ αυτών των αντικειμένων.
2. **IODeviceTree Plane**: Αυτό το plane αναπαριστά τις φυσικές συνδέσεις μεταξύ των συσκευών, καθώς αυτές συνδέονται στο σύστημα. Χρησιμοποιείται συχνά για την οπτικοποίηση της ιεραρχίας των συσκευών που συνδέονται μέσω buses όπως USB ή PCI.
3. **IOPower Plane**: Εμφανίζει αντικείμενα και τις σχέσεις τους σε ό,τι αφορά το power management. Μπορεί να δείξει ποια αντικείμενα επηρεάζουν την κατάσταση ισχύος άλλων αντικειμένων, κάτι χρήσιμο για το debugging προβλημάτων που σχετίζονται με την ισχύ.
4. **IOUSB Plane**: Εστιάζει ειδικά σε USB devices και στις σχέσεις τους, εμφανίζοντας την ιεραρχία των USB hubs και των συνδεδεμένων συσκευών.
5. **IOAudio Plane**: Αυτό το plane χρησιμοποιείται για την αναπαράσταση των audio devices και των σχέσεών τους μέσα στο σύστημα.
6. ...

## Παράδειγμα κώδικα Driver Comm

Ο ακόλουθος κώδικας συνδέεται στην υπηρεσία IOKit `YourServiceNameHere` και καλεί τον selector 0:

- Αρχικά καλεί τις **`IOServiceMatching`** και **`IOServiceGetMatchingServices`** για να εντοπίσει την υπηρεσία.
- Στη συνέχεια δημιουργεί μια σύνδεση καλώντας την **`IOServiceOpen`**.
- Τέλος, καλεί μια function με την **`IOConnectCallScalarMethod`**, υποδεικνύοντας τον selector 0 (ο selector είναι ο αριθμός που έχει αντιστοιχιστεί στη function που θέλετε να καλέσετε).

<details>
<summary>Παράδειγμα κλήσης από user-space σε selector ενός driver</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

Υπάρχουν **και άλλες** functions που μπορούν να χρησιμοποιηθούν για την κλήση functions του IOKit, εκτός από την **`IOConnectCallScalarMethod`**, όπως οι **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

Μπορείτε, για παράδειγμα, να τις αποκτήσετε από ένα [**firmware image (ipsw)**](#ipsw). Στη συνέχεια, φορτώστε το στον decompiler της προτίμησής σας.

Μπορείτε να ξεκινήσετε κάνοντας decompile τη function **`externalMethod`**, καθώς αυτή είναι η driver function που θα λαμβάνει την κλήση και θα καλεί τη σωστή function:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Αυτή η απαίσια κλήση, μετά το demangling, σημαίνει:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Σημειώστε ότι στον προηγούμενο ορισμό παραλείπεται η παράμετρος **`self`**, ο σωστός ορισμός θα ήταν:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Στην πραγματικότητα, μπορείτε να βρείτε τον πραγματικό ορισμό στη διεύθυνση [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Με αυτές τις πληροφορίες μπορείς να ξαναγράψεις το Ctrl+Right -> `Edit function signature` και να ορίσεις τους γνωστούς τύπους:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Ο νέος decompiled κώδικας θα έχει την εξής μορφή:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Για το επόμενο βήμα πρέπει να έχουμε ορίσει το struct **`IOExternalMethodDispatch2022`**. Είναι opensource στο [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), και μπορείς να το ορίσεις:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Τώρα, ακολουθώντας το `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, μπορείς να δεις πολλά δεδομένα:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Άλλαξε το Data Type σε **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

μετά την αλλαγή:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Και, όπως γνωρίζουμε πλέον, εκεί υπάρχει ένα **array 7 στοιχείων** (έλεγξε τον τελικό decompiled κώδικα). Κάνε κλικ για να δημιουργήσεις ένα array 7 στοιχείων:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Αφού δημιουργηθεί το array, μπορείς να δεις όλες τις exported functions:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θυμάσαι, για να **καλέσουμε** μια **exported** function από user space δεν χρειάζεται να καλέσουμε το όνομα της function, αλλά τον **selector number**. Εδώ μπορείς να δεις ότι ο selector **0** είναι η function **`initializeDecoder`**, ο selector **1** είναι η **`startDecoder`**, ο selector **2** η **`initializeEncoder`**...

## Πρόσφατη επιφάνεια επίθεσης του IOKit (2023–2025)

- **Keystroke capture μέσω του IOHIDFamily** – Το CVE-2024-27799 (14.5) έδειξε ότι ένας permissive client του `IOHIDSystem` μπορούσε να αρπάξει HID events ακόμη και με ενεργοποιημένο το secure input. Βεβαιώσου ότι οι handlers του `externalMethod` επιβάλλουν entitlements αντί να βασίζονται μόνο στον τύπο του user-client.<sup>[2]</sup>
- **Memory corruption στο IOGPUFamily** – Τα CVE-2024-44197 και CVE-2025-24257 διόρθωσαν OOB writes που ήταν προσβάσιμα από sandboxed apps οι οποίες περνούσαν malformed variable-length data σε GPU user clients. Το συνηθισμένο bug είναι ο ανεπαρκής έλεγχος ορίων γύρω από τα arguments του `IOConnectCallStructMethod`.<sup>[1]</sup>
- **Legacy keystroke monitoring** – Το CVE-2023-42891 (14.2) επιβεβαίωσε ότι οι HID user clients παραμένουν vector για sandbox escape. Κάνε fuzzing σε οποιονδήποτε driver εκθέτει keyboard/event queues.<sup>[3]</sup>

### Γρήγορες συμβουλές για triage και fuzzing

- Κάνε enumerate όλες τις external methods για έναν user client από userland, ώστε να τροφοδοτήσεις έναν fuzzer:
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Κατά το reversing, δώστε προσοχή στα counts του `IOExternalMethodDispatch2022`. Ένα συνηθισμένο bug pattern σε πρόσφατα CVE είναι η ασυνέπεια μεταξύ των `structureInputSize`/`structureOutputSize` και του πραγματικού μήκους `copyin`, που οδηγεί σε heap OOB στο `IOConnectCallStructMethod`.
- Η δυνατότητα πρόσβασης από το Sandbox εξακολουθεί να εξαρτάται από τα entitlements. Πριν αφιερώσετε χρόνο σε έναν target, ελέγξτε αν ο client επιτρέπεται από εφαρμογή τρίτου μέρους:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Για bugs σε GPU/iomfb, η μεταβίβαση υπερμεγεθών arrays μέσω του `IOConnectCallMethod` συχνά αρκεί για την ενεργοποίηση εσφαλμένων ελέγχων ορίων. Ελάχιστο harness (selector X) για την ενεργοποίηση σύγχυσης μεγέθους:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Οδηγοί σε χώρο χρήστη

### Βασικές πληροφορίες

Το **DriverKit** είναι η αντικατάσταση των kernel extensions (kexts) από την Apple σε χώρο χρήστη, η οποία εισήχθη στο macOS 10.15. Τα binaries του DriverKit (bundles `.dext`) εκτελούνται ως processes σε χώρο χρήστη, αλλά επικοινωνούν απευθείας με τον kernel μέσω μιας προνομιούχας διεπαφής IOKit.

Οι επεκτάσεις DriverKit διαχειρίζονται hardware:
- **USB** controllers και συσκευές
- **Thunderbolt** / συσκευές PCIe
- **HID** (πληκτρολόγια, ποντίκια, game controllers)
- **Audio** hardware
- **Networking** interfaces
- **Serial** και **Block Storage** συσκευές

Σε αντίθεση με τα kexts (τα οποία απαιτούσαν εκκίνηση με απενεργοποιημένο το SIP ή notarization), οι επεκτάσεις DriverKit εγκαθίστανται μέσω του `SystemExtensions.framework` και απαιτούν μόνο **έγκριση χρήστη μία φορά**.

### Εντοπισμός και Απαρίθμηση
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Επιπτώσεις στην ασφάλεια

> [!WARNING]
> Τα binaries του DriverKit διαθέτουν **άμεσο κανάλι επικοινωνίας με τον kernel**. Η αποστολή malformed μηνυμάτων μέσω αυτού του καναλιού μπορεί να ενεργοποιήσει vulnerabilities του kernel. Κάθε driver καταχωρίζει συγκεκριμένες user-client classes και κλήσεις `IOConnectCallMethod` με malformed ορίσματα μπορούν να προκαλέσουν καταστροφή μνήμης του kernel.

**Επιφάνεια επίθεσης:**
1. **Kernel IOKit message fuzzing** — Κάθε DriverKit user-client εκθέτει selectors που μπορούν να κληθούν από το user space. Malformed ορίσματα ενεργοποιούν kernel bugs.
2. **USB device spoofing** — Ένα compromised USB DriverKit binary μπορεί να παρουσιάσει ένα malicious USB device profile (π.χ. να προσομοιώσει ένα keyboard για HID injection).
3. **DMA attacks** — Τα PCIe/Thunderbolt DriverKit extensions έχουν πιθανή πρόσβαση DMA στη physical memory.
4. **Persistence** — Μόλις εγκατασταθούν ως system extension, τα DriverKit binaries παραμένουν ενεργά μετά από reboot και app updates.

### DriverKit IOKit User-Client Fuzzing
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### CVE του DriverKit

| CVE | Περιγραφή |
|---|---|
| CVE-2022-26766 | Ευπάθεια στη στοίβα USB του DriverKit — εκτέλεση κώδικα στον kernel |
| CVE-2021-30838 | Σύγχυση τύπου στο user-client του IOKit σε graphic drivers |
| CVE-2024-44197 | OOB write στο IOGPUFamily μέσω κακοσχηματισμένων ορισμάτων του DriverKit |

## Αναφορές

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – σύνοψη του IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
