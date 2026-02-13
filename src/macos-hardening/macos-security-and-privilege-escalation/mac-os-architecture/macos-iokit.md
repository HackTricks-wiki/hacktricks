# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Το I/O Kit είναι ένα ανοιχτού κώδικα, αντικειμενοστραφές **device-driver framework** στον XNU πυρήνα, που διαχειρίζεται **dynamically loaded device drivers**. Επιτρέπει την προσθήκη modular κώδικα στον πυρήνα εν κινήσει, υποστηρίζοντας ποικίλο hardware.

Οι IOKit drivers ουσιαστικά **export functions from the kernel**. Οι τύποι παραμέτρων αυτών των συναρτήσεων (**types**) είναι **προκαθορισμένοι** και επαληθεύονται. Επιπλέον, παρόμοια με το XPC, το IOKit είναι απλώς ένα ακόμα επίπεδο πάνω από τα **Mach messages**.

**IOKit XNU kernel code** είναι ανοιχτού κώδικα από την Apple στο [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Επιπλέον, τα components χώρου χρήστη του IOKit είναι επίσης ανοιχτού κώδικα [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Ωστόσο, **κανένας IOKit driver** δεν είναι ανοιχτού κώδικα. Παρ' όλα αυτά, κατά καιρούς μια έκδοση ενός driver μπορεί να περιλαμβάνει σύμβολα που διευκολύνουν το debugging του. Δείτε πώς να [**get the driver extensions from the firmware here**](#ipsw)**.**

Γράφεται σε **C++**. Μπορείτε να πάρετε αποδιαμορφωμένα σύμβολα C++ με:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **εκτεθειμένες λειτουργίες** μπορεί να εκτελέσουν **επιπλέον ελέγχους ασφαλείας** όταν ένας client προσπαθεί να καλέσει μια συνάρτηση, αλλά σημειώστε ότι οι apps συνήθως είναι **περιορισμένες** από το **sandbox** όσον αφορά τις IOKit λειτουργίες με τις οποίες μπορούν να αλληλεπιδράσουν.

## Οδηγοί

Στο macOS βρίσκονται σε:

- **`/System/Library/Extensions`**
- Αρχεία KEXT ενσωματωμένα στο λειτουργικό σύστημα OS X.
- **`/Library/Extensions`**
- Αρχεία KEXT που εγκαθίστανται από λογισμικό τρίτων

Στο iOS βρίσκονται σε:

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
Μέχρι τον αριθμό 9 οι καταχωρημένοι drivers είναι **loaded in the address 0**. Αυτό σημαίνει ότι αυτοί δεν είναι πραγματικοί drivers αλλά **part of the kernel and they cannot be unloaded**.

In order to find specific extensions you can use:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Για να φορτώσετε και να αποφορτώσετε kernel extensions, κάντε:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Το **IORegistry** είναι ένα κρίσιμο μέρος του πλαισίου IOKit στα macOS και iOS, το οποίο χρησιμεύει ως βάση δεδομένων για την αναπαράσταση της διαμόρφωσης και της κατάστασης του υλικού του συστήματος. Είναι μια **ιεραρχική συλλογή αντικειμένων που αντιπροσωπεύουν όλο το υλικό και τους οδηγούς** που έχουν φορτωθεί στο σύστημα, και τις σχέσεις τους μεταξύ τους.

Μπορείτε να λάβετε το IORegistry χρησιμοποιώντας το cli **`ioreg`** για να το επιθεωρήσετε από την κονσόλα (ιδιαίτερα χρήσιμο για iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Μπορείτε να κατεβάσετε το **`IORegistryExplorer`** από τα **Xcode Additional Tools** στο [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) και να επιθεωρήσετε το **macOS IORegistry** μέσω μιας **γραφικής** διεπαφής.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Στο IORegistryExplorer, τα «επίπεδα» χρησιμοποιούνται για να οργανώσουν και να εμφανίσουν τις σχέσεις μεταξύ διαφορετικών αντικειμένων στο IORegistry. Κάθε επίπεδο αντιπροσωπεύει έναν συγκεκριμένο τύπο σχέσης ή μια ιδιαίτερη όψη της διαμόρφωσης υλικού και drivers του συστήματος. Ακολουθούν μερικά από τα κοινά επίπεδα που μπορεί να συναντήσετε στο IORegistryExplorer:

1. **IOService Plane**: Αυτό είναι το πιο γενικό επίπεδο, εμφανίζοντας τα service objects που αντιπροσωπεύουν drivers και nubs (κανάλια επικοινωνίας μεταξύ drivers). Δείχνει τις σχέσεις provider-client μεταξύ αυτών των αντικειμένων.
2. **IODeviceTree Plane**: Αυτό το επίπεδο αντιπροσωπεύει τις φυσικές συνδέσεις μεταξύ συσκευών όπως συνδέονται στο σύστημα. Συχνά χρησιμοποιείται για να οπτικοποιήσει την ιεραρχία των συσκευών που είναι συνδεδεμένες μέσω διαύλων όπως USB ή PCI.
3. **IOPower Plane**: Εμφανίζει αντικείμενα και τις σχέσεις τους σε όρους διαχείρισης ενέργειας. Μπορεί να δείξει ποια αντικείμενα επηρεάζουν την κατάσταση ισχύος άλλων, χρήσιμο για debugging θεμάτων σχετικών με την ενέργεια.
4. **IOUSB Plane**: Ειδικά εστιασμένο σε USB συσκευές και τις σχέσεις τους, δείχνοντας την ιεραρχία των USB hubs και των συνδεδεμένων συσκευών.
5. **IOAudio Plane**: Αυτό το επίπεδο προορίζεται για την αναπαράσταση audio συσκευών και των σχέσεών τους μέσα στο σύστημα.
6. ...

## Παράδειγμα κώδικα επικοινωνίας με driver

Ο παρακάτω κώδικας συνδέεται με την IOKit service `YourServiceNameHere` και καλεί τον selector 0:

- Πρώτα καλεί τις **`IOServiceMatching`** και **`IOServiceGetMatchingServices`** για να βρει την υπηρεσία.
- Στη συνέχεια δημιουργεί μια σύνδεση καλώντας **`IOServiceOpen`**.
- Τέλος καλεί μια συνάρτηση με **`IOConnectCallScalarMethod`** δείχνοντας τον selector 0 (ο selector είναι ο αριθμός που έχει ανατεθεί στη συνάρτηση που θέλετε να καλέσετε).

<details>
<summary>Παράδειγμα κλήσης από user-space σε driver selector</summary>
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

Υπάρχουν **άλλες** συναρτήσεις που μπορούν να χρησιμοποιηθούν για να καλέσουν IOKit συναρτήσεις πέρα από **`IOConnectCallScalarMethod`** όπως **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

Μπορείτε να αποκτήσετε αυτά, για παράδειγμα, από ένα [**firmware image (ipsw)**](#ipsw). Στη συνέχεια, φορτώστε το στο αγαπημένο σας decompiler.

Μπορείτε να ξεκινήσετε decompiling της **`externalMethod`** συνάρτησης καθώς αυτή είναι η driver function που θα λαμβάνει το call και θα καλεί τη σωστή function:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Αυτό το απαίσιο demagled call σημαίνει:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Σημειώστε πώς στον προηγούμενο ορισμό λείπει η παράμετρος **`self`**, ο σωστός ορισμός θα ήταν:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Στην πραγματικότητα, μπορείτε να βρείτε τον πραγματικό ορισμό στο [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
With this info you can rewrite Ctrl+Right -> `Edit function signature` and set the known types:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

The new decompiled code will look like:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

For the next step we need to have defined the **`IOExternalMethodDispatch2022`** struct. It's opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), you could define it:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Now, following the `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` you can see a lot of data:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Change the Data Type to **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

after the change:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

And as we now in there we have an **array of 7 elements** (check the final decompiled code), click to create an array of 7 elements:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

After the array is created you can see all the exported functions:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θυμάσαι, για να **call** μια **exported** function από το user space δεν χρειάζεται να καλέσεις το όνομα της function, αλλά τον **selector number**. Εδώ βλέπεις ότι ο selector **0** είναι η function **`initializeDecoder`**, ο selector **1** είναι **`startDecoder`**, ο selector **2** **`initializeEncoder`**...

## Recent IOKit attack surface (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) έδειξε ότι ένας permissive `IOHIDSystem` client μπορούσε να πάρει HID events ακόμα και με secure input· βεβαιώσου ότι οι `externalMethod` handlers επιβάλλουν entitlements αντί να ελέγχουν μόνο τον τύπο του user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 και CVE-2025-24257 διόρθωσαν OOB writes που ήταν προσβάσιμες από sandboxed apps που περνάνε malformed variable-length data σε GPU user clients· το συνηθισμένο bug είναι οι κακές περιοριστικές τιμές γύρω από τα `IOConnectCallStructMethod` arguments.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) επιβεβαίωσε ότι HID user clients παραμένουν vector για sandbox-escape· fuzz οποιονδήποτε driver εκθέτει keyboard/event queues.

### Quick triage & fuzzing tips

- Enumerate all external methods for a user client from userland to seed a fuzzer:
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
- When reversing, προσέξτε τα counts του `IOExternalMethodDispatch2022`. Ένα κοινό μοτίβο σφάλματος σε πρόσφατα CVE είναι ασυνεπές `structureInputSize`/`structureOutputSize` σε σχέση με το πραγματικό μήκος του `copyin`, οδηγώντας σε heap OOB στο `IOConnectCallStructMethod`.
- Sandbox reachability εξακολουθεί να εξαρτάται από entitlements. Πριν αφιερώσετε χρόνο σε έναν στόχο, ελέγξτε αν ο client επιτρέπεται από μια third‑party app:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Για σφάλματα GPU/iomfb, η αποστολή υπερμεγεθών πινάκων μέσω του `IOConnectCallMethod` συχνά αρκεί για να προκαλέσει λανθασμένα όρια. Ελάχιστο harness (selector X) για να προκαλέσει size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Αναφορές

- [Ενημερώσεις ασφάλειας της Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 σύνοψη](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Ενημερώσεις ασφάλειας της Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
