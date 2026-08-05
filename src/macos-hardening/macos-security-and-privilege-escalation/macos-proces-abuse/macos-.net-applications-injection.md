# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύνοψη της ανάρτησης [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Δείτε την για περισσότερες λεπτομέρειες!**<sup>[1]</sup>

## Αποσφαλμάτωση .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Εγκαθίδρυση μιας συνεδρίας αποσφαλμάτωσης** <a href="#net-core-debugging" id="net-core-debugging"></a>

Η διαχείριση της επικοινωνίας μεταξύ debugger και debuggee στο .NET γίνεται από το [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Αυτό το component δημιουργεί δύο named pipes ανά .NET process, όπως φαίνεται στο [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), τα οποία αρχικοποιούνται μέσω του [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Αυτά τα pipes έχουν ως κατάληξη τα **`-in`** και **`-out`**.

Με την επίσκεψη στο **`$TMPDIR`** του χρήστη, μπορεί κανείς να βρει διαθέσιμα debugging FIFOs για την αποσφαλμάτωση εφαρμογών .Net.

Το [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) είναι υπεύθυνο για τη διαχείριση της επικοινωνίας από έναν debugger. Για την έναρξη μιας νέας συνεδρίας αποσφαλμάτωσης, ένας debugger πρέπει να στείλει ένα μήνυμα μέσω του pipe `out`, το οποίο ξεκινά με ένα struct `MessageHeader`, όπως περιγράφεται στον πηγαίο κώδικα του .NET:
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Για να ζητηθεί μια νέα session, αυτή η struct συμπληρώνεται ως εξής, ορίζοντας τον τύπο μηνύματος σε `MT_SessionRequest` και την έκδοση του protocol στην τρέχουσα έκδοση:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Αυτή η επικεφαλίδα αποστέλλεται στη συνέχεια στον στόχο χρησιμοποιώντας το syscall `write`, ακολουθούμενη από το struct `sessionRequestData`, το οποίο περιέχει ένα GUID για τη session:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Μια λειτουργία ανάγνωσης στο pipe `out` επιβεβαιώνει την επιτυχία ή την αποτυχία εγκαθίδρυσης της debugging session:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Ανάγνωση μνήμης

Μόλις εγκατασταθεί μια debugging session, η μνήμη μπορεί να διαβαστεί χρησιμοποιώντας τον τύπο μηνύματος [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Η συνάρτηση `readMemory` περιγράφεται αναλυτικά και εκτελεί τα απαραίτητα βήματα για την αποστολή ενός read request και την ανάκτηση της απόκρισης:
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
Το πλήρες proof of concept (POC) είναι διαθέσιμο [εδώ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Εγγραφή στη μνήμη

Παρομοίως, η μνήμη μπορεί να εγγραφεί χρησιμοποιώντας τη συνάρτηση `writeMemory`. Η διαδικασία περιλαμβάνει τον ορισμό του τύπου μηνύματος σε `MT_WriteMemory`, τον καθορισμό της διεύθυνσης και του μήκους των δεδομένων και, στη συνέχεια, την αποστολή των δεδομένων:
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
Το σχετικό POC είναι διαθέσιμο [εδώ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Εκτέλεση κώδικα .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Για την εκτέλεση κώδικα, πρέπει να εντοπιστεί μια περιοχή μνήμης με δικαιώματα rwx, κάτι που μπορεί να γίνει χρησιμοποιώντας το vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Ο εντοπισμός ενός σημείου για την overwrite ενός function pointer είναι απαραίτητος και στο .NET Core αυτό μπορεί να γίνει με στόχευση του **Dynamic Function Table (DFT)**. Ο συγκεκριμένος πίνακας, ο οποίος περιγράφεται στο [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), χρησιμοποιείται από το runtime για helper functions του JIT compilation.

Σε συστήματα x64, μπορεί να χρησιμοποιηθεί signature hunting για τον εντοπισμό μιας αναφοράς στο symbol `_hlpDynamicFuncTable` στο `libcorclr.dll`.

Η debugger function `MT_GetDCB` παρέχει χρήσιμες πληροφορίες, συμπεριλαμβανομένης της διεύθυνσης μιας helper function, `m_helperRemoteStartAddr`, η οποία υποδεικνύει τη θέση του `libcorclr.dll` στη μνήμη της διεργασίας. Αυτή η διεύθυνση χρησιμοποιείται στη συνέχεια για την έναρξη αναζήτησης του DFT και την overwrite ενός function pointer με τη διεύθυνση του shellcode.

Ο πλήρης κώδικας POC για injection στο PowerShell είναι διαθέσιμος [εδώ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Αναφορές

- [1] [Adam Chester (xpnsec) - macOS Injection μέσω Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
