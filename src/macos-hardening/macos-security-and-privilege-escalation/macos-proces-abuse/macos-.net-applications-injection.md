# macOS .Net Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια περίληψη της ανάρτησης [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Ελέγξτε την για περισσότερες λεπτομέρειες!**

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Establishing a Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

Η διαχείριση της επικοινωνίας μεταξύ του debugger και του debuggee στο .NET γίνεται από το [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Αυτό το συστατικό ρυθμίζει δύο ονομαστικούς σωλήνες ανά διαδικασία .NET όπως φαίνεται στο [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), οι οποίοι ξεκινούν μέσω του [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Αυτοί οι σωλήνες έχουν το επίθημα **`-in`** και **`-out`**.

Επισκεπτόμενος το **`$TMPDIR`** του χρήστη, μπορεί κανείς να βρει διαθέσιμα FIFOs αποσφαλμάτωσης για εφαρμογές .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) είναι υπεύθυνος για τη διαχείριση της επικοινωνίας από έναν debugger. Για να ξεκινήσει μια νέα συνεδρία αποσφαλμάτωσης, ένας debugger πρέπει να στείλει ένα μήνυμα μέσω του σωλήνα `out` που ξεκινά με μια δομή `MessageHeader`, λεπτομερώς στον πηγαίο κώδικα .NET:
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
Για να ζητήσετε μια νέα συνεδρία, αυτή η δομή συμπληρώνεται ως εξής, ορίζοντας τον τύπο μηνύματος σε `MT_SessionRequest` και την έκδοση πρωτοκόλλου στην τρέχουσα έκδοση:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Αυτή η κεφαλίδα αποστέλλεται στη συνέχεια στον στόχο χρησιμοποιώντας την κλήση συστήματος `write`, ακολουθούμενη από τη δομή `sessionRequestData` που περιέχει ένα GUID για τη συνεδρία:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Μια λειτουργία ανάγνωσης στον σωλήνα `out` επιβεβαιώνει την επιτυχία ή την αποτυχία της εγκαθίδρυσης της συνεδρίας αποσφαλμάτωσης:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Ανάγνωση Μνήμης

Μόλις καθοριστεί μια συνεδρία αποσφαλμάτωσης, η μνήμη μπορεί να διαβαστεί χρησιμοποιώντας τον τύπο μηνύματος [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Η συνάρτηση readMemory περιγράφεται λεπτομερώς, εκτελώντας τα απαραίτητα βήματα για να στείλει ένα αίτημα ανάγνωσης και να ανακτήσει την απάντηση:
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
Η πλήρης απόδειξη της έννοιας (POC) είναι διαθέσιμη [εδώ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Γράφοντας Μνήμη

Ομοίως, η μνήμη μπορεί να γραφτεί χρησιμοποιώντας τη λειτουργία `writeMemory`. Η διαδικασία περιλαμβάνει την ρύθμιση του τύπου μηνύματος σε `MT_WriteMemory`, καθορίζοντας τη διεύθυνση και το μήκος των δεδομένων, και στη συνέχεια στέλνοντας τα δεδομένα:
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
Η σχετική POC είναι διαθέσιμη [εδώ](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## .NET Core Εκτέλεση Κώδικα <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Για να εκτελέσετε κώδικα, πρέπει να εντοπίσετε μια περιοχή μνήμης με άδειες rwx, κάτι που μπορεί να γίνει χρησιμοποιώντας vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Η τοποθέτηση ενός σημείου για την επαναγραφή ενός δείκτη συνάρτησης είναι απαραίτητη, και στο .NET Core, αυτό μπορεί να γίνει στοχεύοντας τον **Dynamic Function Table (DFT)**. Αυτός ο πίνακας, που περιγράφεται στο [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), χρησιμοποιείται από το runtime για τις βοηθητικές συναρτήσεις JIT compilation.

Για συστήματα x64, η αναζήτηση υπογραφών μπορεί να χρησιμοποιηθεί για να βρεθεί μια αναφορά στο σύμβολο `_hlpDynamicFuncTable` στο `libcorclr.dll`.

Η συνάρτηση debugger `MT_GetDCB` παρέχει χρήσιμες πληροφορίες, συμπεριλαμβανομένης της διεύθυνσης μιας βοηθητικής συνάρτησης, `m_helperRemoteStartAddr`, που υποδεικνύει την τοποθεσία του `libcorclr.dll` στη μνήμη της διαδικασίας. Αυτή η διεύθυνση χρησιμοποιείται στη συνέχεια για να ξεκινήσει μια αναζήτηση για το DFT και να επαναγραφεί ένας δείκτης συνάρτησης με τη διεύθυνση του shellcode.

Ο πλήρης κώδικας POC για την ένεση στο PowerShell είναι προσβάσιμος [εδώ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Αναφορές

- [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

{{#include ../../../banners/hacktricks-training.md}}
