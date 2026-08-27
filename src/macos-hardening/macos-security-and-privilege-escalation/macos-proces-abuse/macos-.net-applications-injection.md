# Injection σε .Net Applications του macOS

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύνοψη του post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Δείτε το για περισσότερες λεπτομέρειες!**<sup>[[1]](#references)</sup>

## `DOTNET_STARTUP_HOOKS`

Οι .NET Core 3.0 και νεότερες εκδόσεις υποστηρίζουν τη μεταβλητή περιβάλλοντος `DOTNET_STARTUP_HOOKS`. Κάθε path πρέπει να προσδιορίζει ένα managed assembly που περιέχει έναν global τύπο `StartupHook` με μια μέθοδο `public static void Initialize()`. Ο host φορτώνει τα assemblies και καλεί τους initializers τους συγχρονισμένα, πριν από το `Main` entry point της εφαρμογής, παρέχοντας έλεγχο του περιβάλλοντος και σε ένα readable DLL ένα άμεσο pre-main code-execution primitive.<sup>[[2]](#references)</sup>
```csharp
// StartupHook.cs — compile as a class-library assembly.
using System.IO;

internal class StartupHook
{
public static void Initialize()
{
File.WriteAllText("/tmp/dotnet-startup-hook-executed", "executed\n");
}
}
```

```bash
dotnet new classlib -n StartupHookPayload -f net8.0
cp StartupHook.cs StartupHookPayload/Class1.cs
dotnet build StartupHookPayload -c Release

DOTNET_STARTUP_HOOKS="$PWD/StartupHookPayload/bin/Release/net8.0/StartupHookPayload.dll" \
dotnet /path/to/TargetApplication.dll
```
Το hook assembly πρέπει να είναι συμβατό με το runtime και τις dependencies της εφαρμογής. Τα relative paths που περιέχουν διαχωριστικά καταλόγων απορρίπτονται· χρησιμοποιήστε absolute path ή όνομα assembly που μπορεί να επιλυθεί από το default load context. Τα startup hooks είναι απενεργοποιημένα από προεπιλογή σε trimmed applications, ενώ custom native hosts ενδέχεται να παρέχουν απευθείας runtime properties αντί να κληρονομούν το environment.<sup>[[2]](#references)</sup>

Οι defensive launchers θα πρέπει να εκκαθαρίζουν το `DOTNET_STARTUP_HOOKS`, να αποτρέπουν μη αξιόπιστες εγγραφές σε application και shared assembly paths και να ελέγχουν ξεχωριστά τα self-contained και trimmed deployments.

## .NET Core Debugging <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Εγκαθίδρυση Debugging Session** <a href="#net-core-debugging" id="net-core-debugging"></a>

Η διαχείριση της επικοινωνίας μεταξύ debugger και debuggee στο .NET γίνεται από το [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Αυτό το component ρυθμίζει δύο named pipes για κάθε .NET process, όπως φαίνεται στο [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), τα οποία αρχικοποιούνται μέσω του [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Αυτά τα pipes έχουν τα suffixes **`-in`** και **`-out`**.

Με την επίσκεψη στο **`$TMPDIR`** του χρήστη, μπορεί κανείς να βρει debugging FIFOs διαθέσιμα για debugging .Net applications.

Το [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) είναι υπεύθυνο για τη διαχείριση της επικοινωνίας από έναν debugger. Για την έναρξη ενός νέου debugging session, ένας debugger πρέπει να στείλει ένα message μέσω του `out` pipe, το οποίο ξεκινά με ένα `MessageHeader` struct, όπως περιγράφεται στον source code του .NET:
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
Για να ζητηθεί μια νέα session, αυτό το struct συμπληρώνεται ως εξής, ορίζοντας τον τύπο μηνύματος σε `MT_SessionRequest` και την έκδοση του protocol στην τρέχουσα έκδοση:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Αυτή η κεφαλίδα αποστέλλεται στη συνέχεια στον στόχο χρησιμοποιώντας το syscall `write`, και ακολουθεί το struct `sessionRequestData`, που περιέχει ένα GUID για τη session:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Μια λειτουργία ανάγνωσης στο pipe `out` επιβεβαιώνει την επιτυχία ή την αποτυχία της εγκαθίδρυσης της συνεδρίας debugging:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Ανάγνωση μνήμης

Μόλις etablerωθεί μια debugging session, η μνήμη μπορεί να διαβαστεί χρησιμοποιώντας τον τύπο μηνύματος [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Η function readMemory περιγράφεται αναλυτικά και εκτελεί τα απαραίτητα βήματα για την αποστολή ενός read request και την ανάκτηση της response:
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
Η πλήρης proof of concept (POC) είναι διαθέσιμη [εδώ](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

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

## .NET Core Εκτέλεση Κώδικα <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Για την εκτέλεση κώδικα, πρέπει να εντοπιστεί μια περιοχή μνήμης με δικαιώματα rwx, κάτι που μπορεί να γίνει χρησιμοποιώντας το vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Ο εντοπισμός μιας τοποθεσίας για την overwrite ενός function pointer είναι απαραίτητος και στο .NET Core αυτό μπορεί να γίνει με στόχευση του **Dynamic Function Table (DFT)**. Ο πίνακας αυτός, ο οποίος περιγράφεται στο [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), χρησιμοποιείται από το runtime για helper functions του JIT compilation.

Σε συστήματα x64, μπορεί να χρησιμοποιηθεί signature hunting για την εύρεση μιας αναφοράς στο symbol `_hlpDynamicFuncTable` μέσα στο `libcorclr.dll`.

Η debugger function `MT_GetDCB` παρέχει χρήσιμες πληροφορίες, συμπεριλαμβανομένης της διεύθυνσης μιας helper function, `m_helperRemoteStartAddr`, η οποία υποδεικνύει την τοποθεσία του `libcorclr.dll` στη μνήμη της διεργασίας. Αυτή η διεύθυνση χρησιμοποιείται στη συνέχεια για την έναρξη αναζήτησης του DFT και την overwrite ενός function pointer με τη διεύθυνση του shellcode.

Ο πλήρης κώδικας POC για injection στο PowerShell είναι διαθέσιμος [εδώ](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## References

- [1] [Adam Chester (xpnsec) - Injection στο macOS μέσω Third Party Frameworks](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)
- [2] [Σχεδιασμός host startup hook του .NET runtime](https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md)
{{#include ../../../banners/hacktricks-training.md}}
