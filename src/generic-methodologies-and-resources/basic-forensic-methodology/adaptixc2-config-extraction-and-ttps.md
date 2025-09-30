# AdaptixC2 Εξαγωγή διαμόρφωσης και TTPs

{{#include ../../banners/hacktricks-training.md}}

Το AdaptixC2 είναι ένα modular, open‑source framework post‑exploitation/C2 με Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) και υποστήριξη BOF. Αυτή η σελίδα τεκμηριώνει:
- Πώς η RC4‑packed διαμόρφωσή του ενσωματώνεται και πώς να την εξαγάγετε από beacons
- Δείκτες δικτύου/προφίλ για HTTP/SMB/TCP listeners
- Κοινές TTPs για loader και persistence που παρατηρήθηκαν στο πεδίο, με links προς σχετικές σελίδες τεχνικών για Windows

## Beacon profiles and fields

Το AdaptixC2 υποστηρίζει τρεις κύριους τύπους beacon:
- BEACON_HTTP: web C2 με ρυθμιζόμενους servers/ports/SSL, method, URI, headers, user‑agent, και ένα custom parameter name
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, προαιρετικά με ένα prepended marker για να αποπροσανατολίσει την έναρξη του πρωτοκόλλου

Τυπικά πεδία προφίλ που παρατηρούνται σε HTTP beacon configs (μετά την αποκρυπτογράφηση):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – χρησιμοποιούνται για να αναλύσουν τα μεγέθη των αποκρίσεων
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Παράδειγμα προεπιλεγμένου HTTP profile (από ένα beacon build):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["172.16.196.1"],
"ports": [4443],
"http_method": "POST",
"uri": "/uri.php",
"parameter": "X-Beacon-Id",
"user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 2,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
Παρατηρήθηκε κακόβουλο προφίλ HTTP (πραγματική επίθεση):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["tech-system[.]online"],
"ports": [443],
"http_method": "POST",
"uri": "/endpoint/api",
"parameter": "X-App-Id",
"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 4,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
## Κρυπτογραφημένη συσκευασία διαμόρφωσης και διαδρομή φόρτωσης

Όταν ο χειριστής κάνει κλικ στο Create στον builder, το AdaptixC2 ενσωματώνει το κρυπτογραφημένο προφίλ ως tail blob στο beacon. Η μορφή είναι:
- 4 bytes: μέγεθος διαμόρφωσης (uint32, little‑endian)
- N bytes: RC4‑κρυπτογραφημένα δεδομένα διαμόρφωσης
- 16 bytes: RC4 κλειδί

Ο beacon loader αντιγράφει το 16‑byte κλειδί από το τέλος και RC4‑αποκρυπτογραφεί το μπλοκ των N‑byte επί τόπου:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- Η ολόκληρη δομή συχνά βρίσκεται μέσα στο τμήμα .rdata του PE.
- Η εξαγωγή είναι ντετερμινιστική: read size, read ciphertext of that size, read the 16‑byte key placed immediately after, then RC4‑decrypt.

## Διαδικασία εξαγωγής διαμόρφωσης (αμυνόμενοι)

Γράψτε ένα εργαλείο εξαγωγής που μιμείται τη λογική του beacon:
1) Εντοπίστε το blob μέσα στο PE (συνήθως .rdata). Μια πρακτική προσέγγιση είναι να σαρώσετε το .rdata για μια πιθανή διάταξη [size|ciphertext|16‑byte key] και να δοκιμάσετε RC4.
2) Διαβάστε τα πρώτα 4 bytes → size (uint32 LE).
3) Διαβάστε τα επόμενα N=size bytes → ciphertext.
4) Διαβάστε τα τελικά 16 bytes → RC4 key.
5) RC4‑decrypt το ciphertext. Έπειτα αναλύστε το plain profile ως:
- u32/boolean scalars όπως αναφέρθηκαν παραπάνω
- length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
- arrays: servers_count followed by that many [string, u32 port] pairs

Minimal Python proof‑of‑concept (standalone, χωρίς εξωτερικές εξαρτήσεις) που λειτουργεί με ένα προ‑εξαγόμενο blob:
```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
S = list(range(256))
j = 0
for i in range(256):
j = (j + S[i] + key[i % len(key)]) & 0xFF
S[i], S[j] = S[j], S[i]
i = j = 0
out = bytearray()
for b in data:
i = (i + 1) & 0xFF
j = (j + S[i]) & 0xFF
S[i], S[j] = S[j], S[i]
K = S[(S[i] + S[j]) & 0xFF]
out.append(b ^ K)
return bytes(out)

class P:
def __init__(self, buf: bytes):
self.b = buf; self.o = 0
def u32(self) -> int:
v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
def u8(self) -> int:
v = self.b[self.o]; self.o += 1; return v
def s(self) -> str:
L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
p = P(plain)
cfg = {}
cfg['agent_type']    = p.u32()
cfg['use_ssl']       = bool(p.u8())
n                    = p.u32()
cfg['servers']       = []
cfg['ports']         = []
for _ in range(n):
cfg['servers'].append(p.s())
cfg['ports'].append(p.u32())
cfg['http_method']   = p.s()
cfg['uri']           = p.s()
cfg['parameter']     = p.s()
cfg['user_agent']    = p.s()
cfg['http_headers']  = p.s()
cfg['ans_pre_size']  = p.u32()
cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
cfg['kill_date']     = p.u32()
cfg['working_time']  = p.u32()
cfg['sleep_delay']   = p.u32()
cfg['jitter_delay']  = p.u32()
cfg['listener_type'] = 0
cfg['download_chunk_size'] = 0x19000
return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```
Tips:
- Κατά την αυτοματοποίηση, χρησιμοποιήστε έναν PE parser για να διαβάσετε το .rdata και στη συνέχεια εφαρμόστε ένα sliding window: για κάθε offset o, δοκιμάστε size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt και ελέγξτε ότι τα string fields αποκωδικοποιούνται ως UTF‑8 και ότι τα μήκη είναι λογικά.
- Αναλύστε SMB/TCP προφίλ ακολουθώντας τις ίδιες length‑prefixed συμβάσεις.

## Network fingerprinting and hunting

HTTP
- Συνηθισμένο: POST σε URIs επιλεγμένα από τον operator (π.χ., /uri.php, /endpoint/api)
- Προσαρμοσμένη παράμετρος header που χρησιμοποιείται για το beacon ID (π.χ., X‑Beacon‑Id, X‑App‑Id)
- User‑agents που μιμούνται το Firefox 20 ή σύγχρονες Chrome builds
- Ρυθμός polling ορατός μέσω sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners για intranet C2 όπου το web egress είναι περιορισμένο
- TCP beacons μπορεί να προθέτουν μερικά bytes πριν την κίνηση για να συγκαλύψουν την έναρξη του πρωτοκόλλου

## Loader and persistence TTPs seen in incidents

PowerShell loaders σε μνήμη (in‑memory)
- Κατεβάζουν payloads σε Base64/XOR (Invoke‑RestMethod / WebClient)
- Κάνουν allocate unmanaged memory, αντιγράφουν shellcode, αλλάζουν το protection σε 0x40 (PAGE_EXECUTE_READWRITE) μέσω VirtualProtect
- Εκτέλεση μέσω .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Συντόμευση στο Startup (.lnk) για επανεκκίνηση του loader κατά το logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), συχνά με ονόματα που ακούγονται benign όπως "Updater" για να εκκινήσει το loader.ps1
- DLL search‑order hijack με τοποθέτηση msimg32.dll στο %APPDATA%\Microsoft\Windows\Templates για ευάλωτες διεργασίες

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- Περιπτώσεις PowerShell με μεταβάσεις RW→RX: VirtualProtect σε PAGE_EXECUTE_READWRITE μέσα σε powershell.exe
- Δυναμικά πρότυπα invocation (GetDelegateForFunctionPointer)
- Startup .lnk στον φάκελο Startup του χρήστη ή στους κοινόχρηστους φακέλους Startup
- Υποψιάζoμενα Run keys (π.χ., "Updater"), και ονόματα loader όπως update.ps1/loader.ps1
- Διαδρομές DLL εγγράψιμες από τον χρήστη κάτω από %APPDATA%\Microsoft\Windows\Templates που περιέχουν msimg32.dll

## Notes on OpSec fields

- KillDate: χρονική σφραγίδα μετά την οποία το agent αυτο‑λήγει
- WorkingTime: ώρες κατά τις οποίες ο agent θα πρέπει να είναι ενεργός για να συγχωνευτεί με την επιχειρησιακή δραστηριότητα

Αυτά τα πεδία μπορούν να χρησιμοποιηθούν για clustering και για να εξηγήσουν παρατηρούμενες ήσυχες περιόδους.

## YARA and static leads

Unit 42 δημοσίευσε βασικές YARA για beacons (C/C++ και Go) και constants για loader API‑hashing. Σκεφτείτε να συμπληρώσετε με κανόνες που αναζητούν τη διάταξη [size|ciphertext|16‑byte‑key] κοντά στο τέλος του PE .rdata και τις προεπιλεγμένες συμβολοσειρές προφίλ HTTP.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
