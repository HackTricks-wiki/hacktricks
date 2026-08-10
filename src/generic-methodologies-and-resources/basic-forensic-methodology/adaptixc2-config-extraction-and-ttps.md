# Εξαγωγή Configuration και TTPs του AdaptixC2

Το AdaptixC2 είναι ένα modular, open-source post-exploitation/C2 framework με Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) και υποστήριξη BOF.<sup>[[1]](#references)</sup> Αυτή η σελίδα τεκμηριώνει:
- Πώς είναι ενσωματωμένο το RC4-packed configuration και πώς να το εξαγάγετε από beacons
- Network/profile indicators για HTTP/SMB/TCP listeners
- Συνήθη loader και persistence TTPs που έχουν παρατηρηθεί in the wild, με links προς σχετικές σελίδες τεχνικών Windows

Οι πρόσφατες upstream releases περιλαμβάνουν επίσης DNS/DoH beacon listeners και τη ξεχωριστή οικογένεια Gopher agent/listener, επομένως η σύγχρονη υποδομή Adaptix μπορεί να εκθέτει περισσότερες επιφάνειες από τις αρχικές HTTP/SMB/TCP, ακόμη και όταν ένα συγκεκριμένο sample εξακολουθεί να χρησιμοποιεί τον classic beacon agent.<sup>[[2]](#references)</sup>

## Beacon profiles και fields

Το AdaptixC2 υποστηρίζει τρεις βασικούς τύπους beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 με configurable servers/ports/SSL, method, URI, headers, user-agent και custom parameter name
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, προαιρετικά με prepended marker για την απόκρυψη της έναρξης του protocol

Αυτά είναι τα layouts των beacon που τεκμηριώθηκαν δημόσια σε πρώιμες αναλύσεις του Adaptix και εξακολουθούν να αποτελούν το πιο συνηθισμένο starting point για sample-side extraction.<sup>[[1]](#references)</sup> Ωστόσο, τα τρέχοντα upstream builds περιλαμβάνουν επίσης `BeaconDNS` και Gopher extenders στην πλευρά του server, επομένως μην υποθέτετε ότι κάθε live Adaptix deployment εκθέτει μόνο HTTP/SMB/TCP infrastructure.<sup>[[2]](#references)</sup>

Τυπικά profile fields που παρατηρούνται σε HTTP beacon configs (μετά την αποκρυπτογράφηση):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – χρησιμοποιούνται για την ανάλυση των response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Τα πρόσφατα BeaconHTTP builds υποστηρίζουν επίσης rotation που επιλέγεται από τον operator μεταξύ πολλαπλών URIs, user-agents, Host headers και servers, με sequential ή random selection.<sup>[[2]](#references)</sup> Από την οπτική του hunting, αυτό σημαίνει ότι ένα single infected host μπορεί να πραγματοποιεί callbacks προς πολλές callback paths και header combinations, χωρίς να απομακρύνεται από την classic RC4-packed beacon family.

Παράδειγμα default HTTP profile (από beacon build):<sup>[[1]](#references)</sup>
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
Παρατηρημένο κακόβουλο HTTP profile (πραγματική επίθεση):<sup>[[1]](#references)</sup>
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
## Κρυπτογραφημένη συσκευασία ρυθμίσεων και διαδρομή φόρτωσης

Όταν ο operator κάνει κλικ στο Create στον builder, το AdaptixC2 ενσωματώνει το encrypted profile ως tail blob στο beacon. Η μορφή είναι:<sup>[[1]](#references)</sup>
- 4 bytes: μέγεθος ρυθμίσεων (uint32, little-endian)
- N bytes: RC4-encrypted δεδομένα ρυθμίσεων
- 16 bytes: RC4 key

Ο loader του beacon αντιγράφει το key των 16 bytes από το τέλος και αποκρυπτογραφεί με RC4 το block των N bytes in place:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Πρακτικές επιπτώσεις:<sup>[[1]](#references)</sup>
- Ολόκληρη η δομή βρίσκεται συχνά μέσα στην ενότητα PE .rdata.
- Η εξαγωγή είναι ντετερμινιστική: διαβάστε το size, διαβάστε το ciphertext αυτού του μεγέθους, διαβάστε το κλειδί 16 byte που βρίσκεται αμέσως μετά και, στη συνέχεια, εκτελέστε RC4-decrypt.

## Ροή εργασίας εξαγωγής Configuration (defenders)

Γράψτε έναν extractor που μιμείται τη λογική του beacon:<sup>[[1]](#references)</sup>
1) Εντοπίστε το blob μέσα στο PE (συνήθως στο .rdata). Μια πρακτική προσέγγιση είναι να σαρώσετε το .rdata για μια πιθανή διάταξη [size|ciphertext|16-byte key] και να δοκιμάσετε RC4.
2) Διαβάστε τα πρώτα 4 bytes → size (uint32 LE).
3) Διαβάστε τα επόμενα N=size bytes → ciphertext.
4) Διαβάστε τα τελευταία 16 bytes → RC4 key.
5) Κάντε RC4-decrypt στο ciphertext. Στη συνέχεια, αναλύστε το plain profile ως εξής:
- u32/boolean scalars όπως σημειώνεται παραπάνω
- strings με length-prefix (μήκος u32 ακολουθούμενο από bytes· μπορεί να υπάρχει τελικό NUL)
- arrays: servers_count ακολουθούμενο από τόσα ζεύγη [string, u32 port]

Ελάχιστο Python proof-of-concept (standalone, χωρίς external deps) που λειτουργεί με ένα pre-extracted blob:
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
Συμβουλές:
- Κατά την αυτοματοποίηση, χρησιμοποιήστε έναν PE parser για να διαβάσετε το .rdata και εφαρμόστε sliding window: για κάθε offset o, δοκιμάστε size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes· κάντε RC4-decrypt και ελέγξτε ότι τα string fields αποκωδικοποιούνται ως UTF-8 και ότι τα lengths είναι λογικά.
- Κάντε parse τα SMB/TCP profiles ακολουθώντας τις ίδιες length-prefixed conventions.

## Custom listener profiles: μην κάνετε hard-code μόνο το classic HTTP schema

Το outer packing format (`u32 size | RC4 ciphertext | 16-byte key`) είναι επαναχρησιμοποιήσιμο, επομένως listeners που έχουν τροποποιηθεί από τον actor μπορούν να διατηρούν το ίδιο extraction workflow, αλλάζοντας πλήρως το decrypted field layout.

Ένα καλό πρόσφατο παράδειγμα είναι η campaign του Tropic Trooper τον Μάρτιο του 2026, όπου το extracted Adaptix beacon δεν περιείχε standard HTTP/TCP profile. Αντίθετα, το decrypted blob αποθήκευε GitHub transport parameters όπως:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (για παράδειγμα `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Πρακτική parser strategy:
- Αρχικά εντοπίστε το outer RC4 blob ακριβώς όπως συνήθως.
- Μετά το decryption, κάντε branch με βάση sentinel strings και field sanity, αντί να επιβάλετε αμέσως τον HTTP parser.
- Καλά sentinels είναι τα `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, strings τύπου named-pipe ή προφανώς έγκυρα server/port arrays.
- Αν ο HTTP parser αποτύχει, αλλά το plaintext περιέχει συνεκτικά length-prefixed UTF-8 strings, κρατήστε το sample και δοκιμάστε alternative schemas αντί να το απορρίψετε ως false positive.

Σε εκείνη την campaign, ο custom listener χρησιμοποιούσε GitHub issues ως C2 transport και το beacon έκανε query στο `ipinfo.io` για να μάθει την εξωτερική IP του, επειδή το GitHub API δεν αποκαλύπτει απευθείας στον operator τη source address του victim.<sup>[[5]](#references)</sup>

## Network fingerprinting και hunting

HTTP:<sup>[[1]](#references)</sup>
- Συνηθισμένο: POST σε URIs που επιλέγει ο operator (π.χ. /uri.php, /endpoint/api)
- Custom header parameter που χρησιμοποιείται για το beacon ID (π.χ. X‑Beacon‑Id, X‑App‑Id)
- User-agents που μιμούνται Firefox 20 ή σύγχρονα Chrome builds
- Η συχνότητα polling είναι ορατή μέσω των sleep_delay/jitter_delay
- Τα νεότερα builds μπορούν να αλλάζουν URIs, user-agents, Host headers και servers μεταξύ callbacks, επομένως κάντε clustering με βάση ασυνήθιστα header names, response-size patterns, TLS reuse και timing, αντί να υποθέτετε ένα μοναδικό path/UA pair.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners για intranet C2 όπου το web egress είναι περιορισμένο
- Τα TCP beacons μπορεί να προσθέτουν μερικά bytes πριν από την traffic για να αποκρύψουν την αρχή του protocol

Current upstream teamserver defaults
- Το `profile.yaml` περιλαμβάνει επί του παρόντος teamserver `0.0.0.0:4321`, endpoint `/endpoint`, filenames certificate/key `server.rsa.crt` και `server.rsa.key`, καθώς και extenders για HTTP, SMB, TCP, DNS, Beacon agent και Gopher.<sup>[[2]](#references)</sup>
- Σε routes που δεν αντιστοιχούν, ο default error handler επιστρέφει `Server: AdaptixC2` και `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Το stock 404 body περιέχει `AdaptixC2 404` και `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide scans το 2026 εντόπισαν πολλούς exposed teamservers στη `4321` και πολλούς beacon listeners στη `43211`, επομένως και οι δύο ports είναι χρήσιμα seed pivots, αλλά δεν πρέπει να θεωρούνται exhaustive.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- Το τρέχον BeaconDNS extender απαντά authoritatively (`AA=true`)
- Queries που δεν ταιριάζουν στο beacon protocol shape — ιδιαίτερα names με λιγότερα από 5 labels πριν από το configured domain — συνήθως απαντώνται με `TXT "OK"`
- Αν το configured base TTL παραμείνει στο zero, ο listener χρησιμοποιεί base 10 δευτερολέπτων και προσθέτει jitter έως 59 δευτερόλεπτα
- Αυτό καθιστά τα short-label active probes χρήσιμα όταν δεν εκτίθεται HTTP listener

## Loader και persistence TTPs που παρατηρήθηκαν σε incidents

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Κάνουν download Base64/XOR payloads (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Κάνουν allocate unmanaged memory, αντιγράφουν shellcode και αλλάζουν την protection σε 0x40 (PAGE_EXECUTE_READWRITE) μέσω VirtualProtect.<sup>[[7]](#references)</sup>
- Κάνουν execute μέσω .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Μια chain του Tropic Trooper το 2026 χρησιμοποίησε ένα trojanized SumatraPDF executable (TOSHIS loader), το οποίο ανακατεύθυνε το `_security_init_cookie` σε malicious code αντί να κάνει patch το PE entry point
- Ο loader έκανε resolve APIs μέσω Adler-32 hashing, κατέβαζε ένα decoy PDF, έκανε fetch second-stage shellcode, το έκανε decrypt με AES-128-CBC μέσω WinCrypt (`CryptDeriveKey` από hardcoded seed) και εκτελούσε reflectively ένα Adaptix beacon στη μνήμη
- Αργότερα, το persistence μεταφέρθηκε σε scheduled tasks με benign-looking names όπως `\MSDNSvc` ή `\MicrosoftUDN`, ρυθμισμένα να κάνουν re-launch τον agent περίπου κάθε δύο ώρες

Ελέγξτε αυτές τις σελίδες για in-memory execution και AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms που παρατηρήθηκαν:<sup>[[1]](#references)</sup>
- Shortcut (.lnk) στον Startup folder για re-launch ενός loader κατά το logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), συχνά με benign-sounding names όπως "Updater", για εκκίνηση του loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack με τοποθέτηση του msimg32.dll κάτω από το %APPDATA%\Microsoft\Windows\Templates για susceptible processes

Technique deep-dives και checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell που προκαλεί RW→RX transitions: VirtualProtect σε PAGE_EXECUTE_READWRITE μέσα στο powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s με `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ή `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses με `AA=true` και `TXT "OK"` για short queries κάτω από suspect domains.<sup>[[4]](#references)</sup>
- GitHub API traffic προς `/repos/<owner>/<repo>/issues`, ακολουθούμενο από lookups στο `ipinfo.io` από την ίδια loader/beacon chain.<sup>[[5]](#references)</sup>
- Startup .lnk κάτω από user ή common Startup folders.<sup>[[1]](#references)</sup>
- Suspicious Run keys (π.χ. "Updater") και loader names όπως update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE samples που ανακατευθύνουν το `_security_init_cookie` σε downloader code πριν εμφανίσουν ένα decoy document.<sup>[[5]](#references)</sup>
- User-writable DLL paths κάτω από το %APPDATA%\Microsoft\Windows\Templates που περιέχουν msimg32.dll.<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: timestamp μετά το οποίο ο agent κάνει self-expire.<sup>[[1]](#references)</sup>
- WorkingTime: ώρες κατά τις οποίες ο agent πρέπει να είναι active, ώστε να ενσωματώνεται στη business activity.<sup>[[1]](#references)</sup>

Αυτά τα fields μπορούν να χρησιμοποιηθούν για clustering και για την εξήγηση observed quiet periods.

## YARA και static leads

Η Unit 42 δημοσίευσε basic YARA για beacons (C/C++ και Go) και loader API-hashing constants.<sup>[[1]](#references)</sup> Εξετάστε το ενδεχόμενο να τα συμπληρώσετε με rules που αναζητούν το layout [size|ciphertext|16-byte-key] κοντά στο τέλος του PE .rdata, τα default HTTP profile strings και νεότερα server/listener markers όπως `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` και `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
