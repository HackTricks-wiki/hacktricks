# Εξαγωγή διαμόρφωσης και TTPs του AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

Το AdaptixC2 είναι ένα modular, open-source framework post-exploitation/C2 με beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) και υποστήριξη BOF.<sup>[[1]](#references)</sup> Αυτή η σελίδα τεκμηριώνει:
- Πώς είναι ενσωματωμένη η διαμόρφωση που έχει packed με RC4 και πώς να την εξαγάγετε από beacons
- Ενδείξεις δικτύου/profile για HTTP/SMB/TCP listeners
- Συνήθη TTPs για loaders και persistence που έχουν παρατηρηθεί στο πεδίο, με συνδέσμους προς σχετικές σελίδες τεχνικών Windows

Οι πρόσφατες upstream εκδόσεις περιλαμβάνουν επίσης DNS/DoH beacon listeners και τη χωριστή οικογένεια Gopher agent/listener, επομένως οι σύγχρονες υποδομές Adaptix μπορεί να εκθέτουν περισσότερα από τις αρχικές επιφάνειες HTTP/SMB/TCP, ακόμη κι όταν ένα συγκεκριμένο δείγμα εξακολουθεί να χρησιμοποιεί τον κλασικό beacon agent.<sup>[[2]](#references)</sup>

## Profiles και πεδία Beacon

Το AdaptixC2 υποστηρίζει τρεις κύριους τύπους beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 με ρυθμιζόμενους servers/ports/SSL, method, URI, headers, user-agent και προσαρμοσμένο όνομα parameter
- BEACON_SMB: peer-to-peer C2 μέσω named pipe (intranet)
- BEACON_TCP: απευθείας sockets, προαιρετικά με marker στην αρχή για την απόκρυψη της έναρξης του protocol

Αυτές είναι οι διατάξεις beacon που τεκμηριώθηκαν δημόσια σε πρώιμες αναλύσεις του Adaptix και εξακολουθούν να αποτελούν το συνηθέστερο σημείο εκκίνησης για εξαγωγή από δείγματα.<sup>[[1]](#references)</sup> Ωστόσο, οι τρέχουσες upstream εκδόσεις περιλαμβάνουν επίσης extenders `BeaconDNS` και Gopher στην πλευρά του server, επομένως μην υποθέτετε ότι κάθε ενεργή εγκατάσταση Adaptix εκθέτει μόνο υποδομή HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Τυπικά πεδία profile που έχουν παρατηρηθεί σε διαμορφώσεις HTTP beacon (μετά την αποκρυπτογράφηση):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – χρησιμοποιούνται για την ανάλυση των μεγεθών των responses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Οι πρόσφατες εκδόσεις BeaconHTTP υποστηρίζουν επίσης επιλογή από τον operator για rotation μεταξύ πολλαπλών URIs, user-agents, Host headers και servers, με διαδοχική ή τυχαία επιλογή.<sup>[[2]](#references)</sup> Από την οπτική του hunting, αυτό σημαίνει ότι ένας μολυσμένος host μπορεί να χρησιμοποιεί πολλαπλές διαδρομές callback και συνδυασμούς headers, χωρίς να εγκαταλείπει την κλασική οικογένεια beacon με packed RC4.

Παράδειγμα προεπιλεγμένου HTTP profile (από build beacon):<sup>[[1]](#references)</sup>

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

Όταν ο operator κάνει κλικ στο Create στο builder, το AdaptixC2 ενσωματώνει το κρυπτογραφημένο profile ως tail blob στο beacon. Η μορφή είναι:<sup>[[1]](#references)</sup>
- 4 bytes: μέγεθος ρυθμίσεων (uint32, little-endian)
- N bytes: δεδομένα ρυθμίσεων κρυπτογραφημένα με RC4
- 16 bytes: κλειδί RC4

Ο loader του beacon αντιγράφει το κλειδί των 16 bytes από το τέλος και αποκρυπτογραφεί με RC4 το μπλοκ των N bytes επιτόπου:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Πρακτικές επιπτώσεις:<sup>[[1]](#references)</sup>
- Ολόκληρη η δομή βρίσκεται συχνά στην ενότητα PE .rdata.
- Η εξαγωγή είναι ντετερμινιστική: διαβάστε το μέγεθος, διαβάστε το ciphertext αυτού του μεγέθους, διαβάστε το κλειδί 16 byte που βρίσκεται αμέσως μετά και έπειτα αποκρυπτογραφήστε με RC4.

## Ροή εργασίας εξαγωγής ρυθμίσεων (defenders)

Γράψτε έναν extractor που μιμείται τη λογική του beacon:<sup>[[1]](#references)</sup>
1) Εντοπίστε το blob μέσα στο PE (συνήθως στο .rdata). Μια πρακτική προσέγγιση είναι να σαρώσετε το .rdata για μια εύλογη διάταξη [size|ciphertext|16-byte key] και να δοκιμάσετε RC4.
2) Διαβάστε τα πρώτα 4 bytes → size (uint32 LE).
3) Διαβάστε τα επόμενα N=size bytes → ciphertext.
4) Διαβάστε τα τελευταία 16 bytes → RC4 key.
5) Αποκρυπτογραφήστε το ciphertext με RC4. Έπειτα αναλύστε το plain profile ως εξής:
   - βαθμωτές τιμές u32/boolean, όπως σημειώθηκε παραπάνω
   - συμβολοσειρές με πρόθεμα μήκους (μήκος u32 ακολουθούμενο από bytes· μπορεί να υπάρχει τελικό NUL)
   - πίνακες: servers_count και έπειτα τόσα ζεύγη [string, u32 port]

Ελάχιστο Python proof-of-concept (αυτόνομο, χωρίς εξωτερικές εξαρτήσεις) που λειτουργεί με ένα blob που έχει εξαχθεί εκ των προτέρων:

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
- Κατά την αυτοματοποίηση, χρησιμοποιήστε PE parser για να διαβάσετε το .rdata και έπειτα εφαρμόστε sliding window: για κάθε offset o, δοκιμάστε size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = τα επόμενα 16 bytes· κάντε RC4-decrypt και ελέγξτε αν τα πεδία string αποκωδικοποιούνται ως UTF-8 και αν τα lengths είναι λογικά.
- Κάντε parse τα SMB/TCP profiles ακολουθώντας τις ίδιες συμβάσεις length-prefixed.

## Προσαρμοσμένα listener profiles: μην περιορίζεστε μόνο στο κλασικό HTTP schema

Η εξωτερική μορφή packing (`u32 size | RC4 ciphertext | 16-byte key`) μπορεί να επαναχρησιμοποιηθεί, επομένως οι listeners που έχουν προσαρμοστεί από τον actor μπορούν να ακολουθούν την ίδια ροή εξαγωγής, αλλάζοντας εντελώς τη διάταξη των decrypted πεδίων.

Ένα καλό πρόσφατο παράδειγμα είναι η καμπάνια Tropic Trooper του Μαρτίου 2026, όπου το εξαγμένο Adaptix beacon δεν περιείχε τυπικό HTTP/TCP profile. Αντίθετα, το decrypted blob αποθήκευε παραμέτρους μεταφοράς GitHub, όπως:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (για παράδειγμα `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Πρακτική στρατηγική parser:
- Εντοπίστε πρώτα το εξωτερικό RC4 blob με τον συνηθισμένο τρόπο.
- Μετά την αποκρυπτογράφηση, επιλέξτε κλάδο με βάση sentinel strings και τη λογικότητα των πεδίων, αντί να επιβάλετε αμέσως το HTTP parser.
- Κατάλληλα sentinels είναι τα `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, strings σε μορφή named pipe ή προφανώς έγκυροι πίνακες server/port.
- Αν αποτύχει το HTTP parser, αλλά το plaintext περιέχει συνεκτικά UTF-8 strings με length-prefix, διατηρήστε το δείγμα και δοκιμάστε εναλλακτικά schemas αντί να το απορρίψετε ως false positive.

Σε εκείνη την καμπάνια, ο προσαρμοσμένος listener χρησιμοποιούσε τα GitHub issues ως μεταφορά C2, ενώ το beacon έκανε query στο `ipinfo.io` για να μάθει την εξωτερική IP του, επειδή το GitHub API δεν αποκαλύπτει απευθείας στον operator τη διεύθυνση προέλευσης του θύματος.<sup>[[5]](#references)</sup>

## Network fingerprinting και hunting

HTTP:<sup>[[1]](#references)</sup>
- Συνήθης συμπεριφορά: POST σε URIs που επιλέγει ο operator (π.χ. /uri.php, /endpoint/api)
- Προσαρμοσμένη παράμετρος header για το beacon ID (π.χ., X‑Beacon‑Id, X‑App‑Id)
- User-agents που μιμούνται το Firefox 20 ή σύγχρονες εκδόσεις του Chrome
- Ο ρυθμός polling είναι ορατός μέσω των sleep_delay/jitter_delay
- Νεότερα builds μπορούν να εναλλάσσουν URIs, user-agents, Host headers και servers μεταξύ callbacks, επομένως κάντε clustering με βάση ασυνήθιστα ονόματα header, μοτίβα μεγέθους απόκρισης, επαναχρησιμοποίηση TLS και χρονισμό, αντί να υποθέτετε ένα συγκεκριμένο ζεύγος path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners για εσωτερικού δικτύου C2, όπου η εξερχόμενη κίνηση web περιορίζεται
- Τα TCP beacons μπορεί να προσθέτουν μερικά bytes πριν από την κίνηση, ώστε να αποκρύπτουν την αρχή του protocol

Προεπιλογές του τρέχοντος upstream teamserver
- Το `profile.yaml` περιλαμβάνει αυτήν τη στιγμή teamserver `0.0.0.0:4321`, endpoint `/endpoint`, ονόματα αρχείων certificate/key `server.rsa.crt` και `server.rsa.key`, καθώς και extenders για HTTP, SMB, TCP, DNS, Beacon agent και Gopher.<sup>[[2]](#references)</sup>
- Για routes που δεν αντιστοιχίζονται, ο προεπιλεγμένος error handler επιστρέφει `Server: AdaptixC2` και `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Το τυπικό 404 body περιέχει `AdaptixC2 404` και `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Σαρώσεις σε ολόκληρο το διαδίκτυο το 2026 εντόπισαν πολλούς εκτεθειμένους teamservers στη θύρα `4321` και πολλούς beacon listeners στη θύρα `43211`. Συνεπώς, και οι δύο θύρες είναι χρήσιμα seed pivots, αλλά δεν πρέπει να θεωρούνται εξαντλητικές.<sup>[[4]](#references)</sup>

Αποτυπώματα DNS/DoH listener:<sup>[[4]](#references)</sup>
- Το τρέχον BeaconDNS extender απαντά αυθεντικά (`AA=true`)
- Σε queries που δεν ταιριάζουν στη μορφή του beacon protocol —κυρίως ονόματα με λιγότερα από 5 labels πριν από το ρυθμισμένο domain— συνήθως απαντά με `TXT "OK"`
- Αν το ρυθμισμένο base TTL παραμείνει στο μηδέν, ο listener χρησιμοποιεί base 10 δευτερολέπτων και προσθέτει jitter έως 59 δευτερόλεπτα
- Αυτό καθιστά τα active probes με σύντομα labels χρήσιμα όταν δεν είναι εκτεθειμένος HTTP listener

## TTPs loader και persistence που εντοπίστηκαν σε περιστατικά

Loaders PowerShell στη μνήμη:<sup>[[1]](#references)</sup>
- Κατεβάζουν payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Δεσμεύουν unmanaged memory, αντιγράφουν shellcode και αλλάζουν την προστασία σε 0x40 (PAGE_EXECUTE_READWRITE) μέσω VirtualProtect.<sup>[[7]](#references)</sup>
- Εκτελούν μέσω .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Μια αλυσίδα επιθέσεων Tropic Trooper του 2026 χρησιμοποίησε ένα trojanized εκτελέσιμο SumatraPDF (TOSHIS loader), το οποίο ανακατεύθυνε το `_security_init_cookie` σε κακόβουλο κώδικα αντί να τροποποιήσει το PE entry point
- Ο loader εντόπιζε APIs μέσω hashing Adler-32, κατέβαζε ένα παραπλανητικό PDF, ανακτούσε shellcode δεύτερου σταδίου, το αποκρυπτογραφούσε με AES-128-CBC μέσω WinCrypt (`CryptDeriveKey` από hardcoded seed) και εκτελούσε ανακλαστικά ένα Adaptix beacon στη μνήμη
- Αργότερα, το persistence μεταφέρθηκε σε scheduled tasks με ονόματα που έμοιαζαν αθώα, όπως `\MSDNSvc` ή `\MicrosoftUDN`, ρυθμισμένα να επανεκκινούν τον agent περίπου κάθε δύο ώρες

Δείτε αυτές τις σελίδες για εκτέλεση στη μνήμη και ζητήματα AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Μηχανισμοί persistence που παρατηρήθηκαν:<sup>[[1]](#references)</sup>
- Συντόμευση (.lnk) στον φάκελο Startup για επανεκκίνηση ενός loader κατά τη σύνδεση
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), συχνά με ονόματα που ακούγονται αθώα, όπως "Updater", για την εκκίνηση του loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack με τοποθέτηση του msimg32.dll στο %APPDATA%\Microsoft\Windows\Templates για ευάλωτες διεργασίες

Αναλύσεις τεχνικών και έλεγχοι:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ιδέες για hunting
- Μεταβάσεις PowerShell από RW σε RX: VirtualProtect σε PAGE_EXECUTE_READWRITE μέσα στο powershell.exe.<sup>[[8]](#references)</sup>
- Μοτίβα dynamic invocation (GetDelegateForFunctionPointer)
- HTTPS 404s που δεν αντιστοιχίζονται, με `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ή `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses με `AA=true` και `TXT "OK"` για σύντομα queries σε ύποπτα domains.<sup>[[4]](#references)</sup>
- Κίνηση GitHub API προς `/repos/<owner>/<repo>/issues`, ακολουθούμενη από lookups στο `ipinfo.io` από την ίδια αλυσίδα loader/beacon.<sup>[[5]](#references)</sup>
- Startup .lnk σε φακέλους Startup χρήστη ή κοινόχρηστους.<sup>[[1]](#references)</sup>
- Ύποπτα Run keys (π.χ., "Updater") και ονόματα loader όπως update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized δείγματα PE που ανακατευθύνουν το `_security_init_cookie` σε κώδικα downloader πριν εμφανίσουν ένα παραπλανητικό έγγραφο.<sup>[[5]](#references)</sup>
- Διαδρομές DLL εγγράψιμες από τον χρήστη κάτω από το %APPDATA%\Microsoft\Windows\Templates, οι οποίες περιέχουν msimg32.dll.<sup>[[1]](#references)</sup>

## Σημειώσεις για τα πεδία OpSec

- KillDate: χρονική σήμανση μετά την οποία ο agent αυτοαπενεργοποιείται.<sup>[[1]](#references)</sup>
- WorkingTime: ώρες κατά τις οποίες ο agent πρέπει να είναι ενεργός, ώστε να ενσωματώνεται στη συνήθη επιχειρησιακή δραστηριότητα.<sup>[[1]](#references)</sup>

Αυτά τα πεδία μπορούν να χρησιμοποιηθούν για clustering και για να εξηγηθούν οι παρατηρούμενες περίοδοι αδράνειας.

## YARA και στατικά στοιχεία

Η Unit 42 δημοσίευσε βασικούς κανόνες YARA για beacons (C/C++ και Go) και σταθερές API-hashing των loaders.<sup>[[1]](#references)</sup> Εξετάστε το ενδεχόμενο να τους συμπληρώσετε με κανόνες που αναζητούν τη διάταξη [size|ciphertext|16-byte-key] κοντά στο τέλος του PE .rdata, τα προεπιλεγμένα HTTP profile strings και νεότερα markers server/listener, όπως `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` και `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Ένα νέο open-source framework που αξιοποιείται σε πραγματικές επιθέσεις (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 στο GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Τεκμηρίωση Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Αποτύπωση ενός open-source C2 framework σε μεγάλη κλίμακα (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Η Tropic Trooper στρέφεται στο AdaptixC2 και σε προσαρμοσμένο Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Σταθερές προστασίας μνήμης – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
