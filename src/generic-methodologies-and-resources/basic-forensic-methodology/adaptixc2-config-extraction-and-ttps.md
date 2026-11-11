# Εξαγωγή διαμόρφωσης AdaptixC2 και TTPs

{{#include ../../banners/hacktricks-training.md}}

Το AdaptixC2 είναι ένα modular, open-source framework post-exploitation/C2 με beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) και υποστήριξη BOF.<sup>[[1]](#references)</sup> Αυτή η σελίδα τεκμηριώνει:
- Πώς ενσωματώνεται η διαμόρφωση που έχει συσκευαστεί με RC4 και πώς να την εξαγάγετε από beacons
- Ενδείξεις δικτύου/profile για HTTP/SMB/TCP listeners
- Συνήθη TTPs για loader και persistence που έχουν παρατηρηθεί στη φύση, με συνδέσμους προς σχετικές σελίδες τεχνικών Windows

Οι πρόσφατες upstream εκδόσεις περιλαμβάνουν επίσης DNS/DoH beacon listeners και τη χωριστή οικογένεια Gopher agent/listener, επομένως η σύγχρονη υποδομή Adaptix μπορεί να εκθέτει περισσότερα από τις αρχικές επιφάνειες HTTP/SMB/TCP, ακόμη κι όταν ένα συγκεκριμένο δείγμα εξακολουθεί να χρησιμοποιεί τον κλασικό beacon agent.<sup>[[2]](#references)</sup>

## Προφίλ beacon και πεδία

Το AdaptixC2 υποστηρίζει τρεις κύριους τύπους beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 με παραμετροποιήσιμους servers/ports/SSL, method, URI, headers, user-agent και προσαρμοσμένο όνομα parameter
- BEACON_SMB: peer-to-peer C2 μέσω named pipe (intranet)
- BEACON_TCP: direct sockets, προαιρετικά με προσαρτημένο marker για την απόκρυψη της αρχής του protocol

Αυτές είναι οι διατάξεις beacon που τεκμηριώθηκαν δημόσια σε πρώιμες αναλύσεις του Adaptix και παραμένουν το συνηθέστερο σημείο εκκίνησης για εξαγωγή από δείγματα.<sup>[[1]](#references)</sup> Ωστόσο, οι τρέχουσες upstream builds περιλαμβάνουν επίσης `BeaconDNS` και Gopher extenders στην πλευρά του server, επομένως μην υποθέτετε ότι κάθε ενεργή εγκατάσταση Adaptix εκθέτει μόνο υποδομή HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Η ακόλουθη σύνοψη πεδίων και τα δείγματα JSON περιγράφουν τη μορφή HTTP που αναλύθηκε το 2025· δεν αποτελούν προδιαγραφή parser για νεότερες upstream builds. Τυπικά πεδία σε αυτά τα δείγματα (μετά την αποκρυπτογράφηση):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – χρησιμοποιούνται για την ανάλυση των μεγεθών των responses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Οι πρόσφατες builds του BeaconHTTP υποστηρίζουν επίσης επιλογή από τον operator για εναλλαγή μεταξύ πολλαπλών URI, user-agent, Host headers και servers, με διαδοχική ή τυχαία επιλογή.<sup>[[2]](#references)</sup> Από την οπτική του hunting, αυτό σημαίνει ότι ένας μολυσμένος host μπορεί να χρησιμοποιεί πολλαπλές διαδρομές callback και συνδυασμούς headers, χωρίς να εγκαταλείπει την κλασική οικογένεια beacon που έχει συσκευαστεί με RC4.

Παράδειγμα προεπιλεγμένου HTTP profile (από beacon build):<sup>[[1]](#references)</sup>

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

Παρατηρημένο κακόβουλο προφίλ HTTP (πραγματική επίθεση):<sup>[[1]](#references)</sup>

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

## Συσκευασία κρυπτογραφημένης διαμόρφωσης και διαδρομή φόρτωσης

Όταν ο operator κάνει κλικ στο Create στο builder, το AdaptixC2 μεταγλωττίζει το κρυπτογραφημένο profile μέσα στο beacon. Μην υποθέτετε ότι βρίσκεται στο τέλος του PE ή του shellcode: εντοπίστε τα bytes του profile σαρώνοντας τις ενότητες ή ακολουθώντας το `getProfile()` στο δείγμα. Η συσκευασμένη μορφή είναι:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bytes: μέγεθος διαμόρφωσης (uint32, little-endian)
- N bytes: δεδομένα διαμόρφωσης κρυπτογραφημένα με RC4
- 16 bytes: κλειδί RC4

Ο loader του beacon αντιγράφει το κλειδί των 16 bytes από το τέλος και αποκρυπτογραφεί με RC4 το block των N bytes επιτόπου:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Πρακτικές επιπτώσεις:<sup>[[1]](#references)</sup>
- Ολόκληρη η δομή βρίσκεται συχνά μέσα στην ενότητα PE .rdata.
- Η εξαγωγή είναι ντετερμινιστική: διαβάστε το μέγεθος, διαβάστε το κρυπτοκείμενο αυτού του μεγέθους, διαβάστε το κλειδί των 16 byte που βρίσκεται αμέσως μετά και, στη συνέχεια, αποκρυπτογραφήστε με RC4.

## Ροή εργασίας εξαγωγής ρυθμίσεων (defenders)

Για γενική αρχική διαλογή δείγματος πριν από την εξαγωγή του beacon, δείτε την [Ανάλυση κακόβουλου λογισμικού](malware-analysis.md).

Γράψτε έναν extractor που μιμείται τη λογική του beacon:<sup>[[1]](#references)</sup>
1) Εντοπίστε το blob μέσα στο PE (συνήθως στο .rdata). Μια πρακτική προσέγγιση είναι να σαρώσετε το .rdata για μια εύλογη διάταξη [size|ciphertext|16‑byte key] και να δοκιμάσετε RC4.
2) Διαβάστε τα πρώτα 4 byte → μέγεθος (uint32 LE).
3) Διαβάστε τα επόμενα N=size byte → κρυπτοκείμενο.
4) Διαβάστε τα τελευταία 16 byte → κλειδί RC4.
5) Αποκρυπτογραφήστε το κρυπτοκείμενο με RC4. Στη συνέχεια, αναλύστε το απλό profile ως εξής:
   - scalar τιμές u32/boolean, όπως σημειώθηκε παραπάνω
   - συμβολοσειρές με πρόθεμα μήκους (μήκος u32 ακολουθούμενο από byte· μπορεί να υπάρχει τελικό NUL)
   - πίνακες: servers_count ακολουθούμενο από τόσα ζεύγη [string, u32 port]

Legacy HTTP proof-of-concept σε Python (αυτόνομο, χωρίς εξωτερικές εξαρτήσεις) για ένα blob που έχει εξαχθεί εκ των προτέρων, με τη σειρά πεδίων του 2025. Για πρόσφατες stock builds, χρησιμοποιήστε τον parser current-schema παρακάτω:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Ανάλυση τρεχόντων stock HTTP και DNS profiles

Το τρέχον upstream περιλαμβάνει πρώτα έξι little-endian τιμές `u32`: agent watermark/type, kill date, working time, sleep, jitter και listener watermark/type. Έπειτα ξεκινούν τα ειδικά δεδομένα HTTP με ένα μονο-byte SSL flag. Σε αντίθεση με το legacy παράδειγμα, υπάρχουν λίστες URI, user-agent και Host header με μετρητή, ακολουθούμενες από rotation mode και ρυθμίσεις proxy. Επομένως, ο legacy parser αρχίζει να διαβάζει το SSL flag από το πεδίο kill-date και επιστρέφει λανθασμένα αποτελέσματα σε αυτά τα builds. Τα μήκη των strings και οι ακέραιες τιμές σε αυτό το profile χρησιμοποιούν little-endian encoding· τα packed strings περιλαμβάνουν ένα τελικό NUL όταν δεν είναι κενά.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Με τα helpers `P` και `rc4` παραπάνω, χρησιμοποιήστε αυτόν τον parser σε αποκρυπτογραφημένο plaintext **stock HTTP**. Μην αποκαλύπτετε το κλειδί RC4 σε δημόσιες αναφορές: το HTTP profile μπορεί να περιέχει όνομα χρήστη και κωδικό πρόσβασης proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Ανάλυση τρέχοντος stock HTTP plaintext profile</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

Για ένα stock DNS beacon, διαβάστε τα ίδια έξι κοινά πεδία `u32` και, στη συνέχεια, τις συμβολοσειρές `domain`, `resolvers`, `doh_resolvers` και `qtype`, με πρόθεμα το μήκος τους. Διαβάστε τα `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` και `dns_mode` ως `u32` και, στη συνέχεια, τη συμβολοσειρά user-agent του DoH, με πρόθεμα το μήκος της. Το `dns_mode` διακρίνει μεταξύ UDP, DoH και των δύο κατευθύνσεων fallback. Πρόκειται για ξεχωριστή διάταξη: μην περνάτε με το ζόρι το DNS plaintext από τον HTTP parser.<sup>[[12]](#references)[[13]](#references)</sup>

Συμβουλές:
- Κατά την αυτοματοποίηση, χρησιμοποιήστε έναν PE parser για να διαβάσετε το .rdata και, στη συνέχεια, εφαρμόστε ένα sliding window: για κάθε offset o, δοκιμάστε size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = τα επόμενα 16 bytes· κάντε RC4-decrypt και ελέγξτε αν τα πεδία συμβολοσειρών αποκωδικοποιούνται ως UTF-8 και αν τα μήκη είναι εύλογα.
- Κάντε parse τα SMB/TCP profiles ακολουθώντας τις ίδιες συμβάσεις για πεδία με πρόθεμα μήκους.

## Προσαρμοσμένα listener profiles: μην περιορίζεστε αποκλειστικά στο κλασικό HTTP schema

Η εξωτερική μορφή συσκευασίας (`u32 size | RC4 ciphertext | 16-byte key`) είναι επαναχρησιμοποιήσιμη, οπότε οι προσαρμοσμένοι από τον actor listeners μπορούν να χρησιμοποιούν την ίδια ροή εξαγωγής, αλλάζοντας εντελώς τη διάταξη των αποκρυπτογραφημένων πεδίων.

Ένα καλό πρόσφατο παράδειγμα είναι η καμπάνια Tropic Trooper του Μαρτίου 2026, όπου το εξαγόμενο Adaptix beacon δεν περιείχε τυπικό HTTP/TCP profile. Αντί γι' αυτό, το αποκρυπτογραφημένο blob αποθήκευε παραμέτρους μεταφοράς GitHub, όπως:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (για παράδειγμα `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Πρακτική στρατηγική parser:
- Αρχικά, εντοπίστε το εξωτερικό RC4 blob όπως συνήθως.
- Μετά την αποκρυπτογράφηση, επιλέξτε parser με βάση sentinel strings και την εγκυρότητα των πεδίων, αντί να επιβάλετε αμέσως τη χρήση του HTTP parser.
- Χρήσιμα sentinels είναι τα `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, συμβολοσειρές τύπου named pipe ή προφανώς έγκυροι πίνακες server/port.
- Αν αποτύχει ο HTTP parser, αλλά το plaintext περιέχει συνεκτικές συμβολοσειρές UTF-8 με πρόθεμα μήκους, κρατήστε το δείγμα και δοκιμάστε εναλλακτικά schemas αντί να το απορρίψετε ως false positive.

Σε αυτή την καμπάνια, ο προσαρμοσμένος listener χρησιμοποιούσε τα GitHub issues ως μεταφορά C2 και το beacon έκανε query στο `ipinfo.io` για να μάθει την εξωτερική IP του, καθώς το GitHub API δεν αποκαλύπτει απευθείας στον operator τη διεύθυνση προέλευσης του θύματος.<sup>[[5]](#references)</sup>

## Fingerprinting δικτύου και threat hunting

HTTP:<sup>[[1]](#references)</sup>
- Συνήθης συμπεριφορά: POST σε URI που επιλέγει ο operator (π.χ., /uri.php, /endpoint/api)
- Προσαρμοσμένη παράμετρος header για το beacon ID (π.χ., X‑Beacon‑Id, X‑App‑Id)
- User-agents που μιμούνται τον Firefox 20 ή σύγχρονες εκδόσεις του Chrome
- Η συχνότητα polling είναι ορατή μέσω των sleep_delay/jitter_delay
- Οι νεότερες εκδόσεις μπορούν να εναλλάσσουν URI, user-agents, Host headers και servers μεταξύ callbacks· επομένως, ομαδοποιήστε με βάση ασυνήθιστα ονόματα header, μοτίβα μεγέθους απόκρισης, επαναχρησιμοποίηση TLS και χρονισμό, αντί να θεωρείτε δεδομένο ένα συγκεκριμένο ζεύγος path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners για intranet C2, όταν η εξερχόμενη κίνηση web υπόκειται σε περιορισμούς
- Τα TCP beacons μπορεί να προσθέτουν λίγα bytes πριν από την κίνηση, ώστε να συγκαλύπτουν την αρχή του πρωτοκόλλου

Προεπιλεγμένες ρυθμίσεις του τρέχοντος upstream teamserver
- Το `profile.yaml` περιλαμβάνει επί του παρόντος το teamserver `0.0.0.0:4321`, το endpoint `/endpoint`, τα ονόματα αρχείων certificate/key `server.rsa.crt` και `server.rsa.key`, καθώς και extenders για HTTP, SMB, TCP, DNS, Beacon agent και Gopher.<sup>[[2]](#references)</sup>
- Για routes που δεν αντιστοιχούν σε κάποιο endpoint, ο προεπιλεγμένος error handler επιστρέφει `Server: AdaptixC2` και `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Το προεπιλεγμένο σώμα 404 περιέχει τα `AdaptixC2 404` και `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Σαρώσεις σε ολόκληρο το Internet το 2026 εντόπισαν πολλά εκτεθειμένα teamservers στη θύρα `4321` και πολλούς beacon listeners στη θύρα `43211`. Συνεπώς, και οι δύο θύρες είναι χρήσιμες ως αρχικά σημεία διερεύνησης, αλλά δεν πρέπει να θεωρούνται εξαντλητικές.<sup>[[4]](#references)</sup>

Fingerprints DNS/DoH listener:<sup>[[4]](#references)</sup>
- Το τρέχον BeaconDNS extender απαντά authoritative (`AA=true`)
- Τα queries που δεν ταιριάζουν στη μορφή του πρωτοκόλλου beacon —ιδίως ονόματα με λιγότερα από 5 labels πριν από το ρυθμισμένο domain— συνήθως απαντώνται με `TXT "OK"`
- Αν το ρυθμισμένο base TTL παραμείνει μηδενικό, ο listener χρησιμοποιεί βάση 10 δευτερολέπτων και προσθέτει έως 59 δευτερόλεπτα jitter
- Έτσι, τα active probes με σύντομα labels είναι χρήσιμα όταν δεν εκτίθεται HTTP listener

## TTPs loader και persistence που παρατηρήθηκαν σε περιστατικά

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Κατεβάζουν payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Δεσμεύουν unmanaged memory, αντιγράφουν shellcode και αλλάζουν την προστασία σε 0x40 (PAGE_EXECUTE_READWRITE) μέσω VirtualProtect.<sup>[[7]](#references)</sup>
- Εκτελούν μέσω .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Μια αλυσίδα επίθεσης του Tropic Trooper το 2026 χρησιμοποίησε ένα trojanized εκτελέσιμο SumatraPDF (TOSHIS loader), το οποίο ανακατεύθυνε το `_security_init_cookie` σε κακόβουλο κώδικα αντί να τροποποιήσει το PE entry point
- Ο loader επιλύει APIs μέσω κατακερματισμού Adler-32, κατεβάζει ένα παραπλανητικό PDF, ανακτά shellcode δεύτερου σταδίου, το αποκρυπτογραφεί με AES-128-CBC μέσω WinCrypt (`CryptDeriveKey` από ένα hardcoded seed) και εκτελεί reflectively ένα Adaptix beacon στη μνήμη
- Αργότερα, το persistence βασίστηκε σε scheduled tasks με ονόματα που φαίνονται ακίνδυνα, όπως `\MSDNSvc` ή `\MicrosoftUDN`, ρυθμισμένα να επανεκκινούν τον agent περίπου κάθε δύο ώρες

Δείτε αυτές τις σελίδες για εκτέλεση στη μνήμη και ζητήματα AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Μηχανισμοί persistence που παρατηρήθηκαν:<sup>[[1]](#references)</sup>
- Συντόμευση (.lnk) στον φάκελο Startup για επανεκκίνηση ενός loader κατά τη σύνδεση του χρήστη
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), συχνά με ονόματα που ακούγονται ακίνδυνα, όπως "Updater", για την εκκίνηση του loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack με απόθεση του msimg32.dll στο %APPDATA%\Microsoft\Windows\Templates για ευάλωτες διεργασίες

Αναλυτικές παρουσιάσεις τεχνικών και έλεγχοι:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ιδέες για threat hunting
- Μεταβάσεις RW→RX από PowerShell: VirtualProtect σε PAGE_EXECUTE_READWRITE μέσα στο powershell.exe.<sup>[[8]](#references)</sup>
- Μοτίβα dynamic invocation (GetDelegateForFunctionPointer)
- Μη αντιστοιχισμένα HTTPS 404 με `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ή `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Απαντήσεις DNS με `AA=true` και `TXT "OK"` για σύντομα queries σε ύποπτα domains.<sup>[[4]](#references)</sup>
- Κίνηση προς το GitHub API στο `/repos/<owner>/<repo>/issues`, ακολουθούμενη από queries στο `ipinfo.io` από την ίδια αλυσίδα loader/beacon.<sup>[[5]](#references)</sup>
- Startup .lnk σε φακέλους Startup χρήστη ή κοινόχρηστους φακέλους Startup.<sup>[[1]](#references)</sup>
- Ύποπτα Run keys (π.χ., "Updater") και ονόματα loader όπως update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized δείγματα PE που ανακατευθύνουν το `_security_init_cookie` σε κώδικα downloader πριν εμφανίσουν ένα παραπλανητικό έγγραφο.<sup>[[5]](#references)</sup>
- Εγγράψιμες από τον χρήστη διαδρομές DLL στο %APPDATA%\Microsoft\Windows\Templates που περιέχουν το msimg32.dll.<sup>[[1]](#references)</sup>

## Σημειώσεις για τα πεδία OpSec

- KillDate: χρονική σήμανση μετά την οποία ο agent αυτοκαταργείται.<sup>[[1]](#references)</sup>
- WorkingTime: ώρες κατά τις οποίες ο agent πρέπει να είναι ενεργός, ώστε να συγχέεται με την επιχειρησιακή δραστηριότητα.<sup>[[1]](#references)</sup>

Αυτά τα πεδία μπορούν να χρησιμοποιηθούν για ομαδοποίηση και για να εξηγηθούν περίοδοι μειωμένης δραστηριότητας.

## YARA και στατικά ευρήματα

Η Unit 42 δημοσίευσε βασικούς κανόνες YARA για beacons (C/C++ και Go) και σταθερές API-hashing των loaders.<sup>[[1]](#references)</sup> Εξετάστε το ενδεχόμενο να τους συμπληρώσετε με κανόνες που αναζητούν τη διάταξη [size|ciphertext|16-byte-key] κοντά στο τέλος του PE .rdata, τις προεπιλεγμένες συμβολοσειρές HTTP profile και νεότερους δείκτες server/listener, όπως `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` και `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Ένα νέο open-source framework που αξιοποιείται σε πραγματικές επιθέσεις (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 στο GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Τεκμηρίωση του Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting ενός open-source C2 framework σε μεγάλη κλίμακα (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Το Tropic Trooper στρέφεται στο AdaptixC2 και σε έναν προσαρμοσμένο Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Τεκμηρίωση Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Τεκμηρίωση Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Σταθερές προστασίας μνήμης – Τεκμηρίωση Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Δημιουργία profile AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser beacon profile του AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Δημιουργία DNS profile του AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Συσκευασία profile του AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
