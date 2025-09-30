# AdaptixC2 Ekstrakcija konfiguracije i TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 je modularan, open‑source post‑exploitation/C2 framework sa Windows x86/x64 beaconima (EXE/DLL/service EXE/raw shellcode) i podrškom za BOF. Ova stranica dokumentuje:
- Kako je njegova RC4‑packed konfiguracija ugrađena i kako je izvući iz beacons
- Mrežni/profile indikatori za HTTP/SMB/TCP listeners
- Uobičajene loader i persistence TTPs primećene u prirodi, sa linkovima ka relevantnim stranicama tehnika za Windows

## Beacon profili i polja

AdaptixC2 podržava tri primarna tipa beacon-a:
- BEACON_HTTP: web C2 sa podesivim servers/ports/SSL, method, URI, headers, user‑agent i prilagođenim imenom parametra
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direktni sockets, opciono sa prepended markerom za obfuscation starta protokola

Tipična polja profila zabeležena u HTTP beacon konfiguracijama (posle dekripcije):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
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
Uočen zlonamerni HTTP profil (stvarni napad):
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
## Pakovanje šifrovane konfiguracije i put učitavanja

Kada operator klikne Create u builderu, AdaptixC2 ugradi šifrovani profil kao tail blob u beacon. Format je:
- 4 bajta: veličina konfiguracije (uint32, little‑endian)
- N bajtova: RC4‑šifrovani podaci konfiguracije
- 16 bajtova: RC4 ključ

Beacon loader kopira 16‑bajtni ključ sa kraja i RC4 dekriptuje N‑bajtni blok na mestu:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- The entire structure often lives inside the PE .rdata section.
- Extraction is deterministic: read size, read ciphertext of that size, read the 16‑byte key placed immediately after, then RC4‑decrypt.

## Tok ekstrakcije konfiguracije (odbrambeni timovi)

Napišite extractor koji oponaša beacon logic:
1) Pronađite blob unutar PE (obično .rdata). Pragmatičan pristup je skenirati .rdata za verovatnim [size|ciphertext|16‑byte key] rasporedom i pokušati RC4.
2) Pročitajte prvih 4 bajta → size (uint32 LE).
3) Pročitajte narednih N=size bajtova → ciphertext.
4) Pročitajte zadnjih 16 bajtova → RC4 key.
5) RC4‑decrypt the ciphertext. Zatim parsirajte plain profile kao:
- u32/boolean scalari kao što je gore navedeno
- length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
- arrays: servers_count followed by that many [string, u32 port] pairs

Minimalni Python proof‑of‑concept (samostalan, bez eksternih zavisnosti) koji radi sa pre‑ekstrahovanim blob-om:
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
- Kada automatizujete, koristite PE parser da pročitate .rdata pa primenite sliding window: za svaki offset o, probajte size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], kandidat ključ = narednih 16 bajtova; RC4‑decrypt i proverite da li string polja dekodiraju kao UTF‑8 i da su dužine razumske.
- Parse‑ujte SMB/TCP profile prateći iste length‑prefixed konvencije.

## Mrežno fingerprintovanje i lov

HTTP
- Uobičajeno: POST ka operator‑selektovanim URI‑jevima (npr. /uri.php, /endpoint/api)
- Custom header parametar koji se koristi za beacon ID (npr. X‑Beacon‑Id, X‑App‑Id)
- User‑agenti koji imitiraju Firefox 20 ili savremene Chrome buildove
- Polling cadence vidljiv kroz sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe slušači za intranet C2 gde je web egress ograničen
- TCP beacons mogu prepended nekoliko bajtova pre saobraćaja da zamaskiraju početak protokola

## Loader and persistence TTPs viđeni u incidentima

In‑memory PowerShell loaders
- Download Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Allocate unmanaged memory, copy shellcode, switch protection to 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Execute via .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Startup folder shortcut (.lnk) za ponovni launch loader‑a pri logon‑u
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), često sa benigno‑zvučnim imenima kao "Updater" za startovanje loader.ps1
- DLL search‑order hijack postavljanjem msimg32.dll pod %APPDATA%\Microsoft\Windows\Templates za ranjive procese

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideje za lov
- PowerShell procesi koji prave RW→RX prelaze: VirtualProtect na PAGE_EXECUTE_READWRITE unutar powershell.exe
- Dynamic invocation obrasci (GetDelegateForFunctionPointer)
- Startup .lnk u korisničkim ili zajedničkim Startup folderima
- Sumnjivi Run ključevi (npr. "Updater"), i imena loadera kao update.ps1/loader.ps1
- User‑writable DLL putanje pod %APPDATA%\Microsoft\Windows\Templates koje sadrže msimg32.dll

## Napomene o OpSec poljima

- KillDate: timestamp posle kojeg se agent samouništava / isključuje
- WorkingTime: sati kada agent treba da bude aktivan da bi se uklopio sa poslovnom aktivnošću

Ova polja se mogu koristiti za klasterovanje i za objašnjenje primećenih mirnih perioda.

## YARA i statički tragovi

Unit 42 je objavio osnovne YARA za beacons (C/C++ i Go) i konstante za loader API‑hashing. Razmotrite dopunu pravilima koja traže [size|ciphertext|16‑byte‑key] raspored blizu kraja PE .rdata i podrazumevanih HTTP profile stringova.

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
