# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 è un framework modulare, open‑source post‑exploitation/C2 con beacon Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e supporto BOF. Questa pagina documenta:
- Come la sua configurazione RC4‑packed è incorporata e come estrarla dai beacon
- Indicatori di rete/profilo per listener HTTP/SMB/TCP
- TTPs comuni di loader e persistence osservati nel mondo reale, con link alle pagine sulle tecniche Windows rilevanti

## Beacon profiles and fields

AdaptixC2 supporta tre tipi principali di beacon:
- BEACON_HTTP: web C2 con servers/ports/SSL configurabili, method, URI, headers, user‑agent, e un nome di parametro personalizzato
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: socket diretti, opzionalmente con un marker prefisso per offuscare l'inizio del protocollo

Campi tipici del profilo osservati nelle configurazioni del beacon HTTP (dopo la decrittazione):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Esempio di profilo HTTP predefinito (da una build del beacon):
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
Profilo HTTP malevolo osservato (attacco reale):
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
## Impacchettamento della configurazione cifrata e percorso di caricamento

Quando l'operatore clicca Create nel builder, AdaptixC2 incorpora il profilo cifrato come tail blob nel beacon. Il formato è:
- 4 byte: dimensione della configurazione (uint32, little-endian)
- N byte: dati di configurazione cifrati con RC4
- 16 byte: chiave RC4

Il beacon loader copia la chiave di 16 byte dalla fine e decifra in loco il blocco di N byte con RC4:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicazioni pratiche:
- L'intera struttura spesso risiede nella sezione PE .rdata.
- L'estrazione è deterministica: leggere la dimensione, leggere il ciphertext di quella dimensione, leggere la chiave di 16‑byte posta immediatamente dopo, quindi RC4‑decrypt.

## Flusso di estrazione della configurazione (difensori)

Implementare un extractor che emuli la beacon logic:
1) Individuare il blob all'interno del PE (di solito .rdata). Un approccio pragmatico è scansionare .rdata alla ricerca di un layout plausibile [size|ciphertext|16‑byte key] e tentare RC4.
2) Leggere i primi 4 bytes → size (uint32 LE).
3) Leggere i successivi N=size bytes → ciphertext.
4) Leggere gli ultimi 16 bytes → RC4 key.
5) RC4‑decrypt il ciphertext. Quindi analizzare il profilo in chiaro come:
- u32/boolean scalars come indicato sopra
- length‑prefixed strings (u32 length seguito da bytes; può essere presente NUL terminale)
- arrays: servers_count seguito da quel numero di coppie [string, u32 port]

Proof‑of‑concept Python minimale (standalone, senza dipendenze esterne) che funziona con un blob pre‑estratto:
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
- When automating, use a PE parser to read .rdata then apply a sliding window: for each offset o, try size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt and check that string fields decode as UTF‑8 and lengths are sane.
- Parse SMB/TCP profiles by following the same length‑prefixed conventions.

## Fingerprinting di rete e hunting

HTTP
- Common: POST to operator‑selected URIs (e.g., /uri.php, /endpoint/api)
- Custom header parameter used for beacon ID (e.g., X‑Beacon‑Id, X‑App‑Id)
- User‑agents mimicking Firefox 20 or contemporary Chrome builds
- Polling cadence visible via sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners for intranet C2 where web egress is constrained
- TCP beacons may prepend a few bytes before traffic to obfuscate protocol start

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Download Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Allocate unmanaged memory, copy shellcode, switch protection to 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Execute via .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Startup folder shortcut (.lnk) to re‑launch a loader at logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), often with benign‑sounding names like "Updater" to start loader.ps1
- DLL search‑order hijack by dropping msimg32.dll under %APPDATA%\Microsoft\Windows\Templates for susceptible processes

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell spawning RW→RX transitions: VirtualProtect to PAGE_EXECUTE_READWRITE inside powershell.exe
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Startup .lnk under user or common Startup folders
- Suspicious Run keys (e.g., "Updater"), and loader names like update.ps1/loader.ps1
- User‑writable DLL paths under %APPDATA%\Microsoft\Windows\Templates containing msimg32.dll

## Note sui campi OpSec

- KillDate: timestamp after which the agent self‑expires
- WorkingTime: hours when the agent should be active to blend with business activity

These fields can be used for clustering and to explain observed quiet periods.

## YARA e indizi statici

Unit 42 published basic YARA for beacons (C/C++ and Go) and loader API‑hashing constants. Consider complementing with rules that look for the [size|ciphertext|16‑byte‑key] layout near PE .rdata end and the default HTTP profile strings.

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
