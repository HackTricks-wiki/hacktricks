# AdaptixC2 Konfigurations-Extraktion und TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ist ein modulares, Open‑Source Post‑Exploitation/C2‑Framework mit Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) und BOF‑Support. Diese Seite dokumentiert:
- Wie seine RC4‑verpackte Konfiguration eingebettet ist und wie man sie aus Beacons extrahiert
- Netzwerk-/Profilindikatoren für HTTP/SMB/TCP Listener
- Häufige Loader- und Persistence‑TTPs, die in der Wildnis beobachtet wurden, mit Links zu relevanten Windows‑Technikseiten

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei Haupt‑Beacon‑Typen:
- BEACON_HTTP: web C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User‑Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: named‑pipe Peer‑to‑Peer C2 (Intranet)
- BEACON_TCP: direkte Sockets, optional mit einem vorangestellten Marker, um den Protokollstart zu verschleiern

Typische Profilfelder, die in HTTP‑Beacon‑Konfigurationen beobachtet werden (nach der Entschlüsselung):
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
Beobachtetes bösartiges HTTP-Profil (echter Angriff):
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
## Verschlüsselte Konfigurationsverpackung und Ladepfad

Wenn der Operator im builder auf Create klickt, bettet AdaptixC2 das verschlüsselte Profil als tail blob in den beacon ein. Das Format ist:
- 4 Bytes: Größe der Konfiguration (uint32, little‑endian)
- N Bytes: RC4‑verschlüsselte Konfigurationsdaten
- 16 Bytes: RC4‑Schlüssel

Der beacon loader kopiert den 16‑Byte‑Schlüssel vom Ende und RC4‑entschlüsselt den N‑Byte‑Block an Ort und Stelle:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- Die gesamte Struktur liegt oft im PE-.rdata-Abschnitt.
- Die Extraktion ist deterministisch: Größe lesen, den ciphertext dieser Größe lesen, den unmittelbar danach platzierten 16‑Byte‑Key lesen und dann mit RC4 entschlüsseln.

## Workflow zur Konfigurations-Extraktion (Verteidiger)

Schreibe einen Extractor, der die beacon-Logik nachahmt:
1) Finde den Blob innerhalb der PE (häufig .rdata). Ein pragmatischer Ansatz ist, .rdata nach einem plausiblen [size|ciphertext|16‑byte key]-Layout zu scannen und RC4 zu versuchen.
2) Lese die ersten 4 Bytes → size (uint32 LE).
3) Lese die nächsten N=size Bytes → ciphertext.
4) Lese die letzten 16 Bytes → RC4 key.
5) RC4‑entschlüssele den ciphertext. Dann parse das plain profile als:
- u32/boolean scalars wie oben beschrieben
- length‑prefixed strings (u32 length gefolgt von Bytes; trailing NUL kann vorhanden sein)
- arrays: servers_count gefolgt von entsprechend vielen [string, u32 port]-Paaren

Minimaler Python proof‑of‑concept (standalone, ohne externe Abhängigkeiten), das mit einem vorab extrahierten Blob funktioniert:
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
- Beim Automatisieren einen PE‑Parser verwenden, .rdata auslesen und ein Sliding‑Window anwenden: für jeden Offset o versuche size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt und prüfen, ob String‑Felder als UTF‑8 decodieren und Längen plausibel sind.
- SMB/TCP‑Profile nach denselben length‑prefixed Konventionen parsen.

## Network fingerprinting and hunting

HTTP
- Common: POST an vom Operator ausgewählte URIs (z. B. /uri.php, /endpoint/api)
- Custom header parameter verwendet für beacon ID (z. B. X‑Beacon‑Id, X‑App‑Id)
- User‑agents, die Firefox 20 oder zeitgenössische Chrome‑Builds nachahmen
- Polling‑Cadence sichtbar via sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe Listener für intranet C2, wenn Web‑Egress eingeschränkt ist
- TCP‑Beacons können einige Bytes vor dem Traffic voranstellen, um den Protokollstart zu verschleiern

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Laden Base64/XOR Payloads (Invoke‑RestMethod / WebClient)
- Unmanaged Memory allokieren, Shellcode kopieren, Protection via VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE) setzen
- Ausführen über .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Startup‑Ordner Shortcut (.lnk), um einen Loader beim Logon neu zu starten
- Registry Run Keys (HKCU/HKLM ...\CurrentVersion\Run), oft mit harmlos klingenden Namen wie "Updater", um loader.ps1 zu starten
- DLL Search‑Order Hijack durch Ablegen von msimg32.dll unter %APPDATA%\Microsoft\Windows\Templates für anfällige Prozesse

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting‑Ideen
- PowerShell‑Spawns mit RW→RX‑Transitions: VirtualProtect zu PAGE_EXECUTE_READWRITE innerhalb von powershell.exe
- Dynamic invocation‑Muster (GetDelegateForFunctionPointer)
- Startup .lnk unter user oder common Startup‑Ordnern
- Suspicious Run Keys (z. B. "Updater") und Loader‑Namen wie update.ps1/loader.ps1
- User‑writable DLL‑Pfad unter %APPDATA%\Microsoft\Windows\Templates, der msimg32.dll enthält

## Notes on OpSec fields

- KillDate: Timestamp, nach dem der Agent sich selbst deaktiviert
- WorkingTime: Stunden, in denen der Agent aktiv sein sollte, um sich an Geschäftstätigkeit anzupassen

Diese Felder können für Clustering genutzt werden und helfen, beobachtete ruhige Perioden zu erklären.

## YARA and static leads

Unit 42 veröffentlichte grundlegende YARA für beacons (C/C++ und Go) und Loader API‑hashing Konstanten. In Erwägung ziehen, Regeln zu ergänzen, die nach dem [size|ciphertext|16‑byte‑key] Layout in der Nähe des PE .rdata‑Endes und den Default HTTP‑Profilstrings suchen.

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
