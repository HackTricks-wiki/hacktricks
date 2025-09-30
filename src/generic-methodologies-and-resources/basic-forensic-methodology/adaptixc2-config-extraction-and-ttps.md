# AdaptixC2 Ekstrakcja konfiguracji i TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 to modułowy, open‑source framework post‑exploitation/C2 z Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) i wsparciem BOF. Ta strona opisuje:
- Jak jego konfiguracja spakowana RC4 jest osadzana i jak ją wyodrębnić z beacons
- Wskaźniki sieciowe/profilowe dla listenerów HTTP/SMB/TCP
- Typowe TTPs dotyczące loaderów i persistence obserwowane w rzeczywistych atakach, z linkami do odpowiednich stron technik Windows

## Profile i pola Beacon

AdaptixC2 obsługuje trzy główne typy beacon:
- BEACON_HTTP: web C2 z konfigurowalnymi serwerami/portami/SSL, metodą, URI, nagłówkami, user‑agent i niestandardową nazwą parametru
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, opcjonalnie z prefiksowanym markerem do zacierania początku protokołu

Typowe pola profilu obserwowane w konfiguracjach HTTP beacon (po odszyfrowaniu):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Przykładowy domyślny profil HTTP (z beacon build):
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
Zaobserwowany złośliwy profil HTTP (rzeczywisty atak):
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
## Szyfrowane pakowanie konfiguracji i ścieżka ładowania

Gdy operator kliknie Create w builderze, AdaptixC2 osadza zaszyfrowany profil jako tail blob w beaconie. Format jest następujący:
- 4 bajty: rozmiar konfiguracji (uint32, little‑endian)
- N bajtów: dane konfiguracji zaszyfrowane RC4
- 16 bajtów: klucz RC4

Beacon loader kopiuje 16‑bajtowy klucz z końca i deszyfruje RC4 blok N‑bajtów na miejscu:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implikacje praktyczne:
- Cała struktura często znajduje się w sekcji PE .rdata.
- Ekstrakcja jest deterministyczna: odczytaj size, odczytaj ciphertext o tej wielkości, odczytaj 16‑byte key umieszczony bezpośrednio po nim, a następnie RC4‑decrypt.

## Proces ekstrakcji konfiguracji (obrońcy)

Napisz extractor, który naśladuje logikę beacon:
1) Zlokalizuj blob wewnątrz PE (zwykle .rdata). Pragmatyczne podejście to przeskanowanie .rdata w poszukiwaniu prawdopodobnego układu [size|ciphertext|16‑byte key] i próba RC4.
2) Odczytaj pierwsze 4 bajty → size (uint32 LE).
3) Odczytaj następne N=size bajtów → ciphertext.
4) Odczytaj ostatnie 16 bajtów → RC4 key.
5) RC4‑decrypt ciphertext. Następnie sparsuj odszyfrowany profil jako:
- u32/boolean scalars zgodnie z powyższym
- length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
- arrays: servers_count followed by that many [string, u32 port] pairs

Minimalny proof‑of‑concept w Pythonie (samodzielny, bez zewnętrznych zależności), który działa z wstępnie wyodrębnionym blobem:
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
- Przy automatyzacji użyj parsera PE do odczytu .rdata, następnie zastosuj sliding window: dla każdego offsetu o spróbuj size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt i sprawdź, czy pola string dekodują się jako UTF‑8 i czy długości są sensowne.
- Parsuj profile SMB/TCP stosując te same konwencje z prefiksem długości.

## Network fingerprinting and hunting

HTTP
- Common: POST to operator‑selected URIs (e.g., /uri.php, /endpoint/api)
- Niestandardowy parametr nagłówka używany jako beacon ID (e.g., X‑Beacon‑Id, X‑App‑Id)
- User‑agents podszywające się pod Firefox 20 lub współczesne buildy Chrome
- Polling cadence widoczna przez sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners dla intranetowego C2, gdy egress webowy jest ograniczony
- TCP beacons mogą dołączać kilka bajtów przed ruchem, aby zniekształcić początek protokołu

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Pobierają payloady Base64/XOR (Invoke‑RestMethod / WebClient)
- Alokują unmanaged memory, kopiują shellcode, zmieniają ochronę na 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Wykonanie przez .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Zaobserwowane mechanizmy persistence
- Skrót w folderze Startup (.lnk) do ponownego uruchomienia loadera przy logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), często z nazwami brzmiącymi benign‑owo jak "Updater" uruchamiającymi loader.ps1
- DLL search‑order hijack przez upuszczenie msimg32.dll pod %APPDATA%\Microsoft\Windows\Templates dla podatnych procesów

Szczegółowe opisy technik i kontrole:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pomysły na hunting
- Przejścia RW→RX w powershell.exe: VirtualProtect do PAGE_EXECUTE_READWRITE
- Wzorce dynamic invocation (GetDelegateForFunctionPointer)
- Skróty .lnk w folderach Startup użytkownika lub wspólnym Startup
- Podejrzane Run keys (np. "Updater") oraz nazwy loaderów jak update.ps1/loader.ps1
- Ścieżki DLL zapisywalne przez użytkownika pod %APPDATA%\Microsoft\Windows\Templates zawierające msimg32.dll

## Notes on OpSec fields

- KillDate: znacznik czasu, po którym agent sam wygasa
- WorkingTime: godziny, w których agent powinien być aktywny, by wtopić się w aktywność biznesową

Pola te można wykorzystać do klastrowania i wyjaśniania obserwowanych okresów ciszy.

## YARA and static leads

Unit 42 opublikował podstawowe reguły YARA dla beaconów (C/C++ i Go) oraz stałe API‑hashingu loaderów. Rozważ uzupełnienie reguł o wzorce szukające układu [size|ciphertext|16‑byte‑key] w pobliżu końca PE .rdata oraz domyślnych stringów profilu HTTP.

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
