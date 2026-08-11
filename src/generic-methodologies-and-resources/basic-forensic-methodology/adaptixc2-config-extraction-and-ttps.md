# AdaptixC2-Konfigurationsextraktion und TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ist ein modulares, Open-Source-Post-Exploitation/C2-Framework mit Windows-x86/x64-Beacons (EXE/DLL/Service-EXE/Raw-Shellcode) und BOF-Unterstützung.<sup>[[1]](#references)</sup> Diese Seite dokumentiert:
- Wie die RC4-gepackte Konfiguration eingebettet ist und wie sie aus Beacons extrahiert werden kann
- Netzwerk-/Profilindikatoren für HTTP/SMB/TCP-Listener
- Häufige Loader- und Persistence-TTPs, die in freier Wildbahn beobachtet wurden, mit Links zu relevanten Windows-Technikseiten

Neuere Upstream-Releases enthalten außerdem DNS-/DoH-Beacon-Listener und die separate Gopher-Agent-/Listener-Familie. Daher kann eine moderne Adaptix-Infrastruktur mehr als die ursprünglichen HTTP-/SMB-/TCP-Oberflächen offenlegen, selbst wenn ein bestimmtes Sample weiterhin den klassischen Beacon-Agent verwendet.<sup>[[2]](#references)</sup>

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei primäre Beacon-Typen:<sup>[[1]](#references)</sup>
- BEACON_HTTP: Web-C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User-Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: Named-Pipe-Peer-to-Peer-C2 (Intranet)
- BEACON_TCP: direkte Sockets, optional mit einem vorangestellten Marker zur Verschleierung des Protokollstarts

Dies sind die öffentlich dokumentierten Beacon-Layouts aus frühen Adaptix-Analysen, und sie sind weiterhin der häufigste Ausgangspunkt für die Extraktion auf Sample-Seite.<sup>[[1]](#references)</sup> Aktuelle Upstream-Builds enthalten jedoch auch `BeaconDNS`- und Gopher-Extender auf der Server-Seite. Daher sollte nicht davon ausgegangen werden, dass jede aktive Adaptix-Bereitstellung ausschließlich HTTP-/SMB-/TCP-Infrastruktur offenlegt.<sup>[[2]](#references)</sup>

Typische Profilfelder, die in HTTP-Beacon-Konfigurationen beobachtet werden (nach der Entschlüsselung):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (Array von Strings), ports (Array von u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed Strings)
- ans_pre_size (u32), ans_size (u32) – werden zum Parsen der Antwortgrößen verwendet
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Aktuelle BeaconHTTP-Builds unterstützen außerdem die vom Operator ausgewählte Rotation über mehrere URIs, User-Agents, Host-Header und Server hinweg, mit sequenzieller oder zufälliger Auswahl.<sup>[[2]](#references)</sup> Aus Sicht des Huntings bedeutet dies, dass ein einzelner infizierter Host über mehrere Callback-Pfade und Header-Kombinationen kommunizieren kann, ohne die klassische RC4-gepackte Beacon-Familie zu verlassen.

Beispiel für ein standardmäßiges HTTP-Profil (aus einem Beacon-Build):<sup>[[1]](#references)</sup>
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
Beobachtetes bösartiges HTTP-Profil (echter Angriff):<sup>[[1]](#references)</sup>
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
## Verschlüsselte Konfigurationspaketierung und Ladepfad

Wenn der Operator im Builder auf „Create“ klickt, bettet AdaptixC2 das verschlüsselte Profil als Tail-Blob in den Beacon ein. Das Format ist:<sup>[[1]](#references)</sup>
- 4 Bytes: Konfigurationsgröße (uint32, Little-Endian)
- N Bytes: RC4-verschlüsselte Konfigurationsdaten
- 16 Bytes: RC4-Schlüssel

Der Beacon-Loader kopiert den 16-Byte-Schlüssel vom Ende und entschlüsselt den N-Byte-Block mittels RC4 direkt an Ort und Stelle:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktische Auswirkungen:<sup>[[1]](#references)</sup>
- Die gesamte Struktur befindet sich häufig im PE-Abschnitt .rdata.
- Die Extraktion ist deterministisch: Größe lesen, den Ciphertext dieser Größe lesen, den direkt danach platzierten 16-Byte-Schlüssel lesen und anschließend per RC4 entschlüsseln.

## Workflow zur Configuration-Extraktion (Defenders)

Schreibe einen Extractor, der die Beacon-Logik nachahmt:<sup>[[1]](#references)</sup>
1) Finde den Blob innerhalb des PE (üblicherweise in .rdata). Ein pragmatischer Ansatz besteht darin, .rdata nach einem plausiblen Layout [size|ciphertext|16-byte key] zu durchsuchen und RC4 zu testen.
2) Lies die ersten 4 Bytes → size (uint32 LE).
3) Lies die nächsten N=size Bytes → ciphertext.
4) Lies die letzten 16 Bytes → RC4 key.
5) Entschlüssele den ciphertext per RC4. Parse anschließend das Plain-Profil wie folgt:
- u32/boolean-Skalare wie oben beschrieben
- Strings mit vorangestellter Länge (u32 length gefolgt von Bytes; ein abschließendes NUL kann vorhanden sein)
- Arrays: servers_count, gefolgt von entsprechend vielen [string, u32 port]-Paaren

Minimaler Python-Proof-of-Concept (standalone, ohne externe Abhängigkeiten), der mit einem vorab extrahierten Blob funktioniert:
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
Tipps:
- Verwende bei der Automatisierung einen PE parser, um .rdata zu lesen, und wende anschließend ein sliding window an: Für jeden Offset o versuche size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = nächste 16 Bytes; entschlüssele mit RC4 und prüfe, ob String-Felder als UTF-8 decodiert werden und die Längen plausibel sind.
- Parse SMB/TCP profiles, indem du denselben length-prefixed conventions folgst.

## Custom listener profiles: nicht nur das klassische HTTP-Schema fest codieren

Das äußere packing format (`u32 size | RC4 ciphertext | 16-byte key`) ist wiederverwendbar. Daher können actor-customized listeners denselben extraction workflow beibehalten, während sie das Layout der entschlüsselten Felder vollständig ändern.

Ein gutes aktuelles Beispiel ist die Tropic-Trooper-Kampagne vom März 2026, bei der der extrahierte Adaptix beacon kein standardmäßiges HTTP/TCP profile enthielt. Stattdessen speicherte der entschlüsselte blob GitHub-Transportparameter wie:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (zum Beispiel `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktische parser strategy:
- Erkenne zunächst den äußeren RC4 blob genau wie üblich.
- Verzweige nach der Entschlüsselung anhand von sentinel strings und der Plausibilität der Felder, anstatt sofort den HTTP parser zu erzwingen.
- Gute sentinels sind `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings oder offensichtlich gültige server/port arrays.
- Wenn der HTTP parser fehlschlägt, der plaintext jedoch kohärente length-prefixed UTF-8 strings enthält, behalte das sample und versuche alternative schemas, anstatt es als false positive zu verwerfen.

In dieser Kampagne verwendete der custom listener GitHub issues als C2-Transport, und der beacon fragte `ipinfo.io` ab, um seine externe IP zu ermitteln, da die GitHub API dem operator die Quelladresse des Opfers nicht direkt offenlegt.<sup>[[5]](#references)</sup>

## Network fingerprinting und Hunting

HTTP:<sup>[[1]](#references)</sup>
- Häufig: POST an vom operator ausgewählte URIs (z. B. /uri.php, /endpoint/api)
- Custom header parameter, der für die beacon ID verwendet wird (z. B. X‑Beacon‑Id, X‑App‑Id)
- User-agents, die Firefox 20 oder aktuelle Chrome builds nachahmen
- Anhand von sleep_delay/jitter_delay sichtbare polling cadence
- Neuere builds können URIs, user-agents, Host headers und server über verschiedene callbacks rotieren. Daher sollte anhand ungewöhnlicher header names, response-size patterns, TLS reuse und timing geclustert werden, statt ein einzelnes path/UA-Paar anzunehmen.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners für intranet C2, wenn der Web-egress eingeschränkt ist
- TCP beacons können dem Traffic einige Bytes voranstellen, um den protocol start zu verschleiern

Aktuelle upstream teamserver defaults
- `profile.yaml` wird derzeit mit dem teamserver `0.0.0.0:4321`, dem endpoint `/endpoint`, den certificate/key filenames `server.rsa.crt` und `server.rsa.key` sowie extenders für HTTP, SMB, TCP, DNS, Beacon agent und Gopher ausgeliefert.<sup>[[2]](#references)</sup>
- Bei nicht übereinstimmenden routes gibt der default error handler `Server: AdaptixC2` und `Adaptix-Version: v1.2` zurück.<sup>[[4]](#references)</sup>
- Der standardmäßige 404 body enthält `AdaptixC2 404` und `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internetweite scans fanden 2026 viele exponierte teamservers auf `4321` und viele beacon listeners auf `43211`. Daher sind beide ports nützliche seed pivots, sollten jedoch nicht als vollständig betrachtet werden.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- Der aktuelle BeaconDNS extender antwortet autoritativ (`AA=true`)
- Queries, die nicht der Form des beacon protocols entsprechen – insbesondere Namen mit weniger als 5 labels vor der konfigurierten domain – werden üblicherweise mit `TXT "OK"` beantwortet
- Wenn die konfigurierte base TTL auf null belassen wird, verwendet der listener eine 10-sekündige base und fügt bis zu 59 Sekunden jitter hinzu
- Dadurch sind active probes mit kurzen labels nützlich, wenn kein HTTP listener exponiert ist

## In Vorfällen beobachtete Loader- und Persistence-TTPs

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Laden Base64/XOR payloads herunter (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Reservieren unmanaged memory, kopieren shellcode und ändern den Schutz über VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE).<sup>[[7]](#references)</sup>
- Führen über .NET dynamic invocation aus: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Eine Tropic-Trooper-Kette aus dem Jahr 2026 verwendete eine trojanized SumatraPDF executable (TOSHIS loader), die `_security_init_cookie` in malicious code umleitete, anstatt den PE entry point zu patchen
- Der loader löste APIs über Adler-32 hashing auf, lud ein decoy PDF herunter, bezog second-stage shellcode, entschlüsselte ihn mit AES-128-CBC über WinCrypt (`CryptDeriveKey` aus einem hardcoded seed) und führte einen Adaptix beacon reflectively im memory aus
- Die Persistence wechselte später zu scheduled tasks mit harmlos wirkenden Namen wie `\MSDNSvc` oder `\MicrosoftUDN`, die so konfiguriert waren, dass sie den agent ungefähr alle zwei Stunden erneut starteten

Siehe diese Seiten für in-memory execution und AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Beobachtete Persistence mechanisms:<sup>[[1]](#references)</sup>
- Shortcut (.lnk) im Startup folder, um bei der Anmeldung einen loader erneut zu starten
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), häufig mit harmlos klingenden Namen wie "Updater", um loader.ps1 zu starten.<sup>[[10]](#references)</sup>
- DLL search-order hijack durch Ablegen von msimg32.dll unter %APPDATA%\Microsoft\Windows\Templates für anfällige processes

Technique deep-dives und Prüfungen:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting-Ideen
- PowerShell, das RW→RX transitions erzeugt: VirtualProtect auf PAGE_EXECUTE_READWRITE innerhalb von powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Nicht zugeordnete HTTPS-404s mit `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` oder `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses mit `AA=true` und `TXT "OK"` für kurze queries unter verdächtigen domains.<sup>[[4]](#references)</sup>
- GitHub API traffic zu `/repos/<owner>/<repo>/issues`, gefolgt von `ipinfo.io` lookups aus derselben loader/beacon chain.<sup>[[5]](#references)</sup>
- Startup .lnk im Benutzer- oder gemeinsamen Startup folder.<sup>[[1]](#references)</sup>
- Verdächtige Run keys (z. B. "Updater") und loader names wie update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE samples, die `_security_init_cookie` in downloader code umleiten, bevor ein decoy document angezeigt wird.<sup>[[5]](#references)</sup>
- Vom Benutzer beschreibbare DLL paths unter %APPDATA%\Microsoft\Windows\Templates, die msimg32.dll enthalten.<sup>[[1]](#references)</sup>

## Hinweise zu OpSec-Feldern

- KillDate: timestamp, nach dem der agent sich selbst beendet.<sup>[[1]](#references)</sup>
- WorkingTime: Stunden, in denen der agent aktiv sein soll, um sich an geschäftliche Aktivitäten anzupassen.<sup>[[1]](#references)</sup>

Diese Felder können zum Clustering und zur Erklärung beobachteter Ruhephasen verwendet werden.

## YARA und statische Anhaltspunkte

Unit 42 veröffentlichte grundlegende YARA für beacons (C/C++ und Go) sowie loader API-hashing constants.<sup>[[1]](#references)</sup> Ergänze diese Regeln durch Regeln, die nach dem Layout [size|ciphertext|16-byte-key] nahe dem Ende von PE .rdata, den default HTTP profile strings und neueren server/listener markers wie `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` und `ipinfo.io` suchen.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Ein neues Open-Source-Framework, das bei Angriffen in der Praxis eingesetzt wird (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting eines Open-Source-C2-Frameworks im großen Maßstab (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper wechselt zu AdaptixC2 und einem Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
