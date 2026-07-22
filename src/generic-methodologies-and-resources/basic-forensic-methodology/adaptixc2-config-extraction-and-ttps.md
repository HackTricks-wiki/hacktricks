# AdaptixC2-Konfigurationsextraktion und TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ist ein modulares, open-source Post-Exploitation-/C2-Framework mit Windows-x86/x64-beacons (EXE/DLL/service EXE/raw shellcode) und BOF-Unterstützung. Diese Seite dokumentiert:
- Wie die RC4-gepackte Konfiguration eingebettet ist und wie sie aus beacons extrahiert werden kann
- Netzwerk-/Profilindikatoren für HTTP-/SMB-/TCP-listeners
- Häufige Loader- und Persistence-TTPs, die in freier Wildbahn beobachtet wurden, mit Links zu relevanten Windows-Technikseiten

Neuere Upstream-Releases enthalten außerdem DNS-/DoH-beacon-listeners sowie die separate Gopher-Agent-/listener-Familie. Daher kann moderne Adaptix-Infrastruktur mehr als nur die ursprünglichen HTTP-/SMB-/TCP-Oberflächen offenlegen, selbst wenn ein bestimmtes Sample weiterhin den klassischen beacon agent verwendet.

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei primäre beacon-Typen:
- BEACON_HTTP: Web-C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User-Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: Named-Pipe-Peer-to-Peer-C2 (Intranet)
- BEACON_TCP: direkte Sockets, optional mit einem vorangestellten Marker zur Verschleierung des Protokollstarts

Dies sind die in frühen Adaptix-Analysen öffentlich dokumentierten beacon-Layouts, die weiterhin den häufigsten Ausgangspunkt für die Extraktion auf Sample-Seite darstellen. Aktuelle Upstream-Builds enthalten jedoch ebenfalls `BeaconDNS`- und Gopher-extenders auf der Serverseite. Daher sollte nicht angenommen werden, dass jede aktive Adaptix-Bereitstellung ausschließlich HTTP-/SMB-/TCP-Infrastruktur offenlegt.

Typische Profilfelder, die in HTTP-beacon-Konfigurationen beobachtet wurden (nach der Entschlüsselung):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – werden zum Parsen der Antwortgrößen verwendet
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Neuere BeaconHTTP-Builds unterstützen außerdem eine vom Operator ausgewählte Rotation über mehrere URIs, User-Agents, Host-Header und Server hinweg, mit sequenzieller oder zufälliger Auswahl. Aus Sicht der Bedrohungssuche bedeutet dies, dass ein einzelner infizierter Host über mehrere Callback-Pfade und Header-Kombinationen kommunizieren kann, ohne die klassische RC4-gepackte beacon-Familie zu verlassen.

Beispiel für ein standardmäßiges HTTP-Profil (aus einem beacon build):
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
## Verschlüsseltes Configuration-Packing und Ladepfad

Wenn der Operator im Builder auf Create klickt, bettet AdaptixC2 das verschlüsselte Profil als Tail-Blob in den Beacon ein. Das Format ist:
- 4 Bytes: Größe der Configuration (uint32, little-endian)
- N Bytes: RC4-verschlüsselte Configuration-Daten
- 16 Bytes: RC4-Key

Der Beacon-Loader kopiert den 16-Byte-Key vom Ende und entschlüsselt den N-Byte-Block per RC4 direkt an Ort und Stelle:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktische Auswirkungen:
- Die gesamte Struktur befindet sich häufig innerhalb des PE-Abschnitts .rdata.
- Die Extraktion ist deterministisch: size auslesen, den Ciphertext dieser Größe auslesen, den direkt danach platzierten 16-Byte-Key auslesen und anschließend mit RC4 entschlüsseln.

## Workflow zur Configuration-Extraktion (Verteidiger)

Schreibe einen Extractor, der die Beacon-Logik nachahmt:
1) Finde den Blob innerhalb des PE (üblicherweise in .rdata). Ein pragmatischer Ansatz besteht darin, .rdata nach einem plausiblen Layout [size|ciphertext|16-byte key] zu durchsuchen und RC4 zu versuchen.
2) Lies die ersten 4 Bytes aus → size (uint32 LE).
3) Lies die nächsten N=size Bytes aus → ciphertext.
4) Lies die letzten 16 Bytes aus → RC4 key.
5) Entschlüssele den ciphertext mit RC4. Parse das Plaintext-Profil anschließend wie folgt:
- u32/boolean-Skalare wie oben angegeben
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
- Verwende beim Automatisieren einen PE-Parser, um .rdata zu lesen, und wende anschließend ein Sliding Window an: Versuche für jeden Offset o die Größe = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size] und den Kandidatenschlüssel = die nächsten 16 Bytes; entschlüssele mit RC4 und prüfe, ob String-Felder als UTF-8 decodiert werden und die Längen plausibel sind.
- Parse SMB/TCP-Profile, indem du denselben längenpräfixierten Konventionen folgst.

## Custom listener profiles: nicht nur das klassische HTTP-Schema fest codieren

Das äußere Packformat (`u32 size | RC4 ciphertext | 16-byte key`) ist wiederverwendbar. Daher können angepasste Listener von Actors denselben Extraktionsworkflow beibehalten und gleichzeitig das Layout der entschlüsselten Felder vollständig ändern.

Ein gutes aktuelles Beispiel ist die Tropic-Trooper-Kampagne von April 2026, bei der der extrahierte Adaptix beacon kein Standard-HTTP/TCP-Profil enthielt. Stattdessen speicherte der entschlüsselte Blob GitHub-Transportparameter wie:
- `repo_owner`
- `repo_name`
- `api_host` (zum Beispiel `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktische Parser-Strategie:
- Erkenne den äußeren RC4-Blob zunächst genau wie üblich.
- Verzweige nach der Entschlüsselung anhand von Sentinel-Strings und der Plausibilität der Felder, anstatt sofort den HTTP-Parser zu erzwingen.
- Gute Sentinels sind `api.github.com`, `/issues?state=open`, HTTP-Verben/URIs, Named-Pipe-ähnliche Strings oder offensichtlich gültige Server-/Port-Arrays.
- Wenn der HTTP-Parser fehlschlägt, der Plaintext aber zusammenhängende längenpräfixierte UTF-8-Strings enthält, behalte das Sample und versuche alternative Schemata, anstatt es als False Positive zu verwerfen.

In dieser Kampagne verwendete der Custom Listener GitHub issues als C2-Transport. Der beacon fragte außerdem `ipinfo.io` ab, um seine externe IP zu ermitteln, da die GitHub API dem Operator die Quelladresse des Opfers nicht direkt offenlegt.

## Network fingerprinting und Hunting

HTTP
- Üblich: POST an vom Operator ausgewählte URIs (z. B. /uri.php, /endpoint/api)
- Benutzerdefinierter Header-Parameter für die beacon-ID (z. B. X‑Beacon‑Id, X‑App‑Id)
- User-Agents, die Firefox 20 oder zeitgenössische Chrome-Builds imitieren
- Anhand von sleep_delay/jitter_delay sichtbare Polling-Frequenz
- Neuere Builds können URIs, User-Agents, Host-Header und Server über verschiedene Callbacks hinweg rotieren. Daher sollte nach ungewöhnlichen Header-Namen, Response-Größenmustern, TLS-Wiederverwendung und Timing geclustert werden, anstatt von einem einzelnen Pfad-/UA-Paar auszugehen.

SMB/TCP
- SMB Named-Pipe-Listener für Intranet-C2, wenn der Web-Egress eingeschränkt ist
- TCP beacons können dem Traffic einige Bytes voranstellen, um den Protokollbeginn zu verschleiern

Aktuelle Upstream-teamserver-Defaults
- `profile.yaml` wird derzeit mit dem teamserver `0.0.0.0:4321`, dem Endpoint `/endpoint`, den Zertifikat-/Key-Dateinamen `server.rsa.crt` und `server.rsa.key` sowie Extendern für HTTP, SMB, TCP, DNS, Beacon agent und Gopher ausgeliefert.
- Bei nicht passenden Routen gibt der Standard-Error-Handler `Server: AdaptixC2` und `Adaptix-Version: v1.2` zurück.
- Der standardmäßige 404-Body enthält `AdaptixC2 404` und `You need to enter the correct connection details.`
- Internetweite Scans fanden 2026 viele exponierte teamserver auf `4321` und zahlreiche beacon listeners auf `43211`. Beide Ports sind daher nützliche Seed-Pivots, sollten aber nicht als vollständig betrachtet werden.

DNS/DoH listener fingerprints
- Der aktuelle BeaconDNS-Extender antwortet autoritativ (`AA=true`).
- Queries, die nicht dem Shape des beacon-Protokolls entsprechen — insbesondere Namen mit weniger als 5 Labels vor der konfigurierten Domain — werden üblicherweise mit `TXT "OK"` beantwortet.
- Wenn die konfigurierte Basis-TTL auf null belassen wird, verwendet der Listener eine 10-Sekunden-Basis und fügt bis zu 59 Sekunden Jitter hinzu.
- Dadurch sind Active Probes mit kurzen Labels nützlich, wenn kein HTTP-Listener exponiert ist.

## In Vorfällen beobachtete Loader- und Persistence-TTPs

In-memory-PowerShell-Loader
- Laden Base64/XOR-Payloads herunter (Invoke-RestMethod / WebClient).
- Allokieren unmanaged memory, kopieren Shellcode, ändern den Schutz über VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE).
- Führen über .NET dynamic invocation aus: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- Eine Tropic-Trooper-Kette von 2026 verwendete eine trojanized-SumatraPDF-Executable (TOSHIS loader), die `_security_init_cookie` in bösartigen Code umleitete, anstatt den PE entry point zu patchen.
- Der Loader löste APIs über Adler-32-Hashing auf, lud ein Decoy-PDF herunter, rief Second-stage-Shellcode ab, entschlüsselte ihn mit AES-128-CBC über WinCrypt (`CryptDeriveKey` aus einem hardcodierten Seed) und führte einen Adaptix beacon reflectively im Speicher aus.
- Die Persistence wurde später auf scheduled tasks mit unauffällig wirkenden Namen wie `\MSDNSvc` oder `\MicrosoftUDN` verlagert, die so konfiguriert waren, den Agenten ungefähr alle zwei Stunden erneut zu starten.

Siehe diese Seiten für In-memory execution und AMSI/ETW-Aspekte:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Beobachtete Persistence-Mechanismen
- Shortcut (.lnk) im Startup-Ordner, um beim Logon einen Loader erneut zu starten
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), oft mit unauffälligen Namen wie "Updater", um loader.ps1 zu starten
- DLL search-order hijack durch Ablegen von msimg32.dll unter %APPDATA%\Microsoft\Windows\Templates für anfällige Prozesse

Technik-Deep-Dives und Prüfungen:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting-Ideen
- PowerShell, das RW→RX-Übergänge erzeugt: VirtualProtect auf PAGE_EXECUTE_READWRITE innerhalb von powershell.exe
- Dynamic-invocation-Muster (GetDelegateForFunctionPointer)
- Nicht passende HTTPS-404s mit `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` oder `You need to enter the correct connection details.`
- DNS-Antworten mit `AA=true` und `TXT "OK"` für kurze Queries unter verdächtigen Domains
- GitHub-API-Traffic zu `/repos/<owner>/<repo>/issues`, gefolgt von `ipinfo.io`-Abfragen aus derselben Loader-/beacon-Kette
- Startup-.lnk unter Benutzer- oder allgemeinen Startup-Ordnern
- Verdächtige Run keys (z. B. "Updater") und Loader-Namen wie update.ps1/loader.ps1
- Trojanized-PE-Samples, die `_security_init_cookie` in Downloader-Code umleiten, bevor ein Decoy-Dokument angezeigt wird
- Vom Benutzer beschreibbare DLL-Pfade unter %APPDATA%\Microsoft\Windows\Templates, die msimg32.dll enthalten

## Hinweise zu OpSec-Feldern

- KillDate: Zeitstempel, nach dem der Agent sich selbst beendet
- WorkingTime: Zeitfenster, in denen der Agent aktiv sein soll, um sich an die Geschäftsaktivität anzupassen

Diese Felder können zum Clustering und zur Erklärung beobachteter Ruhephasen verwendet werden.

## YARA und statische Anhaltspunkte

Unit 42 veröffentlichte grundlegende YARA für beacons (C/C++ und Go) sowie Konstanten für das API-Hashing von Loadern. Ergänze dies durch Regeln, die nach dem Layout [size|ciphertext|16-byte-key] nahe dem Ende von PE .rdata, den Standard-HTTP-Profil-Strings und neueren Server-/Listener-Markern wie `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` und `ipinfo.io` suchen.

## Referenzen

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
