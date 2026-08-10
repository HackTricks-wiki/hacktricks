# AdaptixC2-Konfigurationsextraktion und TTPs

AdaptixC2 ist ein modulares, Open-Source-Post-Exploitation-/C2-Framework mit Windows-x86/x64-Beacons (EXE/DLL/Service-EXE/Raw-Shellcode) und BOF-Unterstützung.<sup>[[1]](#references)</sup> Diese Seite dokumentiert:
- Wie seine RC4-gepackte Konfiguration eingebettet ist und wie sie aus Beacons extrahiert wird
- Netzwerk-/Profilindikatoren für HTTP-/SMB-/TCP-Listener
- Häufige Loader- und Persistence-TTPs, die in freier Wildbahn beobachtet wurden, mit Links zu relevanten Windows-Technikseiten

Aktuelle Upstream-Releases enthalten außerdem DNS-/DoH-Beacon-Listener und die separate Gopher-Agent-/Listener-Familie. Daher kann moderne Adaptix-Infrastruktur mehr als die ursprünglichen HTTP-/SMB-/TCP-Oberflächen offenlegen, selbst wenn ein bestimmtes Sample weiterhin den klassischen Beacon-Agent verwendet.<sup>[[2]](#references)</sup>

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei primäre Beacon-Typen:<sup>[[1]](#references)</sup>
- BEACON_HTTP: Web-C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User-Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: Named-Pipe-Peer-to-Peer-C2 (Intranet)
- BEACON_TCP: direkte Sockets, optional mit einem vorangestellten Marker zur Verschleierung des Protokollstarts

Diese Beacon-Layouts sind in frühen Adaptix-Analysen öffentlich dokumentiert und weiterhin der häufigste Ausgangspunkt für die Extraktion auf Sample-Seite.<sup>[[1]](#references)</sup> Aktuelle Upstream-Builds enthalten jedoch auch `BeaconDNS` und Gopher-Extender auf der Serverseite. Gehe daher nicht davon aus, dass jede aktive Adaptix-Deployment ausschließlich HTTP-/SMB-/TCP-Infrastruktur offenlegt.<sup>[[2]](#references)</sup>

Typische Profilfelder, die in HTTP-Beacon-Konfigurationen beobachtet werden (nach der Entschlüsselung):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – werden zum Parsen von Response-Größen verwendet
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Aktuelle BeaconHTTP-Builds unterstützen außerdem die vom Operator ausgewählte Rotation über mehrere URIs, User-Agents, Host-Header und Server mit sequenzieller oder zufälliger Auswahl.<sup>[[2]](#references)</sup> Aus Sicht des Huntings bedeutet dies, dass ein einzelner infizierter Host über mehrere Callback-Pfade und Header-Kombinationen kommunizieren kann, ohne die klassische RC4-gepackte Beacon-Familie zu verlassen.

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
Beobachtetes bösartiges HTTP-Profil (realer Angriff):<sup>[[1]](#references)</sup>
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
## Verschlüsseltes Configuration-Packing und Load-Pfad

Wenn der Operator im Builder auf Create klickt, bettet AdaptixC2 das verschlüsselte Profil als Tail-Blob in den Beacon ein. Das Format ist:<sup>[[1]](#references)</sup>
- 4 Bytes: Configuration-Größe (uint32, little-endian)
- N Bytes: RC4-verschlüsselte Configuration-Daten
- 16 Bytes: RC4-Key

Der Beacon-Loader kopiert den 16-Byte-Key vom Ende und entschlüsselt den N-Byte-Block mit RC4 in place:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktische Auswirkungen:<sup>[[1]](#references)</sup>
- Die gesamte Struktur befindet sich häufig innerhalb des PE-Abschnitts .rdata.
- Die Extraktion ist deterministisch: size auslesen, den ciphertext dieser Größe auslesen, anschließend den direkt dahinter platzierten 16-Byte-key auslesen und dann per RC4 entschlüsseln.

## Workflow zur Configuration-Extraktion (Verteidiger)

Schreibe einen Extractor, der die Beacon-Logik nachahmt:<sup>[[1]](#references)</sup>
1) Den Blob innerhalb des PE lokalisieren (üblicherweise in .rdata). Ein pragmatischer Ansatz besteht darin, .rdata nach einem plausiblen Layout [size|ciphertext|16-byte key] zu durchsuchen und RC4 zu versuchen.
2) Die ersten 4 Bytes auslesen → size (uint32 LE).
3) Die nächsten N=size Bytes auslesen → ciphertext.
4) Die letzten 16 Bytes auslesen → RC4 key.
5) Den ciphertext per RC4 entschlüsseln. Anschließend das Klartext-Profil wie folgt parsen:
- u32/boolean-Skalare wie oben beschrieben
- Length-prefixed strings (u32 length gefolgt von Bytes; ein abschließendes NUL kann vorhanden sein)
- Arrays: servers_count, gefolgt von ebenso vielen [string, u32 port]-Paaren

Minimaler Python-Proof-of-Concept (standalone, keine externen Abhängigkeiten), der mit einem vorab extrahierten Blob funktioniert:
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
- Verwende bei der Automatisierung einen PE-Parser, um .rdata zu lesen, und wende anschließend ein Sliding Window an: Versuche für jeden Offset o die Größe = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = nächste 16 Bytes; entschlüssele mit RC4 und prüfe, ob String-Felder als UTF-8 decodiert werden und die Längen plausibel sind.
- Parse SMB/TCP-Profile, indem du denselben Length-prefixed-Konventionen folgst.

## Custom listener profiles: nicht nur das klassische HTTP-Schema fest codieren

Das äußere Packformat (`u32 size | RC4 ciphertext | 16-byte key`) ist wiederverwendbar. Daher können actor-customized Listener denselben Extraktionsworkflow beibehalten und gleichzeitig das Layout der entschlüsselten Felder vollständig ändern.

Ein gutes aktuelles Beispiel ist die Tropic-Trooper-Kampagne vom März 2026, bei der der extrahierte Adaptix beacon kein standardmäßiges HTTP/TCP-Profil enthielt. Stattdessen speicherte der entschlüsselte Blob GitHub-Transportparameter wie:<sup>[[5]](#references)</sup>
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
- Wenn der HTTP-Parser fehlschlägt, der Plaintext aber zusammenhängende Length-prefixed-UTF-8-Strings enthält, behalte das Sample und versuche alternative Schemas, anstatt es als False Positive zu verwerfen.

In dieser Kampagne verwendete der Custom Listener GitHub Issues als C2-Transport, und der beacon fragte `ipinfo.io` ab, um seine externe IP zu ermitteln, da die GitHub API dem Operator die Quelladresse des Opfers nicht direkt offenlegt.<sup>[[5]](#references)</sup>

## Network fingerprinting und Hunting

HTTP:<sup>[[1]](#references)</sup>
- Häufig: POST an vom Operator ausgewählte URIs (z. B. /uri.php, /endpoint/api)
- Benutzerdefinierter Header-Parameter für die beacon-ID (z. B. X‑Beacon‑Id, X‑App‑Id)
- User-Agents, die Firefox 20 oder aktuelle Chrome-Builds imitieren
- Anhand von `sleep_delay`/`jitter_delay` sichtbare Polling-Frequenz
- Neuere Builds können URIs, User-Agents, Host-Header und Server über verschiedene Callbacks hinweg rotieren. Daher sollte anhand ungewöhnlicher Header-Namen, Antwortgrößenmustern, TLS-Wiederverwendung und Timing geclustert werden, statt ein einzelnes Pfad-/UA-Paar anzunehmen.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB Named-Pipe-Listener für Intranet-C2, wenn der Web-Egress eingeschränkt ist
- TCP-Beacons können dem Datenverkehr einige Bytes voranstellen, um den Protokollbeginn zu verschleiern

Aktuelle Upstream-Teamserver-Defaults
- `profile.yaml` wird derzeit mit dem Teamserver `0.0.0.0:4321`, dem Endpoint `/endpoint`, den Zertifikat-/Key-Dateinamen `server.rsa.crt` und `server.rsa.key` sowie Extendern für HTTP, SMB, TCP, DNS, Beacon agent und Gopher ausgeliefert.<sup>[[2]](#references)</sup>
- Bei nicht übereinstimmenden Routen gibt der Standard-Error-Handler `Server: AdaptixC2` und `Adaptix-Version: v1.2` zurück.<sup>[[4]](#references)</sup>
- Der standardmäßige 404-Body enthält `AdaptixC2 404` und `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internetweite Scans fanden 2026 viele exponierte Teamserver auf `4321` und viele Beacon-Listener auf `43211`. Beide Ports sind daher nützliche Seed-Pivots, sollten jedoch nicht als vollständig angesehen werden.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- Der aktuelle BeaconDNS-Extender antwortet autoritativ (`AA=true`).
- Queries, die nicht der Form des Beacon-Protokolls entsprechen — insbesondere Namen mit weniger als 5 Labels vor der konfigurierten Domain — werden üblicherweise mit `TXT "OK"` beantwortet.
- Wenn die konfigurierte Basis-TTL auf null belassen wird, verwendet der Listener eine Basis von 10 Sekunden und fügt bis zu 59 Sekunden Jitter hinzu.
- Dadurch eignen sich Active Probes mit kurzen Labels, wenn kein HTTP-Listener exponiert ist.

## Loader- und Persistence-TTPs aus Incidents

In-memory-PowerShell-Loader:<sup>[[1]](#references)</sup>
- Laden Base64/XOR-Payloads herunter (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Reservieren unmanaged memory, kopieren Shellcode und ändern den Schutz über VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE).<sup>[[7]](#references)</sup>
- Führen über .NET dynamic invocation aus: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Eine Tropic-Trooper-Kette aus dem Jahr 2026 verwendete eine trojanisierte SumatraPDF-Executable (TOSHIS loader), die `_security_init_cookie` in schädlichen Code umleitete, anstatt den PE-Entry-Point zu patchen.
- Der Loader löste APIs über Adler-32-Hashing auf, lud ein Decoy-PDF herunter, bezog Second-Stage-Shellcode, entschlüsselte ihn mit AES-128-CBC über WinCrypt (`CryptDeriveKey` aus einem hardcodierten Seed) und führte einen Adaptix beacon reflectively im Speicher aus.
- Die Persistence wurde später auf Scheduled Tasks mit harmlos wirkenden Namen wie `\MSDNSvc` oder `\MicrosoftUDN` verlagert, die so konfiguriert waren, dass sie den Agent ungefähr alle zwei Stunden erneut starteten.

Siehe diese Seiten zu In-memory-Ausführung und AMSI/ETW-Aspekten:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Beobachtete Persistence-Mechanismen:<sup>[[1]](#references)</sup>
- Verknüpfung (.lnk) im Startup-Ordner, um bei der Anmeldung einen Loader erneut zu starten
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), häufig mit harmlos klingenden Namen wie "Updater", um loader.ps1 zu starten.<sup>[[10]](#references)</sup>
- DLL search-order hijacking durch Ablegen von msimg32.dll unter %APPDATA%\Microsoft\Windows\Templates für anfällige Prozesse

Technik-Deep-Dives und Prüfungen:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting-Ideen
- PowerShell, die RW→RX-Transitions auslöst: VirtualProtect auf PAGE_EXECUTE_READWRITE innerhalb von powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic-invocation-Muster (GetDelegateForFunctionPointer)
- Nicht übereinstimmende HTTPS-404s mit `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` oder `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-Antworten mit `AA=true` und `TXT "OK"` für kurze Queries unter verdächtigen Domains.<sup>[[4]](#references)</sup>
- GitHub-API-Datenverkehr zu `/repos/<owner>/<repo>/issues`, gefolgt von `ipinfo.io`-Abfragen aus derselben Loader-/Beacon-Kette.<sup>[[5]](#references)</sup>
- Startup-.lnk unter benutzerbezogenen oder allgemeinen Startup-Ordnern.<sup>[[1]](#references)</sup>
- Verdächtige Run keys (z. B. "Updater") sowie Loader-Namen wie update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanisierte PE-Samples, die `_security_init_cookie` in Downloader-Code umleiten, bevor ein Decoy-Dokument angezeigt wird.<sup>[[5]](#references)</sup>
- Vom Benutzer beschreibbare DLL-Pfade unter %APPDATA%\Microsoft\Windows\Templates, die msimg32.dll enthalten.<sup>[[1]](#references)</sup>

## Hinweise zu OpSec-Feldern

- KillDate: Zeitstempel, nach dem der Agent sich selbst deaktiviert.<sup>[[1]](#references)</sup>
- WorkingTime: Zeitfenster, in dem der Agent aktiv sein soll, um sich an Geschäftsaktivitäten anzupassen.<sup>[[1]](#references)</sup>

Diese Felder können zum Clustering und zur Erklärung beobachteter Ruhephasen verwendet werden.

## YARA und statische Anhaltspunkte

Unit 42 veröffentlichte grundlegende YARA-Regeln für Beacons (C/C++ und Go) sowie API-Hashing-Konstanten von Loadern.<sup>[[1]](#references)</sup> Ergänzend können Regeln verwendet werden, die nach dem Layout [size|ciphertext|16-byte-key] nahe dem Ende von PE .rdata, den Standard-HTTP-Profil-Strings und neueren Server-/Listener-Markern wie `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` und `ipinfo.io` suchen.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Ein neues Open-Source-Framework, das bei Angriffen in der Praxis eingesetzt wird (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework-Dokumentation](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting eines Open-Source-C2-Frameworks im großen Maßstab (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper wechselt zu AdaptixC2 und einem benutzerdefinierten Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft-Dokumentation](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Speicherschutzkonstanten – Microsoft-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
