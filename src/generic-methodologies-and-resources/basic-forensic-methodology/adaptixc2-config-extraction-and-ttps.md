# AdaptixC2-Konfigurationsextraktion und TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ist ein modulares, quelloffenes Post-Exploitation-/C2-Framework mit Windows-x86/x64-Beacons (EXE/DLL/Service-EXE/Raw-Shellcode) und BOF-Unterstützung.<sup>[[1]](#references)</sup> Diese Seite dokumentiert:
- Wie die mit RC4 gepackte Konfiguration eingebettet ist und wie sie aus Beacons extrahiert werden kann
- Netzwerk-/Profilindikatoren für HTTP-/SMB-/TCP-Listener
- Häufige Loader- und Persistence-TTPs, die in freier Wildbahn beobachtet wurden, mit Links zu relevanten Windows-Technikseiten

Aktuelle Upstream-Versionen enthalten außerdem DNS-/DoH-Beacon-Listener sowie die separate Gopher-Agent-/Listener-Familie. Moderne Adaptix-Infrastrukturen können daher mehr als nur die ursprünglichen HTTP-/SMB-/TCP-Schnittstellen bereitstellen, selbst wenn ein bestimmtes Sample noch den klassischen Beacon-Agent verwendet.<sup>[[2]](#references)</sup>

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei primäre Beacon-Typen:<sup>[[1]](#references)</sup>
- BEACON_HTTP: Web-C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User-Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: Peer-to-Peer-C2 über Named Pipes (Intranet)
- BEACON_TCP: direkte Sockets, optional mit vorangestelltem Marker zur Verschleierung des Protokollstarts

Dies sind die in frühen Adaptix-Analysen öffentlich dokumentierten Beacon-Layouts, die weiterhin den häufigsten Ausgangspunkt für die Extraktion auf Sample-Seite darstellen.<sup>[[1]](#references)</sup> Aktuelle Upstream-Builds enthalten jedoch auch `BeaconDNS`- und Gopher-Erweiterungen auf der Serverseite. Gehe also nicht davon aus, dass jede aktive Adaptix-Bereitstellung ausschließlich HTTP-/SMB-/TCP-Infrastruktur bereitstellt.<sup>[[2]](#references)</sup>

Typische Profilfelder, die in HTTP-Beacon-Konfigurationen beobachtet wurden (nach der Entschlüsselung):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (Array aus Strings), ports (Array aus u32)
- http_method, uri, parameter, user_agent, http_headers (längenpräfixierte Strings)
- ans_pre_size (u32), ans_size (u32) – werden zum Parsen von Antwortgrößen verwendet
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Aktuelle BeaconHTTP-Builds unterstützen außerdem eine vom Operator ausgewählte Rotation über mehrere URIs, User-Agents, Host-Header und Server, mit sequenzieller oder zufälliger Auswahl.<sup>[[2]](#references)</sup> Für die Bedrohungssuche bedeutet das, dass ein einzelner infizierter Host mehrere Callback-Pfade und Header-Kombinationen nutzen kann, ohne die klassische RC4-gepackte Beacon-Familie zu verlassen.

Beispiel für ein Standard-HTTP-Profil (aus einem Beacon-Build):<sup>[[1]](#references)</sup>

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

## Verschlüsselte Konfigurationsverpackung und Ladepfad

Wenn der Operator im Builder auf Create klickt, bettet AdaptixC2 das verschlüsselte Profil als Tail-Blob in den Beacon ein. Das Format ist:<sup>[[1]](#references)</sup>
- 4 Bytes: Konfigurationsgröße (uint32, little‑endian)
- N Bytes: RC4-verschlüsselte Konfigurationsdaten
- 16 Bytes: RC4-Schlüssel

Der Beacon-Loader kopiert den 16-Byte-Schlüssel vom Ende und entschlüsselt den N-Byte-Block mit RC4 direkt an Ort und Stelle:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktische Auswirkungen:<sup>[[1]](#references)</sup>
- Die gesamte Struktur befindet sich oft im PE-Abschnitt .rdata.
- Die Extraktion ist deterministisch: Größe lesen, Ciphertext dieser Größe lesen, anschließend den direkt dahinter abgelegten 16-Byte-Schlüssel lesen und dann mit RC4 entschlüsseln.

## Workflow zur Konfigurationsextraktion (Verteidiger)

Schreibe einen Extractor, der die Beacon-Logik nachahmt:<sup>[[1]](#references)</sup>
1) Finde den Blob im PE (häufig in .rdata). Ein pragmatischer Ansatz ist, .rdata nach einem plausiblen Layout aus [Größe|Ciphertext|16-Byte-Schlüssel] zu durchsuchen und RC4 auszuprobieren.
2) Lies die ersten 4 Bytes → Größe (uint32 LE).
3) Lies die nächsten N=size Bytes → Ciphertext.
4) Lies die letzten 16 Bytes → RC4-Schlüssel.
5) Entschlüssele den Ciphertext mit RC4. Parse anschließend das Klartextprofil wie folgt:
   - u32-/Boolean-Skalare wie oben angegeben
   - längenpräfixierte Strings (u32-Länge gefolgt von Bytes; abschließendes NUL-Byte kann vorhanden sein)
   - Arrays: servers_count gefolgt von ebenso vielen [String, u32-Port]-Paaren

Minimaler Python-Proof-of-Concept (eigenständig, keine externen Abhängigkeiten), der mit einem vorab extrahierten Blob funktioniert:

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
- Verwende bei der Automatisierung einen PE-Parser, um .rdata auszulesen, und wende dann ein Sliding Window an: Pro Offset o versuche size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = die nächsten 16 Bytes; entschlüssele mit RC4 und prüfe, ob sich String-Felder als UTF-8 dekodieren lassen und die Längen plausibel sind.
- Parse SMB/TCP-Profile nach denselben längenpräfixierten Konventionen.

## Custom listener profiles: nicht nur das klassische HTTP-Schema fest codieren

Das äußere Packformat (`u32 size | RC4 ciphertext | 16-byte key`) lässt sich wiederverwenden. Actor-angepasste Listener können also denselben Extraktionsworkflow beibehalten und gleichzeitig das Layout der entschlüsselten Felder vollständig ändern.

Ein gutes aktuelles Beispiel ist die Tropic-Trooper-Kampagne vom März 2026, bei der der extrahierte Adaptix beacon kein standardmäßiges HTTP/TCP-Profil enthielt. Stattdessen speicherte das entschlüsselte Blob GitHub-Transportparameter wie:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (zum Beispiel `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktische Parser-Strategie:
- Erkenne zuerst wie gewohnt das äußere RC4-Blob.
- Prüfe nach der Entschlüsselung Sentinel-Strings und die Plausibilität der Felder, statt sofort den HTTP-Parser zu erzwingen.
- Geeignete Sentinels sind `api.github.com`, `/issues?state=open`, HTTP-Verben/URIs, Strings im Named-Pipe-Stil oder offensichtlich gültige Server-/Port-Arrays.
- Wenn der HTTP-Parser fehlschlägt, der Klartext aber zusammenhängende längenpräfixierte UTF-8-Strings enthält, behalte das Sample und versuche alternative Schemas, statt es als False Positive zu verwerfen.

In dieser Kampagne verwendete der Custom Listener GitHub Issues als C2-Transport. Der beacon fragte außerdem `ipinfo.io` ab, um seine externe IP zu ermitteln, da die GitHub API dem Operator die Quelladresse des Opfers nicht direkt anzeigt.<sup>[[5]](#references)</sup>

## Network fingerprinting und Hunting

HTTP:<sup>[[1]](#references)</sup>
- Häufig: POST an vom Operator ausgewählte URIs (z. B. /uri.php, /endpoint/api)
- Benutzerdefinierter Header-Parameter für die beacon-ID (z. B. X‑Beacon‑Id, X‑App‑Id)
- User-Agents, die Firefox 20 oder aktuelle Chrome-Versionen imitieren
- Der Polling-Rhythmus ist über sleep_delay/jitter_delay erkennbar
- Neuere Builds können URIs, User-Agents, Host-Header und Server über mehrere Callbacks hinweg rotieren. Daher sollte man anhand ungewöhnlicher Header-Namen, Antwortgrößenmuster, TLS-Wiederverwendung und Timing clustern, statt von einem einzelnen Pfad-/UA-Paar auszugehen.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB Named-Pipe-Listener für Intranet-C2, wenn der Web-Egress eingeschränkt ist
- TCP-beacons können dem Traffic einige Bytes voranstellen, um den Protokollstart zu verschleiern

Aktuelle teamserver-Standardeinstellungen im Upstream
- `profile.yaml` wird derzeit mit teamserver `0.0.0.0:4321`, Endpoint `/endpoint`, den Zertifikat-/Schlüsseldateien `server.rsa.crt` und `server.rsa.key` sowie Extendern für HTTP, SMB, TCP, DNS, Beacon-Agent und Gopher ausgeliefert.<sup>[[2]](#references)</sup>
- Bei nicht zugeordneten Routen gibt der standardmäßige Fehler-Handler `Server: AdaptixC2` und `Adaptix-Version: v1.2` zurück.<sup>[[4]](#references)</sup>
- Der Standard-404-Body enthält `AdaptixC2 404` und `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internetweite Scans im Jahr 2026 fanden viele exponierte teamserver auf `4321` und zahlreiche beacon-Listener auf `43211`. Beide Ports sind daher nützliche Ausgangspunkte für die Suche, sollten aber nicht als umfassend betrachtet werden.<sup>[[4]](#references)</sup>

DNS/DoH-Listener-Fingerprints:<sup>[[4]](#references)</sup>
- Der aktuelle BeaconDNS-Extender antwortet autoritativ (`AA=true`).
- Anfragen, die nicht der Form des beacon-Protokolls entsprechen — insbesondere Namen mit weniger als 5 Labels vor der konfigurierten Domain — werden häufig mit `TXT "OK"` beantwortet.
- Wenn der konfigurierte Basis-TTL auf null gesetzt bleibt, verwendet der Listener einen Basiswert von 10 Sekunden und fügt bis zu 59 Sekunden Jitter hinzu.
- Dadurch sind aktive Probes mit kurzen Labels nützlich, wenn kein HTTP-Listener exponiert ist.

## Bei Vorfällen beobachtete Loader- und Persistence-TTPs

In-Memory-PowerShell-Loader:<sup>[[1]](#references)</sup>
- Laden Base64-/XOR-Payloads herunter (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Weisen nicht verwalteten Speicher zu, kopieren Shellcode hinein und ändern den Schutz über VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE).<sup>[[7]](#references)</sup>
- Führen ihn über dynamische .NET-Aufrufe aus: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanisierte signierte Software / gestufte Shellcode-Loader:<sup>[[5]](#references)</sup>
- Eine Tropic-Trooper-Kette von 2026 verwendete eine trojanisierte SumatraPDF-Executable (TOSHIS-Loader), die `_security_init_cookie` in bösartigen Code umleitete, statt den PE-Entry-Point zu patchen.
- Der Loader löste APIs über Adler-32-Hashing auf, lud ein Köder-PDF herunter, rief Shellcode der zweiten Stufe ab, entschlüsselte ihn mit AES-128-CBC über WinCrypt (`CryptDeriveKey` aus einem fest codierten Seed) und führte einen Adaptix beacon reflektiv im Speicher aus.
- Die Persistence wurde später auf Scheduled Tasks mit harmlos wirkenden Namen wie `\MSDNSvc` oder `\MicrosoftUDN` umgestellt, die so konfiguriert waren, dass sie den Agent etwa alle zwei Stunden erneut starteten.

Weitere Informationen zur In-Memory-Ausführung und zu AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Beobachtete Persistence-Mechanismen:<sup>[[1]](#references)</sup>
- Verknüpfung (.lnk) im Startup-Ordner, um einen Loader bei der Anmeldung erneut zu starten
- Registry-Run-Keys (HKCU/HKLM ...\CurrentVersion\Run), oft mit harmlos klingenden Namen wie "Updater", um loader.ps1 zu starten.<sup>[[10]](#references)</sup>
- DLL-Suchreihenfolge-Hijacking, indem msimg32.dll für anfällige Prozesse unter %APPDATA%\Microsoft\Windows\Templates abgelegt wird

Technik-Deep-Dives und Prüfungen:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting-Ideen
- PowerShell-Prozesse mit RW→RX-Übergängen: VirtualProtect auf PAGE_EXECUTE_READWRITE innerhalb von powershell.exe.<sup>[[8]](#references)</sup>
- Muster für dynamische Aufrufe (GetDelegateForFunctionPointer)
- Nicht zugeordnete HTTPS-404-Antworten mit `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` oder `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-Antworten mit `AA=true` und `TXT "OK"` auf kurze Anfragen unter verdächtigen Domains.<sup>[[4]](#references)</sup>
- GitHub-API-Traffic zu `/repos/<owner>/<repo>/issues`, gefolgt von Abfragen an `ipinfo.io` aus derselben Loader-/beacon-Kette.<sup>[[5]](#references)</sup>
- Startup-.lnk-Dateien in benutzerspezifischen oder gemeinsamen Startup-Ordnern.<sup>[[1]](#references)</sup>
- Verdächtige Run-Keys (z. B. "Updater") und Loader-Namen wie update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanisierte PE-Samples, die `_security_init_cookie` in Downloader-Code umleiten, bevor ein Köderdokument angezeigt wird.<sup>[[5]](#references)</sup>
- Von Benutzern beschreibbare DLL-Pfade unter %APPDATA%\Microsoft\Windows\Templates, die msimg32.dll enthalten.<sup>[[1]](#references)</sup>

## Hinweise zu OpSec-Feldern

- KillDate: Zeitstempel, nach dem sich der Agent selbst beendet.<sup>[[1]](#references)</sup>
- WorkingTime: Stunden, in denen der Agent aktiv sein soll, um sich in die Geschäftsaktivität einzufügen.<sup>[[1]](#references)</sup>

Diese Felder können zum Clustern und zur Erklärung beobachteter Ruhephasen verwendet werden.

## YARA und statische Anhaltspunkte

Unit 42 veröffentlichte grundlegende YARA-Regeln für beacons (C/C++ und Go) sowie für API-Hashing-Konstanten in Loadern.<sup>[[1]](#references)</sup> Ergänzend bieten sich Regeln an, die nach dem Layout [size|ciphertext|16-byte-key] nahe dem Ende von PE .rdata, den Standard-HTTP-Profil-Strings und neueren Server-/Listener-Markern wie `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` und `ipinfo.io` suchen.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Ein neues Open-Source-Framework, das bei realen Angriffen eingesetzt wird (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting eines Open-Source-C2-Frameworks im großen Maßstab (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper setzt auf AdaptixC2 und einen benutzerdefinierten Beacon-Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Speicherschutzkonstanten – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry-Run-Keys/Startup-Ordner](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
