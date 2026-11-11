# AdaptixC2-Konfigurationsextraktion und TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ist ein modulares, Open-Source-Post-Exploitation/C2-Framework mit Windows-x86/x64-Beacons (EXE/DLL/Service-EXE/Raw-Shellcode) und BOF-Unterstützung.<sup>[[1]](#references)</sup> Diese Seite dokumentiert:
- Wie die mit RC4 gepackte Konfiguration eingebettet ist und wie sie aus Beacons extrahiert werden kann
- Netzwerk-/Profilindikatoren für HTTP/SMB/TCP-Listener
- Gängige Loader- und Persistence-TTPs, die in freier Wildbahn beobachtet wurden, mit Links zu relevanten Windows-Technikseiten

Aktuelle Upstream-Releases enthalten außerdem DNS-/DoH-Beacon-Listener und die separate Gopher-Agent-/Listener-Familie. Daher kann moderne Adaptix-Infrastruktur mehr als die ursprünglichen HTTP-/SMB-/TCP-Oberflächen bereitstellen, selbst wenn ein bestimmtes Sample weiterhin den klassischen Beacon-Agent verwendet.<sup>[[2]](#references)</sup>

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei primäre Beacon-Typen:<sup>[[1]](#references)</sup>
- BEACON_HTTP: Web-C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User-Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: Peer-to-Peer-C2 über Named Pipes (Intranet)
- BEACON_TCP: direkte Sockets, optional mit vorangestellter Markierung zur Verschleierung des Protokollstarts

Dies sind die in frühen Adaptix-Analysen öffentlich dokumentierten Beacon-Layouts und sie sind nach wie vor der häufigste Ausgangspunkt für die Extraktion auf Sample-Seite.<sup>[[1]](#references)</sup> Aktuelle Upstream-Builds enthalten jedoch auch `BeaconDNS`- und Gopher-Extender auf der Serverseite. Gehen Sie daher nicht davon aus, dass jede aktive Adaptix-Bereitstellung ausschließlich HTTP-/SMB-/TCP-Infrastruktur verwendet.<sup>[[2]](#references)</sup>

Die folgende Feldübersicht und die JSON-Beispiele beschreiben das 2025 analysierte HTTP-Format; sie sind keine Parser-Spezifikation für neuere Upstream-Builds. Typische Felder in diesen Beispielen (nach der Entschlüsselung):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – werden zum Parsen der Antwortgrößen verwendet
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Aktuelle BeaconHTTP-Builds unterstützen außerdem die vom Operator ausgewählte Rotation über mehrere URIs, User-Agents, Host-Header und Server hinweg, wobei die Auswahl sequenziell oder zufällig erfolgen kann.<sup>[[2]](#references)</sup> Für die Suche nach Bedrohungen bedeutet das, dass ein einzelner infizierter Host mehrere Callback-Pfade und Header-Kombinationen verwenden kann, ohne die klassische RC4-gepackte Beacon-Familie zu verlassen.

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

## Packing und Ladepfad der verschlüsselten Konfiguration

Wenn der Operator im Builder auf Create klickt, kompiliert AdaptixC2 das verschlüsselte Profil in den Beacon. Gehe nicht davon aus, dass es sich am Ende der PE oder des Shellcodes befindet: Suche die Profil-Bytes durch einen Section-Scan oder folge `getProfile()` im Sample. Das gepackte Format ist:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 Bytes: Konfigurationsgröße (uint32, little-endian)
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
- Die Extraktion ist deterministisch: Größe auslesen, den Ciphertext dieser Größe auslesen, anschließend den direkt dahinter platzierten 16‑Byte-Schlüssel auslesen und dann mit RC4 entschlüsseln.

## Workflow zur Konfigurationsextraktion (Verteidiger)

Eine allgemeine Triage von Samples vor dem Extrahieren des Beacons findest du unter [Malware Analysis](malware-analysis.md).

Schreibe einen Extractor, der die Logik des Beacons nachbildet:<sup>[[1]](#references)</sup>
1) Den Blob im PE suchen (häufig in .rdata). Ein pragmatischer Ansatz ist, .rdata nach einem plausiblen Layout [size|ciphertext|16-byte key] zu durchsuchen und RC4 auszuprobieren.
2) Die ersten 4 Bytes auslesen → Größe (uint32 LE).
3) Die nächsten N=size Bytes auslesen → Ciphertext.
4) Die letzten 16 Bytes auslesen → RC4-Schlüssel.
5) Den Ciphertext mit RC4 entschlüsseln. Anschließend das Klartextprofil wie folgt parsen:
   - u32-/Boolean-Skalare wie oben angegeben
   - längenpräfixierte Strings (u32-Länge gefolgt von Bytes; ein abschließendes NUL kann vorhanden sein)
   - Arrays: servers_count gefolgt von der entsprechenden Anzahl an [string, u32 port]-Paaren

Legacy-HTTP-Python-Proof-of-Concept (eigenständig, keine externen Abhängigkeiten) für einen vorab extrahierten Blob in der Feldreihenfolge von 2025. Für aktuelle Stock-Builds den Parser für das aktuelle Schema weiter unten verwenden:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Aktuelle stock HTTP- und DNS-Profile parsen

Current upstream packs zuerst sechs Little-Endian-`u32`-Werte: Agent-Watermark/-Typ, Kill-Date, Working Time, Sleep, Jitter und Listener-Watermark/-Typ. Die HTTP-spezifischen Daten beginnen dann mit einem ein Byte langen SSL-Flag. Anders als im Legacy-Beispiel enthalten sie Listen mit URI-, User-Agent- und Host-Header-Einträgen, jeweils mit einer Anzahl, gefolgt von Rotationsmodus und Proxy-Einstellungen. Daher beginnt der Legacy-Parser auf diesen Builds, das SSL-Flag aus dem Kill-Date-Feld zu lesen, und liefert falsche Ergebnisse. Stringlängen und Integer-Werte in diesem Profil sind Little-Endian-kodiert; gepackte Strings enthalten, wenn sie nicht leer sind, ein abschließendes NUL-Zeichen.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Verwende mit den obigen `P`- und `rc4`-Helfern diesen Parser für entschlüsselten **stock HTTP**-Klartext. Halte den RC4-Schlüssel aus öffentlichen Berichten heraus: Das HTTP-Profil kann einen Proxy-Benutzernamen und ein Passwort enthalten.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Ein aktuelles stock HTTP-Klartextprofil parsen</summary>

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

Bei einem standardmäßigen DNS-beacon werden dieselben sechs gängigen `u32`-Felder und anschließend die längenpräfixierten Strings `domain`, `resolvers`, `doh_resolvers` und `qtype` gelesen. `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` und `dns_mode` werden als `u32` gelesen, danach folgt der längenpräfixierte DoH-user-agent-String. `dns_mode` unterscheidet zwischen UDP, DoH und den beiden Fallback-Richtungen. Dies ist ein separates Layout: DNS-Plaintext darf nicht durch den HTTP-Parser geleitet werden.<sup>[[12]](#references)[[13]](#references)</sup>

Tipps:
- Verwenden Sie bei der Automatisierung einen PE-Parser, um .rdata auszulesen, und wenden Sie dann ein Sliding Window an: Versuchen Sie für jeden Offset o size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size] und candidate key = die nächsten 16 Bytes; entschlüsseln Sie mit RC4 und prüfen Sie, ob sich die String-Felder als UTF-8 decodieren lassen und die Längen plausibel sind.
- Parsen Sie SMB/TCP-Profile nach denselben längenpräfixierten Konventionen.

## Benutzerdefinierte Listener-Profile: nicht ausschließlich das klassische HTTP-Schema fest codieren

Das äußere Packformat (`u32 size | RC4 ciphertext | 16-byte key`) ist wiederverwendbar. Daher können von einem Angreifer angepasste Listener denselben Extraktionsablauf verwenden und zugleich das entschlüsselte Feldlayout vollständig ändern.

Ein gutes aktuelles Beispiel ist die Tropic-Trooper-Kampagne vom März 2026, bei der der extrahierte Adaptix-beacon kein standardmäßiges HTTP/TCP-Profil enthielt. Stattdessen speicherte der entschlüsselte Blob GitHub-Transportparameter wie:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (zum Beispiel `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktische Parser-Strategie:
- Erkennen Sie zuerst wie üblich genau den äußeren RC4-Blob.
- Verzweigen Sie nach der Entschlüsselung anhand von Sentinel-Strings und der Plausibilität der Felder, statt sofort den HTTP-Parser zu erzwingen.
- Gute Sentinels sind `api.github.com`, `/issues?state=open`, HTTP-Verben/URIs, Strings im Named-Pipe-Stil oder offensichtlich gültige Server-/Port-Arrays.
- Wenn der HTTP-Parser fehlschlägt, der Plaintext aber zusammenhängende längenpräfixierte UTF-8-Strings enthält, behalten Sie das Sample bei und versuchen Sie alternative Schemas, statt es als False Positive zu verwerfen.

In dieser Kampagne verwendete der benutzerdefinierte Listener GitHub issues als C2-Transport, und der beacon fragte `ipinfo.io` ab, um seine externe IP zu ermitteln, da die GitHub API dem Operator die Quelladresse des Opfers nicht direkt offenlegt.<sup>[[5]](#references)</sup>

## Netzwerk-Fingerprinting und Threat Hunting

HTTP:<sup>[[1]](#references)</sup>
- Üblich: POST-Anfragen an vom Operator ausgewählte URIs (z. B. /uri.php, /endpoint/api)
- Benutzerdefinierter Header-Parameter für die beacon-ID (z. B. X‑Beacon‑Id, X‑App‑Id)
- User-Agents, die Firefox 20 oder aktuelle Chrome-Versionen imitieren
- Der Abfragetakt ist anhand von sleep_delay/jitter_delay erkennbar
- Neuere Builds können URIs, User-Agents, Host-Header und Server zwischen Callbacks rotieren. Gruppieren Sie daher nach ungewöhnlichen Headernamen, Antwortgrößenmustern, TLS-Wiederverwendung und Zeitabständen, statt ein einzelnes Pfad-/UA-Paar vorauszusetzen.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB-Named-Pipe-Listener für intranet-C2, wenn der Web-Egress eingeschränkt ist
- TCP-beacons können dem Datenverkehr einige Bytes voranstellen, um den Protokollbeginn zu verschleiern

Aktuelle Standardwerte des Upstream-Teamservers
- `profile.yaml` wird derzeit mit teamserver `0.0.0.0:4321`, dem Endpunkt `/endpoint`, den Zertifikat-/Schlüsseldateien `server.rsa.crt` und `server.rsa.key` sowie Extendern für HTTP, SMB, TCP, DNS, Beacon-agent und Gopher ausgeliefert.<sup>[[2]](#references)</sup>
- Bei nicht übereinstimmenden Routen liefert der Standard-Fehlerhandler `Server: AdaptixC2` und `Adaptix-Version: v1.2` zurück.<sup>[[4]](#references)</sup>
- Der standardmäßige 404-Body enthält `AdaptixC2 404` und `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internetweite Scans im Jahr 2026 fanden zahlreiche exponierte Teamserver auf `4321` und viele beacon-Listener auf `43211`. Beide Ports eignen sich daher als Ausgangspunkte für weitere Untersuchungen, sind aber nicht vollständig.<sup>[[4]](#references)</sup>

DNS/DoH-Listener-Fingerprints:<sup>[[4]](#references)</sup>
- Der aktuelle BeaconDNS-Extender antwortet autoritativ (`AA=true`)
- Anfragen, die nicht dem beacon-Protokollformat entsprechen – insbesondere Namen mit weniger als 5 Labels vor der konfigurierten Domain –, werden üblicherweise mit `TXT "OK"` beantwortet
- Wenn die konfigurierte Basis-TTL auf null belassen wird, verwendet der Listener eine Basis von 10 Sekunden und fügt bis zu 59 Sekunden Jitter hinzu
- Dadurch eignen sich aktive Abfragen mit kurzen Labels, wenn kein HTTP-Listener exponiert ist

## In Vorfällen beobachtete Loader- und Persistence-TTPs

In-Memory-PowerShell-Loader:<sup>[[1]](#references)</sup>
- Laden Base64-/XOR-Payloads herunter (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allokieren unmanaged memory, kopieren Shellcode und ändern den Schutzstatus über VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE).<sup>[[7]](#references)</sup>
- Führen den Code über .NET dynamic invocation aus: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanisierte signierte Software / gestaffelte Shellcode-Loader:<sup>[[5]](#references)</sup>
- Eine Tropic-Trooper-Angriffskette von 2026 verwendete eine trojanisierte SumatraPDF-Executable (TOSHIS-Loader), die `_security_init_cookie` in bösartigen Code umleitete, statt den PE-Einstiegspunkt zu patchen.
- Der Loader löste APIs per Adler-32-Hashing auf, lud ein Decoy-PDF herunter, rief Shellcode der zweiten Stufe ab, entschlüsselte ihn mit AES-128-CBC über WinCrypt (`CryptDeriveKey` mit einem fest codierten Seed) und führte einen Adaptix-beacon reflektiv im Arbeitsspeicher aus.
- Die Persistence wurde später auf geplante Tasks mit harmlos wirkenden Namen wie `\MSDNSvc` oder `\MicrosoftUDN` verlagert, die so konfiguriert waren, dass sie den Agenten etwa alle zwei Stunden erneut starteten.

Auf diesen Seiten finden Sie Informationen zur In-Memory-Ausführung und zu AMSI/ETW-Aspekten:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Beobachtete Persistence-Mechanismen:<sup>[[1]](#references)</sup>
- Verknüpfung (.lnk) im Startup-Ordner, um bei der Anmeldung einen Loader erneut zu starten
- Registry-Run-Keys (HKCU/HKLM ...\CurrentVersion\Run), oft mit harmlos klingenden Namen wie "Updater", um loader.ps1 zu starten.<sup>[[10]](#references)</sup>
- DLL-Suchreihenfolge-Hijacking durch Ablegen von msimg32.dll unter %APPDATA%\Microsoft\Windows\Templates für anfällige Prozesse

Ausführliche Informationen zu Techniken und Prüfungen:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ansätze für Threat Hunting
- PowerShell-Prozesse mit RW→RX-Übergängen: VirtualProtect auf PAGE_EXECUTE_READWRITE innerhalb von powershell.exe.<sup>[[8]](#references)</sup>
- Muster für dynamic invocation (GetDelegateForFunctionPointer)
- Nicht zugeordnete HTTPS-404-Antworten mit `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` oder `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-Antworten mit `AA=true` und `TXT "OK"` auf kurze Anfragen unter verdächtigen Domains.<sup>[[4]](#references)</sup>
- GitHub-API-Datenverkehr zu `/repos/<owner>/<repo>/issues`, gefolgt von `ipinfo.io`-Abfragen aus derselben Loader-/beacon-Angriffskette.<sup>[[5]](#references)</sup>
- Startup-.lnk in benutzerbezogenen oder allgemeinen Startup-Ordnern.<sup>[[1]](#references)</sup>
- Verdächtige Run-Keys (z. B. "Updater") und Loader-Namen wie update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanisierte PE-Samples, die `_security_init_cookie` in Downloader-Code umleiten, bevor ein Decoy-Dokument angezeigt wird.<sup>[[5]](#references)</sup>
- Vom Benutzer beschreibbare DLL-Pfade unter %APPDATA%\Microsoft\Windows\Templates, die msimg32.dll enthalten.<sup>[[1]](#references)</sup>

## Hinweise zu OpSec-Feldern

- KillDate: Zeitstempel, nach dem sich der Agent selbst beendet.<sup>[[1]](#references)</sup>
- WorkingTime: Stunden, in denen der Agent aktiv sein soll, um sich in die geschäftliche Aktivität einzufügen.<sup>[[1]](#references)</sup>

Diese Felder können zur Gruppierung und zur Erklärung beobachteter Ruhephasen verwendet werden.

## YARA und statische Anhaltspunkte

Unit 42 veröffentlichte grundlegende YARA-Regeln für beacons (C/C++ und Go) sowie Konstanten für das API-Hashing von Loadern.<sup>[[1]](#references)</sup> Ergänzend bieten sich Regeln an, die nach dem Layout [size|ciphertext|16-byte-key] nahe dem Ende von PE .rdata, den standardmäßigen HTTP-Profil-Strings und neueren Server-/Listener-Markern wie `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` und `ipinfo.io` suchen.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Ein neues Open-Source-Framework, das in realen Angriffen eingesetzt wird (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 auf GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentation des Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting eines Open-Source-C2-Frameworks im großen Maßstab (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper setzt auf AdaptixC2 und einen benutzerdefinierten Beacon-Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft-Dokumentation](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Speicherschutzkonstanten – Microsoft-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry-Run-Keys/Startup-Ordner](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2-Profilgenerierung (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2-beacon-Profilparser (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2-DNS-Profilgenerierung (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2-Profil-Packing (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
