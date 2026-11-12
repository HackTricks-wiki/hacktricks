# AdaptixC2-Konfigurationsextraktion und TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ist ein modulares Open-Source-Post-Exploitation-/C2-Framework mit Windows-x86/x64-Beacons (EXE/DLL/Service-EXE/Roh-Shellcode) und BOF-Unterstützung.<sup>[[1]](#references)</sup> Diese Seite beschreibt:
- Wie die mit RC4 gepackte Konfiguration eingebettet ist und wie sie aus Beacons extrahiert werden kann
- Netzwerk-/Profilindikatoren für HTTP-/SMB-/TCP-Listener
- Häufige Loader- und Persistenz-TTPs, die in freier Wildbahn beobachtet wurden, mit Links zu relevanten Seiten über Windows-Techniken

Aktuelle Upstream-Releases enthalten auch DNS-/DoH-Beacon-Listener und die separate Gopher-Agent-/Listener-Familie. Daher kann moderne Adaptix-Infrastruktur mehr als nur die ursprünglichen HTTP-/SMB-/TCP-Schnittstellen aufweisen, selbst wenn ein bestimmtes Sample weiterhin den klassischen Beacon-Agent verwendet.<sup>[[2]](#references)</sup>

## Beacon-Profile und Felder

AdaptixC2 unterstützt drei primäre Beacon-Typen:<sup>[[1]](#references)</sup>
- BEACON_HTTP: Web-C2 mit konfigurierbaren Servern/Ports/SSL, Methode, URI, Headern, User-Agent und einem benutzerdefinierten Parameternamen
- BEACON_SMB: Peer-to-Peer-C2 über Named Pipes (Intranet)
- BEACON_TCP: direkte Sockets, optional mit vorangestellter Markierung zur Verschleierung des Protokollstarts

Dies sind die Beacon-Layouts, die in frühen Adaptix-Analysen öffentlich dokumentiert wurden, und sie sind nach wie vor der häufigste Ausgangspunkt für die Extraktion auf Sample-Seite.<sup>[[1]](#references)</sup> Aktuelle Upstream-Builds enthalten jedoch auch `BeaconDNS`- und Gopher-Erweiterungen auf der Serverseite. Gehe daher nicht davon aus, dass jede aktive Adaptix-Implementierung ausschließlich HTTP-/SMB-/TCP-Infrastruktur verwendet.<sup>[[2]](#references)</sup>

Die folgende Feldübersicht und die JSON-Beispiele beschreiben das 2025 analysierte HTTP-Format; sie sind keine Parser-Spezifikation für neuere Upstream-Builds. Typische Felder in diesen Beispielen (nach der Entschlüsselung):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – werden zum Parsen der Antwortgrößen verwendet
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Aktuelle BeaconHTTP-Builds unterstützen außerdem die vom Operator ausgewählte Rotation über mehrere URIs, User-Agents, Host-Header und Server hinweg, mit sequenzieller oder zufälliger Auswahl.<sup>[[2]](#references)</sup> Für die Threat-Jagd bedeutet dies, dass ein einzelner kompromittierter Host über mehrere Callback-Pfade und Header-Kombinationen kommunizieren kann, ohne die klassische RC4-gepackte Beacon-Familie zu verlassen.

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

## Verschlüsselte Konfigurationsverpackung und Ladepfad

Wenn der Operator im Builder auf Create klickt, kompiliert AdaptixC2 das verschlüsselte Profil in den Beacon. Gehen Sie nicht davon aus, dass es sich am Ende der PE-Datei oder des Shellcodes befindet: Lokalisieren Sie die Profilbytes durch einen Abschnittsscan oder indem Sie im Beispiel `getProfile()` verfolgen. Das gepackte Format ist:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 Bytes: Konfigurationsgröße (uint32, Little-Endian)
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
- Die gesamte Struktur befindet sich häufig im PE-Abschnitt .rdata.
- Die Extraktion ist deterministisch: Größe lesen, Ciphertext dieser Größe lesen, danach den unmittelbar folgenden 16‑Byte-Schlüssel lesen und anschließend mit RC4 entschlüsseln.

## Workflow zur Konfigurationsextraktion (Verteidiger)

Allgemeine Sample-Triage vor dem Carving des Beacons findest du unter [Malware Analysis](malware-analysis.md).

Schreibe einen Extractor, der die Logik des Beacons nachbildet:<sup>[[1]](#references)</sup>
1) Finde den Blob im PE (üblicherweise in .rdata). Ein pragmatischer Ansatz ist, .rdata nach einem plausiblen Layout aus [Größe|Ciphertext|16‑Byte-Schlüssel] zu durchsuchen und RC4 darauf anzuwenden.
2) Lies die ersten 4 Bytes → Größe (uint32 LE).
3) Lies die nächsten N=size Bytes → Ciphertext.
4) Lies die letzten 16 Bytes → RC4-Schlüssel.
5) Entschlüssle den Ciphertext mit RC4. Parse anschließend das Klartextprofil wie folgt:
   - u32-/Boolean-Skalare wie oben angegeben
   - Strings mit vorangestellter Länge (u32-Länge gefolgt von Bytes; ein abschließendes NUL kann vorhanden sein)
   - Arrays: servers_count, gefolgt von ebenso vielen [String, u32-Port]-Paaren

Legacy-HTTP-Python-Proof-of-Concept (eigenständig, keine externen Abhängigkeiten) für einen vorab extrahierten Blob in der Feldreihenfolge von 2025. Verwende für aktuelle Stock-Builds den Parser für das aktuelle Schema weiter unten:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Aktuelle Stock-HTTP- und DNS-Profile parsen

Der aktuelle Upstream packt zuerst sechs Little-Endian-`u32`-Werte: Agent-Watermark/-Typ, Kill Date, Working Time, Sleep, Jitter und Listener-Watermark/-Typ. Die HTTP-spezifischen Daten beginnen dann mit einem ein Byte großen SSL-Flag. Anders als im Legacy-Beispiel folgen darauf Listen mit URI-, User-Agent- und Host-Header-Einträgen, jeweils mit Anzahl, gefolgt vom Rotationsmodus und den Proxy-Einstellungen. Daher liest der Legacy-Parser bei diesen Builds das SSL-Flag ab dem Kill-Date-Feld und liefert falsche Ergebnisse. Stringlängen und Integerwerte in diesem Profil sind Little-Endian-codiert; gepackte Strings enthalten, sofern nicht leer, ein abschließendes NUL.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Verwende mit den obigen `P`- und `rc4`-Hilfsfunktionen diesen Parser für entschlüsselten **Stock-HTTP**-Klartext. Nimm den RC4-Schlüssel nicht in öffentliche Berichte auf: Das HTTP-Profil kann einen Proxy-Benutzernamen und ein Passwort enthalten.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Ein aktuelles Stock-HTTP-Klartextprofil parsen</summary>

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

Bei einem standardmäßigen DNS beacon lesen Sie dieselben sechs gemeinsamen `u32`-Felder und anschließend die längenpräfixierten Zeichenfolgen `domain`, `resolvers`, `doh_resolvers` und `qtype`. Lesen Sie `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` und `dns_mode` als `u32`, dann die längenpräfixierte DoH-User-Agent-Zeichenfolge. `dns_mode` unterscheidet UDP, DoH und die beiden Fallback-Richtungen. Dies ist ein separates Layout: Leiten Sie DNS-Plaintext nicht durch den HTTP-Parser.<sup>[[12]](#references)[[13]](#references)</sup>

Tipps:
- Verwenden Sie bei der Automatisierung einen PE-Parser, um `.rdata` auszulesen, und wenden Sie dann ein Sliding Window an: Probieren Sie für jeden Offset o `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]` und den nächsten 16 Bytes als möglichen Schlüssel aus; entschlüsseln Sie mit RC4 und prüfen Sie, ob sich Zeichenfolgenfelder als UTF-8 dekodieren lassen und die Längen plausibel sind.
- Analysieren Sie SMB/TCP-Profile anhand derselben längenpräfixierten Konventionen.

## Benutzerdefinierte Listener-Profile: Nicht ausschließlich das klassische HTTP-Schema fest codieren

Das äußere Packformat (`u32 size | RC4 ciphertext | 16-byte key`) lässt sich wiederverwenden. Daher können von Angreifern angepasste Listener denselben Extraktionsablauf nutzen und zugleich das entschlüsselte Feldlayout vollständig ändern.

Ein gutes aktuelles Beispiel ist die Tropic-Trooper-Kampagne vom März 2026, bei der der extrahierte Adaptix beacon kein standardmäßiges HTTP/TCP-Profil enthielt. Stattdessen speicherte der entschlüsselte Blob GitHub-Transportparameter wie:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (zum Beispiel `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktische Strategie für den Parser:
- Erkennen Sie zunächst wie gewohnt den äußeren RC4-Blob.
- Verzweigen Sie nach der Entschlüsselung anhand von Sentinel-Zeichenfolgen und plausiblen Feldwerten, anstatt sofort den HTTP-Parser zu erzwingen.
- Gute Sentinels sind `api.github.com`, `/issues?state=open`, HTTP-Verben/URIs, Zeichenfolgen im Named-Pipe-Stil oder offensichtlich gültige Server-/Port-Arrays.
- Wenn der HTTP-Parser fehlschlägt, der Klartext aber zusammenhängende längenpräfixierte UTF-8-Zeichenfolgen enthält, behalten Sie das Sample bei und versuchen Sie alternative Schemata, anstatt es als False Positive zu verwerfen.

In dieser Kampagne nutzte der benutzerdefinierte Listener GitHub Issues als C2-Transport. Der beacon fragte `ipinfo.io` ab, um seine externe IP-Adresse zu ermitteln, da die GitHub API dem Operator die Quelladresse des Opfers nicht direkt offenlegt.<sup>[[5]](#references)</sup> Ein separates Handshake-Verfahren über Issues und Repository-Dateien wird unter [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md) beschrieben.

## Netzwerk-Fingerprinting und Hunting

HTTP:<sup>[[1]](#references)</sup>
- Häufig: POST an vom Operator gewählte URIs (z. B. /uri.php, /endpoint/api)
- Benutzerdefinierter Header-Parameter für die beacon-ID (z. B. X‑Beacon‑Id, X‑App‑Id)
- User-Agents, die Firefox 20 oder aktuelle Chrome-Versionen imitieren
- Abfrageintervall anhand von sleep_delay/jitter_delay erkennbar
- Neuere Builds können URIs, User-Agents, Host-Header und Server zwischen Callbacks rotieren lassen. Gruppieren Sie daher anhand ungewöhnlicher Headernamen, Antwortgrößenmuster, TLS-Wiederverwendung und Timing, anstatt von einem einzelnen Pfad-/UA-Paar auszugehen.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB-Listener mit Named Pipes für internes C2, wenn ausgehender Webverkehr eingeschränkt ist
- TCP-beacons können dem Datenverkehr einige Bytes voranstellen, um den Protokollbeginn zu verschleiern

Aktuelle Standardwerte des Upstream-Teamservers
- `profile.yaml` wird derzeit mit dem Teamserver unter `0.0.0.0:4321`, dem Endpunkt `/endpoint`, den Zertifikat-/Schlüsseldateien `server.rsa.crt` und `server.rsa.key` sowie Extendern für HTTP, SMB, TCP, DNS, den Beacon-Agent und Gopher ausgeliefert.<sup>[[2]](#references)</sup>
- Bei nicht passenden Routen gibt der standardmäßige Fehler-Handler `Server: AdaptixC2` und `Adaptix-Version: v1.2` zurück.<sup>[[4]](#references)</sup>
- Der standardmäßige 404-Body enthält `AdaptixC2 404` und `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internetweite Scans fanden 2026 viele offengelegte Teamserver auf `4321` und zahlreiche beacon-Listener auf `43211`. Beide Ports eignen sich daher als Ausgangspunkte für weitere Untersuchungen, sind aber nicht als vollständige Liste zu betrachten.<sup>[[4]](#references)</sup>

Fingerprints von DNS/DoH-Listenern:<sup>[[4]](#references)</sup>
- Der aktuelle BeaconDNS-Extender antwortet autoritativ (`AA=true`)
- Abfragen, die nicht dem beacon-Protokollformat entsprechen – insbesondere Namen mit weniger als 5 Labels vor der konfigurierten Domain – werden häufig mit `TXT "OK"` beantwortet
- Wenn die konfigurierte Basis-TTL auf null belassen wird, verwendet der Listener eine Basis von 10 Sekunden und fügt bis zu 59 Sekunden Jitter hinzu
- Dadurch eignen sich aktive Abfragen mit kurzen Labels, wenn kein HTTP-Listener offengelegt ist

## Loader- und Persistence-TTPs aus Vorfällen

In-Memory-PowerShell-Loader:<sup>[[1]](#references)</sup>
- Laden Base64/XOR-Payloads herunter (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allokieren nicht verwalteten Speicher, kopieren Shellcode hinein und ändern den Schutz über VirtualProtect auf 0x40 (PAGE_EXECUTE_READWRITE).<sup>[[7]](#references)</sup>
- Führen den Code über dynamischen .NET-Aufruf aus: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanisierte signierte Software / gestaffelte Shellcode-Loader:<sup>[[5]](#references)</sup>
- Eine Tropic-Trooper-Kette aus dem Jahr 2026 verwendete eine trojanisierte SumatraPDF-Executable (TOSHIS loader), die `_security_init_cookie` in schädlichen Code umleitete, statt den PE-Einstiegspunkt zu patchen
- Der Loader löste APIs mithilfe von Adler-32-Hashing auf, lud ein Täuschungs-PDF herunter, rief Shellcode der zweiten Stufe ab, entschlüsselte ihn mit AES-128-CBC über WinCrypt (`CryptDeriveKey` aus einem fest codierten Seed) und führte einen Adaptix beacon per Reflective Loading im Speicher aus
- Später erfolgte die Persistence über Scheduled Tasks mit harmlos wirkenden Namen wie `\MSDNSvc` oder `\MicrosoftUDN`, die so konfiguriert waren, dass sie den Agenten etwa alle zwei Stunden erneut starteten

Weitere Informationen zur In-Memory-Ausführung und zu AMSI/ETW-Aspekten finden Sie auf diesen Seiten:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Beobachtete Persistence-Mechanismen:<sup>[[1]](#references)</sup>
- Verknüpfung (.lnk) im Autostartordner, um beim Anmelden einen Loader erneut zu starten
- Registry-Run-Keys (HKCU/HKLM ...\CurrentVersion\Run), häufig mit harmlos klingenden Namen wie "Updater", um loader.ps1 zu starten.<sup>[[10]](#references)</sup>
- DLL-Suchreihenfolge-Hijacking durch Ablegen von msimg32.dll unter %APPDATA%\Microsoft\Windows\Templates für anfällige Prozesse

Ausführliche Analysen und Prüfungen zu Techniken:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting-Ideen
- PowerShell-Prozesse mit RW→RX-Übergängen: VirtualProtect auf PAGE_EXECUTE_READWRITE innerhalb von powershell.exe.<sup>[[8]](#references)</sup>
- Muster für dynamische Aufrufe (GetDelegateForFunctionPointer)
- Nicht passende HTTPS-404-Antworten mit `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` oder `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-Antworten mit `AA=true` und `TXT "OK"` auf kurze Abfragen unter verdächtigen Domains.<sup>[[4]](#references)</sup>
- GitHub-API-Verkehr zu `/repos/<owner>/<repo>/issues`, gefolgt von `ipinfo.io`-Abfragen aus derselben Loader-/beacon-Kette.<sup>[[5]](#references)</sup>
- Startup-.lnk-Dateien in benutzerbezogenen oder allgemeinen Autostartordnern.<sup>[[1]](#references)</sup>
- Verdächtige Run-Keys (z. B. "Updater") und Loader-Namen wie update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanisierte PE-Samples, die `_security_init_cookie` in Downloader-Code umleiten, bevor ein Täuschungsdokument angezeigt wird.<sup>[[5]](#references)</sup>
- Benutzerschreibbare DLL-Pfade unter %APPDATA%\Microsoft\Windows\Templates, die msimg32.dll enthalten.<sup>[[1]](#references)</sup>

## Hinweise zu OpSec-Feldern

- KillDate: Zeitstempel, nach dem sich der Agent selbst beendet.<sup>[[1]](#references)</sup>
- WorkingTime: Stunden, in denen der Agent aktiv sein soll, um sich in den Geschäftsalltag einzufügen.<sup>[[1]](#references)</sup>

Diese Felder können zur Gruppierung und zur Erklärung beobachteter Ruhephasen verwendet werden.

## YARA und statische Anhaltspunkte

Unit 42 veröffentlichte grundlegende YARA-Regeln für beacons (C/C++ und Go) sowie Konstanten für das API-Hashing von Loadern.<sup>[[1]](#references)</sup> Ergänzen Sie diese durch Regeln, die nach dem Layout [size|ciphertext|16-byte-key] nahe dem Ende von PE .rdata, den standardmäßigen HTTP-Profilzeichenfolgen und neueren Server-/Listener-Markern wie `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` und `ipinfo.io` suchen.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Ein neues Open-Source-Framework, das bei realen Angriffen eingesetzt wird (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 auf GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentation des Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting eines Open-Source-C2-Frameworks in großem Maßstab (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper setzt verstärkt auf AdaptixC2 und einen benutzerdefinierten Beacon-Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Speicherschutzkonstanten – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry-Run-Keys/Autostartordner](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2-Profilgenerierung (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2-beacon-Profilparser (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2-DNS-Profilgenerierung (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2-Profil-Packformat (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
