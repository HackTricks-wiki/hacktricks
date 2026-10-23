# LDAP Signing & Channel Binding-Härtung

{{#include ../../banners/hacktricks-training.md}}

## Warum es wichtig ist

LDAP-Relay-/MITM-Angriffe leiten die Authentifizierung an einen Domain Controller weiter, um einen authentifizierten LDAP-Kontext zu erhalten. Der [Überblick zu Name-Resolution-Poisoning und Relay-Angriffen](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) beschreibt den umfassenderen Ablauf. Zwei verwandte Kontrollen schränken diese Möglichkeiten ein:

- **LDAP channel binding (CBT)** bindet die entsprechende Authentifizierung an das TLS-Serverzertifikat bzw. den TLS-Kanal von LDAPS und erschwert kanalübergreifende Relays.
- **LDAP signing** verlangt Integritätsschutz für SASL-LDAP-Binds. Es bietet keine Vertraulichkeit; verwendet TLS, wenn auch LDAP-Inhalte verschlüsselt werden müssen.<sup>[[2]](#references)</sup>

**Schnelle Prüfung der Sicherheitslage**: Tools wie `netexec ldap <dc> -u user -p pass` zeigen die erkannten Richtlinien für Signing und Channel Binding an. `(signing:None)` und `(channel binding:Never)` weisen auf fehlende Kontrollen hin. Ein erfolgreicher Relay hängt jedoch weiterhin vom erfassten Authentifizierungstyp, dem EPA-Verhalten, den Kontoberechtigungen, dem Zielprotokoll und den Relay-Schutzmaßnahmen ab. Verfügt der weitergeleitete Principal über die nötigen Rechte, kann ein Tool wie KrbRelayUp `msDS-AllowedToActOnBehalfOfOtherIdentity` schreiben, ressourcenbasierte eingeschränkte Delegierung (RBCD) konfigurieren und den daraus entstehenden Delegierungspfad verwenden, um sich als privilegierter Principal auszugeben.<sup>[[4]](#references)</sup>

**Server-2025-DCs** führen eine neue GPO (**LDAP server signing requirements Enforcement**) ein, deren Standardwert **Require Signing** ist, wenn sie auf **Not Configured** belassen wird. Um die Erzwingung zu vermeiden, muss diese Richtlinie ausdrücklich auf **Disabled** gesetzt werden.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (nur LDAPS)

- **Voraussetzungen**:
  - Der Patch CVE-2017-8563 (2017) ergänzt die Unterstützung für Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) ergänzt LDAPS-CBT-Telemetrie im „What-if“-Modus.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (Standard, kein CBT)
  - `When Supported` (teilweise Erzwingung: CBT-fähige Clients müssen ein gültiges Token bereitstellen; Clients ohne CBT-Unterstützung können weiterhin Binds durchführen, und Überwachungsereignisse werden ausgegeben)
  - `Always` (erzwingen: LDAPS-Binds ohne gültiges CBT werden abgewiesen)<sup>[[1]](#references)</sup>
- **Überwachung**: Lege **When Supported** fest, um Folgendes zu erfassen:
  - **3074** – Ein LDAPS-Bind wäre bei erzwungener CBT-Validierung fehlgeschlagen.
  - **3075** – Bei einem LDAPS-Bind fehlten CBT-Daten; bei erzwungener Richtlinie wäre er abgewiesen worden.
  - (Ereignis **3039** weist bei älteren Builds weiterhin auf CBT-Fehler hin.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Erzwingung**: Lege **Always** fest, sobald LDAPS-Clients CBTs senden; dies wirkt sich nur auf **LDAPS** aus (nicht auf rohes LDAP über Port 389).<sup>[[1]](#references)</sup>

`When Supported` dient nicht nur der Überwachung: Für CBT-fähige Clients wird CBT validiert, während Clients ohne CBT-Unterstützung weiterhin zugelassen werden. Die [Microsoft-Richtlinienreferenz](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) beschreibt die von der Version abhängigen Standardwerte. LDAP signing gilt für entsprechende Binds über LDAP/389; Channel Binding gilt für TLS-geschützte LDAP-Authentifizierung.

## LDAP Signing

- **Client-GPO**: `Network security: LDAP client signing requirements` = `Require signing` (statt des Standardwerts `Negotiate signing` bei modernen Windows-Versionen).<sup>[[1]](#references)</sup>
- **DC-GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (Standardwert ist `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: Belasse die Legacy-Richtlinie auf `None` und setze `LDAP server signing requirements Enforcement` auf `Enabled` (`Not Configured` erzwingt die Richtlinie standardmäßig; setze `Disabled`, um dies zu vermeiden).<sup>[[1]](#references)</sup>
- **Kompatibilität**: Erfasse Nicht-Windows-Geräte und Anwendungen, die Simple Binds oder nicht signierte SASL-Binds verwenden. Microsoft dokumentiert die Unterstützung für weiterhin gewartete Windows-Versionen; Aussagen zur Kompatibilität mit älteren Clients sollten anhand des tatsächlichen Client-Stacks geprüft werden und nicht auf eine XP-Versionsgrenze reduziert werden.<sup>[[2]](#references)</sup>

## Zuerst überwachen (empfohlene Dauer: ca. 30 Tage)

1. Aktiviere auf jedem DC die LDAP-Schnittstellendiagnose, um nicht signierte Binds zu protokollieren (Ereignis **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Setze die DC-GPO `LDAP server channel binding token requirements` auf **When Supported**, um CBT teilweise durchzusetzen und Telemetriedaten zu erfassen; prüfe vorher die Kompatibilität mit Legacy-Clients.<sup>[[1]](#references)</sup>
3. Überwache Directory-Service-Ereignisse:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – nicht signierte bzw. nicht signiert zugelassene Bindungen (Signierung nicht konform).
   - **3074/3075** – LDAPS-Bindungen, die fehlschlagen oder CBT auslassen würden (erfordert KB4520412 auf 2019/2022 und den obigen Schritt 2).
4. Setze die folgenden Einstellungen in getrennten Änderungen durch:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (Clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **oder** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec – LDAP-Kanalbindung und LDAP-Signierung](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 – Anforderungen an LDAP-Kanalbindung und -Signierung](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 – Update zur Abschwächung von LDAP-Relay-Angriffen](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP-Signierung deaktiviert → Kerberos-Relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
