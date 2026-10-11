# LDAP-Signing- und Channel-Binding-Hardening

{{#include ../../banners/hacktricks-training.md}}

## Warum das wichtig ist

LDAP-Relay-/MITM-Angriffe leiten die Authentifizierung an einen Domain Controller weiter, um einen authentifizierten LDAP-Kontext zu erhalten. Zwei verwandte Kontrollen schränken diese Angriffswege ein:

- **LDAP channel binding (CBT)** bindet die entsprechende Authentifizierung an das TLS-Serverzertifikat bzw. den TLS-Kanal von LDAPS und erschwert so Cross-Channel-Relays.
- **LDAP signing** verlangt Integritätsschutz für SASL-LDAP-Binds. Es bietet keine Vertraulichkeit; verwenden Sie TLS, wenn LDAP-Inhalte ebenfalls verschlüsselt werden müssen.<sup>[[2]](#references)</sup>

**Schnelle Überprüfung der Sicherheitslage**: Tools wie `netexec ldap <dc> -u user -p pass` zeigen die ermittelte Signing- und Channel-Binding-Richtlinie an. `(signing:None)` und `(channel binding:Never)` weisen auf fehlende Kontrollen hin. Ein erfolgreicher Relay hängt jedoch weiterhin vom erfassten Authentifizierungstyp, dem EPA-Verhalten, den Kontoberechtigungen, dem Zielprotokoll und den Relay-Schutzmaßnahmen ab. Wenn der relayed Principal über die erforderlichen Rechte verfügt, kann ein Tool wie KrbRelayUp `msDS-AllowedToActOnBehalfOfOtherIdentity` schreiben, resource-based constrained delegation (RBCD) konfigurieren und den daraus entstehenden Delegierungspfad nutzen, um sich als privilegierter Principal auszugeben.<sup>[[4]](#references)</sup>

**Server-2025-DCs** führen eine neue GPO (**LDAP server signing requirements Enforcement**) ein, die standardmäßig auf **Require Signing** gesetzt ist, wenn sie auf **Not Configured** belassen wird. Um die Erzwingung zu verhindern, müssen Sie diese Richtlinie explizit auf **Disabled** setzen.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (nur LDAPS)

- **Anforderungen**:
  - Der Patch für CVE-2017-8563 (2017) ergänzt die Unterstützung für Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) ergänzt LDAPS-CBT-Telemetrie im „What-if“-Modus.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (Standard, kein CBT)
  - `When Supported` (teilweise Erzwingung: CBT-fähige Clients müssen ein gültiges Token bereitstellen; Clients ohne CBT-Unterstützung können weiterhin Binds ausführen, und Audit-Ereignisse werden ausgegeben)
  - `Always` (erzwingen: LDAPS-Binds ohne gültiges CBT werden abgewiesen)<sup>[[1]](#references)</sup>
- **Audit**: Setzen Sie **When Supported**, um Folgendes sichtbar zu machen:
  - **3074** – Der LDAPS-Bind wäre bei erzwungener CBT-Validierung fehlgeschlagen.
  - **3075** – Beim LDAPS-Bind wurden keine CBT-Daten übermittelt; bei Erzwingung würde er abgewiesen.
  - (Ereignis **3039** weist bei älteren Builds weiterhin auf CBT-Fehler hin.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Erzwingung**: Setzen Sie **Always**, sobald LDAPS-Clients CBTs senden; wirksam ist dies nur für **LDAPS** (nicht für rohes LDAP auf Port 389).<sup>[[1]](#references)</sup>

`When Supported` dient nicht nur dem Audit: CBT wird für fähige Clients validiert, während Clients ohne CBT-Unterstützung weiterhin zugelassen werden. Die [Microsoft-Richtlinienreferenz](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) beschreibt die je nach Version unterschiedlichen Standardwerte. LDAP signing gilt für entsprechende Binds über LDAP/389; Channel Binding gilt für TLS-geschützte LDAP-Authentifizierung.

## LDAP Signing

- **Client-GPO**: `Network security: LDAP client signing requirements` = `Require signing` (anstelle von `Negotiate signing`, dem Standard bei modernen Windows-Versionen).<sup>[[1]](#references)</sup>
- **DC-GPO**:
  - Ältere Versionen: `Domain controller: LDAP server signing requirements` = `Require signing` (Standard ist `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: Lassen Sie die ältere Richtlinie auf `None` und setzen Sie `LDAP server signing requirements Enforcement` auf `Enabled` (`Not Configured` bedeutet standardmäßige Erzwingung; setzen Sie die Richtlinie auf `Disabled`, um diese zu verhindern).<sup>[[1]](#references)</sup>
- **Kompatibilität**: Erfassen Sie nicht Windows-basierte Geräte und Anwendungen, die einfache Binds oder nicht signierte SASL-Binds verwenden. Microsoft dokumentiert die Unterstützung für gewartete Windows-Versionen. Aussagen zur Kompatibilität älterer Clients sollten anhand des tatsächlichen Client-Stacks überprüft und nicht auf eine XP-Versionsgrenze reduziert werden.<sup>[[2]](#references)</sup>

## Audit zuerst: Rollout (empfohlen: etwa 30 Tage)

1. Aktivieren Sie die LDAP-Schnittstellendiagnose auf jedem DC, um nicht signierte Binds zu protokollieren (Ereignis **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Setze auf dem DC die GPO `LDAP server channel binding token requirements` auf **When Supported**, um CBT teilweise durchzusetzen und Telemetriedaten zu erfassen; prüfe zuerst die Kompatibilität mit älteren Clients.<sup>[[1]](#references)</sup>
3. Überwache Directory Service-Ereignisse:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – Bindungen ohne Signatur bzw. mit erlaubter fehlender Signatur (Signierung nicht konform).
   - **3074/3075** – LDAPS-Bindungen, die fehlschlagen würden oder CBT auslassen (erfordert KB4520412 auf 2019/2022 sowie den obigen Schritt 2).
4. Erzwinge die Einstellungen in separaten Änderungen:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (Clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **oder** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec – LDAP Channel Binding und LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 – Anforderungen an LDAP channel binding und signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 – Update zur Abwehr von LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing deaktiviert → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
