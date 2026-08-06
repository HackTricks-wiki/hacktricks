# Härtung von LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Warum das wichtig ist

LDAP relay/MITM ermöglicht es Angreifern, Binds an Domain Controllers weiterzuleiten, um authentifizierte Kontexte zu erhalten. Zwei serverseitige Kontrollen schränken diese Angriffswege ein:

- **LDAP Channel Binding (CBT)** bindet einen LDAPS-Bind an den spezifischen TLS-Tunnel und verhindert Relays/Replays über unterschiedliche Channels.
- **LDAP Signing** erzwingt integritätsgeschützte LDAP-Nachrichten und verhindert Manipulationen sowie die meisten unsigned Relays.

**Schneller offensiver Check**: Tools wie `netexec ldap <dc> -u user -p pass` geben die Server-Konfiguration aus. Wenn `(signing:None)` und `(channel binding:Never)` angezeigt werden, sind **Relays zu LDAP** mit Kerberos/NTLM möglich (z. B. mit KrbRelayUp, um `msDS-AllowedToActOnBehalfOfOtherIdentity` für RBCD zu schreiben und Administratoren zu impersonifizieren).<sup>[[4]](#references)</sup>

**Server-2025-DCs** führen eine neue GPO (**LDAP server signing requirements Enforcement**) ein, die standardmäßig **Require Signing** verwendet, wenn sie **Not Configured** ist. Um die Erzwingung zu vermeiden, muss diese Richtlinie explizit auf **Disabled** gesetzt werden.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (nur LDAPS)

- **Anforderungen**:
- Der CVE-2017-8563-Patch (2017) fügt Unterstützung für Extended Protection for Authentication hinzu.<sup>[[3]](#references)</sup>
- **KB4520412** (Server 2019/2022) fügt LDAPS-CBT-„What-if“-Telemetrie hinzu.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (Standard, kein CBT)
- `When Supported` (Audit: gibt Fehler aus, blockiert jedoch nicht)
- `Always` (erzwingen: weist LDAPS-Binds ohne gültiges CBT zurück)<sup>[[1]](#references)</sup>
- **Audit**: **When Supported** setzen, um Folgendes sichtbar zu machen:
- **3074** – Der LDAPS-Bind wäre bei aktivierter Erzwingung durch die CBT-Validierung fehlgeschlagen.
- **3075** – Der LDAPS-Bind enthielt keine CBT-Daten und würde bei aktivierter Erzwingung abgewiesen werden.
- (Event **3039** signalisiert CBT-Fehler weiterhin auf älteren Builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Erzwingung**: **Always** setzen, sobald LDAPS-Clients CBTs senden; dies ist nur für **LDAPS** wirksam (nicht für rohes 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client-GPO**: `Network security: LDAP client signing requirements` = `Require signing` (gegenüber dem Standardwert `Negotiate signing` auf modernen Windows-Systemen).<sup>[[1]](#references)</sup>
- **DC-GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (Standard ist `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: Die Legacy-Richtlinie auf `None` belassen und `LDAP server signing requirements Enforcement` = `Enabled` setzen (`Not Configured` bedeutet standardmäßig Erzwingung; `Disabled` setzen, um diese zu vermeiden).<sup>[[1]](#references)</sup>
- **Kompatibilität**: Nur Windows **XP SP3+** unterstützt LDAP Signing; ältere Systeme funktionieren nicht mehr, sobald die Erzwingung aktiviert wird.

## Audit-first-Rollout (empfohlen: ca. 30 Tage)

1. LDAP-Interface-Diagnose auf jedem DC aktivieren, um unsigned Binds zu protokollieren (Event **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Setze die DC-GPO `LDAP server channel binding token requirements` = **When Supported**, um CBT-Telemetrie zu starten.<sup>[[1]](#references)</sup>
3. Überwache Directory Service-Ereignisse:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (nicht signing-konform).
- **3074/3075** – LDAPS binds, die fehlschlagen oder CBT auslassen würden (erfordert KB4520412 unter 2019/2022 sowie den obigen Schritt 2).
4. Setze die Einstellungen in separaten Änderungen durch:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (Clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **oder** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referenzen

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing deaktiviert → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
