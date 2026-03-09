# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Warum es wichtig ist

LDAP relay/MITM erlaubt Angreifern, binds an Domain Controllers weiterzuleiten, um authentifizierte Kontexte zu erhalten. Zwei serverseitige Kontrollen schränken diese Angriffswege ein:

- **LDAP Channel Binding (CBT)** verknüpft einen LDAPS bind mit dem spezifischen TLS-Tunnel und verhindert so Relays/Replays über unterschiedliche Channels.
- **LDAP Signing** erzwingt integritätsgeschützte LDAP-Nachrichten, verhindert Manipulationen und die meisten unsigned relays.

**Quick offensive check**: Tools wie `netexec ldap <dc> -u user -p pass` zeigen die Server-Postur. Wenn Sie `(signing:None)` und `(channel binding:Never)` sehen, sind Kerberos/NTLM **relays to LDAP** möglich (z. B. mit KrbRelayUp um `msDS-AllowedToActOnBehalfOfOtherIdentity` für RBCD zu schreiben und Administratoren zu impersonifizieren).

**Server 2025 DCs** führen eine neue GPO ein (**LDAP server signing requirements Enforcement**), die standardmäßig auf **Require Signing** gesetzt wird, wenn sie auf **Not Configured** verbleibt. Um die Durchsetzung zu vermeiden, müssen Sie diese Richtlinie explizit auf **Disabled** setzen.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) fügt Extended Protection for Authentication-Unterstützung hinzu.
- **KB4520412** (Server 2019/2022) fügt LDAPS CBT „what-if“ Telemetrie hinzu.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (Standard, kein CBT)
- `When Supported` (Audit: protokolliert Fehler, blockiert nicht)
- `Always` (Enforcement: lehnt LDAPS binds ohne gültigen CBT ab)
- **Audit**: Setzen Sie **When Supported**, um sichtbar zu machen:
- **3074** – LDAPS bind hätte die CBT-Validierung fehlgeschlagen, wenn Enforcement aktiv gewesen wäre.
- **3075** – LDAPS bind ließ CBT-Daten weg und wäre bei Enforcement abgelehnt worden.
- (Event **3039** signalisiert CBT-Fehler weiterhin auf älteren Builds.)
- **Enforcement**: Setzen Sie **Always**, sobald LDAPS-Clients CBTs senden; wirksam nur für **LDAPS** (nicht für rohen Port 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` Standard auf modernen Windows-Versionen).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (Standard ist `None`).
- **Server 2025**: Lassen Sie die Legacy-Richtlinie auf `None` und setzen Sie `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = standardmäßig durchgesetzt; setzen Sie `Disabled`, um dies zu vermeiden).
- **Compatibility**: Nur Windows **XP SP3+** unterstützt LDAP signing; ältere Systeme brechen, wenn Enforcement aktiviert wird.

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Setzen Sie in der DC-GPO `LDAP server channel binding token requirements` = **When Supported**, um CBT-Telemetrie zu starten.
3. Überwachen Sie Directory Service-Ereignisse:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Erzwingen Sie dies durch separate Änderungen:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referenzen

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
