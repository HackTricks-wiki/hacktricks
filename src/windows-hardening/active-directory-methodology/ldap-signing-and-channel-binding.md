# LDAP Signing & Channel Binding Härtung

{{#include ../../banners/hacktricks-training.md}}

## Warum es wichtig ist

LDAP relay/MITM ermöglicht es Angreifern, binds an Domänencontroller weiterzuleiten, um authentifizierte Kontexte zu erhalten. Zwei serverseitige Kontrollen unterbinden diese Wege:

- **LDAP Channel Binding (CBT)** verknüpft einen LDAPS bind mit dem spezifischen TLS-Tunnel und verhindert relays/replays über unterschiedliche Kanäle.
- **LDAP Signing** erzwingt integritätgeschützte LDAP-Nachrichten, verhindert Manipulationen und die meisten nicht signierten Relays.

**Server 2025 DCs** führen eine neue GPO (**LDAP server signing requirements Enforcement**) ein, die standardmäßig auf **Require Signing** gesetzt ist, wenn sie auf **Not Configured** belassen wird. Um die Durchsetzung zu vermeiden, müssen Sie diese Richtlinie explizit auf **Disabled** setzen.

## LDAP Channel Binding (LDAPS only)

- **Anforderungen**:
- CVE-2017-8563 patch (2017) fügt Unterstützung für Extended Protection for Authentication hinzu.
- **KB4520412** (Server 2019/2022) fügt LDAPS CBT „what-if“ Telemetrie hinzu.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (Standard, kein CBT)
- `When Supported` (Audit: meldet Fehler, blockiert nicht)
- `Always` (Durchsetzung: lehnt LDAPS binds ohne gültiges CBT ab)
- **Audit**: setzen Sie **When Supported**, um sichtbar zu machen:
- **3074** – LDAPS bind wäre bei Durchsetzung an der CBT-Validierung gescheitert.
- **3075** – LDAPS bind ließ CBT-Daten aus und würde bei Durchsetzung abgelehnt werden.
- (Event **3039** signalisiert weiterhin CBT-Fehler auf älteren Builds.)
- **Durchsetzung**: setzen Sie **Always**, sobald LDAPS-Clients CBTs senden; nur wirksam für **LDAPS** (nicht für unverschlüsseltes 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` Standard auf modernen Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (Standard ist `None`).
- **Server 2025**: lassen Sie die Legacy-Richtlinie auf `None` und setzen Sie `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = standardmäßig durchgesetzt; setzen Sie `Disabled`, um das zu vermeiden).
- **Kompatibilität**: nur Windows **XP SP3+** unterstützt LDAP signing; ältere Systeme brechen, wenn die Durchsetzung aktiviert ist.

## Audit-first rollout (empfohlen ~30 Tage)

1. Aktivieren Sie LDAP-Interface-Diagnosen auf jedem DC, um nicht signierte binds zu protokollieren (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Setzen Sie die DC-GPO `LDAP server channel binding token requirements` = **When Supported**, um CBT-Telemetrie zu starten.
3. Directory Service-Ereignisse überwachen:
- **2889** – unsigned/unsigned-allow binds (Signierung nicht konform).
- **3074/3075** – LDAPS binds, die fehlschlagen würden oder CBT auslassen (erfordert KB4520412 auf 2019/2022 und Schritt 2 oben).
4. In separaten Schritten durchsetzen:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (Clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **oder** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referenzen

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
