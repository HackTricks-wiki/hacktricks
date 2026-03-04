# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Warum es wichtig ist

LDAP relay/MITM erlaubt es Angreifern, binds an Domain Controllers weiterzuleiten, um authentifizierte Kontexte zu erhalten. Zwei serverseitige Kontrollen machen diese Wege weitgehend unwirksam:

- **LDAP Channel Binding (CBT)** ties an LDAPS bind to the specific TLS tunnel, wodurch Relays/Replays über unterschiedliche Kanäle verhindert werden.
- **LDAP Signing** erzwingt integritätsgeschützte LDAP-Nachrichten und verhindert Manipulationen sowie die meisten nicht signierten Relays.

**Schneller offensiver Check**: Tools wie `netexec ldap <dc> -u user -p pass` geben die Server-Posture aus. Wenn Sie `(signing:None)` und `(channel binding:Never)` sehen, sind Kerberos/NTLM **relays to LDAP** praktikabel (z. B. mit KrbRelayUp, um `msDS-AllowedToActOnBehalfOfOtherIdentity` für RBCD zu schreiben und Administratoren zu impersonieren).

Server 2025 DCs führen eine neue GPO (**LDAP server signing requirements Enforcement**) ein, die standardmäßig auf **Require Signing** gesetzt wird, wenn sie **Not Configured** bleibt. Um die Durchsetzung zu vermeiden, müssen Sie diese Richtlinie explizit auf **Disabled** setzen.

## LDAP Channel Binding (LDAPS only)

- **Anforderungen**:
- CVE-2017-8563 patch (2017) fügt Extended Protection for Authentication-Unterstützung hinzu.
- **KB4520412** (Server 2019/2022) fügt LDAPS CBT „what-if“ Telemetrie hinzu.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (Standard, kein CBT)
- `When Supported` (Audit: meldet Fehler, blockiert nicht)
- `Always` (Durchsetzung: lehnt LDAPS-Binds ohne gültigen CBT ab)
- **Audit**: Setzen Sie **When Supported**, um sichtbar zu machen:
- **3074** – LDAPS-Bind hätte die CBT-Validierung nicht bestanden, wenn durchgesetzt.
- **3075** – LDAPS-Bind ließ CBT-Daten weg und würde bei Durchsetzung abgelehnt werden.
- (Ereignis **3039** signalisiert CBT-Fehler weiterhin auf älteren Builds.)
- **Durchsetzung**: Setzen Sie **Always**, sobald LDAPS-Clients CBTs senden; wirkt nur auf **LDAPS** (nicht auf rohen Port 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` Standard auf modernen Windows-Versionen).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (Standard ist `None`).
- **Server 2025**: Lassen Sie die Legacy-Richtlinie auf `None` und setzen Sie `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = standardmäßig durchgesetzt; setzen Sie `Disabled`, um dies zu vermeiden).
- **Kompatibilität**: Nur Windows **XP SP3+** unterstützt LDAP Signing; ältere Systeme brechen, wenn die Durchsetzung aktiviert wird.

## Audit-first rollout (recommended ~30 days)

1. Aktivieren Sie LDAP-Interface-Diagnosen auf jedem DC, um nicht signierte Binds zu protokollieren (Ereignis **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Setze die DC-GPO `LDAP server channel binding token requirements` = **When Supported**, um CBT-Telemetrie zu starten.
3. Überwache Directory Service-Ereignisse:
- **2889** – unsigned/unsigned-allow binds (signing nicht konform).
- **3074/3075** – LDAPS binds, die CBT auslassen oder fehlschlagen würden (erfordert KB4520412 auf 2019/2022 und Schritt 2 oben).
4. In separaten Änderungen durchsetzen:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referenzen

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
