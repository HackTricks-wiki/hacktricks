# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c'est important

LDAP relay/MITM permet aux attaquants de relayer des binds vers les Domain Controllers pour obtenir des contextes authentifiés. Deux contrôles côté serveur atténuent ces vecteurs :

- **LDAP Channel Binding (CBT)** ties an LDAPS bind to the specific TLS tunnel, breaking relays/replays across different channels.
- **LDAP Signing** forces integrity-protected LDAP messages, preventing tampering and most unsigned relays.

**Server 2025 DCs** introduce a new GPO (**LDAP server signing requirements Enforcement**) that defaults to **Require Signing** when left **Not Configured**. To avoid enforcement you must explicitly set that policy to **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Exigences** :
- CVE-2017-8563 patch (2017) adds Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) adds LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (par défaut, pas de CBT)
- `When Supported` (audit : enregistre des échecs, n'empêche pas)
- `Always` (enforce : rejette les LDAPS binds sans CBT valide)
- **Audit** : définir **When Supported** pour faire ressortir :
- **3074** – LDAPS bind would have failed CBT validation if enforced.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
- (Event **3039** still signals CBT failures on older builds.)
- **Enforcement** : définir **Always** une fois que les clients LDAPS envoient des CBTs ; n'est efficace que sur **LDAPS** (pas le port 389 brut).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO** :
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (la valeur par défaut est `None`).
- **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).
- **Compatibilité** : seuls Windows **XP SP3+** supportent LDAP signing ; les systèmes plus anciens ne fonctionneront plus correctement lorsque l'enforcement est activé.

## Déploiement axé audit (recommandé ~30 jours)

1. Activez le diagnostic de l'interface LDAP sur chaque DC pour consigner les binds non signés (Event **2889**) :
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Définir le GPO DC `LDAP server channel binding token requirements` = **When Supported** pour démarrer la télémétrie CBT.
3. Surveiller les événements Directory Service :
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Appliquer dans des modifications séparées :
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Références

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
