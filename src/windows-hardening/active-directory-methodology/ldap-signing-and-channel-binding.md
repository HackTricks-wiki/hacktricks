# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c'est important

LDAP relay/MITM permet aux attaquants de rediriger des binds vers les contrôleurs de domaine pour obtenir des contextes authentifiés. Deux contrôles côté serveur limitent ces vecteurs :

- **LDAP Channel Binding (CBT)** lie un LDAPS bind au tunnel TLS spécifique, empêchant les relays/replays entre différents canaux.
- **LDAP Signing** impose des messages LDAP protégés par intégrité, empêchant la manipulation et la plupart des relays non signés.

**Quick offensive check** : des outils comme `netexec ldap <dc> -u user -p pass` affichent la posture du serveur. Si vous voyez `(signing:None)` et `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** sont viables (par ex., en utilisant KrbRelayUp pour écrire `msDS-AllowedToActOnBehalfOfOtherIdentity` pour RBCD et usurper des administrateurs).

**Server 2025 DCs** introduisent une nouvelle GPO (**LDAP server signing requirements Enforcement**) qui par défaut devient **Require Signing** si laissée **Not Configured**. Pour éviter l'application de cette règle, vous devez définir explicitement cette stratégie sur **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Exigences** :
- Le patch CVE-2017-8563 (2017) ajoute le support d'Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) ajoute la télémétrie "what-if" LDAPS CBT.
- **GPO (DCs)** : `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit** : définir **When Supported** pour faire remonter :
- **3074** – LDAPS bind would have failed CBT validation if enforced.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
- (Event **3039** still signals CBT failures on older builds.)
- **Enforcement** : définir **Always** une fois que les clients LDAPS envoient des CBT ; n'est efficace que sur **LDAPS** (pas sur le port 389 non chiffré).

## LDAP Signing

- **Client GPO** : `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO** :
- Legacy : `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025** : laisser la stratégie legacy sur `None` et définir `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default ; mettre `Disabled` pour l'éviter).
- **Compatibilité** : seules les versions Windows **XP SP3+** prennent en charge LDAP signing ; les systèmes plus anciens tomberont en panne lorsque l'enforcement sera activé.

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Configurer le GPO des DC `LDAP server channel binding token requirements` = **When Supported** pour démarrer la télémétrie CBT.
3. Surveiller les événements Directory Service :
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds qui échoueraient ou omettraient CBT (nécessite KB4520412 sur 2019/2022 et l'étape 2 ci-dessus).
4. Appliquer dans des modifications séparées :
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Références

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
