# Renforcement LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c'est important

Le relais LDAP/MITM permet aux attaquants de retransmettre des binds vers des contrôleurs de domaine pour obtenir des contextes authentifiés. Deux contrôles côté serveur limitent ces vecteurs :

- **LDAP Channel Binding (CBT)** lie un bind LDAPS au tunnel TLS spécifique, empêchant les relays/replays à travers différents canaux.
- **LDAP Signing** oblige des messages LDAP protégés par intégrité, empêchant la modification et la plupart des relays non signés.

**Vérification offensive rapide** : des outils comme `netexec ldap <dc> -u user -p pass` affichent la posture du serveur. Si vous voyez `(signing:None)` et `(channel binding:Never)`, les relays Kerberos/NTLM **vers LDAP** sont possibles (par ex. en utilisant KrbRelayUp pour écrire `msDS-AllowedToActOnBehalfOfOtherIdentity` pour RBCD et usurper des administrateurs).

**Server 2025 DCs** introduisent une nouvelle GPO (**LDAP server signing requirements Enforcement**) qui par défaut met **Require Signing** quand elle est **Not Configured**. Pour éviter l'application vous devez explicitement régler cette stratégie sur **Disabled**.

## LDAP Channel Binding (LDAPS uniquement)

- **Requirements** :
- Le patch CVE-2017-8563 (2017) ajoute le support de Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) ajoute la télémétrie “what-if” pour LDAPS CBT.
- **GPO (DCs)** : `Domain controller: LDAP server channel binding token requirements`
- `Never` (par défaut, pas de CBT)
- `When Supported` (audit : émet des échecs, ne bloque pas)
- `Always` (enforce : rejette les binds LDAPS sans CBT valide)
- **Audit** : mettre **When Supported** pour afficher :
- **3074** – Le bind LDAPS aurait échoué la validation CBT si appliqué.
- **3075** – Le bind LDAPS a omis les données CBT et serait rejeté si appliqué.
- (L'événement **3039** signale encore les échecs CBT sur les anciennes builds.)
- **Enforcement** : définir **Always** une fois que les clients LDAPS envoient des CBT ; n'est effectif que sur **LDAPS** (pas sur le port 389 non chiffré).

## LDAP Signing

- **Client GPO** : `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` par défaut sur les Windows modernes).
- **DC GPO** :
- Legacy : `Domain controller: LDAP server signing requirements` = `Require signing` (par défaut `None`).
- **Server 2025** : laissez la politique legacy à `None` et définissez `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = appliqué par défaut ; mettez `Disabled` pour l'éviter).
- **Compatibilité** : seuls Windows **XP SP3+** prennent en charge LDAP signing ; les systèmes plus anciens seront affectés lorsque l'enforcement est activé.

## Déploiement en audit d'abord (recommandé ~30 jours)

1. Activez les diagnostics de l'interface LDAP sur chaque DC pour consigner les binds non signés (Événement **2889**) :
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Définir la GPO DC `LDAP server channel binding token requirements` = **When Supported** pour démarrer la télémétrie CBT.
3. Surveiller les événements Directory Service :
- **2889** – unsigned/unsigned-allow binds (signature non conforme).
- **3074/3075** – LDAPS binds qui échoueraient ou omettraient CBT (requiert KB4520412 sur 2019/2022 et l'étape 2 ci‑dessus).
4. Appliquer via des modifications distinctes :
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Références

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
