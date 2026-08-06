# Durcissement de LDAP Signing et du Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c'est important

LDAP relay/MITM permet aux attaquants de transférer des binds vers les contrôleurs de domaine afin d'obtenir des contextes authentifiés. Deux contrôles côté serveur limitent ces chemins :

- **LDAP Channel Binding (CBT)** lie un bind LDAPS au tunnel TLS spécifique, empêchant les relays/replays entre différents canaux.
- **LDAP Signing** force l'intégrité des messages LDAP, empêchant leur falsification et la plupart des relays non signés.

**Vérification offensive rapide** : des outils comme `netexec ldap <dc> -u user -p pass` affichent la configuration de sécurité du serveur. Si vous voyez `(signing:None)` et `(channel binding:Never)`, les **relays Kerberos/NTLM vers LDAP** sont possibles (par exemple avec KrbRelayUp pour écrire `msDS-AllowedToActOnBehalfOfOtherIdentity` pour le RBCD et usurper l'identité d'administrateurs).<sup>[[4]](#references)</sup>

Les **DC Server 2025** introduisent une nouvelle GPO (**LDAP server signing requirements Enforcement**) qui utilise par défaut **Require Signing** lorsqu'elle reste sur **Not Configured**. Pour éviter l'application de cette configuration, vous devez définir explicitement cette stratégie sur **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS uniquement)

- **Prérequis** :
- Le patch CVE-2017-8563 (2017) ajoute la prise en charge d'Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **GPO (DCs)** : `Domain controller: LDAP server channel binding token requirements`
- `Never` (par défaut, sans CBT)
- `When Supported` (audit : génère des échecs, mais ne bloque pas)
- `Always` (application : rejette les binds LDAPS sans CBT valide)<sup>[[1]](#references)</sup>
- **Audit** : définissez **When Supported** pour faire apparaître :
- **3074** – le bind LDAPS aurait échoué à la validation CBT si l'application avait été activée.
- **3075** – le bind LDAPS n'incluait pas de données CBT et aurait été rejeté si l'application avait été activée.
- (L'événement **3039** signale toujours les échecs CBT sur les builds plus anciens.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Application** : définissez **Always** une fois que les clients LDAPS envoient des CBT ; cela ne s'applique qu'à **LDAPS** (pas au port 389 brut).<sup>[[1]](#references)</sup>


## LDAP Signing

- **GPO client** : `Network security: LDAP client signing requirements` = `Require signing` (contre `Negotiate signing`, la valeur par défaut sur les versions modernes de Windows).<sup>[[1]](#references)</sup>
- **GPO des DC** :
- Héritée : `Domain controller: LDAP server signing requirements` = `Require signing` (la valeur par défaut est `None`).<sup>[[2]](#references)</sup>
- **Server 2025** : laissez la stratégie héritée sur `None` et définissez `LDAP server signing requirements Enforcement` sur `Enabled` (`Not Configured` = application par défaut ; définissez `Disabled` pour l'éviter).<sup>[[1]](#references)</sup>
- **Compatibilité** : seul Windows **XP SP3+** prend en charge LDAP signing ; les systèmes plus anciens cesseront de fonctionner lorsque l'application sera activée.

## Déploiement axé d'abord sur l'audit (environ 30 jours recommandés)

1. Activez les diagnostics de l'interface LDAP sur chaque DC afin de journaliser les binds non signés (événement **2889**) :<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Définissez la GPO du DC `LDAP server channel binding token requirements` sur **When Supported** pour commencer la télémétrie CBT.<sup>[[1]](#references)</sup>
3. Surveillez les événements Directory Service :<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – binds unsigned/unsigned-allow (non-conformes aux exigences de signing).
- **3074/3075** – binds LDAPS qui échoueraient ou omettraient le CBT (nécessite KB4520412 sur 2019/2022 ainsi que l’étape 2 ci-dessus).
4. Appliquez les changements séparément :<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Références

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Exigences de LDAP channel binding et signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Mise à jour d’atténuation contre le LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing désactivé → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
