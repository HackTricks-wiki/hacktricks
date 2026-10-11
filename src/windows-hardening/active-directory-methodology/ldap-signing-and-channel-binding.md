# Renforcement de la signature LDAP et du Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c’est important

Les attaques LDAP relay/MITM transmettent l’authentification à un contrôleur de domaine afin d’obtenir un contexte LDAP authentifié. Deux contrôles liés réduisent ces possibilités :

- **LDAP channel binding (CBT)** lie l’authentification concernée au certificat TLS du serveur/canal utilisé par LDAPS, ce qui complique les attaques de relay entre canaux.
- **LDAP signing** exige une protection de l’intégrité pour les binds LDAP SASL. Elle n’ajoute pas de confidentialité ; utilisez TLS lorsque le contenu LDAP doit également être chiffré.<sup>[[2]](#references)</sup>

**Vérification rapide de la configuration** : des outils comme `netexec ldap <dc> -u user -p pass` indiquent les stratégies de signature et de channel binding observées. `(signing:None)` et `(channel binding:Never)` signalent l’absence de ces contrôles, mais la réussite d’un relay dépend toujours du type d’authentification capturé, du comportement d’EPA, des privilèges du compte, du protocole cible et des protections contre le relay. Lorsque le principal relayé dispose des droits nécessaires, des outils comme KrbRelayUp peuvent écrire dans `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurer la délégation contrainte basée sur les ressources (RBCD) et exploiter le chemin de délégation ainsi créé pour usurper l’identité d’un principal privilégié.<sup>[[4]](#references)</sup>

**Les DC Server 2025** introduisent une nouvelle GPO (**LDAP server signing requirements Enforcement**) qui, si elle reste sur **Not Configured**, est définie par défaut sur **Require Signing**. Pour éviter l’application de cette stratégie, vous devez explicitement la définir sur **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS uniquement)

- **Prérequis** :
  - Le correctif CVE-2017-8563 (2017) ajoute la prise en charge d’Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) ajoute la télémétrie LDAPS CBT « what-if ».<sup>[[2]](#references)</sup>
- **GPO (DCs)** : `Domain controller: LDAP server channel binding token requirements`
  - `Never` (valeur par défaut, sans CBT)
  - `When Supported` (application partielle : les clients compatibles avec CBT doivent fournir un jeton valide ; les clients sans prise en charge de CBT peuvent toujours se connecter, et des événements d’audit sont générés)
  - `Always` (application stricte : rejette les binds LDAPS sans CBT valide)<sup>[[1]](#references)</sup>
- **Audit** : définissez **When Supported** pour faire apparaître :
  - **3074** – le bind LDAPS aurait échoué à la validation CBT si celle-ci avait été appliquée.
  - **3075** – le bind LDAPS n’a pas fourni de données CBT et aurait été rejeté si la validation avait été appliquée.
  - (L’événement **3039** signale toujours les échecs CBT sur les versions antérieures.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Application** : définissez **Always** une fois que les clients LDAPS envoient des CBT ; cette option n’est efficace que sur **LDAPS** (pas sur le port 389 sans TLS).<sup>[[1]](#references)</sup>

`When Supported` ne se limite pas à l’audit : cette option valide les CBT des clients compatibles tout en autorisant les clients qui ne prennent pas en charge CBT. La [documentation Microsoft sur la stratégie](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) décrit les valeurs par défaut selon la version. LDAP signing s’applique aux binds concernés sur LDAP/389 ; le channel binding s’applique à l’authentification LDAP protégée par TLS.


## LDAP Signing

- **GPO client** : `Network security: LDAP client signing requirements` = `Require signing` (au lieu de `Negotiate signing`, valeur par défaut sur les versions modernes de Windows).<sup>[[1]](#references)</sup>
- **GPO DC** :
  - Héritée : `Domain controller: LDAP server signing requirements` = `Require signing` (la valeur par défaut est `None`).<sup>[[2]](#references)</sup>
  - **Server 2025** : laissez la stratégie héritée sur `None` et définissez `LDAP server signing requirements Enforcement` sur `Enabled` (`Not Configured` entraîne l’application par défaut ; définissez `Disabled` pour l’éviter).<sup>[[1]](#references)</sup>
- **Compatibilité** : recensez les équipements et applications non Windows qui utilisent des binds simples ou des binds SASL non signés. Microsoft documente la prise en charge sur les versions de Windows maintenues ; les indications de compatibilité avec les anciens clients doivent être vérifiées à partir de la pile réelle du client, plutôt que ramenées à un seuil de version XP.<sup>[[2]](#references)</sup>

## Déploiement en commençant par l’audit (environ 30 jours recommandés)

1. Activez les diagnostics de l’interface LDAP sur chaque DC pour journaliser les binds non signés (événement **2889**) :<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Définissez `LDAP server channel binding token requirements` = **When Supported** dans la GPO du DC pour une application partielle de CBT et la collecte de télémétrie ; vérifiez d’abord la compatibilité avec les clients existants.<sup>[[1]](#references)</sup>
3. Surveillez les événements Directory Service :<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – liaisons non signées/« unsigned-allow » (non conformes aux exigences de signature).
   - **3074/3075** – liaisons LDAPS qui échoueraient ou omettraient le CBT (nécessite KB4520412 sur 2019/2022 et l’étape 2 ci-dessus).
4. Appliquez les paramètres dans des changements distincts :<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DC) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - Liaison de canal LDAP et signature LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Exigences relatives à la liaison de canal LDAP et à la signature LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Mise à jour pour atténuer les relais LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (signature LDAP désactivée → relais Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
