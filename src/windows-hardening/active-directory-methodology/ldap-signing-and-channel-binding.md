# Renforcement de la signature LDAP et du channel binding

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c’est important

Les attaques de relais LDAP/MITM transmettent l’authentification à un contrôleur de domaine pour obtenir un contexte LDAP authentifié. La [présentation de l’empoisonnement de la résolution de noms et des attaques par relais](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) couvre le déroulement général. Deux contrôles associés réduisent ces risques :

- **Le channel binding LDAP (CBT)** lie les authentifications concernées au certificat du serveur TLS ou au canal utilisé par LDAPS, ce qui complique les relais entre canaux.
- **La signature LDAP** exige une protection de l’intégrité pour les liaisons LDAP SASL. Elle n’ajoute pas de confidentialité ; utilisez TLS si le contenu LDAP doit également être chiffré.<sup>[[2]](#references)</sup>

**Vérification rapide de la configuration** : des outils comme `netexec ldap <dc> -u user -p pass` indiquent les stratégies de signature et de channel binding observées. `(signing:None)` et `(channel binding:Never)` indiquent que ces contrôles sont absents, mais la réussite d’un relais dépend toujours du type d’authentification intercepté, du comportement d’EPA, des privilèges du compte, du protocole cible et des protections contre les relais. Lorsque le principal relayé dispose des droits nécessaires, des outils comme KrbRelayUp peuvent modifier `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurer la délégation contrainte basée sur les ressources (RBCD) et utiliser le chemin de délégation ainsi obtenu pour usurper l’identité d’un principal privilégié.<sup>[[4]](#references)</sup>

**Les contrôleurs de domaine Server 2025** introduisent une nouvelle GPO (**LDAP server signing requirements Enforcement**) qui applique par défaut **Require Signing** lorsqu’elle reste sur **Not Configured**. Pour éviter cette application, vous devez explicitement définir cette stratégie sur **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS uniquement)

- **Prérequis** :
  - Le correctif CVE-2017-8563 (2017) ajoute la prise en charge d’Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) ajoute la télémétrie « what-if » du CBT pour LDAPS.<sup>[[2]](#references)</sup>
- **GPO (contrôleurs de domaine)** : `Domain controller: LDAP server channel binding token requirements`
  - `Never` (valeur par défaut, sans CBT)
  - `When Supported` (application partielle : les clients prenant en charge le CBT doivent fournir un jeton valide ; les clients sans prise en charge du CBT peuvent toujours se connecter, et des événements d’audit sont générés)
  - `Always` (application obligatoire : rejette les liaisons LDAPS sans CBT valide)<sup>[[1]](#references)</sup>
- **Audit** : définissez **When Supported** pour détecter :
  - **3074** – la liaison LDAPS aurait échoué à la validation du CBT si celui-ci avait été appliqué.
  - **3075** – la liaison LDAPS ne contenait pas de données CBT et aurait été rejetée si celui-ci avait été appliqué.
  - (L’événement **3039** signale toujours les échecs du CBT sur les anciennes versions.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Application** : définissez **Always** une fois que les clients LDAPS envoient des CBT ; cette option ne s’applique qu’à **LDAPS** (pas au port 389 brut).<sup>[[1]](#references)</sup>

`When Supported` ne se limite pas à l’audit : cette option valide le CBT pour les clients compatibles tout en autorisant les clients qui ne le prennent pas en charge. La [documentation Microsoft sur cette stratégie](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) décrit ses valeurs par défaut, qui varient selon la version. La signature LDAP s’applique aux liaisons concernées sur LDAP/389 ; le channel binding s’applique à l’authentification LDAP protégée par TLS.


## Signature LDAP

- **GPO client** : `Network security: LDAP client signing requirements` = `Require signing` (au lieu de `Negotiate signing`, la valeur par défaut sur les versions modernes de Windows).<sup>[[1]](#references)</sup>
- **GPO des contrôleurs de domaine** :
  - Ancienne stratégie : `Domain controller: LDAP server signing requirements` = `Require signing` (la valeur par défaut est `None`).<sup>[[2]](#references)</sup>
  - **Server 2025** : laissez l’ancienne stratégie sur `None` et définissez `LDAP server signing requirements Enforcement` sur `Enabled` (`Not Configured` entraîne une application par défaut ; définissez `Disabled` pour l’éviter).<sup>[[1]](#references)</sup>
- **Compatibilité** : inventorie les appliances et applications non Windows qui utilisent des liaisons simples ou des liaisons SASL non signées. Microsoft documente la prise en charge sur les versions de Windows maintenues ; les déclarations de compatibilité avec les anciens clients doivent être vérifiées avec la pile logicielle réelle du client, plutôt que résumées par une limite de version XP.<sup>[[2]](#references)</sup>

## Déploiement avec audit préalable (environ 30 jours recommandés)

1. Activez les diagnostics de l’interface LDAP sur chaque contrôleur de domaine afin de consigner les liaisons non signées (événement **2889**) :<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Définissez `LDAP server channel binding token requirements` sur le GPO du DC à **When Supported** pour une application partielle de CBT et la télémétrie ; vérifiez d’abord la compatibilité avec les clients hérités.<sup>[[1]](#references)</sup>
3. Surveillez les événements Directory Service :<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds non signés/acceptés sans signature (non-conformité de la signature).
   - **3074/3075** – binds LDAPS qui échoueraient ou omettraient le CBT (nécessite KB4520412 sur 2019/2022 et l’étape 2 ci-dessus).
4. Appliquez les paramètres dans des modifications distinctes :<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Liaison de canal LDAP et signature LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Exigences de liaison de canal et de signature LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Mise à jour d’atténuation des relais LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (signature LDAP désactivée → relais Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
