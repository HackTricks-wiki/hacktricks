# Renforcement de la sécurité de la signature LDAP et du channel binding

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi c’est important

Les attaques de relay/MITM LDAP transmettent l’authentification à un contrôleur de domaine afin d’obtenir un contexte LDAP authentifié. La [présentation du poisoning de résolution de noms et des attaques de relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) décrit le processus général. Deux contrôles associés réduisent ces risques :

- **Le channel binding LDAP (CBT)** lie les authentifications concernées au certificat/canal TLS utilisé par LDAPS, ce qui complique les attaques de relay entre canaux.
- **La signature LDAP** exige une protection de l’intégrité pour les binds LDAP SASL. Elle n’ajoute pas de confidentialité ; utilisez TLS si le contenu LDAP doit également être chiffré.<sup>[[2]](#references)</sup>

**Vérification rapide de la posture** : des outils comme `netexec ldap <dc> -u user -p pass` indiquent les politiques de signature et de channel binding observées. `(signing:None)` et `(channel binding:Never)` signalent l’absence de contrôles, mais la réussite d’un relay dépend toujours du type d’authentification capturé, du comportement d’EPA, des privilèges du compte, du protocole cible et des protections contre le relay. Si le principal relayé possède les droits nécessaires, des outils comme KrbRelayUp peuvent modifier `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurer une délégation contrainte basée sur les ressources (RBCD), puis utiliser le chemin de délégation obtenu pour usurper l’identité d’un principal privilégié.<sup>[[4]](#references)</sup>

**Les contrôleurs de domaine Server 2025** introduisent une nouvelle GPO (**LDAP server signing requirements Enforcement**) dont la valeur par défaut est **Require Signing** lorsqu’elle reste **Not Configured**. Pour éviter l’application de cette exigence, vous devez explicitement définir cette stratégie sur **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS uniquement)

- **Prérequis** :
  - Le correctif CVE-2017-8563 (2017) ajoute la prise en charge d’Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) ajoute la télémétrie LDAPS CBT « what-if ».<sup>[[2]](#references)</sup>
- **GPO (contrôleurs de domaine)** : `Domain controller: LDAP server channel binding token requirements`
  - `Never` (valeur par défaut, sans CBT)
  - `When Supported` (application partielle : les clients prenant en charge CBT doivent fournir un jeton valide ; les clients sans prise en charge de CBT peuvent toujours effectuer un bind, et des événements d’audit sont générés)
  - `Always` (application obligatoire : rejette les binds LDAPS sans CBT valide)<sup>[[1]](#references)</sup>
- **Audit** : définissez **When Supported** pour détecter les cas suivants :
  - **3074** – Le bind LDAPS aurait échoué à la validation CBT si celle-ci avait été appliquée.
  - **3075** – Le bind LDAPS ne contenait pas de données CBT et aurait été rejeté si la validation avait été appliquée.
  - (L’événement **3039** signale toujours les échecs CBT sur les anciennes versions.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Application obligatoire** : définissez **Always** une fois que les clients LDAPS envoient des CBT ; cette option ne s’applique qu’à **LDAPS** (pas au port 389 sans TLS).<sup>[[1]](#references)</sup>

`When Supported` ne se limite pas à l’audit : cette option valide les CBT des clients compatibles tout en autorisant les clients qui ne les prennent pas en charge. La [documentation de référence Microsoft sur cette stratégie](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) décrit les valeurs par défaut selon la version. La signature LDAP s’applique aux binds concernés sur LDAP/389 ; le channel binding s’applique à l’authentification LDAP protégée par TLS.


## Signature LDAP

- **GPO client** : `Network security: LDAP client signing requirements` = `Require signing` (au lieu de la valeur par défaut `Negotiate signing` sur les versions modernes de Windows).<sup>[[1]](#references)</sup>
- **GPO des contrôleurs de domaine** :
  - Ancienne stratégie : `Domain controller: LDAP server signing requirements` = `Require signing` (la valeur par défaut est `None`).<sup>[[2]](#references)</sup>
  - **Server 2025** : laissez l’ancienne stratégie sur `None` et définissez `LDAP server signing requirements Enforcement` sur `Enabled` (`Not Configured` entraîne l’application par défaut ; définissez `Disabled` pour l’éviter).<sup>[[1]](#references)</sup>
- **Compatibilité** : recensez les appareils et applications non-Windows qui utilisent des binds simples ou des binds SASL non signés. Microsoft documente la prise en charge sur les versions de Windows maintenues ; les affirmations de compatibilité avec les anciens clients doivent être vérifiées avec la pile cliente réelle, plutôt que réduites à un seuil de version XP.<sup>[[2]](#references)</sup>

## Chemins de relay et réauthentification SASL signée

Si **seule la signature** est requise, le relay vers LDAPS peut encore fonctionner si le channel binding n’est pas appliqué : TLS assure l’intégrité du transport. Si **seul le channel binding** est requis, LDAP en clair ne dispose pas de canal TLS auquel le lier ; un relay peut authentifier sur TCP 389, puis utiliser StartTLS pour les opérations qui nécessitent TLS, à condition que l’identité relayée ait les droits nécessaires. L’application des deux contrôles ferme ces solutions de remplacement conventionnelles, mais n’a pas empêché la faille suivante sur les contrôleurs de domaine non corrigés.<sup>[[5]](#references)</sup>

### Ajouter une opération LDAP après un Bind relayé

Sur les contrôleurs de domaine Windows Server 2016–2025 concernés, établissez d’abord une **connexion LDAP SASL NTLM signée** sur TCP 389 en tant qu’identité X, en utilisant des identifiants dont vous connaissez la clé de session (ou un contexte SASL NTLM anonyme, si celui-ci est accepté). Forcez l’identité Y à s’authentifier **via SMB** auprès du relay. Transmettez les messages NTLM NEGOTIATE de Y et CHALLENGE du contrôleur de domaine dans des requêtes Bind GSS-SPNEGO sur la connexion LDAP existante de X. Le client SMB Windows définit `NTLMSSP_NEGOTIATE_SIGN` ; le bind LDAP obtenu exige donc une couche SASL signée. Un échange provenant de HTTP/WebDAV ne comporte généralement pas cet indicateur et ne peut pas être utilisé de la même manière ici.<sup>[[5]](#references)</sup>

Lorsque Y envoie NTLM AUTHENTICATE, placez **deux messages LDAP distincts dans un seul enregistrement SASL préfixé par sa longueur** : un BindRequest contenant cette réponse, suivi d’un ModifyRequest. Signez l’ensemble de l’enregistrement avec la clé connue de X. Le contrôleur de domaine vulnérable vérifie l’enregistrement avec la clé de X, termine le Bind et fait de Y l’identité autorisée sur la connexion, puis exécute le ModifyRequest restant en tant que Y sans revérifier l’enregistrement avec la clé de Y. Cela ne révèle ni le mot de passe ni la clé de session de Y ; un enregistrement ultérieur signé par X échoue. Une modification RBCD de `msDS-AllowedToActOnBehalfOfOtherIdentity` ou une modification de shadow credentials de `msDS-KeyCredentialLink` exige toujours que Y ait les droits sur l’objet cible. Voir [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) et, pour un compte machine de contrôleur de domaine relayé, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Il s’agit d’un contournement sur **LDAP en clair**, et non d’un contournement du channel binding LDAPS. Sur LDAPS, TLS protège la connexion et Windows n’établit pas la couche de signature SASL NTLM avec la clé de X requise pour cette méthode d’empilement d’enregistrements. Si TCP 389 n’est pas disponible, la technique ne peut pas simplement être transposée à TCP 636. Les mises à jour de sécurité d’octobre 2026 empêchent l’opération dans le même enregistrement en supprimant les données restantes lorsque le Bind modifie l’identité de la connexion.<sup>[[5]](#references)</sup> KB5126646 est la mise à jour pour Windows Server 2025 ; les autres versions de Server concernées ont des numéros KB différents.<sup>[[7]](#references)</sup>

L’outil [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) du chercheur encapsule une version modifiée de `ntlmrelayx.py` pour ce processus. Il nécessite une source de coercition **SMB**, une version figée d’Impacket exposant les API de signature LDAP/contexte de sécurité (Impacket 0.13.1 de PyPI ne suffit pas) et un compte contrôlé par l’attaquant pour le bind signé initial. Pour une modification RBCD, fournissez le DN de l’objet victime et le SID d’un ordinateur délégant contrôlé ; utilisez `-attribute` avec `-value` ou `-value-hex` pour une autre modification autorisée. Vérifiez la lecture de confirmation signée effectuée indépendamment par l’outil, plutôt que de considérer un message `FAILED` côté relay comme la preuve que le ModifyRequest a échoué.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Déclenchez l’authentification SMB séparément ; consultez [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) pour un vecteur de coercition et la [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) pour d’autres vecteurs. La commande et l’implémentation de l’outil sont documentées dans son dépôt.<sup>[[6]](#references)</sup>

## Déploiement axé d’abord sur l’audit (environ 30 jours recommandés)

1. Activez les diagnostics de l’interface LDAP sur chaque DC pour journaliser les liaisons non signées (événement **2889**) :<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Définissez dans la GPO des DC `LDAP server channel binding token requirements` = **When Supported** pour une application partielle de CBT et la télémétrie ; vérifiez d’abord la compatibilité avec les clients hérités.<sup>[[1]](#references)</sup>
3. Surveillez les événements Directory Service :<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – liaisons non signées/acceptées sans signature (non conformes aux exigences de signature).
   - **3074/3075** – liaisons LDAPS qui échoueraient ou omettraient le CBT (nécessite KB4520412 sur 2019/2022 et l’étape 2 ci-dessus).
4. Appliquez les paramètres dans des changements distincts :<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DC) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Liaison de canal LDAP et signature LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Exigences de liaison de canal LDAP et de signature LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Mise à jour de l’atténuation des relais LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (signature LDAP désactivée → relais Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signé, scellé et relayé, style NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Preuve de concept LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Informations sur les versions de Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
