# Certificats AD

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé détenue secrètement afin de relier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, fourni par la Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** désigne la CA ayant émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires au sujet, offrant davantage de flexibilité pour l'identification.
- Les **Basic Constraints** indiquent si le certificat est destiné à une CA ou à une entité finale, et définissent les restrictions d'utilisation.
- Les **Extended Key Usages (EKUs)** définissent les usages spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, au moyen d'Object Identifiers (OIDs).
- La **Signature Algorithm** spécifie la méthode utilisée pour signer le certificat.
- La **Signature**, créée avec la clé privée de l'émetteur, garantit l'authenticité du certificat.<sup>[[4]](#references)</sup>

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l'utilisation d'un certificat à plusieurs identités, ce qui est essentiel pour les serveurs hébergeant plusieurs domaines. Des processus d'émission sécurisés sont indispensables afin d'éviter les risques d'usurpation liés à la manipulation de la spécification SAN par des attaquants.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD au moyen de conteneurs dédiés, chacun ayant un rôle particulier :<sup>[[4]](#references)</sup>

- Le conteneur **Certification Authorities** contient les certificats des CA racines approuvées.
- Le conteneur **Enrolment Services** fournit des informations sur les Enterprise CAs et leurs modèles de certificats.
- L'objet **NTAuthCertificates** contient les certificats de CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats grâce aux certificats intermédiaires et inter-CA.

### Acquisition d'un certificat : flux de demande de certificat client

1. Le processus de demande commence lorsque les clients recherchent une Enterprise CA.
2. Un CSR est créé après la génération d'une paire de clés publique-privée ; il contient une clé publique ainsi que d'autres informations.
3. La CA évalue le CSR par rapport aux modèles de certificats disponibles et émet le certificat selon les permissions du modèle.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.<sup>[[4]](#references)</sup>

### Modèles de certificats

Définis dans AD, ces modèles décrivent les paramètres et les permissions utilisés pour émettre des certificats, notamment les EKUs autorisés ainsi que les droits d'inscription ou de modification, qui sont essentiels à la gestion de l'accès aux services de certificats.<sup>[[4]](#references)</sup>

**La version du schéma du modèle est importante.** Les modèles **v1** legacy (par exemple, le modèle **WebServer** intégré) ne disposent pas de plusieurs mécanismes modernes de contrôle. Les recherches **ESC15/EKUwu** ont montré que, sur les modèles **v1**, un demandeur peut intégrer des **Application Policies/EKUs** dans le CSR ; celles-ci sont **préférées aux** EKUs configurés dans le modèle, ce qui permet d'obtenir des certificats d'authentification client, d'agent d'inscription ou de signature de code avec uniquement des droits d'inscription. Privilégiez les modèles **v2/v3**, supprimez ou remplacez les modèles v1 par défaut et limitez strictement les EKUs à l'usage prévu.<sup>[[1]](#references)</sup>

## Inscription aux certificats

Le processus d'inscription aux certificats est lancé par un administrateur qui **crée un modèle de certificat**, ensuite **publié** par une Enterprise Certificate Authority (CA). Le modèle devient ainsi disponible pour l'inscription des clients, une étape réalisée en ajoutant le nom du modèle au champ `certificatetemplates` d'un objet Active Directory.<sup>[[4]](#references)</sup>

Pour qu'un client puisse demander un certificat, des **droits d'inscription** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le modèle de certificat et sur l'Enterprise CA elle-même. Des permissions doivent être accordées aux deux emplacements pour qu'une demande aboutisse.

### Droits d'inscription du modèle

Ces droits sont spécifiés au moyen d'Access Control Entries (ACEs), qui détaillent des permissions telles que :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, qui autorise toutes les permissions étendues.
- **FullControl/GenericAll**, qui fournit un contrôle complet sur le modèle.

### Droits d'inscription de l'Enterprise CA

Les droits de la CA sont définis dans son descripteur de sécurité, accessible depuis la console de gestion de Certificate Authority. Certains paramètres permettent même aux utilisateurs disposant de faibles privilèges d'y accéder à distance, ce qui peut constituer un problème de sécurité.

### Contrôles d'émission supplémentaires

Certains contrôles peuvent s'appliquer, notamment :

- **Manager Approval** : place les demandes dans un état d'attente jusqu'à leur approbation par un gestionnaire de certificats.
- **Enrolment Agents and Authorized Signatures** : spécifie le nombre de signatures requises sur un CSR ainsi que les OIDs d'Application Policy nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés au moyen des éléments suivants :

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), à l'aide d'interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via des named pipes ou TCP/IP.
3. L'**interface web d'inscription aux certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), conjointement avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les périphériques réseau, à l'aide du Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l’authentification par certificat, en utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d’authentification Kerberos

Dans le processus d’authentification Kerberos, la demande d’un utilisateur pour obtenir un Ticket Granting Ticket (TGT) est signée à l’aide de la **clé privée** du certificat de l’utilisateur. Cette demande fait l’objet de plusieurs validations par le contrôleur de domaine, notamment la **validité**, le **chemin** et l’**état de révocation** du certificat. Les validations consistent également à vérifier que le certificat provient d’une source approuvée et à confirmer la présence de l’émetteur dans le **magasin de certificats NTAUTH**. La réussite de ces validations entraîne l’émission d’un TGT. L’objet **`NTAuthCertificates`** dans AD, situé à l’emplacement suivant :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est essentiel pour établir la confiance lors de l’authentification par certificat.<sup>[[4]](#references)</sup>

Depuis le déploiement de **KB5014754**, l’authentification moderne par certificat Kerberos concerne principalement la **force du mapping**, et pas uniquement les EKU.<sup>[[2]](#references)</sup> Dans les forêts renforcées :

- Un certificat qui contient uniquement un **UPN/DNS SAN** peut ne plus suffire pour l’ouverture de session.
- Le KDC privilégie une **liaison forte**, généralement l’extension de sécurité **SID** (`1.3.6.1.4.1.311.25.2`) ou un mapping explicite fort dans `altSecurityIdentities`.
- Si le certificat ne possède pas de mapping fort, les DC consignent les événements **Kdcsvc Event ID 39/41** en mode de compatibilité et refusent l’authentification en mode d’application.
- Dans les chemins d’attaque mixtes, **ESC9/ESC16** sont importants, car ils suppriment l’extension SID des certificats émis ; les opérateurs s’appuient alors sur des mappings explicites ou sur les formats SID d’URL SAN lorsque le chemin d’attaque les prend en charge.

### Authentification Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées. Lors d’un handshake, le client présente un certificat qui, s’il est correctement validé, autorise l’accès. Le mapping d’un certificat vers un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat, entre autres méthodes.<sup>[[4]](#references)</sup>

Schannel constitue également la solution de repli pratique lorsque **PKINIT** n’est pas disponible. Par exemple, si un domain controller ne possède pas de certificat **Smart Card Logon** adapté, les outils `certipy auth`/PKINIT peuvent échouer à obtenir un TGT, mais le même certificat peut tout de même être utilisable via **LDAPS** ou **LDAP StartTLS** pour l’authentification et les opérations LDAP.

### Énumération des services de certificats AD

Les services de certificats d’AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leur configuration. Cette opération est accessible à tout utilisateur authentifié du domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l’énumération et l’évaluation des vulnérabilités dans les environnements AD CS.

Les commandes permettant d’utiliser ces outils incluent :
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnérabilités récentes et mises à jour de sécurité (2022-2025)

| Année | ID / Nom | Impact | Points clés |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Élévation de privilèges* par usurpation de certificats de comptes machine pendant PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Les contrôles d’audit et de *strong mapping* ont été introduits via **KB5014754** ; les environnements devraient désormais être en mode *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif disponible depuis le Patch Tuesday de **juillet 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Sur les **templates v1**, un demandeur disposant de droits d’enrollment peut intégrer des **Application Policies/EKUs** dans le CSR, lesquelles sont prioritaires par rapport aux EKUs du template, permettant de générer des certificats d’authentification client, d’Enrollment Agent ou de signature de code. | Corrigé depuis le **12 novembre 2024**. Remplacez ou faites évoluer les templates v1 (par exemple, WebServer par défaut), limitez les EKUs à leur usage prévu et restreignez les droits d’enrollment. |

### Chronologie du hardening Microsoft (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibility → Audit → Enforcement) afin d’éloigner l’authentification Kerberos par certificat des mappings implicites faibles. Depuis le **11 février 2025**, les contrôleurs de domaine passent automatiquement en mode **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n’est pas définie. Microsoft a ensuite actualisé la chronologie afin que le retour au mode compatibility reste possible jusqu’à la mise à jour de sécurité du **9 septembre 2025**.<sup>[[2]](#references)</sup> Les administrateurs doivent :

1. Appliquer les correctifs à tous les DC et serveurs AD CS (mai 2022 ou ultérieur).
2. Surveiller les Event ID 39/41 afin de détecter les mappings faibles pendant la phase *Audit*.
3. Réémettre les certificats d’authentification client avec la nouvelle **SID extension**, ou configurer des mappings manuels forts avant que l’enforcement ne bloque les mappings faibles.

### Notes opérateur pour les forêts renforcées

- **ESC1/ESC6 ne suffisent plus à eux seuls** dans les environnements 2025+. Si vous demandez un certificat pour un autre principal, vous avez généralement aussi besoin d’un artefact de mapping fort, tel que la SID extension ou un mapping explicite.
- **ESC15 (EKUwu)** est surtout intéressant dans les environnements non corrigés, car il transforme des templates **v1** inoffensifs tels que **WebServer** en certificats capables d’authentification ou d’Enrollment Agent, en injectant des **Application Policies**. Kerberos PKINIT évalue toujours les EKUs, mais **LDAP Schannel** respecte également les Application Policies, ce qui maintient la pertinence des abus basés sur LDAP.<sup>[[1]](#references)</sup>
- **ESC16** est un paramètre applicable à toute la CA : si la CA désactive globalement la SID security extension, chaque certificat émis revient à un comportement de mapping plus faible, sauf si la chaîne d’attaque injecte une SID dans un autre format pris en charge.

---

## Améliorations de la détection et du hardening

* Le **Defender for Identity AD CS sensor (2023-2024)** expose désormais des évaluations de posture pour ESC1-ESC8/ESC11 et génère des alertes en temps réel telles que *“Domain-controller certificate issuance for a non-DC”* (ESC8) et *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assurez-vous que les sensors sont déployés sur tous les serveurs AD CS afin de bénéficier de ces détections.<sup>[[3]](#references)</sup>
* Désactivez ou limitez strictement l’option **“Supply in the request”** sur tous les templates ; préférez des valeurs SAN/EKU définies explicitement.
* Supprimez **Any Purpose** ou **No EKU** des templates, sauf nécessité absolue (réduit les scénarios ESC2).
* Exigez une **approbation du responsable** ou des workflows dédiés d’Enrollment Agent pour les templates sensibles (par exemple, WebServer / CodeSigning).
* Restreignez l’enrollment web (`certsrv`) et les endpoints CES/NDES aux réseaux de confiance, ou protégez-les derrière une authentification par certificat client.
* Forcez le chiffrement RPC de l’enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) afin de réduire les risques liés à ESC11 (RPC relay). Le flag est **activé par défaut**, mais il est souvent désactivé pour les clients legacy, ce qui réintroduit le risque de relay.
* Sécurisez les endpoints d’enrollment basés sur **IIS** (CES/Certsrv) : désactivez NTLM lorsque possible, ou exigez HTTPS + Extended Protection afin de bloquer les relays ESC8.

---

## Références

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
