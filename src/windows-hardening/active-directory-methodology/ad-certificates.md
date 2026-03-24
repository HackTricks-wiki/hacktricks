# Certificats AD

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée détenue pour lier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, fourni par l'Autorité de Certification (CA), identifie chaque certificat.
- L'**Issuer** fait référence à la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires pour le sujet, améliorant la flexibilité d'identification.
- Les **Basic Constraints** indiquent si le certificat est destiné à une CA ou à une entité finale et définissent des restrictions d'utilisation.
- Les **Extended Key Usages (EKUs)** délimitent les usages spécifiques du certificat, comme le code signing ou le chiffrement d'email, via des Object Identifiers (OIDs).
- L'**Signature Algorithm** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'émetteur, garantit l'authenticité du certificat.

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l'applicabilité d'un certificat à plusieurs identités, crucial pour les serveurs avec plusieurs domaines. Des processus d'émission sécurisés sont essentiels pour éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.

### Autorités de Certification (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats CA dans une forêt AD via des conteneurs désignés, chacun remplissant des rôles spécifiques :

- Le conteneur **Certification Authorities** contient les certificats CA racines de confiance.
- Le conteneur **Enrolment Services** détaille les Enterprise CAs et leurs certificate templates.
- L'objet **NTAuthCertificates** inclut les certificats CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificat avec les certificats intermédiaires et cross CA.

### Acquisition de certificats : flux de requête client

1. Le processus de demande commence par la découverte d'une Enterprise CA par les clients.
2. Un CSR est créé, contenant une public key et d'autres détails, après la génération d'une paire de clés publique-privée.
3. La CA évalue le CSR par rapport aux certificate templates disponibles, émettant le certificat en fonction des permissions du template.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.

### Certificate Templates

Définis dans AD, ces templates décrivent les paramètres et permissions pour l'émission des certificats, y compris les EKUs permis et les droits d'enrollment ou de modification, essentiels pour gérer l'accès aux services de certificats.

Le **Template schema version** a de l'importance. Les templates legacy **v1** (par exemple, le template intégré **WebServer**) n'ont pas plusieurs des contrôles d'application modernes. La recherche ESC15/EKUwu a montré que sur les templates **v1**, un demandeur peut insérer des **Application Policies/EKUs** dans le CSR qui sont **préférées par rapport à** les EKUs configurés du template, permettant d'obtenir des certificats client-auth, enrollment agent ou code-signing avec seulement des droits d'enrollment. Préférez les templates **v2/v3**, supprimez ou remplacez les valeurs par défaut v1, et restreignez strictement les EKUs à l'usage prévu.

## Enrollment de certificat

Le processus d'enrollment pour les certificats est initié par un administrateur qui **crée un certificate template**, lequel est ensuite **publié** par une Enterprise Certificate Authority (CA). Cela rend le template disponible pour l'enrollment client, étape réalisée en ajoutant le nom du template au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client puisse demander un certificat, des **enrollment rights** doivent être accordés. Ces droits sont définis par les security descriptors sur le certificate template et sur l'Enterprise CA elle‑même. Les permissions doivent être accordées aux deux emplacements pour qu'une requête aboutisse.

### Droits d'enrollment sur les templates

Ces droits sont spécifiés via des Access Control Entries (ACEs), détaillant des permissions telles que :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUIDs spécifiques.
- **ExtendedRights**, autorisant toutes les permissions étendues.
- **FullControl/GenericAll**, fournissant le contrôle complet sur le template.

### Droits d'enrollment de l'Enterprise CA

Les droits de la CA sont décrits dans son security descriptor, accessible via la console de gestion Certificate Authority. Certains réglages permettent même à des utilisateurs de faible privilège un accès distant, ce qui peut constituer un risque de sécurité.

### Contrôles d'émission additionnels

Certains contrôles peuvent s'appliquer, tels que :

- **Manager Approval** : place les requêtes en état pending jusqu'à approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifient le nombre de signatures requises sur un CSR et les OIDs d'Application Policy nécessaires.

### Méthodes pour demander des certificats

Les certificats peuvent être demandés via :

1. Le **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilisant les interfaces DCOM.
2. Le **ICertPassage Remote Protocol** (MS-ICPR), via named pipes ou TCP/IP.
3. L'**interface web d'enrollment de certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), en conjonction avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les devices réseau, utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée en utilisant la **clé privée** du certificat de l'utilisateur. Cette demande subit plusieurs validations par le contrôleur de domaine, incluant la **validité**, le **chemin** et l'**état de révocation** du certificat. Les validations incluent aussi la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **magasin de certificats NTAUTH**. Les validations réussies aboutissent à la délivrance d'un TGT. L'objet **`NTAuthCertificates`** dans AD, situé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est central pour établir la confiance pour l'authentification par certificat.

### Authentification Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées, où, durant le handshake, le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. L'association d'un certificat à un compte AD peut impliquer la fonction Kerberos **S4U2Self** ou le **Subject Alternative Name (SAN)** du certificat, parmi d'autres méthodes.

### AD Certificate Services Enumeration

Les services de certificats d'AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leurs configurations. Cela est accessible à tout utilisateur authentifié sur le domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation des vulnérabilités dans les environnements AD CS.

Les commandes pour utiliser ces outils incluent:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Vulnérabilités récentes et mises à jour de sécurité (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalade de privilèges* via le spoofing de certificats de compte machine durant PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d'audit et de strong-mapping ont été introduits via **KB5014754** ; les environnements doivent désormais être en mode *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif disponible à partir du Patch Tuesday **juillet 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Sur les **v1 templates**, un requester avec des droits d'enrollment peut intégrer des **Application Policies/EKUs** dans le CSR qui sont préférées aux EKU du template, produisant des certificats client-auth, enrollment agent, ou code-signing. | Corrigé depuis le **12 novembre 2024**. Remplacer ou superséder les v1 templates (ex. default WebServer), restreindre les EKU à l'intention prévue, et limiter les droits d'enrollment. |

### Chronologie de durcissement Microsoft (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibility → Audit → Enforcement) pour éloigner l'authentification Kerberos basée sur certificats des mappings implicites faibles. Au **11 février 2025**, les domain controllers basculent automatiquement en **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n'est pas définie. Les administrateurs doivent :

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Surveiller les Event ID 39/41 pour les mappings faibles durant la phase *Audit*.
3. Réémettre les client-auth certificates avec la nouvelle **SID extension** ou configurer des strong manual mappings avant février 2025.

---

## Détection et améliorations du durcissement

* **Defender for Identity AD CS sensor (2023-2024)** affiche désormais des évaluations de posture pour ESC1-ESC8/ESC11 et génère des alertes en temps réel telles que *“Domain-controller certificate issuance for a non-DC”* (ESC8) et *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assurez-vous que les sensors sont déployés sur tous les serveurs AD CS pour bénéficier de ces détections.
* Désactiver ou restreindre fortement l'option **“Supply in the request”** sur tous les templates ; préférer des valeurs SAN/EKU explicitement définies.
* Retirer **Any Purpose** ou **No EKU** des templates sauf si strictement nécessaire (adresse les scénarios ESC2).
* Exiger une **manager approval** ou des workflows Enrollment Agent dédiés pour les templates sensibles (ex. WebServer / CodeSigning).
* Restreindre le web enrollment (`certsrv`) et les endpoints CES/NDES aux réseaux de confiance ou derrière une authentification par client-certificate.
* Enforcer le chiffrement des enrollments RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) pour atténuer ESC11 (RPC relay). Le flag est **on by default**, mais est souvent désactivé pour les clients legacy, ce qui rouvre le risque de relay.
* Sécuriser les **IIS-based enrollment endpoints** (CES/Certsrv) : désactiver NTLM lorsque possible ou exiger HTTPS + Extended Protection pour bloquer les relays ESC8.

---



## Références

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
