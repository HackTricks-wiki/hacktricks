# Certificats AD

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée pour lier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, fourni par la Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** fait référence à la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires pour le sujet, améliorant la flexibilité d'identification.
- Les **Basic Constraints** indiquent si le certificat est destiné à une CA ou à une entité finale et définissent des restrictions d'utilisation.
- Les **Extended Key Usages (EKUs)** définissent les usages spécifiques du certificat, comme le code signing ou l'email encryption, via des Object Identifiers (OIDs).
- L'**Signature Algorithm** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'**Issuer**, garantit l'authenticité du certificat.

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l'applicabilité d'un certificat à plusieurs identités, crucial pour les serveurs multi-domaines. Des processus d'émission sécurisés sont essentiels pour éviter les risques d'usurpation par des attaquants qui manipulent la spécification SAN.

### Certificate Authorities (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats CA dans une forêt AD via des conteneurs désignés, chacun ayant des rôles spécifiques :

- Le conteneur **Certification Authorities** contient les certificats de root CA de confiance.
- Le conteneur **Enrolment Services** contient des informations sur les Enterprise CAs et leurs modèles de certificats.
- L'objet **NTAuthCertificates** inclut les certificats CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec les certificats intermédiaires et les certificats cross-CA.

### Certificate Acquisition: Client Certificate Request Flow

1. Le processus commence par la découverte d'une Enterprise CA par les clients.
2. Un CSR est créé, contenant une public key et d'autres détails, après la génération d'une paire de clés publique-privée.
3. La CA évalue le CSR par rapport aux certificate templates disponibles, et émet le certificat en fonction des permissions du template.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.

### Certificate Templates

Définis dans AD, ces modèles précisent les paramètres et permissions pour l'émission de certificats, y compris les EKUs autorisés et les droits d'enrollment ou de modification, essentiels pour gérer l'accès aux services de certificats.

**La version du schéma de template est importante.** Les templates **v1** hérités (par exemple le template intégré **WebServer**) manquent de plusieurs mécanismes d'application modernes. La recherche **ESC15/EKUwu** a montré que sur les templates **v1**, un requérant peut insérer des **Application Policies/EKUs** dans le CSR qui sont **préférées aux** EKUs configurés par le template, permettant d'obtenir des certificats client-auth, enrollment agent ou code-signing avec seulement les droits d'enrollment. Privilégiez les templates **v2/v3**, supprimez ou remplacez les valeurs par défaut v1, et restreignez strictement les EKUs à leur usage prévu.

## Enrôlement des certificats

Le processus d'enrôlement des certificats est initié par un administrateur qui **crée un certificate template**, lequel est ensuite **publié** par une Enterprise Certificate Authority (CA). Cela rend le template disponible pour l'enrollment client, étape réalisée en ajoutant le nom du template au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client puisse demander un certificat, des **enrollment rights** doivent être accordés. Ces droits sont définis par les security descriptors sur le template de certificat et sur l'Enterprise CA elle-même. Les permissions doivent être accordées dans les deux emplacements pour que la demande aboutisse.

### Droits d'enrollment sur le template

Ces droits sont spécifiés via des Access Control Entries (ACEs), détaillant des permissions telles que :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUIDs spécifiques.
- **ExtendedRights**, permettant toutes les permissions étendues.
- **FullControl/GenericAll**, fournissant le contrôle total sur le template.

### Droits d'enrollment sur l'Enterprise CA

Les droits de la CA sont définis dans son security descriptor, accessible via la console de gestion Certificate Authority. Certains paramètres permettent même à des utilisateurs peu privilégiés l'accès à distance, ce qui peut poser un problème de sécurité.

### Contrôles d'émission supplémentaires

Certains contrôles peuvent s'appliquer, tels que :

- **Manager Approval** : place les demandes en attente jusqu'à approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifient le nombre de signatures requises sur un CSR et les Application Policy OIDs nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés via :

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilisant des interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via named pipes ou TCP/IP.
3. L'**interface web d'enrollment de certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), en conjonction avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les équipements réseau, utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent aussi demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou via des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette requête subit plusieurs validations par le contrôleur de domaine, incluant la **validité**, la **chaîne de certification** et le **statut de révocation** du certificat. Les validations incluent aussi la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **magasin de certificats NTAUTH**. Les validations réussies entraînent l'émission d'un TGT. L'objet **`NTAuthCertificates`** dans AD, situé à:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est central pour établir la confiance pour l'authentification par certificat.

### Authentification Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées, où pendant le handshake, le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. L'association d'un certificat à un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat, parmi d'autres méthodes.

### Énumération des services de certificats AD

Les services de certificats d'AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leurs configurations. Ceci est accessible par tout utilisateur authentifié dans le domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation des vulnérabilités dans les environnements AD CS.

Les commandes pour utiliser ces outils incluent :
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

| Année | ID / Nom | Impact | Points clés |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalade de privilèges* en falsifiant des certificats de comptes machine pendant PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d'audit et de strong-mapping ont été introduits via **KB5014754** ; les environnements devraient maintenant être en *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans AD CS Web Enrollment (certsrv) et les rôles CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif depuis le **Patch Tuesday de juillet 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Sur les templates **v1**, un requérant avec des droits d'enrollment peut intégrer des **Application Policies/EKUs** dans le CSR qui sont privilégiés par rapport aux EKU du template, produisant des certificats client-auth, enrollment agent ou code-signing. | Corrigé depuis le **12 novembre 2024**. Remplacez ou supersédez les templates v1 (p.ex., WebServer par défaut), restreignez les EKU à leur intention et limitez les droits d'enrollment. |

### Microsoft hardening timeline (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibility → Audit → Enforcement) pour éloigner l'authentification Kerberos par certificat des mappages implicites faibles. À partir du **11 février 2025**, les domain controllers basculent automatiquement en **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n'est pas définie. Les administrateurs doivent :

1. Patcher tous les DCs & serveurs AD CS (mai 2022 ou ultérieur).
2. Surveiller Event ID 39/41 pour les mappages faibles pendant la phase *Audit*.
3. Réémettre les certificats client-auth avec la nouvelle **SID extension** ou configurer des mappages manuels strong avant février 2025.

---

## Détection et améliorations du durcissement

* **Defender for Identity AD CS sensor (2023-2024)** affiche désormais des évaluations de posture pour ESC1-ESC8/ESC11 et génère des alertes en temps réel telles que *“Domain-controller certificate issuance for a non-DC”* (ESC8) et *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assurez-vous que les capteurs sont déployés sur tous les serveurs AD CS pour bénéficier de ces détections.
* Désactivez ou restreignez fortement l'option **“Supply in the request”** sur tous les templates ; privilégiez des valeurs SAN/EKU explicitement définies.
* Supprimez **Any Purpose** ou **No EKU** des templates sauf si absolument nécessaire (traite les scénarios ESC2).
* Exigez une approbation manager ou des workflows dédiés Enrollment Agent pour les templates sensibles (p.ex., WebServer / CodeSigning).
* Restreignez web enrollment (`certsrv`) et les endpoints CES/NDES aux réseaux de confiance ou placez-les derrière une authentification par certificat client.
* Appliquez l'encryption des enrollments RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) pour atténuer ESC11 (RPC relay). Le flag est **activé par défaut**, mais est souvent désactivé pour des clients legacy, ce qui rouvre le risque de relay.
* Sécurisez les endpoints d'enrollment basés sur IIS (CES/Certsrv) : désactivez NTLM lorsque possible ou exigez HTTPS + Extended Protection pour bloquer les relays ESC8.

---



## Références

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
