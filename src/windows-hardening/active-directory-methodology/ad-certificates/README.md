# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est appairée à une clé privée détenue pour lier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, marque la durée de validité effective du certificat.
- Un **Serial Number** unique, fourni par l'Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** fait référence à la CA qui a émis le certificat.
- **SubjectAlternativeName** permet des noms supplémentaires pour le subject, améliorant la flexibilité d'identification.
- Les **Basic Constraints** indiquent si le certificat est destiné à une CA ou à une entité finale et définissent les restrictions d'utilisation.
- Les **Extended Key Usages (EKUs)** délimitent les usages spécifiques du certificat, comme le code signing ou le chiffrement d'email, via des Object Identifiers (OIDs).
- L'**Signature Algorithm** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'issuer, garantit l'authenticité du certificat.

### Special Considerations

- Les **Subject Alternative Names (SANs)** étendent l'applicabilité d'un certificat à plusieurs identités, crucial pour les serveurs ayant plusieurs domaines. Des processus d'émission sécurisés sont essentiels pour éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD via des conteneurs désignés, chacun ayant des rôles uniques :

- Le conteneur **Certification Authorities** contient les certificats des root CA de confiance.
- Le conteneur **Enrolment Services** détaille les Enterprise CAs et leurs certificate templates.
- L'objet **NTAuthCertificates** inclut les certificats CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec les certificats intermédiaires et les cross CA.

### Certificate Acquisition: Client Certificate Request Flow

1. Le processus de demande commence par la découverte d'une Enterprise CA par les clients.
2. Un CSR est créé, contenant une public key et d'autres détails, après la génération d'une paire de clés publique-privée.
3. La CA évalue le CSR par rapport aux certificate templates disponibles, émettant le certificat selon les permissions du template.
4. Après approbation, la CA signe le certificat avec sa clé privée et le retourne au client.

### Certificate Templates

Définis au sein d'AD, ces templates décrivent les paramètres et permissions pour l'émission de certificats, incluant les EKUs permis et les droits d'enrôlement ou de modification, critiques pour la gestion de l'accès aux services de certificat.

## Certificate Enrollment

Le processus d'enrôlement pour les certificats est initié par un administrateur qui **create a certificate template**, lequel est ensuite **published** par une Enterprise Certificate Authority (CA). Cela rend le template disponible pour l'enrôlement des clients, une étape réalisée en ajoutant le nom du template au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client puisse demander un certificat, des **enrollment rights** doivent être accordés. Ces droits sont définis par les security descriptors sur le certificate template et sur l'Enterprise CA elle-même. Des permissions doivent être accordées aux deux emplacements pour qu'une demande réussisse.

### Template Enrollment Rights

Ces droits sont spécifiés via des Access Control Entries (ACEs), détaillant des permissions telles que :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUIDs spécifiques.
- **ExtendedRights**, permettant toutes les permissions étendues.
- **FullControl/GenericAll**, fournissant le contrôle complet sur le template.

### Enterprise CA Enrollment Rights

Les droits de la CA sont définis dans son security descriptor, accessible via la console de gestion Certificate Authority. Certains paramètres permettent même à des utilisateurs à faibles privilèges un accès distant, ce qui peut représenter un risque de sécurité.

### Additional Issuance Controls

Certains contrôles peuvent s'appliquer, tels que :

- **Manager Approval** : place les demandes en état pending jusqu'à approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifient le nombre de signatures requises sur un CSR et les Application Policy OIDs nécessaires.

### Methods to Request Certificates

Les certificats peuvent être demandés via :

1. Le **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilisant des interfaces DCOM.
2. Le **ICertPassage Remote Protocol** (MS-ICPR), via des named pipes ou TCP/IP.
3. L'**interface web d'enrôlement de certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), en conjonction avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les dispositifs réseau, utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent aussi demander des certificats via l'GUI (`certmgr.msc` ou `certlm.msc`) ou les outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette demande subit plusieurs validations par le contrôleur de domaine, incluant la **validité**, le **chemin de certification** et le **statut de révocation** du certificat. Les validations incluent également la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **magasin de certificats NTAUTH**. Les validations réussies entraînent l'émission d'un TGT. L'objet **`NTAuthCertificates`** dans AD, situé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est central pour établir la confiance dans l'authentification par certificat.

### Secure Channel (Schannel) Authentication

Schannel facilite les connexions TLS/SSL sécurisées, où lors d'une négociation (handshake), le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. L'association d'un certificat à un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat, parmi d'autres méthodes.

### AD Certificate Services Enumeration

Les services de certificats d'AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leurs configurations. Cela est accessible à tout utilisateur authentifié sur le domaine sans privilèges particuliers. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation des vulnérabilités dans les environnements AD CS.

Les commandes pour utiliser ces outils incluent:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Références

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
