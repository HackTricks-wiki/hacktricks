# Certificats AD

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée afin de relier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, fourni par la Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** désigne la CA qui a délivré le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires au sujet, offrant davantage de flexibilité pour l'identification.
- Les **Basic Constraints** indiquent si le certificat concerne une CA ou une entité finale et définissent les restrictions d'utilisation.
- Les **Extended Key Usages (EKUs)** définissent les usages spécifiques du certificat, tels que la signature de code ou le chiffrement des e-mails, au moyen d'Object Identifiers (OIDs).
- La **Signature Algorithm** précise la méthode utilisée pour signer le certificat.
- La **Signature**, créée avec la clé privée de l'issuer, garantit l'authenticité du certificat.<sup>[[1]](#references)</sup>

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l'utilisation d'un certificat à plusieurs identités, ce qui est essentiel pour les serveurs possédant plusieurs domaines. Des processus d'émission sécurisés sont indispensables afin d'éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD grâce à des conteneurs dédiés, chacun ayant un rôle particulier :<sup>[[1]](#references)</sup>

- Le conteneur **Certification Authorities** contient les certificats des CA racines approuvées.
- Le conteneur **Enrolment Services** fournit des informations sur les Enterprise CAs et leurs certificate templates.
- L'objet **NTAuthCertificates** contient les certificats de CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats grâce aux certificats intermédiaires et aux certificats de CA croisées.

### Acquisition d'un certificat : flux de demande de certificat client

1. Le processus de demande commence lorsque les clients recherchent une Enterprise CA.
2. Un CSR est créé, contenant une clé publique et d'autres informations, après la génération d'une paire de clés publique-privée.
3. La CA évalue le CSR par rapport aux certificate templates disponibles et délivre le certificat selon les permissions du template.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.<sup>[[1]](#references)</sup>

### Certificate Templates

Définis dans AD, ces templates décrivent les paramètres et les permissions nécessaires à l'émission de certificats, notamment les EKUs autorisés ainsi que les droits d'enrollment ou de modification, essentiels à la gestion de l'accès aux services de certificats.<sup>[[1]](#references)</sup>

## Enrollment de certificats

Le processus d'enrollment des certificats est initié par un administrateur qui **crée un certificate template**, ensuite **publié** par une Enterprise Certificate Authority (CA). Le template devient ainsi disponible pour l'enrollment des clients, une étape réalisée en ajoutant le nom du template au champ `certificatetemplates` d'un objet Active Directory.<sup>[[1]](#references)</sup>

Pour qu'un client puisse demander un certificat, des **enrollment rights** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le certificate template et sur l'Enterprise CA elle-même. Des permissions doivent être accordées aux deux emplacements pour qu'une demande aboutisse.<sup>[[1]](#references)</sup>

### Droits d'enrollment des templates

Ces droits sont spécifiés au moyen d'Access Control Entries (ACEs), qui détaillent des permissions telles que :<sup>[[1]](#references)</sup>

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, permettant toutes les permissions étendues.
- **FullControl/GenericAll**, fournissant un contrôle complet sur le template.

### Droits d'enrollment de l'Enterprise CA

Les droits de la CA sont définis dans son descripteur de sécurité, accessible via la console de gestion Certificate Authority. Certains paramètres permettent même aux utilisateurs disposant de faibles privilèges d'accéder à distance, ce qui peut constituer un problème de sécurité.<sup>[[1]](#references)</sup>

### Contrôles d'émission supplémentaires

Certains contrôles peuvent s'appliquer, notamment :<sup>[[1]](#references)</sup>

- **Manager Approval** : place les demandes dans un état d'attente jusqu'à leur approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifient le nombre de signatures requises sur un CSR ainsi que les Application Policy OIDs nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés via :<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), en utilisant des interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via des named pipes ou TCP/IP.
3. L'**interface web d'enrollment des certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), conjointement avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les périphériques réseau, en utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via la GUI (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l’authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Processus d’authentification Kerberos

Dans le processus d’authentification Kerberos, la demande d’un utilisateur pour obtenir un Ticket Granting Ticket (TGT) est signée à l’aide de la **clé privée** du certificat de l’utilisateur. Cette demande fait l’objet de plusieurs validations par le contrôleur de domaine, notamment la **validité**, la **chaîne de certification** et le **statut de révocation** du certificat. Les validations consistent également à vérifier que le certificat provient d’une source approuvée et à confirmer la présence de l’émetteur dans le **magasin de certificats NTAUTH**. La réussite des validations entraîne l’émission d’un TGT. L’objet **`NTAuthCertificates`** dans AD, situé à l’emplacement suivant :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est essentiel pour établir la confiance lors de l’authentification par certificat.<sup>[[1]](#references)</sup>

### Authentification via Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées. Lors de la négociation, le client présente un certificat qui, s’il est correctement validé, autorise l’accès.<sup>[[2]](#references)</sup> L’association d’un certificat à un compte AD peut notamment impliquer la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat.<sup>[[1]](#references)</sup>

### Énumération des services de certificats AD

Les services de certificats d’AD peuvent être énumérés au moyen de requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leurs configurations. Cette opération est accessible à tout utilisateur authentifié sur le domaine sans privilèges particuliers.<sup>[[1]](#references)</sup> Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l’énumération et l’évaluation des vulnérabilités dans les environnements AD CS.<sup>[[3]](#references)</sup>

Les commandes permettant d’utiliser ces outils sont les suivantes :
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

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Qu’est-ce que l’authentification client SSL/TLS et comment fonctionne-t-elle ?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
