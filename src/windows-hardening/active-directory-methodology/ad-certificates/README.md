# Certificats AD

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée afin de relier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, fourni par la Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** désigne la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms au sujet, offrant ainsi une plus grande flexibilité d'identification.
- Les **Basic Constraints** indiquent si le certificat est destiné à une CA ou à une entité finale, et définissent les restrictions d'utilisation.
- Les **Extended Key Usages (EKUs)** définissent les objectifs spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, au moyen d'Object Identifiers (OIDs).
- La **Signature Algorithm** spécifie la méthode utilisée pour signer le certificat.
- La **Signature**, créée avec la clé privée de l'issuer, garantit l'authenticité du certificat.<sup>[[1]](#references)</sup>

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l'utilisation d'un certificat à plusieurs identités, ce qui est essentiel pour les serveurs possédant plusieurs domaines. Des processus d'émission sécurisés sont indispensables afin d'éviter les risques d'usurpation par des attackers manipulant la spécification SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD au moyen de conteneurs dédiés, chacun remplissant un rôle particulier :<sup>[[1]](#references)</sup>

- Le conteneur **Certification Authorities** contient les certificats des CA racines approuvées.
- Le conteneur **Enrolment Services** fournit les informations sur les Enterprise CAs et leurs certificate templates.
- L'objet **NTAuthCertificates** contient les certificats de CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats grâce aux certificats intermédiaires et inter-CA.

### Acquisition de certificats : flux de demande d'un certificat client

1. Le processus de demande commence lorsque les clients recherchent une Enterprise CA.
2. Un CSR est créé après la génération d'une paire de clés publique-privée ; il contient une clé publique ainsi que d'autres informations.
3. La CA évalue le CSR par rapport aux certificate templates disponibles et émet le certificat en fonction des permissions du template.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.<sup>[[1]](#references)</sup>

### Certificate Templates

Définis dans AD, ces templates décrivent les paramètres et les permissions utilisés pour émettre des certificats, notamment les EKUs autorisés ainsi que les droits d'enrollment ou de modification, essentiels à la gestion de l'accès aux services de certificats.<sup>[[1]](#references)</sup>

## Enrollment de certificats

Le processus d'enrollment des certificats est lancé par un administrateur qui **crée un certificate template**, ensuite **publié** par une Enterprise Certificate Authority (CA). Le template devient alors disponible pour l'enrollment des clients, grâce à l'ajout de son nom dans le champ `certificatetemplates` d'un objet Active Directory.<sup>[[1]](#references)</sup>

Pour qu'un client puisse demander un certificat, des **droits d'enrollment** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le certificate template et sur l'Enterprise CA elle-même. Les permissions doivent être accordées aux deux endroits pour qu'une demande aboutisse.<sup>[[1]](#references)</sup>

### Droits d'enrollment des templates

Ces droits sont spécifiés au moyen d'Access Control Entries (ACEs), qui définissent notamment les permissions suivantes :<sup>[[1]](#references)</sup>

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, qui autorise toutes les permissions étendues.
- **FullControl/GenericAll**, qui fournit un contrôle complet sur le template.

### Droits d'enrollment de l'Enterprise CA

Les droits de la CA sont décrits dans son descripteur de sécurité, accessible depuis la console de gestion Certificate Authority. Certains paramètres permettent même aux utilisateurs disposant de faibles privilèges d'y accéder à distance, ce qui peut constituer un problème de sécurité.<sup>[[1]](#references)</sup>

### Contrôles supplémentaires d'émission

Certains contrôles peuvent s'appliquer, notamment :<sup>[[1]](#references)</sup>

- **Manager Approval** : place les demandes en attente jusqu'à leur approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifient le nombre de signatures requises sur un CSR ainsi que les Application Policy OIDs nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés via :<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), à l'aide d'interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via des named pipes ou TCP/IP.
3. L'**interface web d'enrollment des certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), conjointement avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les périphériques réseau, à l'aide du Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l’authentification par certificat, en utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Processus d’authentification Kerberos

Dans le processus d’authentification Kerberos, la demande d’un utilisateur pour obtenir un Ticket Granting Ticket (TGT) est signée à l’aide de la **clé privée** du certificat de l’utilisateur. Cette demande fait l’objet de plusieurs validations par le contrôleur de domaine, notamment la **validité**, le **chemin** et l’état de **révocation** du certificat. Les validations comprennent également la vérification que le certificat provient d’une source approuvée et la confirmation de la présence de l’émetteur dans le **magasin de certificats NTAUTH**. La réussite de ces validations entraîne l’émission d’un TGT. L’objet **`NTAuthCertificates`** dans AD, situé à l’emplacement suivant :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est essentiel pour établir la confiance lors de l’authentification par certificat.<sup>[[1]](#references)</sup>

### Authentification Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées. Lors d’une négociation, le client présente un certificat qui, s’il est correctement validé, autorise l’accès.<sup>[[2]](#references)</sup> La mise en correspondance d’un certificat avec un compte AD peut faire intervenir la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat, entre autres méthodes.<sup>[[1]](#references)</sup>

### Énumération des services de certificats AD

Les services de certificats d’AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leurs configurations. Cette opération est accessible à tout utilisateur authentifié sur le domaine, sans privilèges particuliers.<sup>[[1]](#references)</sup> Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l’énumération et l’évaluation des vulnérabilités dans les environnements AD CS.<sup>[[3]](#references)</sup>

Les commandes permettant d’utiliser ces outils incluent :
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
Rubeus peut également utiliser un certificat PFX protégé par mot de passe pour l’authentification PKINIT et demander un TGT. Le commutateur facultatif `/getcredentials` demande un ticket de service U2U et tente de récupérer le hash NT du compte :<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned : Abuser des services de certificats Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Qu’est-ce que l’authentification client SSL/TLS et comment fonctionne-t-elle ?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
