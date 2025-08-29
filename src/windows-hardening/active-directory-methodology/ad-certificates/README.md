# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Le **Subject** du certificat indique son propriétaire.
- Une **Public Key** est appariée à une clé privée détenue pour lier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, marque la durée de validité du certificat.
- Un **Serial Number** unique, fourni par l'Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** fait référence à la CA qui a émis le certificat.
- **SubjectAlternativeName** permet des noms supplémentaires pour le sujet, améliorant la flexibilité d'identification.
- **Basic Constraints** indiquent si le certificat est pour une CA ou une entité finale et définissent les restrictions d'utilisation.
- **Extended Key Usages (EKUs)** délimitent les usages spécifiques du certificat, comme le code signing ou le chiffrement d'e-mail, via des Object Identifiers (OIDs).
- Le **Signature Algorithm** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'issuer, garantit l'authenticité du certificat.

### Special Considerations

- Les **Subject Alternative Names (SANs)** élargissent l'applicabilité d'un certificat à plusieurs identités, crucial pour les serveurs gérant plusieurs domaines. Des processus d'émission sécurisés sont essentiels pour éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS reconnaît les certificats CA dans une forêt AD via des conteneurs désignés, chacun jouant un rôle spécifique :

- Le conteneur **Certification Authorities** contient les certificats de CA racine de confiance.
- Le conteneur **Enrolment Services** détaille les CA d'entreprise et leurs certificate templates.
- L'objet **NTAuthCertificates** inclut les certificats CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec les certificats intermediates et cross CA.

### Certificate Acquisition: Client Certificate Request Flow

1. Le processus de demande commence par la recherche par les clients d'une CA d'entreprise.
2. Un CSR est créé, contenant une public key et d'autres détails, après la génération d'une paire clé publique/privée.
3. La CA évalue le CSR par rapport aux certificate templates disponibles, émettant le certificat en fonction des permissions du template.
4. Après approbation, la CA signe le certificat avec sa clé privée et le retourne au client.

### Certificate Templates

Définis au sein d'AD, ces templates décrivent les paramètres et permissions pour l'émission des certificats, y compris les EKUs permis et les droits d'enrollment ou de modification, essentiels pour gérer l'accès aux services de certificats.

## Certificate Enrollment

Le processus d'enrollment des certificats est initié par un administrateur qui **crée un certificate template**, lequel est ensuite **publié** par une Enterprise Certificate Authority (CA). Cela rend le template disponible pour l'enrollment des clients, une étape réalisée en ajoutant le nom du template au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client puisse demander un certificat, des **enrollment rights** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le certificate template et sur la Enterprise CA elle-même. Les permissions doivent être accordées dans les deux emplacements pour qu'une demande réussisse.

### Template Enrollment Rights

Ces droits sont spécifiés via des Access Control Entries (ACEs), détaillant des permissions comme :

- **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacune associée à des GUID spécifiques.
- **ExtendedRights**, autorisant toutes les permissions étendues.
- **FullControl/GenericAll**, fournissant un contrôle complet sur le template.

### Enterprise CA Enrollment Rights

Les droits de la CA sont décrits dans son descripteur de sécurité, accessible via la console de gestion Certificate Authority. Certains paramètres permettent même à des utilisateurs faiblement privilégiés un accès distant, ce qui peut constituer un risque de sécurité.

### Additional Issuance Controls

Certains contrôles supplémentaires peuvent s'appliquer, tels que :

- **Manager Approval** : place les demandes en attente jusqu'à approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifient le nombre de signatures requises sur un CSR et les Application Policy OIDs nécessaires.

### Methods to Request Certificates

Les certificats peuvent être demandés via :

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilisant des interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via des named pipes ou TCP/IP.
3. L'interface web d'enrollment de certificats, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), conjointement avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les dispositifs réseau, utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent aussi demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou PowerShell's `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la requête d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette requête subit plusieurs validations par le contrôleur de domaine, notamment la **validité**, la **chaîne de certification** et le **statut de révocation** du certificat. Les validations comprennent également la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **magasin de certificats NTAUTH**. Les validations réussies entraînent l'émission d'un TGT. L'objet **`NTAuthCertificates`** dans AD, situé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est central pour établir la confiance dans l'authentification par certificat.

### Authentification Secure Channel (Schannel)

Schannel facilite des connexions TLS/SSL sécurisées, où, lors d'un handshake, le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. L'appariement d'un certificat à un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat, parmi d'autres méthodes.

### Énumération des services de certificats AD

Les services de certificats d'AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **autorités de certification d'entreprise (CAs)** et leurs configurations. Ceci est accessible par tout utilisateur authentifié sur le domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation des vulnérabilités dans les environnements AD CS.

Les commandes pour utiliser ces outils incluent :
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
