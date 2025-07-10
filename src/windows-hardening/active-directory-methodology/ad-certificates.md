# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée pour lier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, marque la durée effective du certificat.
- Un **Serial Number** unique, fourni par l'Autorité de Certification (CA), identifie chaque certificat.
- L'**Issuer** fait référence à la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires pour le sujet, améliorant la flexibilité d'identification.
- **Basic Constraints** identifient si le certificat est destiné à une CA ou à une entité finale et définissent les restrictions d'utilisation.
- **Extended Key Usages (EKUs)** délimitent les objectifs spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, à travers des Identifiants d'Objet (OIDs).
- L'**Signature Algorithm** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'émetteur, garantit l'authenticité du certificat.

### Special Considerations

- Les **Subject Alternative Names (SANs)** étendent l'applicabilité d'un certificat à plusieurs identités, crucial pour les serveurs avec plusieurs domaines. Des processus d'émission sécurisés sont essentiels pour éviter les risques d'imitation par des attaquants manipulant la spécification SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS reconnaît les certificats CA dans une forêt AD à travers des conteneurs désignés, chacun ayant des rôles uniques :

- Le conteneur **Certification Authorities** contient des certificats CA racines de confiance.
- Le conteneur **Enrolment Services** détaille les CAs d'entreprise et leurs modèles de certificats.
- L'objet **NTAuthCertificates** inclut les certificats CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec des certificats CA intermédiaires et croisés.

### Certificate Acquisition: Client Certificate Request Flow

1. Le processus de demande commence par la recherche d'une CA d'entreprise par les clients.
2. Un CSR est créé, contenant une clé publique et d'autres détails, après la génération d'une paire de clés publique-privée.
3. La CA évalue le CSR par rapport aux modèles de certificats disponibles, émettant le certificat en fonction des autorisations du modèle.
4. Une fois approuvé, la CA signe le certificat avec sa clé privée et le renvoie au client.

### Certificate Templates

Définis dans AD, ces modèles décrivent les paramètres et les autorisations pour l'émission de certificats, y compris les EKUs autorisés et les droits d'inscription ou de modification, critiques pour la gestion de l'accès aux services de certificats.

## Certificate Enrollment

Le processus d'inscription pour les certificats est initié par un administrateur qui **crée un modèle de certificat**, qui est ensuite **publié** par une Autorité de Certification (CA) d'entreprise. Cela rend le modèle disponible pour l'inscription des clients, étape réalisée en ajoutant le nom du modèle au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client demande un certificat, des **droits d'inscription** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le modèle de certificat et la CA d'entreprise elle-même. Les autorisations doivent être accordées dans les deux emplacements pour qu'une demande soit réussie.

### Template Enrollment Rights

Ces droits sont spécifiés par des Entrées de Contrôle d'Accès (ACEs), détaillant des autorisations telles que :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, permettant toutes les autorisations étendues.
- **FullControl/GenericAll**, fournissant un contrôle total sur le modèle.

### Enterprise CA Enrollment Rights

Les droits de la CA sont décrits dans son descripteur de sécurité, accessible via la console de gestion de l'Autorité de Certification. Certains paramètres permettent même aux utilisateurs à faibles privilèges d'accéder à distance, ce qui pourrait poser un problème de sécurité.

### Additional Issuance Controls

Certaines contrôles peuvent s'appliquer, tels que :

- **Manager Approval** : Place les demandes dans un état en attente jusqu'à approbation par un gestionnaire de certificats.
- **Enrolment Agents and Authorized Signatures** : Spécifient le nombre de signatures requises sur un CSR et les OIDs de Politique d'Application nécessaires.

### Methods to Request Certificates

Les certificats peuvent être demandés via :

1. Le **Windows Client Certificate Enrollment Protocol** (MS-WCCE), utilisant des interfaces DCOM.
2. Le **ICertPassage Remote Protocol** (MS-ICPR), à travers des pipes nommés ou TCP/IP.
3. L'**interface web d'inscription de certificats**, avec le rôle d'Inscription Web de l'Autorité de Certification installé.
4. Le **Certificate Enrollment Service** (CES), en conjonction avec le service de Politique d'Inscription de Certificats (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les dispositifs réseau, utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande `Get-Certificate` de PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, utilisant principalement les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette demande subit plusieurs validations par le contrôleur de domaine, y compris la **validité** du certificat, le **chemin** et le **statut de révocation**. Les validations incluent également la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **magasin de certificats NTAUTH**. Des validations réussies entraînent l'émission d'un TGT. L'objet **`NTAuthCertificates`** dans AD, trouvé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est central pour établir la confiance pour l'authentification par certificat.

### Authentification Secure Channel (Schannel)

Schannel facilite les connexions TLS/SSL sécurisées, où, lors d'une poignée de main, le client présente un certificat qui, s'il est validé avec succès, autorise l'accès. La correspondance d'un certificat à un compte AD peut impliquer la fonction **S4U2Self** de Kerberos ou le **Subject Alternative Name (SAN)** du certificat, parmi d'autres méthodes.

### Énumération des Services de Certificat AD

Les services de certificat AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Autorités de Certification (CAs) d'Entreprise** et leurs configurations. Cela est accessible par tout utilisateur authentifié de domaine sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l'énumération et l'évaluation des vulnérabilités dans les environnements AD CS.

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
---

## Vulnérabilités récentes & mises à jour de sécurité (2022-2025)

| Année | ID / Nom | Impact | Points clés |
|-------|----------|--------|-------------|
| 2022  | **CVE-2022-26923** – “Certifried” / ESC6 | *Escalade de privilèges* en usurpant des certificats de compte machine lors de PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d'audit et de mappage strict ont été introduits via **KB5014754** ; les environnements devraient maintenant être en mode *Full Enforcement*. citeturn2search0 |
| 2023  | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoCs publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif à partir du **juillet 2023** Patch Tuesday. citeturn3search0 |
| 2024  | **CVE-2024-49019** – “EKUwu” / ESC15 | Les utilisateurs à faibles privilèges avec des droits d'inscription pouvaient remplacer **n'importe quel** EKU ou SAN lors de la génération de CSR, émettant des certificats utilisables pour l'authentification client ou la signature de code, menant à un *compromis de domaine*. | Résolu dans les mises à jour de **avril 2024**. Supprimez “Supply in the request” des modèles et restreignez les autorisations d'inscription. citeturn1search3 |

### Chronologie de durcissement de Microsoft (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibilité → Audit → Application) pour déplacer l'authentification par certificat Kerberos loin des mappages implicites faibles. À partir du **11 février 2025**, les contrôleurs de domaine passent automatiquement à **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n'est pas définie. Les administrateurs devraient :

1. Appliquer les correctifs à tous les DC et serveurs AD CS (mai 2022 ou ultérieur).
2. Surveiller l'ID d'événement 39/41 pour des mappages faibles pendant la phase *Audit*.
3. Réémettre des certificats d'authentification client avec la nouvelle **extension SID** ou configurer des mappages manuels stricts avant février 2025. citeturn2search0

---

## Améliorations de détection et de durcissement

* Le **capteur Defender for Identity AD CS (2023-2024)** affiche désormais des évaluations de posture pour ESC1-ESC8/ESC11 et génère des alertes en temps réel telles que *“Émission de certificat de contrôleur de domaine pour un non-DC”* (ESC8) et *“Prévenir l'inscription de certificat avec des politiques d'application arbitraires”* (ESC15). Assurez-vous que les capteurs sont déployés sur tous les serveurs AD CS pour bénéficier de ces détections. citeturn5search0
* Désactivez ou restreignez strictement l'option **“Supply in the request”** sur tous les modèles ; préférez des valeurs SAN/EKU explicitement définies.
* Supprimez **Any Purpose** ou **No EKU** des modèles sauf si absolument nécessaire (adresse les scénarios ESC2).
* Exigez **l'approbation du responsable** ou des flux de travail d'Agent d'inscription dédiés pour les modèles sensibles (par exemple, WebServer / CodeSigning).
* Restreignez l'inscription web (`certsrv`) et les points de terminaison CES/NDES aux réseaux de confiance ou derrière une authentification par certificat client.
* Appliquez le chiffrement d'inscription RPC (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`) pour atténuer l'ESC11.

---

## Références

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
