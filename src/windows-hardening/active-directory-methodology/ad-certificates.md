# Certificats AD

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d’un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée afin de relier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la période de validité du certificat.
- Un **Serial Number** unique, attribué par l’autorité de certification (CA), identifie chaque certificat.
- L’**Issuer** désigne la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d’ajouter des noms pour le sujet, afin de rendre son identification plus flexible.
- **Basic Constraints** indique si le certificat est destiné à une CA ou à une entité finale et définit les restrictions d’utilisation.
- **Extended Key Usages (EKUs)** définissent les usages spécifiques du certificat, comme la signature de code ou le chiffrement des e-mails, au moyen d’identifiants d’objet (OIDs).
- **Signature Algorithm** précise la méthode utilisée pour signer le certificat.
- La **Signature**, créée avec la clé privée de l’émetteur, garantit l’authenticité du certificat.<sup>[[4]](#references)</sup>

### Points particuliers

- Les **Subject Alternative Names (SANs)** étendent l’utilisation d’un certificat à plusieurs identités, ce qui est essentiel pour les serveurs hébergeant plusieurs domaines. Des processus d’émission sécurisés sont indispensables pour éviter les risques d’usurpation d’identité par des attaquants qui manipulent la spécification SAN.<sup>[[4]](#references)</sup>

### Autorités de certification (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats des CA dans une forêt AD au moyen de conteneurs dédiés, chacun ayant un rôle spécifique :<sup>[[4]](#references)</sup>

- Le conteneur **Certification Authorities** contient les certificats des CA racines de confiance.
- Le conteneur **Enrolment Services** répertorie les CA Enterprise et leurs modèles de certificats.
- L’objet **NTAuthCertificates** contient les certificats des CA autorisés pour l’authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats grâce aux certificats intermédiaires et aux certificats de CA croisées.

### Obtention d’un certificat : flux de demande de certificat client

1. Le processus de demande commence lorsque les clients recherchent une CA Enterprise.
2. Une CSR est créée après la génération d’une paire de clés publique-privée ; elle contient une clé publique et d’autres informations.
3. La CA évalue la CSR par rapport aux modèles de certificats disponibles et émet le certificat selon les autorisations définies dans le modèle.
4. Une fois la demande approuvée, la CA signe le certificat avec sa clé privée et le renvoie au client.<sup>[[4]](#references)</sup>

### Modèles de certificats

Définis dans AD, ces modèles précisent les paramètres et les autorisations applicables à l’émission des certificats, notamment les EKUs autorisés et les droits d’inscription ou de modification, qui sont essentiels à la gestion de l’accès aux services de certificats.<sup>[[4]](#references)</sup>

**La version du schéma du modèle est importante.** Les modèles **v1** hérités (par exemple, le modèle intégré **WebServer**) ne disposent pas de plusieurs contrôles modernes. Les recherches sur **ESC15/EKUwu** ont montré que, pour les modèles **v1**, un demandeur peut intégrer des **Application Policies/EKUs** dans la CSR, qui sont **privilégiées par rapport aux** EKUs configurés dans le modèle. Cela permet d’obtenir des certificats d’authentification client, d’agent d’inscription ou de signature de code avec de simples droits d’inscription. Privilégiez les modèles **v2/v3**, supprimez ou remplacez les modèles v1 par défaut et limitez strictement les EKUs à l’usage prévu.<sup>[[1]](#references)</sup>

## Inscription de certificats

Le processus d’inscription des certificats est lancé par un administrateur qui **crée un modèle de certificat**, lequel est ensuite **publié** par une autorité de certification Enterprise (CA). Le modèle devient ainsi disponible pour l’inscription des clients. Pour cela, son nom est ajouté au champ `certificatetemplates` d’un objet Active Directory.<sup>[[4]](#references)</sup>

Pour qu’un client puisse demander un certificat, il doit disposer de **droits d’inscription**. Ces droits sont définis par les descripteurs de sécurité du modèle de certificat et de la CA Enterprise elle-même. Les autorisations doivent être accordées aux deux emplacements pour que la demande aboutisse.

### Droits d’inscription au modèle

Ces droits sont définis au moyen d’entrées de contrôle d’accès (ACEs), qui précisent notamment les autorisations suivantes :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à un GUID spécifique.
- **ExtendedRights**, qui autorise toutes les autorisations étendues.
- **FullControl/GenericAll**, qui donne un contrôle total sur le modèle.

### Droits d’inscription auprès de la CA Enterprise

Les droits de la CA sont définis dans son descripteur de sécurité, accessible depuis la console de gestion Certificate Authority. Certains paramètres permettent même aux utilisateurs disposant de faibles privilèges d’y accéder à distance, ce qui peut présenter un risque de sécurité.

### Contrôles d’émission supplémentaires

Certains contrôles peuvent s’appliquer, notamment :

- **Manager Approval** : place les demandes en attente jusqu’à leur approbation par un gestionnaire de certificats.
- **Enrolment Agents and Authorized Signatures** : précisent le nombre de signatures requises sur une CSR et les OIDs d’Application Policy nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés par les moyens suivants :

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), via des interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via des canaux nommés ou TCP/IP.
3. L’**interface web d’inscription des certificats**, lorsque le rôle Certificate Authority Web Enrollment est installé.
4. Le **Certificate Enrollment Service** (CES), associé au service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES), destiné aux équipements réseau et utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats depuis l’interface graphique (`certmgr.msc` ou `certlm.msc`) ou à l’aide d’outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Authentification par certificat

Active Directory (AD) prend en charge l’authentification par certificat, principalement à l’aide des protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d’authentification Kerberos

Dans le processus d’authentification Kerberos, la demande d’un utilisateur pour obtenir un Ticket Granting Ticket (TGT) est signée à l’aide de la **clé privée** du certificat de l’utilisateur. Cette demande fait l’objet de plusieurs validations par le contrôleur de domaine, notamment la **validité**, le **chemin** et le statut de **révocation** du certificat. Les validations comprennent également la vérification que le certificat provient d’une source approuvée et la confirmation de la présence de l’émetteur dans le **magasin de certificats NTAUTH**. Si les validations réussissent, un TGT est émis. L’objet **`NTAuthCertificates`** dans AD, situé à :

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

est essentiel pour établir la confiance lors de l’authentification par certificat.<sup>[[4]](#references)</sup>

Depuis le déploiement de **KB5014754**, l’authentification Kerberos moderne par certificat dépend surtout de la **force du mapping**, et pas seulement des EKU.<sup>[[2]](#references)</sup> Dans les forêts renforcées :

- Un certificat qui ne contient qu’un **SAN UPN/DNS** peut ne plus suffire pour l’ouverture de session.
- Le KDC privilégie une **liaison forte**, généralement l’**extension de sécurité SID** (`1.3.6.1.4.1.311.25.2`) ou un mapping explicite fort dans `altSecurityIdentities`.
- Si le certificat ne comporte pas de mapping fort, les contrôleurs de domaine consignent **Kdcsvc Event ID 39/41** en mode de compatibilité et refusent l’authentification en mode d’application.
- Dans les chaînes d’attaque mixtes, **ESC9/ESC16** sont importants, car ils retirent l’extension SID des certificats émis ; les opérateurs s’appuient alors sur des mappings explicites ou des formats SID d’URL SAN lorsque la chaîne d’attaque le permet.

### Authentification par canal sécurisé (Schannel)

Schannel permet d’établir des connexions TLS/SSL sécurisées. Lors de la négociation, le client présente un certificat qui, s’il est validé avec succès, autorise l’accès. Le mapping d’un certificat vers un compte AD peut faire appel à la fonction **S4U2Self** de Kerberos ou au **Subject Alternative Name (SAN)** du certificat, entre autres méthodes.<sup>[[4]](#references)</sup>

Schannel constitue également une solution de repli pratique lorsque **PKINIT** n’est pas disponible. Par exemple, si un contrôleur de domaine ne possède pas de certificat **Smart Card Logon** adapté, `certipy auth`/les outils PKINIT peuvent échouer à obtenir un TGT, mais le même certificat peut tout de même être utilisable auprès de **LDAPS** ou de **LDAP StartTLS** pour l’authentification et les opérations LDAP.

### Énumération des services de certificats AD

Les services de certificats AD peuvent être énumérés au moyen de requêtes LDAP, qui révèlent des informations sur les **Enterprise Certificate Authorities (CA)** et leurs configurations. Tout utilisateur authentifié du domaine peut y accéder sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** servent à l’énumération et à l’évaluation des vulnérabilités dans les environnements AD CS.

Voici des commandes pour utiliser ces outils :

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

| Année | ID / Nom | Impact | Points clés à retenir |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – « Certifried » / ESC6 | *Élévation de privilèges* par usurpation de certificats de comptes machine lors de PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d’audit et de mappage fort ont été introduits avec **KB5014754** ; les environnements devraient désormais être en mode *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Appliquez le correctif publié lors du Patch Tuesday de **juillet 2023**.  |
| 2024 | **CVE-2024-49019** – « EKUwu » / ESC15 | Sur les **modèles v1**, un demandeur disposant de droits d’inscription peut intégrer des **Application Policies/EKUs** dans la CSR, qui prévalent sur les EKU du modèle et permettent d’obtenir des certificats d’authentification client, d’agent d’inscription ou de signature de code. | Corrigé depuis le **12 novembre 2024**. Remplacez ou faites superséder les modèles v1 (par exemple, le modèle WebServer par défaut), limitez les EKU à leur usage prévu et restreignez les droits d’inscription. |

### Calendrier de renforcement de Microsoft (KB5014754)

Microsoft a mis en place un déploiement en trois phases (Compatibility → Audit → Enforcement) afin d’abandonner les mappages implicites faibles pour l’authentification par certificat Kerberos. Depuis le **11 février 2025**, les contrôleurs de domaine passent automatiquement en mode **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n’est pas définie. Microsoft a ensuite mis à jour le calendrier afin que le retour au mode de compatibilité reste possible jusqu’à la mise à jour de sécurité du **9 septembre 2025**.<sup>[[2]](#references)</sup> Les administrateurs doivent :

1. Appliquer les correctifs à tous les DC et serveurs AD CS (mai 2022 ou version ultérieure).
2. Surveiller les événements ID 39/41 pour détecter les mappages faibles pendant la phase *Audit*.
3. Réémettre les certificats d’authentification client avec la nouvelle **extension SID** ou configurer des mappages manuels forts avant que l’application du mode Enforcement ne bloque les mappages faibles.

### Notes opérateur pour les forêts renforcées

- **ESC1/ESC6 ne suffisent plus à eux seuls** dans les environnements 2025 et ultérieurs. Si vous demandez un certificat pour un autre principal, vous avez généralement aussi besoin d’un élément de mappage fort, comme l’extension SID ou un mappage explicite.
- **ESC15 (EKUwu)** est surtout utile dans les environnements non corrigés, car il transforme des modèles **v1** inoffensifs tels que **WebServer** en certificats capables d’authentification ou d’agir comme agents d’inscription en injectant des **Application Policies**. Kerberos PKINIT évalue toujours les EKU, mais **LDAP Schannel** prend également en compte les Application Policies, ce qui maintient la pertinence des abus basés sur LDAP.<sup>[[1]](#references)</sup>
- **ESC16** est un paramètre à l’échelle de l’AC : si l’AC désactive globalement l’extension de sécurité SID, tous les certificats émis adoptent un comportement de mappage plus faible, à moins que la chaîne d’attaque n’injecte un SID dans un autre format pris en charge.
- **Les droits ESC7 sont distincts :** une autorisation `ManageCA` sur une AC peut permettre de modifier des paramètres tels que `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), tandis que `ManageCertificates` régit l’approbation des demandes. Un refus explicite des droits de gestion des certificats peut bloquer cette voie d’approbation même si une autorisation est également présente ; évaluez les ACL effectives de l’AC avant de combiner paramètres et modèles. Consultez [l’évaluation des ACL d’AC de Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Améliorations de la détection et du renforcement

* Le **capteur AD CS de Defender for Identity (2023-2024)** affiche désormais des évaluations de la posture de sécurité pour ESC1-ESC8/ESC11 et génère des alertes en temps réel, telles que *« Émission d’un certificat de contrôleur de domaine pour un système qui n’est pas un DC »* (ESC8) et *« Empêcher l’inscription de certificats avec des Application Policies arbitraires »* (ESC15). Déployez les capteurs sur tous les serveurs AD CS pour bénéficier de ces détections.<sup>[[3]](#references)</sup>
* Désactivez ou limitez strictement l’option **« Supply in the request »** sur tous les modèles ; privilégiez les valeurs SAN/EKU explicitement définies.
* Supprimez **Any Purpose** ou **No EKU** des modèles, sauf nécessité absolue (cela traite les scénarios ESC2).
* Exigez l’**approbation d’un responsable** ou des workflows dédiés d’Enrollment Agent pour les modèles sensibles (par exemple, WebServer / CodeSigning).
* Limitez l’accès à l’inscription Web (`certsrv`) et aux points de terminaison CES/NDES aux réseaux de confiance ou protégez-les par une authentification avec certificat client.
* Imposez le chiffrement de l’inscription RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) afin d’atténuer ESC11 (relais RPC). Le paramètre est **activé par défaut**, mais il est souvent désactivé pour les clients anciens, ce qui réintroduit le risque de relais.
* Sécurisez les **points de terminaison d’inscription basés sur IIS** (CES/Certsrv) : désactivez NTLM lorsque c’est possible ou exigez HTTPS + Extended Protection pour bloquer les relais ESC8.

Évaluez ESC11 sur l’hôte qui exécute l’AC, lequel peut être un serveur membre du domaine plutôt qu’un contrôleur de domaine. Lisez la valeur `InterfaceFlags` de l’AC active sous `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` ; une valeur illisible ou manquante indique un résultat inconnu, et non une preuve que le chiffrement RPC est désactivé. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` désactivé est une piste de configuration qui nécessite encore un point de terminaison RPC d’inscription accessible, des identifiants dont l’utilisation peut être contrainte et un modèle de certificat exploitable. Pour ESC8, un défi HTTP NTLM à lui seul ne suffit pas : vérifiez qu’un point de terminaison d’inscription fonctionnel est disponible.

---

## References

- [1] [EKUwu : pas simplement un autre ESC AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754 : modifications de l’authentification par certificat sur les contrôleurs de domaine Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Évaluations de la posture de sécurité des certificats - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned : abus des services de certificats Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
