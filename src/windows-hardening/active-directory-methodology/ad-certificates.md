# Certificats AD

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé privée afin de relier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité du certificat.
- Un **Serial Number** unique, attribué par l'autorité de certification (CA), identifie chaque certificat.
- L'**Issuer** désigne la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'associer des noms supplémentaires au sujet, offrant ainsi davantage de souplesse pour l'identification.
- **Basic Constraints** indique si le certificat est destiné à une CA ou à une entité finale, et définit les restrictions d'utilisation.
- **Extended Key Usages (EKUs)** précisent les usages du certificat, comme la signature de code ou le chiffrement des e-mails, au moyen d'identifiants d'objet (OIDs).
- Le **Signature Algorithm** spécifie la méthode utilisée pour signer le certificat.
- La **Signature**, créée avec la clé privée de l'émetteur, garantit l'authenticité du certificat.<sup>[[4]](#references)</sup>

### Considérations particulières

- Les **Subject Alternative Names (SANs)** étendent l'utilisation d'un certificat à plusieurs identités, ce qui est essentiel pour les serveurs associés à plusieurs domaines. Des processus d'émission sécurisés sont indispensables pour éviter les risques d'usurpation d'identité par des attaquants qui manipulent la spécification SAN.<sup>[[4]](#references)</sup>

### Autorités de certification (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD au moyen de conteneurs dédiés, chacun ayant un rôle spécifique :<sup>[[4]](#references)</sup>

- Le conteneur **Certification Authorities** contient les certificats des CA racines approuvées.
- Le conteneur **Enrolment Services** répertorie les CAs d'entreprise et leurs modèles de certificats.
- L'objet **NTAuthCertificates** contient les certificats de CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats au moyen de certificats intermédiaires et de CA croisées.

### Obtention d'un certificat : flux de demande de certificat client

1. Le processus de demande commence par la recherche d'une CA d'entreprise par le client.
2. Après la génération d'une paire de clés publique-privée, un CSR est créé. Il contient une clé publique et d'autres informations.
3. La CA évalue le CSR par rapport aux modèles de certificats disponibles et émet le certificat selon les autorisations du modèle.
4. Après approbation, la CA signe le certificat avec sa clé privée et le renvoie au client.<sup>[[4]](#references)</sup>

### Modèles de certificats

Définis dans AD, ces modèles précisent les paramètres et les autorisations d'émission des certificats, notamment les EKUs autorisés et les droits d'inscription ou de modification. Ils sont essentiels à la gestion de l'accès aux services de certificats.<sup>[[4]](#references)</sup>

**La version du schéma du modèle est importante.** Les anciens modèles **v1** (par exemple, le modèle intégré **WebServer**) ne disposent pas de plusieurs mécanismes modernes d'application des règles. Les recherches sur **ESC15/EKUwu** ont montré qu'avec les **modèles v1**, un demandeur peut intégrer des **Application Policies/EKUs** dans le CSR, qui sont **prioritaires sur** les EKUs configurés dans le modèle. Cela permet d'obtenir des certificats d'authentification client, d'agent d'inscription ou de signature de code avec de simples droits d'inscription. Privilégiez les modèles **v2/v3**, supprimez ou remplacez les modèles v1 par défaut et limitez strictement les EKUs à l'usage prévu.<sup>[[1]](#references)</sup>

## Inscription aux certificats

Le processus d'inscription aux certificats est lancé par un administrateur qui **crée un modèle de certificat**, ensuite **publié** par une autorité de certification (CA) d'entreprise. Le modèle devient alors disponible pour l'inscription des clients. Pour cela, son nom est ajouté au champ `certificatetemplates` d'un objet Active Directory.<sup>[[4]](#references)</sup>

Pour qu'un client puisse demander un certificat, il doit disposer de **droits d'inscription**. Ces droits sont définis par des descripteurs de sécurité sur le modèle de certificat et sur la CA d'entreprise elle-même. Les autorisations doivent être accordées aux deux emplacements pour que la demande aboutisse.

### Droits d'inscription au modèle

Ces droits sont spécifiés au moyen d'entrées de contrôle d'accès (ACEs), qui définissent des autorisations telles que :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, qui accorde toutes les autorisations étendues.
- **FullControl/GenericAll**, qui donne un contrôle complet sur le modèle.

### Droits d'inscription auprès d'une CA d'entreprise

Les droits de la CA sont définis dans son descripteur de sécurité, accessible depuis la console de gestion de l'autorité de certification. Certains paramètres permettent même aux utilisateurs disposant de faibles privilèges d'y accéder à distance, ce qui peut poser un problème de sécurité.

### Contrôles supplémentaires à l'émission

Certains contrôles peuvent s'appliquer, notamment :

- **Manager Approval** : place les demandes en attente jusqu'à leur approbation par un gestionnaire de certificats.
- **Enrolment Agents and Authorized Signatures** : spécifie le nombre de signatures requises sur un CSR ainsi que les OIDs d'Application Policy nécessaires.

### Méthodes de demande de certificats

Les certificats peuvent être demandés par les moyens suivants :

1. Le **Windows Client Certificate Enrollment Protocol** (MS-WCCE), à l'aide d'interfaces DCOM.
2. Le **ICertPassage Remote Protocol** (MS-ICPR), via des canaux nommés ou TCP/IP.
3. L'**interface web d'inscription aux certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), associé au service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES), pour les appareils réseau, à l'aide du Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats depuis l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou à l'aide d'outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Authentification par certificat

Active Directory (AD) prend en charge l’authentification par certificat, principalement au moyen des protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d’authentification Kerberos

Dans le processus d’authentification Kerberos, la requête d’un utilisateur pour obtenir un Ticket Granting Ticket (TGT) est signée à l’aide de la **clé privée** du certificat de l’utilisateur. Cette requête est soumise à plusieurs validations par le contrôleur de domaine, notamment celles de la **validité**, de la **chaîne** et du **statut de révocation** du certificat. Les validations consistent également à vérifier que le certificat provient d’une source de confiance et à confirmer la présence de l’émetteur dans le **magasin de certificats NTAUTH**. Si les validations réussissent, un TGT est émis. L’objet **`NTAuthCertificates`** dans AD se trouve à :

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

est essentiel pour établir la confiance lors de l’authentification par certificat.<sup>[[4]](#references)</sup>

Depuis le déploiement de **KB5014754**, l’authentification moderne par certificat Kerberos repose surtout sur la **robustesse du mapping**, et pas seulement sur les EKU.<sup>[[2]](#references)</sup> Dans les forêts renforcées :

- Un certificat qui ne contient qu’un **UPN/DNS SAN** peut ne plus suffire pour l’ouverture de session.
- Le KDC privilégie une **liaison forte**, généralement l’**extension de sécurité SID** (`1.3.6.1.4.1.311.25.2`) ou un mapping explicite fort dans `altSecurityIdentities`.
- Si le certificat ne comporte pas de mapping fort, les DC enregistrent **Kdcsvc Event ID 39/41** en mode de compatibilité et refusent l’authentification en mode d’application.
- Dans les chemins d’attaque mixtes, **ESC9/ESC16** sont importants, car ils suppriment l’extension SID des certificats émis ; les opérateurs s’appuient alors sur des mappings explicites ou des formats SID d’URL SAN lorsque le chemin d’attaque le permet.

### Authentification Secure Channel (Schannel)

Schannel permet d’établir des connexions TLS/SSL sécurisées. Lors d’une négociation, le client présente un certificat qui, s’il est validé, autorise l’accès. Le mapping d’un certificat vers un compte AD peut faire appel à la fonction **S4U2Self** de Kerberos ou au **Subject Alternative Name (SAN)** du certificat, entre autres méthodes.<sup>[[4]](#references)</sup>

Schannel constitue également la solution de repli pratique lorsque **PKINIT** n’est pas disponible. Par exemple, si un contrôleur de domaine ne possède pas de certificat **Smart Card Logon** adapté, les outils `certipy auth`/PKINIT peuvent échouer à obtenir un TGT, mais le même certificat peut tout de même être utilisable auprès de **LDAPS** ou de **LDAP StartTLS** pour l’authentification et les opérations LDAP.

### Énumération des services de certificats AD

Les services de certificats d’AD peuvent être énumérés à l’aide de requêtes LDAP, qui révèlent des informations sur les **Autorités de certification (CA) d’entreprise** et leur configuration. Tout utilisateur authentifié sur le domaine peut y accéder sans privilèges particuliers. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** servent à l’énumération et à l’évaluation des vulnérabilités dans les environnements AD CS.

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
| 2022 | **CVE-2022-26923** – « Certifried » / ESC6 | *Élévation de privilèges* par usurpation de certificats de comptes machine pendant PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d’audit et de strong mapping ont été introduits via **KB5014754** ; les environnements devraient désormais être en mode *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif disponible depuis le Patch Tuesday de **juillet 2023**.  |
| 2024 | **CVE-2024-49019** – « EKUwu » / ESC15 | Sur les **templates v1**, un demandeur disposant des droits d’enrollment peut intégrer des **Application Policies/EKUs** dans le CSR, qui prévalent sur les EKU du template et produisent des certificats d’authentification client, d’Enrollment Agent ou de signature de code. | Corrigé depuis le **12 novembre 2024**. Remplacez ou remplacez par une version plus récente les templates v1 (p. ex., WebServer par défaut), limitez les EKU à leur usage prévu et restreignez les droits d’enrollment. |

### Calendrier de renforcement de Microsoft (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibility → Audit → Enforcement) pour éloigner l’authentification par certificat Kerberos des mappings implicites faibles. Depuis le **11 février 2025**, les contrôleurs de domaine passent automatiquement en mode **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n’est pas définie. Microsoft a ensuite mis à jour le calendrier afin de permettre le retour au mode Compatibility jusqu’à la mise à jour de sécurité du **9 septembre 2025**.<sup>[[2]](#references)</sup> Les administrateurs doivent :

1. Appliquer les correctifs à tous les DC et serveurs AD CS (mai 2022 ou version ultérieure).
2. Surveiller les événements ID 39/41 pour repérer les mappings faibles pendant la phase *Audit*.
3. Réémettre les certificats d’authentification client avec la nouvelle **extension SID**, ou configurer des mappings manuels forts avant que l’application des règles ne bloque les mappings faibles.

### Notes pour les opérateurs de forêts renforcées

- **ESC1/ESC6 ne suffisent plus à eux seuls** dans les environnements 2025+. Si vous demandez un certificat pour un autre principal, vous avez généralement aussi besoin d’un artefact de mapping fort, comme l’extension SID ou un mapping explicite.
- **ESC15 (EKUwu)** est surtout utile dans les environnements non corrigés, car il transforme des templates **v1** inoffensifs comme **WebServer** en certificats compatibles avec l’authentification ou le rôle Enrollment Agent, en injectant des **Application Policies**. Kerberos PKINIT évalue toujours les EKU, mais **LDAP Schannel** tient également compte des Application Policies, ce qui maintient la pertinence des attaques basées sur LDAP.<sup>[[1]](#references)</sup>
- **ESC16** est un paramètre à l’échelle de la CA : si la CA désactive globalement l’extension de sécurité SID, tous les certificats émis retombent vers un comportement de mapping plus faible, sauf si la chaîne d’attaque injecte un SID dans un autre format pris en charge.
- **Les droits ESC7 sont distincts :** une attribution `ManageCA` sur une CA peut permettre de modifier des paramètres tels que `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), tandis que `ManageCertificates` régit l’approbation des demandes. Un refus explicite des droits de gestion des certificats peut bloquer cette voie d’approbation, même si une autorisation est également présente ; évaluez l’ACL effective de la CA avant de combiner paramètres et templates. Voir [l’évaluation des ACL de CA de Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Améliorations de la détection et du renforcement

* Le **capteur AD CS de Defender for Identity (2023-2024)** présente désormais des évaluations de posture pour ESC1-ESC8/ESC11 et génère des alertes en temps réel, comme *« Émission d’un certificat de contrôleur de domaine pour un hôte qui n’est pas un contrôleur de domaine »* (ESC8) et *« Empêcher l’enrollment de certificats avec des Application Policies arbitraires »* (ESC15). Déployez des capteurs sur tous les serveurs AD CS pour bénéficier de ces détections.<sup>[[3]](#references)</sup>
* Désactivez l’option **« Supply in the request »** sur tous les templates ou limitez-la strictement ; privilégiez des valeurs SAN/EKU définies explicitement.
* Supprimez **Any Purpose** ou **No EKU** des templates, sauf nécessité absolue (répond aux scénarios ESC2).
* Exigez l’**approbation d’un responsable** ou des workflows dédiés d’Enrollment Agent pour les templates sensibles (p. ex., WebServer / CodeSigning).
* Limitez les points de terminaison web enrollment (`certsrv`) et CES/NDES aux réseaux de confiance ou placez-les derrière une authentification par certificat client.
* Appliquez le chiffrement RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) pour atténuer ESC11 (relais RPC). L’indicateur est **activé par défaut**, mais souvent désactivé pour les clients anciens, ce qui réintroduit le risque de relais.
* Sécurisez les **points de terminaison d’enrollment basés sur IIS** (CES/Certsrv) : désactivez NTLM lorsque c’est possible, ou exigez HTTPS + Extended Protection pour bloquer les relais ESC8.

Évaluez ESC11 sur l’hôte exécutant la CA, qui peut être un serveur membre du domaine plutôt qu’un contrôleur de domaine. Consultez `InterfaceFlags` pour la CA active sous `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` ; une valeur illisible ou manquante indique un résultat inconnu, et ne prouve pas que le chiffrement RPC est désactivé. Un bit `IF_ENFORCEENCRYPTICERTREQUEST` à zéro est une piste de configuration qui nécessite toujours un point de terminaison RPC enrollment accessible, des identifiants dont l’utilisation peut être forcée et un template de certificat exploitable. Pour ESC8, un défi HTTP NTLM ne suffit pas à lui seul : confirmez qu’un point de terminaison enrollment fonctionnel existe.

---

## References

- [1] [EKUwu : pas seulement un autre ESC AD CS](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754 : modifications de l’authentification basée sur les certificats sur les contrôleurs de domaine Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Évaluations de la posture de sécurité des certificats - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned : abus des services de certificats Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
