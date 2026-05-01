# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Composants d'un certificat

- Le **Subject** du certificat désigne son propriétaire.
- Une **Public Key** est associée à une clé détenue en privé afin de relier le certificat à son propriétaire légitime.
- La **Validity Period**, définie par les dates **NotBefore** et **NotAfter**, indique la durée de validité effective du certificat.
- Un **Serial Number** unique, fourni par la Certificate Authority (CA), identifie chaque certificat.
- L'**Issuer** désigne la CA qui a émis le certificat.
- **SubjectAlternativeName** permet d'ajouter des noms supplémentaires pour le subject, améliorant la flexibilité de l'identification.
- **Basic Constraints** identifient si le certificat est destiné à une CA ou à une entité finale et définissent les restrictions d'usage.
- **Extended Key Usages (EKUs)** délimitent les usages spécifiques du certificat, comme le code signing ou le chiffrement d'e-mail, via des Object Identifiers (OIDs).
- L'**Signature Algorithm** spécifie la méthode de signature du certificat.
- La **Signature**, créée avec la clé privée de l'issuer, garantit l'authenticité du certificat.

### Considérations spéciales

- **Subject Alternative Names (SANs)** étendent l'applicabilité d'un certificat à plusieurs identités, ce qui est crucial pour les serveurs ayant plusieurs domaines. Des processus d'émission sécurisés sont essentiels pour éviter les risques d'usurpation par des attaquants manipulant la spécification SAN.

### Certificate Authorities (CAs) dans Active Directory (AD)

AD CS reconnaît les certificats de CA dans une forêt AD via des conteneurs dédiés, chacun ayant un rôle spécifique :

- Le conteneur **Certification Authorities** contient les certificats racine de CA approuvés.
- Le conteneur **Enrolment Services** détaille les Enterprise CAs et leurs certificate templates.
- L'objet **NTAuthCertificates** inclut les certificats de CA autorisés pour l'authentification AD.
- Le conteneur **AIA (Authority Information Access)** facilite la validation de la chaîne de certificats avec des certificats intermédiaires et cross CA.

### Acquisition de certificat : flux de demande de certificat client

1. Le processus de demande commence lorsque les clients trouvent une Enterprise CA.
2. Un CSR est créé, contenant une Public Key et d'autres détails, après la génération d'une paire de clés public-privé.
3. La CA évalue le CSR par rapport aux certificate templates disponibles et émet le certificat en fonction des permissions du template.
4. Une fois approuvé, la CA signe le certificat avec sa clé privée et le renvoie au client.

### Certificate Templates

Définis dans AD, ces templates décrivent les paramètres et les permissions pour l'émission de certificats, y compris les EKUs autorisés et les droits d'enrollment ou de modification, essentiels pour gérer l'accès aux services de certificats.

**Template schema version matters.** Les templates hérités **v1** (par exemple, le template **WebServer** intégré) ne disposent pas de plusieurs mécanismes modernes de contrôle. La recherche **ESC15/EKUwu** a montré que sur les **v1 templates**, un demandeur peut intégrer des **Application Policies/EKUs** dans le CSR qui sont **préférés par rapport** aux EKUs configurés dans le template, ce qui permet d'obtenir des certificats client-auth, enrollment agent ou code-signing avec de simples droits d'enrollment. Préférez les **v2/v3 templates**, supprimez ou remplacez les valeurs par défaut v1, et limitez strictement les EKUs à l'usage prévu.

## Certificate Enrollment

Le processus d'enrollment pour les certificats est initié par un administrateur qui **crée un certificate template**, lequel est ensuite **publié** par une Enterprise Certificate Authority (CA). Cela rend le template disponible pour l'enrollment client, une étape réalisée en ajoutant le nom du template au champ `certificatetemplates` d'un objet Active Directory.

Pour qu'un client puisse demander un certificat, des **enrollment rights** doivent être accordés. Ces droits sont définis par des descripteurs de sécurité sur le certificate template et sur l'Enterprise CA elle-même. Les permissions doivent être accordées aux deux emplacements pour qu'une demande aboutisse.

### Template Enrollment Rights

Ces droits sont spécifiés au moyen d'Access Control Entries (ACEs), détaillant des permissions comme :

- Les droits **Certificate-Enrollment** et **Certificate-AutoEnrollment**, chacun associé à des GUID spécifiques.
- **ExtendedRights**, permettant toutes les permissions étendues.
- **FullControl/GenericAll**, offrant un contrôle complet sur le template.

### Enterprise CA Enrollment Rights

Les droits de la CA sont décrits dans son descripteur de sécurité, accessible via la console de gestion Certificate Authority. Certains paramètres permettent même à des utilisateurs à faible privilège un accès à distance, ce qui peut représenter un risque de sécurité.

### Contrôles d'émission supplémentaires

Certains contrôles peuvent s'appliquer, tels que :

- **Manager Approval** : place les demandes dans un état en attente jusqu'à leur approbation par un certificate manager.
- **Enrolment Agents and Authorized Signatures** : spécifie le nombre de signatures requises sur un CSR et les Application Policy OIDs nécessaires.

### Méthodes pour demander des certificats

Les certificats peuvent être demandés via :

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), en utilisant des interfaces DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), via des named pipes ou TCP/IP.
3. L'**interface web d'enrollment de certificats**, avec le rôle Certificate Authority Web Enrollment installé.
4. Le **Certificate Enrollment Service** (CES), en conjonction avec le service Certificate Enrollment Policy (CEP).
5. Le **Network Device Enrollment Service** (NDES) pour les périphériques réseau, en utilisant le Simple Certificate Enrollment Protocol (SCEP).

Les utilisateurs Windows peuvent également demander des certificats via l'interface graphique (`certmgr.msc` ou `certlm.msc`) ou des outils en ligne de commande (`certreq.exe` ou la commande PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Authentification par certificat

Active Directory (AD) prend en charge l'authentification par certificat, en s'appuyant principalement sur les protocoles **Kerberos** et **Secure Channel (Schannel)**.

### Processus d'authentification Kerberos

Dans le processus d'authentification Kerberos, la demande d'un utilisateur pour un Ticket Granting Ticket (TGT) est signée à l'aide de la **clé privée** du certificat de l'utilisateur. Cette demande subit plusieurs validations par le contrôleur de domaine, notamment la **validité**, le **chemin** et l'état de **révocation** du certificat. Les validations incluent également la vérification que le certificat provient d'une source de confiance et la confirmation de la présence de l'émetteur dans le **NTAUTH certificate store**. Si les validations réussissent, un TGT est émis. L'objet **`NTAuthCertificates`** dans AD, situé à :
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
est au cœur de l’établissement de la confiance pour l’authentification par certificat.

Depuis le déploiement de **KB5014754**, l’authentification Kerberos moderne par certificat concerne surtout la **mapping strength**, pas seulement les EKUs. Dans les forêts durcies :

- Un certificat qui ne contient qu’un **UPN/DNS SAN** peut ne plus suffire pour la connexion.
- Le KDC privilégie un **strong binding**, généralement la **SID security extension** (`1.3.6.1.4.1.311.25.2`) ou un mapping explicite fort dans `altSecurityIdentities`.
- Si le certificat n’a pas de mapping fort, les DC consignent **Kdcsvc Event ID 39/41** en mode compatibilité et refusent l’authentification en mode enforcement.
- Dans les chemins d’attaque mixtes, **ESC9/ESC16** comptent parce qu’ils retirent l’extension SID des certificats émis ; les opérateurs s’appuient alors sur des mappings explicites ou sur des formats SAN URL SID lorsque le chemin d’attaque les prend en charge.

### Secure Channel (Schannel) Authentication

Schannel facilite les connexions TLS/SSL sécurisées, où, pendant un handshake, le client présente un certificat qui, s’il est validé avec succès, autorise l’accès. Le mapping d’un certificat vers un compte AD peut impliquer la fonction Kerberos **S4U2Self** ou le **Subject Alternative Name (SAN)** du certificat, entre autres méthodes.

Schannel est aussi le repli pratique lorsque **PKINIT** n’est pas disponible. Par exemple, si un domain controller n’a pas de certificat **Smart Card Logon** approprié, `certipy auth`/les outils PKINIT peuvent échouer à obtenir un TGT, mais le même certificat peut encore être utilisable contre **LDAPS** ou **LDAP StartTLS** pour l’authentification et les opérations LDAP.

### AD Certificate Services Enumeration

Les certificate services d’AD peuvent être énumérés via des requêtes LDAP, révélant des informations sur les **Enterprise Certificate Authorities (CAs)** et leurs configurations. Cela est accessible à tout utilisateur authentifié dans le domain, sans privilèges spéciaux. Des outils comme **[Certify](https://github.com/GhostPack/Certify)** et **[Certipy](https://github.com/ly4k/Certipy)** sont utilisés pour l’énumération et l’évaluation des vulnérabilités dans les environnements AD CS.

Les commandes pour utiliser ces outils incluent :
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

## Vulnérabilités récentes & mises à jour de sécurité (2022-2025)

| Année | ID / Nom | Impact | Points clés |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Élévation de privilèges* par usurpation de certificats de compte machine durant PKINIT. | Le correctif est inclus dans les mises à jour de sécurité du **10 mai 2022**. Des contrôles d’audit & de strong-mapping ont été introduits via **KB5014754** ; les environnements doivent désormais être en mode *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Exécution de code à distance* dans les rôles AD CS Web Enrollment (certsrv) et CES. | Les PoC publics sont limités, mais les composants IIS vulnérables sont souvent exposés en interne. Correctif à partir du Patch Tuesday de **juillet 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Sur les **v1 templates**, un demandeur disposant des droits d’enrollment peut intégrer des **Application Policies/EKUs** dans le CSR, qui sont prioritaires sur les EKU du template, produisant des certificats client-auth, enrollment agent ou code-signing. | Corrigé au **12 novembre 2024**. Remplacez ou supprimez les v1 templates (par ex. le WebServer par défaut), limitez les EKU à l’usage prévu et restreignez les droits d’enrollment. |

### Chronologie de durcissement Microsoft (KB5014754)

Microsoft a introduit un déploiement en trois phases (Compatibility → Audit → Enforcement) pour éloigner l’authentification Kerberos par certificat des mappings implicites faibles. Au **11 février 2025**, les contrôleurs de domaine basculent automatiquement en **Full Enforcement** si la valeur de registre `StrongCertificateBindingEnforcement` n’est pas définie. Microsoft a ensuite mis à jour la chronologie afin que le retour au mode compatibility reste possible jusqu’à la mise à jour de sécurité du **9 septembre 2025**. Les administrateurs doivent :

1. Patcher tous les DCs & serveurs AD CS (mai 2022 ou plus récent).
2. Surveiller les Event ID 39/41 pour les mappings faibles pendant la phase *Audit*.
3. Réémettre les certificats client-auth avec la nouvelle **SID extension** ou configurer des strong manual mappings avant que l’application du contrôle ne bloque les mappings faibles.

### Notes opérateur pour les forêts durcies

- **ESC1/ESC6 seuls ne racontent plus toute l’histoire** dans les environnements 2025+. Si vous demandez un cert pour un autre principal, vous avez généralement aussi besoin d’un artefact de strong mapping comme la SID extension ou d’un mapping explicite.
- **ESC15 (EKUwu)** est surtout utile dans les environnements non patchés, car il transforme des templates **v1** sans danger comme **WebServer** en certs capables d’authentification ou d’enrollment agent en injectant des **Application Policies**. Kerberos PKINIT évalue toujours les EKU, mais **LDAP Schannel** prend aussi en compte les Application Policies, ce qui maintient la pertinence des abus via LDAP.
- **ESC16** est un réglage global de la CA : si la CA désactive l’extension de sécurité SID au niveau global, chaque certificat émis retombe vers un comportement de mapping plus faible, sauf si la chaîne d’attaque injecte un SID via un autre format pris en charge.

---

## Améliorations de détection & de durcissement

* Le **Defender for Identity AD CS sensor (2023-2024)** affiche désormais des évaluations de posture pour ESC1-ESC8/ESC11 et génère des alertes en temps réel telles que *“Domain-controller certificate issuance for a non-DC”* (ESC8) et *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Assurez-vous que les capteurs sont déployés sur tous les serveurs AD CS pour bénéficier de ces détections.
* Désactivez ou limitez strictement l’option **“Supply in the request”** sur tous les templates ; privilégiez des valeurs SAN/EKU définies explicitement.
* Supprimez **Any Purpose** ou **No EKU** des templates sauf si c’est absolument nécessaire (cela couvre les scénarios ESC2).
* Exigez une **approbation du manager** ou des workflows Enrollment Agent dédiés pour les templates sensibles (par ex. WebServer / CodeSigning).
* Restreignez les points de terminaison web enrollment (`certsrv`) et CES/NDES aux réseaux de confiance ou placez-les derrière une authentification par certificat client.
* Imposer le chiffrement de l’enrollment RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) pour atténuer ESC11 (RPC relay). Le flag est **activé par défaut**, mais il est souvent désactivé pour les clients legacy, ce qui rouvre le risque de relay.
* Sécurisez les **IIS-based enrollment endpoints** (CES/Certsrv) : désactivez NTLM lorsque c’est possible ou exigez HTTPS + Extended Protection pour bloquer les relays ESC8.

---



## Références

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
