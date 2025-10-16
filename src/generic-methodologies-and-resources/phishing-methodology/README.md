# Phishing Méthodologie

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Recon de la victime
1. Sélectionnez le **domaine victime**.
2. Effectuez une énumération web de base **en recherchant des portails de connexion** utilisés par la victime et **décidez** lequel vous allez **usurper**.
3. Utilisez de l'**OSINT** pour **trouver des emails**.
2. Préparer l'environnement
1. **Acheter le domaine** que vous allez utiliser pour l'évaluation phishing
2. **Configurer les enregistrements** liés au service email (SPF, DMARC, DKIM, rDNS)
3. Configurer le VPS avec **gophish**
3. Préparer la campagne
1. Préparer le **modèle d'email**
2. Préparer la **page web** pour voler les identifiants
4. Lancez la campagne!

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de variation de noms de domaine

- **Mot-clé** : Le nom de domaine **contient** un **mot-clé** important du domaine original (p.ex., zelster.com-management.com).
- **Sous-domaine avec tiret** : Remplacez le **point par un tiret** d'un sous-domaine (p.ex., www-zelster.com).
- **Nouveau TLD** : Même domaine utilisant un **nouveau TLD** (p.ex., zelster.org)
- **Homoglyph** : Il **remplace** une lettre dans le nom de domaine par des **lettres qui se ressemblent** (p.ex., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition :** Elle **inverse deux lettres** dans le nom de domaine (p.ex., zelsetr.com).
- **Singularization/Pluralization** : Ajoute ou supprime un « s » à la fin du nom de domaine (p.ex., zeltsers.com).
- **Omission :** Elle **supprime une** des lettres du nom de domaine (p.ex., zelser.com).
- **Répétition :** Elle **répète une** des lettres du nom de domaine (p.ex., zeltsser.com).
- **Remplacement** : Comme homoglyph mais moins furtif. Il remplace une des lettres du nom de domaine, peut-être par une lettre proche de la lettre originale sur le clavier (p.ex., zektser.com).
- **Subdomained** : Introduire un **point** à l'intérieur du nom de domaine (p.ex., ze.lster.com).
- **Insertion** : Elle **insère une lettre** dans le nom de domaine (p.ex., zerltser.com).
- **Point manquant** : Ajouter le TLD au nom de domaine. (p.ex., zelstercom.com)

**Outils automatiques**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il existe une **possibilité que certains bits stockés ou en communication puissent être inversés automatiquement** en raison de divers facteurs comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Quand ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que le domaine initialement demandé.

Par exemple, une modification d'un seul bit dans le domaine "windows.com" peut le changer en "windnws.com".

Les attaquants peuvent **profiter de cela en enregistrant plusieurs domaines sujets au bit-flipping** qui sont similaires au domaine de la victime. Leur intention est de rediriger des utilisateurs légitimes vers leur infrastructure.

Pour plus d'informations lisez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acheter un domaine de confiance

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon SEO** vous pouvez vérifier comment il est catégorisé dans :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte d'adresses email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir davantage** d'adresses email valides ou **vérifier celles** que vous avez déjà découvertes vous pouvez vérifier si vous pouvez brute-force les serveurs SMTP de la victime. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs mails**, vous pouvez vérifier s'il est vulnérable à la **username brute force**, et exploiter la vulnérabilité si possible.

## Configuring GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez et décompressez-le dans `/opt/gophish` et exécutez `/opt/gophish/gophish`\
Un mot de passe pour l'utilisateur admin vous sera donné dans la sortie pour le port 3333. Par conséquent, accédez à ce port et utilisez ces identifiants pour changer le mot de passe admin. Il se peut que vous deviez tunneliser ce port en local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez **avoir déjà acheté le domaine** que vous allez utiliser et il doit être **pointé** vers l'**IP du VPS** où vous configurez **gophish**.
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
**Configuration du mail**

Commencez l'installation : `apt-get install postfix`

Ajoutez ensuite le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec votre nom de domaine et **redémarrez votre VPS.**

Créez maintenant un **enregistrement DNS A** pour `mail.<domain>` pointant vers l'**adresse IP** de votre VPS, et un **enregistrement DNS MX** pointant vers `mail.<domain>`

Testons maintenant l'envoi d'un e-mail :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuration de Gophish**

Arrêtez l'exécution de gophish et configurons-le.  
Modifiez `/opt/gophish/config.json` comme suit (notez l'utilisation de https):
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

Pour créer le service gophish afin qu'il puisse être démarré automatiquement et géré comme un service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
Terminer la configuration du service et vérifier ce qu'il fait :
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

### Attendre & paraître légitime

Plus un domaine est ancien, moins il est probable qu'il soit traité comme spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l'évaluation phishing. De plus, si vous mettez une page liée à un secteur à bonne réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration de tout dès maintenant.

### Configurer l'enregistrement Reverse DNS (rDNS)

Créez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Enregistrement SPF (Sender Policy Framework)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../images/image (1037).png>)

Voici le contenu qui doit être placé dans un enregistrement TXT du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Authentification des messages basée sur le domaine, Reporting & Conformance (DMARC) — Enregistrement

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

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un e-mail à l'adresse qu'ils vous fournissent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez aussi **vérifier votre configuration e-mail** en envoyant un e-mail à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela vous devrez **ouvrir** le port **25** et voir la réponse dans le fichier _/var/mail/root_ si vous envoyez l'e-mail en tant que root).\
Vérifiez que vous passez tous les tests :
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
Vous pouvez également envoyer **un message vers un compte Gmail que vous contrôlez**, et vérifier les **en-têtes du courriel** dans votre boîte Gmail : `dkim=pass` devrait être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Suppression de Spamhouse Blacklist

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par spamhouse. Vous pouvez demander le retrait de votre domaine/IP à : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de Microsoft Blacklist

​​Vous pouvez demander le retrait de votre domaine/IP à [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Donnez un **nom pour identifier** le profil d'expéditeur
- Décidez depuis quel compte vous allez envoyer les phishing emails. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser vide le username et le password, mais assurez-vous de cocher l'option Ignorer les erreurs de certificat

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Envoyer un e-mail de test**" pour vérifier que tout fonctionne.\
> Je recommande d'**envoyer les e-mails de test vers des adresses 10min mails** afin d'éviter d'être mis sur liste noire lors des tests.

### Email Template

- Donnez un **nom pour identifier** le template
- Ensuite écrivez un **subject** (rien d'étrange, juste quelque chose que vous pourriez vous attendre à lire dans un e-mail classique)
- Assurez-vous d'avoir coché "**Add Tracking Image**"
- Rédigez le **email template** (vous pouvez utiliser des variables comme dans l'exemple suivant)
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
Notez que **pour augmenter la crédibilité de l'email**, il est recommandé d'utiliser une signature extraite d'un email du client. Suggestions :

- Envoyer un email à une **adresse inexistante** et vérifier si la réponse contient une signature.
- Rechercher des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com, leur envoyer un email et attendre la réponse.
- Tenter de contacter **une adresse valide découverte** et attendre la réponse

![](<../../images/image (80).png>)

> [!TIP]
> Le modèle d'email permet aussi d'**attacher des fichiers à envoyer**. Si vous souhaitez également voler des challenges NTLM en utilisant des fichiers/documents spécialement conçus, [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Saisir un **nom**
- **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Marquer **Capture Submitted Data** et **Capture Passwords**
- Définir une **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Généralement, vous devrez modifier le code HTML de la page et effectuer des tests en local (par exemple avec un serveur Apache) **jusqu'à obtenir le résultat souhaité.** Ensuite, collez ce code HTML dans la zone.\
> Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (par exemple des pages CSS et JS) vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pouvez **rediriger les utilisateurs vers la page principale légitime** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, afficher une **roue de chargement** ([https://loading.io/](https://loading.io)) pendant 5 secondes puis indiquer que le processus a réussi.

### Users & Groups

- Définir un nom
- **Importer les données** (notez que pour utiliser le template de l'exemple vous aurez besoin du firstname, last name et email address de chaque utilisateur)

![](<../../images/image (163).png>)

### Campaign

Enfin, créez une campagne en sélectionnant un nom, le email template, la landing page, l'URL, le sending profile et le groupe. Notez que l'URL sera le lien envoyé aux victimes

Notez que le **Sending Profile permet d'envoyer un email de test pour voir à quoi ressemblera l'email de phishing final** :

![](<../../images/image (192).png>)

> [!TIP]
> Je recommande d'**envoyer les emails de test vers des adresses 10min mails** afin d'éviter de se faire blacklister lors des tests.

Une fois tout prêt, lancez simplement la campagne !

## Website Cloning

Si pour une raison quelconque vous souhaitez cloner le site web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Dans certaines évaluations de phishing (principalement pour Red Teams), vous voudrez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou quelque chose qui déclenche une authentification).\
Consultez la page suivante pour des exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est plutôt ingénieuse car vous falsifiez un site réel et recueillez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous avez falsifiée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'identité de l'utilisateur piégé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. Essentiellement, l'attaque fonctionne comme suit :

1. Vous **usurpez le formulaire de login** de la page web réelle.
2. L'utilisateur **envoie** ses **credentials** à votre page factice et l'outil les relaie vers la page réelle, **vérifiant si les credentials fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM le demandera et, une fois que **l'utilisateur le saisit**, l'outil le transmettra à la page réelle.
4. Une fois l'utilisateur authentifié, vous (en tant qu'attaquant) aurez **capturé les credentials, le 2FA, le cookie et toute information** de chaque interaction pendant que l'outil effectue le MitM.

### Via VNC

Et si, au lieu de **rediriger la victime vers une page malveillante** ressemblant à l'originale, vous l'envoyiez vers une **session VNC avec un navigateur connecté à la page web réelle** ? Vous pourrez voir ses actions, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Évidemment une des meilleures façons de savoir si vous vous êtes fait repérer est de **chercher votre domaine dans les blacklists**. S'il apparaît listé, votre domaine a été détecté comme suspect.\
Un moyen simple de vérifier si votre domaine apparaît dans une blacklist est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **recherche activement des activités de phishing suspectes** comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine au nom très similaire** au domaine de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une interaction **DNS ou HTTP** avec eux, vous saurez qu'**elle recherche activement** des domaines suspects et vous devrez être très discret.

### Evaluate the phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email finira dans le dossier spam, sera bloqué ou sera réussi.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les jeux d'intrusion modernes évitent de plus en plus les leurres par email et ciblent **directement le workflow du service-desk / identity-recovery** pour contourner le MFA. L'attaque est entièrement "living-off-the-land" : une fois que l'opérateur possède des credentials valides, il pivote avec des outils d'administration intégrés — aucun malware n'est requis.

### Attack flow
1. Reconnaissance de la victime
* Collecter des informations personnelles et d'entreprise depuis LinkedIn, des data breaches, GitHub public, etc.
* Identifier les identités à haute valeur (executives, IT, finance) et énumérer le **processus exact du help-desk** pour la réinitialisation de mot de passe / MFA.
2. Social engineering en temps réel
* Téléphoner, utiliser Teams ou chatter le help-desk en usurpant l'identité de la cible (souvent avec **spoofed caller-ID** ou **cloned voice**).
* Fournir les PII collectées précédemment pour passer la vérification basée sur la connaissance.
* Convaincre l'agent de **réinitialiser le secret MFA** ou d'effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions post-accès immédiates (≤60 min dans les cas réels)
* Établir un point d'appui via n'importe quel portail SSO web.
* Énumérer AD / AzureAD avec les outils intégrés (aucun binaire déployé) :
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents **RMM** légitimes déjà en liste blanche dans l'environnement.

### Detection & Mitigation
* Considérez la récupération d'identité via le help-desk comme une **opération privilégiée** – exiger une step-up auth et l'approbation d'un manager.
* Déployer des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui alertent sur :
* Changement de méthode MFA + authentification depuis un nouvel appareil / une nouvelle géo.
* Élévation immédiate du même principal (user → admin).
* Enregistrer les appels du help-desk et imposer un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Mettre en place **Just-In-Time (JIT) / Privileged Access** afin que les comptes nouvellement réinitialisés **n'** héritent pas automatiquement des tokens à haut privilège.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Les groupes commodity compensent le coût des opérations high-touch par des attaques de masse qui transforment **les moteurs de recherche et les réseaux publicitaires en canal de livraison**.

1. **SEO poisoning** / malvertising pousse un résultat factice comme `chromium-update[.]site` en haut des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur et les credential DBs, puis récupère un **silent loader** qui décide – *en temps réel* – de déployer :
* RAT (ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistance (clé Run du registre + tâche planifiée)

### Hardening tips
* Bloquer les domaines récemment enregistrés et appliquer **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que les e-mails.
* Restreindre l'installation de logiciels aux packages MSI signés / Store, interdire l'exécution de `HTA`, `ISO`, `VBS` via les politiques.
* Surveiller les processus enfants des navigateurs ouvrant des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chasser les LOLBins fréquemment abusés par les first-stage loaders (ex. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Les attaquants enchaînent désormais des **LLM & voice-clone APIs** pour des leurres entièrement personnalisés et des interactions en temps réel.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Générer et envoyer >100 k emails / SMS avec formulations randomisées & liens de tracking.|
|Generative AI|Produire des emails uniques référant des M&A publiques, des private jokes issues des réseaux sociaux ; deep-fake de la voix du CEO lors d'un callback scam.|
|Agentic AI|Enregistrer des domaines de façon autonome, scraper de l'OSINT, rédiger les emails de l'étape suivante quand une victime clique mais ne soumet pas ses credentials.|

**Defence:**
• Ajouter des **bannières dynamiques** mettant en évidence les messages envoyés par des automatisations non fiables (via anomalies ARC/DKIM).  
• Déployer des **phrases challenge biométriques vocales** pour les demandes téléphoniques à haut risque.  
• Simuler en continu des leurres générés par AI dans les programmes de sensibilisation – les templates statiques sont obsolètes.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
En plus du classic push-bombing, les opérateurs forcent simplement une **nouvelle inscription MFA** pendant l'appel au help-desk, annulant le token existant de l'utilisateur. Toute invite de connexion ultérieure apparaîtra légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveiller les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d'intervalle depuis la même IP**.

## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse‑papiers de la victime depuis une page web compromise ou typosquattée, puis inciter l'utilisateur à les coller dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing pour contourner crawlers/sandboxes
Les opérateurs placent de plus en plus leurs flux de phishing derrière un simple contrôle d'appareil afin que les desktop crawlers n'atteignent jamais les pages finales. Un schéma courant est un petit script qui teste si le DOM est touch-capable et envoie le résultat à un server endpoint ; les clients non‑mobile reçoivent HTTP 500 (ou une page vide), tandis que les utilisateurs mobile se voient servir le flux complet.

Extrait client minimal (logique typique) :
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logique (simplifiée):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportement du serveur souvent observé :
- Définit un cookie de session lors du premier chargement.
- Accepts `POST /detect {"is_mobile":true|false}`.
- Retourne 500 (or placeholder) aux GETs suivants lorsque `is_mobile=false` ; ne sert le phishing que si `true`.

Heuristiques de chasse et de détection :
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Télémétrie web : séquence de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour non‑mobile ; les chemins légitimes pour victimes mobiles renvoient 200 avec HTML/JS ultérieur.
- Bloquez ou scrutez les pages qui conditionnent le contenu exclusivement sur `ontouchstart` ou des vérifications d'appareil similaires.

Conseils de défense :
- Exécutez des crawlers avec des fingerprints de type mobile et JS activé pour révéler le contenu restreint.
- Alerter sur les réponses 500 suspectes apparaissant après `POST /detect` sur des domaines récemment enregistrés.

## Références

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
