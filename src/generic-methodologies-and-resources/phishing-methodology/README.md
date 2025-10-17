# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Recon de la victime
1. Sélectionnez le **domaine de la victime**.
2. Effectuez une énumération web basique **en recherchant les portails de connexion** utilisés par la victime et **décidez** lequel vous allez **usurper**.
3. Utilisez de l'**OSINT** pour **trouver des e-mails**.
2. Préparer l'environnement
1. **Acheter le domaine** que vous allez utiliser pour le test de phishing
2. **Configurer les enregistrements** liés au service email (SPF, DMARC, DKIM, rDNS)
3. Configurer le VPS avec **gophish**
3. Préparer la campagne
1. Préparer le **modèle d'email**
2. Préparer la **page web** pour voler les identifiants
4. Lancer la campagne!

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de variation de nom de domaine

- **Mot-clé** : Le nom de domaine **contient** un **mot-clé** important du domaine original (par ex., zelster.com-management.com).
- **sous-domaine avec tiret** : Remplacer le **point par un tiret** d'un sous-domaine (par ex., www-zelster.com).
- **Nouveau TLD** : Même domaine avec un **nouveau TLD** (par ex., zelster.org)
- **Homoglyph** : Il **remplace** une lettre du nom de domaine par des **lettres visuellement similaires** (par ex., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition :** Il **inverse deux lettres** dans le nom de domaine (par ex., zelsetr.com).
- **Singularisation/Pluralisation** : Ajoute ou supprime un “s” à la fin du nom de domaine (par ex., zeltsers.com).
- **Omission** : Il **supprime une** des lettres du nom de domaine (par ex., zelser.com).
- **Répétition :** Il **répète une** des lettres du nom de domaine (par ex., zeltsser.com).
- **Remplacement** : Comme homoglyph mais moins discret. Il remplace une des lettres du nom de domaine, peut-être par une lettre proche sur le clavier (par ex., zektser.com).
- **Subdomained** : Introduire un **point** à l'intérieur du nom de domaine (par ex., ze.lster.com).
- **Insertion** : Il **insère une lettre** dans le nom de domaine (par ex., zerltser.com).
- **Point manquant** : Ajouter le TLD au nom de domaine. (par ex., zelstercom.com)

**Outils automatiques**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites Web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il existe une **possibilité qu'un ou plusieurs bits stockés ou en communication se retournent automatiquement** en raison de divers facteurs comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Quand ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que le domaine initialement demandé.

Par exemple, une modification d'un seul bit dans le domaine "windows.com" peut le transformer en "windnws.com."

Les attaquants peuvent **profiter de cela en enregistrant plusieurs domaines bit-flipping** similaires au domaine de la victime. Leur intention est de rediriger des utilisateurs légitimes vers leur propre infrastructure.

Pour plus d'informations, lisez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acheter un domaine de confiance

Vous pouvez chercher sur [https://www.expireddomains.net/](https://www.expireddomains.net) un domaine expiré que vous pourriez utiliser.\
Afin de vous assurer que le domaine expiré que vous allez acheter **dispose déjà d'un bon SEO**, vous pouvez vérifier comment il est catégorisé dans :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte d'e-mails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir davantage** d'adresses e-mail valides ou **vérifier celles** que vous avez déjà trouvées, vous pouvez essayer de les brute-force via les serveurs SMTP de la victime. [Apprenez comment vérifier/découvrir des adresses e-mail ici](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n'oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs mails**, vous pouvez vérifier s'il est vulnérable au **username brute force**, et exploiter la vulnérabilité si possible.

## Configuring GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez et décompressez‑le dans `/opt/gophish` et exécutez `/opt/gophish/gophish`\
Vous recevrez un mot de passe pour l'utilisateur admin sur le port 3333 dans la sortie. Par conséquent, accédez à ce port et utilisez ces identifiants pour changer le mot de passe admin. Vous devrez peut-être tunneliser ce port en local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

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

Créez maintenant un **enregistrement DNS A** pour `mail.<domain>` pointant vers l'**adresse IP** du VPS et un enregistrement **DNS MX** pointant vers `mail.<domain>`

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
Terminer la configuration du service et vérifier son bon fonctionnement :
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

Plus un domaine est ancien, moins il est probable qu'il soit détecté comme spam. Vous devriez donc attendre autant que possible (au moins 1 semaine) avant le phishing assessment. De plus, si vous mettez une page liée à un secteur ayant une bonne réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez finir de tout configurer maintenant.

### Configurer l'enregistrement Reverse DNS (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Sender Policy Framework (SPF) Record

Vous devez **configurer un SPF record pour le nouveau domaine**. Si vous ne savez pas ce qu'est un SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser https://www.spfwizard.net/ pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../images/image (1037).png>)

Ceci est le contenu qui doit être placé dans un enregistrement TXT du domaine:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Authentification des messages basée sur le domaine, rapports et conformité (DMARC) — Enregistrement

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant le nom d'hôte `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Vous devez concaténer les deux valeurs B64 que génère la clé DKIM :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Accédez simplement à la page et envoyez un email à l'adresse qu'ils vous fournissent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez aussi **vérifier votre configuration e-mail** en envoyant un e-mail à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela vous devrez **ouvrir** le port **25** et consulter la réponse dans le fichier _/var/mail/root_ si vous envoyez l'e-mail en tant que root).\
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
Vous pouvez aussi envoyer **un message vers un compte Gmail sous votre contrôle**, et vérifier les **en-têtes de l'email** dans votre boîte Gmail, `dkim=pass` devrait être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Suppression de la liste noire Spamhouse

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par spamhouse. Vous pouvez demander la suppression de votre domaine/IP à : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de la liste noire Microsoft

​​Vous pouvez demander la suppression de votre domaine/IP à [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d'envoi

- Définissez un **nom pour identifier** le profil d'expéditeur
- Décidez depuis quel compte vous allez envoyer les emails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser le username et le password vides, mais assurez-vous de cocher Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" pour vérifier que tout fonctionne.\
> Je recommande d'**envoyer les emails de test vers des adresses 10min mails** afin d'éviter d'être mis sur liste noire lors des tests.

### Modèle d'email

- Donnez un **nom pour identifier** le modèle
- Ensuite écrivez un **subject** (rien d'étrange, juste quelque chose que l'on pourrait s'attendre à lire dans un email ordinaire)
- Assurez-vous d'avoir coché "**Add Tracking Image**"
- Rédigez le **email template** (vous pouvez utiliser des variables comme dans l'exemple suivant) :
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
- Rechercher des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com, leur envoyer un email et attendre la réponse.
- Essayer de contacter **quelques adresses valides découvertes** et attendre la réponse.

![](<../../images/image (80).png>)

> [!TIP]
> Le Email Template permet aussi **d'attacher des fichiers à envoyer**. Si vous souhaitez aussi voler des challenges NTLM en utilisant des fichiers/documents spécialement conçus, [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Indiquer un **nom**
- **Écrire le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cocher **Capture Submitted Data** et **Capture Passwords**
- Définir une **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> En général vous devrez modifier le code HTML de la page et faire des tests en local (peut‑être en utilisant un serveur Apache) **jusqu'à obtenir le rendu souhaité.** Ensuite, collez ce code HTML dans la zone prévue.\
> Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (par exemple des pages CSS ou JS) vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pouvez **rediriger les utilisateurs vers la page web légitime** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, afficher une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes puis indiquer que le processus a réussi**.

### Users & Groups

- Définir un nom
- **Importer les données** (notez que pour utiliser le template de l'exemple vous avez besoin du firstname, last name et email address de chaque utilisateur)

![](<../../images/image (163).png>)

### Campaign

Enfin, créez une campaign en sélectionnant un nom, le email template, la landing page, l'URL, le sending profile et le group. Notez que l'URL sera le lien envoyé aux victimes.

Notez que le **Sending Profile permet d'envoyer un email de test pour voir à quoi ressemblera l'email de phishing final** :

![](<../../images/image (192).png>)

> [!TIP]
> Je recommande d'**envoyer les emails de test vers des adresses 10min mail** afin d'éviter d'être blacklisté pendant les tests.

Une fois que tout est prêt, lancez la campaign !

## Website Cloning

Si pour une raison quelconque vous voulez cloner le site web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Dans certaines évaluations de phishing (principalement pour les Red Teams) vous souhaiterez aussi **envoyer des fichiers contenant une sorte de backdoor** (peut‑être un C2 ou simplement quelque chose qui déclenche une authentification).\
Consultez la page suivante pour des exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous simulez un vrai site web et collectez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le mot de passe correct ou si l'application que vous avez simulée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'identité de l'utilisateur trompé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permet de générer une attaque MitM. Fondamentalement, l'attaque fonctionne de la manière suivante :

1. Vous **vous faites passer pour le formulaire de login** de la page réelle.
2. L'utilisateur **envoie** ses **credentials** à votre page factice et l'outil les transmet à la page réelle, **vérifiant si les credentials fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM demandera la 2FA et une fois que **l'utilisateur la saisit**, l'outil la transmettra à la page réelle.
4. Une fois l'utilisateur authentifié, vous (en tant qu'attaquant) aurez **capturé les credentials, la 2FA, le cookie et toute information** de chaque interaction pendant que l'outil réalise le MitM.

### Via VNC

Et si, au lieu de **rediriger la victime vers une page malveillante** ressemblant à l'originale, vous la redirigiez vers une **session VNC avec un navigateur connecté à la page réelle** ? Vous pourrez voir ce qu'il fait, voler le mot de passe, la MFA utilisée, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Évidemment, une des meilleures façons de savoir si vous avez été détecté est de **chercher votre domaine dans les blacklists**. S'il apparaît listé, d'une manière ou d'une autre votre domaine a été détecté comme suspect.\
Un moyen simple de vérifier si votre domaine figure dans une blacklist est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **cherche activement des activités de phishing suspectes dans la nature** comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine avec un nom très similaire** à celui de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine que vous contrôlez **contenant** le **mot‑clé** du domaine de la victime. Si la **victime** effectue une quelconque interaction DNS ou HTTP avec ceux-ci, vous saurez qu'**elle recherche activement** des domaines suspects et vous devrez être très stealth.

### Evaluate the phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email ira dans le dossier spam ou s'il sera bloqué ou réussi.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les opérations d'intrusion modernes évitent de plus en plus les leurres par email et ciblent **directement le service-desk / le workflow de récupération d'identité** pour contourner la MFA. L'attaque est entièrement "living-off-the-land" : une fois que l'opérateur obtient des credentials valides, il pivote avec les outils d'administration intégrés – aucun malware n'est nécessaire.

### Attack flow
1. Recon de la victime
* Collecter des informations personnelles & corporates depuis LinkedIn, data breaches, GitHub public, etc.
* Identifier les identités à haute valeur (dirigeants, IT, finance) et énumérer le **processus exact du help-desk** pour la réinitialisation du mot de passe / MFA.
2. Social engineering en temps réel
* Appeler, utiliser Teams ou chatter avec le help-desk en se faisant passer pour la cible (souvent avec **spoofed caller-ID** ou **voice cloned**).
* Fournir les PII collectées précédemment pour passer la vérification basée sur les connaissances.
* Convaincre l'agent de **réinitialiser le secret MFA** ou d'effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions post‑accès immédiates (≤60 min dans des cas réels)
* Établir une présence via n'importe quel portail web SSO.
* Énumérer AD / AzureAD avec les outils intégrés (aucun binaire déployé) :
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents **RMM** légitimes déjà whitelistés dans l'environnement.

### Detection & Mitigation
* Traitez la récupération d'identité par le help-desk comme une **opération privilégiée** – exiger une authentification renforcée & une approbation du manager.
* Déployer **Identity Threat Detection & Response (ITDR)** / règles **UEBA** qui alertent sur :
* Méthode MFA modifiée + authentification depuis un nouvel appareil / géolocalisation.
* Élévation immédiate du même principal (user → admin).
* Enregistrer les appels au help-desk et exiger un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Implémenter **Just-In-Time (JIT) / Privileged Access** pour que les comptes nouvellement réinitialisés **n'héritent pas** automatiquement de jetons à haute-privilege.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Des groupes commodity compensent le coût des opérations high-touch avec des attaques de masse qui transforment **les moteurs de recherche & les réseaux publicitaires en canal de distribution**.

1. **SEO poisoning / malvertising** pousse un résultat factice tel que `chromium-update[.]site` en tête des annonces de recherche.
2. La victime télécharge un petit **loader de première phase** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur + les credential DBs, puis télécharge un **silent loader** qui décide – *en temps réel* – s'il faut déployer :
* RAT (p.ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistance (clé Run du registre + tâche planifiée)

### Hardening tips
* Bloquer les domaines nouvellement enregistrés & appliquer un **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que sur les emails.
* Restreindre l'installation de logiciels aux packages MSI signés / Store, refuser l'exécution de `HTA`, `ISO`, `VBS` par politique.
* Surveiller les processus enfants des navigateurs ouvrant des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chasser les LOLBins fréquemment abusés par les loaders de première phase (p.ex. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Les attaquants enchaînent désormais les **API LLM & voice-clone** pour des leurres complètement personnalisés et des interactions en temps réel.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Ajouter des **bannières dynamiques** signalant les messages envoyés par des automations non fiables (via anomalies ARC/DKIM).  
• Déployer des **voice-biometric challenge phrases** pour les demandes téléphoniques à haut risque.  
• Simuler en continu des leurres générés par AI dans les programmes de sensibilisation – les templates statiques sont obsolètes.

Voir aussi – agentic browsing abuse for credential phishing :

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Voir aussi – AI agent abuse of local CLI tools and MCP (pour l'inventaire des secrets et la détection) :

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Outre le push-bombing classique, les opérateurs forcent simplement une nouvelle inscription MFA pendant l'appel au help-desk, annulant le token existant de l'utilisateur. Toute invite de connexion ultérieure paraît légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveiller les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d'intervalle depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse‑papier de la victime depuis une page web compromise ou typosquattée, puis tromper l'utilisateur pour qu'il les colle dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Les opérateurs placent de plus en plus leurs flows de phishing derrière un simple contrôle de dispositif pour que les crawlers desktop n'atteignent jamais les pages finales. Un schéma courant est un petit script qui teste si le DOM est compatible tactile et envoie le résultat à un endpoint serveur ; les clients non‑mobiles reçoivent une erreur HTTP 500 (ou une page blanche), tandis que les utilisateurs mobiles voient l'intégralité du flow.

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
Server behaviour often observed:
- Définit un cookie de session lors du premier chargement.
- Accepte `POST /detect {"is_mobile":true|false}`.
- Renvoie 500 (ou un contenu de substitution) aux GET suivants lorsque `is_mobile=false` ; ne sert le phishing que si `true`.

Hunting and detection heuristics:
- Requête urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: séquence de `GET /static/detect_device.js` → `POST /detect` → HTTP 500 for non‑mobile; legitimate mobile victim paths return 200 with follow‑on HTML/JS.
- Bloquez ou scrutez les pages qui conditionnent le contenu exclusivement sur `ontouchstart` ou des vérifications de dispositif similaires.

Defence tips:
- Exécutez des crawlers avec des empreintes de type mobile et JS activé pour révéler le contenu conditionné.
- Déclenchez des alertes pour les réponses 500 suspectes suite à `POST /detect` sur des domaines nouvellement enregistrés.

## Références

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
