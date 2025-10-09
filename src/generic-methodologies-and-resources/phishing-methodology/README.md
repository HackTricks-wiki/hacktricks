# Méthodologie de phishing

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Recon the victim
1. Select the **domaine de la victime**.
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

## Générez des noms de domaine similaires ou achetez un domaine de confiance

### Techniques de variation de nom de domaine

- **Mot-clé**: Le nom de domaine **contient** un **mot-clé** important du domaine original (ex. zelster.com-management.com).
- **Sous-domaine avec tiret**: Remplacez le **point par un tiret** du sous-domaine (ex. www-zelster.com).
- **New TLD**: Même domaine utilisant un **nouveau TLD** (ex. zelster.org)
- **Homoglyph**: Il **remplace** une lettre dans le nom de domaine par des **lettres qui ressemblent** (ex. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Il **échange deux lettres** au sein du nom de domaine (ex. zelsetr.com).
- **Singularization/Pluralization**: Ajoute ou enlève un “s” à la fin du nom de domaine (ex. zeltsers.com).
- **Omission**: Il **supprime une** des lettres du nom de domaine (ex. zelser.com).
- **Repetition:** Il **répète une** des lettres du nom de domaine (ex. zeltsser.com).
- **Replacement**: Comme homoglyph mais moins discret. Il remplace une des lettres du nom de domaine, peut-être par une lettre située à proximité sur le clavier (ex. zektser.com).
- **Subdomained**: Introduire un **point** à l'intérieur du nom de domaine (ex. ze.lster.com).
- **Insertion**: Il **insère une lettre** dans le nom de domaine (ex. zerltser.com).
- **Missing dot**: Ajouter la TLD au nom de domaine. (ex. zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Acheter un domaine de confiance

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découverte d'emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Apprenez comment vérifier/découvrir des adresses email ici](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devez **avoir déjà acheté le domaine** que vous allez utiliser et il doit **pointer** vers l'**IP du VPS** où vous configurez **gophish**.
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

Ajoutez ensuite le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez aussi les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** avec votre nom de domaine et **redémarrez votre VPS.**

Créez maintenant un **enregistrement DNS A** de `mail.<domain>` pointant vers l'**adresse IP** du VPS et un **enregistrement DNS MX** pointant vers `mail.<domain>`

Testons maintenant l'envoi d'un email :
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

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

Pour créer le service gophish afin qu'il puisse démarrer automatiquement et être géré en tant que service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :
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
Terminez la configuration du service et vérifiez son bon fonctionnement en procédant ainsi :
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

### Attendre et rester légitime

Plus un domaine est ancien, moins il a de chances d'être détecté comme spam. Vous devez donc attendre autant que possible (au moins 1 semaine) avant l'évaluation phishing. De plus, si vous ajoutez une page liée à un secteur ayant une bonne réputation, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer la configuration maintenant.

### Configurez l'enregistrement Reverse DNS (rDNS)

Configurez un enregistrement rDNS (PTR) qui résout l'adresse IP du VPS vers le nom de domaine.

### Enregistrement SPF (Sender Policy Framework)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement SPF [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l'IP de la machine VPS)

![](<../../images/image (1037).png>)

Voici le contenu qui doit être placé dans un enregistrement TXT du domaine :
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant le nom d'hôte `_dmarc.<domain>` avec le contenu suivant :
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu'est un enregistrement DMARC [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Vous devez concaténer les deux valeurs B64 que génère la clé DKIM :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testez le score de configuration de votre e-mail

Vous pouvez le faire en utilisant [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un e-mail à l'adresse qu'ils vous donnent :
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Vous pouvez aussi **vérifier la configuration de votre email** en envoyant un email à `check-auth@verifier.port25.com` et en **lisant la réponse** (pour cela vous devrez **ouvrir** le port **25** et voir la réponse dans le fichier _/var/mail/root_ si vous envoyez l'email en tant que root).\
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
Vous pouvez également envoyer **un message à un compte Gmail que vous contrôlez**, et vérifier les **en-têtes de l’email** dans votre boîte de réception Gmail, `dkim=pass` doit être présent dans le champ d'en-tête `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Retrait de la blacklist Spamhouse

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par Spamhouse. Vous pouvez demander le retrait de votre domaine/IP sur : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Retrait de la blacklist Microsoft

​​Vous pouvez demander le retrait de votre domaine/IP sur [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d'envoi

- Donnez un **nom pour identifier** le profil d'expéditeur
- Décidez depuis quel compte vous allez envoyer les phishing emails. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser vide le username et le password, mais assurez-vous de cocher l'option Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d'utiliser la fonctionnalité "**Send Test Email**" pour vérifier que tout fonctionne.\
> Je recommande d'**envoyer les test emails vers des adresses 10min mails** afin d'éviter d'être mis sur une blacklist lors des tests.

### Email Template

- Donnez un **nom pour identifier** le template
- Puis écrivez un **subject** (rien d'étrange, juste quelque chose que vous pourriez lire dans un email normal)
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
- Rechercher des **emails publics** comme info@ex.com ou press@ex.com ou public@ex.com et leur envoyer un email en attendant la réponse.
- Essayer de contacter **une adresse valide découverte** et attendre la réponse

![](<../../images/image (80).png>)

> [!TIP]
> Le Email Template permet aussi **d'attacher des fichiers à envoyer**. Si vous souhaitez aussi voler des challenges NTLM en utilisant des fichiers/documents spécialement construits [lisez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Saisir un **nom**
- **Saisir le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cocher **Capture Submitted Data** et **Capture Passwords**
- Définir une **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> En général vous devrez modifier le code HTML de la page et faire des tests en local (peut-être en utilisant un serveur Apache) **jusqu'à obtenir le résultat souhaité.** Ensuite, collez ce code HTML dans la boîte.\
> Notez que si vous avez besoin d'**utiliser des ressources statiques** pour le HTML (par exemple des pages CSS et JS) vous pouvez les sauvegarder dans _**/opt/gophish/static/endpoint**_ puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection vous pouvez **rediriger les utilisateurs vers la page web légitime principale** de la victime, ou les rediriger vers _/static/migration.html_ par exemple, mettre une **animation de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes puis indiquer que le processus a réussi**.

### Users & Groups

- Définir un nom
- **Importer les données** (notez que pour utiliser le template d'exemple vous avez besoin du firstname, last name et email address de chaque utilisateur)

![](<../../images/image (163).png>)

### Campaign

Enfin, créez une campagne en sélectionnant un nom, le email template, la landing page, l'URL, le Sending Profile et le groupe. Notez que l'URL sera le lien envoyé aux victimes

Notez que le **Sending Profile permet d'envoyer un email de test pour voir à quoi ressemblera l'email de phishing final** :

![](<../../images/image (192).png>)

> [!TIP]
> Je recommande d'**envoyer les emails de test vers des adresses 10min mails** afin d'éviter d'être blacklisté lors des tests.

Une fois que tout est prêt, lancez simplement la campagne !

## Website Cloning

Si, pour une raison quelconque, vous voulez cloner le site web consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Dans certaines évaluations de phishing (principalement pour les Red Teams) vous souhaiterez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou peut-être juste quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

L'attaque précédente est assez astucieuse car vous falsifiez un vrai site et collectez les informations saisies par l'utilisateur. Malheureusement, si l'utilisateur n'a pas saisi le bon mot de passe ou si l'application que vous avez falsifiée est configurée avec 2FA, **ces informations ne vous permettront pas d'usurper l'utilisateur piégé**.

C'est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Ces outils permettent de générer une attaque de type MitM. En gros, l'attaque fonctionne de la manière suivante :

1. Vous **usurpez le formulaire de login** de la page réelle.
2. L'utilisateur **envoie** ses **identifiants** à votre page factice et l'outil les transmet à la page réelle, **vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec **2FA**, la page MitM demandera le code et une fois que **l'utilisateur le saisit** l'outil l'enverra à la page réelle.
4. Une fois l'utilisateur authentifié vous (en tant qu'attaquant) aurez **capturé les identifiants, le 2FA, le cookie et toute information** de chaque interaction pendant que l'outil réalise le MitM.

### Via VNC

Et si, au lieu d'**envoyer la victime vers une page malveillante** ayant la même apparence que l'originale, vous l'envoyiez vers une **session VNC avec un navigateur connecté à la page réelle** ? Vous pourrez voir ce qu'il fait, voler le mot de passe, le MFA utilisé, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Évidemment, l'une des meilleures façons de savoir si vous avez été repéré est de **rechercher votre domaine dans des listes noires**. S'il apparaît listé, d'une manière ou d'une autre votre domaine a été détecté comme suspect.\
Une façon simple de vérifier si votre domaine apparaît dans une liste noire est d'utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d'autres moyens de savoir si la victime **cherche activement des activités de phishing suspectes dans la nature** comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine au nom très similaire** à celui de la victime **et/ou générer un certificat** pour un **sous-domaine** d'un domaine contrôlé par vous **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue n'importe quel type d'**interaction DNS ou HTTP** avec eux, vous saurez qu'**elle recherche activement** des domaines suspects et vous devrez être très discret.

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious) pour évaluer si votre email finira dans le dossier spam, s'il sera bloqué ou s'il sera réussi.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Les ensembles d'intrusion modernes évitent de plus en plus les leurres par email et **visent directement le service-desk / le workflow de récupération d'identité** pour contourner la MFA. L'attaque est entièrement "living-off-the-land" : une fois que l'opérateur possède des identifiants valides, il pivote avec des outils d'administration intégrés – aucun malware n'est requis.

### Attack flow
1. Reconnaissance de la victime
* Récupérer des détails personnels & professionnels depuis LinkedIn, des fuites de données, GitHub public, etc.
* Identifier les identités à haute valeur (cadres, IT, finance) et énumérer le **processus exact du help-desk** pour la réinitialisation de mot de passe / MFA.
2. Social engineering en temps réel
* Appeler, contacter via Teams ou chat le help-desk en usurpant l'identité de la cible (souvent avec **spoofed caller-ID** ou **cloned voice**).
* Fournir les PII précédemment collectées pour passer la vérification basée sur les connaissances.
* Convaincre l'agent de **réinitialiser le secret MFA** ou d'effectuer un **SIM-swap** sur un numéro mobile enregistré.
3. Actions post-accès immédiates (≤60 min dans des cas réels)
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
* Mouvement latéral avec **WMI**, **PsExec**, ou des agents **RMM** légitimes déjà en liste blanche dans l'environnement.

### Detection & Mitigation
* Traiter la récupération d'identité via le help-desk comme une **opération privilégiée** – exiger une authentification renforcée & l'approbation d'un manager.
* Déployer des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui alertent sur :
* Méthode MFA changée + authentification depuis un nouvel appareil / une nouvelle géo.
* Élévation immédiate du même principal (user → admin).
* Enregistrer les appels du help-desk et imposer un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Mettre en place **Just-In-Time (JIT) / Privileged Access** afin que les comptes nouvellement réinitialisés **n'héritent pas** automatiquement de jetons à haut privilège.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Des groupes grand public compensent le coût des opérations high-touch par des attaques massives qui transforment **les moteurs de recherche & les réseaux publicitaires en canal de distribution**.

1. **SEO poisoning / malvertising** pousse un faux résultat comme `chromium-update[.]site` en haut des annonces de recherche.
2. La victime télécharge un petit **first-stage loader** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur + les bases de données d'identifiants, puis récupère un **silent loader** qui décide – *en temps réel* – s'il va déployer :
* RAT (ex. AsyncRAT, RustDesk)
* ransomware / wiper
* composant de persistence (clé Run du registre + tâche planifiée)

### Conseils de durcissement
* Bloquer les domaines nouvellement enregistrés & appliquer un **Advanced DNS / URL Filtering** sur les *search-ads* ainsi que sur les e-mails.
* Restreindre l'installation de logiciels aux packages MSI signés / Store, interdire l'exécution de `HTA`, `ISO`, `VBS` par politique.
* Surveiller les processus enfants des navigateurs lançant des installateurs :
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Chasser les LOLBins fréquemment abusés par les first-stage loaders (ex. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Les attaquants enchaînent maintenant **LLM & APIs de clonage vocal** pour des leurres totalement personnalisés et des interactions en temps réel.

| Couche | Exemple d'utilisation par un acteur de menace |
|-------|-----------------------------|
|Automation|Générer & envoyer >100 k emails / SMS avec une formulation aléatoire & des liens trackés.|
|Generative AI|Produire des emails *one-off* faisant référence à des M&A publics, des blagues internes issues des réseaux sociaux ; voix deep-fake du CEO lors d'un rappel.|
|Agentic AI|Enregistrer automatiquement des domaines, scraper l'OSINT, rédiger les emails de l'étape suivante quand une victime clique mais ne soumet pas ses identifiants.|

**Défense :**
• Ajouter des **bannières dynamiques** mettant en évidence les messages envoyés par de l'automatisation non fiable (via anomalies ARC/DKIM).  
• Déployer des **phrases de défi biométriques vocales** pour les demandes téléphoniques à haut risque.  
• Simuler en continu des leurres générés par IA dans les programmes de sensibilisation – les modèles statiques sont obsolètes.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Outre le push-bombing classique, les opérateurs forcent simplement un nouvel enregistrement MFA pendant l'appel au help-desk, annulant le token existant de l'utilisateur. Toute invite de connexion suivante paraît légitime pour la victime.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Surveiller les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d'intervalle depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le clipboard de la victime depuis une page web compromise ou typosquattée, puis tromper l'utilisateur pour qu'il les colle dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant du code arbitraire sans aucun téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Les opérateurs placent de plus en plus leurs flux de phishing derrière une vérification simple de l'appareil afin que les crawlers desktop n'atteignent jamais les pages finales. Un schéma courant est un petit script qui teste pour un touch-capable DOM et envoie le résultat à un server endpoint ; les clients non‑mobile reçoivent HTTP 500 (ou une page vide), tandis que les utilisateurs mobiles se voient servir le flux complet.

Extrait client minimal (logique typique):
```html
<script src="/static/detect_device.js"></script>
```
Logique de `detect_device.js` (simplifiée) :
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- Crée un cookie de session lors du premier chargement.
- Accepts `POST /detect {"is_mobile":true|false}`.
- Retourne 500 (ou un espace réservé) aux GET suivants lorsque `is_mobile=false` ; ne sert le phishing que si `true`.

Hunting and detection heuristics:
- Requête urlscan: `filename:"detect_device.js" AND page.status:500`
- Télémétrie web : séquence `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour non‑mobile ; les parcours légitimes de victimes mobile renvoient 200 avec HTML/JS suivant.
- Bloquer ou scruter les pages qui conditionnent le contenu exclusivement sur `ontouchstart` ou des vérifications d'appareil similaires.

Defence tips:
- Exécuter des crawlers avec des empreintes simulant un mobile et le JS activé pour révéler le contenu restreint.
- Alerter sur les réponses 500 suspectes suite à `POST /detect` sur des domaines nouvellement enregistrés.

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
