# Μεθοδολογία Phishing

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon του θύματος
1. Επιλέξτε το **victim domain**.
2. Πραγματοποιήστε κάποια βασική web enumeration **ψάχνοντας για login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **υποδυθείτε**.
3. Χρησιμοποιήστε **OSINT** για να **βρείτε διευθύνσεις email**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing
2. **Διαμορφώστε τις εγγραφές** που σχετίζονται με την υπηρεσία email (SPF, DMARC, DKIM, rDNS)
3. Ρυθμίστε το VPS με **gophish**
3. Προετοιμάστε την καμπάνια
1. Προετοιμάστε το **email template**
2. Προετοιμάστε τη **web page** για να υποκλέψετε τα διαπιστευτήρια
4. Εκκινήστε την καμπάνια!

## Generate similar domain names or buy a trusted domain

### Τεχνικές παραλλαγής ονόματος domain

- **Keyword**: Το domain name **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Αντικαταστήστε την **τελεία με παύλα** ενός subdomain (e.g., www-zelster.com).
- **New TLD**: Το ίδιο domain χρησιμοποιώντας ένα **νέο TLD** (e.g., zelster.org)
- **Homoglyph**: Αντικαθιστά ένα γράμμα στο domain name με **γράμματα που μοιάζουν** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ανταλλάσσει δύο γράμματα εντός του domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του domain name (e.g., zeltsers.com).
- **Omission**: Αφαιρεί ένα από τα γράμματα στο domain name (e.g., zelser.com).
- **Repetition:** Επαναλαμβάνει ένα από τα γράμματα στο domain name (e.g., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο κρυφό. Αντικαθιστά ένα από τα γράμματα στο domain name, ίσως με γράμμα κοντά στο αρχικό πάνω στο πληκτρολόγιο (e.g, zektser.com).
- **Subdomained**: Εισάγει μια **τελεία** μέσα στο domain name (e.g., ze.lster.com).
- **Insertion**: Εισάγει ένα γράμμα μέσα στο domain name (e.g., zerltser.com).
- **Missing dot**: Προσθέτει την TLD στο τέλος του domain name. (e.g., zelstercom.com)

**Αυτόματα Εργαλεία**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Ιστοσελίδες**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει η **πιθανότητα ότι κάποιο bit που αποθηκεύεται ή βρίσκεται σε επικοινωνία να αλλάξει αυτόματα** λόγω διάφορων παραγόντων όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η ιδέα **εφαρμόζεται σε DNS requests**, είναι πιθανό ότι το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που αρχικά ζητήθηκε.

Για παράδειγμα, μια μεμονωμένη τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι επιτιθέμενοι μπορεί να **εκμεταλλευτούν αυτό καταχωρώντας πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Μπορείτε να ψάξετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που θα αγοράσετε **έχει ήδη καλό SEO** μπορείτε να ελέγξετε πως κατηγοριοποιείται σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εντοπισμός Διευθύνσεων Email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **ανακαλύψετε περισσότερες** έγκυρες διευθύνσεις email ή να **επαληθεύσετε αυτές** που έχετε ήδη βρει, μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στους smtp servers του θύματος. [Μάθετε πώς να επαληθεύετε/ανακαλύπτετε διευθύνσεις email εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχάσετε ότι αν οι χρήστες χρησιμοποιούν **κάποιο web portal για να έχουν πρόσβαση στα mails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force**, και να εκμεταλλευτείτε την ευπάθεια αν είναι δυνατό.

## Ρύθμιση GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός για τον admin χρήστη στην έξοδο για την πόρτα 3333. Επομένως, προσπελάστε αυτήν την πόρτα και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε τον κωδικό του admin. Ίσως χρειαστεί να κάνετε tunnel αυτή την πόρτα τοπικά:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Ρύθμιση πιστοποιητικού TLS**

Πριν από αυτό το βήμα θα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και αυτό πρέπει να **δείχνει** στη **διεύθυνση IP του VPS** όπου ρυθμίζετε το **gophish**.
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
**Διαμόρφωση αλληλογραφίας**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Έπειτα προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** στο domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε ένα **DNS A record** για το `mail.<domain>` που δείχνει στη **διεύθυνση IP** του VPS και ένα **DNS MX** record που δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish διαμόρφωση**

Διακόψτε την εκτέλεση του gophish και ας το διαμορφώσουμε.\
Τροποποιήστε `/opt/gophish/config.json` ως εξής (σημειώστε τη χρήση του https):
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
**Ρυθμίστε την υπηρεσία gophish**

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
## Ρύθμιση mail server και domain

### Περίμενε και γίνε αξιόπιστος

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Γι' αυτό πρέπει να περιμένεις όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν το phishing assessment. Επιπλέον, αν τοποθετήσεις μια σελίδα σχετική με έναν τομέα που έχει καλή φήμη, η συνολική φήμη θα είναι καλύτερη.

Σημείωση: ακόμη κι αν πρέπει να περιμένεις μια εβδομάδα, μπορείς να ολοκληρώσεις τώρα όλες τις ρυθμίσεις.

### Ρύθμιση Reverse DNS (rDNS) record

Δημιούργησε ένα rDNS (PTR) record που επιλύει τη διεύθυνση IP του VPS στο domain.

### Sender Policy Framework (SPF) Record

Πρέπει να **διαμορφώσεις μια SPF record για το νέο domain**. Αν δεν ξέρεις τι είναι μια SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείς να χρησιμοποιήσεις [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσεις την πολιτική SPF σου (χρησιμοποίησε την IP του VPS)

![](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να τεθεί μέσα σε ένα TXT record στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Πρέπει να **διαμορφώσετε ένα DMARC record για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα DNS TXT record που δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο domain**. Εάν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να ενώσετε και τις δύο τιμές B64 που παράγει το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Δοκιμάστε τη βαθμολογία της διαμόρφωσης του email σας

Μπορείτε να το κάνετε χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Απλώς επισκεφθείτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη ρύθμιση του ηλεκτρονικού ταχυδρομείου σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** την θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Μπορείτε επίσης να στείλετε **μήνυμα σε λογαριασμό Gmail που έχετε υπό τον έλεγχό σας**, και να ελέγξετε τις **κεφαλίδες του email** στον φάκελο εισερχομένων του Gmail σας — το `dkim=pass` πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Αφαίρεση από τη Μαύρη Λίστα του Spamhouse

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας δείξει αν το domain σας μπλοκάρεται από spamhouse. Μπορείτε να αιτηθείτε την αφαίρεση του domain/IP σας στο: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Μαύρη Λίστα της Microsoft

​​Μπορείτε να αιτηθείτε την αφαίρεση του domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Εκστρατείας GoPhish

### Sending Profile

- Ορίστε ένα **όνομα για αναγνώριση** του προφίλ αποστολέα
- Αποφασίστε από ποιο λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνίσταται να χρησιμοποιήσετε τη λειτουργία "Send Test Email" για να ελέγξετε ότι όλα λειτουργούν.\
> Συστήνω να στέλνετε τα test emails σε διευθύνσεις 10min mails για να αποφύγετε να μπλοκαριστείτε κατά τις δοκιμές.

### Email Template

- Ορίστε ένα **όνομα για αναγνώριση** του προτύπου
- Στη συνέχεια γράψτε ένα **θέμα** (τίποτα περίεργο, απλά κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε επιλέξει "**Add Tracking Image**"
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
Σημειώστε ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **διεύθυνση που δεν υπάρχει** και ελέγξτε αν η απάντηση περιέχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με **κάποιο έγκυρο εντοπισμένο** email και περιμένετε την απάντηση

![](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης να **επισυνάψετε αρχεία για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας κάποια ειδικά κατασκευασμένα αρχεία/έγγραφα [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της σελίδας. Σημειώστε ότι μπορείτε να **εισάγετε** web pages.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε κάποιες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να είστε ευχαριστημένοι με το αποτέλεσμα.** Στη συνέχεια, γράψτε εκείνον τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι αν χρειαστεί να **χρησιμοποιήσετε κάποιον static resource** για το HTML (ίσως κάποιο CSS και JS) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και μετά να τα προσεγγίσετε από _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην νόμιμη κύρια σελίδα** του θύματος, ή να τους ανακατευθύνετε στο _/static/migration.html_ για παράδειγμα, βάλτε έναν **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και μετά υποδείξτε ότι η διαδικασία ήταν επιτυχής**.

### Users & Groups

- Ορίστε ένα όνομα
- **Εισάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το template για το παράδειγμα χρειάζεστε το firstname, last name και email address κάθε χρήστη)

![](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και την group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα αποσταλεί στα θύματα

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή ενός test email για να δείτε πώς θα φαίνεται το τελικό phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Θα σύστηνα να **στείλετε τα test emails σε 10min mails διευθύνσεις** ώστε να αποφύγετε να μπλοκαριστείτε κατά τις δοκιμές.

Μόλις όλα είναι έτοιμα, απλώς ξεκινήστε την campaign!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε την ιστοσελίδα δείτε την παρακάτω σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε κάποιες phishing αξιολογήσεις (κυρίως για Red Teams) θα θελήσετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως κάτι που θα πυροδοτήσει ένα authentication).\
Δείτε την παρακάτω σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς πλαστογραφείτε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισάγει τον σωστό κωδικό ή αν η εφαρμογή που πλαστογράφησατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να εξαπατήσετε τον χρήστη**.

Εδώ εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena) είναι χρήσιμα. Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια MitM επίθεση. Βασικά, η επίθεση λειτουργεί ως εξής:

1. Εσείς **πλαστογραφείτε τη φόρμα login** της πραγματικής σελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη ψεύτικη σελίδα σας και το εργαλείο τα προωθεί στην πραγματική σελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η MitM σελίδα θα το ζητήσει και μόλις ο **χρήστης το εισάγει** το εργαλείο θα το στείλει στην πραγματική σελίδα.
4. Μόλις ο χρήστης αυθεντικοποιηθεί εσείς (ως επιτιθέμενος) θα έχετε **συλλέξει τα credentials, το 2FA, το cookie και οποιαδήποτε πληροφορία** από κάθε αλληλεπίδραση ενώ το εργαλείο εκτελεί MitM.

### Via VNC

Τι γίνεται αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση της πρωτότυπης, τον στείλετε σε μια **VNC συνεδρία με έναν browser συνδεδεμένο στην πραγματική σελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιείται, τα cookies...\
Αυτό μπορείτε να το κάνετε με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους για να ξέρετε αν σας έχουν ανακαλύψει είναι να **ψάξετε το domain σας μέσα σε blacklists**. Αν εμφανίζεται καταχωρημένο, με κάποιο τρόπο το domain σας εντοπίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να καταλάβετε αν το θύμα **αναζητά ενεργά ύποπτη phishing δραστηριότητα** όπως εξηγείται σε:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε **να αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε **που να περιέχει** την **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιονδήποτε τύπο **DNS ή HTTP αλληλεπίδρασης** με αυτά, θα καταλάβετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Evaluate the phishing

Χρησιμοποιήστε [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας πρόκειται να καταλήξει στο φάκελο spam ή αν θα μπλοκαριστεί ή θα πετύχει.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Σύγχρονα intrusion sets ολοένα και συχνότερα παραλείπουν εντελώς τα email lures και **στοχεύουν άμεσα τη ροή εργασίας service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο χειριστής αποκτήσει έγκυρα credentials pivotάρει με ενσωματωμένο admin tooling – δεν απαιτείται malware.

### Attack flow
1. Recon του θύματος
* Συλλογή προσωπικών & εταιρικών στοιχείων από LinkedIn, data breaches, public GitHub, κ.λπ.
* Εντοπισμός high-value ταυτοτήτων (executives, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset password / MFA.
2. Real-time social engineering
* Τηλεφωνικά, Teams ή chat στο help-desk ενώ μιμείστε τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παροχή των προ-συλλεγμένων PII για να περάσετε την επαλήθευση βασισμένη στη γνώση.
* Πείστε τον agent να **επαναφέρει το MFA secret** ή να πραγματοποιήσει **SIM-swap** σε έναν καταχωρημένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικά περιστατικά)
* Εγκατάσταση foothold μέσω οποιουδήποτε web SSO portal.
* Επεξεργασία AD / AzureAD με ενσωματωμένα εργαλεία (χωρίς πτώση δυαδικών αρχείων):
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
* Θεωρήστε την identity recovery του help-desk ως **privileged operation** – απαιτήστε step-up auth & έγκριση manager.
* Αναπτύξτε **Identity Threat Detection & Response (ITDR)** / **UEBA** κανόνες που θα ειδοποιούν για:
* Αλλαγή μεθόδου MFA + authentication από νέα συσκευή / γεωγραφική θέση.
* Άμεση ανύψωση δικαιωμάτων του ίδιου principal (user→admin).
* Καταγράψτε κλήσεις help-desk και επιβάλετε **call-back σε ήδη καταχωρημένο αριθμό** πριν οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι πρόσφατα επαναρυθμισμένοι λογαριασμοί να μην κληρονομούν αυτόματα tokens υψηλών προνομίων.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Ομάδες commodity αντισταθμίζουν το κόστος των high-touch ops με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης & δίκτυα διαφημίσεων σε κανάλι παράδοσης**.

1. **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα όπως `chromium-update[.]site` στα κορυφαία search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που έχει δει η Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies + credential DBs, και έπειτα τραβάει έναν **σιωπηλό loader** ο οποίος αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Μπλοκάρετε newly-registered domains & επιβάλετε **Advanced DNS / URL Filtering** σε *search-ads* καθώς και σε e-mail.
* Περιορίστε την εγκατάσταση λογισμικού σε signed MSI / Store πακέτα, απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθείτε για child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Κυνήγι για LOLBins που χρησιμοποιούνται συχνά από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Οι επιτιθέμενοι πλέον αλυσσοδένουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα απο αποδεδειγμένα μη-έμπιστα automation (μέσω ARC/DKIM ανωμαλιών).  
• Αναπτύξτε **voice-biometric challenge phrases** για αιτήματα υψηλού ρίσκου μέσω τηλεφώνου.  
• Συνεχίστε να προσομοιώνετε AI-generated lures σε προγράμματα ευαισθητοποίησης – τα στατικά templates είναι απαρχαιωμένα.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι χειριστές απλώς **αναγκάζουν μια νέα εγγραφή MFA** κατά τη διάρκεια της κλήσης στο help-desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επόμενο prompt σύνδεσης φαίνεται νόμιμο στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε για AzureAD/AWS/Okta γεγονότα όπου **`deleteMFA` + `addMFA`** συμβαίνουν **εντός λίγων λεπτών από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι attackers μπορούν σιωπηλά να αντιγράψουν κακόβουλες εντολές στο πρόχειρο του θύματος από μια συμβιβασμένη ή typosquatted σελίδα web και στη συνέχεια να ξεγελάσουν τον χρήστη να τις επικολλήσει μέσα σε **Win + R**, **Win + X** ή ένα terminal window, εκτελώντας αυθαίρετο κώδικα χωρίς καμία λήψη ή συνημμένο.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Οι operators τοποθετούν όλο και πιο συχνά έναν απλό έλεγχο συσκευής πριν από τις ροές phishing τους, ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα συνηθισμένο μοτίβο είναι ένα μικρό script που ελέγχει αν το DOM υποστηρίζει αφής (touch-capable DOM) και στέλνει το αποτέλεσμα σε ένα server endpoint· οι μη‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ οι mobile users εξυπηρετούνται με ολόκληρη τη ροή.

Μικρό απόσπασμα πελάτη (τυπική λογική):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` λογική (απλοποιημένη):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Συμπεριφορά διακομιστή που παρατηρείται συχνά:
- Θέτει ένα session cookie κατά το πρώτο φόρτωμα.
- Accepts `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (or placeholder) σε επόμενα GETs όταν `is_mobile=false`; εξυπηρετεί phishing μόνο αν `true`.

Σημεία ανίχνευσης και heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: αλληλουχία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη‑mobile· νόμιμες διαδρομές θυμάτων σε mobile επιστρέφουν 200 με επακόλουθο HTML/JS.
- Μπλοκάρετε ή ελέγξτε σχολαστικά σελίδες που προσαρμόζουν περιεχόμενο αποκλειστικά βάσει του `ontouchstart` ή παρόμοιων ελέγχων συσκευής.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με mobile‑like fingerprints και JS ενεργοποιημένο για να αποκαλύψετε αποκλεισμένο περιεχόμενο.
- Ειδοποιήστε για ύποπτες 500 απαντήσεις μετά το `POST /detect` σε newly registered domains.

## Αναφορές

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
