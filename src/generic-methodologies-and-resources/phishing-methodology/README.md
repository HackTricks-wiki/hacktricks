# Phishing Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon του θύματος
1. Επιλέξτε το **victim domain**.
2. Εκτελέστε βασική web enumeration **αναζητώντας login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **impersonate**.
3. Χρησιμοποιήστε **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Buy the domain** που πρόκειται να χρησιμοποιήσετε για την phishing αξιολόγηση
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure το VPS με **gophish**
3. Προετοιμάστε την καμπάνια
1. Προετοιμάστε το **email template**
2. Προετοιμάστε τη **web page** για να κλέψετε τα credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το domain name **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (π.χ., zelster.com-management.com).
- **hypened subdomain**: Αλλάξτε την **τελεία σε παύλα** ενός subdomain (π.χ., www-zelster.com).
- **New TLD**: Το ίδιο domain χρησιμοποιώντας **νέο TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain με **γράμματα που μοιάζουν** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Ανταλλάσσει δύο γράμματα** μέσα στο domain name (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του domain name (π.χ., zeltsers.com).
- **Omission**: **Αφαιρεί ένα** από τα γράμματα του domain name (π.χ., zelser.com).
- **Repetition:** **Επαναλαμβάνει ένα** από τα γράμματα στο domain name (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο stealthy. Αντικαθιστά ένα από τα γράμματα στο domain name, πιθανώς με γράμμα κοντά στο αρχικό πάνω στο keyboard (π.χ., zektser.com).
- **Subdomained**: Εισάγει μια **τελεία** μέσα στο domain name (π.χ., ze.lster.com).
- **Insertion**: **Εισάγει ένα γράμμα** μέσα στο domain name (π.χ., zerltser.com).
- **Missing dot**: Προσθέτει το TLD αμέσως μετά το domain name. (π.χ., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει η **πιθανότητα ότι κάποιοι bits που αποθηκεύονται ή βρίσκονται σε επικοινωνία να αντιστραφούν αυτόματα** λόγω διαφόρων παραγόντων όπως ηλιακές εκρήξεις, cosmic rays ή hardware errors.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι πιθανό ότι το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που αρχικά ζητήθηκε.

Για παράδειγμα, μια μεμονωμένη τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι attackers μπορεί να **εκμεταλλευτούν αυτό δημιουργώντας και καταχωρώντας πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του θύματος. Η πρόθεσή τους είναι να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Μπορείτε να ψάξετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που θα αγοράσετε **έχει ήδη καλό SEO** μπορείτε να ελέγξετε πώς είναι κατηγοριοποιημένο σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **ανακαλύψετε περισσότερα** έγκυρα email addresses ή να **επαληθεύσετε αυτά** που έχετε ήδη ανακαλύψει μπορείτε να ελέγξετε αν μπορείτε να τα brute-force στους smtp servers του θύματος. [Μάθετε πώς να επαληθεύετε/ανακαλύπτετε email address εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχάσετε ότι αν οι χρήστες χρησιμοποιούν **οποιοδήποτε web portal για πρόσβαση στα mails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force**, και να εκμεταλλευτείτε το αν είναι δυνατό.

## Configuring GoPhish

### Installation

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε `/opt/gophish/gophish`\
Θα σας δοθεί ένα password για τον admin user στην port 3333 στην έξοδο. Συνεπώς, προσπελάστε αυτή την port και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε το admin password. Ίσως χρειαστεί να tunnel αυτή την port τοπικά:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και να **δείχνει** στην **IP του VPS** όπου διαμορφώνετε το **gophish**.
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

Έπειτα προσθέστε το domain στα παρακάτω αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** στο domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε μια **DNS A record** για το `mail.<domain>` που δείχνει στη **διεύθυνση IP** του VPS και μια **DNS MX** εγγραφή που δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

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
**Διαμόρφωση της υπηρεσίας gophish**

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
## Ρύθμιση mail server και domain

### Περίμενε & να είσαι νόμιμος

Όσο πιο παλιό είναι ένα domain, τόσο λιγότερο πιθανό είναι να πιαστεί ως spam. Γι' αυτό πρέπει να περιμένεις όσο περισσότερο γίνεται (τουλάχιστον 1 εβδομάδα) πριν την αξιολόγηση phishing. Επιπλέον, αν βάλεις μια σελίδα σε έναν τομέα με καλή φήμη, η απόκτηση καλής φήμης θα είναι ευκολότερη.

Σημείωσε ότι ακόμη κι αν χρειαστεί να περιμένεις μια εβδομάδα, μπορείς να ολοκληρώσεις τώρα όλες τις ρυθμίσεις.

### Configure Reverse DNS (rDNS) record

Ρύθμισε ένα rDNS (PTR) record που θα επιλύει τη διεύθυνση IP του VPS στο domain name.

### Sender Policy Framework (SPF) Record

Πρέπει να **διαμορφώσεις ένα SPF record για το νέο domain**. Αν δεν ξέρεις τι είναι ένα SPF record [**διάβασε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείς να χρησιμοποιήσεις [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσεις την πολιτική SPF σου (χρησιμοποίησε την IP της μηχανής VPS)

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

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που παράγει το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Ελέγξτε τη βαθμολογία διαμόρφωσης του email σας

Μπορείτε να το κάνετε χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com/)\ Απλώς μπείτε στη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη ρύθμιση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** την πόρτα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Μπορείτε επίσης να στείλετε **μήνυμα σε ένα Gmail που ελέγχετε**, και να ελέγξετε τις **κεφαλίδες του email** στο inbox σας στο Gmail, το `dkim=pass` πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Αφαίρεση από το Spamhouse Blacklist

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας υποδείξει αν το domain σας αποκλείεται από το Spamhaus. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Microsoft Blacklist

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Καμπάνιας GoPhish

### Sending Profile

- Ορίστε ένα **όνομα για αναγνώριση** του προφίλ αποστολέα
- Αποφασίστε από ποιο account θα στέλνετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά τα username και password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Συστήνω να **στείλετε τα test emails σε διευθύνσεις 10min mails** ώστε να αποφύγετε το blacklisting κατά τις δοκιμές.

### Email Template

- Ορίστε ένα **όνομα για αναγνώριση** του template
- Γράψτε ένα **subject** (τίποτα περίεργο, κάτι που θα περίμενε να διαβάσει κανείς σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε επιλέξει "**Add Tracking Image**"
- Γράψτε το **email template** (μπορείτε να χρησιμοποιήσετε μεταβλητές όπως στο παρακάτω παράδειγμα):
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
Σημειώστε ότι **για να αυξηθεί η αξιοπιστία του email**, συστήνεται να χρησιμοποιήσετε κάποια υπογραφή από ένα email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **ανύπαρκτη διεύθυνση** και ελέγξτε αν η απάντηση έχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με **κάποια έγκυρη ανακαλυφθείσα** διεύθυνση email και περιμένετε την απάντηση.

![](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης να **επισυνάπτετε αρχεία για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας ειδικά κατασκευασμένα αρχεία/έγγραφα, [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισαγάγετε/import** ιστοσελίδες.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε μερικά τοπικά tests (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να μείνετε ικανοποιημένοι με τα αποτελέσματα.** Έπειτα, επικολλήστε αυτόν τον HTML κώδικα στο πεδίο.\
> Σημειώστε ότι αν χρειάζεστε **στατικά resources** για το HTML (όπως CSS και JS αρχεία) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και μετά να τα προσεγγίσετε από _**/static/\<filename>**_

> [!TIP]
> Για τη redirection μπορείτε να **ανακατευθύνετε τους χρήστες στην νόμιμη κύρια σελίδα** του θύματος, ή να τους ανακατευθύνετε στο _/static/migration.html_ για παράδειγμα, βάλτε ένα **spinning wheel** ([https://loading.io/](https://loading.io)) για 5 δευτερόλεπτα και μετά δείξτε ότι η διαδικασία ήταν επιτυχής.

### Users & Groups

- Ορίστε ένα όνομα
- **Import the data** (σημειώστε ότι για να χρησιμοποιήσετε το template στο παράδειγμα χρειάζεστε το firstname, last name και email address κάθε χρήστη)

![](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια καμπάνια επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και την ομάδα. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα.

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή ενός test email για να δείτε πώς θα φαίνεται το τελικό phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Προτείνω να **στέλνετε τα test emails σε 10min mails διευθύνσεις** για να αποφύγετε τη μαύρη λίστα κατά τις δοκιμές.

Μόλις όλα είναι έτοιμα, απλώς ξεκινήστε την καμπάνια!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε την ιστοσελίδα, ελέγξτε την παρακάτω σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε κάποιες phishing αξιολογήσεις (κυρίως για Red Teams) μπορεί να θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή απλά κάτι που θα ενεργοποιεί μια authentication).\
Δείτε την παρακάτω σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς προσποιείστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισάγει το σωστό password ή αν η εφαρμογή που μιμήθηκες είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να μιμηθείτε τον παραπλανημένο χρήστη**.

Εδώ είναι χρήσιμα εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια MitM επίθεση. Βασικά, η επίθεση λειτουργεί ως εξής:

1. Εσείς **παριστάνετε τη φόρμα login** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη fake σελίδα σας και το εργαλείο τα προωθεί στην πραγματική σελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός έχει **2FA**, η MitM σελίδα θα ζητήσει τον κωδικό και μόλις ο **χρήστης τον εισάγει** το εργαλείο θα τον στείλει στην πραγματική σελίδα.
4. Μόλις ο χρήστης αυθεντικοποιηθεί, εσείς (ως attacker) θα έχετε **συλλέξει τα credentials, το 2FA, το cookie και κάθε πληροφορία** από κάθε αλληλεπίδραση ενώ το εργαλείο εκτελεί MitM.

### Via VNC

Τι γίνεται αν αντί να **στέλνετε το θύμα σε μια κακόβουλη σελίδα** με όψη ίδια με την πραγματική, το στέλνετε σε μια **VNC συνεδρία με ένα browser συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους να μάθετε αν έχετε αποκαλυφθεί είναι να **ελέγξετε το domain σας σε μαύρες λίστες**. Αν εμφανιστεί καταχωρημένο, κάπως το domain σας εντοπίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να μάθετε αν το θύμα **αναζητά ενεργά ύποπτη phishing δραστηριότητα** όπως εξηγείται σε:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε εσείς **που περιέχει** τη **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** εκτελέσει οποιαδήποτε ενέργεια DNS ή HTTP με αυτά, θα ξέρετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Evaluate the phishing

Χρησιμοποιήστε [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο spam ή αν θα μπλοκαριστεί ή θα είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Σύγχρονα intrusion sets όλο και περισσότερο παρακάμπτουν εντελώς τα email lures και **στοχεύουν απευθείας τη διαδικασία service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση βασίζεται αποκλειστικά σε “living-off-the-land”: μόλις ο χειριστής αποκτήσει έγκυρα credentials, μετακινείται με τα ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.

### Attack flow
1. Recon του θύματος
* Συλλογή προσωπικών & εταιρικών στοιχείων από LinkedIn, data breaches, δημόσιο GitHub, κ.λπ.
* Εντοπισμός υψηλής αξίας ταυτοτήτων (executives, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset password / MFA.
2. Real-time social engineering
* Τηλέφωνο, Teams ή chat στο help-desk ενώ παριστάνετε το στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παρέχετε τα προ-συλλεγμένα PII για να περάσετε την verification με βάση γνώση.
* Πείστε τον agent να **resetάρει το MFA secret** ή να πραγματοποιήσει **SIM-swap** σε καταχωρημένο κινητό.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικές περιπτώσεις)
* Εγκαταστήστε foothold μέσω οποιουδήποτε web SSO portal.
* Enumerator AD / AzureAD με ενσωματωμένα εργαλεία (χωρίς drop binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement με **WMI**, **PsExec**, ή νόμιμα **RMM** agents που ήδη είναι whitelist στο περιβάλλον.

### Detection & Mitigation
* Αντιμετωπίστε την identity recovery του help-desk ως **privileged operation** – απαιτήστε step-up auth & έγκριση manager.
* Αναπτύξτε **Identity Threat Detection & Response (ITDR)** / **UEBA** κανόνες που ειδοποιούν για:
* Αλλαγή μεθόδου MFA + authentication από νέα συσκευή / γεωγραφία.
* Άμεση άνοδο του ίδιου principal (user-→-admin).
* Καταγράφετε κλήσεις help-desk και επιβάλετε **call-back σε ήδη καταχωρημένο αριθμό** πριν οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι πρόσφατα resetαρισμένοι λογαριασμοί να **μην** κληρονομούν αυτόματα υψηλό-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews μειώνουν το κόστος των high-touch ops με μαζικές επιθέσεις που μετατρέπουν ** τις μηχανές αναζήτησης & δίκτυα διαφημίσεων σε κανάλι παράδοσης**.

1. **SEO poisoning / malvertising** προωθεί ένα fake αποτέλεσμα όπως `chromium-update[.]site` στην κορυφή των search ads.
2. Το θύμα κατεβάζει ένα μικρό **first-stage loader** (συνήθως JS/HTA/ISO). Παραδείγματα που είδε η Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει cookies του browser + credential DBs, και μετά τραβάει έναν **silent loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Μπλοκάρετε newly-registered domains & εφαρμόστε **Advanced DNS / URL Filtering** σε *search-ads* καθώς και σε email.
* Περιορίστε την εγκατάσταση λογισμικού σε υπογεγραμμένα MSI / Store πακέτα, απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Monitor για child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Κυνήγι για LOLBins που συχνά καταχρώνται από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Οι επιτιθέμενοι πλέον συνδέουν **LLM & voice-clone APIs** για πλήρως προσωποποιημένα lures και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα που απεστάλησαν από μη αξιόπιστο automation (μέσω ARC/DKIM ανωμαλιών).  
• Αναπτύξτε **voice-biometric challenge phrases** για high-risk τηλεφωνικά αιτήματα.  
• Προσομοιώνετε συνεχώς AI-generated lures στα awareness προγράμματα – τα στατικά templates είναι obsolete.

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
Εκτός από το κλασικό push-bombing, οι operators απλά **επικυρώνουν ένα νέο MFA registration** κατά τη διάρκεια της κλήσης στο help-desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επόμενο login prompt φαίνεται νόμιμο στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε συμβάντα AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **εντός λεπτών από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν σιωπηλά να αντιγράψουν κακόβουλες εντολές στο clipboard του θύματος από μια compromised ή typosquatted web page και στη συνέχεια να ξεγελάσουν τον χρήστη να τις paste μέσα σε **Win + R**, **Win + X** ή ένα terminal window, εκτελώντας αυθαίρετο κώδικα χωρίς κανένα download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing για να αποφύγουν crawlers/sandboxes
Οι operators όλο και περισσότερο τοποθετούν τις phishing flows πίσω από έναν απλό έλεγχο συσκευής ώστε desktop crawlers να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα κοινό μοτίβο είναι ένα μικρό script που ελέγχει για touch-capable DOM και στέλνει το αποτέλεσμα σε ένα server endpoint· μη‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ mobile users σερβίρονται το πλήρες flow.

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
Συμπεριφορά διακομιστή που συχνά παρατηρείται:
- Κατά το πρώτο φόρτωμα ορίζεται ένα session cookie.
- Δέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν `is_mobile=false`; σερβίρει phishing μόνο αν `true`.

Κανόνες αναζήτησης και ανίχνευσης:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Τηλεμετρία Web: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη‑mobile; οι νόμιμες mobile διαδρομές θυμάτων επιστρέφουν 200 με επακόλουθο HTML/JS.
- Αποκλείστε ή ελέγξτε σχολαστικά σελίδες που προσαρμόζουν το περιεχόμενο αποκλειστικά βάσει `ontouchstart` ή παρόμοιων ελέγχων συσκευής.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με mobile‑like fingerprints και με ενεργοποιημένο JS για να αποκαλύψετε gated content.
- Ειδοποιήστε για ύποπτες απαντήσεις 500 που ακολουθούν `POST /detect` σε πρόσφατα εγγεγραμμένα domains.

## Αναφορές

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
