# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon του θύματος
1. Επιλέξτε το **victim domain**.
2. Εκτελέστε κάποια βασική web enumeration **αναζητώντας πύλες σύνδεσης** που χρησιμοποιεί το θύμα και **αποφασίστε** ποια θα **παραστήσετε**.
3. Χρησιμοποιήστε OSINT για να **εντοπίσετε διευθύνσεις email**.
2. Προετοιμάστε το περιβάλλον
1. **Buy the domain** που θα χρησιμοποιήσετε για την phishing αξιολόγηση
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με **gophish**
3. Προετοιμάστε την καμπάνια
1. Ετοιμάστε το **email template**
2. Ετοιμάστε τη **web page** για να υποκλέψετε τα διαπιστευτήρια
4. Ξεκινήστε την καμπάνια!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το όνομα domain **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Αλλάξτε την **τελεία για παύλα** ενός subdomain (e.g., www-zelster.com).
- **New TLD**: Το ίδιο domain χρησιμοποιώντας ένα **new TLD** (e.g., zelster.org)
- **Homoglyph**: Αντικαθιστά ένα γράμμα στο όνομα domain με **γράμματα που μοιάζουν** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ανταλλάσσει **δύο γράμματα** μέσα στο όνομα domain (e.g., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του ονόματος domain (e.g., zeltsers.com).
- **Omission**: Αφαιρεί **ένα** από τα γράμματα του ονόματος domain (e.g., zelser.com).
- **Repetition:** Επαναλαμβάνει **ένα** από τα γράμματα στο όνομα domain (e.g., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο διακριτικό. Αντικαθιστά ένα από τα γράμματα στο όνομα domain, ίσως με γράμμα κοντά στο αρχικό στο πληκτρολόγιο (e.g, zektser.com).
- **Subdomained**: Εισάγει μια **τελεία** μέσα στο όνομα domain (e.g., ze.lster.com).
- **Insertion**: Εισάγει **ένα γράμμα** στο όνομα domain (e.g., zerltser.com).
- **Missing dot**: Προσθέτει το TLD στο όνομα domain χωρίς τελεία. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει η **πιθανότητα ότι κάποιο από τα bits που αποθηκεύονται ή διακινούνται να αναστραφεί αυτόματα** λόγω διάφορων παραγόντων όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS αιτήματα**, είναι πιθανό ότι το **domain που λαμβάνει ο DNS server** δεν είναι το ίδιο με το αρχικά ζητηθέν domain.

Για παράδειγμα, μια μόνo bit τροποποίηση στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι επιτιθέμενοι μπορεί να **εκμεταλλευτούν αυτό καταχωρίζοντας πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Μπορείτε να ψάξετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO** μπορείτε να ελέγξετε πώς είναι κατηγοριοποιημένο σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εντοπισμός διευθύνσεων email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **εντοπίσετε περισσότερες** έγκυρες διευθύνσεις email ή να **επαληθεύσετε αυτές** που έχετε ήδη εντοπίσει, μπορείτε να ελέγξετε αν μπορείτε να τις brute-force στους smtp servers του θύματος. [Μάθετε πώς να επαληθεύσετε/εντοπίσετε διεύθυνση email εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχάσετε ότι αν οι χρήστες χρησιμοποιούν **κάποια web portal για να έχουν πρόσβαση στα mail τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force**, και να εκμεταλλευτείτε την ευπάθεια αν είναι δυνατό.

## Διαμόρφωση GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός για τον admin user στο port 3333 στην έξοδο. Επομένως, προσπελάστε αυτό το port και χρησιμοποιήστε αυτά τα credentials για να αλλάξετε τον admin password. Ενδέχεται να χρειαστεί να κάνετε tunnel αυτό το port τοπικά:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα θα πρέπει να έχετε **ήδη αγοράσει το domain** που θα χρησιμοποιήσετε και πρέπει να **δείχνει** στην **IP του VPS** όπου ρυθμίζετε το **gophish**.
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

Στη συνέχεια προσθέστε το domain στα εξής αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** στο domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε μια **DNS A record** για `mail.<domain>` που δείχνει στη **διεύθυνση ip** του VPS και μια **DNS MX** εγγραφή που δείχνει σε `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish διαμόρφωση**

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
Ολοκληρώστε τη ρύθμιση της υπηρεσίας και τον έλεγχό της κάνοντας:
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
## Διαμόρφωση διακομιστή αλληλογραφίας και domain

### Περίμενε & να είσαι νόμιμος

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Συνεπώς, πρέπει να περιμένεις όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν την phishing αξιολόγηση. Επιπλέον, αν ανεβάσεις μία σελίδα σχετική με έναν τομέα με καλή φήμη, η αποκτούμενη φήμη θα είναι καλύτερη.

Σημείωση ότι ακόμα κι αν πρέπει να περιμένεις μία εβδομάδα, μπορείς να ολοκληρώσεις τώρα όλη τη διαμόρφωση.

### Διαμόρφωση Reverse DNS (rDNS) record

Ρύθμισε ένα rDNS (PTR) record που αντιστοιχίζει τη διεύθυνση IP του VPS στο domain name.

### Sender Policy Framework (SPF) Record

Πρέπει **να ρυθμίσεις ένα SPF record για το νέο domain**. If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείς να χρησιμοποιήσεις [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσεις την πολιτική SPF σου (χρησιμοποίησε τη διεύθυνση IP της μηχανής VPS)

![](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να καταχωρηθεί μέσα σε ένα TXT record στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Εγγραφή DMARC (Domain-based Message Authentication, Reporting & Conformance)

Πρέπει να **διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα DNS TXT εγγραφή που δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Δοκιμάστε το σκορ διαμόρφωσης του email σας

Μπορείτε να το κάνετε χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς μπείτε στη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη ρύθμιση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** port **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Μπορείτε επίσης να στείλετε **μήνυμα σε έναν λογαριασμό Gmail που έχετε υπό τον έλεγχό σας**, και να ελέγξετε τις **κεφαλίδες του email** στο inbox του Gmail σας, `dkim=pass` πρέπει να είναι παρόν στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Αφαίρεση από Spamhouse Blacklist

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας δείξει αν το domain σας αποκλείεται από το spamhouse. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από Microsoft Blacklist

Μπορείτε να ζητήσετε την αφαίρεση του domain/IP στη διεύθυνση [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση GoPhish Campaign

### Προφίλ Αποστολής

- Ορίστε ένα **όνομα για αναγνώριση** του προφίλ αποστολέα
- Αποφασίστε από ποιον λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα πρότεινα να **στείλετε τα test emails σε διευθύνσεις 10min mails** για να αποφύγετε να μπείτε σε blacklist κάνοντας δοκιμές.

### Πρότυπο Email

- Ορίστε ένα **όνομα για αναγνώριση** του προτύπου
- Στη συνέχεια γράψτε ένα **subject** (τίποτα περίεργο, απλώς κάτι που θα περιμένατε να δείτε σε ένα κανονικό email)
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
Σημειώστε ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από ένα πραγματικό email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **μη υπαρκτή διεύθυνση** και ελέγξτε αν η απάντηση περιέχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με **κάποιον έγκυρο ανακαλυφθέν** email και περιμένετε την απάντηση

![](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επίσης επιτρέπει να **επισυνάψετε αρχεία προς αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας κάποια ειδικά δημιουργημένα αρχεία/έγγραφα, διαβάστε αυτή τη σελίδα: [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της σελίδας. Σημειώστε ότι μπορείτε να **import** web pages.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **έως ότου μείνετε ικανοποιημένοι με το αποτέλεσμα.** Έπειτα, γράψτε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι αν χρειάζεστε να **χρησιμοποιήσετε στατικά resources** για το HTML (όπως CSS και JS αρχεία) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και μετά να τα προσπελάσετε από _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε **να κατευθύνετε τους χρήστες στην νόμιμη κύρια σελίδα** του θύματος, ή να τους κατευθύνετε στο _/static/migration.html_ για παράδειγμα, να βάλετε έναν **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και μετά να υποδείξετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Users & Groups

- Ορίστε ένα όνομα
- **Import the data** (σημειώστε ότι για να χρησιμοποιήσετε το template στο παράδειγμα χρειάζεστε το firstname, last name και email address κάθε χρήστη)

![](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και την group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή ενός test email για να δείτε πώς θα φαίνεται το τελικό phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Θα πρότεινα να **στείλετε τα test emails σε 10min mails διευθύνσεις** προκειμένου να αποφύγετε το να μπείτε σε blacklist κατά τις δοκιμές.

Μόλις όλα είναι έτοιμα, απλώς ξεκινήστε την campaign!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε τον ιστότοπο ελέγξτε την παρακάτω σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένες phishing αξιολογήσεις (κυρίως για Red Teams) μπορεί να θελήσετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως κάτι που θα ενεργοποιήσει αυθεντικοποίηση).\
Δείτε την παρακάτω σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς πλαστογραφείτε μια πραγματική ιστοσελίδα και συγκεντρώνετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισάγει τον σωστό κωδικό ή αν η εφαρμογή που πλαστογράφησε έχει ενεργοποιημένο 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να προσποιηθείτε τον παραπλανημένο χρήστη**.

Εδώ είναι χρήσιμα εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια MitM επίθεση. Βασικά, η επίθεση λειτουργεί ως εξής:

1. Εσείς **πλαστογραφείτε τη φόρμα login** της πραγματικής σελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη ψεύτικη σελίδα και το εργαλείο τα προωθεί στην πραγματική σελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός έχει ρυθμιστεί με **2FA**, η MitM σελίδα θα το ζητήσει και μόλις ο **χρήστης το εισάγει** το εργαλείο θα το στείλει στην πραγματική σελίδα.
4. Μόλις ο χρήστης αυθεντικοποιηθεί, εσείς (ως επιτιθέμενος) θα έχετε **συλλέξει τα credentials, το 2FA, το cookie και οποιαδήποτε πληροφορία** από κάθε αλληλεπίδραση ενώ το εργαλείο εκτελεί MitM.

### Via VNC

Τι γίνεται αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με πανομοιότυπη εμφάνιση, τον στείλετε σε μια **VNC συνεδρία με έναν browser συνδεδεμένο στην πραγματική σελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους να μάθετε αν σας έχουν εντοπίσει είναι να **αναζητήσετε το domain σας μέσα σε blacklists**. Αν εμφανιστεί, με κάποιον τρόπο το domain σας ανιχνεύτηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να μάθετε αν το θύμα **ενεργά ψάχνει για ύποπτη phishing δραστηριότητα στο wild** όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε **να αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχεται από εσάς **που να περιέχει** το **keyword** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιονδήποτε τύπο **DNS ή HTTP interaction** με αυτά, θα ξέρετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Evaluate the phishing

Χρησιμοποιήστε το [**Phishious**](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας πρόκειται να καταλήξει στο φάκελο spam ή αν πρόκειται να μπλοκαριστεί ή να είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Σύγχρονα intrusion sets ολοένα και περισσότερο παρακάμπτουν εντελώς τα email lures και **στοχεύουν απευθείας τη ροή εργασίας του service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο χειριστής αποκτήσει έγκυρα credentials, μετακινείται με ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.

### Attack flow
1. Recon του θύματος
* Συλλογή προσωπικών & εταιρικών στοιχείων από LinkedIn, data breaches, public GitHub, κ.λπ.
* Εντοπισμός υψηλής αξίας ταυτοτήτων (εκτελεστικά στελέχη, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset κωδικού / MFA.
2. Real-time social engineering
* Τηλεφωνικά, Teams ή chat στο help-desk ενώ προσποιείστε τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παροχή των προηχοποιημένων PII για να περάσετε την επαλήθευση βάσει γνώσης.
* Πείστε τον agent να **reset-άρει το MFA secret** ή να εκτελέσει **SIM-swap** σε έναν καταχωρημένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικά περιστατικά)
* Εγκαθιδρύστε foothold μέσω οποιουδήποτε web SSO portal.
* Καταγράψτε το AD / AzureAD με ενσωματωμένα εργαλεία (χωρίς drop binaries):
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
* Θεωρήστε την identity recovery του help-desk ως **privileged operation** – απαιτήστε step-up auth & έγκριση από manager.
* Αναπτύξτε **Identity Threat Detection & Response (ITDR)** / **UEBA** κανόνες που ειδοποιούν για:
* Αλλαγή μεθόδου MFA + authentication από νέα συσκευή / γεωγραφία.
* Άμεση ανύψωση του ίδιου principal (user-→-admin).
* Καταγράψτε τις κλήσεις του help-desk και επιβάλετε **call-back σε έναν ήδη καταχωρημένο αριθμό** πριν από οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι νεο-ρυθμισμένοι λογαριασμοί **να μην** κληρονομούν αυτόματα high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Οι commodity crews αντισταθμίζουν το κόστος των high-touch ops με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης & τα ad networks σε κανάλι παράδοσης**.

1. **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα όπως `chromium-update[.]site` στις κορυφαίες διαφημίσεις αναζήτησης.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που έχει δει η Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies + credential DBs, μετά κατεβάζει έναν **σιωπηλό loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block νέες-καταχωρημένες domains & επιβάλετε **Advanced DNS / URL Filtering** τόσο σε *search-ads* όσο και σε email.
* Περιορίστε την εγκατάσταση λογισμικού σε signed MSI / Store πακέτα, απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` με policy.
* Παρακολουθήστε για child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Ψάξτε για LOLBins που συχνά καταχρώνται από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Οι επιτιθέμενοι πλέον συνδέουν **LLM & voice-clone APIs** για πλήρως προσωποποιημένα lures και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS με τυποποιημένη διατύπωση & tracking links.|
|Generative AI|Παράγουν *one-off* emails που αναφέρουν δημόσιες M&A, inside jokes από social media; deep-fake CEO voice σε callback scam.|
|Agentic AI|Αυτονομώς καταχωρούν domains, συλλέγουν open-source intel, συντάσσουν τα επόμενα mails όταν ένα θύμα κλικάρει αλλά δεν υποβάλει credentials.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα απο μη-εμπιστευμένη αυτοματοποίηση (μέσω ARC/DKIM ανωμαλιών).  
• Ανάπτυξη **voice-biometric challenge phrases** για αιτήματα υψηλού ρίσκου μέσω τηλεφώνου.  
• Συνεχής προσομοίωση AI-generated lures σε εκπαιδευτικά προγράμματα – τα στατικά templates είναι ξεπερασμένα.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι operators απλά **επιβάλλουν μια νέα εγγραφή MFA** κατά τη διάρκεια της κλήσης στο help-desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επόμενο prompt login φαίνεται νόμιμο στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε για γεγονότα AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **εντός λίγων λεπτών από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν σιωπηλά να αντιγράψουν κακόβουλες εντολές στο πρόχειρο του θύματος από μια compromised ή typosquatted ιστοσελίδα και στη συνέχεια να ξεγελάσουν τον χρήστη να τις επικολλήσει μέσα στο **Win + R**, **Win + X** ή σε ένα παράθυρο τερματικού, εκτελώντας αυθαίρετο κώδικα χωρίς κατέβασμα αρχείων ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Οι operators όλο και περισσότερο περιορίζουν τα phishing flows πίσω από έναν απλό έλεγχο συσκευής ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα συνηθισμένο pattern είναι ένα μικρό script που δοκιμάζει αν το DOM υποστηρίζει touch και στέλνει το αποτέλεσμα σε ένα server endpoint· οι non‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ οι mobile users σερβίρονται με το πλήρες flow.

Ελάχιστο απόσπασμα κώδικα πελάτη (τυπική λογική):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` λογική (απλοποιημένη):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- Θέτει ένα session cookie κατά το πρώτο φόρτωμα.
- Αποδέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν `is_mobile=false`; σερβίρει phishing μόνο αν `true`.

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web τηλεμετρία: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη‑mobile· νόμιμες mobile διαδρομές θυμάτων επιστρέφουν 200 με επακόλουθο HTML/JS.
- Μπλοκάρετε ή ελέγξτε σχολαστικά σελίδες που βασίζουν το περιεχόμενο αποκλειστικά στο `ontouchstart` ή παρόμοιους ελέγχους συσκευής.

Defence tips:
- Εκτελέστε crawlers με mobile‑like fingerprints και ενεργοποιημένο JS για να αποκαλύψετε gated content.
- Ειδοποιήστε για ύποπτες αποκρίσεις 500 μετά από `POST /detect` σε πρόσφατα καταχωρημένα domains.

## Αναφορές

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
