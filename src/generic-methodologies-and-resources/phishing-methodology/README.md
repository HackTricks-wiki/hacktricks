# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Επιλέξτε το **domain του θύματος**.
2. Εκτελέστε κάποια βασική διαδικτυακή καταμέτρηση **αναζητώντας πύλες σύνδεσης** που χρησιμοποιούνται από το θύμα και **αποφασίστε** ποια θα **παραστήσετε**.
3. Χρησιμοποιήστε κάποια **OSINT** για να **βρείτε emails**.
2. Prepare the environment
1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing
2. **Ρυθμίστε την υπηρεσία email** σχετικές εγγραφές (SPF, DMARC, DKIM, rDNS)
3. Ρυθμίστε το VPS με **gophish**
3. Prepare the campaign
1. Ετοιμάστε το **email template**
2. Ετοιμάστε την **ιστοσελίδα** για να κλέψετε τα διαπιστευτήρια
4. Εκκινήστε την καμπάνια!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το domain name **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (π.χ., zelster.com-management.com).
- **hypened subdomain**: Αλλάξτε την **τελεία σε παύλα** ενός υποτομέα (π.χ., www-zelster.com).
- **New TLD**: Ίδιο domain χρησιμοποιώντας ένα **νέο TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν** (π.χ., zelfser.com).

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **Ανταλλάσσει δύο γράμματα** μέσα στο domain name (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του domain name (π.χ., zeltsers.com).
- **Omission**: **Αφαιρεί ένα** από τα γράμματα του domain name (π.χ., zelser.com).
- **Repetition:** **Επαναλαμβάνει ένα** από τα γράμματα στο domain name (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο διακριτικό. Αντικαθιστά ένα από τα γράμματα στο domain name, ίσως με ένα γράμμα κοντά στο αρχικό γράμμα στο πληκτρολόγιο (π.χ., zektser.com).
- **Subdomained**: Εισάγει μια **τελεία** μέσα στο domain name (π.χ., ze.lster.com).
- **Insertion**: **Εισάγει ένα γράμμα** στο domain name (π.χ., zerltser.com).
- **Missing dot**: Προσθέστε το TLD στο domain name. (π.χ., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει μια **πιθανότητα ότι ένα από τα bits που αποθηκεύονται ή επικοινωνούνται μπορεί να αλλάξει αυτόματα** λόγω διαφόρων παραγόντων όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS αιτήματα**, είναι πιθανό ότι το **domain που λαμβάνεται από τον DNS server** δεν είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια μόνο τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι επιτιθέμενοι μπορεί να **εκμεταλλευτούν αυτό καταχωρώντας πολλαπλά domains bit-flipping** που είναι παρόμοια με το domain του θύματος. Η πρόθεσή τους είναι να ανακατευθύνουν τους νόμιμους χρήστες στην υποδομή τους.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Μπορείτε να αναζητήσετε σε [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα ληγμένο domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το ληγμένο domain που πρόκειται να αγοράσετε **έχει ήδη καλή SEO** μπορείτε να ελέγξετε πώς είναι κατηγοριοποιημένο σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% δωρεάν)
- [https://phonebook.cz/](https://phonebook.cz) (100% δωρεάν)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **ανακαλύψετε περισσότερες** έγκυρες διευθύνσεις email ή **να επαληθεύσετε αυτές** που έχετε ήδη ανακαλύψει μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στους smtp servers του θύματος. [Μάθετε πώς να επαληθεύσετε/ανακαλύψετε διεύθυνση email εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **οποιαδήποτε διαδικτυακή πύλη για να αποκτήσουν πρόσβαση στα emails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτη σε **brute force ονόματος χρήστη**, και να εκμεταλλευτείτε την ευπάθεια αν είναι δυνατόν.

## Configuring GoPhish

### Installation

Μπορείτε να το κατεβάσετε από [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός πρόσβασης για τον διαχειριστή στη θύρα 3333 στην έξοδο. Επομένως, αποκτήστε πρόσβαση σε αυτή τη θύρα και χρησιμοποιήστε αυτά τα διαπιστευτήρια για να αλλάξετε τον κωδικό πρόσβασης του διαχειριστή. Ίσως χρειαστεί να στείλετε αυτή τη θύρα τοπικά:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Ρύθμιση

**Ρύθμιση πιστοποιητικού TLS**

Πριν από αυτό το βήμα θα πρέπει να έχετε **αγοράσει ήδη το domain** που θα χρησιμοποιήσετε και πρέπει να **δείχνει** στη **διεύθυνση IP του VPS** όπου ρυθμίζετε το **gophish**.
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
**Ρύθμιση ταχυδρομείου**

Αρχίστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια, προσθέστε το domain στα παρακάτω αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** με το όνομα του domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε μια **DNS A record** του `mail.<domain>` που να δείχνει στη **διεύθυνση ip** του VPS και μια **DNS MX** record που να δείχνει στο `mail.<domain>`

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
## Ρύθμιση διακομιστή αλληλογραφίας και τομέα

### Περίμενε & να είσαι νόμιμος

Όσο παλαιότερος είναι ένας τομέας, τόσο λιγότερο πιθανό είναι να πιαστεί ως spam. Έτσι, θα πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν από την αξιολόγηση phishing. Επιπλέον, αν δημιουργήσετε μια σελίδα σχετικά με έναν τομέα φήμης, η φήμη που θα αποκτηθεί θα είναι καλύτερη.

Σημειώστε ότι ακόμη και αν πρέπει να περιμένετε μια εβδομάδα, μπορείτε να ολοκληρώσετε τη ρύθμιση όλων τώρα.

### Ρύθμιση εγγραφής Αντίστροφης DNS (rDNS)

Ορίστε μια εγγραφή rDNS (PTR) που επιλύει τη διεύθυνση IP του VPS στο όνομα τομέα.

### Εγγραφή Πολιτικής Αποστολέα (SPF)

Πρέπει να **ρυθμίσετε μια εγγραφή SPF για τον νέο τομέα**. Αν δεν ξέρετε τι είναι μια εγγραφή SPF [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF σας (χρησιμοποιήστε τη διεύθυνση IP της μηχανής VPS)

![](<../../images/image (1037).png>)

Αυτή είναι η περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT στον τομέα:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Πρέπει να **ρυθμίσετε ένα DMARC record για το νέο domain**. Αν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε ένα νέο DNS TXT record που να δείχνει το hostname `_dmarc.<domain>` με το εξής περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο τομέα**. Αν δεν ξέρετε τι είναι ένα DMARC record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται σε: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συνδυάσετε και τις δύο τιμές B64 που παράγει το DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλά επισκεφθείτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** την πόρτα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
Ελέγξτε ότι περνάτε όλους τους ελέγχους:
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
Μπορείτε επίσης να στείλετε **μήνυμα σε ένα Gmail υπό τον έλεγχό σας** και να ελέγξετε τα **κεφαλίδες του email** στο Gmail inbox σας, το `dkim=pass` θα πρέπει να είναι παρόν στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Αφαίρεση από τη Μαύρη Λίστα του Spamhouse

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας υποδείξει αν το domain σας μπλοκάρεται από το spamhouse. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Μαύρη Λίστα της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Καμπάνιας GoPhish

### Προφίλ Αποστολής

- Ορίστε κάποιο **όνομα για να αναγνωρίσετε** το προφίλ αποστολέα
- Αποφασίστε από ποιον λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό πρόσβασης, αλλά βεβαιωθείτε ότι έχετε ελέγξει την επιλογή Αγνόηση Σφαλμάτων Πιστοποιητικού

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Αποστολή Δοκιμαστικού Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα πρότεινα να **στείλετε τα δοκιμαστικά emails σε διευθύνσεις 10min mails** για να αποφύγετε την προσθήκη στη μαύρη λίστα κατά τη διάρκεια των δοκιμών.

### Πρότυπο Email

- Ορίστε κάποιο **όνομα για να αναγνωρίσετε** το πρότυπο
- Στη συνέχεια, γράψτε ένα **θέμα** (τίποτα παράξενο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε ελέγξει την επιλογή "**Προσθήκη Εικόνας Παρακολούθησης**"
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

- Στείλτε ένα email σε μια **μη υπάρχουσα διεύθυνση** και ελέγξτε αν η απάντηση έχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με **κάποιο έγκυρο ανακαλυφθέν** email και περιμένετε την απάντηση.

![](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης να **επισυνάπτετε αρχεία για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας κάποια ειδικά κατασκευασμένα αρχεία/έγγραφα [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισάγετε** ιστοσελίδες.
- Επισημάνετε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε κάποιες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να σας αρέσουν τα αποτελέσματα.** Στη συνέχεια, γράψτε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι αν χρειαστεί να **χρησιμοποιήσετε κάποιους στατικούς πόρους** για τον HTML (ίσως κάποιες σελίδες CSS και JS) μπορείτε να τους αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και στη συνέχεια να τους αποκτήσετε από _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην κανονική κύρια ιστοσελίδα** του θύματος, ή να τους ανακατευθύνετε στο _/static/migration.html_ για παράδειγμα, να βάλετε κάποιο **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και στη συνέχεια να υποδείξετε ότι η διαδικασία ήταν επιτυχής**.

### Users & Groups

- Ορίστε ένα όνομα
- **Εισάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το πρότυπο για το παράδειγμα χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)

![](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μια καμπάνια επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και την ομάδα. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα.

Σημειώστε ότι το **Sending Profile επιτρέπει να στείλετε ένα δοκιμαστικό email για να δείτε πώς θα φαίνεται το τελικό phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Θα συνιστούσα να **στείλετε τα δοκιμαστικά emails σε διευθύνσεις 10min mails** για να αποφύγετε να μπείτε σε μαύρη λίστα κάνοντας δοκιμές.

Μόλις είναι όλα έτοιμα, απλά εκκινήστε την καμπάνια!

## Website Cloning

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε την ιστοσελίδα ελέγξτε την παρακάτω σελίδα:

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένες αξιολογήσεις phishing (κυρίως για Red Teams) θα θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως απλώς κάτι που θα ενεργοποιήσει μια αυθεντικοποίηση).\
Δείτε την παρακάτω σελίδα για μερικά παραδείγματα:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς προσποιείστε μια πραγματική ιστοσελίδα και συγκεντρώνετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισάγει τον σωστό κωδικό ή αν η εφαρμογή που προσποιείστε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να προσποιηθείτε τον παραπλανημένο χρήστη**.

Εδώ είναι που εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena) είναι χρήσιμα. Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, οι επιθέσεις λειτουργούν ως εξής:

1. Εσείς **προσποιείστε τη φόρμα σύνδεσης** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **διαπιστευτήριά** του στη ψεύτικη σελίδα σας και το εργαλείο στέλνει αυτά στη πραγματική ιστοσελίδα, **ελέγχοντας αν τα διαπιστευτήρια λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η σελίδα MitM θα ζητήσει αυτό και μόλις ο **χρήστης το εισάγει** το εργαλείο θα το στείλει στη πραγματική ιστοσελίδα.
4. Μόλις ο χρήστης είναι αυθεντικοποιημένος εσείς (ως επιτιθέμενος) θα έχετε **συλλάβει τα διαπιστευτήρια, το 2FA, το cookie και οποιαδήποτε πληροφορία** από κάθε αλληλεπίδραση σας ενώ το εργαλείο εκτελεί μια MitM.

### Via VNC

Τι θα γινόταν αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με την ίδια εμφάνιση όπως η αρχική, το στείλετε σε μια **VNC συνεδρία με έναν περιηγητή συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε τον κωδικό, το MFA που χρησιμοποιείται, τα cookies...\
Μπορείτε να το κάνετε αυτό με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους για να ξέρετε αν έχετε ανακαλυφθεί είναι να **αναζητήσετε το domain σας μέσα σε μαύρες λίστες**. Αν εμφανίζεται καταχωρημένο, με κάποιο τρόπο το domain σας ανιχνεύθηκε ως ύποπτο.\
Ένας εύκολος τρόπος για να ελέγξετε αν το domain σας εμφανίζεται σε οποιαδήποτε μαύρη λίστα είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να ξέρετε αν το θύμα είναι **ενεργά σε αναζήτηση ύποπτης phishing δραστηριότητας στον κόσμο** όπως εξηγείται σε:

{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα πιστοποιητικό** για ένα **subdomain** ενός domain που ελέγχετε **περιέχοντας** τη **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** εκτελέσει οποιαδήποτε **DNS ή HTTP αλληλεπίδραση** με αυτά, θα ξέρετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ διακριτικοί.

### Evaluate the phishing

Χρησιμοποιήστε [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας θα καταλήξει στο φάκελο spam ή αν θα μπλοκαριστεί ή θα είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Οι σύγχρονες επιθέσεις παρακάμπτουν ολοένα και περισσότερο τις παγίδες email και **στοχεύουν άμεσα τη διαδικασία service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο χειριστής αποκτήσει έγκυρα διαπιστευτήρια, προχωρά με τα ενσωματωμένα εργαλεία διαχείρισης – δεν απαιτείται κακόβουλο λογισμικό.

### Attack flow
1. Recon the victim
* Συλλέξτε προσωπικές & εταιρικές λεπτομέρειες από LinkedIn, παραβιάσεις δεδομένων, δημόσιο GitHub, κ.λπ.
* Εντοπίστε ταυτότητες υψηλής αξίας (εκτελεστικά στελέχη, IT, χρηματοοικονομικά) και καταγράψτε τη **συγκεκριμένη διαδικασία help-desk** για επαναφορά κωδικού / MFA.
2. Real-time social engineering
* Καλέστε, χρησιμοποιήστε Teams ή συνομιλήστε με το help-desk προσποιούμενοι τον στόχο (συχνά με **spoofed caller-ID** ή **κλωνοποιημένη φωνή**).
* Παρέχετε τα προηγουμένως συλλεγμένα PII για να περάσετε την επαλήθευση βάσει γνώσεων.
* Πείστε τον πράκτορα να **επαναφέρει το μυστικό MFA** ή να εκτελέσει μια **SIM-swap** σε έναν καταχωρημένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 λεπτά σε πραγματικές περιπτώσεις)
* Δημιουργήστε μια βάση μέσω οποιασδήποτε πύλης SSO ιστού.
* Καταγράψτε το AD / AzureAD με ενσωματωμένα (χωρίς να ρίξετε δυαδικά αρχεία):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Κινήσεις πλευράς με **WMI**, **PsExec**, ή νόμιμους **RMM** πράκτορες που είναι ήδη λευκοί στη λίστα στο περιβάλλον.

### Detection & Mitigation
* Αντιμετωπίστε την ανάκτηση ταυτότητας help-desk ως **προνομιακή λειτουργία** – απαιτήστε step-up auth & έγκριση διευθυντή.
* Αναπτύξτε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που ειδοποιούν για:
* Μέθοδος MFA που άλλαξε + αυθεντικοποίηση από νέα συσκευή / γεωγραφία.
* Άμεση αναβάθμιση του ίδιου προσώπου (χρήστης-→-διαχειριστής).
* Καταγράψτε τις κλήσεις help-desk και επιβάλετε μια **επιστροφή κλήσης σε ήδη καταχωρημένο αριθμό** πριν από οποιαδήποτε επαναφορά.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι νεοεπαναρυθμισμένοι λογαριασμοί να **μην** κληρονομούν αυτόματα υψηλά προνόμια.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Οι ομάδες εμπορευμάτων αντισταθμίζουν το κόστος των υψηλών επαφών με μαζικές επιθέσεις που μετατρέπουν **τις μηχανές αναζήτησης & τα δίκτυα διαφημίσεων σε κανάλι παράδοσης**.

1. **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα όπως το `chromium-update[.]site` στην κορυφή των διαφημίσεων αναζήτησης.
2. Το θύμα κατεβάζει έναν μικρό **loader πρώτης φάσης** (συχνά JS/HTA/ISO). Παραδείγματα που είδαν οι Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει cookies περιηγητή + βάσεις δεδομένων διαπιστευτηρίων, στη συνέχεια τραβά έναν **σιωπηλό loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* συστατικό επιμονής (κλειδί Run μητρώου + προγραμματισμένο έργο)

### Hardening tips
* Εμποδίστε τα νεοκαταχωρημένα domains & επιβάλετε **Advanced DNS / URL Filtering** σε *search-ads* καθώς και σε email.
* Περιορίστε την εγκατάσταση λογισμικού σε υπογεγραμμένα πακέτα MSI / Store, αρνηθείτε την εκτέλεση `HTA`, `ISO`, `VBS` με πολιτική.
* Παρακολουθήστε για διαδικασίες παιδιών περιηγητών που ανοίγουν εγκαταστάτες:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Κυνηγήστε LOLBins που συχνά κακοποιούνται από loaders πρώτης φάσης (π.χ. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Οι επιτιθέμενοι τώρα αλυσσοδένονται **LLM & voice-clone APIs** για πλήρως εξατομικευμένες παγίδες και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Προσθέστε **δυναμικές διαφημίσεις** που επισημαίνουν μηνύματα που αποστέλλονται από μη αξιόπιστη αυτοματοποίηση (μέσω ανωμαλιών ARC/DKIM).
• Αναπτύξτε **φωνητικές προκλήσεις βιομετρικών φράσεων** για αιτήματα τηλεφώνου υψηλού κινδύνου.
• Συνεχώς προσομοιώστε AI-generated παγίδες σε προγράμματα ευαισθητοποίησης – στατικά πρότυπα είναι παρωχημένα.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από την κλασική μέθοδο push-bombing, οι χειριστές απλά **αναγκάζουν μια νέα εγγραφή MFA** κατά τη διάρκεια της κλήσης help-desk, μηδενίζοντας το υπάρχον token του χρήστη. Οποιαδήποτε επόμενη προτροπή σύνδεσης φαίνεται νόμιμη για το θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε για γεγονότα AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **εντός λεπτών από την ίδια IP**.

## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν σιωπηλά να αντιγράψουν κακόβουλες εντολές στο πρόχειρο του θύματος από μια συμβιβασμένη ή typosquatted ιστοσελίδα και στη συνέχεια να παραπλανήσουν τον χρήστη να τις επικολλήσει μέσα σε **Win + R**, **Win + X** ή ένα παράθυρο τερματικού, εκτελώντας αυθαίρετο κώδικα χωρίς καμία λήψη ή συνημμένο.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
