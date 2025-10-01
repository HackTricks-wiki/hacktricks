# Phishing Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon τον στόχο
1. Επιλέξτε το **domain του θύματος**.
2. Εκτελέστε βασική web αναγνώριση **αναζητώντας portals σύνδεσης** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο από αυτά θα **προσποιηθείτε**.
3. Χρησιμοποιήστε OSINT για να **εντοπίσετε emails**.
2. Προετοιμάστε το περιβάλλον
1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing
2. **Διαμορφώστε τις εγγραφές** του email service (SPF, DMARC, DKIM, rDNS)
3. Διαμορφώστε το VPS με **gophish**
3. Προετοιμάστε την καμπάνια
1. Προετοιμάστε το **πρότυπο email**
2. Προετοιμάστε τη **σελίδα web** για να υποκλέψετε τα διαπιστευτήρια
4. Εκκινήστε την καμπάνια!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Το όνομα domain **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (π.χ., zelster.com-management.com).
- **hypened subdomain**: Αλλάξτε το **dot σε παύλα** ενός υποτομέα (π.χ., www-zelster.com).
- **New TLD**: Ίδιο domain χρησιμοποιώντας **νέο TLD** (π.χ., zelster.org)
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο όνομα domain με **γράμματα που μοιάζουν** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Ανταλλάσσει δύο γράμματα μέσα στο όνομα domain (π.χ., zelsetr.com).
- **Singularization/Pluralization**: Προσθέτει ή αφαιρεί “s” στο τέλος του ονόματος domain (π.χ., zeltsers.com).
- **Omission**: Αφαιρεί ένα από τα γράμματα του ονόματος domain (π.χ., zelser.com).
- **Repetition:** Επαναλαμβάνει ένα από τα γράμματα στο όνομα domain (π.χ., zeltsser.com).
- **Replacement**: Όπως το homoglyph αλλά λιγότερο stealthy. Αντικαθιστά ένα από τα γράμματα στο όνομα domain, ίσως με γράμμα κοντά στο πληκτρολόγιο (π.χ., zektser.com).
- **Subdomained**: Εισάγει ένα **dot** μέσα στο όνομα domain (π.χ., ze.lster.com).
- **Insertion**: Εισάγει ένα γράμμα στο όνομα domain (π.χ., zerltser.com).
- **Missing dot**: Επικολλά το TLD στο όνομα domain. (π.χ., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει η **πιθανότητα ότι κάποιο από τα bits που αποθηκεύονται ή βρίσκονται σε επικοινωνία να αλλάξει αυτόματα** λόγω διαφόρων παραγόντων όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε DNS αιτήματα**, είναι πιθανό ότι το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που αρχικά ζητήθηκε.

Για παράδειγμα, μια μεμονωμένη τροποποίηση bit στο domain "windows.com" μπορεί να το αλλάξει σε "windnws.com."

Οι επιτιθέμενοι μπορούν να **εκμεταλλευτούν αυτό εγγραφόμενοι σε πολλαπλά bit-flipping domains** που είναι παρόμοια με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους.

Για περισσότερες πληροφορίες διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

Μπορείτε να αναζητήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) για ένα expired domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το expired domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO** μπορείτε να ελέγξετε πώς είναι κατηγοριοποιημένο σε:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **εντοπίσετε περισσότερες** έγκυρες διευθύνσεις email ή να **επαληθεύσετε αυτές** που έχετε ήδη εντοπίσει μπορείτε να ελέγξετε αν μπορείτε να brute-force τους smtp servers του θύματος. [Μάθετε πώς να επαληθεύετε/εντοπίζετε διευθύνσεις email εδώ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **οποιοδήποτε web portal για πρόσβαση στα mails τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **username brute force**, και να εκμεταλλευτείτε την ευπάθεια αν είναι δυνατόν.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
Θα σας δοθεί ένας κωδικός για τον admin χρήστη στην έξοδο (port 3333). Επομένως, προσπελάστε αυτή την πόρτα και χρησιμοποιήστε αυτά τα διαπιστευτήρια για να αλλάξετε τον κωδικό του admin. Ενδέχεται να χρειαστεί να tunnel αυτή την πόρτα τοπικά:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και αυτό πρέπει να **δείχνει** στην **IP του VPS** όπου ρυθμίζετε το **gophish**.
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
**Ρύθμιση αλληλογραφίας**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια προσθέστε το domain στα παρακάτω αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το domain σας και **επανεκκινήστε το VPS σας.**

Τώρα δημιουργήστε μια **DNS A record** για το `mail.<domain>` που να δείχνει στη **ip address** του VPS και μια **DNS MX** εγγραφή που να δείχνει σε `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish διαμόρφωση**

Σταματήστε την εκτέλεση του gophish και ας το διαμορφώσουμε.\
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
**Διαμόρφωση gophish service**

Για να δημιουργήσετε το gophish service ώστε να μπορεί να ξεκινά αυτόματα και να διαχειρίζεται ως service, δημιουργήστε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:
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
Ολοκληρώστε τη ρύθμιση της υπηρεσίας και ελέγξτε ότι λειτουργεί κάνοντας:
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

### Περίμενε και να είσαι νόμιμος

Όσο παλαιότερο είναι ένα domain τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Γι' αυτό πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν την αξιολόγηση phishing. Επιπλέον, αν δημοσιεύσετε μια σελίδα σχετική με έναν κλάδο με καλή φήμη, η απόκτηση θετικής φήμης θα είναι καλύτερη.

Σημειώστε ότι ακόμα κι αν πρέπει να περιμένετε μία εβδομάδα, μπορείτε να ολοκληρώσετε τη διαμόρφωση τώρα.

### Configure Reverse DNS (rDNS) record

Ορίστε ένα rDNS (PTR) record που αντιστοιχίζει τη διεύθυνση IP του VPS στο domain.

### Sender Policy Framework (SPF) Record

Πρέπει να **διαμορφώσετε ένα SPF record για το νέο domain**. Εάν δεν ξέρετε τι είναι ένα SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF σας (χρησιμοποιήστε την IP της μηχανής VPS)

![](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε ένα TXT record στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Εγγραφή Domain-based Message Authentication, Reporting & Conformance (DMARC)

Πρέπει να **διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο domain**. Αν δεν ξέρετε τι είναι μια εγγραφή DMARC [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που παράγει το DKIM key:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Μπορείτε να το κάνετε χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς μπείτε στη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη ρύθμιση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Μπορείτε επίσης να στείλετε **μήνυμα σε Gmail που ελέγχετε**, και να ελέγξετε τις **κεφαλίδες του email** στο inbox σας στο Gmail — το `dkim=pass` πρέπει να εμφανίζεται στο header `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Αφαίρεση από τη Μαύρη Λίστα του Spamhouse

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας δείξει αν το domain σας μπλοκάρεται από το spamhouse. Μπορείτε να ζητήσετε να αφαιρεθεί το domain/IP σας στο: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη Μαύρη Λίστα της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Εκστρατείας GoPhish

### Προφίλ Αποστολής

- Ορίστε ένα **όνομα για αναγνώριση** του προφίλ αποστολέα
- Αποφασίστε από ποιο λογαριασμό θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το username και το password, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα συνιστούσα να **στείλετε τα test emails σε διευθύνσεις 10min mails** ώστε να αποφύγετε να μπείτε σε blacklist κατά τις δοκιμές.

### Πρότυπο Email

- Ορίστε ένα **όνομα για αναγνώριση** του προτύπου
- Στη συνέχεια γράψτε ένα **θέμα** (τίποτα παράξενο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- Send an email to a **μη υπάρχουσα διεύθυνση** and check if the response has any signature.
- Search for **δημόσιες διευθύνσεις email** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **κάποια έγκυρη εντοπισμένη** διεύθυνση email and wait for the response

![](<../../images/image (80).png>)

> [!TIP]
> Το Πρότυπο Email επίσης επιτρέπει να **επισυνάψετε αρχεία για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας κάποια ειδικά κατασκευασμένα αρχεία/έγγραφα [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **import** web pages.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μία **ανακατεύθυνση**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να σας ικανοποιήσει το αποτέλεσμα.** Στη συνέχεια, επικολλήστε αυτόν τον HTML κώδικα στο πλαίσιο.\
> Σημειώστε ότι αν χρειάζεστε **στατικά resources** για το HTML (π.χ. κάποιες CSS και JS σελίδες) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και μετά να αποκτήσετε πρόσβαση από το _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην νόμιμη κύρια σελίδα** του θύματος, ή να τους ανακατευθύνετε σε _/static/migration.html_ για παράδειγμα, να βάλετε έναν **spinning wheel (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και μετά να υποδείξετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Users & Groups

- Ορίστε ένα όνομα
- **Import the data** (σημειώστε ότι για να χρησιμοποιήσετε το template στο παράδειγμα χρειάζεστε το firstname, last name and email address κάθε χρήστη)

![](<../../images/image (163).png>)

### Campaign

Τέλος, δημιουργήστε μία campaign επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και την group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα αποσταλεί στα θύματα

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> Συστήνω να **στείλετε τα test emails σε 10min mails addresses** ώστε να αποφύγετε να μπλοκαριστείτε κατά τις δοκιμές.

Μόλις όλα είναι έτοιμα, απλά εκκινήστε την καμπάνια!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

Σε ορισμένες phishing αξιολογήσεις (κυρίως για Red Teams) ίσως θελήσετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως κάτι που θα πυροδοτήσει ένα authentication).\
Δείτε την ακόλουθη σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς μιμείστε μια πραγματική ιστοσελίδα και μαζεύετε τα δεδομένα που βάζει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν έβαλε το σωστό password ή αν η εφαρμογή που μιμηθήκατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να μιμηθείτε τον εξαπατημένο χρήστη**.

Εδώ είναι χρήσιμα εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο θα σας επιτρέψει να δημιουργήσετε μια επίθεση τύπου MitM. Βασικά, η επίθεση λειτουργεί ως εξής:

1. Εσείς **μιμείστε τη φόρμα login** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη ψεύτικη σελίδα και το εργαλείο τα στέλνει στην πραγματική σελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η MitM σελίδα θα το ζητήσει και μόλις ο **χρήστης το εισάγει** το εργαλείο θα το στείλει στην πραγματική σελίδα.
4. Μόλις ο χρήστης πιστοποιηθεί, εσείς (ως attacker) θα έχετε **συλλέξει τα credentials, το 2FA, το cookie και οποιαδήποτε πληροφορία** από κάθε αλληλεπίδραση ενώ το εργαλείο πραγματοποιεί MitM.

### Via VNC

Τι γίνεται αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** που μοιάζει με την πρωτότυπη, το στείλετε σε μια **συνδρομή VNC με έναν browser συνδεδεμένο στην πραγματική σελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε το password, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Προφανώς ένας από τους καλύτερους τρόπους να ξέρετε αν έχετε αποκαλυφθεί είναι να **ελέγξετε το domain σας σε blacklists**. Αν εμφανιστεί καταγεγραμμένο, με κάποιο τρόπο το domain σας ανιχνεύτηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να καταλάβετε αν το θύμα **ψάχνει ενεργά για ύποπτη phishing δραστηριότητα** όπως εξηγείται σε:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε **να αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε **που περιέχει** την **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιαδήποτε είδους **DNS ή HTTP αλληλεπίδραση** με αυτά, θα ξέρετε ότι **ψάχνει ενεργά** για ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Evaluate the phishing

Χρησιμοποιήστε [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας θα καταλήξει στο φάκελο spam ή αν θα μπλοκαριστεί ή θα είναι επιτυχημένο.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Τα σύγχρονα intrusion sets όλο και περισσότερο παρακάμπτουν τα email lures εντελώς και **στοχεύουν άμεσα τη ροή service-desk / identity-recovery** για να νικήσουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο operator αποκτήσει έγκυρα credentials περιστρέφεται με built-in admin tooling – δεν απαιτείται malware.

### Attack flow
1. Recon the victim
* Συλλογή προσωπικών & εταιρικών στοιχείων από LinkedIn, data breaches, public GitHub, κ.λπ.
* Εντοπισμός υψηλής αξίας ταυτοτήτων (διευθυντικά στελέχη, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset κωδικού / MFA.
2. Real-time social engineering
* Τηλέφωνο, Teams ή chat στο help-desk ενώ μιμείστε τον στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παροχή των προηγουμένως συλλεχθέντων PII για να περάσετε την επαλήθευση γνώσης.
* Πείστε τον agent να **reset the MFA secret** ή να πραγματοποιήσει **SIM-swap** σε έναν εγγεγραμμένο αριθμό κινητού.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα όπως το `chromium-update[.]site` στην κορυφή των search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που έχει δει το Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies + credential DBs, και στη συνέχεια τραβάει έναν **silent loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Περιορίστε την εγκατάσταση λογισμικού σε signed MSI / Store packages, απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` με πολιτική.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Οι επιτιθέμενοι πλέον αλυσσοδένουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα που στέλνονται από μη αξιόπιστη αυτοματοποίηση (via ARC/DKIM anomalies).  
• Ανάπτυξη **voice-biometric challenge phrases** για αιτήματα υψηλού ρίσκου μέσω τηλεφώνου.  
• Συνεχής προσομοίωση AI-generated lures σε προγράμματα ευαισθητοποίησης – τα στατικά templates είναι obsolete.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολουθήστε γεγονότα AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **εντός λίγων λεπτών από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν αθόρυβα να αντιγράψουν κακόβουλες εντολές στο clipboard του θύματος από μια παραβιασμένη ή typosquatted ιστοσελίδα και στη συνέχεια να ξεγελάσουν τον χρήστη ώστε να τις επικολλήσει μέσα σε **Win + R**, **Win + X** ή σε ένα terminal window, εκτελώντας αυθαίρετο κώδικα χωρίς καμία λήψη ή συνημμένο。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## Αναφορές

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
