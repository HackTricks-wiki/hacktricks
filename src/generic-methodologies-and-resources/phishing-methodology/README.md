# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Μεθοδολογία

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ανακάλυψη Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Διαμόρφωση

**Ρύθμιση πιστοποιητικού TLS**

Πριν από αυτό το βήμα θα πρέπει να έχετε **ήδη αγοράσει το domain** που πρόκειται να χρησιμοποιήσετε και αυτό πρέπει να **δείχνει** στην **IP του VPS** όπου ρυθμίζετε το **gophish**.
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

Στη συνέχεια προσθέστε το domain στα ακόλουθα αρχεία:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Αλλάξτε επίσης τις τιμές των ακόλουθων μεταβλητών μέσα στο /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Τέλος, τροποποιήστε τα αρχεία **`/etc/hostname`** και **`/etc/mailname`** ώστε να περιέχουν το domain σας και **επανεκκινήστε το VPS σας.**

Τώρα, δημιουργήστε ένα **DNS A record** για το `mail.<domain>` που δείχνει στη **διεύθυνση IP** του VPS και ένα **DNS MX** record που δείχνει στο `mail.<domain>`

Τώρα ας δοκιμάσουμε να στείλουμε ένα email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Διαμόρφωση Gophish**

Σταματήστε την εκτέλεση του gophish και ας το διαμορφώσουμε.\
Τροποποιήστε `/opt/gophish/config.json` ως εξής (προσέξτε τη χρήση του https):
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
**Διαμόρφωση υπηρεσίας gophish**

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
Ολοκληρώστε τη διαμόρφωση της υπηρεσίας και επαληθεύστε τη λειτουργία της κάνοντας:
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
## Configuring mail server and domain

### Περίμενε & be legit

Όσο παλαιότερο είναι ένα domain, τόσο λιγότερο πιθανό είναι να εντοπιστεί ως spam. Έτσι πρέπει να περιμένετε όσο το δυνατόν περισσότερο (τουλάχιστον 1 εβδομάδα) πριν την αξιολόγηση phishing. Επιπλέον, αν τοποθετήσετε μια σελίδα σχετική με έναν τομέα με καλή φήμη, η συνολική reputation που θα αποκτήσετε θα είναι καλύτερη.

Σημειώστε ότι ακόμα κι αν χρειάζεται να περιμένετε μια εβδομάδα, μπορείτε να ολοκληρώσετε τώρα τη διαμόρφωση όλων.

### Ρύθμιση Reverse DNS (rDNS) record

Ορίστε μια rDNS (PTR) εγγραφή που επιλύει τη διεύθυνση IP του VPS στο όνομα domain.

### Sender Policy Framework (SPF) Record

Πρέπει να **διαμορφώσετε ένα SPF record για το νέο domain**. Αν δεν ξέρετε τι είναι ένα SPF record [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

Μπορείτε να χρησιμοποιήσετε [https://www.spfwizard.net/](https://www.spfwizard.net) για να δημιουργήσετε την πολιτική SPF σας (χρησιμοποιήστε το IP της μηχανής VPS)

![](<../../images/image (1037).png>)

Αυτό είναι το περιεχόμενο που πρέπει να οριστεί μέσα σε μια TXT εγγραφή στο domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Πιστοποίηση, Αναφορά και Συμμόρφωση Μηνυμάτων βάσει Domain (DMARC) Εγγραφή

Πρέπει να **διαμορφώσετε μια εγγραφή DMARC για το νέο domain**. Αν δεν γνωρίζετε τι είναι μια εγγραφή DMARC [**διαβάστε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

Πρέπει να δημιουργήσετε μια νέα εγγραφή DNS TXT που δείχνει στο hostname `_dmarc.<domain>` με το ακόλουθο περιεχόμενο:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Πρέπει να **ρυθμίσεις DKIM για το νέο domain**. Αν δεν γνωρίζεις τι είναι μια εγγραφή DMARC [**διάβασε αυτή τη σελίδα**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> Πρέπει να συγχωνεύσεις και τις δύο τιμές B64 που παράγει το κλειδί DKIM:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

Μπορείς να το κάνεις χρησιμοποιώντας [https://www.mail-tester.com/](https://www.mail-tester.com/)\
Απλώς μπες στη σελίδα και στείλε ένα email στη διεύθυνση που σου δίνουν:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Μπορείτε επίσης να **ελέγξετε τη ρύθμιση του email σας** στέλνοντας ένα email στο `check-auth@verifier.port25.com` και **διαβάζοντας την απάντηση** (για αυτό θα χρειαστεί να **ανοίξετε** port **25** και να δείτε την απάντηση στο αρχείο _/var/mail/root_ αν στείλετε το email ως root).\
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
Μπορείτε επίσης να στείλετε **μήνυμα σε ένα Gmail υπό τον έλεγχό σας**, και να ελέγξετε τα **email’s headers** στο Gmail inbox σας, `dkim=pass` θα πρέπει να υπάρχει στο πεδίο κεφαλίδας `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Κατάργηση από τη Μαύρη Λίστα του Spamhouse

Η σελίδα [www.mail-tester.com](https://www.mail-tester.com) μπορεί να σας δείξει αν το domain σας μπλοκάρεται από το Spamhouse. Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στη διεύθυνση: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Κατάργηση από τη Μαύρη Λίστα της Microsoft

Μπορείτε να ζητήσετε την αφαίρεση του domain/IP σας στο [https://sender.office.com/](https://sender.office.com).

## Δημιουργία & Εκκίνηση Καμπάνιας GoPhish

### Προφίλ Αποστολέα

- Καθορίστε ένα **όνομα αναγνώρισης** για το προφίλ αποστολέα
- Αποφασίστε από ποιο account θα στείλετε τα phishing emails. Προτάσεις: _noreply, support, servicedesk, salesforce..._
- Μπορείτε να αφήσετε κενά το username και το password, αλλά φροντίστε να τσεκάρετε το Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Συνιστάται να χρησιμοποιήσετε τη λειτουργία "**Send Test Email**" για να ελέγξετε ότι όλα λειτουργούν.\
> Θα συνιστούσα να **στείλετε τα test emails σε διευθύνσεις 10min mails** ώστε να αποφύγετε να μπείτε σε blacklist κατά τις δοκιμές.

### Πρότυπο Email

- Ορίστε ένα **όνομα αναγνώρισης** για το πρότυπο
- Έπειτα γράψτε ένα **subject** (τίποτα περίεργο, απλά κάτι που θα περίμενε κανείς να διαβάσει σε ένα κανονικό email)
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
Σημειώστε ότι **για να αυξήσετε την αξιοπιστία του email**, συνιστάται να χρησιμοποιήσετε κάποια υπογραφή από ένα email του πελάτη. Προτάσεις:

- Στείλτε ένα email σε μια **διεύθυνση που δεν υπάρχει** και ελέγξτε αν η απάντηση περιέχει κάποια υπογραφή.
- Αναζητήστε **δημόσια emails** όπως info@ex.com ή press@ex.com ή public@ex.com και στείλτε τους ένα email και περιμένετε την απάντηση.
- Προσπαθήστε να επικοινωνήσετε με **κάποιον έγκυρο ανακαλυφθέντα** email και περιμένετε την απάντηση

![](<../../images/image (80).png>)

> [!TIP]
> Το Email Template επιτρέπει επίσης να **επισυνάψετε αρχεία για αποστολή**. Αν θέλετε επίσης να κλέψετε NTLM challenges χρησιμοποιώντας κάποια ειδικά διαμορφωμένα αρχεία/έγγραφα, [διαβάστε αυτή τη σελίδα](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Σελίδα Προσγείωσης

- Γράψτε ένα **όνομα**
- **Γράψτε τον HTML κώδικα** της σελίδας. Σημειώστε ότι μπορείτε να **import** web pages.
- Επισημάνετε **Capture Submitted Data** και **Capture Passwords**
- Ορίστε μια **ανακατεύθυνση**

![](<../../images/image (826).png>)

> [!TIP]
> Συνήθως θα χρειαστεί να τροποποιήσετε τον HTML κώδικα της σελίδας και να κάνετε κάποιους ελέγχους τοπικά (ίσως χρησιμοποιώντας κάποιο Apache server) **μέχρι να μείνετε ικανοποιημένοι με τα αποτελέσματα.** Έπειτα, γράψτε αυτόν τον HTML κώδικα στο πεδίο.\
> Σημειώστε ότι αν χρειαστεί να **χρησιμοποιήσετε κάποια static resources** για το HTML (π.χ. CSS και JS) μπορείτε να τα αποθηκεύσετε στο _**/opt/gophish/static/endpoint**_ και μετά να τα προσπελάσετε από _**/static/\<filename>**_

> [!TIP]
> Για την ανακατεύθυνση μπορείτε να **ανακατευθύνετε τους χρήστες στην legit κύρια σελίδα** του θύματος, ή να τους στείλετε στο _/static/migration.html_ για παράδειγμα, να βάλετε έναν **spinning wheel** ([https://loading.io/](https://loading.io/)) για 5 δευτερόλεπτα και μετά να υποδείξετε ότι η διαδικασία ολοκληρώθηκε επιτυχώς.

### Χρήστες & Ομάδες

- Ορίστε ένα όνομα
- **Import the data** (σημειώστε ότι για να χρησιμοποιήσετε το template ως παράδειγμα χρειάζεστε το firstname, last name και email address κάθε χρήστη)

![](<../../images/image (163).png>)

### Καμπάνια

Τέλος, δημιουργήστε μια καμπάνια επιλέγοντας ένα όνομα, το email template, τη landing page, το URL, το sending profile και την group. Σημειώστε ότι το URL θα είναι ο σύνδεσμος που θα σταλεί στα θύματα

Σημειώστε ότι το **Sending Profile επιτρέπει να στείλετε ένα test email για να δείτε πώς θα εμφανίζεται το τελικό phishing email**:

![](<../../images/image (192).png>)

> [!TIP]
> Θα πρότεινα να **στέλνετε τα test emails σε 10min mails addresses** ώστε να αποφύγετε το blacklist ενώ κάνετε δοκιμές.

Μόλις όλα είναι έτοιμα, απλώς ξεκινήστε την καμπάνια!

## Κλωνοποίηση Ιστοσελίδας

Αν για οποιονδήποτε λόγο θέλετε να κλωνοποιήσετε την ιστοσελίδα ελέγξτε την παρακάτω σελίδα:


{{#ref}}
clone-a-website.md
{{#endref}}

## Έγγραφα & Αρχεία με backdoor

Σε κάποιες phishing αξιολογήσεις (κυρίως για Red Teams) ίσως θελήσετε επίσης να **στείλετε αρχεία που περιέχουν κάποιο είδος backdoor** (ίσως ένα C2 ή ίσως απλώς κάτι που θα ενεργοποιήσει μια authentication).\
Eλέγξτε την παρακάτω σελίδα για μερικά παραδείγματα:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Μέσω Proxy MitM

Η προηγούμενη επίθεση είναι αρκετά έξυπνη καθώς προσποιείστε μια πραγματική ιστοσελίδα και συλλέγετε τις πληροφορίες που βάζει ο χρήστης. Δυστυχώς, αν ο χρήστης δεν βάλει το σωστό password ή αν η εφαρμογή που προσποιήθήκατε είναι ρυθμισμένη με 2FA, **αυτές οι πληροφορίες δεν θα σας επιτρέψουν να μιμηθείτε τον χρήστη που ξεγελάσατε**.

Εδώ είναι χρήσιμα εργαλεία όπως [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) και [**muraena**](https://github.com/muraenateam/muraena). Το εργαλείο αυτό θα σας επιτρέψει να δημιουργήσετε μια MitM επίθεση. Βασικά, η επίθεση λειτουργεί ως εξής:

1. Εσείς **προσποιείστε τη φόρμα login** της πραγματικής σελίδας.
2. Ο χρήστης **στέλνει** τα **credentials** του στη ψεύτικη σελίδα σας και το εργαλείο τα στέλνει στην πραγματική σελίδα, **ελέγχοντας αν τα credentials λειτουργούν**.
3. Αν ο λογαριασμός είναι ρυθμισμένος με **2FA**, η MitM σελίδα θα ζητήσει το 2FA και μόλις ο **χρήστης το εισάγει** το εργαλείο θα το στείλει στην πραγματική σελίδα.
4. Μόλις ο χρήστης πιστοποιηθεί, εσείς (ως επιτιθέμενος) θα έχετε **συλλέξει τα credentials, το 2FA, το cookie και κάθε πληροφορία** από κάθε αλληλεπίδραση ενώ το εργαλείο εκτελεί τον MitM.

### Μέσω VNC

Τι γίνεται αν αντί να **στείλετε το θύμα σε μια κακόβουλη σελίδα** με όψη ίδια της πρωτότυπης, τον στείλετε σε μια **VNC session με browser συνδεδεμένο στην πραγματική σελίδα**; Θα μπορείτε να δείτε τι κάνει, να κλέψετε το password, το MFA που χρησιμοποιήθηκε, τα cookies...\
Μπορείτε να το κάνετε αυτό με [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Εντοπίζοντας ότι σας έχουν εντοπίσει

Προφανώς ένας από τους καλύτερους τρόπους να ξέρετε αν σας έχουν πιάσει είναι να **αναζητήσετε το domain σας σε blacklists**. Αν εμφανιστεί καταχωρημένο, κάπως το domain σας ανιχνεύτηκε ως ύποπτο.\
Ένας εύκολος τρόπος να ελέγξετε αν το domain σας εμφανίζεται σε κάποια blacklist είναι να χρησιμοποιήσετε [https://malwareworld.com/](https://malwareworld.com)

Ωστόσο, υπάρχουν και άλλοι τρόποι να μάθετε αν το θύμα **ενεργά ψάχνει για ύποπτη phishing δραστηριότητα** όπως εξηγείται στο:


{{#ref}}
detecting-phising.md
{{#endref}}

Μπορείτε **να αγοράσετε ένα domain με πολύ παρόμοιο όνομα** με το domain του θύματος **και/ή να δημιουργήσετε ένα certificate** για ένα **subdomain** ενός domain που ελέγχετε εσείς **περιέχοντας** το **keyword** του domain του θύματος. Αν το **θύμα** πραγματοποιήσει οποιαδήποτε είδους **DNS ή HTTP αλληλεπίδραση** με αυτά, θα ξέρετε ότι **αναζητά ενεργά** ύποπτα domains και θα χρειαστεί να είστε πολύ stealth.

### Αξιολόγηση του phishing

Χρησιμοποιήστε [**Phishious**](https://github.com/Rices/Phishious) για να αξιολογήσετε αν το email σας θα καταλήξει στο spam folder ή αν θα μπλοκαριστεί ή θα είναι επιτυχές.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Σύγχρονα intrusion sets όλο και περισσότερο παραλείπουν εντελώς τα email lures και **στοχεύουν απευθείας τη ροή εργασίας του service-desk / identity-recovery** για να παρακάμψουν το MFA. Η επίθεση είναι πλήρως "living-off-the-land": μόλις ο χειριστής αποκτήσει έγκυρα credentials, μετακινείται με ενσωματωμένα admin εργαλεία – δεν απαιτείται malware.

### Ροή επίθεσης
1. Recon του θύματος
* Συλλογή προσωπικών & εταιρικών λεπτομερειών από LinkedIn, data breaches, δημόσιο GitHub, κ.λπ.
* Εντοπισμός high-value ταυτοτήτων (executives, IT, finance) και καταγραφή της **ακριβούς διαδικασίας help-desk** για reset password / MFA.
2. Real-time social engineering
* Τηλεφωνικά, Teams ή chat στο help-desk ενώ προσποιείστε το στόχο (συχνά με **spoofed caller-ID** ή **cloned voice**).
* Παροχή των προηγουμένως-συλλεχθέντων PII για να περάσετε knowledge-based verification.
* Πεισμός του agent να **επαναφέρει το MFA secret** ή να εκτελέσει ένα **SIM-swap** σε έναν εγγεγραμμένο αριθμό κινητού.
3. Άμεσες ενέργειες μετά την πρόσβαση (≤60 min σε πραγματικά περιστατικά)
* Εδραίωση foothold μέσω οποιουδήποτε web SSO portal.
* Καταγραφή του AD / AzureAD με ενσωματωμένα εργαλεία (χωρίς binaries):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement με **WMI**, **PsExec**, ή νόμιμους **RMM** agents που ήδη βρίσκονται στην whitelist του περιβάλλοντος.

### Detection & Mitigation
* Αντιμετωπίστε την identity recovery από help-desk ως μια **privileged operation** – απαιτήστε step-up auth & έγκριση manager.
* Αναπτύξτε **Identity Threat Detection & Response (ITDR)** / **UEBA** κανόνες που ειδοποιούν για:
* Αλλαγή μεθόδου MFA + authentication από νέο device / γεωγραφική θέση.
* Άμεση ανύψωση προνομίων του ίδιου principal (user-→-admin).
* Καταγράψτε τις κλήσεις του help-desk και επιβάλετε **call-back σε ήδη-καταχωρημένο αριθμό** πριν από οποιοδήποτε reset.
* Εφαρμόστε **Just-In-Time (JIT) / Privileged Access** ώστε οι νεορυθμισμένοι λογαριασμοί να μην κληρονομούν αυτόματα high-privilege tokens.

---

## Μεγάλης Κλίμακας Απάτη – SEO Poisoning & “ClickFix” Καμπάνιες
Commodity crews αντισταθμίζουν το κόστος των high-touch ops με μαζικές επιθέσεις που μετατρέπουν **τις μηχανές αναζήτησης & τα ad networks σε κανάλι παράδοσης**.

1. **SEO poisoning / malvertising** προωθεί ένα ψεύτικο αποτέλεσμα όπως `chromium-update[.]site` στην κορυφή των search ads.
2. Το θύμα κατεβάζει έναν μικρό **first-stage loader** (συχνά JS/HTA/ISO). Παραδείγματα που έχει δει η Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Ο loader εξάγει browser cookies + credential DBs, μετά κατεβάζει έναν **silent loader** που αποφασίζει – *σε πραγματικό χρόνο* – αν θα αναπτύξει:
* RAT (π.χ. AsyncRAT, RustDesk)
* ransomware / wiper
* component persistence (registry Run key + scheduled task)

### Συμβουλές Σκληραγώγησης
* Block νέες-καταχωρημένες domains & επιβάλετε **Advanced DNS / URL Filtering** σε *search-ads* καθώς και σε e-mail.
* Περιορίστε την εγκατάσταση λογισμικού σε signed MSI / Store packages, απορρίψτε εκτέλεση `HTA`, `ISO`, `VBS` μέσω policy.
* Παρακολουθήστε για child processes των browsers που ανοίγουν installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Αναζητήστε LOLBins που συχνά κακοποιούνται από first-stage loaders (π.χ. `regsvr32`, `curl`, `mshta`).

---

## Phishing με Ενισχυμένη AI
Οι επιτιθέμενοι πλέον συνδυάζουν **LLM & voice-clone APIs** για πλήρως εξατομικευμένα lures και αλληλεπίδραση σε πραγματικό χρόνο.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Άμυνα:**
• Προσθέστε **dynamic banners** που επισημαίνουν μηνύματα απο untrusted automation (μέσω ARC/DKIM anomalies).  
• Αναπτύξτε **voice-biometric challenge phrases** για requests υψηλού ρίσκου τηλεφωνικά.  
• Προσομοιώνετε συνεχώς AI-generated lures σε awareness προγράμματα – τα στατικά templates είναι απαρχαιωμένα.

Δείτε επίσης – agentic browsing abuse για credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Εκτός από το κλασικό push-bombing, οι operators απλά **αναγκάζουν μια νέα εγγραφή MFA** κατά τη διάρκεια της κλήσης στο help-desk, ακυρώνοντας το υπάρχον token του χρήστη. Οποιοδήποτε επακόλουθο prompt σύνδεσης φαίνεται νόμιμο στο θύμα.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Παρακολούθηση για συμβάντα AzureAD/AWS/Okta όπου **`deleteMFA` + `addMFA`** συμβαίνουν **εντός λεπτών από την ίδια IP**.



## Clipboard Hijacking / Pastejacking

Οι επιτιθέμενοι μπορούν σιωπηλά να αντιγράψουν κακόβουλες εντολές στο clipboard του θύματος από μια compromised ή typosquatted web page και να ξεγελάσουν τον χρήστη ώστε να τις επικολλήσει μέσα στο **Win + R**, **Win + X** ή σε ένα terminal παράθυρο, εκτελώντας arbitrary code χωρίς οποιοδήποτε download ή attachment.


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Οι χειριστές ολοένα και περισσότερο τοποθετούν τις phishing ροές τους πίσω από έναν απλό έλεγχο συσκευής, ώστε οι desktop crawlers να μην φτάνουν ποτέ στις τελικές σελίδες. Ένα κοινό μοτίβο είναι ένα μικρό script που ελέγχει για touch-capable DOM και αποστέλλει το αποτέλεσμα σε ένα server endpoint· οι non‑mobile clients λαμβάνουν HTTP 500 (ή μια κενή σελίδα), ενώ στους mobile users σερβίρεται ολόκληρη η ροή.

Ελάχιστο client snippet (τυπική λογική):
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
- Θέτει ένα session cookie κατά την πρώτη φόρτωση.
- Αποδέχεται `POST /detect {"is_mobile":true|false}`.
- Επιστρέφει 500 (ή placeholder) στις επόμενες GET όταν `is_mobile=false`; σερβίρει phishing μόνο αν `true`.

Ευριστικές μέθοδοι ανίχνευσης και εντοπισμού:
- Ερώτημα urlscan: `filename:"detect_device.js" AND page.status:500`
- Web τηλεμετρία: σειρά `GET /static/detect_device.js` → `POST /detect` → HTTP 500 για μη‑mobile; οι νόμιμες διαδρομές για mobile θύματα επιστρέφουν 200 με επακόλουθο HTML/JS.
- Αποκλείστε ή εξετάστε σχολαστικά σελίδες που εξαρτούν το περιεχόμενο αποκλειστικά από `ontouchstart` ή παρόμοιους ελέγχους συσκευής.

Συμβουλές άμυνας:
- Εκτελέστε crawlers με mobile‑like fingerprints και ενεργοποιημένο JS για να αποκαλύψετε gated content.
- Ειδοποιήστε για ύποπτες απαντήσεις 500 μετά από `POST /detect` σε πρόσφατα καταχωρημένα domains.

## Αναφορές

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
