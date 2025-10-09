# Phishing कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## कार्यप्रणाली

1. Recon the victim
1. चुनें **victim domain**.
2. कुछ basic web enumeration करें **searching for login portals** जो victim इस्तेमाल करता है और **decide** करें कि आप किसे **impersonate** करेंगे।
3. कुछ **OSINT** का उपयोग करके **find emails**।
2. पर्यावरण तैयार करें
1. **Buy the domain** जिसे आप phishing assessment के लिए उपयोग करने वाले हैं
2. ईमेल सर्विस से संबंधित रिकॉर्ड **Configure the email service** (SPF, DMARC, DKIM, rDNS)
3. VPS को **gophish** के साथ configure करें
3. campaign तैयार करें
1. **email template** तैयार करें
2. credentials चुराने के लिए **web page** तैयार करें
4. अभियान लॉन्च करें!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: Domain name में original domain का एक महत्वपूर्ण **keyword** होता है (e.g., zelster.com-management.com).
- **hypened subdomain**: किसी subdomain के dot को hyphen से बदल दें (e.g., www-zelster.com).
- **New TLD**: वही domain नया **TLD** का उपयोग करता है (e.g., zelster.org)
- **Homoglyph**: domain नाम में किसी अक्षर को ऐसे अक्षरों से बदलना जो दिखने में समान हों (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** domain name के अंदर दो अक्षरों को swap करना (e.g., zelsetr.com).
- **Singularization/Pluralization**: domain के अंत में “s” जोड़ना या हटाना (e.g., zeltsers.com).
- **Omission**: domain नाम से एक अक्षर हटाना (e.g., zelser.com).
- **Repetition:** domain नाम में किसी अक्षर को repeat करना (e.g., zeltsser.com).
- **Replacement**: Homoglyph जैसा लेकिन कम stealthy। domain के किसी अक्षर को बदलना, संभवतः keyboard पर पास के अक्षर से (e.g, zektser.com).
- **Subdomained**: domain नाम के अंदर एक dot डालना (e.g., ze.lster.com).
- **Insertion**: domain नाम में एक अक्षर insert करना (e.g., zerltser.com).
- **Missing dot**: TLD को domain नाम में append करना। (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

कई कारणों (solar flares, cosmic rays, या hardware errors) से stored या communication में कुछ **bits** अपने आप flip हो सकते हैं।

जब यह अवधारणा **DNS requests** पर लागू होती है, तो संभव है कि **domain जो DNS server को प्राप्त होता है** वह शुरू में request किया गया domain न हो।

उदाहरण के लिए, domain "windows.com" में एक single bit modification इसे "windnws.com" में बदल सकता है।

Attackers इसका फायदा उठा सकते हैं और victim के domain के समान कई bit-flipping domains register कर सकते हैं। उद्देश्य legitimate users को अपनी infrastructure पर redirect करना होता है।

और जानकारी के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

आप expired domain खोजने के लिए [https://www.expireddomains.net/](https://www.expireddomains.net) पर search कर सकते हैं जिसे आप उपयोग कर सकते हैं.\
यह सुनिश्चित करने के लिए कि आप जो expired domain खरीदने वाले हैं **पहले से अच्छा SEO** रखता है, आप यह देख सकते हैं कि वह किस तरह categorize किया गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Emails की खोज

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

और अधिक valid email addresses discover करने या जो addresses आपने पहले ही खोजे हैं उन्हें verify करने के लिए आप victim के smtp servers पर उन्हें brute-force करके चेक कर सकते हैं। [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, याद रखें कि अगर users अपने mails तक पहुँचने के लिए किसी भी web portal का उपयोग करते हैं, तो आप चेक कर सकते हैं कि वह **username brute force** के प्रति vulnerable है या नहीं, और संभव होने पर उस vulnerability का exploit करें।

## Configuring GoPhish

### इंस्टॉलेशन

आप इसे डाउनलोड कर सकते हैं: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download करके इसे `/opt/gophish` के अंदर decompress करें और `/opt/gophish/gophish` execute करें।\
आउटपुट में आपको port 3333 पर admin user के लिए एक password दिया जाएगा। इसलिए उस port तक पहुँचें और उन credentials का उपयोग करके admin password बदलें। आपको वह port local पर tunnel करने की जरूरत पड़ सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS प्रमाणपत्र कॉन्फ़िगरेशन**

इस चरण से पहले आपके पास वह **पहले ही खरीदा हुआ domain** होना चाहिए जिसे आप उपयोग करने वाले हैं और वह उस **VPS का IP** की ओर **pointing** कर रहा होना चाहिए जहाँ आप **gophish** को कॉन्फ़िगर कर रहे हैं।
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
**मेल कॉन्फ़िगरेशन**

इंस्टॉल करना शुरू करें: `apt-get install postfix`

फिर डोमेन को निम्न फ़ाइलों में जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**साथ ही /etc/postfix/main.cf के अंदर निम्न चर (variables) के मान बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** अपने डोमेन नाम में बदलें और **अपना VPS रीस्टार्ट करें.**

अब, VPS के **ip address** की ओर संकेत करते हुए `mail.<domain>` का एक **DNS A record** बनाएं और `mail.<domain>` की ओर संकेत करते हुए एक **DNS MX** रिकॉर्ड बनाएं

अब ईमेल भेजने का परीक्षण करें:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish के निष्पादन को रोकें और इसे कॉन्फ़िगर करें।\
`/opt/gophish/config.json` को निम्न के रूप में संशोधित करें (https के उपयोग पर ध्यान दें):
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
**gophish सेवा कॉन्फ़िगर करें**

gophish सेवा बनाने के लिए ताकि इसे स्वतः शुरू किया जा सके और एक सेवा के रूप में प्रबंधित किया जा सके, आप `/etc/init.d/gophish` फ़ाइल निम्नलिखित सामग्री के साथ बना सकते हैं:
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
सेवा का कॉन्फ़िगरेशन पूरा करें और इसकी जाँच करें:
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
## मेल सर्वर और डोमेन कॉन्फ़िगर करना

### इंतजार करें और वैध रहें

डोमेन जितना पुराना होगा, उसे स्पैम के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए आपको phishing assessment से पहले जितना संभव हो उतना समय (कम से कम 1 सप्ताह) इंतजार करना चाहिए। इसके अलावा, अगर आप प्रतिष्ठा से जुड़ा सेक्टर का एक पेज रखते हैं तो प्राप्त होने वाली प्रतिष्ठा बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह इंतजार करना पड़े, आप अब सब कुछ कॉन्फ़िगर करना पूरा कर सकते हैं।

### Reverse DNS (rDNS) रिकॉर्ड कॉन्फ़िगर करें

एक rDNS (PTR) रिकॉर्ड सेट करें जो VPS के IP address को डोमेन नाम पर resolve करे।

### Sender Policy Framework (SPF) रिकॉर्ड

आपको **नए डोमेन के लिए SPF रिकॉर्ड कॉन्फ़िगर करें**। यदि आप नहीं जानते कि SPF रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

आप अपना SPF policy जनरेट करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS मशीन के IP का उपयोग करें)

![](<../../images/image (1037).png>)

यह वह कंटेंट है जो डोमेन के TXT रिकॉर्ड में सेट किया जाना चाहिए:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### डोमेन-आधारित संदेश प्रमाणीकरण, रिपोर्टिंग और अनुपालन (DMARC) रिकॉर्ड

आपको नए डोमेन के लिए **DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**इस पेज को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको hostname `_dmarc.<domain>` की ओर संकेत करते हुए निम्नलिखित सामग्री के साथ एक नया DNS TXT रिकॉर्ड बनाना होगा:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM कुंजी द्वारा जनरेट किए गए दोनों B64 मानों को जोड़ना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com)\ का उपयोग करके कर सकते हैं। बस पेज खोलें और वे जो पता देते हैं उस पते पर एक ईमेल भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप भी `check-auth@verifier.port25.com` पर ईमेल भेजकर और **प्रतिक्रिया पढ़कर** **अपने ईमेल कॉन्फ़िगरेशन की जाँच कर सकते हैं** (इसके लिए आपको **open** port **25** करना होगा और प्रतिक्रिया को फ़ाइल _/var/mail/root_ में देखना होगा यदि आप ईमेल root के रूप में भेजते हैं).\
सुनिश्चित करें कि आप सभी परीक्षण पास करते हैं:
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
आप अपने नियंत्रण वाले **Gmail खाते में संदेश भेज सकते हैं**, और अपने Gmail इनबॉक्स में **email’s headers** की जाँच करें, `dkim=pass` `Authentication-Results` header field में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist से हटाना

The page [www.mail-tester.com](https://www.mail-tester.com) आपको बता सकता है कि आपका डोमेन spamhouse द्वारा ब्लॉक किया जा रहा है या नहीं। आप अपने डोमेन/IP को हटाने का अनुरोध कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist से हटाना

​​आप अपने डोमेन/IP को हटाने का अनुरोध कर सकते हैं: [https://sender.office.com/](https://sender.office.com).

## GoPhish Campaign बनाएं और लॉन्च करें

### प्रेषक प्रोफ़ाइल

- प्रेषक प्रोफ़ाइल की पहचान के लिए कुछ **नाम सेट करें**
- तय करें कि आप किस खाते से phishing ईमेल भेजने वाले हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन सुनिश्चित करें कि Ignore Certificate Errors को चेक किया गया हो

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह अनुशंसा की जाती है कि "**Send Test Email**" फ़ंक्शन का उपयोग करके जाँच करें कि सब कुछ काम कर रहा है।\
> मैं सुझाव दूँगा कि **send the test emails to 10min mails addresses** ताकि परीक्षण करते समय ब्लैकलिस्ट होने से बचा जा सके।

### ईमेल टेम्पलेट

- टेम्पलेट की पहचान के लिए कुछ **नाम सेट करें**
- फिर एक **subject** लिखें (कुछ अजीब नहीं, बस ऐसा कुछ जो आप एक सामान्य ईमेल में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया हुआ है
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
Note that **in order to increase the credibility of the email**, यह सुझाव दिया जाता है कि क्लाइंट के किसी ईमेल से कुछ signature उपयोग करें। सुझाव:

- किसी **अवस्थित पते (non existent address)** पर ईमेल भेजें और देखें कि उत्तर में कोई signature आता है या नहीं।
- ऐसी **public emails** जैसे info@ex.com या press@ex.com या public@ex.com खोजें और उन्हें ईमेल भेजें और जवाब का इंतजार करें।
- किसी **valid discovered** ईमेल से संपर्क करने की कोशिश करें और जवाब का इंतजार करें।

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template भी **attach files to send** की अनुमति देता है। यदि आप किसी specially crafted files/documents के जरिए NTLM challenges चुराना चाहते हैं तो [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- **Write a name**
- **Write the HTML code** of the web page. ध्यान दें कि आप वेब पेजों को **import** कर सकते हैं।
- **Mark Capture Submitted Data** और **Capture Passwords**
- एक **redirection** सेट करें

![](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको पेज के HTML को संशोधित करना होगा और लोकल में कुछ टेस्ट करने होंगे (शायद कुछ Apache server का उपयोग करके) **जब तक कि आप परिणामों से संतुष्ट न हों।** फिर उस HTML को बॉक्स में लिखें.\
> ध्यान दें कि यदि आपको HTML के लिए कुछ static resources (जैसे CSS और JS पेज) उपयोग करने की आवश्यकता है तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर उन्हें _**/static/\<filename>**_ से एक्सेस कर सकते हैं।

> [!TIP]
> रिडायरेक्शन के लिए आप उपयोगकर्ताओं को पीड़ित की legit मुख्य वेबसाइट पर redirect कर सकते हैं, या उदाहरण के लिए उन्हें _/static/migration.html_ पर redirect करें, कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 सेकंड के लिए दिखाएँ और फिर बताएं कि प्रक्रिया सफल रही**.

### Users & Groups

- एक नाम सेट करें
- **Import the data** (ध्यान दें कि template को उपयोग करने के लिए उदाहरण के लिए आपको प्रत्येक user का firstname, last name और email address चाहिए)

![](<../../images/image (163).png>)

### Campaign

अंत में, एक campaign बनाएँ — नाम, email template, landing page, URL, sending profile और group चुनें। ध्यान दें कि URL वह link होगा जो victims को भेजा जाएगा।

ध्यान दें कि **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> मैं सुझाव दूंगा कि टेस्ट भेजने के लिए **10min mails addresses** का उपयोग करें ताकि टेस्ट करते समय ब्लैकलिस्ट में न आने का जोखिम कम रहे।

सब कुछ तैयार होने के बाद, बस campaign लॉन्च करें!

## वेबसाइट क्लोनिंग

यदि किसी कारणवश आप वेबसाइट को clone करना चाहते हैं तो निम्नलिखित पृष्ठ देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्यतः Red Teams के लिए) में आप ऐसी फ़ाइलें भी भेजना चाहेंगे जिनमें किसी प्रकार का backdoor हो (शायद एक C2 या शायद कुछ ऐसा जो authentication ट्रिगर करे)।\
कुछ उदाहरणों के लिए निम्नलिखित पृष्ठ देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला हमला काफी चालाक है क्योंकि आप एक असली वेबसाइट का नकली रूप दिखा कर उपयोगकर्ता द्वारा भरे गए जानकारी को इकट्ठा कर रहे हैं। दुःख की बात यह है कि यदि उपयोगकर्ता ने सही पासवर्ड नहीं डाला या यदि उस application में जिसे आपने fake किया है 2FA कॉन्फ़िगर है, तो **यह जानकारी आपको धोखा दिए गए उपयोगकर्ता की impersonation करने की अनुमति नहीं देगी**।

यहीं पर [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे टूल्स उपयोगी होते हैं। यह टूल आपको MitM जैसा attack जनरेट करने की अनुमति देगा। मूल रूप से, हमला निम्नलिखित तरीके से काम करता है:

1. आप असली webpage के login form की **impersonate** करते हैं।
2. उपयोगकर्ता अपनी **credentials** आपकी fake page पर **send** करता है और टूल उन्हें असली webpage पर भेजता है, **देखता है कि credentials काम करते हैं या नहीं**।
3. यदि अकाउंट **2FA** के साथ कॉन्फ़िगर है, तो MitM पेज इसके लिए पूछेगा और जैसे ही **user उसे दर्ज करता है** टूल उसे असली वेब पेज पर भेज देगा।
4. एक बार उपयोगकर्ता authenticated हो जाने पर आप (attacker के रूप में) **captured कर चुके होंगे credentials, 2FA, cookie और किसी भी interaction की जानकारी** जबकि टूल MitM कर रहा होता है।

### Via VNC

यदि आप victime को असली पेज जैसा दिखने वाले malicious पेज पर भेजने के बजाय, उसे एक **VNC session** पर भेजें जिसमें ब्राउज़र असली वेब पेज से connected हो — तो क्या होगा? आप देख पाएंगे कि वह क्या करता है, पासवर्ड, इस्तेमाल किया गया MFA, cookies चुरा पाएंगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं।

## Detecting the detection

स्पष्ट रूप से यह जानने का एक बेहतरीन तरीका कि आपको पकड़ लिया गया है या नहीं, यह है कि आप अपनी domain को blacklists में खोजें। यदि यह सूचीबद्ध दिखाई देता है, तो किसी न किसी तरह आपका domain suspicious पाया गया है।\
एक आसान तरीका यह जाँचने का कि क्या आपका domain किसी blacklist में है वह है [https://malwareworld.com/](https://malwareworld.com)

हालाँकि, अन्य तरीके भी हैं जिनसे पता चलता है कि पीड़ित **actively suspicious phishing activity खोज रहा है** जैसा कि नीचे समझाया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप पीड़ित के domain के बहुत समान नाम वाला एक domain खरीद सकते हैं **और/या एक सबडोमेन के लिए certificate जनरेट कर सकते हैं** जो आपके द्वारा कंट्रोल किए जाने वाले domain का हो और उस सबडोमेन में पीड़ित के domain का **keyword** शामिल हो। यदि पीड़ित उनके साथ किसी भी प्रकार की **DNS या HTTP interaction** करता है, तो आपको पता चल जाएगा कि **वह सक्रिय रूप से suspicious domains खोज रहा है** और आपको बहुत stealth होना होगा।

### फ़िशिंग का मूल्यांकन करें

देखें कि आपका ईमेल spam फ़ोल्डर में जाएगा या ब्लॉक हो जाएगा या सफल होगा — इसके लिए [**Phishious** ](https://github.com/Rices/Phishious) का उपयोग करें।

## High- Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion सेट्स अक्सर ईमेल ल्यूर्स को पूरी तरह से छोड़ देते हैं और सीधे service-desk / identity-recovery वर्कफ़्लो को लक्ष्य बनाते हैं ताकि MFA को हराया जा सके। यह हमला पूरी तरह से "living-off-the-land" है: एक बार ऑपरेटर के पास valid credentials आ जाएं तो वे built-in admin tooling के साथ pivot करते हैं – किसी मालवेयर की जरूरत नहीं पड़ती।

### Attack flow
1. Recon the victim
   - LinkedIn, data breaches, public GitHub आदि से personal & corporate details इकट्ठा करें।
   - उच्च-मूल्य की पहचानें (executives, IT, finance) निर्धारित करें और password / MFA reset के लिए **exact help-desk process** को enumerate करें।
2. Real-time social engineering
   - help-desk को फोन, Teams या चैट पर लक्ष्य की impersonation करते हुए contact करें (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
   - पहले से इकट्ठा किया गया PII प्रदान करें ताकि knowledge-based verification पास हो जाए।
   - एजेंट को मनाएं कि वह **MFA secret reset** करे या पंजीकृत मोबाइल नंबर पर **SIM-swap** करे।
3. Immediate post-access actions (≤60 min in real cases)
   - किसी भी web SSO portal के माध्यम से foothold स्थापित करें।
   - AD / AzureAD का enumeration built-ins के साथ करें (कोई बाइनरी ड्रॉप नहीं):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
   - **WMI**, **PsExec**, या environment में पहले से whitelisted वैध **RMM** agents के साथ lateral movement करें।

### Detection & Mitigation
   - help-desk identity recovery को एक **privileged operation** मानें – step-up auth & manager approval आवश्यक करें।
   - ऐसे निगरानी नियम (Identity Threat Detection & Response (ITDR) / **UEBA**) लागू करें जो अलर्ट करें जब:
     - MFA method बदला गया हो + नई डिवाइस / geo से authentication हुआ हो।
     - उसी principal (user → admin) का तात्कालिक elevation हुआ हो।
   - help-desk कॉल्स रिकॉर्ड करें और किसी भी reset से पहले **पहले से-registered नंबर** पर call-back अनिवार्य करें।
   - Implement **Just-In-Time (JIT) / Privileged Access** ताकि newly reset accounts स्वतः high-privilege tokens inherit न करें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
कमोडिटी क्रूज़ उच्च-टच ऑपरेशन्स की लागत को मुआवजा देने के लिए mass attacks का उपयोग करते हैं जो **search engines & ad networks को delivery channel** में बदल देते हैं।

1. **SEO poisoning / malvertising** एक fake result जैसे `chromium-update[.]site` को top search ads में धकेलता है।
2. पीड़ित एक छोटा **first-stage loader** डाउनलोड करता है (अक्सर JS/HTA/ISO)। Unit 42 ने उदाहरणों में देखा:
   - `RedLine stealer`
   - `Lumma stealer`
   - `Lampion Trojan`
3. Loader ब्राउज़र cookies + credential DBs exfiltrate करता है, फिर एक **silent loader** खींचता है जो real-time में तय करता है कि क्या deploy करना है:
   - RAT (उदा। AsyncRAT, RustDesk)
   - ransomware / wiper
   - persistence component (registry Run key + scheduled task)

### Hardening tips
- नए-रजिस्टर्ड domains को ब्लॉक करें और *search-ads* के साथ-साथ ईमेल पर भी **Advanced DNS / URL Filtering** लागू करें।
- सॉफ़्टवेयर इंस्टॉलेशन को signed MSI / Store packages तक सीमित रखें, नीति द्वारा `HTA`, `ISO`, `VBS` execution को deny करें।
- ब्राउज़र के child processes को installers खोलते हुए मॉनिटर करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
- पहले-स्टेज loaders द्वारा अक्सर abused किए जाने वाले LOLBins की खोज करें (उदा। `regsvr32`, `curl`, `mshta`)।

---

## AI-Enhanced Phishing Operations
हमलावर अब पूरी तरह व्यक्तिगत ल्यूर्स और real-time interaction के लिए **LLM & voice-clone APIs** को श्रृंखलाबद्ध करते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
| Automation | >100k ईमेल / SMS generate & भेजना, randomised wording और tracking links के साथ। |
| Generative AI | सार्वजनिक M&A, सोशल मीडिया से अंदरूनी चुटकुले का संदर्भ देकर *one-off* ईमेल बनाना; callback scam में CEO की deep-fake आवाज। |
| Agentic AI | स्वतः डोमेन रजिस्टर करना, open-source intel scrape करना, जब victim क्लिक करे पर creds सबमिट न करे तो अगले चरण के मेल खुद बनाना। |

**Defence:**
• ARC/DKIM anomalities के जरिए untrusted automation से भेजे गए संदेशों पर **dynamic banners** जोड़ें।  
• उच्च-जोखिम फोन अनुरोधों के लिए **voice-biometric challenge phrases** लागू करें।  
• awareness programmes में लगातार AI-generated ल्यूर्स का simulation करें – static templates अब obsolete हैं।

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
क्लासिक push-bombing के अलावा, ऑपरेटर केवल help-desk कॉल के दौरान **नई MFA registration को force कर देते हैं**, जिससे उपयोगकर्ता का मौजूदा token nullify हो जाता है। किसी भी subsequent login prompt पीड़ित को legitimate प्रतीत होता है।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta घटनाओं के लिए मॉनिटर करें जहाँ **`deleteMFA` + `addMFA`** एक ही IP से कुछ ही मिनटों के भीतर होते हैं।



## Clipboard Hijacking / Pastejacking

हमलावर कम्प्रोमाइज़्ड या typosquatted वेब पेज से चुपचाप मैलिशियस कमांड पीड़ित के क्लिपबोर्ड में कॉपी कर सकते हैं और फिर उपयोगकर्ता को धोखा देकर उन्हें **Win + R**, **Win + X** या एक terminal window में पेस्ट करवा देते हैं, जिससे बिना किसी डाउनलोड या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
ऑपरेटर अपने phishing flows को एक सरल डिवाइस चेक के पीछे छिपा रहे हैं, ताकि desktop crawlers अंतिम पेजों तक कभी न पहुँचें। एक आम पैटर्न यह है कि एक छोटा script touch-capable DOM के लिए टेस्ट करता है और परिणाम को एक server endpoint पर पोस्ट करता है; non‑mobile clients को HTTP 500 (या एक खाली पेज) मिलता है, जबकि mobile users को पूरा flow दिखाया जाता है।

क्लाइंट का न्यूनतम स्निपेट (सामान्य लॉजिक):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` लॉजिक (सरलीकृत):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
अक्सर देखे जाने वाले सर्वर व्यवहार:
- पहली लोड पर session cookie सेट करता है।
- स्वीकार करता है `POST /detect {"is_mobile":true|false}`।
- जब `is_mobile=false` तब बाद की GETs पर 500 (या placeholder) लौटाता है; phishing तभी सर्व करता है जब `is_mobile=true`।

हंटिंग और डिटेक्शन हीयूरिस्टिक्स:
- urlscan क्वेरी: `filename:"detect_device.js" AND page.status:500`
- वेब टेलीमेट्री: `GET /static/detect_device.js` → `POST /detect` → non‑mobile के लिए HTTP 500; वैध मोबाइल पाथ 200 लौटाते हैं और उसके बाद HTML/JS मिलते हैं।
- उन पृष्ठों को ब्लॉक या गहराई से जाँचें जिनकी सामग्री केवल `ontouchstart` या समान डिवाइस चेक्स पर निर्भर हो।

रक्षा सुझाव:
- गेटेड कंटेंट उजागर करने के लिए crawlers को mobile‑like fingerprints और JS सक्षम करके चलाएँ।
- नए पंजीकृत डोमेन पर `POST /detect` के बाद आने वाली संदिग्ध 500 responses पर अलर्ट स्थापित करें।

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
