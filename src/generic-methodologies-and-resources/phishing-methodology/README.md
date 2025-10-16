# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## कार्यप्रणाली

1. Recon the victim
1. Select the **लक्षित डोमेन**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **emails खोजें**.
2. Prepare the environment
1. **Buy the domain** जिसे आप phishing assessment के लिए उपयोग करने वाले हैं
2. **Configure the email service** से जुड़े रिकॉर्ड्स (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **ईमेल टेम्पलेट**
2. Prepare the **वेब पेज** ताकि क्रेडेंशियल्स चोरी किए जा सकें
4. Launch the campaign!

## समान डोमेन नाम जेनरेट करें या एक भरोसेमंद डोमेन खरीदें

### Domain Name Variation Techniques

- **Keyword**: डोमेन नाम में मूल डोमेन का एक महत्वपूर्ण **keyword** शामिल होता है (उदा., zelster.com-management.com)।
- **hypened subdomain**: किसी subdomain के लिए **dot को hyphen से बदलें** (उदा., www-zelster.com)।
- **New TLD**: उसी डोमेन का **नई TLD** उपयोग करना (उदा., zelster.org)
- **Homoglyph**: डोमेन नाम में एक अक्षर को ऐसे **letters जो दिखने में समान हों** से बदलना (उदा., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** डोमेन नाम के भीतर दो अक्षरों की **स्थान बदलना** (उदा., zelsetr.com)।
- **Singularization/Pluralization**: डोमेन नाम के अंत में “s” जोड़ना या हटाना (उदा., zeltsers.com)।
- **Omission**: डोमेन नाम से किसी एक अक्षर को **हटा देना** (उदा., zelser.com)।
- **Repetition:** डोमेन नाम में किसी एक अक्षर को **दोहराना** (उदा., zeltsser.com)।
- **Replacement**: homoglyph जैसा, पर कम stealthy। यह डोमेन नाम के किसी अक्षर को बदलता है, संभवतः कीबोर्ड पर मूल अक्षर के पास वाला अक्षर (उदा., zektser.com)।
- **Subdomained**: डोमेन नाम के अंदर एक **dot** इंट्रोड्यूस करना (उदा., ze.lster.com)।
- **Insertion**: डोमेन नाम में एक अक्षर **इन्सर्ट करना** (उदा., zerltser.com)।
- **Missing dot**: TLD को डोमेन नाम के साथ जोड़ देना। (उदा., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

ऐसी संभावनाएँ हैं कि संग्रहीत या संचारित कुछ बिट्स किसी कारण से अपने आप flip हो जाएँ — जैसे सौर फ्लेयर्स, cosmic rays, या hardware errors के कारण।

जब इस कॉन्सेप्ट को DNS requests पर लागू किया जाता है, तो यह संभव है कि **DNS सर्वर द्वारा प्राप्त डोमेन** वह न हो जो मूल रूप से अनुरोधित किया गया था।

उदाहरण के लिए, "windows.com" में एक सिंगल बिट मॉडिफिकेशन इसे "windnws.com" में बदल सकता है।

Attackers इस पहलू का लाभ उठाकर multiple bit-flipping domains रजिस्टर कर सकते हैं जो victim के डोमेन से मिलते-जुलते हों। उनका उद्देश्य वैध उपयोगकर्ताओं को अपने इन्फ्रास्ट्रक्चर पर redirect करना होता है।

अधिक जानकारी के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

आप [https://www.expireddomains.net/](https://www.expireddomains.net) पर खोज कर सकते हैं कि कोई expired domain उपलब्ध है जिसे आप उपयोग कर सकते हैं।\
यह सुनिश्चित करने के लिए कि आप जो expired domain खरीदने जा रहे हैं उसके पास पहले से अच्छा SEO है, आप देख सकते हैं कि यह किस तरह categorize किया गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## ईमेल की खोज

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

अधिक वैध ईमेल एड्रेस खोजने या जिनको आपने पहले ही खोज लिया है उन्हें verify करने हेतु आप देख सकते हैं कि क्या आप victim के smtp servers पर उन्हें brute-force कर सकते हैं। [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, अगर उपयोगकर्ता अपने मेल्स एक्सेस करने के लिए किसी भी वेब पोर्टल का उपयोग करते हैं, तो यह न भूलें कि आप यह जांच सकते हैं कि वह पोर्टल username brute force के प्रति vulnerable है या नहीं, और संभव हो तो उस vulnerability का exploit कर सकते हैं।

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
आपको आउटपुट में admin user के लिए port 3333 पर एक password दिया जाएगा। इसलिए, उस पोर्ट तक पहुँचें और उन credentials का उपयोग करके admin password बदलें। संभव है कि आपको उस पोर्ट को लोकल पर tunnel करना पड़े:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS प्रमाणपत्र कॉन्फ़िगरेशन**

इस चरण से पहले आपके पास **already bought the domain** होना चाहिए जिसे आप उपयोग करने जा रहे हैं, और वह उस **IP of the VPS** की ओर **pointing** कर रहा होना चाहिए जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

फिर निम्न फ़ाइलों में डोमेन जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**इसके अलावा /etc/postfix/main.cf के अंदर निम्न वेरिएबल्स के मान बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** को अपने डोमेन नाम से बदलें और **अपने VPS को रिस्टार्ट करें।**

अब `mail.<domain>` का एक **DNS A record** बनाएं जो VPS के **ip address** की ओर इशारा करे और एक **DNS MX** रिकॉर्ड बनाएं जो `mail.<domain>` की ओर इशारा करे

अब एक ईमेल भेजकर टेस्ट करें:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish के निष्पादन को रोकें और इसे कॉन्फ़िगर करें.\  
`/opt/gophish/config.json` को निम्नलिखित के अनुसार संशोधित करें (https के उपयोग पर ध्यान दें):
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
**gophish service कॉन्फ़िगर करें**

gophish service बनाने के लिए ताकि इसे स्वचालित रूप से शुरू किया जा सके और एक service के रूप में प्रबंधित किया जा सके, आप निम्नलिखित सामग्री के साथ फ़ाइल `/etc/init.d/gophish` बना सकते हैं:
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
service की कॉन्फ़िगरेशन पूरी करें और यह क्या कर रहा है इसकी जांच करें:
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

### प्रतीक्षा करें और वैध बनें

जिस डोमेन की उम्र अधिक होगी, उसे spam के रूप में पकड़ा जाने की संभावना कम होगी। इसलिए phishing assessment से पहले जितना संभव हो उतना समय प्रतीक्षा करें (कम से कम 1week)। इसके अलावा, अगर आप किसी प्रतिष्ठा से जुड़े सेक्टर के बारे में पेज डालते हैं तो प्राप्त reputation बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह इंतज़ार करना पड़े, आप अभी सब कुछ कॉन्फ़िगर कर सकते हैं।

### रिवर्स DNS (rDNS) रिकॉर्ड कॉन्फ़िगर करें

VPS के IP address को डोमेन नाम पर resolve करने वाला rDNS (PTR) रिकॉर्ड सेट करें।

### Sender Policy Framework (SPF) रिकॉर्ड

आपको **नए डोमेन के लिए एक SPF record कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि SPF record क्या है तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

आप अपने SPF policy जनरेट करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS मशीन का IP उपयोग करें)

![](<../../images/image (1037).png>)

यह वह सामग्री है जिसे डोमेन के अंदर एक TXT record में सेट करना होगा:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) रिकॉर्ड

आपको नए डोमेन के लिए **DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**यह पृष्ठ पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको निम्नलिखित सामग्री के साथ होस्टनेम `_dmarc.<domain>` की ओर संकेत करते हुए एक नया DNS TXT रिकॉर्ड बनाना होगा:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा जनरेट किए गए दोनों B64 मानों को जोड़ना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने ईमेल कॉन्फ़िगरेशन स्कोर की जाँच करें

आप यह कर सकते हैं [https://www.mail-tester.com/](https://www.mail-tester.com)\
बस पेज पर जाएँ और उन्हें जो पता देते हैं उस पते पर एक ईमेल भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप भी **अपनी ईमेल कॉन्फ़िगरेशन की जाँच** `check-auth@verifier.port25.com` को एक ईमेल भेजकर और **प्रतिक्रिया पढ़कर** (इसके लिए आपको **खोलना** port **25** और यदि आप ईमेल root के रूप में भेजते हैं तो प्रतिक्रिया फ़ाइल _/var/mail/root_ में देखें)।\
जाँचें कि आप सभी परीक्षण पास कर रहे हैं:
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
आप अपने नियंत्रण वाले किसी Gmail पर भी **संदेश भेज सकते हैं**, और अपने Gmail इनबॉक्स में **ईमेल के हेडर** की जाँच करें; `dkim=pass` को `Authentication-Results` हेडर फ़ील्ड में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist से हटाना

The page [www.mail-tester.com](https://www.mail-tester.com) संकेत दे सकता है कि आपका domain spamhouse द्वारा ब्लॉक किया जा रहा है। आप अपने domain/IP को हटाने के लिए अनुरोध कर सकते हैं: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist से हटाना

आप अपने domain/IP को हटाने के लिए यहाँ अनुरोध कर सकते हैं: [https://sender.office.com/](https://sender.office.com).

## GoPhish Campaign बनाएं और लॉन्च करें

### भेजने की प्रोफ़ाइल

- प्रेषक प्रोफ़ाइल की पहचान के लिए कोई **नाम** सेट करें
- तय करें कि आप किस खाते से phishing emails भेजने वाले हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, पर सुनिश्चित करें कि `Ignore Certificate Errors` को चेक किया गया है

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह सुझाया जाता है कि सब कुछ सही काम कर रहा है यह जाँचने के लिए "**Send Test Email**" फ़ंक्शन का उपयोग करें.\
> मैं सुझाव दूँगा कि tests करते समय blacklisted होने से बचने के लिए **send the test emails to 10min mails addresses**.

### ईमेल टेम्पलेट

- टेम्पलेट की पहचान के लिए कोई **नाम** सेट करें
- फिर कोई **विषय** लिखें (कुछ अजीब नहीं, बस कुछ ऐसा जो आप एक सामान्य ईमेल में पढ़ने की उम्मीद कर सकें)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया है
- **ईमेल टेम्पलेट** लिखें (आप निम्न उदाहरण की तरह variables का उपयोग कर सकते हैं):
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
ध्यान दें कि ईमेल की विश्वसनीयता बढ़ाने के लिए, यह सुझाव दिया जाता है कि क्लाइंट के किसी ईमेल का कुछ सिग्नेचर इस्तेमाल किया जाए। सुझाव:

- किसी **non existent address** पर ईमेल भेजें और जाँचे कि प्रतिक्रिया में कोई सिग्नेचर है या नहीं।
- ऐसे **public emails** खोजें जैसे info@ex.com या press@ex.com या public@ex.com और उन्हें ईमेल भेजकर प्रतिक्रिया का इंतजार करें।
- किसी **valid discovered** ईमेल से संपर्क करने की कोशिश करें और प्रतिक्रिया का इंतजार करें।

![](<../../images/image (80).png>)

> [!TIP]
> Email Template आपको भेजने के लिए **attach files to send** भी करने की अनुमति देता है। यदि आप NTLM challenges कुछ specially crafted files/documents के माध्यम से भी चुराना चाहते हैं तो [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **name** लिखें
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप वेब पेज **import** भी कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को चिन्हित करें
- एक **redirection** सेट करें

![](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको पेज का HTML code संशोधित करना होगा और लोकल में कुछ टेस्ट करने होंगे (शायद किसी Apache server का उपयोग करते हुए) **जब तक आपको परिणाम पसंद न आए।** फिर उस HTML को बॉक्स में लिखें।\
> ध्यान रखें कि यदि HTML के लिए आपको कुछ static resources (जैसे CSS और JS पेज) चाहिए तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर उन्हें _**/static/\<filename>**_ से एक्सेस कर सकते हैं।

> [!TIP]
> रीडायरेक्शन के लिए आप उपयोगकर्ताओं को पीड़ित की legit मुख्य वेब पेज पर redirect कर सकते हैं, या उदाहरण के लिए उन्हें _/static/migration.html_ पर भेज सकते हैं, 5 सेकंड के लिए कोई **spinning wheel** ([https://loading.io/](https://loading.io/)) रखकर फिर सूचित करें कि प्रोसेस सफल रहा।

### Users & Groups

- एक नाम सेट करें
- डेटा **Import** करें (नोट: उदाहरण के लिए template का उपयोग करने के लिए प्रत्येक उपयोगकर्ता का firstname, last name और email address होना आवश्यक है)

![](<../../images/image (163).png>)

### Campaign

अंततः, एक campaign बनाएं जिसमें एक नाम, email template, landing page, URL, sending profile और group चुने। ध्यान दें कि URL वही लिंक होगा जो शिकारियों को भेजा जाएगा

ध्यान दें कि **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> मैं सुझाव दूँगा कि टेस्ट ईमेल भेजने के लिए 10min mails addresses का प्रयोग करें ताकि टेस्ट करते समय ब्लैकलिस्ट होने से बचा जा सके।

जब सब कुछ तैयार हो जाए, तो बस campaign लॉन्च करें!

## Website Cloning

यदि किसी कारणवश आप वेबसाइट को clone करना चाहते हैं तो निम्न पेज देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्यतः Red Teams के लिए) में आप यह भी चाहेंगे कि आप ऐसे files भेजें जिनमें किसी प्रकार का backdoor हो (शायद कोई C2 या सिर्फ कुछ जो authentication को ट्रिगर करे)।\
कुछ उदाहरणों के लिए निम्न पेज देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला हमला काफी चालाक है क्योंकि आप एक असली वेबसाइट का नकली रूप बना रहे हैं और उपयोगकर्ता द्वारा सेट की गई जानकारी इकट्ठा कर रहे हैं। दुर्भाग्यवश, यदि उपयोगकर्ता ने सही password नहीं डाला या यदि उस एप्लिकेशन में जिसे आपने नकली बनाया है 2FA configured है, तो **यह जानकारी आपको ट्रिक किए गए उपयोगकर्ता का impersonate करने की अनुमति नहीं देगी**।

यहीं पर [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे टूल उपयोगी होते हैं। यह टूल आपको MitM जैसा हमला जनरेट करने की अनुमति देगा। मूल रूप से, हमला निम्न तरीके से काम करता है:

1. आप असली वेबपेज के login form का **impersonate** करते हैं।
2. उपयोगकर्ता अपने **credentials** को आपकी नकली पेज पर **send** करता है और टूल उन्हें असली वेबपेज पर भेजता है, **यह चेक करते हुए कि credentials काम कर रहे हैं या नहीं।**
3. यदि खाते में **2FA** configured है, तो MitM पृष्ठ उसके लिए पूछेगा और जब उपयोगकर्ता उसे दर्ज करेगा तो टूल उसे असली वेब पेज पर भेज देगा।
4. एक बार उपयोगकर्ता authenticated हो जाने पर आप (attacker के रूप में) **captured the credentials, the 2FA, the cookie and any information** रख पाएंगे हर इंटरैक्शन का जबकि टूल MitM कर रहा होता है।

### Via VNC

यदि आप शिकार को मूल पृष्ठ जैसी दिखने वाली किसी malicious page पर भेजने के बजाय उसे एक **VNC session with a browser connected to the real web page** पर भेजें तो क्या होगा? आप देख पाएँगे कि वह क्या करता है, password, उपयोग की गयी MFA, cookies इत्यादि चुरा पाएँगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं।

## Detecting the detection

स्पष्ट रूप से यह जानने का एक अच्छा तरीका कि क्या आपको पकड़ा गया है, यह है कि आप अपनी domain को blacklists में search करें। यदि यह सूचीबद्ध दिखाई दे तो किसी तरह आपकी domain को suspicious माना गया है।\
यह देखने का एक आसान तरीका है कि क्या आपकी domain किसी blacklist में है: [https://malwareworld.com/](https://malwareworld.com)

हालाँकि, अन्य तरीके भी हैं यह जानने के कि पीड़ित **actively looking for suspicions phishing activity in the wild** है जैसा कि यहाँ बताया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप पीड़ित की domain के बहुत समान नाम वाला एक domain खरीद सकते हैं **और/या एक certificate जेनरेट कर सकते हैं** अपने नियंत्रित किसी domain के **subdomain** के लिए जिसमें पीड़ित की domain का **keyword** शामिल हो। यदि **victim** उनके साथ किसी भी प्रकार की **DNS or HTTP interaction** करता है, तो आप जान जाएंगे कि **वह सक्रिय रूप से संदिग्ध domains खोज रहा है** और आपको बहुत stealth रहने की आवश्यकता होगी।

### Evaluate the phishing

देखें [**Phishious** ](https://github.com/Rices/Phishious) का उपयोग करके कि आपका ईमेल spam फ़ोल्डर में जाएगा या ब्लॉक हो जाएगा या सफल होगा।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion सेट्स अक्सर ईमेल लूर को पूरी तरह छोड़कर सीधे service-desk / identity-recovery workflow को निशाना बनाते हैं ताकि MFA को मात दी जा सके। यह हमला पूरी तरह "living-off-the-land" है: एक बार ऑपरेटर के पास valid credentials आ गए तो वे built-in admin tooling के साथ pivot करते हैं – कोई malware आवश्यक नहीं होता।

### Attack flow
1. Recon the victim
* LinkedIn, data breaches, public GitHub आदि से व्यक्तिगत और कॉर्पोरेट विवरण जमा करें।
* उच्च-मूल्य की पहचानें (executives, IT, finance) और password / MFA reset के लिए **exact help-desk process** को enumerate करें।
2. Real-time social engineering
* help-desk को फोन, Teams या चैट करें जबकि आप target का impersonate कर रहे हों (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
* knowledge-based verification पास करने के लिए पहले से इकट्ठा किए गए PII प्रदान करें।
* एजेंट को मनाएँ कि वह **reset the MFA secret** करे या किसी registered मोबाइल नंबर पर **SIM-swap** करे।
3. Immediate post-access actions (≤60 min in real cases)
* किसी भी web SSO portal के माध्यम से foothold स्थापित करें।
* AD / AzureAD को built-ins के साथ enumerate करें (कोई binaries drop नहीं किए गए):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement के लिए **WMI**, **PsExec**, या पहले से environment में whitelist किए गए legitimate **RMM** agents का उपयोग।

### Detection & Mitigation
* help-desk identity recovery को एक **privileged operation** मानें – step-up auth और manager approval आवश्यक करें।
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules तैनात करें जो अलर्ट करें जब:
* MFA method बदला गया हो + नए device / geo से authentication।
* उसी principal (user→admin) का तुरंत elevation।
* help-desk कॉल्स को रिकॉर्ड करें और किसी भी reset से पहले **call-back to an already-registered number** लागू करें।
* **Just-In-Time (JIT) / Privileged Access** लागू करें ताकि नए reset किए गए खाते स्वतः high-privilege tokens inherit न करें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews उच्च-मूल्य वाले ops की लागत का संतुलन ऐसे mass हमलों से करते हैं जो search engines & ad networks को delivery channel में बदल देते हैं।

1. **SEO poisoning / malvertising** एक नकली रिज़ल्ट जैसे `chromium-update[.]site` को टॉप search ads पर धकेलता है।
2. पीड़ित एक छोटा **first-stage loader** डाउनलोड करता है (अक्सर JS/HTA/ISO)। Unit 42 द्वारा देखे गए उदाहरण:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader ब्राउज़र cookies + credential DBs को exfiltrate करता है, फिर एक **silent loader** खींचता है जो realtime में तय करता है कि क्या deploy करना है:
* RAT (उदाहरण AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* newly-registered domains को ब्लॉक करें & search-ads के साथ-साथ e-mail पर भी **Advanced DNS / URL Filtering** लागू करें।
* सॉफ़्टवेयर इंस्टॉलेशन को signed MSI / Store packages तक सीमित करें, `HTA`, `ISO`, `VBS` के execution को नीति द्वारा deny करें।
* ब्राउज़र के child processes के द्वारा installers खोलने की निगरानी करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* उन LOLBins की तलाश करें जिन्हें first-stage loaders अक्सर abusing करते हैं (उदा. `regsvr32`, `curl`, `mshta`)।

---

## AI-Enhanced Phishing Operations
हमलावर अब fully personalised lures और real-time interaction के लिए **LLM & voice-clone APIs** को chain करते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• untrusted automation से भेजे गए संदेशों को हाइलाइट करने के लिए **dynamic banners** जोड़ें (ARC/DKIM anomalies के माध्यम से)।  
• high-risk phone requests के लिए **voice-biometric challenge phrases** लागू करें।  
• awareness programmes में लगातार AI-generated lures का simulation करें – static templates obsolete हो चुके हैं।

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
classic push-bombing के अलावा, ऑपरेटर बस help-desk कॉल के दौरान **force a new MFA registration** कर देते हैं, जिससे उपयोगकर्ता के मौजूदा token को nullify कर दिया जाता है। किसी भी बाद की login prompt पीड़ित के लिए легитिमेट दिखाई देगी।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
निम्नस्थितियों के लिए AzureAD/AWS/Okta इवेंट्स की निगरानी करें जहाँ **`deleteMFA` + `addMFA`** समान IP से कुछ ही मिनटों में होते हों।



## Clipboard Hijacking / Pastejacking

हमलावर compromised या typosquatted वेब पेज से चुपचाप पीड़ित के क्लिपबोर्ड में दुर्भावनापूर्ण कमांड कॉपी कर सकते हैं और फिर उपयोगकर्ता को धोखा देकर उन्हें **Win + R**, **Win + X** या एक terminal window में पेस्ट करवा सकते हैं, जिससे बिना किसी डाउनलोड या अटैचमेंट के arbitrary code निष्पादित हो सकता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
ऑपरेटर अक्सर अपने phishing flows को एक साधारण डिवाइस चेक के पीछे बंद कर देते हैं ताकि desktop crawlers कभी अंतिम पेजों तक न पहुँच पाएं। एक सामान्य पैटर्न यह है कि एक छोटा स्क्रिप्ट touch-capable DOM की जाँच करता है और परिणाम को एक server endpoint पर पोस्ट करता है; non‑mobile clients को HTTP 500 (या एक खाली पेज) मिलता है, जबकि mobile users को पूरा flow परोसा जाता है।

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
Server behaviour often observed:
- पहली लोड के दौरान एक session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- यदि `is_mobile=false` तो बाद के GETs पर 500 (या placeholder) लौटाता है; सिर्फ़ तभी phishing परोसता है जब `true` हो।

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequence of `GET /static/detect_device.js` → `POST /detect` → HTTP 500 for non‑mobile; legitimate mobile victim paths return 200 with follow‑on HTML/JS.
- उन पेजों को ब्लॉक या सावधानी से जाँचें जो कंटेंट को विशेष रूप से `ontouchstart` या समान device checks पर आधारित करते हैं।

Defence tips:
- मोबाइल‑जैसे fingerprints और JS सक्षम करके crawlers चलाएँ ताकि gated content उजागर हो सके।
- नए registered domains पर `POST /detect` के बाद मिलने वाले संदिग्ध 500 responses पर अलर्ट करें।

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
