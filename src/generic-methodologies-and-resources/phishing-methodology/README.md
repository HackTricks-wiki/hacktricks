# Phishing कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## कार्यप्रणाली

1. Recon the victim
1. चुनें **victim domain**.
2. कुछ बुनियादी web enumeration करें **searching for login portals** जो victim उपयोग करता है और **decide** करें कि आप किसे **impersonate** करेंगे।
3. कुछ **OSINT** का उपयोग करके **find emails**.
2. पर्यावरण तैयार करें
1. **Buy the domain** जिसे आप phishing assessment के लिए उपयोग करने वाले हैं
2. संबंधित email service रिकॉर्ड्स कॉन्फ़िगर करें (SPF, DMARC, DKIM, rDNS)
3. VPS को **gophish** के साथ कॉन्फ़िगर करें
3. अभियान तैयार करें
1. **email template** तैयार करें
2. क्रेडेंशियल चुराने के लिए **web page** तैयार करें
4. अभियान लॉन्च करें!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: डोमेन नाम मूल डोमेन का एक महत्वपूर्ण **keyword** शामिल करता है (उदा., zelster.com-management.com).
- **hypened subdomain**: उपडोमेन के लिए dot को hyphen से बदलें (उदा., www-zelster.com).
- **New TLD**: वही domain नया **TLD** के साथ (उदा., zelster.org)
- **Homoglyph**: यह डोमेन नाम में एक अक्षर को उन अक्षरों से **replaces** करता है जो दिखने में समान हैं (उदा., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** यह डोमेन नाम के भीतर दो अक्षरों को **swaps** करता है (उदा., zelsetr.com).
- **Singularization/Pluralization**: डोमेन नाम के अंत में “s” जोड़ता या हटाता है (उदा., zeltsers.com).
- **Omission**: यह डोमेन नाम से एक अक्षर **removes** करता है (उदा., zelser.com).
- **Repetition:** यह डोमेन नाम में किसी एक अक्षर को **repeats** करता है (उदा., zeltsser.com).
- **Replacement**: Homoglyph जैसा पर कम stealthy। यह डोमेन नाम के किसी एक अक्षर को बदलता है, संभवतः मूल अक्षर के कीबोर्ड पर नजदीकी अक्षर से (उदा., zektser.com).
- **Subdomained**: डोमेन नाम के अंदर एक **dot** introduce करें (उदा., ze.lster.com).
- **Insertion**: यह डोमेन नाम में एक अक्षर **inserts** करता है (उदा., zerltser.com).
- **Missing dot**: TLD को डोमेन नाम के साथ जोड़ दें। (उदा., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

कई कारणों से जैसे solar flares, cosmic rays, या hardware errors के कारण स्टोर्ड या संचार में रखे गए कुछ bits अपने आप flip होने की **possibility** होती है।

जब इस कांसेप्ट को **DNS requests** पर लागू किया जाता है, तो संभव है कि **domain जो DNS server को मिला है** वह मूल रूप से अनुरोध किया गया domain नहीं हो।

उदाहरण के लिए, domain "windows.com" में एक single bit modification इसे "windnws.com" में बदल सकता है।

Attackers इस बात का **फायदा उठा सकते हैं** कि वे victim के domain के समान कई bit-flipping domains register कर लें। उनका उद्देश्य legitimate users को अपनी infrastructure पर redirect करना होता है।

अधिक जानकारी के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

आप expired domain खोजने के लिए [https://www.expireddomains.net/](https://www.expireddomains.net) पर खोज कर सकते हैं जिसे आप उपयोग कर सकते हैं.\
यह सुनिश्चित करने के लिए कि जो expired domain आप खरीदने जा रहे हैं **पहले से ही अच्छा SEO** रखता है, आप यह देख सकते हैं कि यह किस तरह categorize किया गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

अधिक मान्य email addresses खोजने या पहले से मिले हुए ones को verify करने के लिए आप victim के smtp servers पर उन्हें brute-force करके चेक कर सकते हैं। [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, यह मत भूलिए कि यदि users अपने mails तक पहुँचने के लिए **any web portal** उपयोग करते हैं, तो आप चेक कर सकते हैं कि क्या वह **username brute force** के प्रति vulnerable है, और संभव हो तो उस vulnerability का exploit करें।

## Configuring GoPhish

### Installation

आप इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से डाउनलोड कर सकते हैं

डाउनलोड करके इसे `/opt/gophish` के अंदर decompress करें और `/opt/gophish/gophish` execute करें।\
आउटपुट में आपको admin user के लिए password दिया जाएगा जो port 3333 पर होगा। इसलिए उस port पर पहुँचें और उन credentials का उपयोग करके admin password बदलें। आपको उस port को local पर tunnel करने की आवश्यकता पड़ सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS प्रमाणपत्र कॉन्फ़िगरेशन**

इस कदम से पहले आपके पास वह **पहले से खरीदा हुआ डोमेन** होना चाहिए जिसका आप उपयोग करने वाले हैं और वह **पॉइंट** कर रहा होना चाहिए उस **VPS के IP** की ओर जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

इंस्टॉल करें: `apt-get install postfix`

फिर डोमेन को निम्न फ़ाइलों में जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf के अंदर निम्न वेरिएबल्स के मान भी बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** को अपने डोमेन नाम से बदलें और **restart your VPS.**

अब एक **DNS A record** बनाएं जो `mail.<domain>` को VPS के **ip address** पर पॉइंट करे और एक **DNS MX** record बनाएं जो `mail.<domain>` की ओर पॉइंट करे

अब ईमेल भेजकर टेस्ट करें:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish के निष्पादन को रोकें और इसे कॉन्फ़िगर करें.\
`/opt/gophish/config.json` को निम्नानुसार बदलें (https के उपयोग पर ध्यान दें):
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

gophish सेवा बनाने के लिए ताकि इसे स्वचालित रूप से शुरू किया जा सके और एक service के रूप में प्रबंधित किया जा सके, आप फ़ाइल `/etc/init.d/gophish` निम्नलिखित सामग्री के साथ बना सकते हैं:
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
सेवा का कॉन्फ़िगरेशन पूरा करें और यह जाँचें कि यह कर रहा है:
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

### प्रतीक्षा करें & वैध रहें

किसी डोमेन की उम्र जितनी अधिक होगी, उसे spam के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए phishing assessment से पहले जितना अधिक समय संभव हो उतना प्रतीक्षा करें (कम से कम 1 सप्ताह)। इसके अलावा, यदि आप किसी प्रतिष्ठित सेक्टर से संबंधित एक पेज डालते हैं तो मिलने वाली प्रतिष्ठा बेहतर होगी।

ध्यान रखें कि भले ही आपको एक सप्ताह प्रतीक्षा करनी पड़े, आप अभी सब कुछ कॉन्फ़िगर करना पूरा कर सकते हैं।

### Reverse DNS (rDNS) रिकॉर्ड कॉन्फ़िगर करें

एक rDNS (PTR) रिकॉर्ड सेट करें जो VPS के IP पते को डोमेन नाम पर resolve करे।

### Sender Policy Framework (SPF) Record

आपको नए डोमेन के लिए **SPF रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि SPF रिकॉर्ड क्या है तो [**इस पृष्ठ को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

आप अपने SPF policy जनरेट करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS मशीन के IP का उपयोग करें)

![](<../../images/image (1037).png>)

यह उस सामग्री है जिसे डोमेन के अंदर एक TXT रिकॉर्ड में सेट करना होगा:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### डोमेन-आधारित संदेश प्रमाणिकरण, रिपोर्टिंग और अनुपालन (DMARC) रिकॉर्ड

आपको नए डोमेन के लिए **DMARC रिकॉर्ड कॉन्फ़िगर करना** होगा। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको एक नया DNS TXT रिकॉर्ड बनाना होगा जो होस्टनाम `_dmarc.<domain>` की ओर इशारा करे, जिसमें निम्नलिखित सामग्री हो:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना चाहिए**। अगर आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM कुंजी द्वारा उत्पन्न दोनों B64 मानों को जोड़ना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com)\ का उपयोग करके कर सकते हैं।\
बस पृष्ठ पर जाएँ और वे जो पते देते हैं उस पर एक ईमेल भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप यह भी कर सकते हैं कि **अपने ईमेल कॉन्फ़िगरेशन की जाँच करें** — `check-auth@verifier.port25.com` पर एक ईमेल भेजकर और **प्रतिक्रिया पढ़ें** (इसके लिए आपको **खोलना** पोर्ट **25** होगा और यदि आप ईमेल root के रूप में भेजते हैं तो फ़ाइल _/var/mail/root_ में प्रतिक्रिया देखें).\
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
आप अपने नियंत्रण वाले **Gmail** पर एक संदेश भी भेज सकते हैं, और अपने Gmail इनबॉक्स में **email’s headers** की जाँच कर सकते हैं — `dkim=pass` को `Authentication-Results` header field में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse ब्लैकलिस्ट से हटाना

पेज [www.mail-tester.com](https://www.mail-tester.com) आपको बता सकता है कि आपका डोमेन spamhouse द्वारा ब्लॉक किया जा रहा है या नहीं। आप अपना domain/IP हटवाने के लिए अनुरोध कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft ब्लैकलिस्ट से हटाना

आप अपना domain/IP हटवाने के लिए अनुरोध कर सकते हैं: [https://sender.office.com/](https://sender.office.com).

## बनाएँ और लॉन्च करें GoPhish अभियान

### प्रेषक प्रोफ़ाइल

- प्रेषक प्रोफ़ाइल की पहचान के लिए कोई **नाम** सेट करें
- तय करें कि आप किस account से phishing emails भेजने जा रहे हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन सुनिश्चित करें कि Ignore Certificate Errors को चेक किया गया हो

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह अनुशंसित है कि सब कुछ काम कर रहा है यह जाँचने के लिए "**Send Test Email**" फ़ंक्शन का उपयोग करें।\
> मैं सुझाव दूँगा कि परीक्षण करते समय ब्लैकलिस्ट होने से बचने के लिए **send the test emails to 10min mails addresses**।

### ईमेल टेम्पलेट

- टेम्पलेट की पहचान के लिए कोई **नाम** सेट करें
- फिर एक **subject** लिखें (कुछ अजीब नहीं, बस वह जो आप सामान्य ईमेल में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने **Add Tracking Image** को चेक किया है
- ईमेल टेम्पलेट लिखें (आप नीचे दिए उदाहरण की तरह variables का उपयोग कर सकते हैं):
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
ध्यान दें कि **ईमेल की विश्वसनीयता बढ़ाने के लिए**, यह सलाह दी जाती है कि क्लाइंट के किसी ईमेल से कुछ signature इस्तेमाल किया जाए। सुझाव:

- किसी **अस्तित्वहीन पते** पर ईमेल भेजें और देखें कि क्या रिस्पॉन्स में कोई signature मिलता है।
- ऐसे **सार्वजनिक ईमेल** खोजें जैसे info@ex.com या press@ex.com या public@ex.com और उन्हें ईमेल भेजकर उत्तर का इंतज़ार करें।
- किसी **खोजे गए वैध** ईमेल से संपर्क करने की कोशिश करें और उत्तर का इंतज़ार करें।

![](<../../images/image (80).png>)

> [!TIP]
> Email Template भी **फाइलें अटैच करने** की अनुमति देता है। यदि आप NTLM challenges भी चोरी करना चाहते हैं किसी विशेष crafted फाइल/दस्तावेज़ का उपयोग करके तो [इस पृष्ठ को पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **नाम लिखें**
- वेब पेज का **HTML कोड लिखें**। ध्यान दें कि आप वेब पेजों को **इम्पोर्ट** भी कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को मार्क करें
- एक **redirection सेट करें**

![](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको पेज के HTML कोड में परिवर्तन करने और लोकल में कुछ टेस्ट करने की ज़रूरत पड़ेगी (शायद किसी Apache सर्वर का उपयोग करके) **जब तक कि परिणाम पसंद न आ जाएं।** फिर उस HTML को बॉक्स में लिख दें।\
> यदि आपको HTML के लिए कुछ static resources (शायद कुछ CSS और JS पेज) इस्तेमाल करने की ज़रूरत है तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर उन्हें _**/static/\<filename>**_ से एक्सेस कर सकते हैं।

> [!TIP]
> redirection के लिए आप यूज़र्स को शिकार की legit मुख्य वेब पेज पर redirect कर सकते हैं, या उदाहरण के लिए _/static/migration.html_ पर redirect कर सकते हैं, कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 सेकंड के लिए रखें और फिर बताएं कि प्रोसेस सफल रहा**।

### Users & Groups

- एक नाम सेट करें
- **Import the data** करें (ध्यान दें कि उदाहरण के लिए template उपयोग करने हेतु आपको प्रत्येक user का firstname, last name और email address चाहिए)

![](<../../images/image (163).png>)

### Campaign

अंत में, एक campaign बनाएं जिसमें नाम, email template, landing page, URL, sending profile और group चुनें। ध्यान दें कि URL वही लिंक होगा जो शिकारों को भेजा जाएगा।

ध्यान दें कि **Sending Profile आपको एक टेस्ट ईमेल भेजने की अनुमति देता है ताकि आप देख सकें कि अंतिम phishing ईमेल कैसा दिखेगा**:

![](<../../images/image (192).png>)

> [!TIP]
> मैं सुझाव दूँगा कि **टेस्ट ईमेल 10min mails addresses** पर भेजें ताकि टेस्ट करते समय blacklisted होने से बचा जा सके।

सब कुछ तैयार होने पर, बस campaign लॉन्च करें!

## Website Cloning

यदि किसी कारण से आप वेबसाइट को क्लोन करना चाहें तो नीचे दिए पृष्ठ की जाँच करें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्यतः Red Teams के लिए) में आप ऐसे फाइल भी भेजना चाहेंगे जिनमें किसी तरह का backdoor हो (शायद एक C2 या शायद सिर्फ कुछ जो authentication ट्रिगर करे)।\
कुछ उदाहरणों के लिए निम्न पृष्ठ देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला अटैक काफी चालाक है क्योंकि आप एक असली वेबसाइट की नकल कर रहे हैं और उपयोगकर्ता द्वारा सेट की गई जानकारी एकत्र कर रहे हैं। दुर्भाग्य से, यदि उपयोगकर्ता ने सही पासवर्ड नहीं डाला या यदि जिस एप्लिकेशन की आपने नकल की है वह 2FA के साथ कॉन्फ़िगर है, तो **यह जानकारी आपको धोखा दिए गए उपयोगकर्ता का प्रतिरूपण करने की अनुमति नहीं देगी**।

इसीलिए ऐसे उपकरण उपयोगी हैं जैसे [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena)। यह टूल आपको MitM जैसा अटैक जेनरेट करने की अनुमति देता है। मूल रूप से, अटैक निम्न प्रकार काम करता है:

1. आप असली वेबपेज के लॉगिन फॉर्म का **impersonate** करते हैं।
2. उपयोगकर्ता अपनी **credentials** आपके फेक पेज पर **भेजता है** और टूल उन्हें असली वेबपेज पर भेजता है, यह **सत्यापित करता है कि credentials काम कर रहे हैं**।
3. यदि अकाउंट **2FA** के साथ कॉन्फ़िगर है, तो MitM पेज इसके लिए पूछेगा और एक बार जब **user इसे दर्ज करता है** तो टूल इसे असली वेब पेज को भेज देगा।
4. एक बार उपयोगकर्ता authenticated हो जाने पर आप (एक अटैकर के रूप में) **credentials, 2FA, cookie और हर इंटरैक्शन की कोई भी जानकारी** कैप्चर कर चुके होते हैं जब तक कि टूल MitM कर रहा होता है।

### Via VNC

अगर आप शिकार को असली पेज जैसी दिखने वाली किसी malicious पेज पर भेजने के बजाय उसे एक **VNC session** पर भेजें जिसमें एक ब्राउज़र असली वेब पेज पर कनेक्टेड हो, तो? आप देख पाएंगे कि वह क्या करता है, पासवर्ड, MFA, cookies चोरी कर सकेंगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं

## Detecting the detection

स्पष्ट रूप से यह जानने का एक बेहतर तरीका है कि क्या आपको पकड़ा गया है वह है **अपनी डोमेन को blacklists में खोजना**। यदि यह सूचीबद्ध है, तो किसी न किसी तरह से आपकी डोमेन को संदिग्ध माना गया है।\
अपनी डोमेन किसी भी blacklist में है या नहीं यह जांचने का एक आसान तरीका है [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना।

हालाँकि, यह जानने के और भी तरीके हैं कि क्या शिकार **जंगली में संदिग्ध फिशिंग गतिविधि की सक्रिय रूप से खोज कर रहा है**, जैसा कि नीचे समझाया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप शिकार की डोमेन के बहुत समान नाम के साथ एक डोमेन खरीद सकते हैं **और/या एक सबडोमेन के लिए सर्टिफिकेट जेनरेट कर सकते हैं** जो आपके नियंत्रित डोमेन का हिस्सा हो और उसमें शिकार की डोमेन का **keyword** शामिल हो। यदि **लक्षित** उनके साथ किसी भी प्रकार की **DNS या HTTP interaction** करता है, तो आप जान पाएँगे कि **वह सक्रिय रूप से संदिग्ध डोमेन्स खोज रहा है** और आपको बहुत stealth होने की ज़रूरत होगी।

### Evaluate the phishing

यह जांचने के लिए कि आपकी ईमेल स्पैम फ़ोल्डर में जाएगी या ब्लॉक होगी या सफल रहेगी, [**Phishious** ](https://github.com/Rices/Phishious) का उपयोग करें।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets अधिकतर ईमेल ल्यूर्स को पूरी तरह छोड़कर सीधे service-desk / identity-recovery workflow को टार्गेट करने लगे हैं ताकि MFA को हराया जा सके। यह अटैक पूरी तरह "living-off-the-land" है: एक बार ऑपरेटर के पास वैध credentials आ गए, वे built-in admin tooling के साथ pivot करते हैं – कोई malware आवश्यक नहीं होता।

### Attack flow
1. Recon the victim
* LinkedIn, data breaches, public GitHub आदि से व्यक्तिगत और कॉर्पोरेट विवरण इकट्ठा करें।
* उच्च-मूल्य पहचान (executives, IT, finance) पहचानें और password / MFA reset के लिए **exact help-desk process** का enumeration करें।
2. Real-time social engineering
* help-desk को फोन, Teams या चैट करें जबकि आप लक्ष्य का impersonate कर रहे हों (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
* knowledge-based verification पास करने के लिए पहले से इकट्ठा किया गया PII प्रदान करें।
* एजेंट को मनाएं कि वह **MFA secret reset** कर दे या रजिस्टर किए गए मोबाइल नंबर पर **SIM-swap** कर दे।
3. Immediate post-access actions (≤60 min in real cases)
* किसी भी वेब SSO पोर्टल के माध्यम से foothold स्थापित करें।
* बिल्ट-इन्स के साथ AD / AzureAD का enumeration करें (कोई बाइनरी ड्रॉप किए बिना):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**, **PsExec**, या पहले से whitelist किए गए legit **RMM** agents के साथ lateral movement।

### Detection & Mitigation
* help-desk identity recovery को एक **privileged operation** के रूप में मानें – step-up auth और manager approval आवश्यक करें।
* ऐसी **Identity Threat Detection & Response (ITDR)** / **UEBA** rules तैनात करें जो alert करें जब:
* MFA method बदला गया हो + नई डिवाइस / जियो से authentication।
* उसी principal का तत्काल elevation (user → admin)।
* help-desk कॉल रिकॉर्ड करें और किसी भी reset से पहले **पहले से रजिस्टर्ड नंबर पर call-back** अनिवार्य करें।
* लागू करें **Just-In-Time (JIT) / Privileged Access** ताकि नए reset किए गए accounts स्वतः high-privilege tokens inherit न करें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews उच्च-टच ऑप्स की लागत को ऐसे mass अटैक्स के साथ ऑफ़सेट करते हैं जो **search engines & ad networks को delivery channel में बदल देते हैं**।

1. **SEO poisoning / malvertising** एक फेक रिज़ल्ट जैसे `chromium-update[.]site` को टॉप सर्च एड्स में पुश करता है।
2. शिकार एक छोटा **first-stage loader** डाउनलोड करता है (अक्सर JS/HTA/ISO)। Unit 42 ने जिन उदाहरणों को देखा:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader ब्राउज़र cookies + credential DBs को exfiltrate करता है, फिर एक **silent loader** खींचता है जो *रीअलटाइम* में निर्णय लेता है कि क्या deploy करना है:
* RAT (उदा. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* newly-registered domains को ब्लॉक करें और *search-ads* पर Advanced DNS / URL Filtering लागू करें साथ ही ईमेल पर भी।
* सॉफ़्टवेयर इंस्टालेशन को signed MSI / Store packages तक सीमित करें, `HTA`, `ISO`, `VBS` के execution को policy से deny करें।
*浏览र के child processes को मॉनिटर करें जो installers खोल रहे हों:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* उन LOLBins की खोज करें जिन्हें first-stage loaders अक्सर misuse करते हैं (उदा. `regsvr32`, `curl`, `mshta`)।

---

## AI-Enhanced Phishing Operations
आक्रमणकारी अब पूरी तरह personalise किये गए ल्यूर्स और रियल-टाइम इंटरैक्शन के लिए **LLM & voice-clone APIs** को श्रृंखला में जोड़ते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• अनट्रस्टेड automation से भेजे गए मैसेजेस को हाइलाइट करने के लिए **dynamic banners** जोड़ें (ARC/DKIM anomalies के माध्यम से)।  
• उच्च-जोखिम फोन रिक्वेस्ट्स के लिए **voice-biometric challenge phrases** तैनात करें।  
• awareness programmes में लगातार AI-generated ल्यूर्स का simulation करें – static templates obsolete हैं।

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
क्लासिक push-bombing के अलावा, ऑपरेटर्स बस कॉल के दौरान **नई MFA registration ज़बरदस्ती कर देते हैं**, जिससे उपयोगकर्ता के मौजूदा token शून्य हो जाते हैं। किसी भी बाद के लॉगिन प्रॉम्प्ट को शिकार के लिए वैध ही दिखेगा।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta इवेंट्स के लिए मॉनिटर करें जहाँ **`deleteMFA` + `addMFA`** एक ही IP से कुछ ही मिनटों में घटित हों।



## Clipboard Hijacking / Pastejacking

हमलावर किसी compromised या typosquatted वेब पेज से चुपके से malicious commands पीड़ित के clipboard में कॉपी कर सकते हैं और फिर उपयोगकर्ता को धोखा देकर उन्हें **Win + R**, **Win + X** या किसी terminal window में पेस्ट करवा सकते हैं, जिससे बिना किसी download या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
