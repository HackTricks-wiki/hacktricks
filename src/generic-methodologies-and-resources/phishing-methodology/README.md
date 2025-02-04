# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. पीड़ित की पहचान करें
1. **पीड़ित डोमेन** का चयन करें।
2. पीड़ित द्वारा उपयोग किए जाने वाले **लॉगिन पोर्टल्स** की कुछ बुनियादी वेब एन्यूमरेशन करें और **निर्णय लें** कि आप किसका **नकली रूप** धारण करेंगे।
3. कुछ **OSINT** का उपयोग करके **ईमेल खोजें**।
2. वातावरण तैयार करें
1. **डोमेन खरीदें** जिसका आप फ़िशिंग आकलन के लिए उपयोग करने जा रहे हैं
2. **ईमेल सेवा** से संबंधित रिकॉर्ड (SPF, DMARC, DKIM, rDNS) कॉन्फ़िगर करें
3. **gophish** के साथ VPS कॉन्फ़िगर करें
3. अभियान तैयार करें
1. **ईमेल टेम्पलेट** तैयार करें
2. क्रेडेंशियल चुराने के लिए **वेब पेज** तैयार करें
4. अभियान शुरू करें!

## समान डोमेन नाम उत्पन्न करें या एक विश्वसनीय डोमेन खरीदें

### डोमेन नाम विविधता तकनीकें

- **कीवर्ड**: डोमेन नाम में मूल डोमेन का एक महत्वपूर्ण **कीवर्ड** **शामिल** है (जैसे, zelster.com-management.com)।
- **हाइफनेट सबडोमेन**: एक सबडोमेन के **डॉट को हाइफन** में बदलें (जैसे, www-zelster.com)।
- **नया TLD**: एक **नए TLD** का उपयोग करते हुए वही डोमेन (जैसे, zelster.org)
- **हॉमोग्लिफ**: यह डोमेन नाम में एक अक्षर को **ऐसे अक्षरों से बदलता है जो समान दिखते हैं** (जैसे, zelfser.com)।
- **स्थानांतरण:** यह डोमेन नाम में **दो अक्षरों को स्वैप** करता है (जैसे, zelsetr.com)।
- **एकवचन/बहुवचन**: डोमेन नाम के अंत में “s” जोड़ता या हटाता है (जैसे, zeltsers.com)।
- **अवशेष**: यह डोमेन नाम से **एक** अक्षर को **हटाता है** (जैसे, zelser.com)।
- **दोहराव:** यह डोमेन नाम में **एक** अक्षर को **दोहराता है** (जैसे, zeltsser.com)।
- **प्रतिस्थापन**: हॉमोग्लिफ की तरह लेकिन कम छिपा हुआ। यह डोमेन नाम में एक अक्षर को बदलता है, शायद कीबोर्ड पर मूल अक्षर के निकटता में एक अक्षर के साथ (जैसे, zektser.com)।
- **सबडोमेन**: डोमेन नाम के अंदर एक **डॉट** पेश करें (जैसे, ze.lster.com)।
- **सम्मिलन**: यह डोमेन नाम में **एक अक्षर सम्मिलित** करता है (जैसे, zerltser.com)।
- **गायब डॉट**: डोमेन नाम के साथ TLD जोड़ें। (जैसे, zelstercom.com)

**स्वचालित उपकरण**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**वेबसाइटें**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### बिटफ्लिपिंग

यहां **संभावना है कि कुछ बिट्स जो संग्रहीत हैं या संचार में हैं, स्वचालित रूप से पलट सकते हैं** विभिन्न कारकों के कारण जैसे सौर ज्वालाएं, ब्रह्मांडीय किरणें, या हार्डवेयर त्रुटियां।

जब इस अवधारणा को **DNS अनुरोधों पर लागू किया जाता है**, तो यह संभव है कि **DNS सर्वर द्वारा प्राप्त डोमेन** वही न हो जो प्रारंभ में अनुरोधित था।

उदाहरण के लिए, "windows.com" डोमेन में एकल बिट संशोधन इसे "windnws.com" में बदल सकता है।

हमलावर **इसका लाभ उठाकर कई बिट-फ्लिपिंग डोमेन पंजीकृत कर सकते हैं** जो पीड़ित के डोमेन के समान हैं। उनका इरादा वैध उपयोगकर्ताओं को अपनी खुद की अवसंरचना की ओर पुनर्निर्देशित करना है।

अधिक जानकारी के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### एक विश्वसनीय डोमेन खरीदें

आप [https://www.expireddomains.net/](https://www.expireddomains.net) पर एक समाप्त डोमेन खोज सकते हैं जिसका आप उपयोग कर सकते हैं।\
यह सुनिश्चित करने के लिए कि आप जो समाप्त डोमेन खरीदने जा रहे हैं **उसका पहले से अच्छा SEO है**, आप देख सकते हैं कि यह कैसे वर्गीकृत है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## ईमेल खोजने

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% मुफ्त)
- [https://phonebook.cz/](https://phonebook.cz) (100% मुफ्त)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

**अधिक** मान्य ईमेल पते खोजने या **पहले से खोजे गए पते** की पुष्टि करने के लिए आप देख सकते हैं कि क्या आप पीड़ित के smtp सर्वरों को ब्रूट-फोर्स कर सकते हैं। [यहां ईमेल पते की पुष्टि/खोजने के तरीके के बारे में जानें](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, यह न भूलें कि यदि उपयोगकर्ता **अपने मेल तक पहुंचने के लिए कोई वेब पोर्टल का उपयोग करते हैं**, तो आप देख सकते हैं कि क्या यह **यूजरनेम ब्रूट फोर्स** के लिए कमजोर है, और यदि संभव हो तो इस कमजोरी का लाभ उठाएं।

## GoPhish कॉन्फ़िगर करना

### स्थापना

आप इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से डाउनलोड कर सकते हैं

इसे `/opt/gophish` के अंदर डाउनलोड और डिकंप्रेस करें और `/opt/gophish/gophish` चलाएं।\
आपको आउटपुट में पोर्ट 3333 पर व्यवस्थापक उपयोगकर्ता के लिए एक पासवर्ड दिया जाएगा। इसलिए, उस पोर्ट तक पहुंचें और व्यवस्थापक पासवर्ड बदलने के लिए उन क्रेडेंशियल्स का उपयोग करें। आपको उस पोर्ट को स्थानीय पर टनल करने की आवश्यकता हो सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS प्रमाणपत्र कॉन्फ़िगरेशन**

इस चरण से पहले आपको **पहले से ही डोमेन खरीदना चाहिए** जिसे आप उपयोग करने जा रहे हैं और यह **VPS के IP की ओर** **संकेतित** होना चाहिए जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

शुरू करें इंस्टॉलेशन: `apt-get install postfix`

फिर निम्नलिखित फ़ाइलों में डोमेन जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf के अंदर निम्नलिखित वेरिएबल्स के मान भी बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलों **`/etc/hostname`** और **`/etc/mailname`** को अपने डोमेन नाम में संशोधित करें और **अपने VPS को पुनः प्रारंभ करें।**

अब, एक **DNS A रिकॉर्ड** बनाएं `mail.<domain>` का जो **VPS के ip address** की ओर इशारा करता है और एक **DNS MX** रिकॉर्ड जो `mail.<domain>` की ओर इशारा करता है।

अब चलिए एक ईमेल भेजने का परीक्षण करते हैं:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish का निष्पादन रोकें और इसे कॉन्फ़िगर करें।\
`/opt/gophish/config.json` को निम्नलिखित में संशोधित करें (https के उपयोग का ध्यान रखें):
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

gophish सेवा बनाने के लिए ताकि इसे स्वचालित रूप से शुरू किया जा सके और एक सेवा के रूप में प्रबंधित किया जा सके, आप फ़ाइल `/etc/init.d/gophish` निम्नलिखित सामग्री के साथ बना सकते हैं:
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
सेवा को पूरा करने और इसे जांचने के लिए:
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

जितना पुराना एक डोमेन होगा, उतना ही कम संभावना है कि इसे स्पैम के रूप में पकड़ा जाएगा। इसलिए आपको फ़िशिंग मूल्यांकन से पहले जितना संभव हो सके (कम से कम 1 सप्ताह) प्रतीक्षा करनी चाहिए। इसके अलावा, यदि आप किसी प्रतिष्ठित क्षेत्र के बारे में एक पृष्ठ डालते हैं, तो प्राप्त प्रतिष्ठा बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह प्रतीक्षा करनी पड़े, आप अब सब कुछ कॉन्फ़िगर करना समाप्त कर सकते हैं।

### रिवर्स DNS (rDNS) रिकॉर्ड कॉन्फ़िगर करें

एक rDNS (PTR) रिकॉर्ड सेट करें जो VPS के IP पते को डोमेन नाम में हल करता है।

### सेंडर पॉलिसी फ्रेमवर्क (SPF) रिकॉर्ड

आपको **नए डोमेन के लिए एक SPF रिकॉर्ड कॉन्फ़िगर करना चाहिए**। यदि आप नहीं जानते कि SPF रिकॉर्ड क्या है [**इस पृष्ठ को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf)।

आप अपने SPF नीति को उत्पन्न करने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS मशीन का IP उपयोग करें)

![](<../../images/image (1037).png>)

यह वह सामग्री है जो डोमेन के अंदर एक TXT रिकॉर्ड में सेट की जानी चाहिए:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

आपको **नए डोमेन के लिए DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**इस पृष्ठ को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)।

आपको एक नया DNS TXT रिकॉर्ड बनाना होगा जो होस्टनाम `_dmarc.<domain>` की ओर इंगित करता है जिसमें निम्नलिखित सामग्री है:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको **नए डोमेन के लिए DKIM कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**इस पृष्ठ को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)।

यह ट्यूटोरियल आधारित है: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!NOTE]
> आपको DKIM कुंजी द्वारा उत्पन्न दोनों B64 मानों को संयोजित करने की आवश्यकता है:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने ईमेल कॉन्फ़िगरेशन स्कोर का परीक्षण करें

आप [https://www.mail-tester.com/](https://www.mail-tester.com) का उपयोग करके ऐसा कर सकते हैं\
बस पृष्ठ पर जाएं और आपको दिए गए पते पर एक ईमेल भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप अपने **ईमेल कॉन्फ़िगरेशन** की भी जांच कर सकते हैं `check-auth@verifier.port25.com` पर एक ईमेल भेजकर और **प्रतिक्रिया पढ़कर** (इसके लिए आपको **पोर्ट** **25** खोलने की आवश्यकता होगी और यदि आप ईमेल को रूट के रूप में भेजते हैं तो फ़ाइल _/var/mail/root_ में प्रतिक्रिया देखें)।\
सुनिश्चित करें कि आप सभी परीक्षणों में पास करते हैं:
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
आप **अपने नियंत्रण में एक Gmail को संदेश भेज सकते हैं**, और अपने Gmail इनबॉक्स में **ईमेल के हेडर** की जांच कर सकते हैं, `dkim=pass` `Authentication-Results` हेडर फ़ील्ड में होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse ब्लैकलिस्ट से हटाना

पृष्ठ [www.mail-tester.com](https://www.mail-tester.com) आपको यह बता सकता है कि क्या आपका डोमेन spamhouse द्वारा ब्लॉक किया गया है। आप अपने डोमेन/IP को हटाने के लिए अनुरोध कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft ब्लैकलिस्ट से हटाना

​​आप अपने डोमेन/IP को हटाने के लिए अनुरोध कर सकते हैं [https://sender.office.com/](https://sender.office.com) पर।

## GoPhish अभियान बनाएं और लॉन्च करें

### भेजने की प्रोफ़ाइल

- प्रेषक प्रोफ़ाइल को पहचानने के लिए कुछ **नाम सेट करें**
- तय करें कि आप फ़िशिंग ईमेल किस खाते से भेजने जा रहे हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप उपयोगकर्ता नाम और पासवर्ड को खाली छोड़ सकते हैं, लेकिन सुनिश्चित करें कि Ignore Certificate Errors को चेक करें

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!NOTE]
> यह अनुशंसा की जाती है कि आप यह सुनिश्चित करने के लिए "**Send Test Email**" कार्यक्षमता का उपयोग करें कि सब कुछ काम कर रहा है।\
> मैं अनुशंसा करूंगा कि **परीक्षण ईमेल 10 मिनट के मेल पते पर भेजें** ताकि परीक्षण करते समय ब्लैकलिस्ट में न जाएं।

### ईमेल टेम्पलेट

- टेम्पलेट को पहचानने के लिए कुछ **नाम सेट करें**
- फिर एक **विषय** लिखें (कुछ अजीब नहीं, बस कुछ ऐसा जो आप नियमित ईमेल में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया है
- **ईमेल टेम्पलेट** लिखें (आप निम्नलिखित उदाहरण की तरह वेरिएबल का उपयोग कर सकते हैं):
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
ध्यान दें कि **ईमेल की विश्वसनीयता बढ़ाने के लिए**, किसी क्लाइंट के ईमेल से कुछ सिग्नेचर का उपयोग करने की सिफारिश की जाती है। सुझाव:

- एक **गैर-मौजूद पते** पर ईमेल भेजें और जांचें कि क्या प्रतिक्रिया में कोई सिग्नेचर है।
- **सार्वजनिक ईमेल** जैसे info@ex.com या press@ex.com या public@ex.com की खोज करें और उन्हें एक ईमेल भेजें और प्रतिक्रिया की प्रतीक्षा करें।
- **कुछ मान्य खोजे गए** ईमेल से संपर्क करने की कोशिश करें और प्रतिक्रिया की प्रतीक्षा करें।

![](<../../images/image (80).png>)

> [!NOTE]
> ईमेल टेम्पलेट भी **भेजने के लिए फ़ाइलें संलग्न** करने की अनुमति देता है। यदि आप कुछ विशेष रूप से तैयार की गई फ़ाइलों/दस्तावेज़ों का उपयोग करके NTLM चुनौतियों को चुराना चाहते हैं [इस पृष्ठ को पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### लैंडिंग पृष्ठ

- एक **नाम** लिखें।
- **वेब पृष्ठ का HTML कोड** लिखें। ध्यान दें कि आप **वेब पृष्ठों को आयात** कर सकते हैं।
- **कैप्चर सबमिटेड डेटा** और **कैप्चर पासवर्ड** को चिह्नित करें।
- एक **रीडायरेक्शन** सेट करें।

![](<../../images/image (826).png>)

> [!NOTE]
> आमतौर पर आपको पृष्ठ के HTML कोड को संशोधित करने और कुछ परीक्षण करने की आवश्यकता होगी (शायद कुछ Apache सर्वर का उपयोग करके) **जब तक आपको परिणाम पसंद न आएं।** फिर, उस HTML कोड को बॉक्स में लिखें।\
> ध्यान दें कि यदि आपको HTML के लिए **कुछ स्थिर संसाधनों** का उपयोग करने की आवश्यकता है (शायद कुछ CSS और JS पृष्ठ) तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सहेज सकते हैं और फिर _**/static/\<filename>**_ से उन तक पहुंच सकते हैं।

> [!NOTE]
> रीडायरेक्शन के लिए आप **उपयोगकर्ताओं को पीड़ित के वैध मुख्य वेब पृष्ठ पर रीडायरेक्ट** कर सकते हैं, या उन्हें उदाहरण के लिए _/static/migration.html_ पर रीडायरेक्ट कर सकते हैं, कुछ **स्पिनिंग व्हील** ([**https://loading.io/**](https://loading.io)**) 5 सेकंड के लिए और फिर संकेत दें कि प्रक्रिया सफल रही।**

### उपयोगकर्ता और समूह

- एक नाम सेट करें।
- **डेटा आयात करें** (ध्यान दें कि उदाहरण के लिए टेम्पलेट का उपयोग करने के लिए आपको प्रत्येक उपयोगकर्ता का पहला नाम, अंतिम नाम और ईमेल पता चाहिए)।

![](<../../images/image (163).png>)

### अभियान

अंत में, एक अभियान बनाएं जिसमें एक नाम, ईमेल टेम्पलेट, लैंडिंग पृष्ठ, URL, भेजने की प्रोफ़ाइल और समूह का चयन करें। ध्यान दें कि URL वह लिंक होगा जो पीड़ितों को भेजा जाएगा।

ध्यान दें कि **भेजने की प्रोफ़ाइल परीक्षण ईमेल भेजने की अनुमति देती है ताकि यह देखा जा सके कि अंतिम फ़िशिंग ईमेल कैसा दिखेगा**:

![](<../../images/image (192).png>)

> [!NOTE]
> मैं **10 मिनट के मेल पते पर परीक्षण ईमेल भेजने की सिफारिश करूंगा** ताकि परीक्षण करते समय ब्लैकलिस्ट में न फंसें।

जब सब कुछ तैयार हो जाए, तो बस अभियान शुरू करें!

## वेबसाइट क्लोनिंग

यदि किसी कारणवश आप वेबसाइट को क्लोन करना चाहते हैं तो निम्नलिखित पृष्ठ की जांच करें:

{{#ref}}
clone-a-website.md
{{#endref}}

## बैकडोर वाले दस्तावेज़ और फ़ाइलें

कुछ फ़िशिंग आकलनों (मुख्य रूप से रेड टीमों के लिए) में आप **कुछ प्रकार के बैकडोर वाली फ़ाइलें भेजना** चाहेंगे (शायद एक C2 या शायद कुछ ऐसा जो प्रमाणीकरण को ट्रिगर करेगा)।\
कुछ उदाहरणों के लिए निम्नलिखित पृष्ठ की जांच करें:

{{#ref}}
phishing-documents.md
{{#endref}}

## फ़िशिंग MFA

### प्रॉक्सी MitM के माध्यम से

पिछला हमला काफी चालाक है क्योंकि आप एक असली वेबसाइट का अनुकरण कर रहे हैं और उपयोगकर्ता द्वारा सेट की गई जानकारी एकत्र कर रहे हैं। दुर्भाग्यवश, यदि उपयोगकर्ता ने सही पासवर्ड नहीं डाला या यदि आप जिस एप्लिकेशन का अनुकरण कर रहे हैं वह 2FA के साथ कॉन्फ़िगर किया गया है, **तो यह जानकारी आपको धोखे में पड़े उपयोगकर्ता का अनुकरण करने की अनुमति नहीं देगी**।

यहां ऐसे उपकरण हैं जैसे [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) उपयोगी हैं। यह उपकरण आपको एक MitM जैसे हमले को उत्पन्न करने की अनुमति देगा। मूल रूप से, हमले का काम करने का तरीका इस प्रकार है:

1. आप **वास्तविक वेबपृष्ठ** के लॉगिन फ़ॉर्म का अनुकरण करते हैं।
2. उपयोगकर्ता **अपनी** **क्रेडेंशियल्स** को आपके फ़र्ज़ी पृष्ठ पर भेजता है और उपकरण उन्हें वास्तविक वेबपृष्ठ पर भेजता है, **जांचता है कि क्या क्रेडेंशियल्स काम करते हैं**।
3. यदि खाता **2FA** के साथ कॉन्फ़िगर किया गया है, तो MitM पृष्ठ इसके लिए पूछेगा और एक बार जब **उपयोगकर्ता इसे प्रस्तुत करता है**, तो उपकरण इसे वास्तविक वेब पृष्ठ पर भेज देगा।
4. एक बार जब उपयोगकर्ता प्रमाणित हो जाता है, तो आप (हमलावर के रूप में) **क्रेडेंशियल्स, 2FA, कुकी और आपके द्वारा किए गए हर इंटरैक्शन की कोई भी जानकारी** कैप्चर कर लेंगे जबकि उपकरण एक MitM प्रदर्शन कर रहा है।

### VNC के माध्यम से

क्या होगा यदि आप **पीड़ित को एक दुर्भावनापूर्ण पृष्ठ पर भेजने के बजाय** उसे एक **VNC सत्र में भेजते हैं जिसमें वास्तविक वेब पृष्ठ से जुड़े ब्राउज़र** होते हैं? आप देख सकेंगे कि वह क्या करता है, पासवर्ड, उपयोग किए गए MFA, कुकीज़ चुराते हैं...\
आप इसे [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं।

## पहचानने की पहचान

स्पष्ट रूप से, यह जानने के सबसे अच्छे तरीकों में से एक है कि क्या आपको पकड़ा गया है, **अपने डोमेन को ब्लैकलिस्ट में खोजना**। यदि यह सूचीबद्ध है, तो किसी न किसी तरह आपका डोमेन संदिग्ध के रूप में पहचाना गया।\
यह जांचने का एक आसान तरीका है कि क्या आपका डोमेन किसी भी ब्लैकलिस्ट में दिखाई देता है [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना।

हालांकि, यह जानने के अन्य तरीके हैं कि क्या पीड़ित **संदिग्ध फ़िशिंग गतिविधियों की सक्रिय रूप से खोज कर रहा है** जैसा कि समझाया गया है:

{{#ref}}
detecting-phising.md
{{#endref}}

आप **पीड़ित के डोमेन के बहुत समान नाम** के साथ एक डोमेन खरीद सकते हैं **और/या एक प्रमाणपत्र उत्पन्न कर सकते हैं** एक **उपडोमेन** के लिए जो आपके द्वारा नियंत्रित डोमेन का **कीवर्ड** शामिल करता है। यदि **पीड़ित** उनके साथ किसी प्रकार की **DNS या HTTP इंटरैक्शन** करता है, तो आप जानेंगे कि **वह सक्रिय रूप से खोज रहा है** संदिग्ध डोमेन और आपको बहुत सतर्क रहने की आवश्यकता होगी।

### फ़िशिंग का मूल्यांकन करें

[**Phishious** ](https://github.com/Rices/Phishious) का उपयोग करें यह मूल्यांकन करने के लिए कि क्या आपका ईमेल स्पैम फ़ोल्डर में समाप्त होने वाला है या यदि इसे अवरुद्ध किया जाएगा या सफल होगा।

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{{#include ../../banners/hacktricks-training.md}}
