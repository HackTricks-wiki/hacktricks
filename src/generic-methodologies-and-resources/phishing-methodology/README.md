# Phishing कार्यप्रणाली

{{#include ../../banners/hacktricks-training.md}}

## पद्धति

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### कॉन्फ़िगरेशन

**TLS सर्टिफिकेट कॉन्फ़िगरेशन**

इस चरण से पहले आपको पहले से ही उस domain को खरीद लिया होना चाहिए जिसे आप उपयोग करने वाले हैं, और यह उस VPS के IP की ओर पॉइंट कर रहा होना चाहिए जहाँ आप gophish को कॉन्फ़िगर कर रहे हैं।
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

फिर अपने डोमेन को निम्नलिखित फ़ाइलों में जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**इसके अलावा /etc/postfix/main.cf के अंदर निम्नलिखित वेरिएबल्स के मान बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** को अपने डोमेन नाम पर बदलें और **अपने VPS को रिस्टार्ट करें।**

अब, एक **DNS A record** बनाएं जिसका `mail.<domain>` VPS के **ip address** की ओर पॉइंट करे और एक **DNS MX** record भी बनाएं जो `mail.<domain>` की ओर पॉइंट करे।

अब ईमेल भेजकर परीक्षण करें:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish के निष्पादन को रोकें और इसे कॉन्फ़िगर करें।\
`/opt/gophish/config.json` को निम्नानुसार संशोधित करें (ध्यान दें कि https का उपयोग किया गया है):
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

gophish सेवा बनाने के लिए ताकि इसे स्वचालित रूप से शुरू किया जा सके और एक सेवा के रूप में प्रबंधित किया जा सके, आप फ़ाइल `/etc/init.d/gophish` बना सकते हैं जिसमें निम्नलिखित सामग्री हो:
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
सेवा का कॉन्फ़िगरेशन पूरा करें और जाँचें कि यह क्या कर रहा है:
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
## Configuring mail server and domain

### Wait & be legit

किसी domain जितना पुराना होगा, उसे spam के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए phishing assessment से पहले जितना संभव हो उतना समय (कम से कम 1 week) इंतज़ार करें। इसके अलावा, अगर आप किसी reputational sector के बारे में एक पेज रखते हैं तो मिलने वाली reputation बेहतर होगी।

ध्यान दें कि भले ही आपको एक सप्ताह इंतज़ार करना पड़े, आप अभी सब कुछ configure कर सकते हैं।

### Configure Reverse DNS (rDNS) record

एक rDNS (PTR) रिकॉर्ड सेट करें जो VPS के IP address को domain name पर resolve करे।

### Sender Policy Framework (SPF) Record

आपको नए domain के लिए **SPF रिकॉर्ड configure करना होगा**। If you don't know what is a SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

यह वह content है जिसे domain के TXT रिकॉर्ड में सेट करना होगा:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### डोमेन-आधारित संदेश प्रमाणीकरण, रिपोर्टिंग और अनुरूपता (DMARC) रिकॉर्ड

आपको नए डोमेन के लिए **DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको होस्टनाम `_dmarc.<domain>` की ओर पॉइंट करते हुए एक नया DNS TXT रिकॉर्ड बनाना होगा, जिसमें निम्नलिखित कंटेंट हो:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना आवश्यक है**। अगर आप नहीं जानते कि DMARC record क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा जनरेट किए गए दोनों B64 मानों को concatenate करना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
बस पेज खोलें और उस पते पर एक ईमेल भेजें जो वे आपको देते हैं:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप यह भी कर सकते हैं कि अपने ईमेल कॉन्फ़िगरेशन की **जाँच** करें — `check-auth@verifier.port25.com` पर एक ईमेल भेजें और **प्रतिक्रिया पढ़ें** (इसके लिए आपको **खोलना** पोर्ट **25** होगा और यदि आप root के रूप में ईमेल भेजते हैं तो फ़ाइल _/var/mail/root_ में प्रतिक्रिया देखनी होगी)।\
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
आप यह भी भेज सकते हैं **अपने नियंत्रण वाले Gmail खाते को संदेश**, और अपने Gmail इनबॉक्स में **ईमेल के हेडर** की जाँच करें, `dkim=pass` `Authentication-Results` हैडर फ़ील्ड में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) आपको संकेत दे सकती है कि आपका domain spamhouse द्वारा ब्लॉक किया जा रहा है। आप अपना domain/IP हटाने का अनुरोध यहाँ कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​आप अपना domain/IP यहाँ हटाने का अनुरोध कर सकते हैं: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Set some **name to identify** the sender profile  
- तय करें कि आप किस account से phishing emails भेजने वाले हैं। Suggestions: _noreply, support, servicedesk, salesforce..._  
- आप username और password खाली छोड़ सकते हैं, लेकिन सुनिश्चित करें कि Ignore Certificate Errors को चेक किया गया हो

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Set some **name to identify** the template  
- फिर एक **subject** लिखें (कुछ भी अजीब न रखें, बस ऐसा कुछ जो किसी सामान्य ईमेल में पढ़ने की उम्मीद हो)  
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया है  
- **email template** लिखें (आप नीचे दिए गए उदाहरण की तरह variables इस्तेमाल कर सकते हैं):
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
नोट करें कि ईमेल की विश्वसनीयता बढ़ाने के लिए, क्लाइंट के किसी ईमेल सिग्नेचर का उपयोग करने की सलाह दी जाती है। सुझाव:

- किसी **non existent address** पर ईमेल भेजें और देखें कि क्या प्रतिक्रिया में कोई सिग्नेचर मिलता है।
- info@ex.com या press@ex.com या public@ex.com जैसे **public emails** खोजें और उन्हें ईमेल भेजकर प्रतिक्रिया का इंतज़ार करें।
- किसी **valid discovered** ईमेल से संपर्क करने की कोशिश करें और प्रतिक्रिया का इंतज़ार करें।

![](<../../images/image (80).png>)

> [!TIP]
> Email Template भी आपको **attach files to send** की सुविधा देता है। यदि आप NTLM challenges किसी विशेष रूप से तैयार की गई फाइल/दस्तावेज़ से चोरी करना चाहते हैं तो [इस पेज को पढ़ें](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- एक **name** लिखें
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप वेब पेजों को **import** भी कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को मार्क करें
- एक **redirection** सेट करें

![](<../../images/image (826).png>)

> [!TIP]
> आम तौर पर आपको पेज का HTML code बदलना होगा और लोकल में कुछ टेस्ट करने होंगे (शायद किसी Apache server का उपयोग करके) **जब तक परिणाम पसंद न आए।** फिर वह HTML code बॉक्स में लिख दें.\
> ध्यान रखें कि यदि आपको HTML के लिए कुछ static resources (शायद CSS और JS पेज) उपयोग करने हैं तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर _**/static/\<filename>**_ से एक्सेस कर सकते हैं।

> [!TIP]
> redirection के लिए आप उपयोगकर्ताओं को शिकार के legit main web page पर redirect कर सकते हैं, या उन्हें उदाहरण के लिए _/static/migration.html_ पर भेजें, कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 सेकंड के लिए दिखाएँ और फिर बताएं कि प्रक्रिया सफल रही।**

### Users & Groups

- एक नाम सेट करें
- **Import the data** (ध्यान दें कि टेम्पलेट का उपयोग करने के लिए उदाहरण में हर user का firstname, last name और email address होना आवश्यक है)

![](<../../images/image (163).png>)

### Campaign

अंत में, एक campaign बनाएं जिसमें नाम, email template, landing page, URL, sending profile और group चुनें। ध्यान दें कि URL वही लिंक होगा जो पीड़ितों को भेजा जाएगा

ध्यान दें कि **Sending Profile आपको एक test email भेजने की अनुमति देता है ताकि आप देख सकें कि final phishing email कैसा दिखेगा**:

![](<../../images/image (192).png>)

> [!TIP]
> मैं सलाह दूंगा कि **test emails 10min mails addresses** पर भेजें ताकि टेस्ट करते समय ब्लैकलिस्ट होने से बचा जा सके।

सब कुछ तैयार होने के बाद, बस campaign लॉन्च करें!

## Website Cloning

यदि किसी भी कारण से आप वेबसाइट को clone करना चाहते हैं तो निम्न पेज देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्यतः Red Teams के लिए) में आप ऐसे फाइलें भी भेजना चाहेंगे जिनमें किसी प्रकार का backdoor हो (शायद एक C2 या कुछ ऐसा जो authentication ट्रिगर करे)।\
कई उदाहरणों के लिए निम्न पेज देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला हमला काफी चालाक है क्योंकि आप एक असली वेबसाइट का नकल कर रहे होते हैं और उपयोगकर्ता द्वारा प्रविष्ट की गई जानकारी इकट्ठा कर रहे होते हैं। दुर्भाग्यवश, अगर उपयोगकर्ता ने सही password नहीं डाला या अगर जिस application की आप नकल कर रहे हैं वह 2FA के साथ कॉन्फ़िगर्ड है, तो **यह जानकारी आपको धोखा दिए गए उपयोगकर्ता के रूप में impersonate करने की अनुमति नहीं देगी**।

यहीं पर [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे टूल्स उपयोगी होते हैं। यह टूल आपको MitM जैसा हमला करने की अनुमति देता है। मूलतः, हमला इस तरह काम करता है:

1. आप असली वेबपेज के लॉगिन फॉर्म का **impersonate** करते हैं।
2. उपयोगकर्ता अपने **credentials** आपके fake पेज पर **send** करता है और टूल उन्हें असली वेबपेज पर भेजकर **जाँचता है कि credentials काम करते हैं या नहीं**।
3. यदि अकाउंट **2FA** से कॉन्फ़िगर है, तो MitM पेज इसके लिए पूछेगा और जैसे ही **user इसे दर्ज करता है** टूल इसे असली वेब पेज पर भेज देगा।
4. जब उपयोगकर्ता authenticated हो जाता है तो आप (attacker के रूप में) **captured credentials, 2FA, cookie और हर interaction की जानकारी** प्राप्त कर लेंगे, जबकि टूल MitM कर रहा होता है।

### Via VNC

यदि आप शिकार को मूल वेबपेज जैसा दिखने वाले malicious पेज पर भेजने के बजाय उसे एक **VNC session में एक ब्राउज़र से जोड़े हुए असली वेब पेज** पर भेजें तो क्या होगा? आप देख पाएंगे कि वह क्या कर रहा है, password, MFA, cookies चुरा सकेंगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) का उपयोग करके कर सकते हैं

## Detecting the detection

स्पष्ट रूप से यह जानने के सबसे अच्छे तरीकों में से एक है कि क्या आपको पकड़ा गया है: **blacklists में अपना domain सर्च करें**। यदि यह सूचीबद्ध पाया जाता है, तो किसी तरह आपका domain suspicious के रूप में detect हुआ है।\
एक आसान तरीका यह जाँचने का कि क्या आपका domain किसी blacklist में है वह है [https://malwareworld.com/](https://malwareworld.com)

हालाँकि, अन्य तरीके भी हैं जिससे पता चलता है कि शिकार **actively wild में suspicious phishing activity खोज रहा है** जैसा कि नीचे समझाया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप शिकार के domain के बहुत ही समान नाम वाला एक domain खरीद सकते हैं **और/या एक certificate generate कर सकते हैं** अपने नियंत्रित domain के किसी subdomain के लिए जिसमें शिकार के domain का **keyword** शामिल हो। यदि **victim** उन से किसी भी प्रकार की **DNS या HTTP interaction** करता है, तो आप जान जाएंगे कि **वह सक्रिय रूप से suspicious domains की तलाश कर रहा है** और आपको बहुत ही stealth रहने की आवश्यकता होगी।

### Evaluate the phishing

अगर यह जाँचना है कि आपका ईमेल spam फ़ोल्डर में जाएगा, ब्लॉक होगा या सफल होगा तो [**Phishious**](https://github.com/Rices/Phishious) का उपयोग करें।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion सेट्स अक्सर ईमेल ल्यूर्स को पूरी तरह छोड़कर सीधे service-desk / identity-recovery workflow को निशाना बनाते हैं ताकि MFA को मात दी जा सके। यह हमला पूरी तरह "living-off-the-land" है: एक बार operator के पास valid credentials आ जाएँ तो वे built-in admin tooling के साथ pivot कर लेते हैं – कोई malware आवश्यक नहीं होता।

### Attack flow
1. शिकार का reconnaissance
- LinkedIn, data breaches, public GitHub आदि से व्यक्तिगत और कॉर्पोरेट विवरण इकट्ठा करें।
- उच्च-मूल्य की पहचानें (executives, IT, finance) पहचानें और password / MFA reset के लिए **exact help-desk process** को enumerate करें।
2. रीयल-टाइम social engineering
- help-desk को फोन, Teams या चैट करें जबकि आप लक्ष्य का impersonation कर रहे हों (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
- knowledge-based verification पास करने के लिए पहले से एकत्रित PII प्रदान करें।
- एजेंट को मनाएं कि वह **MFA secret reset** करे या किसी registered mobile number पर **SIM-swap** करे।
3. तुरंत post-access actions (वास्तविक मामलों में ≤60 मिनट)
- किसी भी web SSO portal के माध्यम से foothold स्थापित करें।
- built-ins के साथ AD / AzureAD enumerate करें (कोई binaries ड्रॉप न करें):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
- **WMI**, **PsExec**, या पहले से environment में whitelist किए गए legitimate **RMM** agents के साथ lateral movement।

### Detection & Mitigation
- help-desk identity recovery को एक **privileged operation** के रूप में मानें – step-up auth और manager approval की आवश्यकता रखें।
- उन गतिविधियों पर अलर्ट करने वाले **Identity Threat Detection & Response (ITDR)** / **UEBA** नियम तैनात करें:
  - MFA method बदला गया + नए device/geo से authentication।
  - उसी principal (user→admin) का तत्काल elevation।
- help-desk कॉल्स को रिकॉर्ड करें और किसी भी reset से पहले **पहले से-registered नंबर** पर call-back लागू करें।
- लागू करें **Just-In-Time (JIT) / Privileged Access** ताकि हाल में reset किए गए अकाउंट्स स्वतः ही high-privilege tokens inherit न कर लें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity क्रूज़ उच्च-टच ऑप्स की लागत को उस मास आक्रमण से ऑफ़सेट करते हैं जो **search engines & ad networks को delivery channel** में बदल देता है।

1. **SEO poisoning / malvertising** एक नकली परिणाम जैसे `chromium-update[.]site` को टॉप search ads पर धकेलता है।
2. शिकार एक छोटा **first-stage loader** डाउनलोड करता है (अक्सर JS/HTA/ISO)। Unit 42 द्वारा देखे गए उदाहरण:
- `RedLine stealer`
- `Lumma stealer`
- `Lampion Trojan`
3. Loader browser cookies + credential DBs exfiltrate करता है, फिर एक **silent loader** खींचता है जो *real-time* निर्णय लेता है कि क्या deploy करना है:
- RAT (उदा. AsyncRAT, RustDesk)
- ransomware / wiper
- persistence component (registry Run key + scheduled task)

### Hardening tips
- newly-registered domains को ब्लॉक करें और *search-ads* पर भी Advanced DNS / URL Filtering लागू करें।
- सॉफ्टवेयर इंस्टॉलेशन को signed MSI / Store packages तक सीमित करें, नीति द्वारा `HTA`, `ISO`, `VBS` execution को deny करें।
- उन ब्राउज़र के child processes की निगरानी करें जो installers खोल रहे हैं:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
- उन LOLBins के लिए hunt करें जिन्हें first-stage loaders अक्सर misuse करते हैं (उदा. `regsvr32`, `curl`, `mshta`)।

---

## AI-Enhanced Phishing Operations
Attackers अब fully personalised lures और real-time interaction के लिए **LLM & voice-clone APIs** को chain करते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• untrusted automation से भेजे गए messages को highlight करने के लिए **dynamic banners** जोड़ें (ARC/DKIM anomalies के माध्यम से)।  
• high-risk phone requests के लिए **voice-biometric challenge phrases** लागू करें।  
• awareness programmes में लगातार AI-generated lures का simulation करें – static templates obsolete हैं।

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
क्लासिक push-bombing के अलावा, operators अक्सर बस help-desk कॉल के दौरान **नई MFA registration मजबूर कर देते हैं**, जिससे उपयोगकर्ता के मौजूदा token का असर समाप्त हो जाता है। किसी भी बाद के login prompt को शिकार के लिए वैध लगने लगता है।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

हमलावर compromised या typosquatted वेब पेज से चुपचाप पीड़ित के clipboard में malicious commands कॉपी कर सकते हैं और फिर उपयोगकर्ता को धोखा देकर उन्हें **Win + R**, **Win + X** या एक terminal window में paste करवा कर बिना किसी download या attachment के arbitrary code execute करा सकते हैं।

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators अक्सर अपने phishing flows को एक साधारण device check के पीछे छिपा देते हैं ताकि desktop crawlers अंतिम पन्नों तक न पहुँचें। एक सामान्य पैटर्न यह है कि एक छोटा स्क्रिप्ट touch-capable DOM की जाँच करता है और परिणाम को server endpoint पर पोस्ट कर देता है; non‑mobile clients को HTTP 500 (या एक blank page) मिलता है, जबकि mobile users को पूरा flow दिखता है।

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
- पहली लोड के दौरान session cookie सेट करता है।
- स्वीकार करता है `POST /detect {"is_mobile":true|false}`.
- जब `is_mobile=false` तो बाद के GETs के लिए 500 (या placeholder) लौटाता है; phishing केवल तभी serve करता है जब `true`।

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: sequence of `GET /static/detect_device.js` → `POST /detect` → HTTP 500 for non‑mobile; वैध mobile victim paths 200 लौटाते हैं और follow‑on HTML/JS सर्व करते हैं।
- उन पृष्ठों को ब्लॉक या सावधानी से जाँचें जो सामग्री को केवल `ontouchstart` या समान device checks पर आधारित करते हैं।

Defence tips:
- crawlers को mobile‑like fingerprints और JS सक्षम के साथ चलाएँ ताकि gated content प्रकट हो सके।
- नए पंजीकृत डोमेन पर `POST /detect` के बाद संदिग्ध 500 प्रतिक्रियाओं पर अलर्ट करें।

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
