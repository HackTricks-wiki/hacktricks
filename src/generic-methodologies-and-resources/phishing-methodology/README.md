# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## कार्यप्रणाली

1. Victim का Recon करें
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. पर्यावरण तैयार करें
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. अभियान तैयार करें
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. अभियान लॉन्च करें!

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

**TLS प्रमाणपत्र कॉन्फ़िगरेशन**

इस चरण से पहले आपके पास वह **पहले से खरीदा हुआ डोमेन** होना चाहिए जिसे आप उपयोग करने जा रहे हैं और यह **VPS के IP** की ओर **निर्देशित** होना चाहिए जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

**इसके अलावा /etc/postfix/main.cf के अंदर निम्न वेरिएबल्स के मान भी बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** अपने डोमेन नाम पर बदलें और **अपना VPS रिस्टार्ट करें।**

अब, `mail.<domain>` का एक **DNS A record** बनाएं जो VPS के **ip address** की ओर पॉइंट करे और एक **DNS MX** record बनाएं जो `mail.<domain>` की ओर पॉइंट करे

अब एक ईमेल भेजकर टेस्ट करते हैं:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish कॉन्फ़िगरेशन**

gophish के निष्पादन को रोकें और इसे कॉन्फ़िगर करें.\
Modify `/opt/gophish/config.json` to the following (note the use of https):
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

gophish सेवा बनाने के लिए ताकि इसे स्वचालित रूप से शुरू किया जा सके और सेवा के रूप में प्रबंधित किया जा सके, आप निम्न सामग्री के साथ `/etc/init.d/gophish` फ़ाइल बना सकते हैं:
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
सेवा की कॉन्फ़िगरेशन पूरा करें और निम्न करके इसकी जाँच करें:
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

### प्रतीक्षा करें & वैध दिखें

जो डोमेन पुराना होगा, उसे स्पैम के रूप में पकड़े जाने की संभावना कम होती है। इसलिए आपको phishing assessment से पहले जितना संभव हो सके उतना समय (कम से कम 1 सप्ताह) प्रतीक्षा करनी चाहिए। इसके अलावा, अगर आप किसी प्रतिष्ठा वाले सेक्टर के बारे में एक पेज डालते हैं तो प्राप्त होने वाली प्रतिष्ठा बेहतर होगी।

ध्यान दें कि भले ही आपको एक हफ्ता प्रतीक्षा करनी पड़े, आप सब कुछ अभी ही कॉन्फ़िगर कर सकते हैं।

### रिवर्स DNS (rDNS) रिकॉर्ड कॉन्फ़िगर करें

ऐसा rDNS (PTR) रिकॉर्ड सेट करें जो VPS के IP पते को डोमेन नाम पर रिज़ॉल्व करे।

### Sender Policy Framework (SPF) Record

आपको नए डोमेन के लिए **SPF रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि SPF रिकॉर्ड क्या है तो [**इस पृष्ठ को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (VPS मशीन के IP का उपयोग करें)

![](<../../images/image (1037).png>)

यह वह सामग्री है जिसे डोमेन के अंदर TXT रिकॉर्ड में सेट किया जाना चाहिए:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### डोमेन-आधारित संदेश प्रमाणीकरण, रिपोर्टिंग और संगति (DMARC) रिकॉर्ड

आपको **नए डोमेन के लिए DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है तो [**इस पृष्ठ को पढ़ें**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको होस्टनेम `_dmarc.<domain>` की ओर इशारा करते हुए एक नया DNS TXT रिकॉर्ड बनाना होगा, जिसमें निम्नलिखित सामग्री हो:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना होगा**। अगर आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा जनरेट किए गए दोनों B64 मानों को जोड़ना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपने ईमेल कॉन्फ़िगरेशन स्कोर का परीक्षण करें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com)\ बस पेज पर जाएँ और दिए गए पते पर एक ईमेल भेजें:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप भी **अपना ईमेल कॉन्फ़िगरेशन जांच सकते हैं** `check-auth@verifier.port25.com` पर एक ईमेल भेजकर और **प्रतिक्रिया पढ़कर** (इसके लिए आपको **खोलना** port **25** होगा और यदि आप ईमेल root के रूप में भेजते हैं तो फ़ाइल _/var/mail/root_ में प्रतिक्रिया देखें).\
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
आप **अपने नियंत्रण वाले Gmail पर संदेश** भी भेज सकते हैं, और अपनी Gmail इनबॉक्स में **email’s headers** की जाँच कर सकते हैं; `dkim=pass` को `Authentication-Results` हेडर फील्ड में मौजूद होना चाहिए.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist से हटाना

The page [www.mail-tester.com](https://www.mail-tester.com) यह बता सकता है कि आपका domain स्पैमहाउस द्वारा ब्लॉक किया जा रहा है या नहीं. आप अपने domain/IP को हटाने का अनुरोध यहाँ कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist से हटाना

​​आप अपने domain/IP को हटाने का अनुरोध यहाँ कर सकते हैं: [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### भेजने की प्रोफ़ाइल

- टेम्पलेट की पहचान के लिए कुछ **पहचान के लिए नाम** सेट करें
- तय करें कि आप phishing emails किस अकाउंट से भेजेंगे। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन सुनिश्चित करें कि **Ignore Certificate Errors** को चेक किया गया हो

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह सलाह दी जाती है कि यह सुनिश्चित करने के लिए कि सब कुछ काम कर रहा है, **"Send Test Email"** functionality का उपयोग करें.\
> मैं सुझाव दूँगा कि परीक्षण करते समय blacklisted होने से बचने के लिए **test emails को 10min mails addresses पर भेजें**.

### Email Template

- टेम्पलेट की पहचान के लिए कुछ **पहचान के लिए नाम** सेट करें
- फिर एक **subject** लिखें (कुछ असामान्य नहीं, बस ऐसा कुछ जो आप एक सामान्य ईमेल में पढ़ने की उम्मीद कर सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया है
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
ध्यान दें कि **in order to increase the credibility of the email**, इसे अधिक विश्वसनीय बनाने के लिए क्लाइंट के किसी ईमेल के signature का उपयोग करना सुझाया जाता है। सुझाव:

- किसी **non existent address** पर ईमेल भेजें और जाँच करें कि प्रतिक्रिया में कोई signature है या नहीं।
- **public emails** जैसे info@ex.com या press@ex.com या public@ex.com खोजें और उन्हें ईमेल भेजकर प्रतिक्रिया का इंतज़ार करें।
- किसी **some valid discovered** ईमेल से संपर्क करने की कोशिश करें और प्रतिक्रिया का इंतज़ार करें।

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template भी आपको **attach files to send** की अनुमति देता है। यदि आप कुछ specially crafted files/documents के जरिए NTLM challenges चुराना चाहते हैं तो [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)।

### Landing Page

- एक **name** लिखें
- वेब पेज का **HTML code लिखें**। ध्यान दें कि आप वेब पेज **import** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को मार्क करें
- एक **redirection** सेट करें

![](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको पेज के HTML को modify करना होगा और local में कुछ टेस्ट करने होंगे (शायद किसी Apache server का उपयोग करके) **जब तक आपको परिणाम अच्छे न लगें।** फिर वह HTML code बॉक्स में लिखें.\
> ध्यान दें कि यदि आपको HTML के लिए कुछ static resources (शायद कुछ CSS और JS पेज) उपयोग करने हैं तो आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर _**/static/\<filename>**_ से एक्सेस कर सकते हैं।

> [!TIP]
> रिडायरेक्शन के लिए आप उपयोगकर्ताओं को पीड़ित के legit मुख्य वेब पेज पर redirect कर सकते हैं, या उदाहरण के लिए उन्हें _/static/migration.html_ पर भेजें, कुछ **spinning wheel (**[**https://loading.io/**](https://loading.io)**) 5 सेकंड के लिए दिखाएँ और फिर संकेत दें कि प्रक्रिया सफल रही।**

### Users & Groups

- एक नाम सेट करें
- **Import the data** (ध्यान दें: उदाहरण के लिए template इस्तेमाल करने के लिए आपको हर user का firstname, last name और email address चाहिए)

![](<../../images/image (163).png>)

### Campaign

अंत में, एक campaign बनाएं जिसमें नाम, email template, landing page, URL, sending profile और group चुनें। ध्यान दें कि URL victims को भेजी जाने वाली लिंक होगी

ध्यान दें कि **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> मैं सुझाव दूंगा कि टेस्ट emails भेजने के लिए 10min mails addresses का उपयोग करें ताकि टेस्ट करते समय blacklisted होने से बचा जा सके।

सब कुछ तैयार होने पर, बस campaign लॉन्च करें!

## Website Cloning

यदि किसी कारण से आप वेबसाइट क्लोन करना चाहते हैं तो निम्नलिखित पेज देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्य रूप से Red Teams के लिए) में आप फ़ाइलें भी भेजना चाहेंगे जिनमें किसी प्रकार का backdoor हो (शायद कोई C2 या सिर्फ कुछ जो authentication ट्रिगर करे)।\
कुछ उदाहरणों के लिए निम्नलिखित पेज देखें:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला हमला काफी चालाक है क्योंकि आप एक असली वेबसाइट की नकल कर रहे हैं और उपयोगकर्ता द्वारा दर्ज की गई जानकारी इकट्ठा कर रहे हैं। दुर्भाग्य से, यदि उपयोगकर्ता ने सही password नहीं डाला या यदि जिस application की आपने नकल की है वह 2FA के साथ configured है, तो **यह जानकारी आपको tricked user के रूप में impersonate करने की अनुमति नहीं देगी**।

यहाँ ऐसे tools जैसे [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) उपयोगी होते हैं। ये tools आपको MitM जैसा attack जनरेट करने की अनुमति देते हैं। मूल रूप से, attack निम्न तरीके से काम करता है:

1. आप वास्तविक वेबपेज के लॉगिन फॉर्म की **impersonate** करते हैं।
2. उपयोगकर्ता अपनी **credentials** आपके फेक पेज पर **send** करता है और tool उन्हें वास्तविक वेबपेज पर भेजकर **जाँचता है कि credentials काम करते हैं या नहीं**।
3. अगर खाते में **2FA** configured है, तो MitM पेज उसे मांगेगा और जैसे ही **user उसे दर्ज करता है**, tool उसे वास्तविक वेब पेज पर भेज देगा।
4. एक बार user authenticated हो जाने पर आप (attacker के रूप में) **captured credentials, 2FA, cookie और किसी भी interaction की जानकारी** प्राप्त कर लेंगे जब तक tool MitM कर रहा है।

### Via VNC

अगर आप victim को original पेज जैसा malicious पेज भेजने के बजाय उसे एक **VNC session जिसमें ब्राउज़र वास्तविक वेब पेज से connected हो** भेजें तो क्या होगा? आप देख पाएंगे कि वह क्या कर रहा है, password, MFA, cookies चुरा सकेंगे...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं

## Detecting the detection

साफ है कि यह जानने का एक अच्छा तरीका कि आपको पकड़ा गया है या नहीं, यह है कि आप अपनी domain को blacklists में search करें। अगर यह सूचीबद्ध दिखाई दे, तो किसी तरह आपकी domain suspicious के रूप में detected हुई है।\
अपनी domain किसी भी blacklist में दिखाई दे रही है या नहीं यह जांचने के लिए एक आसान तरीका [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना है

हालांकि, यह जानने के और तरीके भी हैं कि पीड़ित **actively suspicious phishing activity की तलाश कर रहा है** जैसा कि नीचे समझाया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप पीड़ित के domain के बहुत समान नाम वाला एक domain खरीद सकते हैं **और/या** अपने नियंत्रित domain के किसी subdomain के लिए certificate generate कर सकते हैं जिसमें पीड़ित के domain का **keyword** शामिल हो। यदि **victim** उनके साथ किसी भी प्रकार की **DNS या HTTP interaction** करता है, तो आप जान जाएंगे कि **वह सक्रिय रूप से suspicious domains ढूँढ रहा है** और आपको बहुत stealth रहने की आवश्यकता होगी।

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) यह आकलन करने के लिए कि आपका email spam फोल्डर में जाएगा या ब्लॉक/सफल होगा।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion sets अक्सर ईमेल लुरेस को पूरी तरह छोड़ देते हैं और MFA को हराने के लिए सीधे service-desk / identity-recovery workflow को निशाना बनाते हैं। यह attack पूरी तरह "living-off-the-land" है: एक बार operator के पास valid credentials आ गए, वे built-in admin tooling के साथ pivot करते हैं – किसी malware की आवश्यकता नहीं होती।

### Attack flow
1. Victim reconnaissance
* LinkedIn, data breaches, public GitHub आदि से personal और corporate विवरण इकट्ठा करें।
* high-value identities (executives, IT, finance) पहचानें और password / MFA reset के लिए **exact help-desk process** का enumeration करें।
2. Real-time social engineering
* Phone, Teams या चैट के माध्यम से help-desk से target बनकर संपर्क करें (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
* knowledge-based verification पास करने के लिए पहले से इकट्ठा किए गए PII प्रदान करें।
* agent को मनाएँ कि वह **MFA secret reset करे** या किसी registered mobile number पर **SIM-swap** करे।
3. Immediate post-access actions (≤60 min in real cases)
* किसी भी web SSO portal के माध्यम से foothold स्थापित करें।
* built-ins के साथ AD / AzureAD का enumeration करें (कोई binaries drop नहीं किए जाते):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement के लिए **WMI**, **PsExec**, या environment में पहले से whitelisted legitimate **RMM** agents का उपयोग करें।

### Detection & Mitigation
* help-desk identity recovery को एक **privileged operation** मानें – step-up auth और manager approval आवश्यक करें।
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules लागू करें जो alert करें जब:
* MFA method बदला गया + नई device / geo से authentication।
* उसी principal का तुरंत elevation (user → admin)।
* help-desk कॉल रिकॉर्ड करें और किसी भी reset से पहले **पहले से-registered नंबर पर call-back** लागू करें।
* **Just-In-Time (JIT) / Privileged Access** लागू करें ताकि newly reset accounts स्वचालित रूप से high-privilege tokens inherit न करें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews उच्च-touch ops की लागत को mass attacks से ऑफ़सेट करते हैं जो **search engines & ad networks को delivery channel** में बदल देते हैं।

1. **SEO poisoning / malvertising** एक fake result जैसे `chromium-update[.]site` को top search ads में धकेलता है।
2. Victim एक छोटा **first-stage loader** (अक्सर JS/HTA/ISO) डाउनलोड करता है। Unit 42 द्वारा देखे गए उदाहरण:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader browser cookies + credential DBs को exfiltrate करता है, फिर एक **silent loader** खींचता है जो real-time में तय करता है कि क्या deploy करना है:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* newly-registered domains को ब्लॉक करें और *search-ads* के साथ-साथ ईमेल पर भी **Advanced DNS / URL Filtering** लागू करें।
* सॉफ़्टवेयर इंस्टॉलेशन को signed MSI / Store packages तक सीमित करें, और नीति द्वारा `HTA`, `ISO`, `VBS` execution को deny करें।
* browsers के child processes जो installers खोल रहे हैं उनका मॉनिटरिंग करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* उन LOLBins के लिए hunt करें जिन्हें first-stage loaders अक्सर मिसयूज़ करते हैं (उदाहरण: `regsvr32`, `curl`, `mshta`)।

---

## AI-Enhanced Phishing Operations
Attackers अब fully personalised lures और real-time interaction के लिए **LLM & voice-clone APIs** को chain करते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|एक-एक करके emails बनाना जो public M&A, social media के अंदर के जोक्स का संदर्भ देते हैं; callback scam में deep-fake CEO voice।|
|Agentic AI|स्वतंत्र रूप से domains register करना, open-source intel scrape करना, जब victim क्लिक करे पर creds न भेजे तो next-stage mails craft करना।|

**Defence:**
• अनविश्वसनीय automation से भेजे गए messages को highlight करने के लिए **dynamic banners** जोड़ें (ARC/DKIM anomalies के माध्यम से)।  
• high-risk फोन अनुरोधों के लिए **voice-biometric challenge phrases** लागू करें।  
• चेतना कार्यक्रमों में लगातार AI-generated lures का अनुकरण करें – static templates अब obsolete हैं।

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
classic push-bombing के अलावा, operators सीधे help-desk कॉल के दौरान **नया MFA registration force कर देते हैं**, जिससे user के मौजूदा token का नकार होना होता है। किसी भी subsequent login prompt पीड़ित के लिए legitimate दिखाई देगा।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta इवेंट्स की निगरानी करें जहाँ **`deleteMFA` + `addMFA`** एक ही IP से कुछ ही मिनटों के भीतर होते हों।



## Clipboard Hijacking / Pastejacking

हमलावर compromised या typosquatted वेब पेज से चुपचाप घातक कमांड पीड़ित के क्लिपबोर्ड में कॉपी कर सकते हैं और फिर उपयोगकर्ता को उन्हें **Win + R**, **Win + X** या किसी terminal विंडो में paste करने के लिए धोखा दे सकते हैं, जिससे बिना किसी download या attachment के arbitrary code निष्पादित हो जाता है।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
ऑपरेटर अपने phishing flows को एक साधारण डिवाइस चेक के पीछे increasingly gate करते हैं ताकि desktop crawlers कभी अंतिम पेज तक न पहुँचें। एक सामान्य पैटर्न एक छोटा स्क्रिप्ट है जो touch-capable DOM के लिए जाँच करता है और परिणाम को एक server endpoint पर पोस्ट करता है; non‑mobile clients को HTTP 500 (या एक खाली पेज) मिलता है, जबकि mobile users को पूरा flow सर्व किया जाता है।

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
सर्वर का अक्सर देखा गया व्यवहार:
- पहली लोड के दौरान session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- जब `is_mobile=false` हो तो बाद की GETs पर 500 (या placeholder) लौटाता है; केवल जब `true` हो तब phishing सर्व करता है।

हंटिंग और डिटेक्शन हीरिस्टिक्स:
- urlscan क्वेरी: `filename:"detect_device.js" AND page.status:500`
- वेब टेलीमेट्री: `GET /static/detect_device.js` → `POST /detect` → non‑mobile के लिए HTTP 500; वैध मोबाइल victim paths 200 लौटाते हैं और आगे का HTML/JS सर्व करते हैं।
- केवल `ontouchstart` या इसी तरह के device checks पर सामग्री को निर्भर करने वाले पेजों को ब्लॉक या गहन जाँच करें।

रक्षा सुझाव:
- गेटेड सामग्री दिखाने के लिए क्रॉलर को mobile‑like fingerprints और JS सक्षम करके चलाएँ।
- नए पंजीकृत डोमेनों पर `POST /detect` के बाद संदिग्ध 500 responses पर अलर्ट सेट करें।

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
