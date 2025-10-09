# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 方法

1. 侦察受害者
1. 选择 **victim domain**。
2. 对目标的网站进行基础枚举，**搜索 login portals** 并决定你要**冒充**哪一个。
3. 使用一些 **OSINT** 来 **查找 emails**。
2. 准备环境
1. **Buy the domain** 作为 phishing 评估中使用的域名
2. 配置与 email service 相关的记录（SPF, DMARC, DKIM, rDNS）
3. 在 VPS 上配置 **gophish**
3. 准备活动
1. 准备 **email template**
2. 准备用于窃取凭证的 **web page**
4. 发起活动！

## 生成相似域名或购买可信域名

### 域名变体技巧

- **Keyword**：域名包含原始域名的重要**keyword**（例如，zelster.com-management.com）。
- **hypened subdomain**：将子域名的**点改为连字符**（例如，www-zelster.com）。
- **New TLD**：使用不同的**TLD**（例如，zelster.org）
- **Homoglyph**：用**外观相似的字符**替换域名中的字母（例如，zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition：** 在域名中**交换两个字母**（例如，zelsetr.com）。
- **Singularization/Pluralization：** 在域名末尾添加或删除 “s”（例如，zeltsers.com）。
- **Omission：** 从域名中**删除一个字母**（例如，zelser.com）。
- **Repetition：** 在域名中**重复一个字母**（例如，zeltsser.com）。
- **Replacement：** 类似 homoglyph 但不那么隐蔽。用其他字母替换域名中的某个字母，可能是键盘上邻近的字母（例如，zektser.com）。
- **Subdomained：** 在域名内部引入一个**点**（例如，ze.lster.com）。
- **Insertion：** 在域名中**插入一个字母**（例如，zerltser.com）。
- **Missing dot：** 将 TLD 直接附加到域名（例如，zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

存在一种可能性：存储或通信中的某些位可能会由于太阳耀斑、宇宙射线或硬件错误等各种因素而**自动翻转**。

当这个概念**应用到 DNS 请求**时，可能会导致**DNS 服务器接收到的域名**与最初请求的域名不一致。

例如，域名 "windows.com" 的单个位被修改，可能变为 "windnws.com"。

攻击者可能通过注册多个类似于受害者域名的 bit-flipping 域名来利用这一点。他们的目的是将合法用户重定向到自己的基础设施。

更多信息请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买可信域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 上搜索可以购买的过期域名。\
为了确保你要购买的过期域名**已经有良好的 SEO**，你可以在以下位置检查它的分类情况：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现 Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的 email 地址或**验证已发现的地址**，你可以尝试对目标的 smtp servers 进行暴力枚举。 [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，不要忘记如果用户通过**任何 web portal**访问他们的邮件，你可以检查该 portal 是否易受**username brute force**，并在可能的情况下利用该漏洞。

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该已经**购买好将要使用的域名**，并且该域名必须**指向**用于配置 **gophish** 的 **VPS** 的 **IP**。
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

然后将域名添加到以下文件：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**还要更改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后修改文件 **`/etc/hostname`** 和 **`/etc/mailname`** 为你的域名并 **重启你的 VPS。**

现在创建一个 **DNS A record** 为 `mail.<domain>`，指向 VPS 的 **ip address**，并创建一个 **DNS MX** 记录 指向 `mail.<domain>`

现在测试发送一封邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行并开始配置。\
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
**配置 gophish 服务**

为了创建 gophish 服务，使其可以自动启动并作为一个服务进行管理，你可以创建文件 `/etc/init.d/gophish` 并写入以下内容：
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
完成配置该服务并检查其运行情况：
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
## 配置邮件服务器和域名

### 等待并显得可信

域名存在时间越长，被标记为垃圾邮件的概率越低。因此在开展 phishing 评估前应尽量等待（至少 1 week）。此外，如果你在域名上放置与一个有信誉的行业相关的页面，获得的信誉会更好。

注意，即使需要等待一周，你也可以现在完成所有配置。

### Configure Reverse DNS (rDNS) record

设置一个 rDNS (PTR) 记录，将 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) Record

你必须 **configure a SPF record for the new domain**。如果你不知道什么是 SPF 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 https://www.spfwizard.net/ 来生成你的 SPF 策略（使用 VPS 的 IP）

![](<../../images/image (1037).png>)

This is the content that must be set inside a TXT record inside the domain:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告与一致性 (DMARC) 记录

您必须为新域**配置 DMARC 记录**。如果您不知道什么是 DMARC 记录，[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

您需要创建一个新的 DNS TXT 记录，主机名指向 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### 域名密钥识别邮件 (DKIM)

你必须为新域名**配置 DKIM**。如果你不知道什么是 DMARC 记录，[**阅读此页**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要将 DKIM 密钥生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的邮件配置评分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com) 来完成。  
只需访问该页面并向他们提供的地址发送一封电子邮件：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过发送邮件到 `check-auth@verifier.port25.com` 来**检查你的电子邮件配置**，并**读取响应**（为此你需要**打开** port **25**，如果你以 root 身份发送邮件，则在文件 _/var/mail/root_ 中查看响应）。\
检查你是否通过所有测试：
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
你也可以向你控制的 **Gmail 帐户发送一封消息**，并在你的 Gmail 收件箱中检查 **电子邮件的 headers**，`dkim=pass` 应该出现在 `Authentication-Results` header 字段中。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### 从 Spamhouse 黑名单中移除

The page [www.mail-tester.com](https://www.mail-tester.com) 可以告诉你你的域名是否被 spamhouse 阻止。你可以在以下地址请求移除你的域名/IP： ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从 Microsoft 黑名单中移除

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## 创建并启动 GoPhish 活动

### 发送配置

- 为发送者配置设置一个用于识别的**名称**
- 决定你将使用哪个账户发送 phishing 邮件。建议：_noreply, support, servicedesk, salesforce..._
- 用户名和密码可以留空，但请确保勾选 Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用“**Send Test Email**”功能来测试一切是否正常。\
> 我建议**将测试邮件发送到 10min mails 的地址**，以避免在测试时被列入黑名单。

### 邮件模板

- 为模板设置一个用于识别的**名称**
- 然后填写**主题**（不要太奇怪，写一个你在普通邮件中会预期看到的内容）
- 确保已勾选“**Add Tracking Image**”
- 编写**邮件模板**（你可以像下面示例那样使用变量）：
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
请注意，**为了增加邮件的可信度**，建议使用来自目标客户邮件中的某些签名。建议：

- 发送一封邮件到一个**不存在的地址**并检查回复中是否包含任何签名。
- 搜索诸如 info@ex.com、press@ex.com 或 public@ex.com 等**公开邮箱**，向其发送邮件并等待回复。
- 尝试联系一些**已发现的有效**邮箱并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许 **附加要发送的文件**。如果你还想通过某些特制的文件/文档窃取 NTLM challenges，请[阅读此页](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 填写一个**名称**
- **编写网页的 HTML 代码**。注意你可以 **导入** 网页。
- 勾选 **“Capture Submitted Data”** 和 **“Capture Passwords”**
- 设置一个**重定向**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要在本地修改 HTML 代码并进行一些测试（也许使用 Apache 服务器）**直到满意为止。** 然后，将该 HTML 代码写入文本框。\
> 注意，如果你需要为 HTML 使用某些静态资源（例如一些 CSS 和 JS 页面），你可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后通过 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，你可以**将用户重定向到受害者的真实主站点**，或者将其重定向到 _/static/migration.html_，例如放置一个 **旋转加载（**[**https://loading.io/**](https://loading.io)**）持续 5 秒，然后提示流程已成功**。

### Users & Groups

- 设置一个名称
- **导入数据**（注意：为了使用示例模板，你需要每个用户的 firstname、last name 和 email address）

![](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。注意 URL 将是发送给受害者的链接。

注意 **Sending Profile 允许发送测试邮件以查看最终 phishing 邮件的外观**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议将测试邮件发送到 10min mails addresses，以避免在测试时被列入黑名单。

一切就绪后，启动 campaign！

## Website Cloning

如果出于任何原因你想要克隆网站，请查看以下页面：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在一些 phishing 评估（主要是 Red Teams）中，你可能还想**发送包含某种后门的文件**（可能是 C2，或者只是触发一次认证的东西）。\
请查看以下页面获取一些示例：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前面的攻击相当巧妙，因为你伪造了一个真实的网站并收集用户提交的信息。不幸的是，如果用户没有输入正确的密码，或者你伪造的应用配置了 2FA，**这些信息将不足以让你冒充被诱骗的用户**。

这时像 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具就很有用。该类工具可以让你生成类似 MitM 的攻击。基本流程如下：

1. 你**模仿真实网页的登录表单**。
2. 用户将他的**凭证**发送到你的伪造页面，同时该工具会将这些凭证转发到真实网页，**检查凭证是否有效**。
3. 如果账号配置了 **2FA**，MitM 页面会要求输入，一旦**用户输入**，该工具会将其发送到真实网页。
4. 一旦用户认证通过，你（作为攻击者）将**捕获凭证、2FA、cookie 以及在工具进行 MitM 期间的所有交互信息**。

### Via VNC

如果不是**把受害者引导到一个恶意页面**（外观与原始页面相同），而是将其引导到一个**通过浏览器连接到真实网页的 VNC 会话**，那会如何？你将能够看到他所做的操作，窃取密码、使用的 MFA、cookie 等。\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现这一点。

## Detecting the detection

显然，判断自己是否已被识破的最佳方法之一是**在黑名单中搜索你的域名**。如果它出现在列表中，说明你的域名被检测为可疑。\
一种简单的方法是使用 [https://malwareworld.com/](https://malwareworld.com) 来检查你的域名是否出现在任何黑名单中。

不过，还有其他方法可以判断受害者是否**正在主动寻找网络上的可疑 phishing 活动**，如以下内容所述：


{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买与受害者域名非常相似的域名**，和/或为你控制的某个域名的**子域生成证书**，该子域名包含受害者域名的**关键字**。如果**受害者**对这些域名执行任何形式的 **DNS 或 HTTP 交互**，你就会知道他**正在主动搜索**可疑域名，那时你需要非常隐蔽地行动。

### Evaluate the phishing

使用 [**Phishious**](https://github.com/Rices/Phishious) 来评估你的邮件是否会被判为垃圾邮件、被阻断或成功到达。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代的入侵组织越来越多地完全跳过邮件诱饵，直接针对服务台/身份恢复流程以绕过 MFA。该攻击完全依靠“living-off-the-land”：一旦操作员拥有有效凭据，他们就使用内置的管理工具进行横向移动——无需恶意软件。

### Attack flow
1. Recon the victim
* 从 LinkedIn、数据泄露、公开 GitHub 等处收集个人与公司信息。
* 识别高价值身份（高管、IT、财务）并枚举用于密码/MFA 重置的**确切 help-desk 流程**。
2. Real-time social engineering
* 使用电话、Teams 或聊天与 help-desk 联系，同时冒充目标（通常使用 **spoofed caller-ID** 或 **克隆语音**）。
* 提供先前收集的 PII 来通过基于知识的验证。
* 说服客服代理**重置 MFA secret**或对已注册的手机号执行**SIM-swap**。
3. Immediate post-access actions (≤60 min in real cases)
* 通过任何 web SSO 门户建立立足点。
* 使用内置工具枚举 AD / AzureAD（不放置任何二进制文件）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用 **WMI**、**PsExec** 或环境中已被列入白名单的合法 **RMM** 代理进行横向移动。

### Detection & Mitigation
* 将 help-desk 身份恢复视为**特权操作（privileged operation）**——要求 step-up auth 与经理审批。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则以触发告警，例如：
* MFA 方法被更改 + 来自新设备/新地理位置的认证。
* 同一主体的即时权限提升（user → admin）。
* 记录 help-desk 通话，并在任何重置前强制**回拨到已注册的号码**。
* 实施 **Just-In-Time (JIT) / Privileged Access**，以便新重置的账户**不会**自动继承高权限令牌。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
一些普遍的团伙通过大规模攻击来抵消高触达操作的成本，将**搜索引擎和广告网络作为投放渠道**。

1. **SEO poisoning / malvertising** 将一个虚假结果（例如 `chromium-update[.]site`）推上搜索广告顶部。
2. 受害者下载一个小型的**第一阶段加载器**（通常为 JS/HTA/ISO）。Unit 42 见过的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 加载器外泄浏览器 cookie + 凭证数据库，然后拉取一个**静默加载器**，该加载器会实时决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* 持久化组件（注册表 Run 键 + 计划任务）

### Hardening tips
* 阻断新注册域名，并在搜索广告以及电子邮件上强制实施 **Advanced DNS / URL Filtering**。
* 限制软件安装为签名的 MSI / Store 包，策略上禁止执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器的子进程打开安装程序：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜索常被第一阶段加载器滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

---

## AI-Enhanced Phishing Operations
攻击者现在将 **LLM** 与 语音克隆 API 串联起来，用于完全个性化的诱饵和实时交互。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|生成并发送 >100 k 封带有随机措辞与跟踪链接的邮件/SMS。|
|Generative AI|生成一次性邮件，引用公开的并购信息、来自社交媒体的内部笑话；在回拨诈骗中使用 CEO 的 deep-fake 语音。|
|Agentic AI|自动注册域名、爬取开源情报、当受害者点击但未提交凭证时自动制作后续邮件。|

**防御：**
• 添加 **动态横幅**，突出显示来自不受信任自动化发送的消息（通过 ARC/DKIM 异常检测）。  
• 对高风险电话请求部署 **语音生物识别挑战短语**。  
• 在安全意识培训中持续模拟 AI 生成的诱饵 —— 静态模板已过时。

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
除了经典的 push-bombing，操作者也会在 help-desk 通话中直接**强制新的 MFA 注册**，使用户现有的令牌失效。任何随后出现的登录提示对受害者来说都看起来是合法的。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，当 **`deleteMFA` + `addMFA`** 在同一 IP 的几分钟内发生。



## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或 typosquatted 的网页静默地将恶意命令复制到受害者的 clipboard，然后诱导用户将其粘贴到 **Win + R**、**Win + X** 或 terminal 窗口中，从而在无需任何 download 或 attachment 的情况下执行 arbitrary code。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
运营者越来越多地在 phishing 流程后设置简单的设备检测，使 desktop crawlers 无法到达最终页面。常见模式是一个小脚本检测是否有 touch-capable DOM 并将结果 post 到 server endpoint；non‑mobile clients 会收到 HTTP 500（或空白页），而 mobile users 则看到完整流程。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 逻辑 (简化):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behaviour often observed:
- 在首次加载时设置会话 cookie。
- Accepts `POST /detect {"is_mobile":true|false}`.
- 在随后的 GET 请求中当 `is_mobile=false` 时返回 500（或占位页）；仅在 `true` 时提供 phishing。

Hunting and detection heuristics:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web 遥测：序列 `GET /static/detect_device.js` → `POST /detect` → 非移动设备返回 HTTP 500；真实移动受害路径返回 200 并随后返回 HTML/JS。
- 阻止或审查仅基于 `ontouchstart` 或类似设备检测来决定内容的页面。

Defence tips:
- 使用带有移动端指纹且启用 JS 的爬虫来揭示受限内容。
- 对新注册域名上在 `POST /detect` 之后出现的可疑 500 响应发出警报。

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
