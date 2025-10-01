# Phishing 方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法

1. Recon 目标
1. 选择 **目标域名**。
2. 执行一些基本的 web 枚举，**搜索受害者使用的登录门户**，并**决定**你将**冒充**哪个。
3. 使用一些 **OSINT** 来 **查找电子邮件**。
2. 准备环境
1. **Buy the domain**，用于 phishing 评估
2. **Configure the email service** 的相关记录 (SPF, DMARC, DKIM, rDNS)
3. 在 VPS 上配置 **gophish**
3. 准备 campaign
1. 准备 **email template**
2. 准备用于窃取凭证的 **web page**
4. 启动 campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**：域名包含原域名的一个重要**关键词**（例如 zelster.com-management.com）。
- **hypened subdomain**：将子域名的**点替换为连字符**（例如 www-zelster.com）。
- **New TLD**：使用**新的 TLD**的相同域名（例如 zelster.org）
- **Homoglyph**：将域名中的某个字母替换为**外观相似**的字母（例如 zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 在域名中**交换两个字母**（例如 zelsetr.com）。
- **Singularization/Pluralization**：在域名末尾添加或删除 “s”（例如 zeltsers.com）。
- **Omission**：从域名中**去掉一个字母**（例如 zelser.com）。
- **Repetition:** 在域名中**重复一个字母**（例如 zeltsser.com）。
- **Replacement**：类似 homoglyph，但不那么隐蔽。用另一个字母替换域名中的某个字母，可能是键盘上与原字母相邻的字母（例如 zektser.com）。
- **Subdomained**：在域名中插入一个 **点**（例如 ze.lster.com）。
- **Insertion**：在域名中**插入一个字母**（例如 zerltser.com）。
- **Missing dot**：将 TLD 直接附加到域名中。（例如 zelstercom.com）

**自动化工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

存在一种可能性：存储或传输中的某些位会由于太阳耀斑、宇宙射线或硬件错误等各种因素而**自动翻转**。

当该概念**应用于 DNS 请求**时，被 DNS 服务器接收到的域名可能与最初请求的域名不一致。

例如，对域名 "windows.com" 的单个位修改可能会将其变为 "windnws.com"。

攻击者可能**利用这一点注册多个发生 bit-flipping 的域名**，这些域名与受害者的域名相似，目的是将合法用户重定向到他们自己的基础设施。

欲了解更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 上搜索可用的过期域名，作为候选。\
为确保你打算购买的过期域名**已有良好的 SEO**，可以查看其在以下分类中的归属：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为发现更多有效邮箱或验证已发现的邮箱，你可以尝试对受害者的 smtp 服务器进行 username brute-force（查看是否可被爆破）。[在此了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，别忘了如果用户使用任何 web portal 来访问他们的邮件，你可以检查该门户是否存在 username brute force 的漏洞，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### 安装

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该 **已经购买好将要使用的 domain**，并且它必须 **指向** **IP of the VPS**，该 VPS 是你正在为其配置 **gophish** 的。
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

开始安装： `apt-get install postfix`

然后将域添加到以下文件：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**还要在 /etc/postfix/main.cf 中更改以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，并 **重启你的 VPS。**

现在为 `mail.<domain>` 创建一个指向 VPS **ip address** 的 **DNS A record**，并为 `mail.<domain>` 创建一个 **DNS MX** 记录。

现在测试发送电子邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行并开始配置它。\
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

为了创建 gophish 服务，使其可以自动启动并作为服务进行管理，你可以创建文件 `/etc/init.d/gophish`，其内容如下：
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
完成服务配置并检查其运行情况：
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

### 等待并保持可信度

域名存在的时间越长，被判定为垃圾邮件的概率越低。因此在进行 phishing 评估前，应该尽可能等待（至少 1 周）。此外，如果你在域名上放置与有信誉行业相关的页面，所获得的信誉会更好。

注意：即使需要等待一周，你也可以现在完成所有配置。

### 配置反向 DNS (rDNS) 记录

设置一个 rDNS (PTR) 记录，将 VPS 的 IP 地址反向解析到域名。

### Sender Policy Framework (SPF) 记录

你必须 **为新域名配置 SPF record**。如果你不知道什么是 SPF record [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF policy（使用 VPS 机器的 IP）

![](<../../images/image (1037).png>)

这是必须在域名的 TXT record 中设置的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的邮件身份验证、报告与一致性 (DMARC) 记录

你必须为新域名**配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，请[**阅读此页**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，主机名指向 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须为新域名**配置 DKIM**。如果你不知道什么是 DMARC 记录，[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要将 DKIM 密钥生成的两个 B64 值连接在一起：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的邮件配置得分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com/) 来完成。\
只需访问该页面并发送一封邮件到他们提供的地址：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过向 `check-auth@verifier.port25.com` 发送邮件来**检查你的邮件配置**，并**读取响应**（为此你需要**打开**端口 **25**，并在以 root 身份发送邮件时查看文件 _/var/mail/root_ 中的响应）。\
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
你也可以向你控制的 **Gmail** 发送消息，并在你的 Gmail 收件箱中查看 **email’s headers**，在 `Authentication-Results` header 字段中应看到 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### 从 Spamhouse 黑名单移除

页面 [www.mail-tester.com](https://www.mail-tester.com) 可以指示您的域名是否被 Spamhouse 阻止。您可以在 [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) 请求将您的域名/IP 移除。

### 从 Microsoft 黑名单移除

您可以在 [https://sender.office.com/](https://sender.office.com) 请求将您的域名/IP 移除。

## 创建并启动 GoPhish 活动

### 发送配置

- 为发送者配置设置一个用于识别的**名称**
- 决定将使用哪个账户发送钓鱼邮件。建议： _noreply, support, servicedesk, salesforce..._
- 用户名和密码可以留空，但请务必勾选 Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常。\
> 我建议将**测试邮件发送到 10min mails 地址**，以避免在测试时被列入黑名单。

### 邮件模板

- 为模板设置一个用于识别的**名称**
- 然后写一个**主题**（不要奇怪的内容，只写普通邮件中会出现的内容）
- 确保已勾选 "**Add Tracking Image**"
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
请注意，**为了增加邮件的可信度**，建议使用来自客户邮件中的某些签名。建议：

- 给一个**不存在的地址**发送邮件并检查回复中是否有任何签名。
- 搜索像 info@ex.com、press@ex.com 或 public@ex.com 这样的**公开邮箱**，向其发送邮件并等待回复。
- 尝试联系一些**已发现的有效**邮箱并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许**附加要发送的文件**。如果你还想通过某些特制的文件/文档窃取 NTLM 挑战，请[阅读此页](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 填写一个**名称**
- **编写网页的 HTML 代码**。注意你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个**重定向**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改 HTML 代码并在本地进行一些测试（可能使用某些 Apache 服务器），**直到满意为止。** 然后，把该 HTML 代码写入文本框。\
> 注意，如果你需要为 HTML 使用一些静态资源（例如一些 CSS 和 JS 文件），可以将它们保存在 _**/opt/gophish/static/endpoint**_，然后通过 _**/static/\<filename>**_ 来访问它们。

> [!TIP]
> 对于重定向，你可以将用户**重定向到受害者的合法主页面**，或者例如重定向到 _/static/migration.html_，显示一个**旋转加载（**[**https://loading.io/**](https://loading.io)**）持续 5 秒，然后提示操作成功**。

### Users & Groups

- 设置一个名称
- **导入数据**（注意：要使用示例模板，你需要为每个用户提供 firstname、last name 和 email address）

![](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。注意 URL 将是发送给受害者的链接。

注意 **Sending Profile 允许发送测试邮件以查看最终钓鱼邮件的样子**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议将测试邮件发送到 10min mails 地址，以避免测试时被列入黑名单。

一切就绪后，直接启动 campaign！

## Website Cloning

如果出于任何原因你想克隆网站，请查看以下页面：

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在一些钓鱼评估（主要是 Red Teams）中，你可能还希望**发送包含某种后门的文件**（可能是 C2，或只是某些会触发身份验证的内容）。\
查看以下页面获取一些示例：

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述攻击很巧妙，因为你是假冒真实网站并收集用户提交的信息。不幸的是，如果用户没有输入正确的密码，或你伪造的应用启用了 2FA，**这些信息将无法让你冒充被钓用户**。

这时像 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具就很有用。该类工具会让你生成一个 MitM 风格的攻击。基本流程如下：

1. 你**仿冒真实网页的登录**表单。
2. 用户把**凭证**发送到你的伪页面，工具会把这些凭证转发到真实网页，**检查凭证是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会请求该项，一旦**用户输入**，工具会把它发送到真实网页。
4. 一旦用户被认证，你（作为攻击者）将**捕获凭证、2FA、cookie 以及在工具执行 MitM 期间的所有交互信息**。

### Via VNC

如果你不是将受害者发送到一个恶意且外观相同的页面，而是把他带到一个**通过浏览器连接到真实网页的 VNC 会话**中呢？你将能看到他所做的一切，窃取密码、MFA、cookie……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现。

## Detecting the detection

显然，判断是否被发现的最好方法之一是**在黑名单中搜索你的域名**。如果出现列出，说明你的域名被检测为可疑。\
一个简单的方式是使用 [https://malwareworld.com/](https://malwareworld.com) 检查你的域名是否出现在任何黑名单中。

此外，还有其他方法可以判断受害者是否**主动在野外寻找可疑钓鱼活动**，如以下文档所述：

{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个与受害者域名非常相似的域名**，并/或为你控制的域的**子域生成证书**，其中包含受害者域名的**关键词**。如果**受害者**对这些域有任何 DNS 或 HTTP 交互，你就会知道他**正在主动搜索**可疑域名，这时你需要非常隐蔽。

### Evaluate the phishing

使用 [**Phishious** ](https://github.com/Rices/Phishious) 来评估你的邮件是否会进入垃圾邮件文件夹、被阻断或成功送达。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代入侵组织越来越多地完全跳过邮件诱饵，直接针对 service-desk / identity-recovery 工作流以击败 MFA。该攻击完全属于 "living-off-the-land"：一旦操作者获得有效凭证，他们使用内置管理工具横向移动——不需要恶意软件。

### Attack flow
1. Recon the victim
* 从 LinkedIn、数据泄露、公开 GitHub 等处收集个人和公司信息。
* 确定高价值身份（高管、IT、财务），并枚举密码 / MFA 重置的**确切 help-desk 流程**。
2. Real-time social engineering
* 通过电话、Teams 或聊天联系 help-desk，冒充目标（通常使用 **spoofed caller-ID** 或 **cloned voice**）。
* 提供先前收集的 PII 以通过基于知识的验证。
* 说服代理**重置 MFA secret**或对已注册的手机号执行**SIM-swap**。
3. Immediate post-access actions (≤60 min in real cases)
* 通过任何 web SSO 门户建立立足点。
* 使用内置工具枚举 AD / AzureAD（无需投放二进制文件）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用 **WMI**、**PsExec** 或环境中已被白名单的合法 **RMM** 代理进行横向移动。

### Detection & Mitigation
* 将 help-desk 身份恢复视为一种**特权操作**——要求 step-up auth 和经理批准。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则，触发以下告警：
  * MFA 方法更改 + 来自新设备/新地理位置的身份验证。
  * 同一主体（用户→管理员）立即提升权限。
* 记录 help-desk 通话并在任何重置前强制回拨到已注册的号码。
* 实施 **Just-In-Time (JIT) / Privileged Access**，使新重置的账户**不会**自动继承高权限令牌。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
传统团队通过大规模攻击抵消高触达操作的成本，将**搜索引擎和广告网络变成投放渠道**。

1. **SEO poisoning / malvertising** 将一个假结果（例如 chromium-update[.]site）推到搜索广告顶部。
2. 受害者下载一个小型的**第一阶段 loader**（通常是 JS/HTA/ISO）。Unit 42 见过的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader 外泄浏览器 cookie + 凭证数据库，然后拉取一个**静默 loader**，该 loader 实时决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* 持久化组件（registry Run key + scheduled task）

### Hardening tips
* 阻止新注册域名并在搜索广告以及电子邮件上实施**高级 DNS / URL 过滤**。
* 将软件安装限制为签名的 MSI / Store 包，策略上禁止执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器派生子进程打开安装程序的情况：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜索第一阶段 loader 常滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

---

## AI-Enhanced Phishing Operations
攻击者现在将 **LLM & voice-clone APIs** 链接起来，实现完全个性化的诱饵和实时交互。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|生成并发送 >100k 封邮件/SMS，使用随机化措辞和跟踪链接。|
|Generative AI|生成一次性邮件，引用公开的 M&A、社交媒体中的内部玩笑；回拨诈骗中使用深度伪造的 CEO 声音。|
|Agentic AI|自动注册域名、爬取开源情报、当受害者点击但未提交凭证时自动生成后续邮件。|

**Defence:**
• 添加 **动态横幅**，突出显示来自不受信任自动化的消息（通过 ARC/DKIM 异常）。  
• 对高风险电话请求部署 **voice-biometric challenge phrases**。  
• 在安全意识培训中持续模拟 AI 生成的诱饵——静态模板已过时。

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
除了经典的 push-bombing 操作外，操作者也会在 help-desk 通话中**强制进行新的 MFA 注册**，使用户原有的令牌失效。随后出现的任何登录提示对受害者看起来都是合法的。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，当 **`deleteMFA` + `addMFA`** 在 **同一 IP** 几分钟内发生时。



## Clipboard Hijacking / Pastejacking

攻击者可以在被入侵或错拼域名（typosquatted）的网页上悄悄将恶意命令复制到受害者的剪贴板，然后诱使用户在 **Win + R**、**Win + X** 或终端窗口中粘贴，从而在无需任何下载或附件的情况下执行任意代码。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## 参考资料

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
