# Phishing 方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法论

1. 侦查目标
1. 选择 **目标域名**。
2. 进行一些基本的 web 枚举，**搜索登录门户**（login portals）以确定受害方使用的入口，并**决定**你将**冒充**哪一个。
3. 使用一些 **OSINT** 来 **发现电子邮件地址**。
2. 准备环境
1. **购买** 你将用于钓鱼评估的域名
2. **配置邮件服务** 相关记录 (SPF, DMARC, DKIM, rDNS)
3. 在 VPS 上配置 **gophish**
3. 准备活动
1. 准备 **邮件模板**
2. 准备用于窃取凭证的 **网页**
4. 启动活动！

## 生成相似域名或购买可信域名

### 域名变体技术

- **关键词**：域名**包含**原始域名的一个重要**关键词**（例如，zelster.com-management.com）。
- **连字符子域**：将子域名的**点改为连字符**（例如，www-zelster.com）。
- **New TLD**：使用**新的 TLD**的相同域名（例如，zelster.org）
- **Homoglyph**：它用**相似外观的字符**替换域名中的一个字母（例如，zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 在域名中**交换两个字母**（例如，zelsetr.com）。
- **Singularization/Pluralization**：在域名末尾添加或删除 “s”（例如，zeltsers.com）。
- **Omission**：从域名中**移除一个字母**（例如，zelser.com）。
- **Repetition:** 在域名中**重复一个字母**（例如，zeltsser.com）。
- **Replacement**：类似 homoglyph，但隐蔽性较差。它用另一个字母替换域名中的某个字母，可能是键盘上与原字母相邻的字母（例如，zektser.com）。
- **Subdomained**：在域名中加入一个**点**（例如，ze.lster.com）。
- **Insertion**：在域名中**插入一个字母**（例如，zerltser.com）。
- **Missing dot**：将 TLD 附加到域名上。（例如，zelstercom.com）

**自动化工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

存在**存储或通信中的某些位可能被自动翻转**的可能性，原因包括太阳耀斑、宇宙射线或硬件错误等。

当该概念**应用于 DNS 请求**时，可能会出现**DNS 服务器接收到的域名**与最初请求的域名不相同的情况。

例如，对域名 "windows.com" 的单个位修改可能会将其变为 "windnws.com"。

攻击者可能**利用这一点注册多个可能发生 bit-flipping 的域名**，这些域名与受害者的域名相似，目的是将合法用户重定向到他们自己的基础设施。

更多信息请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买可信域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索可用的已过期域名，以供使用。\
为了确保你要购买的过期域名**已经具有良好的 SEO**，你可以查看它在以下网站中的分类情况：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件地址

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的电子邮件地址或**验证**你已经发现的地址，你可以检查是否能够对受害者的 SMTP 服务器进行用户名暴力破解来枚举邮箱。[在此处了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，别忘了如果用户使用**任何 web 门户来访问邮件**，你可以检查该门户是否易受**用户名暴力破解**，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### 安装

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载。

将其下载并解压到 `/opt/gophish`，然后执行 `/opt/gophish/gophish`\
运行输出中会给出 admin 用户在 3333 端口的初始密码。因此，访问该端口并使用这些凭据更改管理员密码。你可能需要将该端口隧道到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该**已经购买好要使用的域名**，并且它必须**指向**你正在配置 **gophish** 的 **VPS 的 IP**。
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

然后将域名添加到以下文件：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**还要在 /etc/postfix/main.cf 中更改以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，并 **重启你的 VPS。**

现在为 `mail.<domain>` 创建一个 **DNS A record**，将其指向 VPS 的 **ip address**，并为 `mail.<domain>` 创建一个 **DNS MX** 记录

现在测试发送邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的运行，然后进行配置。\
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

为了创建 gophish 服务，以便它可以自动启动并作为服务进行管理，您可以创建文件 `/etc/init.d/gophish`，内容如下：
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
完成服务配置并通过以下操作进行检查：
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

### 等待并显得合法

域名存在的时间越长，被判为垃圾邮件的概率越低。因此在进行 phishing 评估之前，应尽可能等待（至少 1 周）。此外，如果你在域名上放置与某个有信誉的行业相关的页面，域名获得的信誉会更好。

注意：即便需要等待一周，你也可以现在完成所有配置。

### 配置反向 DNS (rDNS) 记录

设置 rDNS (PTR) 记录，将 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) 记录

你必须 **为新域配置 SPF 记录**。如果你不知道什么是 SPF 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成 SPF 策略（使用 VPS 机器的 IP）

![](<../../images/image (1037).png>)

以下内容必须作为域名的 TXT 记录设置：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告与一致性 (DMARC) 记录

你必须 **为新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，主机名为 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### 域名密钥识别邮件 (DKIM)

您必须 **为新域名配置 DKIM**。如果您不知道 DMARC 记录是什么，[**阅读此页**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 您需要将 DKIM 密钥生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试您的邮件配置得分

您可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com/) 来完成。\
只需访问该页面并将邮件发送到他们提供的地址：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过发送邮件到 `check-auth@verifier.port25.com` 来**检查你的邮件配置**并**读取响应** (为此你需要**打开**端口 **25** 并在以 root 身份发送邮件时查看文件 _/var/mail/root_ 中的响应)。\
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
你也可以**向你控制的 Gmail 发送消息**，并在你的 Gmail 收件箱中检查 **email’s headers**，`dkim=pass` 应该出现在 `Authentication-Results` 报头字段中。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

该页面 [www.mail-tester.com](https://www.mail-tester.com) 可以提示你域名是否被 spamhouse 屏蔽。你可以在此请求移除你的域名/IP：​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## Create & Launch GoPhish Campaign

### Sending Profile

- 设置一个用于识别发件人配置的**名称**
- 决定你将从哪个账户发送钓鱼邮件。建议：_noreply, support, servicedesk, salesforce..._
- 用户名和密码可以留空，但请确保勾选 Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常。\
> 我建议 **将测试邮件发送到 10min mails 地址**，以避免在测试时被列入黑名单。

### Email Template

- 设置一个用于识别模板的**名称**
- 然后写一个 **subject**（不要奇怪，只写你在普通邮件中会期望看到的内容）
- 确保已勾选 "**Add Tracking Image**"
- 编写 **email template**（你可以像下面的示例中那样使用变量）：
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
注意，**为了提高邮件的可信度**，建议使用来自客户邮件的一些签名。建议：

- 向一个 **non existent address** 发送邮件，并检查回复中是否包含签名。
- 搜索 **public emails**，例如 info@ex.com、press@ex.com 或 public@ex.com，向其发送邮件并等待回复。
- 尝试联系一些已发现的 **valid** 邮箱并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. 如果你还想通过一些特制的文件/文档窃取 NTLM challenges，[read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 填写一个 **name**
- **Write the HTML code** of the web page。注意你可以**import**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个 **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改页面的 HTML 代码并在本地进行一些测试（可能使用 Apache 服务器），**直到你满意结果为止。** 然后将该 HTML 代码写入框中。\
> 注意，如果你需要为 HTML **use some static resources**（比如某些 CSS 和 JS 文件），可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后从 _**/static/\<filename>**_ 访问。

> [!TIP]
> 对于重定向，你可以**redirect the users to the legit main web page**（将用户重定向到受害者的真实主站），或者例如重定向到 _/static/migration.html_，显示一个**spinning wheel （[https://loading.io/](https://loading.io)）持续 5 秒，然后提示操作成功**。

### Users & Groups

- 设置一个 name
- **Import the data**（注意，为了在示例中使用模板，你需要每个用户的 firstname、last name 和 email address）

![](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。注意 URL 将是发送给受害者的链接。

注意 **Sending Profile allow to send a test email to see how will the final phishing email looks like**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议将测试邮件发送到 10min mails 地址，以避免在测试中被列入黑名单。

一切准备就绪后，启动 campaign！

## Website Cloning

如果你出于任何原因想要克隆网站，请查看以下页面：

{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

在一些 phishing 评估中（主要是 Red Teams），你可能还想**发送包含某种后门的文件**（可能是 C2，也可能只是触发认证的文件）。\
查看以下页面了解一些示例：

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

之前的攻击相当巧妙，因为你在伪造真实网站并收集用户填写的信息。不幸的是，如果用户没有输入正确的密码，或者你伪造的应用配置了 2FA，**这些信息不会让你能够冒充被欺骗的用户**。

这时像 [**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具就很有用。该类工具允许你生成类似 MitM 的攻击。基本上，攻击流程如下：

1. 你 **impersonate the login** 表单，模拟真实网页的登录表单。
2. 用户将其 **credentials** 发送到你的假页面，工具再将这些凭证转发到真实网页，**checking if the credentials work**。
3. 如果账户配置了 **2FA**，MitM 页面会请求它，一旦用户 **introduces**，工具会将其发送到真实网页。
4. 一旦用户完成认证，你（作为攻击者）将**capt获凭证、2FA、cookie 以及在工具进行 MitM 期间的所有交互信息**。

### Via VNC

如果不把受害者**发送到一个外观与原始相同的恶意页面**，而是将他带到一个**通过 VNC 会话打开、连接到真实网页的浏览器**，会怎样？你将能够看到他在做什么，窃取密码、所用的 MFA、cookies 等。\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现这一点。

## Detecting the detection

显然，判断你是否被发现的最佳方法之一是**在黑名单中搜索你的域名**。如果它出现在列表中，说明你的域名被识别为可疑。\
检查你的域名是否出现在任何黑名单的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)

不过，还有其他方法可以得知受害者是否在**actively looking for suspicions phishing activity in the wild**，详见：

{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买与受害者域名非常相似的域名**，和/或为你控制的某个域名的 **subdomain** 生成证书，该子域名中包含受害者域名的 **keyword**。如果**victim** 对这些域名有任何 **DNS 或 HTTP 交互**，你就会知道他在**actively looking** 可疑域名，此时你需要非常隐蔽。

### Evaluate the phishing

使用 [**Phishious**](https://github.com/Rices/Phishious) 来评估你的邮件是否会进入垃圾邮箱、被拦截或成功。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代入侵集团越来越多地完全跳过电子邮件诱饵，**直接针对服务台 / identity-recovery 工作流程**以绕过 MFA。该攻击完全是“以现有工具为生”：一旦操作者拥有有效凭证，他们就使用内置的管理工具进行横向移动——无需恶意软件。

### Attack flow
1. Recon the victim
* 从 LinkedIn、数据泄露、公开 GitHub 等处收集个人与公司信息。
* 识别高价值身份（高管、IT、财务）并枚举用于密码 / MFA 重置的 **exact help-desk process**。
2. Real-time social engineering
* 在冒充目标的情况下通过电话、Teams 或聊天联系服务台（通常使用 **spoofed caller-ID** 或 **cloned voice**）。
* 提供先前收集的 PII 以通过基于知识的验证。
* 说服客服 **reset the MFA secret** 或对已注册手机号执行 **SIM-swap**。
3. Immediate post-access actions (≤60 min in real cases)
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
* 通过 **WMI**, **PsExec**, 或环境中已加入白名单的合法 **RMM** 代理进行横向移动。

### Detection & Mitigation
* 将 help-desk 身份恢复视为 **privileged operation** —— 要求提升认证与经理批准。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则以对以下情况发出告警：
  * MFA 方法更改 + 来自新设备 / 新地理位置的认证。
  * 同一主体的即时提权（user-→-admin）。
* 记录服务台通话，并在任何重置前强制 **call-back to an already-registered number**。
* 实施 **Just-In-Time (JIT) / Privileged Access**，以确保新重置的账户不会自动继承高权限令牌。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
常见团伙通过大规模攻击抵消高接触行动的成本，将 **search engines & ad networks** 变成投放渠道。

1. **SEO poisoning / malvertising** 将假结果（例如 `chromium-update[.]site`）推到搜索广告顶部。
2. 受害者下载一个小型 **first-stage loader**（通常为 JS/HTA/ISO）。Unit 42 见过的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 加载器窃取浏览器 cookies + 凭证数据库，然后拉取一个 **silent loader**，该加载器实时决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* 持久化组件（注册表 Run 键 + 计划任务）

### Hardening tips
* 阻断新注册的域名，并在 *search-ads* 及电子邮件上强制执行 **Advanced DNS / URL Filtering**。
* 将软件安装限制为已签名的 MSI / Store 包，通过策略禁止执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器的子进程是否打开安装程序：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜寻首阶段加载器常滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

---

## AI-Enhanced Phishing Operations
攻击者现在将 **LLM & voice-clone APIs** 链接起来，用于完全个性化的诱饵和实时交互。

| 层级 | 威胁行为者的示例用途 |
|-------|-----------------------------|
| Automation | 生成并发送 >100k 邮件 / SMS，使用随机化措辞与跟踪链接。|
| Generative AI | 生成一次性的邮件，引用公开的并购消息、社交媒体上的内部笑话；回拨诈骗中使用深度伪造的 CEO 语音。|
| Agentic AI | 自动注册域名、抓取开源情报、当受害者点击但未提交凭证时自动编写下一阶段邮件。|

**防御：**
• 添加 **dynamic banners**，在消息来自不受信任的自动化（通过 ARC/DKIM 异常）时突出显示。  
• 对高风险电话请求部署 **voice-biometric challenge phrases**。  
• 在意识培训中持续模拟 AI 生成的诱饵——静态模板已过时。

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
除了经典的 push-bombing，操作者还可以在服务台通话期间直接**强制注册新的 MFA**，使用户现有的令牌失效。随后任何登录提示对受害者看起来都是合法的。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或 typosquatted 的网页，悄无声息地将恶意命令复制到受害者的剪贴板，然后诱导用户在 **Win + R**、**Win + X** 或终端窗口中粘贴这些命令，从而在无需任何下载或附件的情况下执行任意代码。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
运营者越来越多地在简单的设备检查后面对其 phishing 流程进行门控，以便桌面 crawlers 永远无法到达最终页面。常见模式是一个小脚本检测是否存在 touch-capable DOM 并将结果 post 到服务器端点；非移动客户端会收到 HTTP 500（或空白页面），而移动用户则会被呈现完整流程。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js logic (simplified):`
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
常见的服务器行为：
- 在首次加载时设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时对后续 GET 返回 500（或占位符）；仅当为 `true` 时提供 phishing。

侦测与检测启发式：
- urlscan 查询： `filename:"detect_device.js" AND page.status:500`
- Web 监测：请求序列 `GET /static/detect_device.js` → `POST /detect` → 对非移动端返回 HTTP 500；真实的移动端受害者路径返回 200 并随后提供 HTML/JS。
- 阻止或仔细审查那些仅基于 `ontouchstart` 或类似设备检测来决定内容的页面。

防御建议：
- 使用具有类似移动端指纹且启用 JS 的爬虫来揭露被限制的内容。
- 对新注册域名上在 `POST /detect` 之后出现的可疑 500 响应发出警报。

## 参考资料

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
