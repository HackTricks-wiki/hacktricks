# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 侦查受害者
1. 选择 **受害者域名**。
2. 执行一些基本的网络枚举 **寻找受害者使用的登录门户** 并 **决定** 你将 **冒充** 哪一个。
3. 使用一些 **OSINT** 来 **查找电子邮件**。
2. 准备环境
1. **购买你将用于钓鱼评估的域名**
2. **配置电子邮件服务** 相关记录 (SPF, DMARC, DKIM, rDNS)
3. 使用 **gophish** 配置 VPS
3. 准备活动
1. 准备 **电子邮件模板**
2. 准备 **网页** 以窃取凭据
4. 启动活动！

## 生成类似域名或购买受信任的域名

### 域名变体技术

- **关键词**: 域名 **包含** 原始域名的重要 **关键词** (例如，zelster.com-management.com)。
- **带连字符的子域**: 将子域中的 **点替换为连字符** (例如，www-zelster.com)。
- **新 TLD**: 使用 **新 TLD** 的相同域名 (例如，zelster.org)
- **同形异义词**: 它 **用看起来相似的字母替换** 域名中的一个字母 (例如，zelfser.com)。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **置换**: 它 **交换域名中的两个字母** (例如，zelsetr.com)。
- **单数/复数化**: 在域名末尾添加或删除 “s” (例如，zeltsers.com)。
- **省略**: 它 **删除域名中的一个字母** (例如，zelser.com)。
- **重复**: 它 **重复域名中的一个字母** (例如，zeltsser.com)。
- **替换**: 类似于同形异义词，但不那么隐蔽。它用键盘上与原字母相近的字母替换域名中的一个字母 (例如，zektser.com)。
- **子域化**: 在域名中引入一个 **点** (例如，ze.lster.com)。
- **插入**: 它 **在域名中插入一个字母** (例如，zerltser.com)。
- **缺失点**: 将 TLD 附加到域名上。 (例如，zelstercom.com)

**自动工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### 位翻转

存在 **某些存储或通信中的位可能会因各种因素而自动翻转的可能性**，例如太阳耀斑、宇宙射线或硬件错误。

当这个概念 **应用于 DNS 请求** 时，**DNS 服务器接收到的域名** 可能与最初请求的域名不同。

例如，域名 "windows.com" 中的单个位修改可以将其更改为 "windnws.com"。

攻击者可能 **利用这一点注册多个位翻转域名**，这些域名与受害者的域名相似。他们的目的是将合法用户重定向到他们自己的基础设施。

有关更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买受信任的域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索可以使用的过期域名。\
为了确保你要购买的过期域名 **已经有良好的 SEO**，你可以搜索它在以下网站的分类：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现电子邮件

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 免费)
- [https://phonebook.cz/](https://phonebook.cz) (100% 免费)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了 **发现更多** 有效的电子邮件地址或 **验证你已经发现的地址**，你可以检查是否可以对受害者的 smtp 服务器进行暴力破解。 [在这里学习如何验证/发现电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，不要忘记，如果用户使用 **任何网络门户访问他们的邮件**，你可以检查它是否容易受到 **用户名暴力破解**，并在可能的情况下利用该漏洞。

## 配置 GoPhish

### 安装

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载。

下载并解压到 `/opt/gophish` 中，并执行 `/opt/gophish/gophish`\
你将在输出中获得端口 3333 的管理员用户密码。因此，访问该端口并使用这些凭据更改管理员密码。你可能需要将该端口隧道到本地：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在这一步之前，您应该已经**购买了您将要使用的域名**，并且它必须**指向**您配置**gophish**的**VPS 的 IP**。
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

开始安装: `apt-get install postfix`

然后将域名添加到以下文件中:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**还要更改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为您的域名并 **重启您的 VPS。**

现在，创建一个指向 VPS **ip 地址** 的 **DNS A 记录** `mail.<domain>` 和一个指向 `mail.<domain>` 的 **DNS MX 记录**

现在让我们测试发送电子邮件:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行并进行配置。\
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

为了创建 gophish 服务，使其能够自动启动并作为服务进行管理，您可以创建文件 `/etc/init.d/gophish`，并添加以下内容：
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
完成配置服务并检查它，方法是：
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

### 等待并保持合法

域名越老，被识别为垃圾邮件的可能性就越小。因此，在进行钓鱼评估之前，您应该尽可能等待更长的时间（至少1周）。此外，如果您放置一个关于声誉行业的页面，获得的声誉将会更好。

请注意，即使您需要等待一周，您现在也可以完成所有配置。

### 配置反向DNS (rDNS) 记录

设置一个将VPS的IP地址解析到域名的rDNS (PTR) 记录。

### 发件人策略框架 (SPF) 记录

您必须**为新域配置SPF记录**。如果您不知道什么是SPF记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

您可以使用[https://www.spfwizard.net/](https://www.spfwizard.net)来生成您的SPF策略（使用VPS机器的IP）。

![](<../../images/image (1037).png>)

这是必须在域名的TXT记录中设置的内容：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告和一致性 (DMARC) 记录

您必须**为新域配置 DMARC 记录**。如果您不知道什么是 DMARC 记录 [**请阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

您需要创建一个新的 DNS TXT 记录，指向主机名 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

您必须**为新域配置DKIM**。如果您不知道什么是DMARC记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 您需要连接DKIM密钥生成的两个B64值：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试您的电子邮件配置得分

您可以使用[https://www.mail-tester.com/](https://www.mail-tester.com)\
只需访问该页面并将电子邮件发送到他们提供的地址：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
您还可以通过发送电子邮件到 `check-auth@verifier.port25.com` 来**检查您的电子邮件配置**，并**阅读响应**（为此，您需要**打开**端口**25**，并在文件 _/var/mail/root_ 中查看响应，如果您以 root 身份发送电子邮件）。\
检查您是否通过了所有测试：
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
您还可以向**您控制的Gmail发送消息**，并在您的Gmail收件箱中检查**电子邮件的头部**，`dkim=pass`应出现在`Authentication-Results`头字段中。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​从Spamhouse黑名单中移除

页面 [www.mail-tester.com](https://www.mail-tester.com) 可以指示您的域名是否被spamhouse阻止。您可以在: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) 请求移除您的域名/IP。

### 从Microsoft黑名单中移除

您可以在 [https://sender.office.com/](https://sender.office.com) 请求移除您的域名/IP。

## 创建并启动GoPhish活动

### 发送配置

- 设置一些 **名称以识别** 发送者配置
- 决定您将从哪个账户发送钓鱼邮件。建议：_noreply, support, servicedesk, salesforce..._
- 您可以将用户名和密码留空，但请确保勾选忽略证书错误

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**发送测试邮件**" 功能来测试一切是否正常。\
> 我建议将 **测试邮件发送到10分钟邮件地址** 以避免在测试中被列入黑名单。

### 邮件模板

- 设置一些 **名称以识别** 模板
- 然后写一个 **主题**（没有奇怪的内容，只是您在常规邮件中可以期待看到的内容）
- 确保您已勾选 "**添加跟踪图像**"
- 编写 **邮件模板**（您可以使用变量，如以下示例所示）：
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
注意，**为了提高电子邮件的可信度**，建议使用客户电子邮件中的某些签名。建议：

- 向一个**不存在的地址**发送电子邮件，并检查回复是否有任何签名。
- 搜索**公共电子邮件**，如 info@ex.com 或 press@ex.com 或 public@ex.com，向它们发送电子邮件并等待回复。
- 尝试联系**一些有效发现的**电子邮件并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> 电子邮件模板还允许**附加要发送的文件**。如果您还想使用一些特别制作的文件/文档窃取 NTLM 挑战，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### 登陆页面

- 写一个**名称**
- **编写网页的 HTML 代码**。请注意，您可以**导入**网页。
- 标记**捕获提交的数据**和**捕获密码**
- 设置**重定向**

![](<../../images/image (826).png>)

> [!TIP]
> 通常，您需要修改页面的 HTML 代码并在本地进行一些测试（可能使用某些 Apache 服务器）**直到您满意结果。** 然后，将该 HTML 代码写入框中。\
> 请注意，如果您需要**使用某些静态资源**用于 HTML（可能是一些 CSS 和 JS 页面），您可以将它们保存在 _**/opt/gophish/static/endpoint**_ 中，然后从 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，您可以**将用户重定向到受害者的合法主网页**，或者例如将他们重定向到 _/static/migration.html_，放置一些**旋转轮**（**[https://loading.io/](https://loading.io)**）5 秒钟，然后指示该过程成功。

### 用户与组

- 设置一个名称
- **导入数据**（请注意，为了使用示例模板，您需要每个用户的名字、姓氏和电子邮件地址）

![](<../../images/image (163).png>)

### 活动

最后，创建一个活动，选择一个名称、电子邮件模板、登陆页面、URL、发送配置文件和组。请注意，URL 将是发送给受害者的链接。

请注意，**发送配置文件允许发送测试电子邮件以查看最终钓鱼电子邮件的外观**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议**将测试电子邮件发送到 10 分钟邮件地址**以避免在测试中被列入黑名单。

一切准备就绪后，只需启动活动！

## 网站克隆

如果出于任何原因您想克隆网站，请查看以下页面：

{{#ref}}
clone-a-website.md
{{#endref}}

## 后门文档和文件

在某些钓鱼评估中（主要针对红队），您还可能想要**发送包含某种后门的文件**（可能是 C2，或者只是一些会触发身份验证的东西）。\
查看以下页面以获取一些示例：

{{#ref}}
phishing-documents.md
{{#endref}}

## 钓鱼 MFA

### 通过代理 MitM

之前的攻击非常聪明，因为您伪造了一个真实的网站并收集了用户输入的信息。不幸的是，如果用户没有输入正确的密码，或者您伪造的应用程序配置了 2FA，**这些信息将无法让您冒充被欺骗的用户**。

这就是像 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、** [**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这样的工具有用的地方。该工具将允许您生成类似 MitM 的攻击。基本上，攻击的工作方式如下：

1. 您**冒充真实网页的登录**表单。
2. 用户**发送**他的**凭据**到您的伪造页面，工具将这些发送到真实网页，**检查凭据是否有效**。
3. 如果账户配置了**2FA**，MitM 页面将要求输入，一旦**用户输入**，工具将其发送到真实网页。
4. 一旦用户通过身份验证，您（作为攻击者）将**捕获凭据、2FA、cookie 和任何信息**，在工具执行 MitM 时的每次交互中。

### 通过 VNC

如果您不是**将受害者发送到一个与原始页面外观相同的恶意页面**，而是将他发送到一个**与真实网页连接的 VNC 会话**呢？您将能够看到他所做的事情，窃取密码、使用的 MFA、cookie...\
您可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来做到这一点。

## 检测检测

显然，知道您是否被发现的最佳方法之一是**在黑名单中搜索您的域**。如果它被列出，您的域以某种方式被检测为可疑。\
检查您的域是否出现在任何黑名单中的一种简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)。

然而，还有其他方法可以知道受害者是否**积极寻找可疑的钓鱼活动**，如以下所述：

{{#ref}}
detecting-phising.md
{{#endref}}

您可以**购买一个与受害者域名非常相似的域名**，**和/或为您控制的域的**子域**生成证书**，**包含**受害者域的**关键字**。如果**受害者**与它们进行任何类型的**DNS 或 HTTP 交互**，您将知道**他在积极寻找**可疑域，您需要非常隐蔽。

### 评估钓鱼

使用 [**Phishious**](https://github.com/Rices/Phishious) 评估您的电子邮件是否会进入垃圾邮件文件夹，或者是否会被阻止或成功。

## 高接触身份妥协（帮助台 MFA 重置）

现代入侵集越来越多地完全跳过电子邮件诱饵，**直接针对服务台/身份恢复工作流程**以击败 MFA。攻击完全是“依靠现成的资源”：一旦操作员拥有有效凭据，他们就会利用内置的管理工具进行转移——不需要恶意软件。

### 攻击流程
1. 侦察受害者
* 从 LinkedIn、数据泄露、公共 GitHub 等收集个人和公司详细信息。
* 确定高价值身份（高管、IT、财务）并列举**确切的帮助台流程**以进行密码/MFA 重置。
2. 实时社会工程
* 在冒充目标的情况下拨打电话、使用 Teams 或聊天帮助台（通常使用**伪造的来电 ID**或**克隆的声音**）。
* 提供先前收集的 PII 以通过知识验证。
* 说服代理**重置 MFA 密钥**或对注册的手机号码执行**SIM 交换**。
3. 立即后访问操作（≤60 分钟的真实案例）
* 通过任何 Web SSO 门户建立立足点。
* 使用内置工具枚举 AD/AzureAD（不需要放置二进制文件）：
```powershell
# 列出目录组和特权角色
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – 列出目录角色
Get-MgDirectoryRole | ft DisplayName,Id

# 枚举账户可以登录的设备
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用**WMI**、**PsExec**或在环境中已列入白名单的合法**RMM**代理进行横向移动。

### 检测与缓解
* 将帮助台身份恢复视为**特权操作**——要求提升身份验证和经理批准。
* 部署**身份威胁检测与响应（ITDR）**/**UEBA**规则，警报：
* MFA 方法更改 + 来自新设备/地理位置的身份验证。
* 同一主体的立即提升（用户-→-管理员）。
* 记录帮助台通话，并在任何重置之前强制**回拨到已注册的号码**。
* 实施**及时（JIT）/特权访问**，以便新重置的账户**不**自动继承高特权令牌。

---

## 大规模欺骗 – SEO 中毒与“ClickFix”活动
商品团队通过大规模攻击来抵消高接触操作的成本，将**搜索引擎和广告网络转变为交付渠道**。

1. **SEO 中毒/恶意广告**将假结果如 `chromium-update[.]site` 推送到顶部搜索广告。
2. 受害者下载一个小的**第一阶段加载器**（通常是 JS/HTA/ISO）。Unit 42 看到的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 加载器提取浏览器 cookie + 凭据数据库，然后拉取一个**静默加载器**，实时决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* 勒索软件/清除器
* 持久性组件（注册表运行键 + 计划任务）

### 加固提示
* 阻止新注册的域名，并在*搜索广告*和电子邮件上强制实施**高级 DNS/URL 过滤**。
* 限制软件安装为签名的 MSI/商店包，通过策略拒绝执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器打开安装程序的子进程：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 搜索经常被第一阶段加载器滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

---

## AI 增强的钓鱼操作
攻击者现在将**LLM 和语音克隆 API**串联起来，以实现完全个性化的诱饵和实时互动。

| 层 | 威胁行为者的示例使用 |
|-------|-----------------------------|
|自动化|生成并发送 >100 k 电子邮件/SMS，带有随机措辞和跟踪链接。|
|生成 AI|制作*一次性*电子邮件，引用公共 M&A、社交媒体中的内部笑话；在回拨诈骗中使用深度伪造的 CEO 声音。|
|代理 AI|自主注册域名，抓取开源情报，当受害者点击但未提交凭据时制作下一阶段邮件。|

**防御：**
• 添加**动态横幅**，突出显示来自不受信任的自动化发送的消息（通过 ARC/DKIM 异常）。
• 部署**语音生物识别挑战短语**以应对高风险电话请求。
• 在意识程序中持续模拟 AI 生成的诱饵——静态模板已过时。

---

## MFA 疲劳/推送轰炸变体 – 强制重置
除了经典的推送轰炸，操作员只需在帮助台通话期间**强制新的 MFA 注册**，使用户现有的令牌失效。任何后续的登录提示对受害者来说看起来都是合法的。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，其中 **`deleteMFA` + `addMFA`** 在 **同一 IP 的几分钟内** 发生。

## 剪贴板劫持 / 粘贴劫持

攻击者可以从被攻陷或拼写错误的网页中静默地将恶意命令复制到受害者的剪贴板中，然后诱使用户在 **Win + R**、**Win + X** 或终端窗口中粘贴这些命令，从而在不下载或附加任何内容的情况下执行任意代码。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## 移动钓鱼与恶意应用分发（Android 和 iOS）

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## 参考文献

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
