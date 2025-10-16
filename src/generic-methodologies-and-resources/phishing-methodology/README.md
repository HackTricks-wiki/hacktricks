# Phishing 方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法

1. 侦察目标
1. 选择 **victim domain**。
2. 进行一些基础的 web 枚举，**搜索登录门户**，并**决定**你要**模拟**哪个门户。
3. 使用一些 **OSINT** 来**查找邮件地址**。
2. 准备环境
1. **购买你将用于钓鱼评估的域名**
2. **配置 email 服务相关记录**（SPF, DMARC, DKIM, rDNS）
3. 在 VPS 上配置 **gophish**
3. 准备活动
1. 准备 **email template**
2. 准备用于窃取凭证的 **web page**
4. 发起活动！

## 生成相似域名或购买一个可信域名

### 域名变体技术

- **Keyword**：域名包含原域名的重要**关键词**（例如，zelster.com-management.com）。
- **hypened subdomain**：将子域名的**点替换为连字符**（例如，www-zelster.com）。
- **New TLD**：使用**新的 TLD** 同样的域名（例如，zelster.org）。
- **Homoglyph**：用**外观相似的字符**替换域名中的字母（例如，zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** 在域名中**交换两个字母**（例如，zelsetr.com）。
- **Singularization/Pluralization**：在域名末尾添加或删除 “s”（例如，zeltsers.com）。
- **Omission**：从域名中**删除一个字母**（例如，zelser.com）。
- **Repetition:** 在域名中**重复一个字母**（例如，zeltsser.com）。
- **Replacement**：类似 homoglyph，但不那么隐蔽。用其他字母替换域名中的一个字母，可能是键盘上邻近的字母（例如，zektser.com）。
- **Subdomained**：在域名中引入一个**点**（例如，ze.lster.com）。
- **Insertion**：在域名中**插入一个字母**（例如，zerltser.com）。
- **Missing dot**：将 TLD 追加到域名后面。（例如，zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

存在这样一种**可能性**：存储或通信中的某些 bit 可能会由于太阳耀斑、宇宙射线或硬件错误等各种因素而**自动翻转**。

当这一概念**应用于 DNS 请求**时，可能出现**DNS 服务器接收到的域名**与最初请求的域名不一致的情况。

例如，对域名 "windows.com" 的一个比特修改可能会将其变为 "windnws.com"。

攻击者可能会**利用这一点注册多个 bit-flipping 域名**，这些域名与受害者的域名相似，目的是将合法用户重定向到他们自己的基础设施。

欲了解更多信息，请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 购买可信域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 上搜索可用的过期域名并考虑购买。\
为了确保你要购买的过期域名**已有良好的 SEO**，你可以查看它在以下网站中的分类情况：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 发现邮箱地址

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多有效的邮箱地址**或**验证已发现的地址**，你可以尝试对受害者的 smtp 服务器进行暴力猜测。 [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
此外，不要忘记，如果用户使用**任何 web 门户访问邮件**，你可以检查该门户是否存在**用户名暴力破解**漏洞，若可利用则进行利用。

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
你将在输出中看到 admin 用户在端口 3333 的一个密码。因此，访问该端口并使用这些凭据更改 admin 密码。你可能需要将该端口做本地隧道：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 配置

**TLS 证书配置**

在此步骤之前，你应该**已经购买了将要使用的域名**，并且该域名必须**指向****VPS 的 IP**，该 VPS 是你用来配置**gophish**的。
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

**同时在 /etc/postfix/main.cf 中更改以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名并 **重启你的 VPS。**

现在为 `mail.<domain>` 创建一个 **DNS A record**，指向 VPS 的 **ip address**，并为 `mail.<domain>` 创建一个 **DNS MX** 记录。

现在来测试发送邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的执行并进行配置。\
修改 `/opt/gophish/config.json` 为以下内容（注意使用 https）：
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

域名越旧，被判为垃圾邮件的概率越低。因此在进行 phishing 评估前应尽可能等待（至少1week）。此外，如果你放一个关于信誉良好行业的页面，获得的信誉会更好。

注意，即使你必须等待一周，你也可以现在完成所有配置。

### 配置反向 DNS (rDNS) 记录

设置一个 rDNS (PTR) 记录，将 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) 记录

你必须 **configure a SPF record for the new domain**。如果你不知道什么是 SPF 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF 策略（使用 VPS 机器的 IP）

![](<../../images/image (1037).png>)

以下内容应以 TXT 记录的形式设置在域名中：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的邮件身份验证、报告与一致性 (DMARC) 记录

你必须 **为新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，主机名为 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须 **为新域名配置 DKIM**。如果你不知道什么是 DMARC 记录，[**阅读此页**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要将 DKIM 密钥生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的邮件配置得分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com/)\ 只需访问该页面并向他们提供的地址发送一封电子邮件：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以 **检查你的邮件配置**：向 `check-auth@verifier.port25.com` 发送电子邮件并 **读取响应**（为此你需要 **打开** 端口 **25**，如果以 root 身份发送邮件，请在文件 _/var/mail/root_ 中查看响应）。\
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
你也可以发送 **到你控制的 Gmail 的消息**，并在你的 Gmail 收件箱中检查该邮件的 **邮件头**，在 `Authentication-Results` 头字段中应出现 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### 从 Spamhouse 黑名单中移除

页面 [www.mail-tester.com](https://www.mail-tester.com) 可以告诉你你的域名是否被 Spamhouse 阻止。你可以在以下地址请求移除你的域名/IP：​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从 Microsoft 黑名单中移除

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## 创建并启动 GoPhish 活动

### Sending Profile

- 为发送者配置文件设置一个 **识别用的名称**
- 决定你将从哪个账号发送 phishing emails。建议：_noreply, support, servicedesk, salesforce..._
- 可以将 username 和 password 留空，但务必勾选 Ignore Certificate Errors

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常。\
> 我建议将测试邮件 **send the test emails to 10min mails addresses**，以避免在测试时被列入黑名单。

### Email Template

- 为模板设置一个 **识别用的名称**
- 然后写一个 **subject**（不要太怪异，就写一些你在普通邮件中可能看到的内容）
- 确保已勾选 "**Add Tracking Image**"
- 编写 **email template**（你可以使用变量，例如下面的示例）：
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
请注意，**为了提高邮件的可信度**，建议使用来自目标客户邮件中的某些签名。建议：

- 发送邮件到一个**不存在的地址**，查看回复中是否包含签名。
- 搜索一些**公开的邮箱**，如 info@ex.com、press@ex.com 或 public@ex.com，向其发送邮件并等待回复。
- 尝试联系一些**已发现且有效的**邮箱并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> 电子邮件模板还允许**附加要发送的文件**。如果你还想通过一些特制的文件/文档窃取 NTLM 挑战，[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### 着陆页

- 填写一个**名称**
- **编写网页的 HTML 代码**。注意你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个**重定向**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改页面的 HTML 代码并在本地进行一些测试（可能使用 Apache 服务器）**直到你满意为止。**然后，将该 HTML 代码写入文本框。\
> 注意如果你需要为 HTML 使用一些**静态资源**（例如某些 CSS 和 JS 页面），你可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后通过 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，你可以**将用户重定向到受害者的合法主网页**，或者将他们重定向到 _/static/migration.html_，例如显示一个**旋转加载动画（**[**https://loading.io/**](https://loading.io)**）5 秒**，然后提示过程已成功完成。

### 用户与群组

- 设置名称
- **导入数据**（注意：要使用示例模板，你需要每个用户的名、姓和电子邮件地址）

![](<../../images/image (163).png>)

### 活动（Campaign）

最后，创建一个 campaign，选择名称、email template、着陆页、URL、发送配置（sending profile）和组。注意 URL 将是发送给受害者的链接。

注意 **Sending Profile 允许发送测试邮件以查看最终钓鱼邮件的外观**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议将测试邮件发送到 10min mails 地址，以避免在测试时被列入黑名单。

准备就绪后，直接启动活动！

## 网站克隆

如果你因为某些原因想要克隆网站，请查看以下页面：

{{#ref}}
clone-a-website.md
{{#endref}}

## 带后门的文档与文件

在一些钓鱼评估（主要是 Red Teams）中，你可能还希望**发送包含某种后门的文件**（可能是 C2，也可能只是触发一次认证）。\
有关示例，请参阅以下页面：

{{#ref}}
phishing-documents.md
{{#endref}}

## 钓鱼与 MFA

### 通过代理 MitM

前述攻击相当聪明，因为你在伪造一个真实网站并收集用户填写的信息。不幸的是，如果用户没有输入正确的密码，或你伪造的应用启用了 2FA，**这些信息将无法让你冒充被欺骗的用户**。

这就是像 [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这类工具有用的地方。此类工具允许你生成一种 MitM 攻击。基本上，攻击的工作方式如下：

1. 你**伪装成真实网页的登录**表单。
2. 用户将其**凭证**发送到你的伪造页面，工具再将这些凭证发送到真实网页，**检查凭证是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会请求 2FA，一旦**用户输入**，工具会将其转发到真实网页。
4. 一旦用户通过认证，你（作为攻击者）将**捕获凭证、2FA、cookie 以及在工具执行 MitM 期间的任何交互信息**。

### 通过 VNC

如果不是**将受害者发送到一个伪造页面**，而是将其发送到一个**通过浏览器连接到真实网页的 VNC 会话**，会怎样？你将能够看到他所做的操作，窃取密码、使用的 MFA、cookie……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现这一点。

## 检测被检测（Detecting the detection）

显然，判断自己是否被发现的最好方法之一是**在黑名单中搜索你的域名**。如果它被列出，说明你的域名在某种程度上被检测为可疑。\
检查域名是否出现在任何黑名单的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)

然而，还有其他方法可以判断受害者是否**在积极地寻找野外的可疑钓鱼活动**，如下面说明：

{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个与受害者域名非常相似的域名**，**和/或为你控制的某个域的子域生成证书**，该子域名中包含受害者域名的**关键字**。如果**受害者**对这些域名进行任何形式的 **DNS 或 HTTP 交互**，你就会知道他**正在积极搜索**可疑域名，此时需要非常隐蔽。

### 评估钓鱼效果

使用 [**Phishious**](https://github.com/Rices/Phishious) 来评估你的邮件是否会进入垃圾邮件文件夹、是否会被拦截或是否会成功。

## 高触达身份劫持（Help-Desk MFA Reset）

现代入侵组织越来越多地完全跳过邮件诱饵，转而直接针对服务台 / 身份恢复工作流，以绕过 MFA。该攻击完全依赖“living-off-the-land”：一旦操作员获得有效凭证，他们就使用内置的管理员工具进行横向转移——无需恶意软件。

### 攻击流程
1. 侦察目标
   - 从 LinkedIn、数据泄露、公开的 GitHub 等处收集个人和公司细节。
   - 识别高价值身份（高管、IT、财务）并枚举用于密码 / MFA 重置的**确切 help-desk 流程**。
2. 实时社交工程
   - 通过电话、Teams 或聊天联系 help-desk，冒充目标（常使用**来电显示伪造**或**语音克隆**）。
   - 提供先前收集的 PII 来通过基于知识的验证。
   - 说服代理**重置 MFA 秘密**或对已注册的手机号执行 **SIM-swap**。
3. 立即的访问后操作（实际案例通常 ≤ 60 分钟）
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
   - 使用 **WMI**、**PsExec** 或环境中已被列入白名单的合法 **RMM** 代理进行横向移动。

### 检测与缓解
   - 将 help-desk 身份恢复视为一种**特权操作**——要求 step-up 认证与经理批准。
   - 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则以警报以下情况：
     - MFA 方法更改 + 来自新设备 / 新地理位置的认证。
     - 同一主体（用户→管理员）的即时权限提升。
   - 记录 help-desk 呼叫，并在任何重置前强制回拨到已注册的号码。
   - 实施 **Just-In-Time (JIT) / Privileged Access**，使新重置的账户**不会**自动继承高权限令牌。

---

## 大规模欺骗 – SEO Poisoning 与 “ClickFix” 活动
大规模团队通过将搜索引擎和广告网络变成分发渠道来抵消高触达操作的成本。

1. **SEO poisoning / malvertising** 将一个伪造结果（如 chromium-update[.]site）推到搜索广告的顶部。
2. 受害者下载一个小型的**第一阶段加载器**（通常为 JS/HTA/ISO）。Unit 42 见到的示例包括：
   - `RedLine stealer`
   - `Lumma stealer`
   - `Lampion Trojan`
3. 加载器外泄浏览器 cookie + 凭证数据库，然后拉取一个**静默加载器**，该加载器实时决定是否部署：
   - RAT（例如 AsyncRAT、RustDesk）
   - 勒索软件 / 擦除器
   - 持久化组件（注册表 Run 键 + 计划任务）

### 加固建议
   - 阻止新注册域名并在搜索广告以及电子邮件上强制执行**高级 DNS / URL 过滤**。
   - 将软件安装限制为签名的 MSI / Store 包，策略上禁止 `HTA`、`ISO`、`VBS` 的执行。
   - 监控浏览器子进程打开安装程序的情况：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
   - 搜索常被第一阶段加载器滥用的 LOLBins（例如 `regsvr32`, `curl`, `mshta`）。

---

## AI 增强的钓鱼行动
攻击者现在将 **LLM 与语音克隆 API** 串联起来，以实现完全个性化的诱饵和实时交互。

| 层级 | 恶意者的示例用途 |
|------|------------------|
|Automation|生成并发送 >100k 封邮件 / SMS，使用随机措辞与跟踪链接。|
|Generative AI|生成一次性邮件，引用公开的并购信息、社交媒体上的内部笑话；在回拨诈骗中使用深度伪造的 CEO 语音。|
|Agentic AI|自动注册域名、抓取开源情报，当受害者点击但未提交凭证时自动编写下一步邮件。|

防御：  
• 添加**动态横幅**来突出显示来自不受信任自动化的消息（通过 ARC/DKIM 异常）。  
• 为高风险电话请求部署**语音生物识别挑战短语**。  
• 在意识培训中持续模拟 AI 生成的诱饵——静态模板已过时。

另见——滥用 agentic browsing 以进行凭证钓鱼：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

另见——AI 代理滥用本地 CLI 工具和 MCP（用于 secrets 清单和检测）：

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

---

## MFA 疲劳 / Push Bombing 变体 – 强制重置
除了经典的 push-bombing，操作员也可以在 help-desk 通话过程中**强制注册新的 MFA**，从而使用户现有的令牌失效。任何随后出现的登录提示对受害者而言都显得合法。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，当 **`deleteMFA` + `addMFA`** 在来自同一 IP 的几分钟内发生时。

## Clipboard Hijacking / Pastejacking

攻击者可以从被入侵或拼写劫持的网页悄悄将恶意命令复制到受害者的剪贴板，然后诱导用户在 **Win + R**、**Win + X** 或终端窗口中粘贴这些命令，从而在无需任何下载或附件的情况下执行任意代码。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
攻击者越来越常通过简单的设备检测来对钓鱼流程进行分流，以便桌面爬虫永远无法到达最终页面。常见模式是一个小脚本检测是否支持触控的 DOM 并将结果发送到服务器端点；非移动客户端会收到 HTTP 500（或空白页面），而移动用户则会被提供完整流程。

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
- 在首次加载时设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 当 `is_mobile=false` 时，对后续 GET 返回 500（或占位符）；仅在 `true` 时提供 phishing。

威胁搜寻与检测启发式：
- urlscan 查询： `filename:"detect_device.js" AND page.status:500`
- Web 遥测：序列 `GET /static/detect_device.js` → `POST /detect` → 对非移动设备返回 HTTP 500；合法的移动受害者路径返回 200 并提供后续的 HTML/JS。
- 对仅依赖 `ontouchstart` 或类似设备检测来决定内容的页面进行封锁或仔细审查。

防御提示：
- 使用具有移动设备指纹并启用 JS 的爬虫来揭示受限内容。
- 对新注册域名中在 `POST /detect` 之后出现的可疑 500 响应发出告警。

## 参考资料

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
