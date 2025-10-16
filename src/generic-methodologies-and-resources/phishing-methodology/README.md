# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. Recon the victim
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

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

在此步骤之前，你应该**已经购买将要使用的域名**，并且它必须**指向**用于配置 **gophish** 的 **VPS 的 IP**。
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

然后将域添加到以下文件:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**还要更改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后将文件 **`/etc/hostname`** 和 **`/etc/mailname`** 修改为你的域名，并 **重启你的 VPS.**

现在为 `mail.<domain>` 创建一个 **DNS A record**，指向 VPS 的 **IP 地址**，并创建一个 **DNS MX** 记录指向 `mail.<domain>`

现在让我们测试发送邮件：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 配置**

停止 gophish 的运行，然后进行配置。\
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
完成服务的配置并检查其运行情况：
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

域名存在的时间越久，被判定为垃圾邮件的概率就越低。因此在进行 phishing assessment 之前应尽可能多地等待（至少1week）。此外，如果你放置一个关于声誉良好行业的页面，所获得的 reputation 会更好。

注意即使你必须等待一周，你也可以现在完成所有配置。

### Configure Reverse DNS (rDNS) record

设置一个 rDNS (PTR) 记录，将 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) Record

你必须 **为新域配置 SPF 记录**。如果你不知道什么是 SPF 记录 [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 来生成你的 SPF 策略（使用 VPS 机器的 IP）

![](<../../images/image (1037).png>)

以下内容必须作为域名的 TXT 记录设置：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### 基于域的消息认证、报告与一致性 (DMARC) Record

你必须 **为新域配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，指向主机名 `_dmarc.<domain>`，内容如下：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

你必须**为新域配置 DKIM**。如果你不知道什么是 DMARC 记录，[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> 你需要将 DKIM 密钥生成的两个 B64 值连接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com)\\
只需访问该页面并将邮件发送到他们提供的地址：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
你也可以通过发送一封邮件到 `check-auth@verifier.port25.com` 来 **检查你的邮件配置**，并 **读取响应**（为此你需要 **打开** 端口 **25**，如果以 root 发送邮件，可以在文件 _/var/mail/root_ 中查看响应）。\
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
你也可以**向你控制的 Gmail 发送一条消息**，并在你的 Gmail 收件箱中检查**邮件头**，在 `Authentication-Results` 头字段中应出现 `dkim=pass`。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

The page [www.mail-tester.com](https://www.mail-tester.com) 可以告诉你你的域名是否被 spamhouse 阻止。你可以在以下地址请求移除你的域名/IP：​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​你可以在 [https://sender.office.com/](https://sender.office.com) 请求移除你的域名/IP。

## Create & Launch GoPhish Campaign

### Sending Profile

- 为发件人配置设置一个用于识别的 **名称**
- 决定你将从哪个账户发送 phishing 邮件。建议：_noreply, support, servicedesk, salesforce..._
- 你可以将 username 和 password 留空，但请确保勾选 **Ignore Certificate Errors**

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用 "**Send Test Email**" 功能来测试一切是否正常。\
> 我建议 **将测试邮件发送到 10min mails 地址**，以避免在测试时被列入黑名单。

### Email Template

- 为模板设置一个用于识别的 **名称**
- 然后写一个 **主题**（不要奇怪，就写你在普通邮件中会看到的内容）
- 确保已勾选 "**Add Tracking Image**"
- 撰写 **邮件模板**（你可以像下面示例一样使用变量）：
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
注意：为了提高邮件的可信度，建议使用来自客户电子邮件的一些签名。建议：

- 向一个 **不存在的地址** 发送电子邮件，检查回复是否包含任何签名。
- 搜索 **公开邮箱**，例如 info@ex.com、press@ex.com 或 public@ex.com，给它们发送邮件并等待回复。
- 尝试联系某些已发现的 **有效邮箱** 并等待回复。

![](<../../images/image (80).png>)

> [!TIP]
> 邮件模板也允许 **附加要发送的文件**。如果你还想使用一些特殊构造的文件/文档来窃取 NTLM challenges，请阅读此页：[read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing 页面

- 填写一个 **名称**
- **编写网页的 HTML 代码**。注意你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置一个 **重定向**

![](<../../images/image (826).png>)

> [!TIP]
> 通常你需要修改页面的 HTML 代码并在本地进行一些测试（例如使用 Apache 服务器），直到你满意结果。然后，将该 HTML 代码写入输入框。\
> 注意，如果你需要为 HTML 使用一些静态资源（例如一些 CSS 和 JS 页面），你可以将它们保存在 _**/opt/gophish/static/endpoint**_，然后从 _**/static/\<filename>**_ 访问它们。

> [!TIP]
> 对于重定向，你可以将用户重定向到受害者的合法主网页，或者重定向到 _/static/migration.html_，例如放一个**旋转加载动画（**[**https://loading.io/**](https://loading.io)**）持续 5 秒，然后提示流程已成功**。

### 用户与组

- 设置名称
- **导入数据**（注意：要使用示例模板，你需要每个用户的 firstname、last name 和 email address）

![](<../../images/image (163).png>)

### 活动

最后，创建一个活动，选择名称、邮件模板、登陆页面、URL、发送配置文件和用户组。注意 URL 将是发送给受害者的链接。

注意 **Sending Profile 允许发送测试邮件来查看最终钓鱼邮件的样子**：

![](<../../images/image (192).png>)

> [!TIP]
> 我建议将**测试邮件发送到 10min mails 地址**，以避免在测试时被列入黑名单。

一切准备就绪后，启动活动即可！

## 网站克隆

如果你出于任何原因想要克隆网站，请查看以下页面：


{{#ref}}
clone-a-website.md
{{#endref}}

## 带后门的文档与文件

在一些钓鱼评估中（主要是 Red Teams），你可能还希望**发送包含某种后门的文件**（可能是 C2，或只是触发身份验证的东西）。\
查看下列页面获取一些示例：


{{#ref}}
phishing-documents.md
{{#endref}}

## 钓鱼 MFA

### 通过 Proxy MitM

前一种攻击相当巧妙，因为你伪造了一个真实网站并收集用户填写的信息。不幸的是，如果用户没有填写正确的密码，或你伪造的应用配置了 2FA，**这些信息并不能让你冒充被欺骗的用户**。

这就是像 [**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 这类工具派上用场的地方。该工具允许你生成类似 MitM 的攻击。基本上，攻击的工作流程如下：

1. 你冒充真实网页的登录表单。
2. 用户将其 credentials 发送到你的假页面，工具会把这些转发到真实网页，检查这些 credentials 是否有效。
3. 如果账户启用了 **2FA**，MitM 页面会请求输入，一旦用户输入，工具会将其转发给真实网页。
4. 用户认证后，你（作为攻击者）将捕获到 credentials、2FA、cookie 以及工具进行 MitM 期间的所有交互信息。

### 通过 VNC

如果不是将受害者发送到一个看起来和原始页面一样的恶意页面，而是把他送到一个通过浏览器连接到真实网页的 VNC 会话呢？你将能够看到他的操作，窃取密码、使用的 MFA、cookies……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现这一点。

## 检测是否被发现

显然，判断自己是否已被发现的最佳方法之一是**在黑名单中搜索你的域名**。如果它出现在列表中，说明你的域名在某种程度上被检测为可疑。\
检查域名是否出现在任何黑名单的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)

然而，还有其他方法可以判断受害者是否在主动搜索野外的可疑钓鱼活动，如下所述：


{{#ref}}
detecting-phising.md
{{#endref}}

你可以购买一个与受害者域名非常相似的域名，和/或为你控制的域名的子域生成一个包含受害者域名关键字的证书。如果受害者对它们执行了任何形式的 DNS 或 HTTP 交互，你就会知道他在主动查找可疑域名，此时你需要非常隐蔽。

### 评估钓鱼

使用 [**Phishious**](https://github.com/Rices/Phishious) 来评估你的邮件是否会进入垃圾邮件文件夹、被拦截或成功送达。

## 高接触身份劫持（帮助台 MFA 重置）

现代入侵组合越来越多地完全跳过电子邮件诱饵，直接针对 service-desk / identity-recovery 工作流以绕过 MFA。该攻击完全属于 "living-off-the-land"：一旦操作员获得有效凭证，他们就使用内置管理工具横向移动——不需要恶意软件。

### 攻击流程
1. Recon 受害者
* 从 LinkedIn、数据泄露、公共 GitHub 等收集个人和公司详细信息。
* 识别高价值身份（高管、IT、财务）并枚举用于密码 / MFA 重置的**确切帮助台流程**。
2. 实时社工
* 在冒充目标的情况下通过电话、Teams 或聊天联系帮助台（通常使用 **spoofed caller-ID** 或 **克隆语音**）。
* 提供之前收集的 PII 以通过基于知识的验证。
* 说服客服人员 **重置 MFA secret** 或对已注册的手机号执行 **SIM-swap**。
3. 即时的访问后操作（实际案例中 ≤60 分钟）
* 通过任何 web SSO 门户建立立足点。
* 使用内置工具列举 AD / AzureAD（不落地二进制）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 使用 **WMI**、**PsExec** 或环境中已被列入白名单的合法 **RMM** 代理进行横向移动。

### 检测与缓解
* 将帮助台的身份恢复视为 **特权操作**——要求提升认证（step-up auth）与经理批准。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则以在以下情况触发告警：
* MFA 方法被更改 + 来自新设备/地理位置的认证。
* 同一主体的即时提权（user → admin）。
* 记录帮助台通话并在任何重置前强制回拨到已注册号码。
* 实施 **Just-In-Time (JIT) / 特权访问**，以便新重置的账户不会自动继承高权限令牌。

---

## 大规模欺骗 — SEO 投毒与 “ClickFix” 活动
普通团队通过大规模攻击将 **搜索引擎与广告网络作为投放渠道** 来抵消高接触操作的成本。

1. **SEO 投毒 / 恶意广告** 将假结果（例如 chromium-update[.]site）推上搜索广告顶部。
2. 受害者下载一个小型 **首阶段加载器**（通常为 JS/HTA/ISO）。Unit 42 见过的示例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. 加载器外泄浏览器 cookies + 凭证数据库，然后拉取一个 **静默加载器**，它实时决定是否部署：
* RAT（例如 AsyncRAT、RustDesk）
* 勒索软件 / 擦除工具
* 持久化组件（注册表 Run 键 + 计划任务）

### 加固建议
* 阻断新注册域名并对搜索广告及邮件实施 **高级 DNS / URL 过滤**。
* 将软件安装限制为签名的 MSI / Store 包，策略上禁止执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器的子进程是否打开安装程序：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 查找首阶段加载器频繁滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

---

## AI 增强的钓鱼行动
攻击者现在串联 **LLM & 语音克隆 API**，用于完全个性化的诱饵和实时交互。

| 层级 | 威胁行为者的示例用法 |
|-------|-----------------------------|
| 自动化 | 生成并发送 >100k 封邮件 / 短信，使用随机化措辞与跟踪链接。 |
| 生成式 AI | 生成一次性邮件，引用公开的并购信息、来自社交媒体的内梗；在回拨诈骗中使用 CEO 的深度伪造语音。 |
| 代理式 AI | 自动注册域名、抓取开源情报，在受害者点击但未提交凭证时自动生成下一阶段邮件。 |

**防御：**
• 添加 **动态横幅**，突出标记来自不受信任自动化的消息（通过 ARC/DKIM 异常）。  
• 对高风险电话请求部署 **语音生物特征挑战短语**。  
• 在安全意识计划中持续模拟 AI 生成的诱饵 —— 静态模板已过时。

另见 — agentic browsing 滥用以进行凭证钓鱼：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA 疲劳 / Push Bombing 变体 — 强制重置
除了经典的 push-bombing 外，操作者在帮助台通话期间直接 **强制新 MFA 注册**，使用户现有的令牌失效。随后出现的任何登录提示对受害者而言都看起来是合法的。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
监控 AzureAD/AWS/Okta 事件，当 **`deleteMFA` + `addMFA`** 在几分钟内从同一 IP 发生时。

## Clipboard Hijacking / Pastejacking

攻击者可以静默地将恶意命令复制到受害者的剪贴板，来源于被入侵或 typosquatted 的网页，然后诱骗用户在 **Win + R**、**Win + X** 或终端窗口中粘贴并执行，从而在无需任何下载或附件的情况下执行任意代码。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
攻击者越来越多地在钓鱼流程后面加入简单的设备检测，从而使桌面爬虫无法访问最终页面。常见的模式是一段小脚本检测是否支持触控的 DOM 并将结果发布到服务器端点；非移动客户端收到 HTTP 500（或空白页），而移动用户则会看到完整流程。

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
- 当 `is_mobile=false` 时，对随后的 GET 返回 500（或占位符）；只有当为 `true` 时才提供钓鱼内容。

狩猎与检测启发式：
- urlscan 查询： `filename:"detect_device.js" AND page.status:500`
- Web 遥测：序列为 `GET /static/detect_device.js` → `POST /detect` → 非移动设备返回 HTTP 500；真实的移动受害者路径返回 200 并返回后续的 HTML/JS。
- 阻断或审查那些仅依赖 `ontouchstart` 或类似设备检测来决定内容的页面。

防御提示：
- 用类似移动设备指纹并启用 JS 的爬虫来抓取，以揭露被门控的内容。
- 对新注册域名上在 `POST /detect` 之后出现的可疑 500 响应发出警报。

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
