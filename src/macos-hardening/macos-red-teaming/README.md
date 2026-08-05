# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDMs の悪用

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

管理プラットフォームにアクセスするための **admin credentials を compromise** できた場合、マシンに malware を配布することで、**すべてのコンピューターを compromise** できる可能性があります。

MacOS 環境で Red Teaming を行うには、MDM の動作についてある程度理解しておくことを強く推奨します:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM の C2 としての利用

MDM には、profiles の install、query、remove、applications の install、local admin accounts の作成、firmware password の設定、FileVault key の変更などを行う権限があります。

独自の MDM を実行するには、**vendor によって署名された CSR** が必要です。これは [**https://mdmcert.download/**](https://mdmcert.download/) から取得できる可能性があります。また、Apple devices 用の独自 MDM を実行するには [**MicroMDM**](https://github.com/micromdm/micromdm) を使用できます。

ただし、enrolled device に application を install するには、developer account による署名が依然として必要です。しかし、MDM enrolment の際に **device は MDM の SSL cert を trusted CA として追加する** ため、これで任意のものに署名できるようになります。<sup>[[4]](#references)</sup>

device を MDM に enrol するには、root として **`mobileconfig`** file を install する必要があります。これは **pkg** file 経由で配布できます（zip に compress しておけば、Safari から download した際に decompress されます）。

**Mythic agent Orthrus** はこの technique を使用します。

### JAMF PRO の悪用

JAMF は、**custom scripts**（sysadmin が開発した scripts）、**native payloads**（local account creation、EFI password の設定、file/process monitoring など）、および **MDM**（device configurations、device certificates など）を実行できます。<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

`https://<company-name>.jamfcloud.com/enroll/` のような page にアクセスして、**self-enrolment が有効になっているか**を確認します。有効になっている場合、**access credentials を要求される**可能性があります。

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script を使用して、password spraying attack を実行できます。

さらに、有効な credentials を見つけた後、次の form を使って他の usernames を brute-force できる可能性があります:

![Abusing JAMF PRO - JAMF self-enrolment: Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary には keychain を開くための secret が含まれており、発見時点では全員の間で **shared** されていました。その値は **`jk23ucnq91jfu9aj`** でした。<sup>[[5]](#references)</sup>\
さらに、jamf は **LaunchDaemon** として **`/Library/LaunchAgents/com.jamf.management.agent.plist`** に **persist** します。

#### JAMF Device Takeover

**`jamf`** が使用する **JSS**（Jamf Software Server）の **URL** は **`/Library/Preferences/com.jamfsoftware.jamf.plist`** にあります。\
この file には基本的に次の URL が含まれています:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
そのため、攻撃者は悪意のあるパッケージ（`pkg`）を配置し、インストール時に**このファイルを上書き**して、**Typhon agentからのMythic C2 listenerのURL**を設定することで、JAMFをC2として悪用できるようになります。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

デバイスと JMF 間の通信を **impersonate** するには、以下が必要です。

- デバイスの **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- `/Library/Application\ Support/Jamf/JAMF.keychain` にある **JAMF keychain**。これにはデバイス証明書が含まれています。

この情報を使用して、**盗んだ** Hardware **UUID** を設定し、**SIP disabled** の **VM を作成**し、**JAMF keychain を配置**して、Jamf **agent** に **hook** を仕掛け、その情報を盗みます。

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

`/Library/Application Support/Jamf/tmp/` の場所を監視することもできます。管理者が Jamf 経由で実行しようとする **custom scripts** は、ここに **配置され、実行され、削除される**ためです。これらのスクリプトには **credentials** が含まれている可能性があります。

ただし、**credentials** はこれらのスクリプトに **parameters** として渡される場合もあるため、`ps aux | grep -i jamf` を監視する必要があります（root でなくても可能です）。

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) スクリプトを使用すると、新しいファイルの追加や新しいプロセス引数を監視できます。

### macOS Remote Access

また、**MacOS** の「special」な **network** **protocols** についても確認してください。


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

場合によっては、**MacOS computer が AD に接続されている**ことがあります。このシナリオでは、普段行っている方法で active directory を **enumerate** してみてください。以下のページに **help** があります。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

役立つ可能性のある **local MacOS tool** として、`dscl` もあります。
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、MacOS向けに、ADの自動列挙やkerberosの操作を行うためのツールもいくつか用意されています。

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundは、MacOSホスト上のActive Directoryの関係情報を収集して取り込めるようにする、Bloodhound audting toolの拡張機能です。<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIsと対話するために設計されたObjective-Cプロジェクトです。このプロジェクトの目的は、ターゲット上で他のframeworkやpackagesを必要とせず、native APIsを使用してmacOS devices上のKerberosに関するsecurity testingをより適切に実行できるようにすることです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumerationを行うためのJavaScript for Automation (JXA) toolです。

### Domain Information
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOS ユーザーには、次の3種類があります。

- **Local Users** — ローカルの OpenDirectory service によって管理され、Active Directory には一切接続されていません。
- **Network Users** — 認証のために DC server への接続を必要とする、一時的な Active Directory ユーザーです。
- **Mobile Users** — credentials と files のローカルバックアップを持つ Active Directory ユーザーです。

ユーザーと groups に関するローカル情報は、フォルダー _/var/db/dslocal/nodes/Default._ に保存されています。\
たとえば、_mark_ というユーザーの情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存され、_admin_ group の情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されています。

HasSession および AdminTo edges に加えて、**MacHound は Bloodhound database に3つの新しい edges を追加します**:<sup>[[2]](#references)</sup>

- **CanSSH** - host への SSH が許可された entity
- **CanVNC** - host への VNC が許可された entity
- **CanAE** - host 上で AppleEvent scripts を実行することが許可された entity
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
詳細情報: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

以下を使用してパスワードを取得します:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** のパスワードは、System keychain 内からアクセスできます。

### Over-Pass-The-Hash

特定の user と service の TGT を取得します：
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGTを取得したら、以下の方法で現在のセッションにinjectできます。
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
取得した service tickets を使えば、他のコンピューター上の共有へのアクセスを試みることが可能です:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Keychainへのアクセス

Keychainには、プロンプトを表示させずにアクセスできれば、red team exerciseを前進させるのに役立つ可能性が非常に高い機密情報が含まれていることがあります。


{{#ref}}
macos-keychain.md
{{#endref}}

## 外部サービス

MacOS Red Teamingは通常のWindows Red Teamingとは異なります。これは、一般的に**MacOSが複数の外部プラットフォームと直接統合されている**ためです。MacOSの一般的な構成では、**OneLoginで同期された認証情報を使用してコンピューターにアクセスし、OneLogin経由で複数の外部サービス**（github、awsなど）にアクセスします。

## その他のRed Teamテクニック

### Safari

Safariでファイルをダウンロードすると、それが「安全な」ファイルである場合、**自動的に開かれます**。たとえば、**zipをダウンロード**すると、自動的に展開されます。

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## 参考資料

- [1] [Gone Apple Pickin': 2021年のMacOS環境に対するRed Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [MacHoundの紹介：macOS Active Directory Based Attacks向けのソリューション](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: macOS Management Evilへの転換](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
