# macOS Red Teaming

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

## MDMの乱用

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

管理プラットフォームにアクセスするために**管理者資格情報を侵害**することができれば、マシンにマルウェアを配布することで、すべてのコンピュータを**潜在的に侵害**することができます。

MacOS環境でのレッドチーミングでは、MDMの動作原理を理解することが強く推奨されています：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDMをC2として使用する

MDMは、プロファイルのインストール、クエリ、削除、アプリケーションのインストール、ローカル管理者アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更などの権限を持っています。

独自のMDMを実行するには、[**https://mdmcert.download/**](https://mdmcert.download/)で取得できるベンダーによって**CSRを署名する必要があります**。Appleデバイス用の独自のMDMを実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用できます。

ただし、登録されたデバイスにアプリケーションをインストールするには、開発者アカウントで署名する必要があります... ただし、MDM登録時には、デバイスがMDMのSSL証明書を信頼できるCAとして追加するため、今後は何でも署名できます。

デバイスをMDMに登録するには、ルートとして**`mobileconfig`**ファイルをインストールする必要があります。これは**pkg**ファイルを介して配信できます（Safariからダウンロードされると解凍されます）。

**MythicエージェントOrthrus**はこのテクニックを使用しています。

### JAMF PROの乱用

JAMFは**カスタムスクリプト**（システム管理者が開発したスクリプト）、**ネイティブペイロード**（ローカルアカウントの作成、EFIパスワードの設定、ファイル/プロセスの監視...）、**MDM**（デバイスの構成、デバイス証明書...）を実行できます。

#### JAMFの自己登録

`https://<company-name>.jamfcloud.com/enroll/`などのページに移動して、**自己登録が有効になっているかどうか**を確認します。有効になっている場合は、**アクセスするための資格情報を要求**するかもしれません。

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)スクリプトを使用してパスワードスプレー攻撃を実行できます。

適切な資格情報を見つけた後、次の形式で他のユーザー名を総当たり攻撃することができるかもしれません：

![](<../../.gitbook/assets/image (107).png>)

#### JAMFデバイス認証

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`**バイナリには、キーチェーンを開くための秘密が含まれており、発見時点では**誰もが共有していた**ものでした：**`jk23ucnq91jfu9aj`**。\
さらに、jamfは**`/Library/LaunchAgents/com.jamf.management.agent.plist`**に**LaunchDaemon**として**永続化**されます。

#### JAMFデバイス乗っ取り

**`jamf`**が使用する**JSS**（Jamf Software Server）**URL**は**`/Library/Preferences/com.jamfsoftware.jamf.plist`**にあります。\
このファイルには基本的にURLが含まれています：

{% code overflow="wrap" %}
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
{% endcode %}

したがって、攻撃者は、**このファイルを上書き**し、TyphonエージェントからMythic C2リスナーへの**URLを設定**するように悪意のあるパッケージ（`pkg`）をインストールすることができ、これによりJAMFをC2として悪用することができます。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonation

デバイスとJMFの間の通信を**偽装**するには、次のものが必要です：

* デバイスの**UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* 次の場所からの**JAMFキーチェーン**：`/Library/Application\ Support/Jamf/JAMF.keychain`（デバイス証明書を含む）

この情報を使用して、**盗まれた**ハードウェア**UUID**を持つVMを作成し、**SIPを無効に**し、**JAMFキーチェーン**をドロップし、Jamf **エージェント**を**フック**して情報を盗みます。

#### Secrets stealing

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

また、**カスタムスクリプト**を監視することもできます。管理者がJamfを介して実行したいと考えるかもしれない場所 `/Library/Application Support/Jamf/tmp/` これらのスクリプトはここに**配置され、実行され、削除**されます。これらのスクリプトには**資格情報**が含まれる可能性があります。

ただし、**資格情報**は**パラメータ**としてこれらのスクリプトに渡される場合がありますので、`ps aux | grep -i jamf` を監視する必要があります（root権限でなくても）。

スクリプト[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) は、新しいファイルが追加されるのを監視し、新しいプロセス引数を聞くことができます。

### macOS Remote Access

そして**MacOS**の"特別な"**ネットワーク** **プロトコル**についても：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

場合によっては、**MacOSコンピューターがADに接続されている**ことがわかります。このシナリオでは、通常どおりにアクティブディレクトリを列挙してみてください。以下のページで**ヘルプ**を見つけることができます：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

あなたを助けるのに役立つ**ローカルMacOSツール**の1つは `dscl` です：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、MacOS向けにActive Directoryの自動列挙やKerberosの操作を行うためのツールがいくつか用意されています:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundはBloodhound監査ツールの拡張機能で、MacOSホスト上でActive Directoryの関係を収集および取り込むことができます。
- [**Bifrost**](https://github.com/its-a-feature/bifrost): BifrostはObjective-Cプロジェクトで、macOS上のHeimdal krb5 APIとやり取りするように設計されています。このプロジェクトの目標は、macOSデバイス上でKerberosに関するセキュリティテストを、ターゲット上で他のフレームワークやパッケージを必要とせずに、ネイティブAPIを使用して可能にすることです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directoryの列挙を行うためのJavaScript for Automation (JXA)ツール。 

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOSの3つのタイプのユーザーは次のとおりです：

- **ローカルユーザー** — ローカルのOpenDirectoryサービスによって管理され、Active Directoryとは何の接続もありません。
- **ネットワークユーザー** — DCサーバーに接続して認証する必要がある一時的なActive Directoryユーザー。
- **モバイルユーザー** — 資格情報とファイルのローカルバックアップを持つActive Directoryユーザー。

ユーザーとグループに関するローカル情報は、_/var/db/dslocal/nodes/Default_ フォルダに保存されています。\
たとえば、ユーザー _mark_ に関する情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存され、グループ _admin_ に関する情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されています。

**MacHoundはHasSessionとAdminToエッジに加えて、Bloodhoundデータベースに3つの新しいエッジを追加**します：

- **CanSSH** - ホストにSSHで接続を許可されたエンティティ
- **CanVNC** - ホストにVNCで接続を許可されたエンティティ
- **CanAE** - ホストでAppleEventスクリプトを実行することを許可されたエンティティ
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
## キーチェーンへのアクセス

キーチェーンには高度に機密性の高い情報が含まれており、プロンプトを生成せずにアクセスすると、レッドチームの演習を前進させるのに役立つ可能性が非常に高いです：

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部サービス

MacOS Red Teamingは通常のWindows Red Teamingとは異なります。通常、**MacOSは複数の外部プラットフォームと直接統合**されています。MacOSの一般的な構成は、**OneLoginと同期された資格情報を使用してコンピュータにアクセスし、OneLoginを介して複数の外部サービス**（github、awsなど）にアクセスすることです。

## その他のレッドチーム技術

### Safari

Safariでファイルをダウンロードすると、"安全"なファイルの場合、**自動的に開かれます**。たとえば、**zipファイルをダウンロード**した場合、自動的に展開されます：

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
