# macOS Red Teaming

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングテクニックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## MDMの悪用

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

管理プラットフォームにアクセスするための**管理者資格情報を侵害**することができれば、マシンにマルウェアを配布することで、**すべてのコンピュータを潜在的に侵害**することができます。

MacOS環境でのレッドチーミングでは、MDMの動作原理についてある程度理解していることが強く推奨されています：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDMをC2として使用する

MDMは、プロファイルのインストール、クエリ、削除、アプリケーションのインストール、ローカル管理者アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更などの権限を持っています。

独自のMDMを実行するには、[**https://mdmcert.download/**](https://mdmcert.download/)で取得できる**ベンダーによって署名されたCSR**が必要です。Appleデバイス用の独自のMDMを実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用できます。

ただし、登録されたデバイスにアプリケーションをインストールするには、開発者アカウントで署名する必要があります... ただし、MDM登録時に**デバイスはMDMのSSL証明書を信頼できるCAとして追加**するため、今後は何でも署名できます。

デバイスをMDMに登録するには、ルートとして**`mobileconfig`**ファイルをインストールする必要があります。これは**pkg**ファイルを介して配信できます（Safariからダウンロードされると解凍されます）。

**MythicエージェントOrthrus**はこのテクニックを使用しています。

### JAMF PROの悪用

JAMFは**カスタムスクリプト**（システム管理者が開発したスクリプト）、**ネイティブペイロード**（ローカルアカウントの作成、EFIパスワードの設定、ファイル/プロセスの監視...）、**MDM**（デバイスの構成、デバイス証明書...）を実行できます。

#### JAMFの自己登録

`https://<company-name>.jamfcloud.com/enroll/`などのページに移動して、**自己登録が有効になっているかどうか**を確認します。有効になっている場合、**アクセスするための資格情報を要求**する場合があります。

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)スクリプトを使用してパスワードスプレー攻撃を実行できます。

さらに、適切な資格情報を見つけた後、次のフォームで他のユーザー名を総当たり攻撃することができるかもしれません：

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMFデバイス認証

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`**バイナリには、発見時点で**誰もが共有していた**キーチェーンを開くための秘密が含まれていました。それは**`jk23ucnq91jfu9aj`**でした。\
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

したがって、攻撃者は、**このファイルを上書き**し、**TyphonエージェントからMythic C2リスナーへのURLを設定**して、JAMFをC2として悪用できるようにするために、悪意のあるパッケージ（`pkg`）をドロップできます。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonation

デバイスとJMFの間の通信を**偽装**するには、以下が必要です：

* デバイスの**UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMFキーチェーン**：`/Library/Application\ Support/Jamf/JAMF.keychain`（デバイス証明書を含む）

この情報を使用して、**盗まれた**ハードウェア**UUID**を持つVMを作成し、**SIPを無効に**し、**JAMFキーチェーン**を落とし、Jamf **エージェント**を**フック**して情報を盗みます。

#### Secrets stealing

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

また、`/Library/Application Support/Jamf/tmp/`の場所を監視して、管理者がJamfを介して実行したい**カスタムスクリプト**を監視することもできます。これらのスクリプトはここに**配置され、実行され、削除**されます。これらのスクリプトには**資格情報**が含まれる可能性があります。

ただし、これらのスクリプトには**パラメータ**として**資格情報**が渡される場合がありますので、`ps aux | grep -i jamf`を監視する必要があります（root権限でなくても）。

スクリプト[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)は、新しいファイルの追加と新しいプロセス引数を監視できます。

### macOS Remote Access

また、**MacOS**の"特別な"**ネットワーク** **プロトコル**についても：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

場合によっては、**MacOSコンピュータがADに接続**されていることがあります。このシナリオでは、通常どおりにActive Directoryを列挙してみてください。以下のページで**ヘルプ**を見つけることができます：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

あなたを助ける**ローカルMacOSツール**の1つは`dscl`です：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、MacOS向けにActive Directoryの自動列挙やKerberosの操作を行うためのツールがいくつか用意されています:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundはBloodhound監査ツールの拡張で、MacOSホスト上でActive Directoryの関係を収集および取り込むことができます。
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上でHeimdal krb5 APIとやり取りするように設計されたObjective-Cプロジェクトです。このプロジェクトの目標は、macOSデバイス上でKerberosに関するセキュリティテストをネイティブAPIを使用して行うことで、対象となる環境に他のフレームワークやパッケージを必要としないようにすることです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directoryの列挙を行うためのJavaScript for Automation (JXA)ツール。
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOSの3つのタイプのユーザーは次のとおりです：

- **ローカルユーザー** — ローカルのOpenDirectoryサービスによって管理され、Active Directoryとは何の接続もありません。
- **ネットワークユーザー** — DCサーバーに接続して認証する必要がある、不安定なActive Directoryユーザー。
- **モバイルユーザー** — 資格情報とファイルのローカルバックアップを持つActive Directoryユーザー。

ユーザーとグループに関するローカル情報は、_var/db/dslocal/nodes/Default_ フォルダに保存されています。\
たとえば、ユーザー _mark_ に関する情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存され、グループ _admin_ に関する情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されています。

HasSessionとAdminToエッジを使用するだけでなく、**MacHoundはBloodhoundデータベースに3つの新しいエッジを追加**します：

- **CanSSH** - ホストにSSH接続を許可されたエンティティ
- **CanVNC** - ホストにVNC接続を許可されたエンティティ
- **CanAE** - ホストでAppleEventスクリプトを実行することが許可されたエンティティ
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
詳細は[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)にあります。

## キーチェーンへのアクセス

キーチェーンには高い確率で機密情報が含まれており、プロンプトを生成せずにアクセスすることで、レッドチームの演習を進めるのに役立つ可能性があります:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部サービス

MacOS Red Teamingは通常のWindows Red Teamingとは異なり、**MacOSは通常、複数の外部プラットフォームと直接統合**されています。 MacOSの一般的な構成は、**OneLoginと同期した資格情報を使用してコンピュータにアクセスし、OneLoginを介して複数の外部サービス**（github、awsなど）にアクセスすることです。

## その他のレッドチーム技術

### Safari

Safariでファイルをダウンロードすると、"安全"なファイルの場合、**自動的に開かれます**。たとえば、**zipファイルをダウンロード**した場合、自動的に展開されます:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
