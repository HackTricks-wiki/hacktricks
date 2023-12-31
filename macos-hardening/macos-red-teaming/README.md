# macOS Red Teaming

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* あなたの**会社をHackTricksに広告掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してハッキングのコツを共有する。

</details>

## MDMの悪用

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

管理プラットフォームへのアクセスに**管理者の資格情報を侵害する**ことに成功した場合、マシンにマルウェアを配布することで**すべてのコンピューターを侵害する可能性**があります。

MacOS環境でのレッドチーミングでは、MDMの動作についての理解が非常に推奨されます：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDMをC2として使用する

MDMはプロファイルのインストール、クエリ、削除、アプリケーションのインストール、ローカル管理アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更などの権限を持っています...

自分のMDMを実行するには、[**https://mdmcert.download/**](https://mdmcert.download/)で試すことができるベンダーによって**署名されたCSRが必要です**。そして、Appleデバイス用の自分のMDMを実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用できます。

しかし、登録されたデバイスにアプリケーションをインストールするには、開発者アカウントによって署名されている必要があります...しかし、MDM登録時に**デバイスはMDMのSSL証明書を信頼されたCAとして追加します**ので、今は何でも署名できます。

デバイスをMDMに登録するには、ルートとして**`mobileconfig`**ファイルをインストールする必要があります。これは、zipで圧縮された**pkg**ファイルを介して配信される可能性があります（safariからダウンロードされると解凍されます）。

**Mythic agent Orthrus**はこの技術を使用しています。

### JAMF PROの悪用

JAMFは**カスタムスクリプト**（システム管理者によって開発されたスクリプト）、**ネイティブペイロード**（ローカルアカウントの作成、EFIパスワードの設定、ファイル/プロセスの監視...）、および**MDM**（デバイスの設定、デバイス証明書...）を実行できます。

#### JAMF自己登録

`https://<company-name>.jamfcloud.com/enroll/`のようなページにアクセスして、**自己登録が有効になっているか**を確認します。有効になっている場合は、**アクセスするための資格情報を求められる**可能性があります。

パスワードスプレー攻撃を実行するために[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)スクリプトを使用できます。

さらに、適切な資格情報を見つけた後、次のフォームで他のユーザー名をブルートフォースすることができるかもしれません：

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMFデバイス認証

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`**バイナリにはキーチェーンを開くための秘密が含まれており、発見時点では**共有されていた**のは**`jk23ucnq91jfu9aj`**でした。\
さらに、jamfは**`/Library/LaunchAgents/com.jamf.management.agent.plist`**に**LaunchDaemon**として**永続化**します。

#### JAMFデバイスの乗っ取り

**`jamf`**が使用する**JSS**（Jamf Software Server）**URL**は**`/Library/Preferences/com.jamfsoftware.jamf.plist`**にあります。\
このファイルは基本的にURLを含んでいます：

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

したがって、攻撃者は悪意のあるパッケージ（`pkg`）をドロップし、インストール時にこのファイルを**上書きし**、**Mythic C2リスナーへのURLをTyphonエージェントから設定する**ことで、JAMFをC2として悪用することができます。

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF なりすまし

デバイスとJMFの通信を**なりすます**ためには以下が必要です:

* デバイスの**UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF キーチェーン**: `/Library/Application\ Support/Jamf/JAMF.keychain` ここにはデバイス証明書が含まれています

この情報を使って、**盗まれた**ハードウェア**UUID**を持つ**VMを作成**し、**SIPを無効化**して、**JAMF キーチェーンをドロップ**し、Jamf **エージェントをフック**して情報を盗みます。

#### 秘密の盗難

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

また、管理者がJamfを介して実行したい**カスタムスクリプト**が `/Library/Application Support/Jamf/tmp/` に**配置され、実行され、削除される**のを監視することもできます。これらのスクリプトには**資格情報が含まれている可能性**があります。

しかし、**資格情報**はスクリプトに**パラメータとして渡される**こともあるため、ルートでなくても `ps aux | grep -i jamf` を監視する必要があります。

スクリプト [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) は新しいファイルの追加と新しいプロセス引数を監視することができます。

### macOS リモートアクセス

そして、**MacOS**の"特別な"**ネットワーク** **プロトコル**についても:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## アクティブディレクトリ

場合によっては、**MacOS コンピュータが AD に接続されている**ことがわかるでしょう。このシナリオでは、慣れ親しんだようにアクティブディレクトリを**列挙**するべきです。以下のページで**ヘルプ**を見つけてください:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

また、役立つかもしれない**ローカル MacOS ツール**には `dscl` があります:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
以下は、MacOSでADを自動的に列挙し、Kerberosを操作するためのツールです：

* [**Machound**](https://github.com/XMCyber/MacHound): MacHoundは、MacOSホスト上のActive Directoryの関係を収集し、取り込むことを可能にするBloodhound監査ツールの拡張です。
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIと対話するために設計されたObjective-Cプロジェクトです。このプロジェクトの目的は、ターゲットに他のフレームワークやパッケージを必要とせずに、macOSデバイス上でKerberosのセキュリティテストをより良く行うために、ネイティブAPIを使用することです。
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directoryの列挙を行うJavaScript for Automation (JXA) ツールです。

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOSのユーザーには3種類あります：

* **ローカルユーザー** — ローカルのOpenDirectoryサービスによって管理されており、Active Directoryとは何の関連もありません。
* **ネットワークユーザー** — 揮発性のActive Directoryユーザーで、認証するためにDCサーバーへの接続が必要です。
* **モバイルユーザー** — Active Directoryユーザーで、資格情報とファイルのローカルバックアップがあります。

ユーザーやグループに関するローカル情報は、_/var/db/dslocal/nodes/Default_ フォルダに保存されています。\
例えば、_mark_ というユーザーに関する情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に、_admin_ グループに関する情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ にあります。

HasSessionやAdminToのエッジを使用することに加えて、**MacHoundはBloodhoundデータベースに3つの新しいエッジを追加します**：

* **CanSSH** - ホストへのSSHが許可されたエンティティ
* **CanVNC** - ホストへのVNCが許可されたエンティティ
* **CanAE** - ホストでAppleEventスクリプトを実行することが許可されたエンティティ
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
詳細は[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)をご覧ください。

## キーチェーンへのアクセス

キーチェーンには、プロンプトを生成せずにアクセスできれば、レッドチーム演習を進めるのに役立つ可能性が高い機密情報が含まれている可能性があります：

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部サービス

MacOS レッドチーミングは、通常 **MacOS が直接いくつかの外部プラットフォームと統合されている**ため、通常の Windows レッドチーミングとは異なります。MacOS の一般的な設定では、**OneLogin と同期された資格情報を使用してコンピューターにアクセスし、OneLogin 経由でいくつかの外部サービス**（github、aws など）にアクセスします：

![](<../../.gitbook/assets/image (563).png>)

## その他のレッドチーム技術

### Safari

Safari でファイルをダウンロードすると、「安全な」ファイルであれば **自動的に開かれます**。例えば、**zip をダウンロードする**と、自動的に解凍されます：

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式の PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックしてください。
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass)に **参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを **共有してください**。

</details>
