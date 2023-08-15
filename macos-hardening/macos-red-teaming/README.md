# macOS レッドチーミング

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## MDMの乱用

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

管理プラットフォームにアクセスするために**管理者の資格情報を侵害**することができれば、マシンにマルウェアを配布することで、**すべてのコンピュータを潜在的に侵害**することができます。

MacOS環境でのレッドチーミングには、MDMの動作原理についての理解が非常に重要です。

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDMをC2として乱用する

MDMは、プロファイルのインストール、クエリ、削除、アプリケーションのインストール、ローカル管理者アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更などの権限を持っています。

独自のMDMを実行するには、[**https://mdmcert.download/**](https://mdmcert.download/)で取得しようとすることができる**ベンダーによって署名されたCSR**が必要です。また、Appleデバイス用の独自のMDMを実行するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を使用することができます。

ただし、登録されたデバイスにアプリケーションをインストールするには、開発者アカウントによって署名されている必要があります...ただし、MDMの登録時に**デバイスはMDMのSSL証明書を信頼できるCAとして追加**するため、今では何でも署名できます。

デバイスをMDMに登録するには、ルートとして**`mobileconfig`**ファイルをインストールする必要があります。これは**pkg**ファイルを介して配信することができます（zipで圧縮し、Safariからダウンロードすると解凍されます）。

**MythicエージェントOrthrus**は、この技術を使用しています。

### JAMF PROの乱用

JAMFは、**カスタムスクリプト**（システム管理者によって開発されたスクリプト）、**ネイティブペイロード**（ローカルアカウントの作成、EFIパスワードの設定、ファイル/プロセスの監視...）、**MDM**（デバイスの設定、デバイスの証明書...）を実行できます。

#### JAMFの自己登録

`https://<company-name>.jamfcloud.com/enroll/`のようなページにアクセスして、**自己登録が有効になっているかどうか**を確認します。有効な場合、**資格情報を入力するように求められる**場合があります。

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)スクリプトを使用してパスワードスプレー攻撃を実行できます。

さらに、適切な資格情報を見つけた後、次のフォームで他のユーザー名をブルートフォース攻撃することができます：

![](<../../.gitbook/assets/image (7).png>)

#### JAMFデバイス認証

<figure><img src="../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`**バイナリには、キーチェーンを開くための秘密が含まれており、発見当時は**誰でも共有**されていました。秘密は**`jk23ucnq91jfu9aj`**でした。\
さらに、jamfは**LaunchDaemon**として**`/Library/LaunchAgents/com.jamf.management.agent.plist`**に**永続化**されます。

#### JAMFデバイスの乗っ取り

**`jamf`**が使用する**JSS**（Jamf Software Server）**URL**は、**`/Library/Preferences/com.jamfsoftware.jamf.plist`**にあります。\
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

したがって、攻撃者は、インストール時にこのファイルを上書きする悪意のあるパッケージ（`pkg`）をドロップすることができます。これにより、TyphonエージェントからのMythic C2リスナーへのURLが設定され、JAMFをC2として悪用することができるようになります。

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMFのなりすまし

デバイスとJMFの間の通信をなりすますためには、以下が必要です：

* デバイスの**UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* デバイス証明書を含む**JAMFキーチェーン**：`/Library/Application\ Support/Jamf/JAMF.keychain`

これらの情報を使用して、**盗まれた**ハードウェア**UUID**と**SIPが無効化された**JAMFキーチェーンを持つVMを作成し、Jamf**エージェント**を**フック**して情報を盗みます。

#### 秘密の盗み出し

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

また、Jamfを介して実行したい**カスタムスクリプト**を管理者が配置し、実行後に削除するために、`/Library/Application Support/Jamf/tmp/`の場所を監視することもできます。これらのスクリプトには**資格情報**が含まれている可能性があります。

ただし、これらのスクリプトには**パラメータ**として資格情報が渡される場合があるため、`ps aux | grep -i jamf`を監視する必要があります（rootでなくても可）。

スクリプト[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)は、新しいファイルの追加と新しいプロセス引数のリッスンを行うことができます。

### macOSリモートアクセス

また、**MacOS**の「特別な」**ネットワーク****プロトコル**についても説明します：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

一部の場合、**MacOSコンピュータがADに接続されている**ことがわかるでしょう。このシナリオでは、通常どおりにActive Directoryを列挙してみることをお勧めします。以下のページで**ヘルプ**を見つけることができます：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

また、あなたに役立つかもしれない**ローカルMacOSツール**には、`dscl`があります：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
また、MacOS用にいくつかのツールが用意されており、ADの自動列挙とKerberosの操作が可能です：

* [**Machound**](https://github.com/XMCyber/MacHound)：MacHoundは、Bloodhound監査ツールの拡張であり、MacOSホスト上でActive Directoryの関係を収集および取り込むことができます。
* [**Bifrost**](https://github.com/its-a-feature/bifrost)：Bifrostは、Objective-Cプロジェクトであり、macOS上のHeimdal krb5 APIとの対話を目的としています。このプロジェクトの目標は、ネイティブAPIを使用してmacOSデバイス上のKerberosのセキュリティテストをより効果的に行うことであり、対象となる環境に他のフレームワークやパッケージを必要としません。
* [**Orchard**](https://github.com/its-a-feature/Orchard)：Active Directoryの列挙を行うためのJavaScript for Automation（JXA）ツールです。

### ドメイン情報
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### ユーザー

MacOSのユーザーには3つのタイプがあります：

* **ローカルユーザー** - ローカルのOpenDirectoryサービスによって管理され、Active Directoryとは何の関係もありません。
* **ネットワークユーザー** - 一時的なActive Directoryユーザーで、認証するためにDCサーバーへの接続が必要です。
* **モバイルユーザー** - ローカルのバックアップを持つActive Directoryユーザーで、資格情報とファイルが保存されます。

ユーザーとグループに関するローカル情報は、_ /var/db/dslocal/nodes/Default _フォルダに保存されています。\
たとえば、ユーザー名が _mark_ の情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に保存され、グループ _admin_ の情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されています。

MacHoundはBloodhoundデータベースにHasSessionとAdminToのエッジに加えて、**3つの新しいエッジ**を追加します：

* **CanSSH** - ホストへのSSHが許可されているエンティティ
* **CanVNC** - ホストへのVNCが許可されているエンティティ
* **CanAE** - ホストでAppleEventスクリプトを実行できるエンティティ
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
詳細は[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)を参照してください。

## キーチェーンへのアクセス

キーチェーンには、プロンプトを生成せずにアクセスすると、赤チームの演習を進めるのに役立つ可能性のある機密情報が含まれています。

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部サービス

MacOS Red Teamingは、通常のWindows Red Teamingとは異なり、**MacOSは通常、複数の外部プラットフォームと直接統合**されています。MacOSの一般的な設定は、**OneLoginと同期された資格情報を使用してコンピュータにアクセスし、OneLoginを介して複数の外部サービス**(github、awsなど)にアクセスすることです。

![](<../../.gitbook/assets/image (563).png>)

## その他のRed Teamテクニック

### Safari

Safariでファイルをダウンロードすると、それが「安全な」ファイルであれば、**自動的に開かれます**。例えば、**zipファイルをダウンロード**すると、自動的に展開されます。

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 参考文献

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksであなたの会社を宣伝したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
