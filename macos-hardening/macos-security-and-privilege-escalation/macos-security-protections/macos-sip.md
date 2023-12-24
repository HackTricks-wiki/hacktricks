# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## **基本情報**

**System Integrity Protection (SIP)** は、macOSのセキュリティ技術で、rootユーザーであっても、特定のシステムディレクトリへの不正アクセスを防ぎます。これにより、ファイルの作成、変更、削除を含むこれらのディレクトリへの変更が防止されます。SIPが保護する主なディレクトリは以下の通りです：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

これらのディレクトリとそのサブディレクトリの保護ルールは、**`/System/Library/Sandbox/rootless.conf`** ファイルで指定されています。このファイル内で、アスタリスク（\*）で始まるパスはSIPの制限の例外を表しています。

例えば、以下の設定：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
**`/usr`** ディレクトリは一般的にSIPによって保護されています。ただし、リストに先行するアスタリスク (\*) が付いている三つのサブディレクトリ（`/usr/libexec/cups`、`/usr/local`、`/usr/share/man`）については変更が許可されています。

ディレクトリやファイルがSIPによって保護されているかどうかを確認するには、**`ls -lOd`** コマンドを使用して **`restricted`** や **`sunlnk`** フラグの存在をチェックします。例えば：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
この場合、**`sunlnk`** フラグは `/usr/libexec/cups` ディレクトリ自体が**削除できない**ことを意味していますが、その中のファイルは作成、変更、または削除することができます。

一方で：
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
以下は、**`restricted`** フラグが `/usr/libexec` ディレクトリがSIPによって保護されていることを示しています。SIPで保護されたディレクトリでは、ファイルを作成、変更、または削除することはできません。

さらに、ファイルに **`com.apple.rootless`** 拡張 **属性** が含まれている場合、そのファイルも **SIPによって保護されます**。

**SIPは他のrootアクションも制限します** 例えば：

* 信頼されていないカーネル拡張のロード
* Appleによって署名されたプロセスのタスクポートの取得
* NVRAM変数の変更
* カーネルデバッグの許可

オプションはnvram変数にビットフラグとして保持されます（Intelでは `csr-active-config`、ARMでは起動したデバイスツリーから `lp-sip0` が読み取られます）。フラグはXNUソースコードの `csr.sh` で見つけることができます：

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIPのステータス

SIPがシステムで有効かどうかは、以下のコマンドで確認できます：
```bash
csrutil status
```
コンピュータをリカバリーモードで再起動する必要があります（起動中にCommand+Rを押す）、その後、以下のコマンドを実行します：
```bash
csrutil disable
```
SIPを有効にしたままデバッグ保護を解除するには、次の操作を行います:
```bash
csrutil enable --without debug
```
### その他の制限

SIPは、**未署名のカーネル拡張（kexts）のロード**やmacOSシステムプロセスの**デバッグ**を禁止するなど、いくつかの追加的な制限を課しています。また、dtraceなどのツールがシステムプロセスを検査することも阻止します。

## SIPバイパス

攻撃者がSIPをバイパスすると、以下のことが可能になります：

* 全ユーザーのメール、メッセージ、Safariの履歴などを読む
* ウェブカメラ、マイクなどの権限を付与する（SIP保護されたTCCデータベースを直接書き換えることによって）
* 永続性：マルウェアをSIP保護された場所に保存し、rootでさえ削除できない。また、MRTを改ざんすることも可能。
* カーネル拡張をロードする容易さ（それでも他の強固な保護が適用されています）。

### インストーラーパッケージ

**Appleの証明書で署名されたインストーラーパッケージ**は、その保護をバイパスできます。つまり、標準の開発者によって署名されたパッケージであっても、SIP保護ディレクトリを変更しようとするとブロックされます。

### 存在しないSIPファイル

潜在的な抜け穴の一つは、**`rootless.conf`に指定されているが現在存在しない**ファイルを作成できることです。マルウェアはこれを利用してシステム上で**永続性を確立**することができます。例えば、悪意のあるプログラムが`/System/Library/LaunchDaemons`に.plistファイルを作成することができます（`rootless.conf`にリストされているが存在しない場合）。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
エンタイトルメント**`com.apple.rootless.install.heritable`**はSIPをバイパスすることを許可します
{% endhint %}

[**このブログ投稿の研究者たち**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)は、macOSのシステムインテグリティプロテクション（SIP）メカニズムにおける脆弱性を発見しました。この脆弱性は'Shrootless'と名付けられ、**`system_installd`**デーモンを中心にしています。このデーモンには、**`com.apple.rootless.install.heritable`**というエンタイトルメントがあり、子プロセスがSIPのファイルシステム制限をバイパスすることを許可します。

**`system_installd`**デーモンは、**Apple**によって署名されたパッケージをインストールします。

研究者たちは、Appleに署名されたパッケージ（.pkgファイル）のインストール中に、**`system_installd`**がパッケージに含まれる**ポストインストール**スクリプトを**実行**することを発見しました。これらのスクリプトはデフォルトのシェルである**`zsh`**によって実行され、**`zsh`**は非対話モードでも存在する場合は自動的に**`/etc/zshenv`**ファイルからコマンドを**実行**します。攻撃者はこの挙動を悪用する可能性があります：悪意のある`/etc/zshenv`ファイルを作成し、**`system_installd`が`zsh`を起動するのを待つ**ことで、デバイス上で任意の操作を実行することができます。

さらに、**`/etc/zshenv`はSIPバイパスだけでなく、一般的な攻撃手法として使用できる**ことが発見されました。各ユーザープロファイルには`~/.zshenv`ファイルがあり、`/etc/zshenv`と同じように動作しますが、root権限は必要ありません。このファイルは、`zsh`が起動するたびにトリガーされる永続性メカニズムとして、または権限昇格メカニズムとして使用できます。管理ユーザーが`sudo -s`または`sudo <command>`を使用してrootに昇格する場合、`~/.zshenv`ファイルがトリガーされ、効果的にrootに昇格します。

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)では、同じ**`system_installd`**プロセスが、**`/tmp`内のSIPによって保護されたランダムな名前のフォルダ内にポストインストールスクリプトを置く**ことでまだ悪用され得ることが発見されました。問題は、**`/tmp`自体はSIPによって保護されていない**ため、**仮想イメージをそれに**マウント**することが可能であり、**インストーラー**はそこに**ポストインストールスクリプト**を置き、仮想イメージを**アンマウント**し、**フォルダー**を**再作成**して、**実行**する**ペイロード**を含む**ポストインストール**スクリプトを**追加**することができました。

### **com.apple.rootless.install**

{% hint style="danger" %}
エンタイトルメント**`com.apple.rootless.install`**はSIPをバイパスすることを許可します
{% endhint %}

[**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)から、システムXPCサービス`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`には、SIPの制限をバイパスする権限をプロセスに付与する**`com.apple.rootless.install`**というエンタイトルメントがあります。また、セキュリティチェックなしにファイルを移動するメソッドも**公開しています。**

## シールドシステムスナップショット

シールドシステムスナップショットは、Appleが**macOS Big Sur（macOS 11）**で導入した、**システムインテグリティプロテクション（SIP）**メカニズムの一部として追加された機能で、セキュリティとシステムの安定性をさらに向上させるためのものです。これらは、基本的にシステムボリュームの読み取り専用バージョンです。

詳細は以下の通りです：

1. **不変のシステム**：シールドシステムスナップショットはmacOSシステムボリュームを「不変」とし、変更できないようにします。これにより、セキュリティやシステムの安定性を損なう可能性のある不正な変更や偶発的な変更を防ぎます。
2. **システムソフトウェアのアップデート**：macOSのアップデートやアップグレードをインストールすると、macOSは新しいシステムスナップショットを作成します。その後、macOSのスタートアップボリュームは**APFS（Appleファイルシステム）**を使用してこの新しいスナップショットに切り替えます。アップデートの適用プロセス全体がより安全で信頼性が高くなり、アップデート中に何か問題が発生した場合には常に前のスナップショットに戻ることができます。
3. **データの分離**：macOS Catalinaで導入されたデータとシステムボリュームの分離の概念と連動して、シールドシステムスナップショット機能は、すべてのデータと設定が別の「**データ**」ボリュームに保存されることを確実にします。この分離により、データはシステムから独立し、システムアップデートのプロセスが簡素化され、システムのセキュリティが向上します。

これらのスナップショットはmacOSによって自動的に管理され、APFSのスペース共有機能のおかげでディスク上に追加のスペースを取らないことを覚えておいてください。また、これらのスナップショットは**Time Machineスナップショット**とは異なることに注意してください。これらはユーザーがアクセス可能なシステム全体のバックアップです。

### スナップショットの確認

コマンド**`diskutil apfs list`**は、**APFSボリュームの詳細**とそのレイアウトをリストします：

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
<pre><code>|   |   スナップショット:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   スナップショットディスク:             disk3s1s1
<strong>|   |   スナップショットマウントポイント:      /
</strong><strong>|   |   スナップショットシールド:           はい
</strong>[...]
+-> ボリューム disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFSボリュームディスク (役割):   disk3s5 (データ)
|   名前:                      Macintosh HD - データ (大文字小文字を区別しない)
<strong>    |   マウントポイント:               /System/Volumes/Data
</strong><strong>    |   使用容量:         412071784448 B (412.1 GB)
</strong>    |   シールド:                    いいえ
|   FileVault:                 はい (アンロック済み)
</code></pre>

前の出力では、**ユーザーがアクセス可能な場所**が `/System/Volumes/Data` にマウントされていることがわかります。

さらに、**macOSシステムボリュームスナップショット**は `/` にマウントされ、**シールド**されています（OSによって暗号的に署名されています）。そのため、SIPがバイパスされて変更された場合、**OSはもう起動しなくなります**。

また、シールが有効かどうかを確認するには、以下のコマンドを実行します：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、スナップショットディスクは**読み取り専用**としてマウントされています：
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか、または**最新版のPEASSを入手**したり**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。**

</details>
