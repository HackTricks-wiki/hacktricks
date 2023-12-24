# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## **基本情報**

**System Integrity Protection (SIP)** は、macOSのセキュリティ技術で、rootユーザーであっても、特定のシステムディレクトリへの不正アクセスを防ぎます。これにより、これらのディレクトリへの変更、ファイルの作成、変更、削除が防止されます。SIPが保護する主なディレクトリは以下の通りです：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

これらのディレクトリとそのサブディレクトリの保護ルールは、**`/System/Library/Sandbox/rootless.conf`** ファイルで指定されています。このファイル内で、アスタリスク（\*）で始まるパスは、SIPの制限の例外を表しています。

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
```
csrutil disable
```
```bash
csrutil disable
```
SIPを有効にしたままデバッグ保護を解除するには、次の操作を行います:
```bash
csrutil enable --without debug
```
### その他の制限

SIPは、**未署名のカーネル拡張**（kexts）のロードを禁止し、macOSシステムプロセスの**デバッグ**を防ぎます。また、dtraceなどのツールがシステムプロセスを検査するのを妨げます。

[このトークでのSIPの詳細情報](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)。

## SIPバイパス

攻撃者がSIPをバイパスすると、以下のことが可能になります：

* すべてのユーザーのメール、メッセージ、Safariの履歴などを読む
* ウェブカメラ、マイクなどの権限を付与する（SIP保護されたTCCデータベースに直接書き込むことで） - TCCバイパス
* 永続性：マルウェアをSIP保護された場所に保存し、rootでさえ削除できない。また、MRTを改ざんすることもできる。
* カーネル拡張をロードする容易さ（それでもこのための他のハードコアな保護が存在します）。

### インストーラーパッケージ

**Appleの証明書で署名されたインストーラーパッケージ**は、その保護をバイパスできます。つまり、標準の開発者によって署名されたパッケージでも、SIP保護ディレクトリを変更しようとするとブロックされます。

### 存在しないSIPファイル

潜在的な抜け穴の一つは、**`rootless.conf`に指定されているが現在存在しない**ファイルを作成することができるということです。マルウェアはこれを利用してシステム上で**永続性を確立**することができます。例えば、悪意のあるプログラムが`/System/Library/LaunchDaemons`に.plistファイルを作成することができる場合、それが`rootless.conf`にリストされているが存在しない場合です。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
エンタイトルメント**`com.apple.rootless.install.heritable`**はSIPをバイパスすることを許可します
{% endhint %}

#### Shrootless

[**このブログ投稿の研究者たち**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)は、macOSのシステムインテグリティプロテクション（SIP）メカニズムにおける脆弱性を発見しました。この脆弱性は'Shrootless'と名付けられ、**`system_installd`**デーモンを中心にしています。このデーモンは、エンタイトルメント**`com.apple.rootless.install.heritable`**を持っており、これにより子プロセスがSIPのファイルシステム制限をバイパスできます。

**`system_installd`**デーモンは、**Apple**によって署名されたパッケージをインストールします。

研究者たちは、Appleに署名されたパッケージ（.pkgファイル）のインストール中に、**`system_installd`**がパッケージに含まれる**ポストインストール**スクリプトを**実行**することを発見しました。これらのスクリプトはデフォルトのシェルである**`zsh`**によって実行され、**`zsh`**は非対話モードでも存在する場合、自動的に**`/etc/zshenv`**ファイルからコマンドを**実行**します。攻撃者はこの挙動を悪用する可能性があります：悪意のある`/etc/zshenv`ファイルを作成し、**`system_installd`が`zsh`を呼び出すのを待つ**ことで、デバイス上で任意の操作を実行できます。

さらに、**`/etc/zshenv`はSIPバイパスだけでなく、一般的な攻撃手法として使用できる**ことが発見されました。各ユーザープロファイルには`~/.zshenv`ファイルがあり、これは`/etc/zshenv`と同じように動作しますが、root権限は必要ありません。このファイルは、`zsh`が起動するたびにトリガーされる永続性メカニズムとして、または権限昇格メカニズムとして使用できます。管理ユーザーが`sudo -s`または`sudo <command>`を使用してrootに昇格する場合、`~/.zshenv`ファイルがトリガーされ、効果的にrootに昇格します。

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)では、**`system_installd`**プロセスが依然として悪用される可能性があることが発見されました。それは、**ポストインストールスクリプトをSIPによって保護されたランダムな名前のフォルダ内の`/tmp`に配置**していました。問題は、**`/tmp`自体はSIPによって保護されていない**ため、**仮想イメージをそれにマウント**することが可能であり、その後**インストーラー**がそこに**ポストインストールスクリプト**を配置し、仮想イメージを**アンマウント**し、すべての**フォルダ**を**再作成**し、**実行**する**ペイロード**を含む**ポストインストール**スクリプトを**追加**することができました。

#### [fsck\_csユーティリティ](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

このバイパスは、**`fsck_cs`**が**シンボリックリンク**をたどり、それに提示されたファイルシステムを修正しようとする事実を利用していました。

したがって、攻撃者は_`/dev/diskX`_から`/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`へのシンボリックリンクを作成し、前者に対して**`fsck_cs`**を呼び出すことができます。`Info.plist`ファイルが破損すると、オペレーティングシステムは**カーネル拡張の除外を制御できなくなり**、その結果SIPをバイパスします。

{% code overflow="wrap" %}
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
{% endcode %}

前述のInfo.plistファイルは、**SIPによって一部のカーネル拡張をホワイトリストに登録し、特定の他の拡張をロードから** **ブロック**するために使用されます。通常、Apple自身のカーネル拡張**`AppleHWAccess.kext`**をブラックリストに登録しますが、設定ファイルが破壊されたことで、システムRAMへの読み書きを自由に行うためにロードして使用することができます。

#### [SIP保護フォルダ上にマウントする](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP保護フォルダ上に新しいファイルシステムをマウントして保護をバイパスする**ことが可能でした。
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [アップグレーダーのバイパス (2016)](https://objective-see.org/blog/blog\_0x14.html)

実行されると、アップグレード/インストーラーアプリケーション（例：`Install macOS Sierra.app`）は、ダウンロードされたアプリケーション内に埋め込まれたインストーラーディスクイメージからシステムをブートするように設定します。このインストーラーディスクイメージには、例えばOS X El CapitanからmacOS SierraへのOSをアップグレードするためのロジックが含まれています。

アップグレード/インストーラーイメージ（`InstallESD.dmg`）からシステムをブートするために、`Install macOS Sierra.app`は**`bless`**ユーティリティ（エンタイトルメント`com.apple.rootless.install.heritable`を継承）を利用します：

{% code overflow="wrap" %}
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
{% endcode %}

したがって、攻撃者がシステムがそれから起動する前にアップグレードイメージ（`InstallESD.dmg`）を変更できれば、SIPをバイパスできます。

イメージを感染させる方法は、アプリケーションのコンテキストで悪意のあるdylibを素朴にロードして実行する動的ローダー（dyld）を置き換えることでした。例えば**`libBaseIA`** dylibのように。したがって、ユーザーがインストーラーアプリケーションを起動するたびに（例えばシステムをアップグレードするために）、私たちの悪意のあるdylib（libBaseIA.dylibと名付けられた）もインストーラーでロードされ、実行されます。

今やインストーラーアプリケーションの'内部'で、私たちはこのアップグレードプロセスのフェーズを制御できます。インストーラーがイメージを'祝福'するので、私たちがしなければならないのは、それが使用される前にイメージ、**`InstallESD.dmg`**、を乗っ取ることです。これは、**`extractBootBits`** メソッドをメソッドスウィズリングでフックすることで可能でした。
悪意のあるコードがディスクイメージが使用される直前に実行されるので、それを感染させる時が来ました。

`InstallESD.dmg`の中には、アップグレードコードの'ルートファイルシステム'である別の埋め込みディスクイメージ`BaseSystem.dmg`があります。`BaseSystem.dmg`に動的ライブラリを注入することで、OSレベルのファイルを変更できるプロセスのコンテキスト内で悪意のあるコードが実行されます。

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)でのこのトークでは、SIPをバイパスできる**`systemmigrationd`**が**bash**と**perl**スクリプトを実行し、環境変数**`BASH_ENV`**と**`PERL5OPT`**を介して悪用される可能性が示されています。

### **com.apple.rootless.install**

{% hint style="danger" %}
権限**`com.apple.rootless.install`**はSIPをバイパスすることを許可します
{% endhint %}

[**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)から、システムXPCサービス`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`は権限**`com.apple.rootless.install`**を持っており、プロセスがSIP制限をバイパスする許可を与えます。また、**セキュリティチェックなしにファイルを移動するメソッドを公開しています。**

## Sealed System Snapshots

Sealed System Snapshotsは、Appleが**macOS Big Sur (macOS 11)**で導入した機能で、**System Integrity Protection (SIP)**メカニズムの一部として追加のセキュリティとシステム安定性を提供するためです。これらは、システムボリュームの読み取り専用バージョンです。

詳細については以下の通りです：

1. **不変のシステム**: Sealed System SnapshotsはmacOSシステムボリュームを「不変」とし、変更できないようにします。これにより、セキュリティやシステム安定性を損なう可能性のある不正な変更や偶発的な変更を防ぎます。
2. **システムソフトウェアアップデート**: macOSのアップデートやアップグレードをインストールすると、macOSは新しいシステムスナップショットを作成します。その後、macOSスタートアップボリュームは**APFS (Apple File System)**を使用してこの新しいスナップショットに切り替えます。アップデートの適用プロセス全体がより安全で信頼性が高くなり、アップデート中に何か問題が発生した場合、システムは常に前のスナップショットに戻ることができます。
3. **データの分離**: macOS Catalinaで導入されたデータとシステムボリュームの分離の概念と連動して、Sealed System Snapshot機能は、すべてのデータと設定が別の「**Data**」ボリュームに保存されることを確実にします。この分離により、データはシステムから独立し、システムアップデートのプロセスが簡素化され、システムのセキュリティが向上します。

これらのスナップショットはmacOSによって自動的に管理され、APFSのスペース共有機能のおかげでディスク上に追加のスペースを取らないことを覚えておいてください。また、これらのスナップショットは**Time Machineスナップショット**とは異なることに注意してください。これらはユーザーがアクセス可能なシステム全体のバックアップです。

### スナップショットの確認

コマンド**`diskutil apfs list`**は**APFSボリュームの詳細**とそのレイアウトをリストします：

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
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

前述の出力では、**ユーザーがアクセス可能な場所**が`/System/Volumes/Data`にマウントされていることがわかります。

さらに、**macOSシステムボリュームスナップショット**は`/`にマウントされ、**シールされています**（OSによって暗号的に署名されています）。したがって、SIPがバイパスされてそれを変更すると、**OSはもう起動しません**。

シールが有効であることを**確認する**には、次のコマンドを実行します：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、スナップショットディスクも**読み取り専用**としてマウントされています：
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
