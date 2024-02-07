# macOS SIP

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングテクニックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリに。

</details>

## **基本情報**

macOS の **System Integrity Protection (SIP)** は、最も特権のあるユーザーでさえ、主要なシステムフォルダーに対して未承認の変更を行うことを防ぐよう設計されたメカニズムです。この機能は、保護された領域でのファイルの追加、変更、削除などのアクションを制限することで、システムの整合性を維持する上で重要な役割を果たします。SIP によって保護される主要なフォルダーには以下が含まれます:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIP の動作を規定するルールは、**`/System/Library/Sandbox/rootless.conf`** にある構成ファイルで定義されています。このファイル内では、アスタリスク (*) で始まるパスは、通常の厳格なSIP制限の例外として示されています。

以下は例です:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
このスニペットは、SIPが一般的に**`/usr`**ディレクトリを保護する一方で、特定のサブディレクトリ（`/usr/libexec/cups`、`/usr/local`、および`/usr/share/man`）では、そのパスの前にアスタリスク（*）が付いているため、変更が許可されていることを示しています。

ディレクトリやファイルがSIPによって保護されているかどうかを確認するには、**`ls -lOd`**コマンドを使用して、**`restricted`**または**`sunlnk`**フラグの存在を確認できます。例：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
この場合、**`sunlnk`** フラグは、`/usr/libexec/cups` ディレクトリそのものは**削除できない**ことを示していますが、その中のファイルは作成、変更、削除ができます。

一方、
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
ここでは、**`restricted`** フラグは `/usr/libexec` ディレクトリが SIP によって保護されていることを示しています。SIP で保護されたディレクトリでは、ファイルを作成、変更、削除することはできません。

さらに、ファイルに属性 **`com.apple.rootless`** 拡張 **属性** が含まれている場合、そのファイルも **SIP によって保護されます**。

**SIP は他の root アクションも制限**します:

* 信頼されていないカーネル拡張機能の読み込み
* Apple が署名したプロセスのタスクポートの取得
* NVRAM 変数の変更
* カーネルデバッグの許可

オプションは nvram 変数にビットフラグとして保持されます（Intel の場合は `csr-active-config`、ARM の場合はブートされたデバイスツリーから `lp-sip0` が読み取られます）。`csr.sh` で XNU ソースコード内のフラグを見つけることができます:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP ステータス

次のコマンドでシステムで SIP が有効になっているかどうかを確認できます:
```bash
csrutil status
```
必要であれば、SIP を無効にするには、コンピュータをリカバリモードで再起動する必要があります（起動時に Command+R を押します）、その後、次のコマンドを実行します：
```bash
csrutil disable
```
SIPを有効のままにしてデバッグ保護を削除したい場合は、次のようにします:
```bash
csrutil enable --without debug
```
### その他の制限

- **署名されていないカーネル拡張機能**（kext）の読み込みを禁止し、検証済みの拡張機能のみがシステムカーネルとやり取りすることを保証します。
- macOSシステムプロセスの**デバッグを防止**し、コアシステムコンポーネントを不正なアクセスや変更から保護します。
- dtraceなどのツールがシステムプロセスを検査するのを**防止**し、システムの運用の整合性をさらに保護します。

**[このトークでSIP情報について詳しく学ぶ](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## SIP バイパス

SIPをバイパスすることで、攻撃者は次のことができます：

- **ユーザーデータへのアクセス**：すべてのユーザーアカウントからメール、メッセージ、Safariの履歴などの機密ユーザーデータを読み取ることができます。
- **TCC バイパス**：TCC（透明性、同意、および制御）データベースを直接操作して、ウェブカメラ、マイク、およびその他のリソースへの不正なアクセスを許可することができます。
- **持続性の確立**：SIPで保護された場所にマルウェアを配置し、ルート権限でも削除できないようにします。これにはマルウェア除去ツール（MRT）を改ざんする可能性も含まれます。
- **カーネル拡張機能の読み込み**：追加の保護策があるものの、SIPをバイパスすると署名されていないカーネル拡張機能を読み込むプロセスが簡素化されます。

### インストーラーパッケージ

**Appleの証明書で署名されたインストーラーパッケージ**は、その保護をバイパスできます。これは、標準開発者によって署名されたパッケージでも、SIPで保護されたディレクトリを変更しようとするとブロックされることを意味します。

### 存在しないSIPファイル

1つの潜在的な抜け穴は、**`rootless.conf`で指定されたファイルが現在存在しない**場合、作成できることです。マルウェアはこれを利用してシステム上に**持続性を確立**する可能性があります。たとえば、`rootless.conf`にリストされているが存在しない場合、悪意のあるプログラムは`/System/Library/LaunchDaemons`に.plistファイルを作成することができます。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
権限 **`com.apple.rootless.install.heritable`** を使用するとSIPをバイパスできます
{% endhint %}

#### Shrootless

[**このブログ投稿からの研究者**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) は、macOSのシステムインテグリティ保護（SIP）メカニズムにおける 'Shrootless' 脆弱性を発見しました。この脆弱性は、**`system_installd`** デーモンを中心にしており、このデーモンには **`com.apple.rootless.install.heritable`** という権限があり、その子プロセスのいずれかがSIPのファイルシステム制限をバイパスできるようにします。

**`system_installd`** デーモンは、**Apple** によって署名されたパッケージ（.pkgファイル）をインストールします。

研究者たちは、Appleによって署名されたパッケージ（.pkgファイル）のインストール中に、**`system_installd`** がパッケージに含まれる **post-install** スクリプトを実行することを発見しました。これらのスクリプトはデフォルトのシェル **`zsh`** によって実行され、非対話モードでも存在する場合は **`/etc/zshenv`** ファイルからコマンドが自動的に実行されます。この動作は攻撃者によって悪用される可能性があります：悪意のある `/etc/zshenv` ファイルを作成し、**`system_installd` が `zsh` を起動するのを待つ**ことで、デバイス上で任意の操作を実行できます。

さらに、**`/etc/zshenv` はSIPバイパスだけでなく一般的な攻撃手法として使用できる**ことが発見されました。各ユーザープロファイルには `~/.zshenv` ファイルがあり、これは `/etc/zshenv` と同じように動作しますが、ルート権限は必要ありません。このファイルは、`zsh` が起動するたびにトリガーされる持続性メカニズムとして使用することができ、また特権昇格メカニズムとしても使用できます。管理者ユーザーが `sudo -s` または `sudo <command>` を使用してルートに昇格すると、`~/.zshenv` ファイルがトリガーされ、実質的にルートに昇格します。

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) では、同じ **`system_installd`** プロセスが **`/tmp` 内のSIPで保護されたランダムな名前のフォルダに post-install スクリプトを配置**していたため、悪用される可能性があることが発見されました。**`/tmp` そのものはSIPで保護されていない**ため、**仮想イメージをマウント**し、**インストーラー**がそこに **post-install スクリプトを配置**し、仮想イメージを **アンマウント**し、**すべてのフォルダを再作成**し、**ペイロードを実行する post-install スクリプト**を追加することが可能でした。

#### [fsck\_cs ユーティリティ](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`** が **シンボリックリンク** をたどる能力により、重要なファイルを破損させるように誤誘導される脆弱性が特定されました。具体的には、攻撃者が _`/dev/diskX`_ からファイル `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` へのリンクを作成しました。 _`/dev/diskX`_ 上で **`fsck_cs`** を実行すると、`Info.plist` が破損します。このファイルの整合性は、カーネル拡張機能の読み込みを制御するmacOSのSIP（システムインテグリティ保護）にとって重要です。破損すると、SIPのカーネル除外の管理能力が損なわれます。

この脆弱性を悪用するためのコマンドは次のとおりです：
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
この脆弱性の悪用には深刻な影響があります。通常、カーネル拡張機能のアクセス許可を管理する`Info.plist`ファイルが無効になります。これには、`AppleHWAccess.kext`など特定の拡張機能をブラックリストに登録できなくなることが含まれます。したがって、SIPの制御メカニズムが機能しなくなると、この拡張機能がロードされ、システムのRAMへの不正な読み取りおよび書き込みアクセスが許可されます。

#### [SIP保護されたフォルダーの上にマウントする](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP保護されたフォルダーに新しいファイルシステムをマウントして保護をバイパスする**ことが可能でした。
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [アップグレードバイパス（2016）](https://objective-see.org/blog/blog\_0x14.html)

システムは、`Install macOS Sierra.app`内の埋め込みインストーラーディスクイメージから起動するように設定されており、`bless`ユーティリティを使用してOSをアップグレードします。使用されるコマンドは次のとおりです：
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
プロセスのセキュリティは、攻撃者がブート前にアップグレードイメージ（`InstallESD.dmg`）を変更すると危険にさらされる可能性があります。この戦略は、動的ローダー（dyld）を悪意のあるバージョン（`libBaseIA.dylib`）で置き換えることを含みます。この置き換えにより、インストーラーが起動されるときに攻撃者のコードが実行されます。

攻撃者のコードは、アップグレードプロセス中に制御を取得し、システムがインストーラーを信頼していることを悪用します。攻撃は、`InstallESD.dmg`イメージをメソッドスイズリングを介して変更し、特に`extractBootBits`メソッドを標的とします。これにより、ディスクイメージが使用される前に悪意のあるコードを注入することが可能となります。

さらに、`InstallESD.dmg`内には、アップグレードコードのルートファイルシステムとして機能する`BaseSystem.dmg`があります。これに動的ライブラリを注入することで、悪意のあるコードがOSレベルのファイルを変更する能力を持つプロセス内で動作することが可能となり、システムの侵害の可能性が大幅に高まります。


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)でのこのトークでは、**SIP**をバイパスできる**`systemmigrationd`**が**bash**と**perl**スクリプトを実行し、**`BASH_ENV`**と**`PERL5OPT`**経由で悪用されることが示されています。

### **com.apple.rootless.install**

{% hint style="danger" %}
権限 **`com.apple.rootless.install`** はSIPをバイパスできます
{% endhint %}

権限 `com.apple.rootless.install` は、macOSにおけるSystem Integrity Protection（SIP）をバイパスすることができることが知られています。これは特に、[**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)に関連して言及されています。

この特定のケースでは、`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`にあるシステムXPCサービスがこの権限を持っています。これにより、関連するプロセスがSIPの制約を回避することが可能となります。さらに、このサービスにはセキュリティ対策を施さずにファイルを移動することを許可するメソッドが存在します。


## Sealed System Snapshots

Sealed System Snapshotsは、**macOS Big Sur（macOS 11）**で導入されたAppleの機能で、**System Integrity Protection（SIP）**メカニズムの一部として追加のセキュリティとシステムの安定性を提供するものです。これらは基本的にシステムボリュームの読み取り専用バージョンです。

以下は、より詳細な説明です：

1. **不変のシステム**：Sealed System SnapshotsはmacOSシステムボリュームを「不変」にし、変更できないようにします。これにより、セキュリティやシステムの安定性が危険にさらされる可能性のある権限なしまたは誤った変更を防ぎます。
2. **システムソフトウェアの更新**：macOSのアップデートやアップグレードをインストールすると、macOSは新しいシステムスナップショットを作成します。macOSの起動ボリュームは、**APFS（Apple File System）**を使用してこの新しいスナップショットに切り替えます。更新を適用するプロセス全体が安全かつ信頼性が高くなり、更新中に何か問題が発生した場合は常に前のスナップショットに戻ることができます。
3. **データの分離**：macOS Catalinaで導入されたデータとシステムボリュームの分離の概念と組み合わせて、Sealed System Snapshot機能は、すべてのデータと設定が別の「**Data**」ボリュームに保存されることを確認します。この分離により、データがシステムから独立しており、システムの更新プロセスが簡素化され、システムのセキュリティが向上します。

これらのスナップショットはmacOSによって自動的に管理され、APFSのスペース共有機能のおかげでディスク上の追加のスペースを取らずに済みます。また、これらのスナップショットは、システム全体のユーザーがアクセス可能なバックアップである**Time Machineスナップショット**とは異なります。

### スナップショットの確認

コマンド **`diskutil apfs list`** は、**APFSボリュームの詳細**とそのレイアウトをリストします：

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

前述の出力では、**ユーザーがアクセス可能な場所**が`/System/Volumes/Data`の下にマウントされていることがわかります。

さらに、**macOSシステムボリュームのスナップショット**は`/`にマウントされており、**封印されています**（OSによって暗号化されています）。したがって、SIPがバイパスされて変更された場合、**OSは起動しなくなります**。

また、**シールが有効になっていることを確認**することも可能です。
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、スナップショットディスクは**読み取り専用**としてマウントされます：
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学ぶ</summary>

HackTricksをサポートする他の方法：

- **会社をHackTricksで宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローする 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)
- **ハッキングトリックを共有する**には、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
