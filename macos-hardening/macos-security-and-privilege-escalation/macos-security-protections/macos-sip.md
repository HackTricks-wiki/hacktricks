# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## **基本情報**

**System Integrity Protection (SIP)** は、macOSのセキュリティ技術であり、特定のシステムディレクトリを未承認のアクセスから保護します。これには、ルートユーザーでもこれらのディレクトリへの変更、ファイルの作成、変更、削除が含まれます。SIPが保護する主なディレクトリは次のとおりです：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

これらのディレクトリおよびサブディレクトリの保護ルールは、**`/System/Library/Sandbox/rootless.conf`** ファイルで指定されています。このファイルでは、アスタリスク（\*）で始まるパスは、SIPの制限の例外を表します。

たとえば、次の設定：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
次のように示されています。**`/usr`** ディレクトリは一般的にSIPによって保護されています。ただし、3つのサブディレクトリ（`/usr/libexec/cups`、`/usr/local`、および`/usr/share/man`）では変更が許可されており、先頭にアスタリスク（\*）が付いてリストされています。

ディレクトリやファイルがSIPによって保護されているかどうかを確認するには、**`ls -lOd`** コマンドを使用して **`restricted`** または **`sunlnk`** フラグの存在をチェックできます。例えば:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
この場合、**`sunlnk`** フラグは、`/usr/libexec/cups` ディレクトリ自体は**削除できない**ことを示していますが、その中のファイルは作成、変更、削除が可能です。

一方、
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
ここでは、**`restricted`** フラグは `/usr/libexec` ディレクトリがSIPによって保護されていることを示しています。SIPで保護されたディレクトリでは、ファイルの作成、変更、削除ができません。

### SIPの状態

次のコマンドを使用して、システムでSIPが有効かどうかを確認できます。
```bash
csrutil status
```
SIPを無効にする必要がある場合は、コンピュータをリカバリーモードで再起動する必要があります（起動時にCommand+Rを押します）。その後、次のコマンドを実行してください：
```bash
csrutil disable
```
SIPを有効にしたままデバッグ保護を削除したい場合は、次の手順で行うことができます。
```bash
csrutil enable --without debug
```
### その他の制限

SIPは他にもいくつかの制限を課しています。たとえば、**署名されていないカーネル拡張（kexts）の読み込み**を禁止し、macOSシステムプロセスの**デバッグ**を防止します。また、dtraceのようなツールがシステムプロセスを検査するのを妨げます。

## SIPの回避方法

### 価格

攻撃者がSIPを回避することに成功した場合、以下のことが得られます：

* すべてのユーザーのメール、メッセージ、Safariの履歴などを読むことができる
* ウェブカメラ、マイクなどの許可を付与することができる（SIPで保護されたTCCデータベースに直接書き込むことにより）
* 永続性：SIPで保護された場所にマルウェアを保存し、誰も削除することができなくなります。また、MRTを改ざんすることもできます。
* カーネル拡張の簡単な読み込み（これには他の厳格な保護策もあります）。

### インストーラーパッケージ

**Appleの証明書で署名されたインストーラーパッケージ**は、SIPの保護を回避することができます。これは、標準の開発者によって署名されたパッケージでも、SIPで保護されたディレクトリを変更しようとする場合にはブロックされます。

### 存在しないSIPファイル

潜在的な抜け穴の1つは、**`rootless.conf`に指定されたファイルが現在存在しない場合**、作成することができるというものです。マルウェアはこれを利用してシステム上で**永続性を確立**することができます。たとえば、悪意のあるプログラムが`rootless.conf`にリストされているが存在しない場合、`/System/Library/LaunchDaemons`に.plistファイルを作成することができます。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
権限 **`com.apple.rootless.install.heritable`** はSIPを回避することができます
{% endhint %}

[**このブログポストの研究者たち**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)は、macOSのシステム整合性保護（SIP）メカニズムである「Shrootless」という脆弱性を発見しました。この脆弱性は、**`system_installd`**デーモンに関連しており、**`com.apple.rootless.install.heritable`**という権限を持っています。この権限により、**`system_installd`**の子プロセスはSIPのファイルシステム制限を回避することができます。

**`system_installd`**デーモンは、**Apple**によって署名されたパッケージをインストールします。

研究者たちは、Appleによって署名されたパッケージ（.pkgファイル）のインストール中に、パッケージに含まれる**post-install**スクリプトが**`system_installd`**によって実行されることを発見しました。これらのスクリプトはデフォルトのシェルである**`zsh`**によって実行され、非対話モードでも**`/etc/zshenv`**ファイルからコマンドが自動的に実行されます。この動作は攻撃者によって悪用される可能性があります。悪意のある`/etc/zshenv`ファイルを作成し、**`system_installd`が`zsh`を呼び出すのを待つ**ことで、デバイス上で任意の操作を実行することができます。

さらに、**`/etc/zshenv`はSIPの回避だけでなく、一般的な攻撃手法としても使用できます**。各ユーザープロファイルには`~/.zshenv`ファイルがあり、これは`/etc/zshenv`と同じように動作しますが、ルート権限は必要ありません。このファイルは、`zsh`が起動するたびにトリガーされる永続性のメカニズムとして、または特権の昇格のメカニズムとして使用することができます。管理者ユーザーが`sudo -s`または`sudo <command>`を使用してルートに昇格する場合、`~/.zshenv`ファイルがトリガーされ、実質的にルートに昇格します。

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)では、同じ**`system_installd`**プロセスが悪用される可能性があることが発見されました。なぜなら、**post-installスクリプトが`/tmp`内のSIPで保護されたランダムに名前が付けられたフォルダに配置されていた**からです。ただし、**`/tmp`自体はSIPで保護されていない**ため、**仮想イメージをマウント**することが可能であり、その後、**インストーラー**が**post-installスクリプト**をそこに配置し、**仮想イメージをアンマウント**し、**すべてのフォルダを再作成**し、**ペイロード**を実行するための**post-installationスクリプト**を追加することができました。

### **com.apple.rootless.install**

{% hint style="danger" %}
権限 **`com.apple.rootless.install`** はSIPを回避することができます
{% endhint %}

[**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)では、システムのXPCサービスである`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc`には、**`com.apple.rootless.install`**という権限があり、プロセスにSIPの制限を回避する権限を与えます。また、**セキュリティチェックなしでファイルを移動する**ためのメソッドを公開しています。

## シールドされたシステムスナップショット

シールドされたシステムスナップショットは、Appleが**macOS Big Sur（macOS 11）**で導入した機能であり、**システム整合性保護（SIP）**メカニズムの一部として、追加のセキュリティとシステムの安定性を提供するためのものです。これらは、システムボリュームの読み取り専用バージョンです。

以下に詳細を示します：

1. **不変のシステム**：シールドされたシステムスナップショットにより、macOSシステムボリュームは「不変」となり、変更することができなくなります。これにより、セキュリティやシステムの安定性に影響を及ぼす可能性のある、不
|   |   スナップショット:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   スナップショットディスク:             disk3s1s1
<strong>|   |   スナップショットマウントポイント:      /
</strong><strong>|   |   スナップショットシールド:           はい
</strong>[...]
+-> ボリューム disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFSボリュームディスク（役割）:   disk3s5（データ）
|   名前:                      Macintosh HD - Data（大文字と小文字を区別しない）
<strong>    |   マウントポイント:               /System/Volumes/Data
</strong><strong>    |   使用済み容量:         412071784448 B（412.1 GB）
</strong>    |   シールド:                    いいえ
|   FileVault:                 はい（ロック解除済み）
</code></pre>

前の出力では、**ユーザーがアクセス可能な場所**が`/System/Volumes/Data`の下にマウントされていることがわかります。

さらに、**macOSシステムボリュームのスナップショット**は`/`にマウントされており、**シールド**（OSによって暗号的に署名されている）されています。したがって、SIPがバイパスされて変更された場合、**OSは起動しなくなります**。

また、シールドが有効であることを**確認する**には、次のコマンドを実行します：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、スナップショットディスクは**読み取り専用**としてマウントされます。
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
