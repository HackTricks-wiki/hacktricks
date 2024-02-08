# macOSメモリーダンピング

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
- **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、**あなたのハッキングテクニックを共有**してください。

</details>

## メモリーアーティファクト

### スワップファイル

`/private/var/vm/swapfile0`などのスワップファイルは、**物理メモリがいっぱいのときのキャッシュ**として機能します。物理メモリにもう余裕がない場合、そのデータはスワップファイルに転送され、必要に応じて物理メモリに戻されます。swapfile0、swapfile1などの名前で複数のスワップファイルが存在する可能性があります。

### ハイバネーションイメージ

`/private/var/vm/sleepimage`にあるファイルは、**ハイバネーションモード**中に重要です。**OS Xが休止状態になるときにメモリからのデータがこのファイルに保存**されます。コンピューターを起動するとき、システムはこのファイルからメモリデータを取得し、ユーザーが前回終了したところから続行できるようにします。

現代のMacOSシステムでは、セキュリティ上の理由からこのファイルが通常暗号化されているため、回復が難しいことに注意してください。

- sleepimageの暗号化が有効かどうかを確認するには、`sysctl vm.swapusage`コマンドを実行します。これにより、ファイルが暗号化されているかどうかが表示されます。

### メモリープレッシャーログ

MacOSシステムのもう1つの重要なメモリ関連ファイルは**メモリープレッシャーログ**です。これらのログは`/var/log`にあり、システムのメモリ使用状況やプレッシャーイベントに関する詳細な情報を含んでいます。これらは、メモリ関連の問題の診断やシステムが時間の経過とともにメモリをどのように管理しているかを理解するのに特に役立ちます。

## osxpmemを使用したメモリーダンプ

MacOSマシンでメモリをダンプするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)を使用できます。

**注意**: 以下の手順は、Intelアーキテクチャを搭載したMacでのみ機能します。このツールは現在アーカイブされており、最後のリリースは2017年に行われました。以下の手順でダウンロードしたバイナリは、Apple Siliconが2017年には存在しなかったため、Intelチップをターゲットにしています。arm64アーキテクチャ向けにバイナリをコンパイルすることも可能かもしれませんが、自分で試してみる必要があります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
もし次のエラーが見つかった場合：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 、次の手順で修正できます：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**その他のエラー**は、「セキュリティとプライバシー --> 一般」で**kextの読み込みを許可**することで修正できるかもしれません。単に**許可**してください。

また、この**ワンライナー**を使用してアプリケーションをダウンロードし、kextをロードしてメモリをダンプすることもできます：

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
