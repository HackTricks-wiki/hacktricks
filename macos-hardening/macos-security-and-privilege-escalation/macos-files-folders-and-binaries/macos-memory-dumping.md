# macOS メモリダンプ

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの**会社を広告掲載したい場合や、**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## メモリアーティファクト

### スワップファイル

* **`/private/var/vm/swapfile0`**: 物理メモリがいっぱいになると、このファイルは**キャッシュとして使用されます**。物理メモリのデータはswapfileにプッシュされ、再び必要になった場合に物理メモリにスワップバックされます。ここには複数のファイルが存在する可能性があります。例えば、swapfile0、swapfile1などが見られるかもしれません。
*   **`/private/var/vm/sleepimage`**: OS Xが**休止状態**に入ると、メモリに保存されているデータはsleepimageファイルに置かれます。ユーザーが戻ってコンピュータを起動すると、メモリはsleepimageから復元され、ユーザーは中断したところから再開できます。

現代のMacOSシステムでは、このファイルはデフォルトで暗号化されているため、回復できない可能性があります。

* しかし、このファイルの暗号化は無効になっているかもしれません。`sysctl vm.swapusage`の出力を確認してください。

### osxpmemを使用したメモリダンプ

MacOSマシンのメモリをダンプするには、[**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)を使用できます。

**注意**: 以下の指示は、Intelアーキテクチャを搭載したMacでのみ機能します。このツールは現在アーカイブされており、最後のリリースは2017年でした。以下の指示でダウンロードされるバイナリは、2017年にはApple Siliconが存在しなかったため、Intelチップを対象としています。arm64アーキテクチャ用にバイナリをコンパイルすることは可能かもしれませんが、自分で試してみる必要があります。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
```bash
sudo chown -R root:wheel osxpmem.app
sudo chmod -R 755 osxpmem.app
sudo kextload osxpmem.app/MacPmem.kext
```
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**その他のエラー**は「セキュリティとプライバシー --> 一般」で**kextのロードを許可する**ことで修正されるかもしれません。ただ**許可**してください。

この**ワンライナー**を使用してアプリケーションをダウンロードし、kextをロードしてメモリをダンプすることもできます：

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
