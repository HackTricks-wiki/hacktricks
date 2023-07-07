# DDexec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## コンテキスト

Linuxでは、プログラムを実行するためには、ファイルとして存在する必要があります。ファイルシステムの階層を通じていくつかの方法でアクセスできる必要があります（これは単に`execve()`が動作する方法です）。このファイルはディスク上に存在するか、ram（tmpfs、memfd）に存在するかもしれませんが、ファイルパスが必要です。これにより、Linuxシステムで実行されるものを制御することが非常に簡単になり、脅威や攻撃者のツールを検出したり、それらが自分自身の何かを実行しようとするのを防止したりすることが容易になります（例：特権のないユーザーが実行可能なファイルをどこにでも配置できないようにする）。

しかし、このテクニックはすべてを変えるためにここにあります。もし、あなたが実行したいプロセスを開始できない場合... **既に存在するプロセスを乗っ取ります**。

このテクニックにより、読み取り専用、noexec、ファイル名のホワイトリスト、ハッシュのホワイトリストなどの一般的な保護技術を**バイパス**することができます。

## 依存関係

最終的なスクリプトは、以下のツールに依存して動作します。攻撃対象のシステムでこれらのツールにアクセスできる必要があります（デフォルトでは、どこにでも見つけることができます）。
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## 技術

プロセスのメモリを任意に変更できる場合、それを乗っ取ることができます。これは既存のプロセスを乗っ取り、別のプログラムで置き換えるために使用することができます。これは、`ptrace()` シスコールを使用するか（シスコールの実行権限が必要であるか、またはシステムに gdb が利用可能である必要があります）、またはより興味深い方法として `/proc/$pid/mem` に書き込むことによって達成することができます。

ファイル `/proc/$pid/mem` は、プロセスのアドレス空間全体（たとえば x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）との一対一のマッピングです。これは、オフセット `x` でこのファイルから読み取るか書き込むことは、仮想アドレス `x` の内容を読み取るか変更することと同じです。

さて、私たちは解決しなければならない基本的な問題が4つあります：

* 一般的に、ルートとファイルのプログラム所有者のみがそれを変更できます。
* ASLR。
* プログラムのアドレス空間にマップされていないアドレスに読み書きしようとすると、I/O エラーが発生します。

これらの問題には、完璧ではないが良い解決策があります：

* ほとんどのシェルインタプリタは、子プロセスで継承されるファイルディスクリプタを作成することを許可します。私たちは、書き込み権限を持つ `mem` ファイルを指す fd を作成することができます... したがって、その fd を使用する子プロセスはシェルのメモリを変更することができます。
* ASLR は問題ではありません。プロセスの `maps` ファイルや procfs の他のファイルを調べることで、プロセスのアドレス空間に関する情報を得ることができます。
* したがって、ファイル上で `lseek()` を行う必要があります。シェルからは、悪名高い `dd` を使用しない限り、これは行えません。

### より詳細に

手順は比較的簡単で、理解するために専門知識は必要ありません：

* 実行したいバイナリとローダーを解析し、必要なマッピングを特定します。そして、カーネルが `execve()` を呼び出すたびに行うのとほぼ同じ手順を実行する "シェル" コードを作成します：
* マッピングを作成します。
* バイナリをそれらに読み込みます。
* 権限を設定します。
* 最後に、プログラムの引数でスタックを初期化し、ローダーが必要とする補助ベクターを配置します。
* ローダーにジャンプし、残りの処理を任せます（プログラムに必要なライブラリをロードします）。
* `syscall` ファイルから、シスコールの実行後にプロセスが戻るアドレスを取得します。
* その場所（実行可能な場所）を私たちのシェルコードで上書きします（`mem` を介して書き込み不可のページを変更できます）。
* 実行したいプログラムをプロセスの stdin に渡します（"シェル" コードによって `read()` されます）。
* この時点で、ローダーがプログラムのために必要なライブラリをロードし、それにジャンプするかどうかはローダー次第です。

**ツールは** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **をチェックしてください**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricks であなたの会社を宣伝したいですか？または、PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロードしたりしたいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見しましょう、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション

- [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) Discord グループ** に参加するか、[telegram グループ](https://t.me/peass) に参加するか、**Twitter** [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md) **@carlospolopm**（[**@hacktricks_live**](https://twitter.com/hacktricks_live)）をフォローしてください**

- **ハッキングのトリックを共有するには、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)** に PR を提出してください。

</details>
