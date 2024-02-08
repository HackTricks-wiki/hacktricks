# DDexec / EverythingExec

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するために、PRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに参加する。**

</details>

## コンテキスト

Linuxでは、プログラムを実行するためには、ファイルとして存在する必要があり、ファイルシステム階層を通じていかなる方法でもアクセス可能である必要があります（これは`execve()`が動作する方法です）。このファイルはディスク上にあるか、ram（tmpfs、memfd）にあるかもしれませんが、ファイルパスが必要です。これにより、Linuxシステムで実行されるものを制御することが非常に簡単になり、脅威や攻撃者のツールを検出したり、それらが自分たちのものを実行しようとするのを防止したりすることが簡単になります（たとえば、特権のないユーザーが実行可能ファイルをどこにでも配置することを許可しない）。

しかし、このテクニックはすべてを変えるためにここにあります。**希望のプロセスを開始できない場合は... すでに存在するプロセスを乗っ取ります**。

このテクニックにより、**読み取り専用、noexec、ファイル名のホワイトリスト、ハッシュのホワイトリストなどの一般的な保護技術をバイパス**できます。

## 依存関係

最終スクリプトは、以下のツールに依存して動作します。攻撃対象のシステムでこれらのツールにアクセスできる必要があります（デフォルトではどこでも見つけることができます）。
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
## テクニック

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは既存のプロセスを乗っ取り、別のプログラムで置き換えるために使用できます。これは、`ptrace()` シスコールを使用するか(`/proc/$pid/mem` に書き込むことで達成できます。

ファイル `/proc/$pid/mem` はプロセスのアドレス空間全体の1対1のマッピングです（例: x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）。これは、オフセット `x` でこのファイルから読み取るか書き込むことは、仮想アドレス `x` の内容を読み取るか変更することと同じです。

今、私たちは4つの基本的な問題に直面しています:

* 一般的に、ルートとファイルのプログラム所有者のみが変更できます。
* ASLR。
* プログラムのアドレス空間にマップされていないアドレスに読み取りまたは書き込みを試みると、I/O エラーが発生します。

これらの問題には、完璧ではないが良い解決策があります:

* ほとんどのシェルインタプリタは、子プロセスで継承されるファイルディスクリプタを作成することを許可します。私たちは、`mem` ファイルへの書き込み権限を持つ fd を作成できます... その fd を使用する子プロセスはシェルのメモリを変更できるようになります。
* ASLR は問題ではありません。プロセスのアドレス空間に関する情報を得るために、シェルの `maps` ファイルや procfs の他のファイルをチェックできます。
* したがって、ファイル上で `lseek()` を行う必要があります。シェルからこれを行うには、悪名高い `dd` を使用する必要があります。

### より詳細に

手順は比較的簡単で、理解するために専門知識は必要ありません:

* 実行したいバイナリとローダーを解析して、必要なマッピングを見つけます。その後、`execve()` の各呼び出しでカーネルが行う手順と大まかに同じ手順を実行する "シェル"コードを作成します:
* これらのマッピングを作成します。
* バイナリを読み込みます。
* 権限を設定します。
* 最後に、プログラムの引数でスタックを初期化し、ローダーが必要とする補助ベクトルを配置します。
* ローダーにジャンプし、残りの処理をさせます（プログラムが必要とするライブラリをロードします）。
* 実行中のプロセスが実行するシスコール後に戻るアドレスを `syscall` ファイルから取得します。
* その場所を上書きし、実行可能な状態になる場所に、私たちのシェルコードを上書きします（`mem` を介して書き込み不可のページを変更できます）。
* 実行したいプログラムをプロセスの stdin に渡します（"シェル"コードによって `read()` されます）。
* この時点で、プログラムをロードするために必要なライブラリをロードし、それにジャンプするかどうかはローダー次第です。

**ツールを確認する** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` の代替手段はいくつかありますが、その1つである `tail` は現在、`mem` ファイルを `lseek()` するためにデフォルトで使用されています（`dd` を使用する唯一の目的でした）。これらの代替手段は次のとおりです:
```bash
tail
hexdump
cmp
xxd
```
変数`SEEKER`を設定すると、使用するシーカーを変更できます。 例：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
もしスクリプトに実装されていない別の有効なシーカーを見つけた場合は、`SEEKER_ARGS`変数を設定して使用することができます:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
ブロックするんだ、EDR。

## 参考文献
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)で**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
