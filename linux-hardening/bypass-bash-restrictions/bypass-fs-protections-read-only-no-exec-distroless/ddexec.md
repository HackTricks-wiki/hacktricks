# DDexec / EverythingExec

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## コンテキスト

Linuxでは、プログラムを実行するためには、ファイルとして存在し、ファイルシステム階層を通じて何らかの方法でアクセス可能である必要があります（これは`execve()`の動作方法です）。このファイルはディスク上にあるか、またはram（tmpfs、memfd）にあるが、ファイルパスが必要です。これにより、Linuxシステム上で実行されるものを制御することが非常に簡単になり、脅威や攻撃者のツールを検出することが容易になるか、または彼らが自分たちのものを一切実行しようとすることを防ぐことができます（例えば、特権のないユーザーが実行可能なファイルをどこにも配置できないようにする）。

しかし、このテクニックはこれをすべて変えるためにここにあります。もし、あなたが望むプロセスを開始できない場合は... **既に存在するプロセスをハイジャックします**。

このテクニックにより、読み取り専用、noexec、ファイル名ホワイトリスト、ハッシュホワイトリストなどの一般的な保護技術を**バイパスすることができます**。

## 依存関係

最終的なスクリプトは、攻撃対象のシステムでアクセス可能である必要がある以下のツールに依存しています（デフォルトでは、これらはどこにでもあります）：
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

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは、既存のプロセスをハイジャックして別のプログラムに置き換えるために使用できます。これは、`ptrace()` システムコールを使用するか（これにはシステムコールを実行する能力があるか、システムに gdb が利用可能である必要があります）、もっと興味深いことに、`/proc/$pid/mem` に書き込むことで実現できます。

ファイル `/proc/$pid/mem` はプロセスのアドレス空間全体の一対一のマッピングです（例えば、x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）。これは、オフセット `x` でこのファイルを読み書きすることは、仮想アドレス `x` の内容を読み取るか変更するのと同じであることを意味します。

現在、私たちは4つの基本的な問題に直面しています：

* 一般的に、ファイルを変更できるのは root とプログラムの所有者だけです。
* ASLR。
* プログラムのアドレス空間にマップされていないアドレスに読み書きしようとすると、I/O エラーが発生します。

これらの問題には解決策がありますが、完璧ではありませんが良いものです：

* ほとんどのシェルインタープリタは、子プロセスに継承されるファイルディスクリプタの作成を許可します。書き込み権限を持つシェルの `mem` ファイルを指す fd を作成することができます... そのため、その fd を使用する子プロセスはシェルのメモリを変更できるようになります。
* ASLR は問題ではありません。プロセスのアドレス空間に関する情報を得るために、シェルの `maps` ファイルや procfs の他のファイルをチェックすることができます。
* したがって、ファイル上で `lseek()` を行う必要があります。シェルからは、悪名高い `dd` を使用しない限り、これを行うことはできません。

### 詳細について

手順は比較的簡単で、理解するための専門知識は必要ありません：

* 実行したいバイナリとローダーを解析して、必要なマッピングを見つけ出します。次に、カーネルが `execve()` を呼び出すたびに行うのと大まかに同じ手順を実行する "シェル"コードを作成します：
* 当該マッピングを作成します。
* バイナリをそれらに読み込みます。
* 権限を設定します。
* 最終的にプログラムの引数と補助ベクトル（ローダーに必要）をスタックに初期化し、配置します。
* ローダーにジャンプして、残りの作業（プログラムに必要なライブラリのロード）をさせます。
* `syscall` ファイルから、プロセスが実行中のシステムコールの後に戻るアドレスを取得します。
* 実行可能なその場所を、私たちのシェルコードで上書きします（`mem` を通じて書き込み不可のページを変更できます）。
* 実行したいプログラムをプロセスの標準入力に渡します（"シェル"コードによって `read()` されます）。
* この時点で、ローダーがプログラムに必要なライブラリをロードしてそれにジャンプするのはローダー次第です。

**ツールはこちらでチェックしてください** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

2022年12月12日現在、`dd` に代わるいくつかの代替手段を見つけました。その中の1つである `tail` は、`mem` ファイルを `lseek()` するために（それが `dd` を使用する唯一の目的でした）現在デフォルトのプログラムとして使用されています。その代替手段は次のとおりです：
```bash
tail
hexdump
cmp
xxd
```
変数 `SEEKER` を設定することで、使用するシーカーを変更できます。例えば：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
スクリプトに実装されていない有効なseekerを見つけた場合でも、`SEEKER_ARGS`変数を設定することで使用することができます：
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
```markdown
Block this, EDRs.

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
```
