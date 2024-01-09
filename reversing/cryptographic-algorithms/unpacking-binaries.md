<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


# パックされたバイナリの特定

* **文字列の欠如**: パックされたバイナリにはほとんど文字列がないことが一般的です。
* 多くの**使用されていない文字列**: また、マルウェアが商用のパッカーを使用している場合、クロスリファレンスのない多くの文字列が見つかることが一般的です。これらの文字列が存在しても、バイナリがパックされていないとは限りません。
* バイナリをパックするために使用されたパッカーを見つけるために、いくつかのツールを使用することもできます:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# 基本的な推奨事項

* **IDAで下からパックされたバイナリの分析を** **開始し、上に移動します**。アンパッカーはアンパックされたコードが終了すると終了するので、アンパッカーが最初にアンパックされたコードに実行を渡すことはありません。
* **レジスタ**や**メモリの領域**への**JMP**や**CALL**を探します。また、**関数が引数とアドレス方向をプッシュしてから`retn`を呼び出す**場合も探します。その場合、関数のリターンはそれを呼び出す前にスタックにプッシュされたアドレスを呼び出す可能性があります。
* `VirtualAlloc`に**ブレークポイント**を設定します。これはプログラムがアンパックされたコードを書き込むことができるメモリのスペースを割り当てます。"ユーザーコードまで実行"を使用するか、関数を実行した後にEAX内の値に**到達するためにF8を使用し**、"**そのアドレスをダンプでフォローする**"。それがアンパックされたコードが保存される領域かどうかはわかりません。
* 引数として値"**40**"を持つ**`VirtualAlloc`**は、Read+Write+Execute（実行が必要なコードがここにコピーされる）を意味します。
* コードをアンパックする際には、**`memcopy`**や**`Virtual`**`Alloc`のような関数と**算術演算**への**複数の呼び出し**を見つけるのが普通です。もし、算術演算のみを行い、多分いくつかの`memcopy`を行う関数に自分自身を見つけた場合、その関数の**終わりを見つける**（多分いくつかのレジスタへのJMPや呼び出し）か、少なくとも**最後の関数への呼び出し**を見つけて、そこまで実行することをお勧めします。なぜなら、コードは興味深くないからです。
* コードをアンパックする際には、**メモリ領域を変更する**たびに注意してください。メモリ領域の変更は、**アンパックコードの開始**を示す可能性があります。Process Hackerを使用して簡単にメモリ領域をダンプできます（プロセス --> プロパティ --> メモリ）。
* コードをアンパックしようとするとき、**アンパックされたコードをすでに扱っているかどうか**（そのためにただダンプできる）を知る良い方法は、**バイナリの文字列をチェックする**ことです。もし、ある時点でジャンプ（多分メモリ領域を変更する）を実行し、**はるかに多くの文字列が追加された**ことに気づいたら、**アンパックされたコードを扱っている**と知ることができます。\
しかし、パッカーにすでに多くの文字列が含まれている場合は、"http"という単語を含む文字列がどれだけあるかを確認し、この数が増えるかどうかを見ることができます。
* メモリの領域から実行可能ファイルをダンプするとき、[PE-bear](https://github.com/hasherezade/pe-bear-releases/releases)を使用していくつかのヘッダーを修正することができます。


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
