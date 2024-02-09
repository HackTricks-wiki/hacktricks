<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングテクニックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>


# パッキングされたバイナリの特定

* **文字列の不足**: パッキングされたバイナリにはほとんど文字列が含まれていないことが一般的です
* **未使用の文字列が多い**: また、マルウェアが商用パッカーを使用している場合、相互参照がない多くの文字列が見つかることが一般的です。これらの文字列が存在しても、バイナリがパッキングされていないとは限りません。
* バイナリがどのパッカーを使用してパッキングされたかを特定しようとするために、いくつかのツールを使用することもできます:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# 基本的な推奨事項

* **IDAでパックされたバイナリを下から上に分析**することを**開始**します。アンパッカーは、アンパックされたコードが終了すると終了するため、アンパックされたコードに実行を渡す可能性は低いです。
* **JMP**や**CALL**、**レジスタ**や**メモリ領域**への**関数の引数とアドレス方向をプッシュし、`retn`を呼び出す**関数を検索します。なぜなら、その場合、関数の戻り値は、呼び出される前にスタックにプッシュされたアドレスを呼び出す可能性があるからです。
* `VirtualAlloc`に**ブレークポイント**を設定します。これは、プログラムがアンパックされたコードを書き込むことができるメモリ領域を割り当てるためです。関数を実行した後にEAX内の値に到達するために「ユーザーコードに実行」を実行するか、F8を使用して**そのアドレスをダンプで追跡**します。アンパックされたコードが保存される領域であるかどうかはわかりません。
* 引数として値「**40**」を持つ**`VirtualAlloc`**は、Read+Write+Execute（実行が必要なコードがここにコピーされる）を意味します。
* コードを**アンパック**する間に、**算術演算**や**`memcopy`**または**`Virtual`**`Alloc`のような関数への**複数の呼び出し**を見つけることが一般的です。関数が明らかに算術演算のみを実行し、おそらくいくつかの`memcopy`を実行している場合、関数の終わりを見つけてみることをお勧めします（おそらくJMPやレジスタへの呼び出し）**または**少なくとも**最後の関数への呼び出し**を見つけ、その後に実行してコードが興味深くないことを確認します。
* コードをアンパックする際に、**メモリ領域が変更されるたびに**メモリ領域の変更がアンパックコードの**開始を示す可能性**があることに注意してください。Process Hackerを使用して簡単にメモリ領域をダンプできます（process --> properties --> memory）。
* コードをアンパックしようとする際に、**バイナリの文字列をチェック**することで、**すでにアンパックされたコードで作業しているかどうかを知る**良い方法です（そのため、単にダンプできます）。ある時点でジャンプを実行し（おそらくメモリ領域を変更）、**追加された文字列がかなり増えた**ことに気付いた場合、**アンパックされたコードで作業している**ことがわかります。\
ただし、パッカーにすでに多くの文字列が含まれている場合は、単語「http」を含む文字列の数を確認して、この数が増加するかどうかを確認できます。
* メモリ領域から実行可能ファイルをダンプする際に、[PE-bear](https://github.com/hasherezade/pe-bear-releases/releases)を使用して一部のヘッダーを修正できます。

</details>
