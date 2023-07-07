<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


# パックされたバイナリの特定

* **文字列の不足**: パックされたバイナリにはほとんど文字列が存在しないことがよくあります。
* 多くの**未使用の文字列**: マルウェアが商用パッカーを使用している場合、クロスリファレンスのない多くの文字列が見つかることがよくあります。ただし、これらの文字列が存在しているからといって、バイナリがパックされていないとは限りません。
* バイナリのパッカーを特定するために、いくつかのツールを使用することもできます:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# 基本的な推奨事項

* パックされたバイナリを解析する場合は、**IDAで下から上に**解析を開始します。アンパッカーは、アンパックされたコードが終了すると終了するため、アンパッカーが最初に実行時にアンパックされたコードに実行を渡すことはまれです。
* **レジスタ**または**メモリの領域**への**JMP**または**CALL**、または**引数とアドレスの方向をプッシュし、`retn`を呼び出す関数**を検索します。この場合、関数の戻り値は、呼び出される前にスタックにプッシュされたアドレスを呼び出す可能性があります。
* `VirtualAlloc`に**ブレークポイント**を設定します。これにより、プログラムがアンパックされたコードを書き込むためのメモリ領域を割り当てることができます。関数を実行した後、"run to user code"またはF8を使用してEAX内の値に到達します。そして、そのアドレスをダンプで**フォロー**します。アンパックされたコードが保存される領域であるかどうかはわかりません。
* 引数として値 "**40**" を持つ **`VirtualAlloc`** は、Read+Write+Execute（実行が必要なコードがここにコピーされる）を意味します。
* コードをアンパックする間に、**算術演算**や**`memcopy`**または**`Virtual`**`Alloc`のような関数への**複数の呼び出し**が見つかることが普通です。関数が算術演算のみを実行し、おそらくいくつかの`memcopy`を実行するように見える場合、関数の**終わり**（おそらくレジスタへのJMPまたは呼び出し）を見つけるか、少なくとも**最後の関数の呼び出し**を見つけてから実行してください。なぜなら、そのコードは興味がないからです。
* コードをアンパックする間に、**メモリ領域の変更**があるたびに**メモ**してください。メモリ領域の変更は、アンパックコードの開始を示す可能性があります。プロセスハッカーを使用して簡単にメモリ領域をダンプすることができます（プロセス→プロパティ→メモリ）。
* コードをアンパックしようとする際に、**アンパックされたコードで作業しているかどうかを知るための良い方法**（そのままダンプできる）は、バイナリの**文字列をチェック**することです。ある時点でジャンプを実行し（おそらくメモリ領域を変更）、**追加された文字列が非常に多い**ことに気付いた場合、**アンパックされたコードで作業している**ことがわかります。\
ただし、パッカーにすでに多くの文字列が含まれている場合は、単語 "http" を含む文字列の数を確認し、この数が増加するかどうかを確認できます。
* メモリ領域から実行可能ファイルをダンプする際には、[PE-bear](https://github.com/hasherezade/pe-bear-releases/releases)を使用して一部のヘッダーを修正することができます。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**
