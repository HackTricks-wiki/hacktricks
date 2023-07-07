<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有する**には、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけて変更するための便利なプログラムです。\
ダウンロードして実行すると、ツールの使用方法についてのチュートリアルが表示されます。ツールの使用方法を学びたい場合は、チュートリアルを完了することを強くお勧めします。

# 何を探していますか？

![](<../../.gitbook/assets/image (580).png>)

このツールは、プログラムのメモリ内にある**特定の値**（通常は数値）が保存されている場所を見つけるのに非常に便利です。\
通常、数値は**4バイト**形式で保存されますが、**倍精度**や**単精度**の形式で見つけることもあります。また、数値以外のものを探したい場合もあります。そのため、**検索する内容**を**選択**する必要があります。

![](<../../.gitbook/assets/image (581).png>)

また、**異なる種類の検索**を指定することもできます。

![](<../../.gitbook/assets/image (582).png>)

メモリのスキャン中にゲームを**停止**するためのチェックボックスもチェックできます。

![](<../../.gitbook/assets/image (584).png>)

## ホットキー

_**編集 --> 設定 --> ホットキー**_で、**ゲームを停止**するなど、さまざまな目的に対して異なる**ホットキー**を設定できます（メモリのスキャンを行いたい場合には非常に便利です）。他のオプションも利用できます。

![](<../../.gitbook/assets/image (583).png>)

# 値の変更

探している**値**の場所を**見つけたら**（次のステップで詳しく説明します）、それをダブルクリックして**変更**し、その値をダブルクリックします。

![](<../../.gitbook/assets/image (585).png>)

そして、変更をメモリに反映させるためにチェックを入れます。

![](<../../.gitbook/assets/image (586).png>)

メモリへの変更は即座に適用されます（ゲームがこの値を再度使用するまで、値はゲーム内で更新されません）。

# 値の検索

したがって、重要な値（ユーザーのライフなど）を改善したいとし、その値をメモリ内で検索しているとします。

## 既知の変更を通じて

値が100であることを探して、その値を検索して多くの一致を見つけました。

![](<../../.gitbook/assets/image (587).png>)

次に、値が変更されるように何かを行い、ゲームを停止して**次のスキャン**を実行します。

![](<../../.gitbook/assets/image (588).png>)

Cheat Engineは、100から新しい値に変わった**値**を検索します。おめでとうございます、探していた値の**アドレス**を見つけました。これで変更できます。\
_複数の値がまだある場合は、再びその値を変更するための何かを行い、別の「次のスキャン」を実行してアドレスをフィルタリングします。_

## 未知の値、既知の変更

値を知らないが、**変更方法**（変更の値さえも）を知っている場合、その数値を探すことができます。

まず、タイプが「**未知の初期値**」のスキャンを実行します。

![](<../../.gitbook/assets/image (589).png>)

次に、値を変更し、**値が変更された方法**（私の場合は1減少した）を示し、**次のスキャン**を実行します。

![](<../../.gitbook/assets/image (590).png>)

選択した方法で変更された**すべての値**が表示されます。

![](<../../.gitbook/assets/image (591).png>)

値が見つかったら、変更できます。

可能な変更は**たくさんあり**、これらのステップを**何度でも**繰り返して結果をフィルタリングできます。

![](<../../.gitbook/assets/image (592).png>)
## ランダムメモリアドレス - コードの検索

これまでに、値を格納しているアドレスを見つける方法を学びましたが、**ゲームの異なる実行では、そのアドレスはメモリの異なる場所にある可能性が非常に高い**です。そこで、常にそのアドレスを見つける方法を見つけましょう。

いくつかのトリックを使用して、現在のゲームが重要な値を格納しているアドレスを見つけます。次に（ゲームを停止する場合は）見つかった**アドレス**を**右クリック**して、「**このアドレスを使用しているものを検索**」または「**このアドレスに書き込んでいるものを検索**」を選択します。

![](<../../.gitbook/assets/image (593).png>)

**最初のオプション**は、この**アドレスを使用しているコードのどの部分**を知るのに役立ちます（これはゲームのコードを変更できる場所を知るためにも役立ちます）。\
**2番目のオプション**は、より**具体的**で、この場合は**どこからこの値が書き込まれているか**を知るのに役立ちます。

これらのオプションのいずれかを選択すると、**デバッガ**がプログラムに**アタッチ**され、新しい**空のウィンドウ**が表示されます。今、**ゲーム**を**プレイ**し、その**値**を**変更**します（ゲームを再起動せずに）。**ウィンドウ**には、**値を変更しているアドレス**が**表示**されるはずです。

![](<../../.gitbook/assets/image (594).png>)

値を変更しているアドレスを見つけたら、**コードを自由に変更**できます（Cheat Engineを使用して簡単に変更できます）。

![](<../../.gitbook/assets/image (595).png>)

したがって、コードを変更して数値に影響を与えないようにしたり、常に正の影響を与えるようにしたりできます。

## ランダムメモリアドレス - ポインタの検索

前の手順に従って、興味のある値がある場所を見つけます。次に、「**このアドレスに書き込んでいるものを検索**」を使用して、この値を書き込んでいるアドレスを見つけ、それをダブルクリックしてディスアセンブリビューを取得します。

![](<../../.gitbook/assets/image (596).png>)

次に、**"\[\]"**（この場合の$edxの値）の間の16進数値を検索する新しいスキャンを実行します。

![](<../../.gitbook/assets/image (597).png>)

（複数の場合は通常、最小のアドレスが必要です）\
これで、**興味のある値を変更するポインタ**を見つけました。

「**アドレスを手動で追加**」をクリックします。

![](<../../.gitbook/assets/image (598).png>)

次に、「ポインタ」のチェックボックスをクリックし、テキストボックスに見つかったアドレスを追加します（このシナリオでは、前の画像で見つかったアドレスは「Tutorial-i386.exe」+2426B0でした）。

![](<../../.gitbook/assets/image (599).png>)

（ポインタアドレスを入力すると、最初の「アドレス」が自動的に入力されることに注意してください）

OKをクリックすると、新しいポインタが作成されます。

![](<../../.gitbook/assets/image (600).png>)

これで、値が異なるメモリアドレスにある場合でも、その値を変更するたびに重要な値が変更されます。

## コードインジェクション

コードインジェクションは、ターゲットプロセスにコードの一部を注入し、コードの実行を自分自身の書かれたコードにリダイレクトする技術です（ポイントを減らす代わりにポイントを与えるなど）。

したがって、プレイヤーのライフを1減らしているアドレスを見つけたとします。

![](<../../.gitbook/assets/image (601).png>)

「ディスアセンブラを表示」をクリックして、**ディスアセンブルコード**を取得します。\
次に、**CTRL+a**をクリックしてオートアセンブルウィンドウを呼び出し、_**テンプレート --> コードインジェクション**_を選択します。

![](<../../.gitbook/assets/image (602).png>)

**変更したい命令のアドレス**を入力します（通常は自動入力されます）。

![](<../../.gitbook/assets/image (603).png>)

テンプレートが生成されます。

![](<../../.gitbook/assets/image (604).png>)

したがって、新しいアセンブリコードを「**newmem**」セクションに挿入し、オリジナルのコードを実行しない場合は「**originalcode**」から削除します。この例では、注入されるコードは1を減算する代わりに2ポイントを追加します。

![](<../../.gitbook/assets/image (605).png>)

**実行**をクリックすると、コードがプログラムに注入され、機能の動作が変更されます。

# **参考文献**

* **Cheat Engineのチュートリアル、Cheat Engineの始め方を学ぶために完了してください**



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**または**[Telegramグループ](https://t.me/peass)**に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
