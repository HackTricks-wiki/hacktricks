# Cheat Engine

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけて変更するための便利なプログラムです。\
ダウンロードして実行すると、ツールの使用方法に関するチュートリアルが表示されます。ツールの使用方法を学びたい場合は、チュートリアルを完了することを強くお勧めします。

## 何を探していますか？

![](<../../.gitbook/assets/image (762).png>)

このツールは、プログラムのメモリ内にある**特定の値**（通常は数値）の保存場所を見つけるのに非常に役立ちます。\
**通常、数値**は**4バイト**形式で保存されますが、**double**や**float**形式で見つけることもできますし、数値以外のものを探したい場合もあります。そのため、**検索する内容を選択**する必要があります：

![](<../../.gitbook/assets/image (324).png>)

また、**異なる**種類の**検索**を指定することもできます：

![](<../../.gitbook/assets/image (311).png>)

また、**メモリのスキャン中にゲームを停止**するためのチェックボックスをオンにすることもできます：

![](<../../.gitbook/assets/image (1052).png>)

### ホットキー

_**編集 --> 設定 --> ホットキー**_で、**ゲームを停止**するなど、異なる目的のために異なる**ホットキー**を設定できます（メモリのスキャンを行いたい場合に便利です）。他のオプションも利用可能です：

![](<../../.gitbook/assets/image (864).png>)

## 値の変更

一度**探している値**の**場所を見つけたら**（次の手順で詳細に説明します）、その値をダブルクリックして**変更**し、その値をダブルクリックします：

![](<../../.gitbook/assets/image (563).png>)

最後に、変更をメモリに適用するために**チェックを入れます**：

![](<../../.gitbook/assets/image (385).png>)

メモリへの**変更**はすぐに**適用**されます（ゲームがこの値を再度使用するまで、値は**ゲーム内で更新されません**）。

## 値の検索

したがって、重要な値（ユーザーのライフなど）を改善したいと仮定し、この値をメモリ内で探しているとします）

### 既知の変更を通じて

値が100であると仮定し、その値を検索するためにスキャンを実行し、多くの一致を見つけます：

![](<../../.gitbook/assets/image (108).png>)

その後、**値を変更**するために何かを行い、ゲームを**停止**して**次のスキャン**を実行します：

![](<../../.gitbook/assets/image (684).png>)

Cheat Engineは、**100から新しい値**に変わった**値**を検索します。おめでとうございます、探していた値の**アドレス**を見つけました。これを変更できます。\
_複数の値がまだある場合は、再度その値を変更するための何かを行い、別の「次のスキャン」を実行してアドレスをフィルタリングします。_

### 未知の値、既知の変更

値を知らないが、**変更方法**（および変更の値）を知っている場合、その数値を探すことができます。

したがって、タイプが「**Unknown initial value**」のスキャンを実行して開始します：

![](<../../.gitbook/assets/image (890).png>)

その後、値を変更し、**値が変更された方法**を示し（私の場合は1減少しました）、**次のスキャン**を実行します：

![](<../../.gitbook/assets/image (371).png>)

選択した方法で**変更されたすべての値**が表示されます：

![](<../../.gitbook/assets/image (569).png>)

値を見つけたら、それを変更できます。

**多くの可能な変更**があり、結果をフィルタリングするためにこれらの手順を**好きなだけ繰り返す**ことができます：

![](<../../.gitbook/assets/image (574).png>)

### ランダムメモリアドレス - コードの検索

値を保存しているアドレスを見つける方法を学びましたが、**ゲームの異なる実行ではそのアドレスがメモリの異なる場所にある可能性が非常に高い**です。そのアドレスを常に見つける方法を見つけましょう。

上記のトリックのいくつかを使用して、現在のゲームが重要な値を保存しているアドレスを見つけます。次に（必要に応じてゲームを停止）、見つかった**アドレス**で**右クリック**し、「**このアドレスを使用している箇所を見つける**」または「**このアドレスに書き込んでいる箇所を見つける**」を選択します：

![](<../../.gitbook/assets/image (1067).png>)

**最初のオプション**は、この**アドレス**を**使用しているコードの部分**を知るのに役立ちます（ゲームのコードを変更できる場所を知るなど、他の用途にも役立ちます）。\
**2番目のオプション**は**特定**であり、この場合は**この値が書き込まれている場所**を知るのに役立ちます。

これらのオプションのいずれかを選択すると、**デバッガ**がプログラムに**アタッチ**され、新しい**空のウィンドウ**が表示されます。今、**ゲーム**を**プレイ**し、その**値**を**変更**します（ゲームを再起動せずに）。**ウィンドウ**には、**値を変更しているアドレス**が表示されるはずです：

![](<../../.gitbook/assets/image (91).png>)

値を変更しているアドレスを見つけたら、コードを**お好みで変更**できます（Cheat Engineを使用して素早くNOPsに変更できます）：

![](<../../.gitbook/assets/image (1057).png>)

したがって、コードが数値に影響を与えないように変更したり、常にポジティブな方法で影響を与えるように変更したりできます。
### ランダムメモリアドレス - ポインターの検索

前の手順に従い、興味のある値がどこにあるかを見つけます。次に、「**このアドレスに書き込むものを調べる**」を使用して、この値を書き込むアドレスを見つけ、それをダブルクリックして逆アセンブリビューを取得します：

![](<../../.gitbook/assets/image (1039).png>)

次に、新しいスキャンを実行し、「\[\]」の間の16進値を検索します（この場合は$edxの値）：

![](<../../.gitbook/assets/image (994).png>)

（複数表示される場合は通常、最小のアドレスが必要です）\
これで、**興味のある値を変更するポインターを見つけました**。

「**アドレスを手動で追加**」をクリックします：

![](<../../.gitbook/assets/image (990).png>)

次に、「ポインター」チェックボックスをクリックして、見つかったアドレスをテキストボックスに追加します（このシナリオでは、前の画像で見つかったアドレスは「Tutorial-i386.exe」+2426B0でした）：

![](<../../.gitbook/assets/image (392).png>)

（ポインターアドレスを入力すると、最初の「アドレス」が自動的に入力されることに注意してください）

OKをクリックすると、新しいポインターが作成されます：

![](<../../.gitbook/assets/image (308).png>)

これで、その値を変更するたびに、**値が異なるメモリアドレスにある場合でも重要な値を変更しています**。

### コードインジェクション

コードインジェクションは、ターゲットプロセスにコードを挿入し、その後、コードの実行を自分の書いたコードを通るようにリダイレクトする技術です（ポイントを与える代わりにそれらをリセットするように）。

したがって、プレイヤーの寿命を1減らすアドレスを見つけたと仮定してください：

![](<../../.gitbook/assets/image (203).png>)

ディスアセンブラを表示するにはクリックします。\
次に、**CTRL+a**をクリックして、自動アセンブルウィンドウを呼び出し、_**Template --> Code Injection**_を選択します。

![](<../../.gitbook/assets/image (902).png>)

変更したい**命令のアドレスを入力**します（通常は自動入力されます）：

![](<../../.gitbook/assets/image (744).png>)

テンプレートが生成されます：

![](<../../.gitbook/assets/image (944).png>)

したがって、「newmem」セクションに新しいアセンブリコードを挿入し、「originalcode」から元のコードを削除すると、実行されないようになります。この例では、挿入されるコードは1を減算する代わりに2ポイントを追加します：

![](<../../.gitbook/assets/image (521).png>)

**実行をクリックして、その他をクリックして、コードがプログラムにインジェクトされ、機能の動作が変更されるはずです！**

## **参考文献**

* **Cheat Engineのチュートリアル、Cheat Engineの使用方法を学ぶために完了してください**

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのスウォッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つけます
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを送信してください。

</details>
