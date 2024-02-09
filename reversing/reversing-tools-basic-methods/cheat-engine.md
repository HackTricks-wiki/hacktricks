<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけて変更するための便利なプログラムです。\
ダウンロードして実行すると、ツールの使用方法に関するチュートリアルが表示されます。ツールの使用方法を学びたい場合は、チュートリアルを完了することを強くお勧めします。

# 何を探していますか？

![](<../../.gitbook/assets/image (580).png>)

このツールは、プログラムのメモリ内にある**特定の値**（通常は数値）の**保存場所を見つけるのに非常に便利**です。\
通常、数値は**4バイト形式**で保存されますが、**double**や**float**形式で見つけることもできますし、数値以外のものを探したい場合もあります。そのため、**検索対象を選択**する必要があります：

![](<../../.gitbook/assets/image (581).png>)

また、**異なる種類の検索**を指定することもできます：

![](<../../.gitbook/assets/image (582).png>)

また、**メモリのスキャン中にゲームを停止**するためのチェックボックスを選択することもできます：

![](<../../.gitbook/assets/image (584).png>)

## ホットキー

_**編集 --> 設定 --> ホットキー**_で、**ゲームを停止**するなど、異なる目的のために異なる**ホットキー**を設定できます（メモリのスキャンを行いたい場合に便利です）。他のオプションも利用可能です：

![](<../../.gitbook/assets/image (583).png>)

# 値の変更

**探している値**が**どこにあるか見つかったら**（次の手順で詳しく説明します）、その値を**変更**することができます。ダブルクリックして値を変更し、その値をダブルクリックします：

![](<../../.gitbook/assets/image (585).png>)

最後に、変更をメモリに適用するために**チェックを入れます**：

![](<../../.gitbook/assets/image (586).png>)

メモリへの**変更**はすぐに**適用**されます（ゲームがこの値を再度使用しない限り、値は**ゲーム内で更新されません**）。

# 値の検索

したがって、重要な値（たとえば、ユーザーのライフ）を改善したいとし、この値をメモリ内で探しているとします）

## 既知の変更を通じて

値が100であると仮定し、その値を検索するスキャンを実行し、多くの一致を見つけます：

![](<../../.gitbook/assets/image (587).png>)

その後、**値を変更**するために何かを行い、ゲームを**停止**して**次のスキャン**を実行します：

![](<../../.gitbook/assets/image (588).png>)

Cheat Engineは、**100から新しい値に変わった値**を検索します。おめでとうございます、探していた値の**アドレス**を見つけました。これを修正できるようになりました。\
_複数の値がまだある場合は、再度その値を変更するための何かを行い、別の「次のスキャン」を実行してアドレスをフィルタリングします。_

## 未知の値、既知の変更

値を知らないが、**変更方法**（および変更の値）を知っている場合、その数値を探すことができます。

したがって、タイプが「**Unknown initial value**」のスキャンを実行して開始します：

![](<../../.gitbook/assets/image (589).png>)

その後、値を変更し、**値がどのように変更されたか**を示し（私の場合は1減少しました）、**次のスキャン**を実行します：

![](<../../.gitbook/assets/image (590).png>)

選択した方法で**変更されたすべての値**が表示されます：

![](<../../.gitbook/assets/image (591).png>)

値を見つけたら、それを変更できます。

多くの可能な変更があり、結果をフィルタリングするためにこれらの手順を**必要なだけ繰り返す**ことができます：

![](<../../.gitbook/assets/image (592).png>)

## ランダムメモリアドレス - コードの検索

値を保存しているアドレスを見つける方法を学びましたが、**ゲームの異なる実行ではそのアドレスがメモリの異なる場所にある可能性が高い**です。そのアドレスを常に見つける方法を見つけましょう。

上記のトリックのいくつかを使用して、現在のゲームが重要な値を保存しているアドレスを見つけます。次に（必要に応じてゲームを停止）、見つかった**アドレスを右クリック**して「**このアドレスを使用しているものを調べる**」または「**このアドレスに書き込んでいるものを調べる**」を選択します：

![](<../../.gitbook/assets/image (593).png>)

**最初のオプション**は、この**アドレスを使用しているコードの部分**を知るのに役立ちます（ゲームのコードを変更できる場所を知るのに役立ちます）。\
**2番目のオプション**は**より具体的**で、この値が**どこから書き込まれているか**を知るのに役立ちます。

これらのオプションのいずれかを選択すると、**デバッガ**がプログラムに**アタッチ**され、新しい**空のウィンドウ**が表示されます。今、**ゲームをプレイ**し、その**値を変更**します（ゲームを再起動せずに）。ウィンドウには、**値を変更しているアドレス**が表示されるはずです：

![](<../../.gitbook/assets/image (594).png>)

値を変更しているアドレスを見つけたので、**コードを自由に変更**できます（Cheat Engineを使用して素早くNOPsに変更できます）：

![](<../../.gitbook/assets/image (595).png>)

したがって、コードが数値に影響を与えないように変更したり、常にポジティブな方法で影響を与えるように変更したりできます。

## ランダムメモリアドレス - ポインタの検索

前の手順に従って、興味のある値がどこにあるかを見つけます。次に、「**このアドレスに書き込んでいるものを調べる**」を使用して、この値を書き込むアドレスを見つけ、それをダブルクリックして逆アセンブリビューを取得します：

![](<../../.gitbook/assets/image (596).png>)

次に、"\[]"の間の16進数値を検索する新しいスキャンを実行します（この場合、$edxの値）：

![](<../../.gitbook/assets/image (597).png>)

（複数の場合、通常は最小のアドレスが必要です）\
これで、**興味のある値を変更するポインタが見つかりました**。

「**アドレスを手動で追加**」をクリックします：

![](<../../.gitbook/assets/image (598).png>)

次に、「ポインタ」チェックボックスをクリックし、前の画像で見つかったアドレスをテキストボックスに追加します（このシナリオでは、前の画像で見つかったアドレスは「Tutorial-i386.exe」+2426B0でした）：

![](<../../.gitbook/assets/image (599).png>)

（最初の「アドレス」が、入力したポインタアドレスから自動的に入力されることに注目してください）

OKをクリックすると、新しいポインタが作成されます：

![](<../../.gitbook/assets/image (600).png>)

これで、メモリアドレスが異なる場合でも、その値を変更するたびに**重要な値を変更**できます。

## コードインジェクション

コードインジェクションは、ターゲットプロセスにコードをインジェクトし、コードの実行を自分の書いたコードを通るようにリダイレクトする技術です（ポイントを減らす代わりにポイントを与えるなど）。

したがって、プレイヤーのライフを1減らしているアドレスを見つけたとします：

![](<../../.gitbook/assets/image (601).png>)

**ディスアセンブラを表示**をクリックして**ディスアセンブルコード**を取得します。\
次に、**CTRL+a**をクリックして**オートアセンブルウィンドウ**を呼び出し、_**テンプレート --> コードインジェクション**_を選択します

![](<../../.gitbook/assets/image (602).png>)

**変更したい命令のアドレス**を入力してください（通常は自動入力されます）：

![](<../../.gitbook/assets/image (603).png>)

テンプレートが生成されます：

![](<../../.gitbook/assets/image (604).png>)

したがって、新しいアセンブリコードを「**newmem**」セクションに挿入し、「**originalcode**」から元のコードを削除すると、（この例では）注入されたコードが1を減算する代わりに2ポイントを追加します：

![](<../../.gitbook/assets/image (605).png>)

**実行をクリック**して、コードがプログラムにインジェクトされ、機能の動作が変更されるはずです！

# **参考文献**

* **Cheat Engineチュートリアル、Cheat Engineの使用方法を学ぶために完了してください**



<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>
