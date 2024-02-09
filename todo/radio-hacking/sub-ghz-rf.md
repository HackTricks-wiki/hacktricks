# サブGHz RF

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。

- [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## ガレージドア

ガレージドアオープナーは通常、300-190 MHzの周波数で動作し、最も一般的な周波数は300 MHz、310 MHz、315 MHz、390 MHzです。この周波数範囲は、他の周波数帯よりも混雑しておらず、他のデバイスからの干渉を受けにくいため、ガレージドアオープナーによく使用されます。

## 車のドア

ほとんどの車のキーフォブは、**315 MHzまたは433 MHz**で動作します。これらはどちらも無線周波数であり、さまざまな異なるアプリケーションで使用されています。これらの周波数の主な違いは、433 MHzの方が315 MHzよりも長い射程を持っていることです。これは、リモートキーレスエントリなどのより長い射程を必要とするアプリケーションには433 MHzが適していることを意味します。\
ヨーロッパでは433.92MHzが一般的であり、米国と日本では315MHzが使用されています。

## **ブルートフォース攻撃**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

各コードを5回送信する代わりに（受信側が受信することを確認するためにこのように送信される）、1回送信すると、時間が6分に短縮されます：

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

また、信号間の2 msの待機時間を**削除**すると、時間を**3分に短縮**できます。

さらに、De Bruijn Sequence（潜在的なすべてのバイナリ数を送信するために必要なビット数を減らす方法）を使用することで、この**時間をわずか8秒に短縮**できます：

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

この攻撃の例は、[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)で実装されました。

**前置詞を必要とすることで、De Bruijn Sequence**の最適化を回避し、**ローリングコード**はこの攻撃を防ぎます（コードがブルートフォース攻撃されないように十分に長い場合）。

## サブGHz攻撃

Flipper Zeroでこれらの信号を攻撃するには、次のチェックを行います：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## ローリングコード保護

自動ガレージドアオープナーは通常、ワイヤレスリモコンを使用してガレージドアを開閉します。リモコンはガレージドアオープナーに**無線周波数（RF）信号を送信**し、モーターを作動させてドアを開閉します。

**コードグラバー**として知られるデバイスを使用してRF信号を傍受し、後で使用するために記録することが可能です。これは**リプレイ攻撃**として知られています。この種の攻撃を防ぐために、多くの現代のガレージドアオープナーは、**ローリングコード**システムとして知られるより安全な暗号化方式を使用しています。

**RF信号は通常、ローリングコードを使用して送信**されるため、コードは使用するたびに変更されます。これにより、誰かが信号を傍受してガレージへの**不正アクセス**を試みることが難しくなります。

ローリングコードシステムでは、リモコンとガレージドアオープナーには、リモコンを使用するたびに新しいコードを生成する**共有アルゴリズム**があります。ガレージドアオープナーは**正しいコードにのみ応答**し、コードをキャプチャしてガレージへの不正アクセスを試みることがはるかに困難になります。

### **Missing Link攻撃**

基本的に、リモコンがデバイス（たとえば車やガレージ）から**離れた状態で信号をキャプチャ**し、その後デバイスに移動して**キャプチャしたコードを使用して開く**ことができます。

### フルリンクジャミング攻撃

攻撃者は、車両や受信機の近くで信号を**ジャミング**することができ、その結果、**受信機がコードを「聞く」ことができなくなり**ます。その後、ジャミングを停止した後に、単純にコードを**キャプチャして再生**することができます。

被害者はある時点で**車をロックするためにキーを使用**するかもしれませんが、その後、攻撃は**十分な「ドアを閉める」コードを記録**しているはずであり、それらを再送信してドアを開けることができるかもしれません（同じコードを開閉に使用する車があり、異なる周波数で両方のコマンドを受信する車があるため、周波数の変更が必要かもしれません）。

{% hint style="warning" %}
**ジャミングは機能します**が、車をロックする人が単にドアをテストしてロックされていることを確認すると、車がロック解除されていることに気づくでしょう。さらに、このような攻撃に気づいている場合、車を「ロック」ボタンを押したときにドアがロックされなかったことや、車のライトが「ロック」ボタンを押したときに点滅しなかったことを聞くことさえできます。
{% endhint %}

### **コードグラビング攻撃（別名‘RollJam’）**

これはより**巧妙なジャミング技術**です。攻撃者は信号をジャミングし、被害者がドアをロックしようとするときに動作しないようにしますが、攻撃者はこのコードを**記録**します。その後、被害者はボタンを押して再度車をロックしようとしますが、車はこの2回目のコードを**記録**します。\
これをすぐに行うと、**攻撃者は最初のコードを送信**し、車が**ロック**します（被害者は2回目の押しで閉じたと思うでしょう）。その後、攻撃者は車を**開くために2番目の盗まれたコードを送信**できます（「車を閉める」コードも開くために使用できると仮定しています）。周波数の変更が必要かもしれません（同じコードを開閉に使用する車があり、異なる周波数で両方のコマンドを受信する車があるため）。

攻撃者は**車の受信機をジャミングせず**、被害者が最初に送信したコードと同じ周波数をジャミングしないようにすることができます。車の受信機がたとえば1MHzの広帯域で受信している場合、攻撃者は**正確な周波数をジャミング**せずに、そのスペクトラム内の**近い周波数**でジャミングします。一方、**攻撃者の受信機は、リモコン信号をジャミング信号なしで受信できるように**、より狭い範囲で受信しています。

{% hint style="warning" %}
他の仕様で見られる実装では、**ローリングコードは送信される合計コードの一部**であることが示されています。つまり、送信されるコードは**24ビットキー**であり、最初の**12ビットがローリングコード**、次の8ビットがコマンド（ロックまたはアンロックなど）、最後の4ビットが**チェックサム**である。このタイプを実装している車両も自然に脆弱性があり、攻撃者は単にローリングコードセグメントを置き換えるだけで、両方の周波数で**任意のローリングコードを使用**できるようになります。
{% endhint %}

{% hint style="danger" %}
被害者が最初のコードを送信する間に攻撃者が最初のコードを送信すると、最初と2番目のコードは無効になります。
{% endhint %}

### アラーム音ジャミング攻撃

車に取り付けられたアフターマーケットのローリングコードシステムに対してテストを行うと、**同じコードを2回送信**するとすぐにアラームが作動し、イモビライザーが提供され、ユニークな**サービスの拒否**の機会が提供されました。皮肉なことに、アラームとイモビライザーを**無効にする**手段は、**リモコンを押す**ことであり、攻撃者に**継続的にDoS攻撃を実行**する能力を提供します。または、この攻撃を**前の攻撃と組み合わせて**、被害者ができるだけ早く攻撃を停止したいと思うため、より多くのコードを取得できます。

## 参考文献

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。

- [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
