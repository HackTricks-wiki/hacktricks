# Sub-GHz RF

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のPRを提出して、あなたのハッキングのコツを共有する [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリ。

</details>

## ガレージドア

ガレージドアオープナーは通常、300-190 MHzの範囲の周波数で動作し、最も一般的な周波数は300 MHz、310 MHz、315 MHz、および390 MHzです。この周波数範囲は、他の周波数帯よりも混雑していなく、他のデバイスからの干渉を受けにくいため、ガレージドアオープナーによく使用されます。

## 車のドア

ほとんどの車のキーフォブは**315 MHzまたは433 MHz**で動作します。これらは両方とも無線周波数であり、さまざまな用途に使用されます。2つの周波数の主な違いは、433 MHzの方が315 MHzよりも長い範囲を持っていることです。これは、リモートキーレスエントリーなどの長距離が必要なアプリケーションにとって433 MHzの方が適していることを意味します。\
ヨーロッパでは433.92MHzが一般的に使用され、アメリカと日本では315MHzです。

## **ブルートフォース攻撃**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

代わりに各コードを5回送信する（受信機が確実に受け取るためにこのように送信されます）ので、一度だけ送信すると、時間は6分に短縮されます：

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

そして、信号間の**2 msの待機時間を取り除く**ことで、**時間を3分に短縮できます。**

さらに、De Bruijn Sequence（ブルートフォースに必要な潜在的なバイナリ数を送信するために必要なビット数を減らす方法）を使用すると、**時間はわずか8秒に短縮されます**：

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

この攻撃の例は[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)で実装されました

**プリアンブルが必要であることは、De Bruijn Sequence**の最適化を回避し、**ローリングコードはこの攻撃を防ぐ**でしょう（コードが十分に長く、ブルートフォースできないと仮定して）。

## Sub-GHz攻撃

これらの信号をFlipper Zeroで攻撃するには、以下を確認してください：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## ローリングコードの保護

自動ガレージドアオープナーは通常、ガレージドアを開閉するために無線リモコンを使用します。リモコンは**無線周波数（RF）信号を送信**し、ガレージドアオープナーがモーターを起動してドアを開閉します。

コードグラバーとして知られるデバイスを使用してRF信号を傍受し、後で使用するために記録することが可能です。これは**リプレイ攻撃**として知られています。このタイプの攻撃を防ぐために、多くの現代のガレージドアオープナーは**ローリングコード**システムとして知られるより安全な暗号化方法を使用しています。

**RF信号は通常、ローリングコードを使用して送信されます**。これは、コードが使用ごとに変更されることを意味します。これにより、信号を傍受して**不正アクセス**を得ることが**困難**になります。

ローリングコードシステムでは、リモコンとガレージドアオープナーは、リモコンが使用されるたびに**新しいコードを生成する共有アルゴリズム**を持っています。ガレージドアオープナーは**正しいコード**にのみ応答するため、コードをキャプチャするだけでは、不正アクセスを得ることははるかに困難です。

### **ミッシングリンク攻撃**

基本的に、ボタンをリッスンして、リモコンがデバイス（車やガレージなど）の範囲外のときに**信号をキャプチャ**します。その後、デバイスに移動して**キャプチャしたコードを使用して開けます**。

### フルリンクジャミング攻撃

攻撃者は、車両または受信機の近くで**信号をジャム**することができるため、受信機が実際にはコードを「聞く」ことができません。それが起こっている間、単にジャミングを停止したときにコードを**キャプチャしてリプレイ**することができます。

被害者はいずれかの時点で**車の鍵を使って車をロック**しますが、その後攻撃者は十分な「ドアを閉める」コードを**記録**しているはずで、それを再送信してドアを開けることができます（**周波数の変更が必要**かもしれません。開けると閉めるのに同じコードを使用する車もありますが、異なる周波数で両方のコマンドを聞きます）。

{% hint style="warning" %}
**ジャミングは機能します**が、車をロックする**人がドアをテスト**してロックされていることを確認すれば、車がロックされていないことに気付くため、目立ちます。さらに、このような攻撃を認識していれば、ドアがロックされたときに**音**がしなかったり、車の**ライト**が「ロック」ボタンを押したときに点滅しなかったりすることに気付くかもしれません。
{% endhint %}

### **コードグラビング攻撃（別名「RollJam」）**

これはより**ステルスなジャミング技術**です。攻撃者は信号をジャムするので、被害者がドアをロックしようとすると機能しませんが、攻撃者はこのコードを**記録します**。その後、被害者はもう一度ボタンを押して車をロックしようとし、車はこの**2番目のコードを記録します**。\
直後に攻撃者は**最初のコードを送信**でき、**車はロックされます**（被害者は2回目のプレスで閉まったと思います）。その後、攻撃者は**2番目の盗まれたコードを送信して車を開ける**ことができます（「車を閉める」コードが開けるのにも使用できると**仮定**して）。周波数の変更が必要になるかもしれません（開けると閉めるのに同じコードを使用する車もありますが、異なる周波数で両方のコマンドを聞きます）。

攻撃者は、例えば1MHzのブロードバンドで車の受信機が聞いている場合、リモコンが使用する正確な周波数を**ジャム**するのではなく、そのスペクトル内の**近い周波数をジャム**する一方で、**攻撃者の受信機はより小さい範囲で聞いています**。そこでは、リモート信号を**ジャム信号なしで聞く**ことができます。

{% hint style="warning" %}
他の実装では、**ローリングコードは送信される全体のコードの一部**であることが仕様で示されています。つまり、送信されるコードは**24ビットキー**で、最初の**12がローリングコード**、次の8が**コマンド**（ロックやアンロックなど）、最後の4が**チェックサム**です。このタイプを実装している車両も、攻撃者がローリングコードセグメントを置き換えるだけで、両方の周波数で**任意のローリングコードを使用できる**ため、自然に脆弱です。
{% endhint %}

{% hint style="danger" %}
被害者が攻撃者が最初のコードを送信している間に3番目のコードを送信した場合、最初と2番目のコードは無効になることに注意してください。
{% endhint %}

### アラームサウンディングジャミング攻撃

車に取り付けられたアフターマーケットのローリングコードシステムに対するテストでは、**同じコードを2回送信する**と直ちに**アラーム**とイモビライザーが**作動し**、独特の**サービス拒否**の機会を提供しました。皮肉なことに、アラームとイモビライザーを**無効にする**手段は**リモコンを押す**ことであり、攻撃者は**継続的にDoS攻撃を実行する**能力を持っていました。または、被害者ができるだけ早く攻撃を止めたいと思うので、**以前の攻撃と組み合わせてより多くのコードを取得する**。

## 参考文献

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のPRを提出して、あなたのハッキングのコツを共有する [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリ。

</details>
