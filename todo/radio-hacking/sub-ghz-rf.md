# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## ガレージのドア

ガレージドアオープナーは通常、300〜190 MHzの周波数で動作し、最も一般的な周波数は300 MHz、310 MHz、315 MHz、および390 MHzです。この周波数帯は、他の周波数帯よりも混雑しておらず、他のデバイスからの干渉を受けにくいため、ガレージドアオープナーによく使用されます。

## 車のドア

ほとんどの車のキーフォブは、**315 MHzまたは433 MHz**で動作します。これらはいずれも無線周波数であり、さまざまなアプリケーションで使用されています。2つの周波数の主な違いは、433 MHzの方が315 MHzよりも長い範囲を持っていることです。これは、リモートキーレスエントリーなどの長い範囲を必要とするアプリケーションには433 MHzが適していることを意味します。\
ヨーロッパでは433.92MHzが一般的に使用され、米国と日本では315MHzです。

## **ブルートフォース攻撃**

<figure><img src="../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

各コードを5回送信する代わりに（受信機が受信することを確認するためにこのように送信される）、1回だけ送信すると、時間が6分に短縮されます。

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

また、信号間の2ミリ秒の待ち時間を**削除**すると、時間を3分に短縮できます。

さらに、De Bruijn Sequence（すべての潜在的なバイナリ数を送信するために必要なビット数を減らす方法）を使用すると、この時間はわずか8秒に短縮されます。

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

この攻撃の例は、[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)で実装されています。

**プリアンブルを要求することで**、De Bruijn Sequenceの最適化を回避し、**ローリングコードはこの攻撃を防ぎます**（コードが十分に長く、ブルートフォース攻撃できない場合を想定しています）。

## Sub-GHz攻撃

Flipper Zeroを使用してこれらの信号を攻撃するには、次を確認してください：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## ローリングコードの保護

自動ガレージドアオープナーは通常、ワイヤレスリモコンを使用してガレージドアを開閉します。リモコンはガレージドアオープナーに**無線周波数（RF）信号**を送信し、モーターを作動させてドアを開閉します。

コードグラバーと呼ばれるデバイスを使用してRF信号を傍受し、後で使用するために記録することができます。これは**リプレイ攻撃**として知られています。このタイプの攻撃を防ぐために、多くの現代のガレージドアオープナーは、より安全な暗号化方式である**ローリングコード**システムを使用しています。

**RF信号は通常、ローリングコードを使用して送信**されるため、コードは使用ごとに変更されます。これにより、コードを傍受してガレージへの**不正アクセス**を試みることが困難になります。

ローリングコードシステムでは、リモコンとガレージドアオープナーには、リモコンが使用されるたびに新しいコードを生成する**共有アルゴリズム**があります。ガレージドアオープナーは**正しいコード**にのみ応答し、コードを傍受してガレージへの不正アクセスを試みることをはるかに困難にします。

### **Missing Link攻撃**

基本的には、リモートがデバイス（車やガレージなど）の**範囲外**にある間にボタンを聞き、**キャプチャしたコードを使用してデバイスを開く**ことです。

### フルリンクジャミング攻撃

攻撃者は、車両または受信機の**近くで信号を妨害**することができます。そのため、受信機は実際にはコードを「聞く」ことができず、ジャミングを停止した後にコードを**キャプチャして再生**することができます。

被害者はある時点で**車をロックするためにキーを使用**しますが、その後、攻撃は十分な「ドアを閉める」コードを記録していることを願って、ドアを開くために再送信できるでしょう（異なる周波数で両方のコマンドを受信する車もあるため、周波数の変更が必要になる場合があります）。

{% hint style="warning" %}
**ジャミングは機能します**が、車をロックする人が単にドアがロックされていることを確認するためにドアをテストすると、ロックされていないことに気付くでしょう。さらに、このような攻撃について知っている場合、車を「ロック」ボタンを押したときにロックの**音**が鳴らなかったり、車の**ライト**が点滅
### **コードグラビング攻撃（別名「RollJam」）**

これはより**ステルスなジャミング技術**です。攻撃者は信号をジャミングし、被害者がドアをロックしようとしてもうまくいかないようにしますが、攻撃者は**このコードを記録**します。その後、被害者はボタンを押して再び車をロックしようとしますが、車は**この2回目のコードを記録**します。\
これにより、**攻撃者は最初のコードを送信**し、車はロックされます（被害者は2回目の押しでロックされたと思うでしょう）。その後、攻撃者は盗まれた2番目のコードを送信して車を開けることができます（「車を閉める」コードも開けるため、前提としています）。周波数の変更が必要な場合もあります（開くと閉じるに同じコードを使用する車があり、両方のコマンドを異なる周波数で受信する）。

攻撃者は**自分の受信機ではなく車の受信機をジャム**することができます。たとえば、車の受信機が1MHzの広帯域で受信している場合、攻撃者はリモートが使用している正確な周波数を**ジャム**するのではなく、そのスペクトラム内の**近い周波数**をジャムします。一方、**攻撃者の受信機はより狭い範囲で受信**し、ジャム信号なしでリモート信号を受信できます。

{% hint style="warning" %}
仕様で見られる他の実装では、**ローリングコードは送信されるコードの一部**です。つまり、送信されるコードは**24ビットのキー**であり、最初の**12ビットがローリングコード**、次の8ビットが**コマンド**（ロックまたはアンロックなど）、最後の4ビットが**チェックサム**です。このタイプを実装している車は、攻撃者が単にローリングコードセグメントを置き換えるだけで、**両方の周波数で任意のローリングコードを使用**できるようになります。
{% endhint %}

{% hint style="danger" %}
被害者が攻撃者が最初のコードを送信している間に3番目のコードを送信した場合、最初のコードと2番目のコードは無効になります。
{% endhint %}

### アラーム音ジャミング攻撃

車に取り付けられたアフターマーケットのローリングコードシステムに対するテストでは、**同じコードを2回送信**すると、アラームとイモビライザーが**即座に作動**し、ユニークな**サービス拒否**の機会が提供されました。皮肉なことに、アラームとイモビライザーを**無効にする手段**は、**リモートを押す**ことでした。これにより、攻撃者は**継続的にDoS攻撃を実行**する能力を持ちます。または、被害者が攻撃をできるだけ早く停止したいと思うため、この攻撃を**前の攻撃と組み合わせてさらに多くのコードを取得**することもできます。

## 参考文献

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **をチェックしてください！**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。当社の独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
