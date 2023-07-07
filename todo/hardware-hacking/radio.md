# ラジオ

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)は、GNU/LinuxとmacOS用の無料のデジタル信号アナライザであり、未知の無線信号の情報を抽出するために設計されています。SoapySDRを介してさまざまなSDRデバイスをサポートし、FSK、PSK、ASK信号の可変復調、アナログビデオのデコード、バースト信号の分析、アナログ音声チャネルのリアルタイムリスニングなどをサポートしています。

### 基本設定

インストール後、いくつかの設定を検討することができます。\
設定（2番目のタブボタン）では、**SDRデバイス**を選択するか、**ファイルを選択**して読み取る周波数とサンプルレート（PCがサポートしている場合は2.56Mspsまで推奨）を選択できます。

![](<../../.gitbook/assets/image (655) (1).png>)

GUIの動作では、PCがサポートしている場合はいくつかの機能を有効にすることをお勧めします。

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
PCがキャプチャできていないことに気付いた場合は、OpenGLを無効にし、サンプルレートを下げてみてください。
{% endhint %}

### 用途

* **信号の一部をキャプチャして分析する**場合は、「Push to capture」ボタンを必要な時間だけ押し続けます。

![](<../../.gitbook/assets/image (631).png>)

* SigDiggerの**チューナー**は、信号をより良くキャプチャするのに役立ちます（ただし、信号を劣化させることもあります）。理想的には、0から始めて、ノイズが本当に増加し始めるレベルまで**大きくしていく**ことが望ましいです。

![](<../../.gitbook/assets/image (658).png>)

### ラジオチャンネルとの同期

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)を使用して、聞きたいチャンネルと同期し、"Baseband audio preview"オプションを設定し、送信されているすべての情報を取得するための帯域幅を設定し、ノイズが本当に増加し始める前のレベルにチューナーを設定します。

![](<../../.gitbook/assets/image (389).png>)

## おもしろいトリック

* デバイスが情報のバーストを送信している場合、通常は**最初の部分が前置部**になるため、そこに情報がない場合やエラーがある場合は心配する必要はありません。
* 情報のフレームでは、通常、**互いによく整列した異なるフレーム**を見つけるはずです。

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **ビットを回復した後、何らかの方法で処理する必要がある場合があります**。たとえば、マンチェスターコーディングでは、上下は1または0であり、下がり上がりはもう一方の値です。つまり、1と0のペア（上と下）は実際の1または実際の0になります。
* マンチェスターコーディングを使用している場合でも（連続して2つ以上の0または1を見つけることは不可能です）、前置部には複数の1または0が一緒になっている場合があります！

### IQを使用して変調方式を特定する

信号には情報を格納するための3つの方法があります：振幅、周波数、または位相を変調します。\
信号をチェックしている場合、情報が格納されている方法を特定しようとするさまざまな方法があります（以下にさらなる方法があります）、しかし、IQグラフをチェックするのは良い方法の1つです。

![](<../../.gitbook/assets/image (630).png>)

* **AMを検出する**：IQグラフに例えば**2つの円**が表示される場合（おそらく1つは0で、もう1つは異なる振幅である可能性があります）、これはAM信号である可能性があります。これは、IQグラフで0と円の間の距離が信号の振幅であるため、異なる振幅が使用されているのが視覚的にわかりやすいからです。
* **PMを検出する**：前の画像のように、関連しない小さな円が見つかる場合、おそらく位相変調が使用されていることを意味します。これは、IQグラフで、点と0,0の間の角度が信号の位相であるため、4つの異なる位相が使用されていることを意味します。
* 情報が位相自体ではなく位相の変化に隠されている場合、異なる位相が明確に区別されない場合があります。
* **FMを検出する**：IQには周波数を識別するためのフィールドがありません（中心への距離は振幅であり、角度は位相です）。\
したがって、FMを識別するには、このグラフで基本的に**円だけを見る**必要があります。\
さらに、異なる周波数は、IQグラフによって**円を加速させることで「表現」**されます（したがって、SysDiggerで信号を選択するとIQグラフが生成され、作成された円に加
## AMの例

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AMの解明

#### エンベロープの確認

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)を使用してAM情報を確認し、**エンベロープ**を見るだけで、異なる明確な振幅レベルが見えます。使用されている信号はAMで情報をパルスで送信しており、以下が1つのパルスの見た目です：

![](<../../.gitbook/assets/image (636).png>)

そして、以下が波形でシンボルの一部の見た目です：

![](<../../.gitbook/assets/image (650) (1).png>)

#### ヒストグラムの確認

情報が存在する信号全体を選択し、**振幅**モードと**選択**を選択し、**ヒストグラム**をクリックします。2つの明確なレベルのみが見つかることがわかります。

![](<../../.gitbook/assets/image (647) (1) (1).png>)

例えば、このAM信号で振幅の代わりに周波数を選択すると、1つの周波数のみが見つかります（周波数で情報が変調されている場合、1つの周波数のみを使用している可能性はありません）。

![](<../../.gitbook/assets/image (637) (1) (1).png>)

もし多くの周波数が見つかる場合、これはFMではないかもしれません。おそらく、チャンネルの影響で信号の周波数が変更されたためです。

#### IQでの確認

この例では、**大きな円**があることと、**中心に多くの点**があることがわかります。

![](<../../.gitbook/assets/image (640).png>)

### シンボルレートの取得

#### 1つのシンボルで

最も小さいシンボルを選択し（1つだけであることを確認するため）、"Selection freq"を確認します。この場合、1.013kHz（つまり1kHz）です。

![](<../../.gitbook/assets/image (638) (1).png>)

#### グループのシンボルで

選択するシンボルの数を指定することもできます。この場合、10個のシンボルを選択し、"Selection freq"は1.004 kHzです。

![](<../../.gitbook/assets/image (635).png>)

### ビットの取得

これが**AM変調**された信号であり、**シンボルレート**がわかっている（この場合、上が1を意味し、下が0を意味する）ことがわかっている場合、信号にエンコードされたビットを非常に簡単に取得できます。したがって、情報を持つ信号を選択し、サンプリングと決定を設定し、サンプルを押します（**振幅**が選択されていること、発見された**シンボルレート**が設定されていること、**ガードナークロックリカバリ**が選択されていることを確認してください）：

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals**は、シンボルレートを見つけるために事前に選択した間隔を使用することを意味します。
* **Manual**は、指定したシンボルレートが使用されることを意味します。
* **Fixed interval selection**では、選択する間隔の数を指定し、それからシンボルレートを計算します。
* **ガードナークロックリカバリ**は通常最適なオプションですが、おおよそのシンボルレートを指定する必要があります。

サンプルを押すと、次のように表示されます：

![](<../../.gitbook/assets/image (659).png>)

次に、SigDiggerに情報を保持しているレベルの範囲を理解させるために、**下のレベル**をクリックし、最大のレベルまでクリックし続ける必要があります。

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

もし例えば**振幅の異なる4つのレベル**があった場合、**Bits per symbolを2に設定**し、最小から最大まで選択する必要があります。

最後に、**ズームを増やし**、**行のサイズを変更**することでビットを見ることができます（すべてを選択してコピーすることもできます）：

![](<../../.gitbook/assets/image (649) (1).png>)

信号が1つのシンボルあたり1ビット以上（例えば2ビット）を持つ場合、SigDiggerはどのシンボルが00、01、10、11であるかを**知る方法がありません**。そのため、それぞれを表すために異なる**グレースケール**を使用します（ビットをコピーすると、**0から3の数字**が使用されますので、それらを処理する必要があります）。

また、**マンチェスター**などの**符号化**を使用する場合、**上+下**は**1または0**であり、**下+上**は1または0になります。この場合、取得した上（1）と下（0）を処理して、01または10のペアを0または1に置き換える必要があります。

## FMの例

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FMの解明

#### 周波数と波形の確認

FMで変調された情報を送信する信号の例：

![](<../../.gitbook/assets/image (661) (1).png>)

前の画像では、**2つの周波数が使用されている**ことがよくわかりますが、**波形**を観察しても正しく2つの異なる周波数を識別することはできないかもしれません：

![](<../../.gitbook/assets/image (653).png>)

これは、私が信号を両方の周波数でキャプチャしたためであり、したがって、1つの周波数は他の周波数に対しておおよそ負の値です：

![](<../../.gitbook/assets/image (656).png>)

同期周波数が**1つの周波数に近い**場合、2つの異なる周波数を簡単に見ることができます：

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### ヒストグラムの確認

情報を含む信号の周波数ヒストグラムを確認すると、2つの異なる信号が簡単に見つかります：

![](<../../.gitbook/assets/image (657).png>)

この場合、**振幅ヒストグラム**を確認すると、**1つの振幅のみ**が見つかるため、これは**AMではない**ことがわかります（多くの振幅が見つかる場合、信号がチャネルを通じてパワーを失っている可能性があります）：

![](<../../.gitbook/assets/image (646).png>)

そして、これが位相ヒストグラムです（信号が位相で変調されていないことが非常に明確です）：

![](<../../.gitbook/assets/image (201) (2).png>)
#### IQを使用して

IQには周波数を識別するためのフィールドがありません（中心への距離は振幅で、角度は位相です）。\
したがって、FMを識別するには、このグラフでは**基本的に円**しか見えません。\
さらに、異なる周波数はIQグラフによって**円周上の速度加速度で「表現」**されます（したがって、SysDiggerで信号を選択するとIQグラフが生成されますが、作成された円に加速度や方向の変化がある場合、これはFMである可能性があります）：

![](<../../.gitbook/assets/image (643) (1).png>)

### シンボルレートの取得

シンボルを運ぶ周波数を見つけた後、AMの例と同じ技術を使用してシンボルレートを取得することができます。

### ビットの取得

信号が周波数で変調されており、シンボルレートがわかっている場合、AMの例と同じ技術を使用してビットを取得することができます。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
