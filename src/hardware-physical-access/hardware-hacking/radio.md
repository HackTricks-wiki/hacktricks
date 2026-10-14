# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) は、未知の無線信号から情報を抽出するために設計された、GNU/Linux および macOS 向けの無料のデジタル信号アナライザーです。SoapySDR 経由で SDR デバイスをサポートし、FSK、PSK、ASK、アナログビデオ、バースト信号、アナログ音声チャネル向けのリアルタイム復調・解析ツールを備えています。<sup>[[1]](#references)</sup>

### Basic Config

インストール後、設定を検討できる項目がいくつかあります。\
設定（2つ目のタブボタン）で、**SDR device** または入力ファイル、受信する周波数、サンプルレートを選択します。ホストが対応していれば、最大 2.56 Msps のレートが実用的です。

![SDR デバイス、入力ファイル、周波数、サンプルレートのオプションを表示する SigDigger の設定画面](<../../images/image (245).png>)

PC が対応している場合は、GUI behaviour でいくつかの項目を有効にすることをおすすめします。

![SigDigger - Basic Config: PC が対応している場合、GUI behaviour でいくつかの項目を有効にすることをおすすめします](<../../images/image (472).png>)

> [!TIP]
> PC で信号をキャプチャできない場合は、OpenGL を無効にし、サンプルレートを下げてみてください。

### Uses

- 信号を一定時間**キャプチャして解析する**には、必要な時間だけ「Push to capture」ボタンを押し続けます。

![Basic Config - Uses: 信号を一定時間キャプチャして解析するには、必要な時間だけ「Push to capture」ボタンを押し続けます](<../../images/image (960).png>)

- SigDigger の **Tuner** を使うと、より良い信号を**キャプチャできます**（ただし、信号が劣化することもあります）。理想的には 0 から始め、必要な信号の改善よりも、加わる**ノイズ**のほうが**大きくなるまで**値を上げていきます。

![キャプチャした無線信号を改善するよう調整された SigDigger のチューナー](<../../images/image (1099).png>)

### Synchronize with radio channel

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)で受信したいチャネルに同期し、「Baseband audio preview」オプションを設定します。送信された情報をすべて取得できるよう帯域幅を設定し、ノイズが大きくなり始める直前のレベルに Tuner を設定します。<sup>[[1]](#references)</sup>

![ベースバンド音声プレビューと帯域幅を設定して無線チャネルに同期した SigDigger](<../../images/image (585).png>)

## Interesting tricks

- デバイスが情報をバースト送信する場合、通常、**最初の部分はプリアンブル**です。そのため、そこに**情報が見つからなくても**、または**エラーがあっても**、気にする必要はありません。
- 情報フレームでは通常、**複数のフレームが互いにきれいに揃っている**のが確認できます。

![Synchronize with radio channel - Interesting tricks: 情報フレームでは通常、複数のフレームが互いにきれいに揃っているのが確認できます](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: 情報フレームでは通常、複数のフレームが互いにきれいに揃っているのが確認できます](<../../images/image (597).png>)

- **レベル遷移を復元した後、デコードが必要になる場合があります。** Manchester encoding では、一方の遷移方向が `0`、逆方向が `1` を表します。どちらの極性を使うかは、採用されている規約によって異なります。
- ペイロードが Manchester encoding を使っていても、プリアンブルには同じサンプリングレベルが連続して含まれる場合があります。そのため、デコード前にフレーム境界を特定してください。

### Uncovering modulation type with IQ

信号で情報を伝える方法は3つあります。**振幅**、**周波数**、**位相**を変調します。\
信号を調べる際、情報を伝えるために何が使われているかを見分ける方法はいくつかあります（他の方法は以下を参照）。そのうちの1つとして、IQ グラフを確認するのが有効です。

![信号が振幅変調、周波数変調、位相変調のどれを使うかを判別するための SigDigger IQ グラフ](<../../images/image (788).png>)

- **AM の検出**: IQ グラフに、たとえば**2つの円**（おそらく片方は 0 にあり、もう片方は異なる振幅にある）が表示された場合、AM 信号の可能性があります。IQ グラフでは 0 から円までの距離が信号の振幅なので、異なる振幅が使われていることを視覚的に確認できます。
- **PM の検出**: 前の画像のように、互いに関連のない小さな円が見つかった場合、位相変調が使われている可能性があります。IQ グラフでは点と (0,0) の間の角度が信号の位相なので、これは4種類の位相が使われていることを意味します。
  - 位相そのものではなく、位相が変化したという事実に情報が含まれている場合、異なる位相をはっきり見分けることはできません。
- **FM の検出**: IQ には周波数を識別するフィールドがありません（中心からの距離は振幅、角度は位相です）。\
  そのため、FM を特定するには、このグラフに基本的に**円だけが見える**はずです。\
  また、周波数オフセットによって IQ の円周上の回転速度が変化します。そのため SigDigger では、回転速度や方向の変化が FM を示す場合があります。

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

[**SigDigger**](https://github.com/BatchDrake/SigDigger)で AM データを調べると、信号の**エンベロープ**から明確な振幅レベルを確認できます。このサンプル信号は振幅変調されたパルスで情報を送信しています。パルスの1つは次のようになります。<sup>[[1]](#references)</sup>

![明確なパルス振幅レベルを示す SigDigger の AM 信号エンベロープ](<../../images/image (590).png>)

波形で見ると、シンボルの一部は次のようになります。

![Uncovering AM - Checking the envelope: 波形で見ると、シンボルの一部は次のようになります](<../../images/image (734).png>)

#### Checking the Histogram

情報が含まれる信号全体を**選択**し、**Amplitude** モードと **Selection** を選択して、**Histogram** をクリックします。明確なレベルが2つだけ見つかることがわかります。

![選択した AM 信号について、明確なレベルが2つ表示された SigDigger の振幅ヒストグラム](<../../images/image (264).png>)

たとえば、この AM 信号で **Amplitude** の代わりに Frequency を選択すると、周波数は1つしか見つかりません（周波数変調された情報が周波数を1つだけ使うことはありません）。

![1つの周波数を示す AM 信号の SigDigger 周波数ヒストグラム](<../../images/image (732).png>)

多くの周波数が見つかった場合、それは FM ではない可能性があります。チャネルの影響で信号の周波数が変化しただけかもしれません。

#### With IQ

この例では、**大きな円**と、中央に**多数の点**があることがわかります。

![Checking the Histogram - With IQ: この例では、大きな円と、中央に多数の点があることがわかります](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

1つのシンボルを明確に含む最小の区間を選択し、**Selection freq** を確認します。この例では 1.013 kHz、つまり約 1 kHz です。

![Get Symbol Rate - With one symbol: 見つけた最小のシンボルを選択し（1つだけであることを確認するため）、"Selection freq" を確認します。この例では 1.013 kHz（つまり 1 kHz）です。](<../../images/image (78).png>)

#### With a group of symbols

選択するシンボル数を指定することもできます。SigDigger が1シンボルの周波数を計算します（選択するシンボル数が多いほど、精度が上がる可能性があります）。この例では10個のシンボルを選択し、「Selection freq」は 1.004 kHz です。

![10個のシンボルを選択して SigDigger がシンボルレートを計算した例](<../../images/image (1008).png>)

### Get Bits

AM を特定して**シンボルレート**を推定したら、信号領域を選択し、振幅サンプリングと判定レベルを設定して、**Gardner clock recovery** を選択し、**Sample** を押します。

![AM サンプリング、シンボルレート、Gardner clock recovery を設定した SigDigger の Get Bits パネル](<../../images/image (965).png>)

- **Sync to selection intervals** は、シンボルレートを求めるために事前に区間を選択していた場合、そのシンボルレートを使う設定です。
- **Manual** は、指定したシンボルレートを使う設定です。
- **Fixed interval selection** では、選択する区間数を指定すると、そこからシンボルレートが計算されます。
- **Gardner clock recovery** は便利なデフォルト設定ですが、おおよそのシンボルレートを指定する必要があります。

Sample を押すと、次のように表示されます。

![With a group of symbols - Get Bits: Sample を押すと、次のように表示されます](<../../images/image (644).png>)

SigDigger に情報を含むレベルの**範囲**を認識させるには、**低いレベル**をクリックし、クリックしたまま最も高いレベルまでドラッグします。

![低い振幅レベルから高いレベルまで選択した SigDigger のレベル範囲](<../../images/image (439).png>)

たとえば振幅レベルが**4種類**ある場合は、**Bits per symbol を 2** に設定し、最小レベルから最大レベルまで選択します。

最後に **Zoom** を上げて **Row size** を変更すると、ビットが表示されます（すべてを選択してコピーすれば、ビット全体を取得できます）。

![With a group of symbols - Get Bits: 最後に Zoom を上げて Row size を変更すると、ビットが表示されます（すべてを選択してコピーすれば、ビット全体を取得できます）](<../../images/image (276).png>)

信号が1シンボルあたり2ビットなど、1ビットを超える場合、SigDigger はどのシンボルが 00、01、10、11 なのかを判別できません。そのため、各シンボルを異なる**グレースケール**で表示します（ビットをコピーすると **0 から 3 の数値**が使われるので、適切に処理する必要があります）。

**Manchester** などのライン符号化では、有効な遷移ペア（`01` または `10`）を、プロトコルで使われている規約に従ってデータビットに変換します。

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

FM 変調で情報を送信する信号の例です。

![Uncovering FM - Checking the frequencies and waveform: FM 変調で情報を送信する信号の例](<../../images/image (725).png>)

スペクトルには**2つの周波数**がはっきり表示されますが、時間領域の波形では見分けにくい場合があります。

![2つの周波数を波形上で直接見分けにくい SigDigger の FM 波形](<../../images/image (717).png>)

これは、キャプチャの中心周波数が2つの周波数の中間にあるためです。その結果、それぞれの周波数オフセットはほぼ反対になります。

![ほぼ互いに反対の値となる2つの周波数を示す SigDigger の FM キャプチャ](<../../images/image (942).png>)

同期した周波数が一方の周波数に**より近い**場合は、2つの異なる周波数を簡単に確認できます。

![Uncovering FM - Checking the frequencies and waveform: 同期した周波数が一方の周波数により近い場合、2つの異なる周波数を簡単に確認できます](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: 同期した周波数が一方の周波数により近い場合、2つの異なる周波数を簡単に確認できます](<../../images/image (488).png>)

#### Checking the histogram

情報を含む信号の周波数ヒストグラムを確認すると、異なる2つの信号を簡単に見つけられます。

![Checking the frequencies and waveform - Checking the histogram: 情報を含む信号の周波数ヒストグラムを確認すると、異なる2つの信号を簡単に見つけられます](<../../images/image (871).png>)

この場合、**Amplitude histogram** を確認すると**振幅は1つだけ**です。そのため、**AM ではありえません**（多くの振幅が見つかる場合、チャネルを通る間に信号が減衰したことが原因かもしれません）。

![振幅レベルが1つだけ表示された SigDigger の FM 信号振幅ヒストグラム](<../../images/image (817).png>)

これは位相ヒストグラムです（信号が位相変調されていないことが明確にわかります）。

![Checking the frequencies and waveform - Checking the histogram: 位相ヒストグラムです（信号が位相変調されていないことが明確にわかります）](<../../images/image (996).png>)

#### With IQ

IQ には周波数を識別するフィールドがありません（中心からの距離は振幅、角度は位相です）。\
そのため、FM を特定するには、このグラフに基本的に**円だけが見える**はずです。\
また、周波数オフセットによって IQ の円周上の回転速度が変化します。そのため SigDigger では、回転速度や方向の変化が FM を示す場合があります。

![円周上の回転速度の変化として FM が表示される SigDigger の IQ グラフ](<../../images/image (81).png>)

### Get Symbol Rate

シンボルを表す周波数が見つかったら、シンボルレートの取得には**AM の例で使ったものと同じ方法**を使えます。

### Get Bits

信号が**周波数変調されていること**と**シンボルレート**がわかったら、ビットの取得には**AM の例で使ったものと同じ方法**を使えます。

## References

- [1] [SigDigger - GNU/Linux および macOS 向け無料デジタル信号アナライザー](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
