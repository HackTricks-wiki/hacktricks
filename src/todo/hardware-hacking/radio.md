# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)は、未知の radio signals から情報を抽出するために設計された、GNU/LinuxおよびmacOS向けの無料のデジタル信号 analyzer です。SoapySDRを通じてさまざまなSDR devicesをサポートし、FSK、PSK、ASK signalsのdemodulationを調整したり、アナログ videoのdecode、burst信号の分析、アナログ voice channelsのlistenを行えます（すべて real timeで実行されます）。<sup>[[1]](#references)</sup>

### Basic Config

インストール後、いくつか設定しておくとよい項目があります。\
settings（2番目のtab button）では、**SDR device**または読み込む**fileを選択**し、syntoniseするfrequencyとSample rateを選択できます（PCが対応している場合、推奨値は最大2.56Mspsです）。

![SDR device、input file、frequency、sample rateのオプションを示すSigDiggerのsettings](<../../images/image (245).png>)

GUI behaviourでは、PCが対応している場合、いくつかの項目を有効にすることを推奨します。

![SigDigger - Basic Config: PCが対応している場合、GUI behaviourでいくつかの項目を有効にすることを推奨します](<../../images/image (472).png>)

> [!TIP]
> PCが何もcaptureしていない場合は、OpenGLを無効にしてsample rateを下げてみてください。

### Uses

- 信号を一定時間**captureして分析する**だけなら、必要な時間だけ「Push to capture」buttonを押し続けます。

![Basic Config - Uses: 信号を一定時間captureして分析するには、必要な時間だけ「Push to capture」buttonを押し続けます](<../../images/image (960).png>)

- SigDiggerの**Tuner**は、**より良い信号をcaptureする**のに役立ちます（ただし、信号を悪化させることもあります）。理想的には0から始め、**noiseの増加**が**必要な信号の改善**を上回るまで値を**大きくしていきます**。

![captureしたradio signalを改善するように調整されたSigDigger tuner control](<../../images/image (1099).png>)

### radio channelとのSynchronize

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)で聞きたいchannelとsynchronizeし、「Baseband audio preview」optionを設定し、送信されているすべての情報を取得できるようにbandwidthを設定します。その後、noiseが本格的に増加する直前のlevelにTunerを設定します。<sup>[[1]](#references)</sup>

![baseband audio previewとbandwidthを設定し、radio channelとsynchronizeしたSigDigger](<../../images/image (585).png>)

## Interesting tricks

- deviceが情報のburstを送信している場合、通常、**最初の部分はpreamble**です。そのため、そこに**情報が見つからなくても**、または**いくつかerrorsがあっても**、**気にする必要はありません**。
- 情報のframesでは、通常、**互いに適切にalignedされた異なるframes**を**見つけることができます**。

![Synchronize with radio channel - Interesting tricks: 情報のframesでは、通常、互いに適切にalignedされた異なるframesを見つけることができます](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: 情報のframesでは、通常、互いに適切にalignedされた異なるframesを見つけることができます](<../../images/image (597).png>)

- **bitsをrecoverした後、それらを何らかの方法でprocessする必要がある場合があります**。たとえば、Manchester codificationでは、up+downが1または0になり、down+upがもう一方になります。つまり、1と0のpairs（upsとdowns）が実際の1または0になります。
- 信号がManchester codificationを使用している場合（連続して3つ以上の0または1が現れることはありません）でも、**preamble内では複数の1や0が連続して見つかることがあります**。

### IQを使用したmodulation typeのUncovering

信号に情報を保存する方法は3つあります。**amplitude**、**frequency**、または**phase**をmodulateすることです。\
信号を調べる際、どの方法が情報の保存に使用されているかを判断する方法はいくつかあります（以下に別の方法も記載します）が、良い方法の1つはIQ graphを確認することです。

![信号がamplitude、frequency、phase modulationのどれを使用しているかを識別するためのSigDigger IQ graph](<../../images/image (788).png>)

- **AMのDetecting**: IQ graphに、たとえば**2つのcircles**（おそらく一方は0、もう一方は異なるamplitude）が表示される場合、AM signalの可能性があります。IQ graphでは0とcircleの距離が信号のamplitudeなので、異なるamplitudesが使用されていることを簡単に確認できます。
- **PMのDetecting**: 前の画像のように、互いに関連しない小さなcirclesが見つかる場合、phase modulationが使用されている可能性があります。IQ graphではpointと0,0の間のangleが信号のphaseなので、これは4つの異なるphasesが使用されていることを意味します。
- 情報がphaseそのものではなく、phaseが変化した事実に隠されている場合、異なるphasesが明確に区別されて表示されることはありません。
- **FMのDetecting**: IQにはfrequenciesを識別するfieldがありません（centreからの距離はamplitude、angleはphaseです）。\
そのため、FMを識別するには、このgraph上で**基本的に1つのcircleだけが見える**はずです。\
さらに、異なるfrequencyはIQ graph上で**circleを横切るspeedのacceleration**として「表現」されます（そのため、SysDiggerでsignalを選択してIQ graphを表示し、作成されたcircleにaccelerationまたはdirectionの変化が見つかれば、FMの可能性があります）。

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AMのUncovering

#### envelopeのChecking

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)でAM informationを確認し、**envelop**を見るだけで、異なる明確なamplitude levelsを確認できます。使用されているsignalは、AMでinformationを含むpulsesを送信しています。1つのpulseは次のようになります。<sup>[[1]](#references)</sup>

![明確なpulse amplitude levelsを持つSigDigger AM signalのenvelope](<../../images/image (590).png>)

waveformを含むsymbolの一部は次のようになります。

![Uncovering AM - Checking the envelope: waveformを含むsymbolの一部](<../../images/image (734).png>)

#### HistogramのChecking

informationが存在する**signal全体をselect**し、**Amplitude** modeと**Selection**を選択して、**Histogram**をclickします。明確なlevelsが2つだけ見つかることを確認できます。

![選択したAM signalの2つの明確なlevelsを示すSigDigger amplitude histogram](<../../images/image (264).png>)

たとえば、このAM signalでAmplitudeの代わりにFrequencyをselectすると、frequencyは1つだけ見つかります（frequencyでmodulateされたinformationが1つのfreqだけを使用しているとは考えにくいためです）。

![1つのfrequencyを示すAM signalのSigDigger frequency histogram](<../../images/image (732).png>)

多数のfrequenciesが見つかる場合、これはFMではない可能性があります。channelの影響でsignal frequencyが変更されただけかもしれません。

#### IQを使用

この例では、**大きなcircle**だけでなく、**centreに多数のpoints**があることがわかります。

![Checking the Histogram - With IQ: 大きなcircleとcentreの多数のpointsを示す例](<../../images/image (222).png>)

### Symbol Rateの取得

#### 1つのsymbolを使用

見つけられる最小のsymbol（確実に1つだけであるもの）をselectし、「Selection freq」を確認します。この場合は1.013kHz（つまり1kHz）です。

![Get Symbol Rate - With one symbol: 見つけられる最小のsymbolをselectし、「Selection freq」を確認します。この場合は1.013kHz（つまり1kHz）です](<../../images/image (78).png>)

#### symbolsのgroupを使用

selectするsymbolsの数を指定することもできます。SigDiggerは1つのsymbolのfrequencyを計算します（おそらく、selectするsymbolsが多いほど精度が向上します）。この例では10 symbolsをselectし、「Selection freq」は1.004 Khzです。

![10個のsymbolsをselectしたgroupを使用したSigDiggerのsymbol-rate calculation](<../../images/image (1008).png>)

### Bitsの取得

これが**AM modulated** signalであり、**symbol rate**も判明した（この例では、上向きが1、下向きが0であることもわかっている）ため、signalにencodedされた**bitsを取得する**のは非常に簡単です。informationを含むsignalをselectし、samplingとdecisionを設定してsampleを押します（**Amplitude**がselectされ、発見した**Symbol rate**が設定され、**Gadner clock recovery**がselectされていることを確認してください）。

![AM sampling、symbol rate、Gardner clock recovery用に設定されたSigDigger Get Bits panel](<../../images/image (965).png>)

- **Sync to selection intervals**は、以前symbol rateを見つけるためにintervalsをselectしていた場合、そのsymbol rateを使用することを意味します。
- **Manual**は、指定したsymbol rateを使用することを意味します。
- **Fixed interval selection**では、selectするintervalsの数を指定し、そこからsymbol rateを計算します。
- **Gadner clock recovery**は通常最適なoptionですが、おおよそのsymbol rateを指定する必要があります。

sampleを押すと、次のように表示されます。

![With a group of symbols - Get Bits: sampleを押すと表示される画面](<../../images/image (644).png>)

ここで、informationを含むlevelの**rangeがどこにあるか**をSigDiggerに認識させるには、**lower level**をclickし、最大levelまでclickしたままにします。

![lower amplitude levelからupper levelまでのSigDigger level-range selection](<../../images/image (439).png>)

たとえば**4つの異なるamplitude levels**がある場合、**Bits per symbolを2**に設定し、最小levelから最大levelまでselectする必要があります。

最後に**Zoom**を**拡大**し、**Row size**を**変更**すると、bitsを確認できます（すべてselectしてcopyすれば、すべてのbitsを取得できます）。

![With a group of symbols - Get Bits: Zoomを拡大し、Row sizeを変更するとbitsを確認できます](<../../images/image (276).png>)

signalが1 symbolあたり1 bitより多く（たとえば2 bits）持つ場合、SigDiggerにはどのsymbolが00、01、10、11なのかを知る方法がありません。そのため、それぞれを異なる**grey scales**で表示します（bitsをcopyすると0から3までの**numbers**が使用されるため、処理する必要があります）。

また、**codifications**として**Manchester**なども使用されます。**up+down**は**1または0**、down+upも1または0になります。この場合、取得したups（1）とdowns（0）を処理し、01または10のpairsを0または1に置き換える必要があります。

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FMのUncovering

#### frequenciesとwaveformのChecking

FMでmodulateされたinformationを送信するsignalの例です。

![Uncovering FM - Checking the frequencies and waveform: FMでmodulateされたinformationを送信するsignalの例](<../../images/image (725).png>)

前の画像では、**2つのfrequenciesが使用されている**ことがかなり明確にわかります。しかし、**waveformを確認**すると、**2つの異なるfrequenciesを正しく識別できない**場合があります。

![2つのfrequenciesを直接識別するのが難しいSigDigger FM waveform](<../../images/image (717).png>)

これは、signalを両方のfrequenciesでcaptureしているため、一方がもう一方のapproximately negativeになっているからです。

![2つのfrequenciesが互いにapproximately negativeとして表示されるSigDigger FM capture](<../../images/image (942).png>)

synchronized frequencyが一方のfrequencyに他方より**近い**場合、2つの異なるfrequenciesを簡単に確認できます。

![synchronized frequencyが一方のfrequencyに他方より近い場合、2つの異なるfrequenciesを簡単に確認できる例](<../../images/image (422).png>)

![synchronized frequencyが一方のfrequencyに他方より近い場合、2つの異なるfrequenciesを簡単に確認できる例](<../../images/image (488).png>)

#### histogramのChecking

informationを含むsignalのfrequency histogramを確認すると、2つの異なるsignalsを簡単に確認できます。

![Checking the frequencies and waveform - Checking the histogram: informationを含むsignalのfrequency histogramで2つの異なるsignalsを確認する例](<../../images/image (871).png>)

この場合、**Amplitude histogram**を確認すると、**amplitudeは1つだけ**見つかります。そのため、これは**AMではありません**（多数のamplitudesが見つかる場合、channel上でsignalがpowerを失ったことが原因かもしれません）。

![単一のamplitude levelを示すSigDigger FM signalのamplitude histogram](<../../images/image (817).png>)

これはphase histogramです（signalがphaseでmodulateされていないことが非常に明確にわかります）。

![Checking the frequencies and waveform - Checking the histogram: signalがphaseでmodulateされていないことを明確に示すphase histogram](<../../images/image (996).png>)

#### IQを使用

IQにはfrequenciesを識別するfieldがありません（centreからの距離はamplitude、angleはphaseです）。\
そのため、FMを識別するには、このgraph上で**基本的に1つのcircleだけが見える**はずです。\
さらに、異なるfrequencyはIQ graph上で**circleを横切るspeedのacceleration**として「表現」されます（そのため、SysDiggerでsignalをselectしてIQ graphを表示し、作成されたcircleにaccelerationまたはdirectionの変化が見つかれば、FMの可能性があります）。

![FMがcircle上のacceleration changesとして表示されるSigDigger IQ graph](<../../images/image (81).png>)

### Symbol Rateの取得

symbolsを含むfrequenciesを見つけたら、AM exampleで使用した**same technique**を使ってsymbol rateを取得できます。

### Bitsの取得

**signalがfrequencyでmodulateされている**ことと**symbol rate**が判明したら、AM exampleで使用した**same technique**を使ってbitsを取得できます。

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
