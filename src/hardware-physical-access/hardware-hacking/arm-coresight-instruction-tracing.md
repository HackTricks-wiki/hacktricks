# SWO経由のARM CoreSight命令トレース

{{#include ../../banners/hacktricks-training.md}}

アクセス可能な[SWD/JTAG debug port](jtag.md)を使用すると、ファームウェアに計測処理を追加せずに、Cortex-Mの実行トレースをリアルタイムで有効化できます。そのためには、ETMとTPIUを備えたMCU、外部に引き出されたSWO経路、デコード用の正確なファームウェアのコピー、および選択したSWOビットレートに対応できる十分な速度のロジックアナライザーが必要です。[電力またはEMサイドチャネル測定](side_channel_analysis.md)とは異なり、ETMはdebug traceです。両方を記録すれば、観測されたleakを実行コードに対応付けられます。同じ対応付けは、[fault injection](fault_injection_attacks.md)のタイミング調整にも役立ちます。<sup>[[1]](#references)</sup>

ETMは命令バイトではなく、圧縮された制御フローイベントを出力します。デコーダーは、対応するファームウェアイメージに基づいて実行内容を再構成します。ITMはソフトウェア計測データを伝送し、TPIUはトレースソースをフレーム化してシリアルワイヤ出力を駆動します。レジスター値を適用する前に、対象のCoreSightコンポーネントとピンの多重化設定をリファレンスマニュアルで確認してください。以下の例はSTM32F401向けであり、すべてのCortex-Mに適用できる設定ではありません。<sup>[[1]](#references)</sup>

## トレース出力を探す

STM32F401では、非同期SWOにPB3を使用します。調査対象のコントローラーでは、PB3は抵抗R15に接続されており、アクセス可能なプローブポイントになっていました。パッケージやネットが隠れている場合は、SWO対応候補ピンを一時的にGPIOとして設定し、SWDのメモリ書き込みでトグルさせます。基板上のポイントをプローブして一致する波形を探し、その後、トレース用のピン設定を元に戻します。アナライザーは共通グラウンドと、互換性のあるロジック電圧で接続してください。<sup>[[1]](#references)</sup>

## OpenOCDでTPIUとETMを有効にする

以下のコマンドは、適切なアダプターと`target/stm32f4x.cfg`を選択した後、OpenOCDの設定に記述します。`setbits`は制御レジスター内の無関係なビットを保持しますが、`mww`はワード全体を上書きします。まずTPIUで非同期トレースを経路設定し、その後ETMのロックを解除してプログラミングモードで設定し、トレースソースID `1`を割り当てて起動します。これらの値は著者が動作を確認したSTM32F401の設定に基づくため、対象のレジスターマップとクロックツリーに合わせて調整してください。<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401 OpenOCDトレースレジスター設定</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

SWO rate は `HCLK / (TPIU_ACPR + 1)` です。HCLK が 16 MHz で `ACPR=3` の場合、4 Mbaud でキャプチャします。PulseView では、SWO アナライザーチャネル上で ETM decoder を UART decoder の上に配置し、UART を実際の信号線の速度に設定し、上記で設定した ETM source ID を使用します。この例では、24 MHz のサンプリング（1 ビットあたり6サンプル）、立ち下がりエッジのトリガー、25% のプリトリガーキャプチャを使用しました。設定後、ターゲットを halt/reset し、キャプチャを開始してから `resume` します。デコード結果がそれらしく見えるだけで信用せず、ETM の同期とファームウェアに照らして妥当な PC の経路を確認してください。<sup>[[1]](#references)</sup>

## クロックおよびピンの多重化変更から復旧する

ファームウェアによる独立した2つの動作で、正常なトレースが停止することがあります。PLL の変更によって HCLK が上昇すると、`ACPR` が固定されたまま SWO のボーレートも上がります。その結果、UART レイヤーは誤ったバイトを復元し、ETM のリプレイは意味をなさなくなります。[firmware analysis](../firmware-analysis/) で RCC/PLL の設定を調べます。STM32F401 の例では、Cortex-M イメージを `0x08000000` にロードし、Ghidra に SVD をインポートして、クロックレジスターへの書き込みに名前を付けます。クロック初期化後にある2バイトの Thumb 命令にハードウェアブレークポイントを設定します。この例では、`bp 0x080001fa 2 hw` に続けて `resume` を実行すると、PLL の設定後に停止します。停止中に `mww 0xe0040010 31` を実行して、新しい分周値を設定します。新しい UART 速度を計算して設定し、キャプチャを開始してから、もう一度 `resume` を実行します。これで遷移後の経路をキャプチャできますが、見逃した遷移を復元することはできません。<sup>[[1]](#references)</sup>

別のケースとして、ファームウェアが SWO パッドを別のペリフェラルに再マッピングすることがあります。この例では、GPIO の代替機能設定によって PB3 が I2C2 SDA に切り替えられていたため、decoder の設定ではその信号線のトレースを復旧できませんでした。ファームウェア内で該当する GPIO 初期化を見つけ、呼び出し箇所をサイズの合う Thumb NOP（半ワードごとに `0xBF00`）に置き換えるか、コアを halt して SWD 経由でトレースに対応したピン設定に戻します。どちらの方法でも、切り替え先のペリフェラルが無効になる場合があります。また、実行時に設定を戻しても、ファームウェアによって再度上書きされる可能性があります。実行時にピンを戻す場合は、現在の HCLK に合わせて SWO divider を設定してください。<sup>[[1]](#references)</sup>

## References

- [1] [命令を追う: ETM、ITM、TPIU による ARM のライブトレース](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD ETM/TPIU 設定](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
