# SWO पर ARM CoreSight Instruction Tracing

{{#include ../../banners/hacktricks-training.md}}

एक सुलभ [SWD/JTAG debug port](jtag.md) का उपयोग firmware instrumentation के बिना लाइव Cortex-M execution trace सक्षम करने के लिए किया जा सकता है। इसके लिए ETM और TPIU वाला MCU, बाहर लाया गया SWO मार्ग, decoding के लिए exact firmware की प्रति और चुनी गई SWO bit rate के लिए पर्याप्त तेज़ logic analyzer चाहिए। [Power या EM side-channel measurements](side_channel_analysis.md) के विपरीत, ETM एक debug trace है; दोनों को रिकॉर्ड करने से देखे गए leakage को निष्पादित code के साथ align किया जा सकता है। यही alignment [fault injection](fault_injection_attacks.md) का समय तय करने में भी मदद कर सकता है।<sup>[[1]](#references)</sup>

ETM instruction bytes के बजाय compressed control-flow events उत्सर्जित करता है। Decoder, matching firmware image के आधार पर execution को पुनर्निर्मित करता है। ITM software instrumentation ले जाता है, जबकि TPIU trace sources को frame करके serial-wire output चलाता है। किसी भी register value को लागू करने से पहले target के reference manual में उसके CoreSight components और pin multiplexing की जाँच करें: नीचे दिया गया उदाहरण STM32F401 के लिए है, न कि हर Cortex-M configuration के लिए।<sup>[[1]](#references)</sup>

## Trace output खोजें

STM32F401 पर asynchronous SWO, PB3 का उपयोग करता है। जाँचे गए controller में PB3, resistor R15 से जुड़ा था, जिससे probe point सुलभ हो गया। जब package या net छिपा हो, तो संभावित SWO-capable pin को अस्थायी रूप से GPIO के रूप में configure करें और SWD memory writes से उसे toggle करें। मेल खाते waveform के लिए board points को probe करें, फिर trace pin configuration को बहाल करें। Analyzer को common ground और संगत logic voltage के साथ जोड़ें।<sup>[[1]](#references)</sup>

## OpenOCD से TPIU और ETM सक्षम करें

नीचे दिए गए commands को OpenOCD configuration में, उपयुक्त adapter और `target/stm32f4x.cfg` चुनने के बाद रखें। `setbits` control registers के असंबंधित bits को सुरक्षित रखता है, जबकि `mww` पूरा word overwrite करता है। पहले TPIU asynchronous trace को route करता है; फिर ETM को unlock करके programming mode में configure किया जाता है, trace source ID `1` दिया जाता है और शुरू किया जाता है। ये मान लेखक के काम करने वाले STM32F401 configuration पर आधारित हैं, इसलिए इन्हें target के register map और clock tree के अनुसार ढालें।<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401 OpenOCD trace-register configuration</summary>

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

SWO rate `HCLK / (TPIU_ACPR + 1)` होता है। 16 MHz HCLK और `ACPR=3` के साथ, 4 Mbaud पर कैप्चर करें। PulseView में, SWO analyzer channel पर UART decoder के ऊपर ETM decoder रखें, UART को wire की वास्तविक दर पर सेट करें, और ऊपर कॉन्फ़िगर किया गया ETM source ID इस्तेमाल करें। उदाहरण में 24 MHz sampling (प्रति bit छह samples), falling-edge trigger और 25% pre-trigger capture का उपयोग किया गया था। कॉन्फ़िगरेशन के बाद, target को halt/reset करें, capture arm करें, फिर `resume` करें; केवल decoded-जैसे दिखने वाले output पर भरोसा करने के बजाय, ETM synchronization और firmware के अनुरूप एक plausible PC path की पुष्टि करें।<sup>[[1]](#references)</sup>

## Clock और pin-mux बदलावों से उबरना

Firmware की दो स्वतंत्र कार्रवाइयाँ valid trace रोक सकती हैं। PLL में बदलाव HCLK बढ़ाता है और इसलिए SWO baud भी बढ़ जाता है, जबकि `ACPR` अपरिवर्तित रहता है; तब UART layer गलत bytes recover करती है और ETM replay बेतुका हो जाता है। [firmware analysis](../firmware-analysis/) में RCC/PLL setup देखें और STM32F401 उदाहरण में Cortex-M image को `0x08000000` पर load करें तथा Ghidra में उसका SVD import करें, ताकि clock-register writes के नाम दिखें। Clock initialization *के बाद* आने वाले दो-byte Thumb instruction पर hardware breakpoint सेट करें। उदाहरण में, `bp 0x080001fa 2 hw` के बाद `resume` करने पर PLL setup के बाद execution रुकता है; halted रहते हुए, `mww 0xe0040010 31` नया divider सेट करता है। नई UART rate की गणना करके उसे सेट करें, capture arm करें, फिर दोबारा `resume` करें। इससे transition के बाद का path कैप्चर होता है; छूटे हुए transition को वापस प्राप्त नहीं किया जा सकता।<sup>[[1]](#references)</sup>

अलग से, firmware SWO pad को किसी दूसरे peripheral पर remap कर सकता है। उदाहरण में, GPIO alternate-function setup ने PB3 को I2C2 SDA पर switch कर दिया, इसलिए कोई भी decoder setting उस wire पर trace वापस नहीं ला सकती थी। Firmware में संबंधित GPIO initialization खोजें, फिर या तो उसके call sites को समान आकार वाले Thumb NOPs (`0xBF00` प्रति halfword) से बदलें, या core को halt करके SWD के ज़रिए trace-compatible pin configuration बहाल करें। दोनों तरीकों से उस pin पर इस्तेमाल हो रहा peripheral बंद हो सकता है; runtime restore को firmware फिर से overwrite भी कर सकता है। Runtime पर pin बहाल करते समय, मौजूदा HCLK के लिए SWO divider सेट करें।<sup>[[1]](#references)</sup>

## References

- [1] [निर्देशों का अनुसरण: ETM, ITM और TPIU के साथ Live ARM Tracing](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD ETM/TPIU configuration](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
