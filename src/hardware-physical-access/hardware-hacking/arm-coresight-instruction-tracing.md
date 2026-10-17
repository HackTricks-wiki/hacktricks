# Ufuatiliaji wa Maelekezo ya ARM CoreSight kupitia SWO

{{#include ../../banners/hacktricks-training.md}}

[SWD/JTAG debug port](jtag.md) inayofikika inaweza kutumika kuwezesha ufuatiliaji wa moja kwa moja wa utekelezaji wa Cortex-M bila kuweka instrumentation kwenye firmware. Hii inahitaji MCU yenye ETM na TPIU, njia ya SWO iliyo wazi, nakala ya firmware halisi kwa ajili ya decoding, na logic analyzer yenye kasi ya kutosha kwa kiwango cha biti cha SWO kilichochaguliwa. Tofauti na vipimo vya [power au EM side-channel](side_channel_analysis.md), ETM ni debug trace; kurekodi vyote viwili kunaweza kulandanisha leakage iliyozingatiwa na code iliyotekelezwa. Ulinganifu huohuo unaweza kusaidia kupanga muda wa [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM hutoa matukio yaliyobanwa ya mtiririko wa udhibiti badala ya baiti za maelekezo. Decoder huunda upya utekelezaji kwa kutumia picha ya firmware inayolingana. ITM hubeba instrumentation ya software, huku TPIU ikiunda fremu za trace sources na kuendesha serial-wire output. Kagua vipengele vya CoreSight vya target na pin multiplexing kwenye reference manual yake kabla ya kutumia thamani zozote za register: mfano ulio hapa chini ni wa STM32F401, si usanidi wa jumla wa Cortex-M.<sup>[[1]](#references)</sup>

## Tafuta sehemu ya kutoa trace

Kwenye STM32F401, SWO isiyosawazishwa hutumia PB3. Kwenye controller iliyochunguzwa, PB3 iliunganishwa na resistor R15, na hivyo kutoa sehemu inayofikika ya kuunganisha probe. Wakati package au net haionekani, sanidi kwa muda pin inayoweza kutumia SWO kama GPIO na uibadilishe hali kupitia SWD memory writes. Chunguza sehemu za board ili kupata waveform inayolingana, kisha rejesha usanidi wa trace pin. Unganisha analyzer kwa kutumia ground ya pamoja na kiwango cha voltage cha logic kinachooana.<sup>[[1]](#references)</sup>

## Wezesha TPIU na ETM kwa OpenOCD

Amri zifuatazo zinapaswa kuwekwa kwenye usanidi wa OpenOCD baada ya kuchagua adapter inayofaa na `target/stm32f4x.cfg`. `setbits` huhifadhi biti zisizohusiana kwenye control registers, ilhali `mww` hubadilisha neno zima. Kwanza TPIU huelekeza trace isiyosawazishwa; kisha ETM hufunguliwa, husanidiwa katika hali ya programming, hupewa trace source ID `1`, na kuwashwa. Thamani hizi zinatokana na usanidi wa STM32F401 uliofanya kazi kwa mwandishi, kwa hiyo zibadilishe kulingana na ramani ya register na clock tree ya target.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Usanidi wa trace-register wa STM32F401 OpenOCD</summary>

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

Kiwango cha SWO ni `HCLK / (TPIU_ACPR + 1)`. Kwa HCLK ya 16 MHz na `ACPR=3`, rekodi kwa 4 Mbaud. Katika PulseView, weka decoder ya ETM juu ya decoder ya UART kwenye channel ya analyzer ya SWO, weka UART kwa kiwango halisi cha waya, na utumie source ID ya ETM iliyosanidiwa hapo juu. Mfano ulitumia sampling ya 24 MHz (sampuli sita kwa kila biti), trigger ya ukingo unaoshuka, na capture ya 25% kabla ya trigger. Baada ya usanidi, simamisha/anzisha upya target, weka capture tayari, kisha `resume`; hakikisha ETM imesawazishwa na njia ya PC inaeleweka ikilinganishwa na firmware, badala ya kuamini tu matokeo yanayoonekana kana kwamba yamesimbuliwa.<sup>[[1]](#references)</sup>

## Rejesha baada ya mabadiliko ya clock na pin-mux

Vitendo viwili huru vya firmware vinaweza kusimamisha trace halali. Mabadiliko ya PLL huongeza HCLK na hivyo baud ya SWO huku `ACPR` ikibaki ileile; kisha safu ya UART hupokea bytes zisizo sahihi na uchezaji upya wa ETM huwa upuuzi. Kagua usanidi wa RCC/PLL katika [uchanganuzi wa firmware](../firmware-analysis/) na, kwenye mfano wa STM32F401, pakia image ya Cortex-M katika `0x08000000` na uingize SVD yake katika Ghidra ili maandishi ya register za clock yawe na majina. Weka hardware breakpoint kwenye instruction ya Thumb ya baiti mbili *baada* ya uanzishaji wa clock. Katika mfano, `bp 0x080001fa 2 hw` ikifuatiwa na `resume` husimamisha utekelezaji baada ya usanidi wa PLL; ikiwa imesimamishwa, `mww 0xe0040010 31` huweka divider mpya. Kokotoa na uweke kiwango kipya cha UART, weka capture tayari, kisha `resume` tena. Hii hunasa njia ya baada ya mabadiliko; hairudishi mabadiliko yaliyokosekana.<sup>[[1]](#references)</sup>

Kando na hilo, firmware inaweza kuelekeza upya padi ya SWO kwenye peripheral nyingine. Katika mfano, usanidi wa alternate-function wa GPIO uliweka PB3 kuwa I2C2 SDA, kwa hiyo hakuna mpangilio wa decoder ambao ungeweza kurejesha trace kwenye waya huo. Tafuta uanzishaji husika wa GPIO katika firmware, kisha ama badilisha sehemu inapoitiwa kwa Thumb NOP zenye ukubwa unaolingana (`0xBF00` kwa kila halfword) au simamisha core na urejeshe usanidi wa pini unaooana na trace kupitia SWD. Mbinu zote mbili zinaweza kuzima peripheral iliyohamishwa; urejeshaji wa wakati wa utekelezaji pia unaweza kufutwa tena na firmware. Unaporejesha pini wakati wa utekelezaji, weka divider ya SWO kulingana na HCLK ya sasa.<sup>[[1]](#references)</sup>

## References

- [1] [Kufuata Maelekezo: Ufuatiliaji wa ARM wa Moja kwa Moja kwa kutumia ETM, ITM, na TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: Usanidi wa STM32F4 OpenOCD ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
