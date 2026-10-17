# ARM CoreSight-instruksiennasporing oor SWO

{{#include ../../banners/hacktricks-training.md}}

’n Toeganklike [SWD/JTAG-debugpoort](jtag.md) kan gebruik word om ’n lewendige Cortex-M-uitvoeringnasporing te aktiveer sonder firmware-instrumentering. Dit vereis ’n MCU met ETM en TPIU, ’n blootgestelde SWO-roete, ’n kopie van die presiese firmware om te dekodeer, en ’n logika-ontleder wat vinnig genoeg is vir die gekose SWO-biskoers. Anders as [krag- of EM-sykanaalmetings](side_channel_analysis.md), is ETM ’n debugnasporing; deur albei op te neem, kan waargenome lekkasie met uitgevoerde kode belyn word. Dieselfde belyning kan help om [fault injection](fault_injection_attacks.md) te tydsbereken.<sup>[[1]](#references)</sup>

ETM stuur saamgeperste beheervloeigebeurtenisse uit, nie instruksiegreepies nie. ’n Dekodeerder rekonstrueer die uitvoering aan die hand van die ooreenstemmende firmwarebeeld. ITM dra sagteware-instrumentering, terwyl TPIU nasporingsbronne raam en die serial-wire-uitset aandryf. Gaan die teiken se CoreSight-komponente en penmultipleksering in sy verwysingshandleiding na voordat enige registerwaardes toegepas word: die voorbeeld hieronder is vir ’n STM32F401, nie ’n universele Cortex-M-konfigurasie nie.<sup>[[1]](#references)</sup>

## Vind die nasporingsuitset

Op die STM32F401 gebruik asynchrone SWO PB3. Op die ondersoekte beheerder was PB3 aan resistor R15 gekoppel, wat ’n toeganklike meetpunt verskaf het. Wanneer die pakket of net nie sigbaar is nie, stel die kandidaatpen wat SWO kan ondersteun tydelik as ’n GPIO op en wissel die toestand daarvan deur SWD-geheueskrywes. Toets bordpunte vir die ooreenstemmende golfvorm en herstel dan die nasporingspenkonfigurasie. Koppel die ontleder met ’n gemeenskaplike grond en ’n versoenbare logikaspanning.<sup>[[1]](#references)</sup>

## Aktiveer TPIU en ETM met OpenOCD

Die volgende opdragte hoort in ’n OpenOCD-konfigurasie nadat die toepaslike adapter en `target/stm32f4x.cfg` gekies is. `setbits` behou onverwante bisse in beheerregisters, terwyl `mww` die hele woord oorskryf. Die TPIU roeteer eers asynchrone nasporing; daarna word ETM ontsluit, in programmeringsmodus gekonfigureer, nasporingsbron-ID `1` toegeken en begin. Hierdie waardes stem ooreen met die outeur se werkende STM32F401-konfigurasie, pas hulle dus by die teiken se registerkaart en klokboom aan.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401 OpenOCD-nasporingsregisterkonfigurasie</summary>

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

Die SWO-tempo is `HCLK / (TPIU_ACPR + 1)`. Met ’n 16 MHz HCLK en `ACPR=3`, neem op teen 4 Mbaud. Plaas in PulseView die ETM-dekodeerder bo ’n UART-dekodeerder op die SWO-ontlederkanaal, stel UART op die werklike tempo op die draad, en gebruik die ETM-bron-ID wat hierbo opgestel is. Die voorbeeld het 24 MHz-steekproefneming gebruik (ses steekproewe per bis), ’n dalende-rand-sneller en 25% voor-sneller-opname. Nadat jy dit opgestel het, stop/herstel die teiken, bewapen die opname en voer dan `resume` uit; verifieer ETM-sinchronisasie en ’n geloofwaardige PC-pad aan die hand van die firmware, eerder as om bloot op dekodeerderuitset wat geloofwaardig lyk, te vertrou.<sup>[[1]](#references)</sup>

## Herstel ná klok- en pin-mux-veranderinge

Twee onafhanklike firmware-aksies kan ’n geldige spoor stop. ’n PLL-verandering verhoog HCLK en dus die SWO-baudtempo terwyl `ACPR` onveranderd bly; die UART-laag herstel dan verkeerde grepe, en ETM-terugspeel word onsinnig. Inspekteer RCC/PLL-opstelling in [firmware analysis](../firmware-analysis/) en laai, in die STM32F401-voorbeeld, die Cortex-M-beeld by `0x08000000` en voer sy SVD in Ghidra in sodat klokregisterskrywes name het. Stel ’n hardeware-breekpunt op ’n twee-greep Thumb-instruksie *ná* klokinitialisering. In die voorbeeld stop `bp 0x080001fa 2 hw` gevolg deur `resume` ná PLL-opstelling; terwyl die teiken gestop is, stel `mww 0xe0040010 31` die nuwe verdeler. Bereken en stel die nuwe UART-tempo in, bewapen die opname en voer dan weer `resume` uit. Dit neem die pad ná die oorgang vas; dit herstel nie die oorgang wat gemis is nie.<sup>[[1]](#references)</sup>

Afsonderlik kan firmware die SWO-pad na ’n ander randtoestel herkarteer. In die voorbeeld het GPIO-alternatiewe-funksie-opstelling PB3 na I2C2 SDA oorgeskakel, so geen dekodeerderinstelling kon die spoor op daardie draad herstel nie. Vind die betrokke GPIO-initialisering in die firmware, en vervang dan óf die oproeppunte daarvan met Thumb-NOP’s wat dieselfde grootte het (`0xBF00` per halfwoord), óf stop die kern en herstel die spoorversoenbare penkonfigurasie deur SWD. Albei benaderings kan die randtoestel wat die pen verloor, deaktiveer; ’n herstel tydens looptyd kan ook weer deur firmware oorskryf word. Wanneer jy die pen tydens looptyd herstel, stel die SWO-verdeler vir die huidige HCLK in.<sup>[[1]](#references)</sup>

## References

- [1] [Following the Instructions: Live ARM Tracing with the ETM, ITM, and TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD ETM/TPIU configuration](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
