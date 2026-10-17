# Praćenje instrukcija ARM CoreSight preko SWO

{{#include ../../banners/hacktricks-training.md}}

Dostupan [SWD/JTAG debug port](jtag.md) može da se iskoristi za uključivanje praćenja izvršavanja Cortex-M procesora uživo, bez instrumentacije firmware-a. Za to je potreban MCU sa ETM i TPIU, dostupan SWO vod, kopija tačnog firmware-a radi dekodiranja i logic analyzer dovoljno brz za izabrani SWO bit rate. Za razliku od [merenja bočnih kanala napajanja ili EM](side_channel_analysis.md), ETM je debug trace; snimanje oba signala može da uskladi uočeno curenje sa izvršenim kodom. Isto usklađivanje može da pomogne pri vremenskom određivanju [ubrizgavanja grešaka](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM emituje kompresovane događaje toka upravljanja umesto bajtova instrukcija. Dekoder rekonstruše izvršavanje na osnovu odgovarajuće firmware slike. ITM prenosi software instrumentation, a TPIU uokviruje izvore trace-a i upravlja serial-wire izlazom. Pre upotrebe bilo kakvih vrednosti registara, proverite CoreSight komponente i multipleksiranje pinova na ciljnom uređaju u referentnom priručniku: primer u nastavku odnosi se na STM32F401 i nije univerzalna konfiguracija za Cortex-M.<sup>[[1]](#references)</sup>

## Pronađite izlaz za trace

Na STM32F401, asinhroni SWO koristi PB3. Na istraživanom kontroleru, PB3 je bio povezan sa otpornikom R15, što je omogućilo pristupačnu tačku za merenje. Ako su kućište ili vod sakriveni, privremeno konfigurišite pin koji može da se koristi za SWO kao GPIO i preklapljajte ga putem SWD upisa u memoriju. Ispitajte tačke na ploči da biste pronašli odgovarajući talasni oblik, a zatim vratite konfiguraciju trace pina. Povežite analyzer sa zajedničkim uzemljenjem i kompatibilnim logičkim naponom.<sup>[[1]](#references)</sup>

## Uključite TPIU i ETM pomoću OpenOCD

Sledeće komande treba da budu u OpenOCD konfiguraciji, nakon što izaberete odgovarajući adapter i `target/stm32f4x.cfg`. `setbits` čuva nepovezane bitove u kontrolnim registrima, dok `mww` prepisuje celu reč. TPIU prvo usmerava asinhroni trace; zatim se ETM otključava, konfiguriše u programming režimu, dodeljuje mu se trace source ID `1` i pokreće se. Ove vrednosti potiču iz autorove funkcionalne konfiguracije za STM32F401, zato ih prilagodite mapi registara i taktu ciljnog uređaja.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Konfiguracija trace registara STM32F401 za OpenOCD</summary>

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

Brzina SWO-a je `HCLK / (TPIU_ACPR + 1)`. Sa HCLK-om od 16 MHz i `ACPR=3`, snimajte pri 4 Mbaud. U PulseView-u postavite ETM dekoder iznad UART dekodera na kanalu SWO analizatora, podesite UART na stvarnu brzinu prenosa preko žice i koristite ETM source ID konfigurisan iznad. U primeru je korišćeno uzorkovanje od 24 MHz (šest uzoraka po bitu), okidanje na opadajuću ivicu i 25% snimka pre okidanja. Nakon konfiguracije, zaustavite/resetujte cilj, aktivirajte snimanje, pa pokrenite `resume`; proverite ETM sinhronizaciju i verodostojnu putanju PC-a u odnosu na firmware, umesto da se oslanjate samo na izlaz koji izgleda dekodirano.<sup>[[1]](#references)</sup>

## Oporavak od promena takta i multipleksiranja pinova

Dve nezavisne radnje firmware-a mogu da prekinu ispravan trace. Promena PLL-a povećava HCLK, a time i brzinu prenosa SWO-a dok `ACPR` ostaje nepromenjen; UART sloj tada pogrešno dekodira bajtove, a ETM replay postaje besmislen. Pregledajte RCC/PLL podešavanje u [firmware analysis](../firmware-analysis/) i, u primeru STM32F401, učitajte Cortex-M sliku na `0x08000000` i uvezite njen SVD u Ghidra, kako bi upisi u registre takta imali nazive. Postavite hardversku breakpoint tačku na Thumb instrukciju od dva bajta *nakon* inicijalizacije takta. U primeru, `bp 0x080001fa 2 hw` praćen sa `resume` zaustavlja izvršavanje nakon podešavanja PLL-a; dok je procesor zaustavljen, `mww 0xe0040010 31` postavlja novi delilac. Izračunajte i podesite novu UART brzinu, aktivirajte snimanje, pa ponovo pokrenite `resume`. Time se snima putanja nakon promene; propuštena promena se ne može povratiti.<sup>[[1]](#references)</sup>

Odvojeno od toga, firmware može da preusmeri SWO pin na drugu periferiju. U primeru, podešavanje GPIO alternate-function-a prebacilo je PB3 na I2C2 SDA, pa nijedno podešavanje dekodera nije moglo da vrati trace na tu žicu. Pronađite odgovarajuću GPIO inicijalizaciju u firmware-u, pa ili zamenite njene pozive Thumb NOP-ovima iste veličine (`0xBF00` po halfword-u) ili zaustavite jezgro i vratite konfiguraciju pina kompatibilnu sa trace-om preko SWD-a. Oba pristupa mogu da onemoguće preusmerenu periferiju; firmware može ponovo da prepiše i podešavanje pina vraćeno tokom izvršavanja. Pri vraćanju pina tokom izvršavanja, podesite SWO delilac za trenutni HCLK.<sup>[[1]](#references)</sup>

## References

- [1] [Praćenje instrukcija: ARM tracing uživo pomoću ETM-a, ITM-a i TPIU-a](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD konfiguracija ETM/TPIU-a](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
